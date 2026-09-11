import asyncio
from types import SimpleNamespace

import pytest

from personal_linux_mcp.config import Settings
from personal_linux_mcp.ssh.manager import (
    CommandDispatchUncertainError,
    SSHConnectionManager,
)


def settings():
    return Settings.model_validate(
        {
            "servers": {
                "a": {
                    "host": "example",
                    "allowed_roots": ["/work"],
                    "permissions": {"read": True, "shell": True},
                }
            }
        }
    )


class FakeReader:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    async def read(self, _n=-1):
        await asyncio.sleep(0)
        return self.chunks.pop(0) if self.chunks else b""


class FakeProcess:
    def __init__(self, stdout=(), stderr=(), *, complete=True, exit_status=0):
        self.stdout = FakeReader(stdout)
        self.stderr = FakeReader(stderr)
        self._done = asyncio.Event()
        if complete:
            self._done.set()
        self._exit_status = exit_status
        self.terminated = False
        self.killed = False

    async def wait(self, check=False, timeout=None):
        if timeout is None:
            await self._done.wait()
        else:
            await asyncio.wait_for(self._done.wait(), timeout)
        return SimpleNamespace(exit_status=self._exit_status)

    async def wait_closed(self):
        await self._done.wait()

    def terminate(self):
        self.terminated = True
        self._done.set()

    def kill(self):
        self.killed = True
        self._done.set()


class FakeConnection:
    def __init__(self, process=None, exc=None):
        self.process = process
        self.exc = exc
        self.calls = 0

    async def create_process(self, *_args, **_kwargs):
        self.calls += 1
        if self.exc:
            raise self.exc
        return self.process


class TestManager(SSHConnectionManager):
    __test__ = False

    def __init__(self, cfg, connection):
        super().__init__(cfg)
        self.fake_connection = connection

    async def connection(self, alias):
        self.server(alias)
        return self.fake_connection


@pytest.mark.asyncio
async def test_output_is_bounded_across_both_streams():
    process = FakeProcess(stdout=[b"123456789"], stderr=[b"abcdef"])
    manager = TestManager(settings(), FakeConnection(process))
    result = await manager.run("a", "cmd", max_output_bytes=5)
    assert result.truncated
    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 5
    assert result.exit_code is None


@pytest.mark.asyncio
async def test_timeout_terminates_foreground_process():
    process = FakeProcess(complete=False)
    manager = TestManager(settings(), FakeConnection(process))
    result = await manager.run("a", "sleep forever", timeout=0.01)
    assert result.timed_out
    assert process.terminated


@pytest.mark.asyncio
async def test_dispatch_failure_is_never_replayed():
    connection = FakeConnection(exc=OSError("transport lost"))
    manager = TestManager(settings(), connection)
    with pytest.raises(CommandDispatchUncertainError):
        await manager.run("a", "side-effect")
    assert connection.calls == 1


def test_wrap_cwd_quotes_safely():
    wrapped = SSHConnectionManager.wrap_cwd("echo hi", "/work/a b")
    assert wrapped == "cd -- '/work/a b' && echo hi"


def test_connect_kwargs_never_disable_host_key_verification():
    manager = SSHConnectionManager(settings())
    kwargs = manager._connect_kwargs(manager.server("a"))
    assert "known_hosts" not in kwargs
    assert kwargs["host"] == "example"


class FakeTransport:
    def __init__(self):
        self.closed = False
        self.keepalive = None

    def is_closed(self):
        return self.closed

    def set_keepalive(self, interval, count_max):
        self.keepalive = (interval, count_max)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


@pytest.mark.asyncio
async def test_connection_reuses_live_transport_and_reconnects_closed(monkeypatch):
    transports = [FakeTransport(), FakeTransport()]
    calls = []

    async def fake_connect(**kwargs):
        calls.append(kwargs)
        return transports[len(calls) - 1]

    monkeypatch.setattr("personal_linux_mcp.ssh.manager.asyncssh.connect", fake_connect)
    manager = SSHConnectionManager(settings())
    first = await manager.connection("a")
    assert await manager.connection("a") is first
    assert len(calls) == 1
    first.closed = True
    second = await manager.connection("a")
    assert second is transports[1]
    assert len(calls) == 2
    assert second.keepalive == (30, 3)
