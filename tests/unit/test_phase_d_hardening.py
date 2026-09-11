import asyncio
import ast
from pathlib import Path

import pytest

from personal_linux_mcp.config import Settings
from personal_linux_mcp.ssh.manager import (
    CommandDispatchUncertainError,
    SSHConnectionManager,
)
from personal_linux_mcp.tools.filesystem import FilesystemService


def one_server(max_channels=8):
    return Settings.model_validate({
        "servers": {"a": {
            "host": "a",
            "allowed_roots": ["/work"],
            "max_concurrent_channels": max_channels,
        }}
    })


class EmptyReader:
    async def read(self, _n=-1):
        await asyncio.sleep(0)
        return b""

class BadReader:
    async def read(self, _n=-1):
        raise OSError("stream lost")


class ImmediateProcess:
    def __init__(self, stdout=None, stderr=None):
        self.stdout = stdout or EmptyReader()
        self.stderr = stderr or EmptyReader()
        self.exit_status = 0

    async def wait_closed(self):
        return None

    def is_closing(self):
        return True


class CountingConnection:
    def __init__(self, process):
        self.process = process
        self.calls = 0

    async def create_process(self, *_args, **_kwargs):
        self.calls += 1
        return self.process

class TestManager(SSHConnectionManager):
    __test__ = False

    def __init__(self, settings, connection):
        super().__init__(settings)
        self.connection_obj = connection

    async def connection(self, _alias):
        return self.connection_obj


@pytest.mark.asyncio
async def test_output_reader_failure_is_uncertain_and_never_replayed():
    conn = CountingConnection(ImmediateProcess(stdout=BadReader()))
    manager = TestManager(one_server(), conn)
    with pytest.raises(CommandDispatchUncertainError, match="not retried"):
        await manager.run("a", "side-effect")
    assert conn.calls == 1


@pytest.mark.asyncio
async def test_concurrent_connection_requests_share_one_dial(monkeypatch):
    calls = 0
    transport = type("T", (), {
        "is_closed": lambda self: False,
        "set_keepalive": lambda self, **kwargs: None,
    })()

    async def fake_connect(**_kwargs):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.02)
        return transport

    monkeypatch.setattr("personal_linux_mcp.ssh.manager.asyncssh.connect", fake_connect)
    manager = SSHConnectionManager(one_server())
    results = await asyncio.gather(*(manager.connection("a") for _ in range(12)))
    assert calls == 1
    assert all(result is transport for result in results)


def two_servers():
    return Settings.model_validate({
        "servers": {
            "a": {"host": "a", "allowed_roots": ["/work"]},
            "b": {"host": "b", "allowed_roots": ["/work"]},
        }
    })


@pytest.mark.asyncio
async def test_different_server_aliases_connect_independently(monkeypatch):
    entered = set()
    both_entered = asyncio.Event()
    release = asyncio.Event()

    class Transport:
        def is_closed(self): return False
        def set_keepalive(self, **_kwargs): pass

    async def fake_connect(**kwargs):
        entered.add(kwargs["host"])
        if len(entered) == 2:
            both_entered.set()
        await release.wait()
        return Transport()

    monkeypatch.setattr("personal_linux_mcp.ssh.manager.asyncssh.connect", fake_connect)
    manager = SSHConnectionManager(two_servers())
    ta = asyncio.create_task(manager.connection("a"))
    tb = asyncio.create_task(manager.connection("b"))
    await asyncio.wait_for(both_entered.wait(), timeout=0.2)
    assert entered == {"a", "b"}
    release.set()
    await asyncio.gather(ta, tb)


class BlockingProcess:
    def __init__(self, release, counter):
        self.stdout = EmptyReader()
        self.stderr = EmptyReader()
        self.exit_status = 0
        self.release = release
        self.counter = counter

    async def wait_closed(self):
        await self.release.wait()
        self.counter["active"] -= 1

    def is_closing(self):
        return True


class BlockingConnection:
    def __init__(self, release, counter):
        self.release = release
        self.counter = counter

    async def create_process(self, *_args, **_kwargs):
        self.counter["active"] += 1
        self.counter["max"] = max(self.counter["max"], self.counter["active"])
        return BlockingProcess(self.release, self.counter)

@pytest.mark.asyncio
async def test_same_server_channel_semaphore_enforces_limit_one():
    release = asyncio.Event()
    counter = {"active": 0, "max": 0}
    conn = BlockingConnection(release, counter)
    manager = TestManager(one_server(max_channels=1), conn)
    first = asyncio.create_task(manager.run("a", "one", timeout=1))
    second = asyncio.create_task(manager.run("a", "two", timeout=1))
    await asyncio.sleep(0.03)
    assert counter["active"] == 1
    assert counter["max"] == 1
    release.set()
    await asyncio.gather(first, second)
    assert counter["max"] == 1


class SearchSSH:
    def __init__(self, settings):
        self.settings = settings

    def server(self, alias):
        return self.settings.servers[alias]


class SearchPaths:
    async def canonicalize(self, _server, path, **_kwargs):
        return path


@pytest.mark.asyncio
async def test_file_search_rejects_nonpositive_max_results_before_shell():
    settings = one_server()
    service = FilesystemService(settings, SearchSSH(settings), SearchPaths())
    with pytest.raises(ValueError, match="max_results"):
        await service.file_search("a", "/work", "x", max_results=-1)


def test_every_v1_tool_handler_contains_audit_context():
    server_path = Path(__file__).parents[2] / "src/personal_linux_mcp/server.py"
    tree = ast.parse(server_path.read_text(encoding="utf-8"))
    expected = {
        "servers_list", "server_info", "directory_list", "file_stat", "file_read",
        "file_write", "file_patch", "file_search", "shell_exec", "job_start",
        "job_status", "job_logs", "job_stdin", "job_terminate", "process_list",
        "system_status",
    }
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in expected:
            continue
        source = ast.get_source_segment(server_path.read_text(encoding="utf-8"), node) or ""
        assert "svc.audit.event" in source, f"missing audit context: {node.name}"
        found.add(node.name)
    assert found == expected


@pytest.mark.asyncio
async def test_durable_job_log_reconciliation_does_not_self_deadlock(tmp_path):
    from contextlib import asynccontextmanager
    from personal_linux_mcp.jobs.manager import JobManager
    from tests.unit.test_jobs import FakePaths, FakeSSH, make_settings

    class SerialFakeSSH(FakeSSH):
        def __init__(self, settings):
            super().__init__(settings)
            self.gate = asyncio.Semaphore(1)

        @asynccontextmanager
        async def sftp(self, alias):
            async with self.gate:
                async with super().sftp(alias) as client:
                    yield client

        async def run(self, server, command, **kwargs):
            async with self.gate:
                return await super().run(server, command, **kwargs)

    settings = make_settings(tmp_path)
    ssh = SerialFakeSSH(settings)
    manager = JobManager(settings, ssh, FakePaths())
    started = await asyncio.wait_for(
        manager.start("a", "echo hi", "/work"), timeout=0.5
    )
    page = await asyncio.wait_for(
        manager.logs(started.job_id, cursor=0, max_lines=1), timeout=0.5
    )
    assert page.content == "line1\n"


@pytest.mark.asyncio
async def test_existing_job_controls_fail_closed_when_jobs_permission_is_revoked(tmp_path):
    from personal_linux_mcp.jobs.manager import JobManager
    from tests.unit.test_jobs import FakePaths, FakeSSH, make_settings

    settings = make_settings(tmp_path)
    ssh = FakeSSH(settings)
    manager = JobManager(settings, ssh, FakePaths())
    started = await manager.start("a", "sleep 100", "/work")
    settings.servers["a"].permissions.jobs = False

    with pytest.raises(PermissionError, match="job permission"):
        await manager.status(started.job_id)
    with pytest.raises(PermissionError, match="job permission"):
        await manager.logs(started.job_id)
    with pytest.raises(PermissionError, match="job permission"):
        await manager.stdin(started.job_id, "x")
    with pytest.raises(PermissionError, match="job permission"):
        await manager.terminate(started.job_id)


class HangingConnection:
    def __init__(self):
        self.calls = 0
        self.never = asyncio.Event()

    async def create_process(self, *_args, **_kwargs):
        self.calls += 1
        await self.never.wait()


@pytest.mark.asyncio
async def test_command_dispatch_timeout_is_uncertain_and_not_replayed():
    conn = HangingConnection()
    manager = TestManager(one_server(), conn)
    with pytest.raises(CommandDispatchUncertainError, match="not retried"):
        await manager.run("a", "side-effect", timeout=0.01)
    assert conn.calls == 1


class BlockingStdin:
    def __init__(self):
        self.data = bytearray()
        self.never = asyncio.Event()
        self.eof = False

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        await self.never.wait()

    def write_eof(self):
        self.eof = True


class StdinBlockingProcess:
    def __init__(self):
        self.stdin = BlockingStdin()
        self.done = asyncio.Event()
        self.exit_status = 0
        self.terminated = False
        self.killed = False

    async def wait_closed(self):
        await self.done.wait()

    def terminate(self):
        self.terminated = True
        self.done.set()

    def kill(self):
        self.killed = True
        self.done.set()


@pytest.mark.asyncio
async def test_stdin_drain_timeout_is_bounded_and_marked_uncertain():
    process = StdinBlockingProcess()
    conn = CountingConnection(process)
    manager = TestManager(one_server(), conn)
    with pytest.raises(CommandDispatchUncertainError, match="may be partial"):
        await manager.write_process_stdin("a", "cat", b"payload", timeout=0.01)
    assert bytes(process.stdin.data) == b"payload"
    assert process.terminated
    assert conn.calls == 1


def test_existing_permissive_state_dir_is_rejected_without_chmod(tmp_path):
    import stat
    from personal_linux_mcp.security.state import prepare_state_dir

    state = tmp_path / "shared"
    state.mkdir(mode=0o755)
    state.chmod(0o755)
    with pytest.raises(PermissionError, match="0700"):
        prepare_state_dir(str(state))
    assert stat.S_IMODE(state.stat().st_mode) == 0o755


def test_state_dir_symlink_is_rejected_without_touching_target(tmp_path):
    import stat
    from personal_linux_mcp.security.state import prepare_state_dir

    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    link = tmp_path / "state-link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(RuntimeError, match="symbolic link"):
        prepare_state_dir(str(link))
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_state_database_symlink_is_rejected(tmp_path):
    import stat
    from personal_linux_mcp.security.audit import AuditLogger

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-touch", encoding="utf-8")
    victim.chmod(0o644)
    (state / "gateway.sqlite3").symlink_to(victim)

    with pytest.raises(RuntimeError, match="symbolic link"):
        AuditLogger(str(state))
    assert victim.read_text(encoding="utf-8") == "do-not-touch"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644


@pytest.mark.asyncio
async def test_job_start_does_not_mask_unexpected_internal_errors(tmp_path):
    from personal_linux_mcp.jobs.manager import JobManager
    from tests.unit.test_jobs import FakePaths, FakeSSH, make_settings

    settings = make_settings(tmp_path)
    ssh = FakeSSH(settings)
    manager = JobManager(settings, ssh, FakePaths())

    async def programming_bug(*_args, **_kwargs):
        raise TypeError("simulated internal bug")

    ssh.run = programming_bug
    with pytest.raises(TypeError, match="simulated internal bug"):
        await manager.start("a", "echo hi", "/work")
    rows = manager.store.list()
    assert len(rows) == 1
    assert rows[0]["status"] == "unknown"
