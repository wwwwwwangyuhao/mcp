import posixpath
import re
from contextlib import asynccontextmanager
from types import SimpleNamespace

import asyncssh
import pytest

from personal_linux_mcp.config import Settings
from personal_linux_mcp.jobs.manager import JobManager
from personal_linux_mcp.models import ShellResult
from personal_linux_mcp.ssh.manager import CommandDispatchUncertainError


class Handle:
    def __init__(self, fs, path, mode):
        self.fs = fs
        self.path = path
        self.mode = mode
        self.buffer = bytearray() if "w" in mode or "x" in mode else bytearray(fs.files.get(path, b""))

    async def read(self, n=-1, offset=0):
        data = self.fs.files.get(self.path, b"")
        return data[offset:] if n < 0 else data[offset : offset + n]

    async def write(self, data):
        raw = data if isinstance(data, bytes) else data.encode()
        self.buffer.extend(raw)
        self.fs.files[self.path] = bytes(self.buffer)

    def close(self):
        pass


class FakeSFTP:
    def __init__(self):
        self.files = {}
        self.dirs = {"/work", "/work/jobs"}

    async def makedirs(self, path, exist_ok=False):
        if path in self.dirs and not exist_ok:
            raise FileExistsError(path)
        self.dirs.add(path)

    async def chmod(self, _path, _mode):
        pass

    async def open(self, path, mode):
        if "x" in mode and path in self.files:
            raise FileExistsError(path)
        if "r" in mode and path not in self.files:
            raise asyncssh.SFTPNoSuchFile("missing")
        return Handle(self, path, mode)

    async def stat(self, path):
        if path not in self.files:
            raise asyncssh.SFTPNoSuchFile("missing")
        return SimpleNamespace(size=len(self.files[path]))


class FakePaths:
    async def canonicalize_with_client(self, _client, _server, path, **_kwargs):
        return path

    async def canonicalize(self, _server, path, **_kwargs):
        return path


class FakeSSH:
    def __init__(self, settings):
        self.settings = settings
        self.fs = FakeSFTP()
        self.current_ticks = 777
        self.launch_calls = 0
        self.uncertain_launch = False
        self.uncertain_probe = False
        self.stdin_payloads = []

    def server(self, alias):
        return self.settings.servers[alias]

    @asynccontextmanager
    async def sftp(self, _alias):
        yield self.fs

    async def run(self, server, command, **_kwargs):
        if "nohup setsid" in command:
            self.launch_calls += 1
            if self.uncertain_launch:
                raise CommandDispatchUncertainError("lost after dispatch")
            match = re.search(r"(/work/jobs/[0-9a-f-]+)/runner\.sh", command)
            assert match, command
            job_dir = match.group(1)
            self.fs.files[posixpath.join(job_dir, "status")] = b"running\n"
            self.fs.files[posixpath.join(job_dir, "pid")] = b"4242\n"
            self.fs.files[posixpath.join(job_dir, "start_ticks")] = b"777\n"
            self.fs.files[posixpath.join(job_dir, "job.log")] = b"line1\nline2\n"
            self.fs.files.pop(posixpath.join(job_dir, "command.sh"), None)
            return ShellResult(stdout="__PLMCP_LAUNCHED__:4242\n", exit_code=0)
        if command.startswith("awk '{print $22}' /proc/4242/stat"):
            if self.uncertain_probe:
                raise CommandDispatchUncertainError("probe transport lost")
            if self.current_ticks is None:
                return ShellResult(exit_code=1)
            return ShellResult(stdout=f"{self.current_ticks}\n", exit_code=0)
        if "kill -TERM" in command:
            for path in list(self.fs.files):
                if path.endswith("/status") and self.fs.files[path] == b"running\n":
                    self.fs.files[path] = b"terminated\n"
                    self.fs.files[posixpath.join(posixpath.dirname(path), "exit_code")] = b"143\n"
            self.current_ticks = None
            return ShellResult(exit_code=0)
        if "kill -KILL" in command:
            self.current_ticks = None
            return ShellResult(exit_code=0)
        raise AssertionError(f"unexpected command: {command}")

    async def write_process_stdin(self, _server, _command, data, **_kwargs):
        self.stdin_payloads.append(data)
        return len(data)


def make_settings(tmp_path):
    return Settings.model_validate(
        {
            "state_dir": str(tmp_path / "state"),
            "servers": {
                "a": {
                    "host": "a",
                    "allowed_roots": ["/work"],
                    "job_root": "/work/jobs",
                    "permissions": {"read": True, "jobs": True},
                }
            },
        }
    )


@pytest.mark.asyncio
async def test_job_is_recoverable_after_gateway_manager_restart(tmp_path):
    settings = make_settings(tmp_path)
    ssh = FakeSSH(settings)
    first_manager = JobManager(settings, ssh, FakePaths())
    started = await first_manager.start("a", "sleep 100", "/work")
    assert started.status == "running"
    assert started.remote_pid == 4242

    second_manager = JobManager(settings, ssh, FakePaths())
    recovered = await second_manager.status(started.job_id)
    assert recovered.status == "running"
    assert recovered.remote_pid == 4242


@pytest.mark.asyncio
async def test_ambiguous_launch_returns_unknown_and_does_not_replay(tmp_path):
    settings = make_settings(tmp_path)
    ssh = FakeSSH(settings)
    ssh.uncertain_launch = True
    manager = JobManager(settings, ssh, FakePaths())
    started = await manager.start("a", "python train.py", "/work")
    assert started.status == "unknown"
    assert "not retried" in started.message
    assert ssh.launch_calls == 1
    assert manager.store.get(started.job_id)["status"] == "unknown"


@pytest.mark.asyncio
async def test_pid_reuse_becomes_orphaned_not_running(tmp_path):
    settings = make_settings(tmp_path)
    ssh = FakeSSH(settings)
    manager = JobManager(settings, ssh, FakePaths())
    started = await manager.start("a", "sleep 100", "/work")
    ssh.current_ticks = 999
    status = await manager.status(started.job_id)
    assert status.status == "orphaned"


@pytest.mark.asyncio
async def test_logs_are_incremental_and_line_bounded(tmp_path):
    settings = make_settings(tmp_path)
    ssh = FakeSSH(settings)
    manager = JobManager(settings, ssh, FakePaths())
    started = await manager.start("a", "echo hi", "/work")
    page = await manager.logs(started.job_id, cursor=0, max_bytes=100, max_lines=1)
    assert page.content == "line1\n"
    assert page.next_cursor == len(b"line1\n")
    assert page.truncated


@pytest.mark.asyncio
async def test_stdin_and_terminate_require_live_verified_identity(tmp_path):
    settings = make_settings(tmp_path)
    ssh = FakeSSH(settings)
    manager = JobManager(settings, ssh, FakePaths())
    started = await manager.start("a", "cat", "/work")
    sent = await manager.stdin(started.job_id, "hello\n")
    assert sent["bytes_sent"] == 6
    assert ssh.stdin_payloads == [b"hello\n"]
    stopped = await manager.terminate(started.job_id, grace_seconds=0.001)
    assert stopped["status"] == "terminated"


@pytest.mark.asyncio
async def test_probe_transport_failure_returns_unknown_without_orphaning(tmp_path):
    settings = make_settings(tmp_path)
    ssh = FakeSSH(settings)
    manager = JobManager(settings, ssh, FakePaths())
    started = await manager.start("a", "sleep 100", "/work")
    ssh.uncertain_probe = True
    status = await manager.status(started.job_id)
    assert status.status == "unknown"
    assert manager.store.get(started.job_id)["status"] == "running"


def test_runner_preserves_launch_working_directory():
    from personal_linux_mcp.jobs.manager import _RUNNER

    assert "RUN_CWD=$(pwd)" in _RUNNER
    assert 'cd "$RUN_CWD"' in _RUNNER


@pytest.mark.asyncio
async def test_log_cursor_beyond_current_size_is_rejected(tmp_path):
    settings = make_settings(tmp_path)
    ssh = FakeSSH(settings)
    manager = JobManager(settings, ssh, FakePaths())
    started = await manager.start("a", "echo hi", "/work")
    with pytest.raises(ValueError, match="beyond current log size"):
        await manager.logs(started.job_id, cursor=999)


@pytest.mark.asyncio
async def test_unreachable_status_preserves_last_known_state(tmp_path):
    settings = make_settings(tmp_path)
    ssh = FakeSSH(settings)
    manager = JobManager(settings, ssh, FakePaths())
    started = await manager.start("a", "sleep 100", "/work")

    @asynccontextmanager
    async def unreachable(_alias):
        raise OSError("host down")
        yield

    ssh.sftp = unreachable
    status = await manager.status(started.job_id)
    assert status.status == "running"
    assert status.reachable is False
    assert manager.store.get(started.job_id)["status"] == "running"


@pytest.mark.asyncio
async def test_uncertain_term_dispatch_does_not_mark_termination_requested(tmp_path):
    settings = make_settings(tmp_path)
    ssh = FakeSSH(settings)
    manager = JobManager(settings, ssh, FakePaths())
    started = await manager.start("a", "sleep 100", "/work")
    original_run = ssh.run

    async def uncertain_term(server, command, **kwargs):
        if "kill -TERM" in command:
            raise CommandDispatchUncertainError("lost after term dispatch")
        return await original_run(server, command, **kwargs)

    ssh.run = uncertain_term
    result = await manager.terminate(started.job_id, grace_seconds=0.001)
    assert result["status"] == "unknown"
    assert manager.store.get(started.job_id)["termination_requested"] == 0


def test_runner_waits_for_child_after_term_signal():
    from personal_linux_mcp.jobs.manager import _RUNNER

    assert "term_requested=1" in _RUNNER
    assert "kill -TERM \"$child\"" in _RUNNER
    assert "if kill -0 \"$child\"" in _RUNNER
    assert "exit 143" not in _RUNNER
