import os
import sqlite3
import stat
from contextlib import closing

import pytest

from personal_linux_mcp.config import Settings
from personal_linux_mcp.jobs.store import JobStore
from personal_linux_mcp.security.audit import AuditLogger
from personal_linux_mcp.server import build_server


def test_state_dir_and_database_are_owner_only(tmp_path):
    state = tmp_path / "state"
    AuditLogger(str(state))
    JobStore(str(state))
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE((state / "gateway.sqlite3").stat().st_mode) == 0o600


@pytest.mark.asyncio
async def test_servers_list_emits_audit_row(tmp_path):
    state = tmp_path / "state"
    settings = Settings.model_validate({
        "state_dir": str(state),
        "servers": {"fake": {"host": "fake", "allowed_roots": ["/work"]}},
    })
    server = build_server(settings)
    tool = next(t for t in server._tool_manager.list_tools() if t.name == "servers_list")
    result = await tool.fn()
    assert result["servers"][0]["alias"] == "fake"
    with closing(sqlite3.connect(state / "gateway.sqlite3")) as db:
        row = db.execute(
            "SELECT tool,status,detail FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row == ("servers_list", "ok", None)


@pytest.mark.asyncio
async def test_mutating_file_write_emits_audit_without_content(tmp_path):
    from types import SimpleNamespace

    state = tmp_path / "state"
    settings = Settings.model_validate({
        "state_dir": str(state),
        "servers": {
            "fake": {
                "host": "fake",
                "allowed_roots": ["/work"],
                "permissions": {"write": True},
            }
        },
    })

    class FakeFS:
        async def file_write(self, server, path, content, **kwargs):
            return {"path": path, "bytes_written": len(content.encode()), "mode": kwargs["mode"]}

    class FakeSSH:
        def server(self, alias):
            return settings.servers[alias]

    services = SimpleNamespace(
        settings=settings,
        ssh=FakeSSH(),
        paths=None,
        fs=FakeFS(),
        jobs=None,
        audit=AuditLogger(str(state)),
    )
    server = build_server(settings, services=services)
    tool = next(t for t in server._tool_manager.list_tools() if t.name == "file_write")
    result = await tool.fn("fake", "/work/out.txt", "top-secret", mode="create")
    assert result["bytes_written"] == len("top-secret")
    with closing(sqlite3.connect(state / "gateway.sqlite3")) as db:
        row = db.execute(
            "SELECT tool,status,target,detail FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row == ("file_write", "ok", "/work/out.txt", None)
