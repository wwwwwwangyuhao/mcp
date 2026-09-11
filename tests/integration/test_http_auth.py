import asyncio
import json

import pytest
from mcp.types import LATEST_PROTOCOL_VERSION

from personal_linux_mcp.config import Settings
from personal_linux_mcp.server import build_server


async def asgi_post(app, body: dict, bearer: str | None):
    payload = json.dumps(body).encode()
    headers = [
        (b"host", b"127.0.0.1:8000"),
        (b"content-type", b"application/json"),
        (b"accept", b"application/json, text/event-stream"),
    ]
    if bearer is not None:
        headers.append((b"authorization", f"Bearer {bearer}".encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
    }
    sent = []
    used = False

    async def receive():
        nonlocal used
        if not used:
            used = True
            return {"type": "http.request", "body": payload, "more_body": False}
        await asyncio.sleep(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    status = next(
        msg["status"] for msg in sent if msg["type"] == "http.response.start"
    )
    raw = b"".join(
        msg.get("body", b"") for msg in sent if msg["type"] == "http.response.body"
    )
    return status, raw


def http_settings(tmp_path):
    return Settings.model_validate({
        "state_dir": str(tmp_path / "state"),
        "http": {"enabled": True, "bearer_token_env": "TEST_MCP_TOKEN"},
        "servers": {"fake": {"host": "fake", "allowed_roots": ["/work"]}},
    })


def initialize_body():
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "phase-c-test", "version": "1"},
        },
    }


def tools_body():
    return {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}


def test_http_mode_refuses_missing_token_env(tmp_path, monkeypatch):
    monkeypatch.delenv("TEST_MCP_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="requires bearer token"):
        build_server(http_settings(tmp_path))


@pytest.mark.asyncio
async def test_http_bearer_auth_and_tool_discovery(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_MCP_TOKEN", "correct-secret")
    server = build_server(http_settings(tmp_path))
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        host="127.0.0.1",
    )

    wrong_status, _ = await asgi_post(app, initialize_body(), "wrong")
    missing_status, _ = await asgi_post(app, initialize_body(), None)
    assert wrong_status == 401
    assert missing_status == 401

    async with app.router.lifespan_context(app):
        init_status, init_raw = await asgi_post(
            app, initialize_body(), "correct-secret"
        )
        assert init_status == 200
        init = json.loads(init_raw)
        assert init["result"]["serverInfo"]["name"] == "Personal Linux MCP"

        tools_status, tools_raw = await asgi_post(
            app, tools_body(), "correct-secret"
        )
        assert tools_status == 200
        names = {tool["name"] for tool in json.loads(tools_raw)["result"]["tools"]}
        assert {"servers_list", "shell_exec", "job_start", "job_status"} <= names
