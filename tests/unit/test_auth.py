import pytest

from personal_linux_mcp.auth import StaticBearerTokenVerifier


@pytest.mark.asyncio
async def test_static_token_verifier_uses_env_and_rejects_wrong(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "correct-secret")
    verifier = StaticBearerTokenVerifier("TEST_TOKEN")
    assert await verifier.verify_token("wrong") is None
    token = await verifier.verify_token("correct-secret")
    assert token is not None
    assert token.subject == "owner"
