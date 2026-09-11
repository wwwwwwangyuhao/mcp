from __future__ import annotations

import os
import secrets

from mcp.server.auth.provider import AccessToken, TokenVerifier


class StaticBearerTokenVerifier(TokenVerifier):
    """Single-owner bearer verifier. The secret is read only from an environment variable."""

    def __init__(self, env_name: str):
        self.env_name = env_name

    async def verify_token(self, token: str) -> AccessToken | None:
        expected = os.environ.get(self.env_name)
        if not expected:
            return None
        if not secrets.compare_digest(token, expected):
            return None
        return AccessToken(
            token=token,
            client_id="personal-linux-mcp-owner",
            scopes=[],
            subject="owner",
        )
