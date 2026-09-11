from __future__ import annotations

import posixpath
from typing import Any

import asyncssh

from ..security.paths import ensure_within_any, require_absolute_posix
from ..ssh.manager import SSHConnectionManager


class RemotePathAuthorizer:
    """Canonicalize remote paths and enforce configured roots without implying read/write permission."""

    def __init__(self, ssh: SSHConnectionManager):
        self.ssh = ssh

    async def canonicalize_with_client(
        self,
        client: Any,
        server: str,
        path: str,
        *,
        allow_missing_leaf: bool = False,
    ) -> str:
        requested = require_absolute_posix(path)
        try:
            canonical = str(await client.realpath(requested))
        except asyncssh.SFTPNoSuchFile:
            if not allow_missing_leaf:
                raise FileNotFoundError(requested)
            current = requested
            suffix: list[str] = []
            while True:
                parent = posixpath.dirname(current)
                if parent == current:
                    raise FileNotFoundError(f"no existing ancestor for {requested!r}")
                suffix.insert(0, posixpath.basename(current))
                current = parent
                try:
                    base = str(await client.realpath(current))
                    canonical = posixpath.join(base, *suffix)
                    break
                except asyncssh.SFTPNoSuchFile:
                    continue

        roots: list[str] = []
        for root in self.ssh.server(server).allowed_roots:
            try:
                roots.append(str(await client.realpath(root)))
            except asyncssh.SFTPNoSuchFile as exc:
                raise FileNotFoundError(f"configured allowed root does not exist: {root!r}") from exc
        return ensure_within_any(posixpath.normpath(canonical), roots)

    async def canonicalize(self, server: str, path: str, *, allow_missing_leaf: bool = False) -> str:
        async with self.ssh.sftp(server) as client:
            return await self.canonicalize_with_client(
                client, server, path, allow_missing_leaf=allow_missing_leaf
            )
