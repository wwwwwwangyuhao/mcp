from __future__ import annotations

import hashlib
import posixpath
import shlex
import stat as statmod
import uuid
from typing import Any

import asyncssh

from ..config import Settings
from ..models import FileReadResult
from ..security.remote_paths import RemotePathAuthorizer
from ..ssh.manager import SSHConnectionManager


class FilesystemService:
    def __init__(
        self,
        settings: Settings,
        ssh: SSHConnectionManager,
        paths: RemotePathAuthorizer | None = None,
    ):
        self.settings = settings
        self.ssh = ssh
        self.paths = paths or RemotePathAuthorizer(ssh)

    def _check_permission(self, server: str, write: bool = False) -> None:
        perms = self.ssh.server(server).permissions
        if write and not perms.write:
            raise PermissionError(f"write permission is disabled for {server!r}")
        if not write and not perms.read:
            raise PermissionError(f"read permission is disabled for {server!r}")

    async def canonicalize(self, server: str, path: str, *, for_write: bool = False) -> str:
        self._check_permission(server, write=for_write)
        return await self.paths.canonicalize(server, path, allow_missing_leaf=for_write)

    async def directory_list(
        self,
        server: str,
        path: str,
        *,
        offset: int = 0,
        limit: int | None = None,
    ) -> dict[str, Any]:
        self._check_permission(server)
        if offset < 0:
            raise ValueError("offset must be >= 0")
        page_limit = min(
            limit or self.settings.limits.directory_list_max_entries,
            self.settings.limits.directory_list_max_entries,
        )
        if page_limit <= 0:
            raise ValueError("limit must be > 0")
        async with self.ssh.sftp(server) as client:
            canonical = await self.paths.canonicalize_with_client(client, server, path)
            rows: list[dict[str, Any]] = []
            seen = 0
            has_more = False
            async for entry in client.scandir(canonical):
                if seen < offset:
                    seen += 1
                    continue
                if len(rows) >= page_limit:
                    has_more = True
                    break
                perms = entry.attrs.permissions or 0
                rows.append(
                    {
                        "name": entry.filename,
                        "type": "directory" if statmod.S_ISDIR(perms) else "file" if statmod.S_ISREG(perms) else "other",
                        "size": entry.attrs.size,
                        "mtime": entry.attrs.mtime,
                    }
                )
                seen += 1
            next_offset = offset + len(rows)
            return {
                "path": canonical,
                "entries": rows,
                "offset": offset,
                "next_offset": next_offset,
                "truncated": has_more,
            }

    async def file_stat(self, server: str, path: str) -> dict[str, Any]:
        self._check_permission(server)
        async with self.ssh.sftp(server) as client:
            canonical = await self.paths.canonicalize_with_client(client, server, path)
            attrs = await client.stat(canonical)
            perms = attrs.permissions or 0
            return {
                "path": canonical,
                "size": attrs.size,
                "mtime": attrs.mtime,
                "permissions": perms,
                "type": "directory" if statmod.S_ISDIR(perms) else "file" if statmod.S_ISREG(perms) else "other",
            }

    @staticmethod
    def _decode_utf8_page(raw: bytes, requested: int, offset: int) -> tuple[str, bytes]:
        if not raw:
            return "", b""
        end = min(requested, len(raw))
        while end > 0:
            try:
                piece = raw[:end]
                return piece.decode("utf-8", errors="strict"), piece
            except UnicodeDecodeError as exc:
                if exc.start == 0 and offset > 0:
                    raise ValueError("offset is not on a UTF-8 codepoint boundary") from exc
                # Only an incomplete final codepoint may be trimmed. Any invalid
                # byte sequence in the interior is rejected instead of skipped.
                if exc.reason != "unexpected end of data" or exc.end != end:
                    raise UnicodeError("file is not valid UTF-8") from exc
                end = exc.start
        raise ValueError("requested length is too small for the next UTF-8 codepoint")

    async def file_read(
        self,
        server: str,
        path: str,
        offset: int = 0,
        length: int | None = None,
    ) -> FileReadResult:
        self._check_permission(server)
        if offset < 0:
            raise ValueError("offset must be >= 0")
        limit = self.settings.limits.file_read_max_bytes
        requested = min(length if length is not None else limit, limit)
        if requested <= 0:
            raise ValueError("length must be > 0")
        async with self.ssh.sftp(server) as client:
            canonical = await self.paths.canonicalize_with_client(client, server, path)
            attrs = await client.stat(canonical)
            size = attrs.size
            if size is not None and offset > size:
                offset = size
            handle = await client.open(canonical, "rb")
            try:
                data = await handle.read(requested + 4, offset)
            finally:
                handle.close()
            raw = data if isinstance(data, bytes) else data.encode("utf-8")
            content, consumed = self._decode_utf8_page(raw, requested, offset) if raw else ("", b"")
            next_offset = offset + len(consumed)
            eof = size is not None and next_offset >= size
            return FileReadResult(
                path=canonical,
                content=content,
                offset=offset,
                bytes_read=len(consumed),
                next_offset=next_offset,
                eof=eof,
                truncated=not eof,
            )

    async def _atomic_write(
        self,
        client: Any,
        target: str,
        raw: bytes,
        *,
        overwrite: bool,
        mode: int | None = None,
    ) -> None:
        parent = posixpath.dirname(target)
        temp = posixpath.join(parent, f".plmcp-{uuid.uuid4().hex}.tmp")
        handle = None
        try:
            handle = await client.open(temp, "xb")
            await handle.write(raw)
            handle.close()
            handle = None
            await client.chmod(temp, mode if mode is not None else 0o600)
            if overwrite:
                await client.posix_rename(temp, target)
            else:
                await client.rename(temp, target)
        except Exception:
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
            try:
                await client.remove(temp)
            except Exception:
                pass
            raise

    async def file_write(
        self,
        server: str,
        path: str,
        content: str,
        *,
        mode: str = "create",
        expected_size: int | None = None,
        expected_mtime: int | None = None,
    ) -> dict[str, Any]:
        self._check_permission(server, write=True)
        if mode not in {"create", "overwrite"}:
            raise ValueError("mode must be 'create' or 'overwrite'")
        raw = content.encode("utf-8")
        if len(raw) > self.settings.limits.file_write_max_bytes:
            raise ValueError(
                f"content exceeds file_write_max_bytes ({self.settings.limits.file_write_max_bytes})"
            )
        async with self.ssh.sftp(server) as client:
            canonical = await self.paths.canonicalize_with_client(
                client, server, path, allow_missing_leaf=True
            )
            try:
                attrs = await client.stat(canonical)
                exists = True
            except asyncssh.SFTPNoSuchFile:
                attrs = None
                exists = False
            if mode == "create" and exists:
                raise FileExistsError(canonical)
            if mode == "overwrite" and not exists:
                raise FileNotFoundError(canonical)
            if attrs is not None:
                if expected_size is not None and attrs.size != expected_size:
                    raise RuntimeError("concurrent modification detected: size changed")
                if expected_mtime is not None and attrs.mtime != expected_mtime:
                    raise RuntimeError("concurrent modification detected: mtime changed")
            if attrs is not None and (expected_size is not None or expected_mtime is not None):
                latest = await client.stat(canonical)
                if expected_size is not None and latest.size != expected_size:
                    raise RuntimeError("concurrent modification detected before rename: size changed")
                if expected_mtime is not None and latest.mtime != expected_mtime:
                    raise RuntimeError("concurrent modification detected before rename: mtime changed")
            original_mode = (attrs.permissions & 0o7777) if attrs and attrs.permissions is not None else None
            await self._atomic_write(
                client, canonical, raw, overwrite=(mode == "overwrite"), mode=original_mode
            )
            return {"path": canonical, "bytes_written": len(raw), "mode": mode}

    async def file_patch(
        self,
        server: str,
        path: str,
        old_string: str,
        new_string: str,
        *,
        expected_replacements: int = 1,
        expected_sha256: str | None = None,
    ) -> dict[str, Any]:
        self._check_permission(server, write=True)
        if not old_string:
            raise ValueError("old_string must not be empty")
        if expected_replacements < 1:
            raise ValueError("expected_replacements must be >= 1")
        max_bytes = self.settings.limits.patch_max_bytes
        async with self.ssh.sftp(server) as client:
            canonical = await self.paths.canonicalize_with_client(client, server, path)
            attrs = await client.stat(canonical)
            if attrs.size is not None and attrs.size > max_bytes:
                raise ValueError(f"file exceeds patch_max_bytes ({max_bytes})")
            handle = await client.open(canonical, "rb")
            try:
                raw = await handle.read(max_bytes + 1)
            finally:
                handle.close()
            raw = raw if isinstance(raw, bytes) else raw.encode("utf-8")
            if len(raw) > max_bytes:
                raise ValueError(f"file exceeds patch_max_bytes ({max_bytes})")
            digest = hashlib.sha256(raw).hexdigest()
            if expected_sha256 and digest != expected_sha256:
                raise RuntimeError("concurrent modification detected: sha256 changed")
            text = raw.decode("utf-8", errors="strict")
            count = text.count(old_string)
            if count != expected_replacements:
                raise ValueError(
                    f"expected {expected_replacements} exact occurrence(s), found {count}; no write performed"
                )
            out = text.replace(old_string, new_string).encode("utf-8")
            if len(out) > max_bytes:
                raise ValueError(f"patched file would exceed patch_max_bytes ({max_bytes})")
            if expected_sha256:
                verify_handle = await client.open(canonical, "rb")
                try:
                    verify_raw = await verify_handle.read(max_bytes + 1)
                finally:
                    verify_handle.close()
                verify_raw = verify_raw if isinstance(verify_raw, bytes) else verify_raw.encode("utf-8")
                if hashlib.sha256(verify_raw).hexdigest() != expected_sha256:
                    raise RuntimeError("concurrent modification detected before rename: sha256 changed")
            original_mode = (attrs.permissions & 0o7777) if attrs.permissions is not None else None
            await self._atomic_write(client, canonical, out, overwrite=True, mode=original_mode)
            return {
                "path": canonical,
                "replacements": count,
                "before_sha256": digest,
                "after_sha256": hashlib.sha256(out).hexdigest(),
                "bytes_written": len(out),
            }

    async def file_search(
        self,
        server: str,
        root: str,
        pattern: str,
        *,
        search_type: str = "files",
        ignore_case: bool = True,
        max_results: int | None = None,
    ) -> dict[str, Any]:
        self._check_permission(server)
        if not pattern:
            raise ValueError("pattern must not be empty")
        canonical = await self.paths.canonicalize(server, root)
        if max_results is not None and max_results <= 0:
            raise ValueError("max_results must be > 0")
        limit = min(
            max_results or self.settings.limits.search_max_results,
            self.settings.limits.search_max_results,
        )
        qroot = shlex.quote(canonical)
        qpattern = shlex.quote(pattern)
        if search_type == "files":
            name_flag = "-iname" if ignore_case else "-name"
            command = f"find {qroot} -type f {name_flag} {qpattern} -print | head -n {limit + 1}"
        elif search_type == "content":
            case_flag = "-i" if ignore_case else ""
            command = f"grep -r -I -n -F {case_flag} -- {qpattern} {qroot} | head -n {limit + 1}"
        else:
            raise ValueError("search_type must be 'files' or 'content'")
        result = await self.ssh.run(
            server,
            command,
            timeout=30,
            max_output_bytes=self.settings.limits.shell_output_max_bytes,
        )
        if result.timed_out:
            raise TimeoutError("file search timed out")
        if result.exit_code not in (0, 1):
            raise RuntimeError(result.stderr or "file search failed")
        lines = result.stdout.splitlines()
        return {
            "root": canonical,
            "results": lines[:limit],
            "truncated": len(lines) > limit or result.truncated,
        }
