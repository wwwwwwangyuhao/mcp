from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urljoin

from mcp.server import MCPServer
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl

from .auth import StaticBearerTokenVerifier
from .config import Settings
from .jobs.manager import JobManager
from .security.audit import AuditLogger
from .security.remote_paths import RemotePathAuthorizer
from .ssh.manager import SSHConnectionManager
from .tools.filesystem import FilesystemService


@dataclass
class Services:
    settings: Settings
    ssh: SSHConnectionManager
    paths: RemotePathAuthorizer
    fs: FilesystemService
    jobs: JobManager
    audit: AuditLogger


def build_services(settings: Settings) -> Services:
    ssh = SSHConnectionManager(settings)
    paths = RemotePathAuthorizer(ssh)
    return Services(
        settings=settings,
        ssh=ssh,
        paths=paths,
        fs=FilesystemService(settings, ssh, paths),
        jobs=JobManager(settings, ssh, paths),
        audit=AuditLogger(settings.state_dir, settings.audit_commands),
    )


def build_server(settings: Settings, services: Services | None = None) -> MCPServer:
    svc = services or build_services(settings)
    verifier = None
    auth = None
    if settings.http.enabled:
        if not os.environ.get(settings.http.bearer_token_env):
            raise RuntimeError(
                f"HTTP mode requires bearer token environment variable "
                f"{settings.http.bearer_token_env!r}"
            )
        verifier = StaticBearerTokenVerifier(settings.http.bearer_token_env)
        issuer = settings.http.public_url.rstrip("/") + "/"
        resource = urljoin(issuer, settings.http.path.lstrip("/"))
        auth = AuthSettings(
            issuer_url=AnyHttpUrl(issuer),
            resource_server_url=AnyHttpUrl(resource),
            required_scopes=[],
            validate_token_resource=False,
        )

    server = MCPServer(
        name="Personal Linux MCP",
        description="Personal multi-server Linux administration gateway over SSH.",
        version="0.1.0",
        token_verifier=verifier,
        auth=auth,
    )

    def require_read(alias: str) -> None:
        if not svc.ssh.server(alias).permissions.read:
            raise PermissionError(f"read permission is disabled for {alias!r}")

    @server.tool()
    async def servers_list() -> dict:
        """List configured server aliases and enabled capabilities without opening SSH."""
        with svc.audit.event("servers_list") as ev:
            out = {
                "servers": [
                    {
                        "alias": alias,
                        "host": cfg.host,
                        "port": cfg.port,
                        "user": cfg.user,
                        "allowed_roots": cfg.allowed_roots,
                        "permissions": cfg.permissions.model_dump(),
                    }
                    for alias, cfg in settings.servers.items()
                ]
            }
            svc.audit.finish(ev, "ok", returned_bytes=len(str(out).encode()))
            return out

    @server.tool()
    async def server_info(server: str) -> dict:
        """Return hostname, kernel and uptime for one configured Linux server."""
        require_read(server)
        with svc.audit.event("server_info", server) as ev:
            result = await svc.ssh.run(
                server,
                "printf 'hostname='; hostname; printf 'kernel='; uname -sr; "
                "printf 'uptime_seconds='; cut -d' ' -f1 /proc/uptime",
                timeout=10,
            )
            svc.audit.finish(
                ev,
                "ok" if result.exit_code == 0 else "error",
                result.exit_code,
                len(result.stdout.encode()) + len(result.stderr.encode()),
            )
            return result.model_dump()

    @server.tool()
    async def directory_list(
        server: str,
        path: str,
        offset: int = 0,
        limit: int | None = None,
    ) -> dict:
        """List one bounded page of a canonical remote directory."""
        with svc.audit.event("directory_list", server, path) as ev:
            out = await svc.fs.directory_list(
                server, path, offset=offset, limit=limit
            )
            svc.audit.finish(ev, "ok", returned_bytes=len(str(out).encode()))
            return out

    @server.tool()
    async def file_stat(server: str, path: str) -> dict:
        """Return metadata for a canonical remote filesystem path."""
        with svc.audit.event("file_stat", server, path) as ev:
            out = await svc.fs.file_stat(server, path)
            svc.audit.finish(ev, "ok", returned_bytes=len(str(out).encode()))
            return out

    @server.tool()
    async def file_read(
        server: str,
        path: str,
        offset: int = 0,
        length: int | None = None,
    ) -> dict:
        """Read a bounded UTF-8 chunk. Byte cursors always end on UTF-8 boundaries."""
        with svc.audit.event("file_read", server, path) as ev:
            out = await svc.fs.file_read(server, path, offset=offset, length=length)
            svc.audit.finish(ev, "ok", returned_bytes=out.bytes_read)
            return out.model_dump()

    @server.tool()
    async def file_write(
        server: str,
        path: str,
        content: str,
        mode: str = "create",
        expected_size: int | None = None,
        expected_mtime: int | None = None,
    ) -> dict:
        """Create or explicitly overwrite a UTF-8 file using same-directory atomic rename."""
        with svc.audit.event("file_write", server, path) as ev:
            out = await svc.fs.file_write(
                server,
                path,
                content,
                mode=mode,
                expected_size=expected_size,
                expected_mtime=expected_mtime,
            )
            svc.audit.finish(ev, "ok")
            return out

    @server.tool()
    async def file_patch(
        server: str,
        path: str,
        old_string: str,
        new_string: str,
        expected_replacements: int = 1,
        expected_sha256: str | None = None,
    ) -> dict:
        """Exact text replacement; ambiguous counts fail before atomic replacement."""
        with svc.audit.event("file_patch", server, path) as ev:
            out = await svc.fs.file_patch(
                server,
                path,
                old_string,
                new_string,
                expected_replacements=expected_replacements,
                expected_sha256=expected_sha256,
            )
            svc.audit.finish(ev, "ok")
            return out

    @server.tool()
    async def file_search(
        server: str,
        root: str,
        pattern: str,
        search_type: str = "files",
        ignore_case: bool = True,
        max_results: int | None = None,
    ) -> dict:
        """Search names or literal content beneath one canonical allowed root."""
        with svc.audit.event("file_search", server, root) as ev:
            out = await svc.fs.file_search(
                server,
                root,
                pattern,
                search_type=search_type,
                ignore_case=ignore_case,
                max_results=max_results,
            )
            svc.audit.finish(ev, "ok", returned_bytes=len(str(out).encode()))
            return out

    @server.tool()
    async def shell_exec(
        server: str,
        command: str,
        cwd: str | None = None,
        timeout: float = 30.0,
        max_output_bytes: int | None = None,
    ) -> dict:
        """Run one foreground shell command with bounded in-memory stdout/stderr."""
        cfg = svc.ssh.server(server)
        if not cfg.permissions.shell:
            raise PermissionError(f"shell permission is disabled for {server!r}")
        if not command or "\x00" in command:
            raise ValueError("command must be non-empty and contain no NUL bytes")
        if cwd is not None:
            cwd = await svc.paths.canonicalize(server, cwd)
        with svc.audit.event("shell_exec", server, cwd) as ev:
            result = await svc.ssh.run(
                server,
                command,
                cwd=cwd,
                timeout=timeout,
                max_output_bytes=max_output_bytes,
            )
            svc.audit.finish(
                ev,
                "timeout"
                if result.timed_out
                else "truncated"
                if result.truncated
                else "ok"
                if result.exit_code == 0
                else "error",
                result.exit_code,
                len(result.stdout.encode()) + len(result.stderr.encode()),
                command if settings.audit_commands else None,
            )
            return result.model_dump()

    @server.tool()
    async def job_start(server: str, command: str, cwd: str | None = None) -> dict:
        """Start one detached durable job. Ambiguous launch is reported and never replayed."""
        if cwd is not None:
            cwd = await svc.paths.canonicalize(server, cwd)
        with svc.audit.event("job_start", server, cwd) as ev:
            out = await svc.jobs.start(server, command, cwd)
            svc.audit.finish(
                ev,
                "ok" if out.status == "running" else out.status,
                detail=command if settings.audit_commands else None,
            )
            return out.model_dump(mode="json")

    @server.tool()
    async def job_status(job_id: str) -> dict:
        """Reconcile job state from SQLite plus durable remote runner metadata."""
        with svc.audit.event("job_status", target=job_id) as ev:
            out = await svc.jobs.status(job_id)
            svc.audit.finish(ev, "ok")
            return out.model_dump(mode="json")

    @server.tool()
    async def job_logs(
        job_id: str,
        cursor: int = 0,
        max_bytes: int | None = None,
        max_lines: int | None = None,
    ) -> dict:
        """Read a bounded incremental slice of the durable remote job log."""
        with svc.audit.event("job_logs", target=job_id) as ev:
            out = await svc.jobs.logs(job_id, cursor, max_bytes, max_lines)
            svc.audit.finish(ev, "ok", returned_bytes=len(out.content.encode()))
            return out.model_dump()

    @server.tool()
    async def job_stdin(job_id: str, data: str) -> dict:
        """Send bounded stdin bytes through the durable job FIFO."""
        with svc.audit.event("job_stdin", target=job_id) as ev:
            out = await svc.jobs.stdin(job_id, data)
            svc.audit.finish(ev, "ok")
            return out

    @server.tool()
    async def job_terminate(
        job_id: str, grace_seconds: float | None = None
    ) -> dict:
        """Terminate only after PID and /proc start-ticks identity both match."""
        with svc.audit.event("job_terminate", target=job_id) as ev:
            out = await svc.jobs.terminate(job_id, grace_seconds)
            svc.audit.finish(ev, "ok" if out["status"] == "terminated" else out["status"])
            return out

    @server.tool()
    async def process_list(server: str, limit: int = 100) -> dict:
        """List top Linux processes by CPU use."""
        require_read(server)
        limit = max(1, min(limit, 500))
        with svc.audit.event("process_list", server) as ev:
            result = await svc.ssh.run(
                server,
                f"ps -eo pid=,ppid=,stat=,%cpu=,%mem=,comm= --sort=-%cpu | head -n {limit}",
                timeout=10,
            )
            svc.audit.finish(
                ev,
                "ok" if result.exit_code == 0 else "error",
                result.exit_code,
                len(result.stdout.encode()) + len(result.stderr.encode()),
            )
            return result.model_dump()

    @server.tool()
    async def system_status(server: str) -> dict:
        """Return CPU, RAM, disk and optional NVIDIA GPU status without modifying the server."""
        require_read(server)
        command = (
            "printf '%s\\n' '---cpu---'; nproc; "
            "printf '%s\\n' '---memory---'; grep -E 'MemTotal|MemAvailable' /proc/meminfo; "
            "printf '%s\\n' '---disk---'; df -P -h; "
            "printf '%s\\n' '---gpu---'; "
            "if command -v nvidia-smi >/dev/null 2>&1; then "
            "nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu "
            "--format=csv,noheader,nounits; else echo 'nvidia-smi unavailable'; fi"
        )
        with svc.audit.event("system_status", server) as ev:
            result = await svc.ssh.run(server, command, timeout=15)
            svc.audit.finish(
                ev,
                "ok" if result.exit_code == 0 else "error",
                result.exit_code,
                len(result.stdout.encode()) + len(result.stderr.encode()),
            )
            return result.model_dump()

    server._personal_linux_services = svc  # type: ignore[attr-defined]
    return server
