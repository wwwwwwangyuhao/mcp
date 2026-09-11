from __future__ import annotations

import asyncio
import shlex
from contextlib import asynccontextmanager
from time import monotonic
from typing import Any, AsyncIterator

import asyncssh

from ..config import ServerConfig, Settings
from ..models import ShellResult


class CommandDispatchUncertainError(RuntimeError):
    """A command-carrying SSH API failed after dispatch may have begun.

    The gateway must never retry the same command automatically after this error.
    """


class SSHConnectionManager:
    """One reusable verified SSH transport per configured server alias."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._connections: dict[str, asyncssh.SSHClientConnection] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._semaphores: dict[str, asyncio.Semaphore] = {}

    def server(self, alias: str) -> ServerConfig:
        try:
            return self.settings.servers[alias]
        except KeyError as exc:
            raise KeyError(f"unknown server alias: {alias!r}") from exc

    def _lock(self, alias: str) -> asyncio.Lock:
        return self._locks.setdefault(alias, asyncio.Lock())

    def _semaphore(self, alias: str) -> asyncio.Semaphore:
        if alias not in self._semaphores:
            self._semaphores[alias] = asyncio.Semaphore(
                self.server(alias).max_concurrent_channels
            )
        return self._semaphores[alias]

    @staticmethod
    def _connect_kwargs(cfg: ServerConfig) -> dict[str, object]:
        kwargs: dict[str, object] = {"host": cfg.host}
        if cfg.port is not None:
            kwargs["port"] = cfg.port
        if cfg.user is not None:
            kwargs["username"] = cfg.user
        if cfg.ssh_config:
            kwargs["config"] = [cfg.ssh_config]
        if cfg.identity_file:
            kwargs["client_keys"] = [cfg.identity_file]
        # Deliberately never pass known_hosts=None. When omitted, AsyncSSH
        # keeps its normal verified known-hosts behavior.
        if cfg.known_hosts:
            kwargs["known_hosts"] = cfg.known_hosts
        return kwargs

    async def connection(self, alias: str) -> asyncssh.SSHClientConnection:
        cfg = self.server(alias)
        existing = self._connections.get(alias)
        if existing is not None and not existing.is_closed():
            return existing
        async with self._lock(alias):
            existing = self._connections.get(alias)
            if existing is not None and not existing.is_closed():
                return existing
            conn = await asyncio.wait_for(
                asyncssh.connect(**self._connect_kwargs(cfg)),
                cfg.connect_timeout_seconds,
            )
            conn.set_keepalive(interval=30, count_max=3)
            self._connections[alias] = conn
            return conn

    def invalidate(self, alias: str) -> None:
        stale = self._connections.pop(alias, None)
        if stale is not None:
            stale.close()

    async def close(self) -> None:
        conns = list(self._connections.values())
        self._connections.clear()
        for conn in conns:
            conn.close()
        for conn in conns:
            try:
                await conn.wait_closed()
            except Exception:
                pass

    @staticmethod
    def wrap_cwd(command: str, cwd: str | None) -> str:
        if cwd is None:
            return command
        return f"cd -- {shlex.quote(cwd)} && {command}"

    async def _stop_process(
        self, process: Any, wait_task: asyncio.Task, grace: float
    ) -> bool:
        """Best-effort TERM/KILL cleanup; return whether remote state is uncertain."""
        uncertain = False
        try:
            process.terminate()
        except Exception:
            uncertain = True
        try:
            await asyncio.wait_for(asyncio.shield(wait_task), timeout=grace)
            return uncertain
        except asyncio.TimeoutError:
            pass
        except Exception:
            return True
        try:
            process.kill()
        except Exception:
            uncertain = True
        try:
            await asyncio.wait_for(asyncio.shield(wait_task), timeout=grace)
        except Exception:
            uncertain = True
        return uncertain

    async def run(
        self,
        alias: str,
        command: str,
        *,
        cwd: str | None = None,
        timeout: float = 30.0,
        max_output_bytes: int | None = None,
    ) -> ShellResult:
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        if not command or "\x00" in command:
            raise ValueError("command must be non-empty and contain no NUL bytes")
        if len(command.encode("utf-8")) > self.settings.limits.command_max_bytes:
            raise ValueError("command exceeds configured command_max_bytes")
        global_limit = self.settings.limits.shell_output_max_bytes
        limit = min(max_output_bytes or global_limit, global_limit)
        if limit <= 0:
            raise ValueError("max_output_bytes must be > 0")

        started = monotonic()
        stdout_buf = bytearray()
        stderr_buf = bytearray()
        retained = 0
        budget_lock = asyncio.Lock()
        output_exceeded = asyncio.Event()

        async def pump(reader: Any, target: bytearray) -> None:
            nonlocal retained
            while True:
                chunk = await reader.read(16 * 1024)
                if not chunk:
                    return
                raw = (
                    chunk
                    if isinstance(chunk, bytes)
                    else str(chunk).encode("utf-8", errors="replace")
                )
                async with budget_lock:
                    remaining = limit - retained
                    if remaining <= 0:
                        output_exceeded.set()
                        return
                    target.extend(raw[:remaining])
                    retained += min(len(raw), remaining)
                    if len(raw) > remaining:
                        output_exceeded.set()
                        return

        async with self._semaphore(alias):
            # A failure obtaining/recreating a transport occurs before command
            # dispatch and is therefore not wrapped as dispatch-uncertain.
            conn = await self.connection(alias)
            process: Any | None = None
            try:
                try:
                    # Dispatch boundary: this exact command is never replayed by
                    # the gateway after this API call is attempted.
                    process = await asyncio.wait_for(
                        conn.create_process(self.wrap_cwd(command, cwd), encoding=None),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError as exc:
                    self.invalidate(alias)
                    raise CommandDispatchUncertainError(
                        "SSH command dispatch timed out after execution may have begun; not retried"
                    ) from exc
                except (asyncssh.Error, OSError) as exc:
                    self.invalidate(alias)
                    raise CommandDispatchUncertainError(
                        "SSH command dispatch failed after execution may have begun; not retried"
                    ) from exc

                stdout_task = asyncio.create_task(pump(process.stdout, stdout_buf))
                stderr_task = asyncio.create_task(pump(process.stderr, stderr_buf))
                wait_task = asyncio.create_task(process.wait_closed())
                budget_task = asyncio.create_task(output_exceeded.wait())

                done, _ = await asyncio.wait(
                    {wait_task, budget_task},
                    timeout=timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                timed_out = not done
                output_limited = (
                    budget_task in done
                    and output_exceeded.is_set()
                    and not wait_task.done()
                )
                cleanup_attempted = timed_out or output_limited
                remote_uncertain = False

                if cleanup_attempted:
                    remote_uncertain = await self._stop_process(
                        process,
                        wait_task,
                        self.settings.jobs.terminate_grace_seconds,
                    )

                try:
                    completed = wait_task.done()
                    if completed:
                        wait_task.result()
                except Exception as exc:
                    self.invalidate(alias)
                    stdout_task.cancel()
                    stderr_task.cancel()
                    await asyncio.gather(
                        stdout_task, stderr_task, return_exceptions=True
                    )
                    raise CommandDispatchUncertainError(
                        "SSH transport failed after command dispatch; command was not retried"
                    ) from exc

                if not budget_task.done():
                    budget_task.cancel()
                await asyncio.gather(budget_task, return_exceptions=True)
                reader_results = await asyncio.gather(
                    stdout_task, stderr_task, return_exceptions=True
                )
                for reader_result in reader_results:
                    if not isinstance(reader_result, BaseException):
                        continue
                    if isinstance(reader_result, (asyncssh.Error, OSError)):
                        self.invalidate(alias)
                        if cleanup_attempted:
                            remote_uncertain = True
                            continue
                        raise CommandDispatchUncertainError(
                            "SSH output stream failed after command dispatch; command was not retried"
                        ) from reader_result
                    raise reader_result

                # A fast command can exit before its readers observe excess
                # buffered output. Honor the shared cap even in that race.
                output_limited = output_limited or output_exceeded.is_set()
                exit_status = getattr(process, "exit_status", getattr(process, "_exit_status", None))
                exit_code = None if timed_out or output_limited else exit_status
                return ShellResult(
                    stdout=bytes(stdout_buf).decode("utf-8", errors="replace"),
                    stderr=bytes(stderr_buf).decode("utf-8", errors="replace"),
                    exit_code=exit_code,
                    timed_out=timed_out,
                    output_limited=output_limited,
                    truncated=output_limited,
                    cleanup_attempted=cleanup_attempted,
                    remote_state_uncertain=remote_uncertain,
                    duration_ms=int((monotonic() - started) * 1000),
                )
            finally:
                if process is not None and hasattr(process, "is_closing"):
                    try:
                        if process.is_closing():
                            await process.wait_closed()
                    except Exception:
                        pass

    async def write_process_stdin(
        self,
        alias: str,
        command: str,
        data: bytes,
        *,
        timeout: float,
    ) -> int:
        """Run a short stdin sink once; never replay after command dispatch."""
        if len(command.encode("utf-8")) > self.settings.limits.command_max_bytes:
            raise ValueError("command exceeds configured command_max_bytes")
        async with self._semaphore(alias):
            conn = await self.connection(alias)
            try:
                process = await asyncio.wait_for(
                    conn.create_process(command, encoding=None), timeout=timeout
                )
            except asyncio.TimeoutError as exc:
                self.invalidate(alias)
                raise CommandDispatchUncertainError(
                    "SSH stdin command dispatch timed out; delivery state is uncertain and was not retried"
                ) from exc
            except (asyncssh.Error, OSError) as exc:
                self.invalidate(alias)
                raise CommandDispatchUncertainError(
                    "SSH stdin command dispatch became uncertain; not retried"
                ) from exc
            try:
                process.stdin.write(data)

                async def deliver() -> None:
                    await process.stdin.drain()
                    process.stdin.write_eof()
                    await process.wait_closed()

                delivery_task = asyncio.create_task(deliver())
                try:
                    await asyncio.wait_for(asyncio.shield(delivery_task), timeout=timeout)
                except asyncio.TimeoutError as exc:
                    delivery_task.cancel()
                    await asyncio.gather(delivery_task, return_exceptions=True)
                    wait_task = asyncio.create_task(process.wait_closed())
                    await self._stop_process(
                        process, wait_task, self.settings.jobs.terminate_grace_seconds
                    )
                    raise CommandDispatchUncertainError(
                        "SSH stdin delivery timed out after dispatch; delivery may be partial and was not retried"
                    ) from exc
                exit_status = getattr(process, "exit_status", None)
                if exit_status not in (None, 0):
                    raise RuntimeError(
                        f"remote stdin sink exited with status {exit_status}"
                    )
                return len(data)
            except (asyncssh.Error, OSError) as exc:
                self.invalidate(alias)
                raise CommandDispatchUncertainError(
                    "SSH stdin delivery became uncertain after dispatch; not retried"
                ) from exc

    @asynccontextmanager
    async def sftp(self, alias: str) -> AsyncIterator[asyncssh.SFTPClient]:
        async with self._semaphore(alias):
            conn = await self.connection(alias)
            client = await conn.start_sftp_client()
            try:
                yield client
            finally:
                client.exit()
                try:
                    await client.wait_closed()
                except Exception:
                    pass
