from __future__ import annotations

import asyncio
import posixpath
import re
import shlex
import uuid
from datetime import datetime
from typing import Any

import asyncssh

from ..config import Settings
from ..models import JobLogsResult, JobStartResult, JobStatusResult, utcnow
from ..security.remote_paths import RemotePathAuthorizer
from ..ssh.manager import CommandDispatchUncertainError, SSHConnectionManager
from .store import JobStore


_LAUNCH_MARKER = "__PLMCP_LAUNCHED__:"
_RUNNER = r'''#!/bin/sh
umask 077
RUN_CWD=$(pwd)
JOBDIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 125
cd "$JOBDIR" || exit 125
: > "$JOBDIR/job.log"
rm -f "$JOBDIR/stdin.fifo"
if ! mkfifo -m 600 "$JOBDIR/stdin.fifo"; then
  printf '%s\n' failed > "$JOBDIR/status"
  printf '%s\n' 125 > "$JOBDIR/exit_code"
  exit 125
fi
exec 3<> "$JOBDIR/stdin.fifo"
printf '%s\n' "$$" > "$JOBDIR/pid"
awk '{print $22}' "/proc/$$/stat" > "$JOBDIR/start_ticks"
printf '%s\n' running > "$JOBDIR/status"
command=$(cat "$JOBDIR/command.sh")
rm -f "$JOBDIR/command.sh"
term_requested=0
child=
on_term() {
  term_requested=1
  if [ -n "$child" ]; then kill -TERM "$child" 2>/dev/null || true; fi
}
trap on_term TERM INT HUP
cd "$RUN_CWD" || {
  printf '%s\n' failed > "$JOBDIR/status"
  printf '%s\n' 125 > "$JOBDIR/exit_code"
  exit 125
}
/bin/sh -lc "$command" <&3 >> "$JOBDIR/job.log" 2>&1 &
child=$!
while :; do
  wait "$child"
  rc=$?
  if kill -0 "$child" 2>/dev/null; then
    continue
  fi
  break
done
printf '%s\n' "$rc" > "$JOBDIR/exit_code.tmp"
mv -f "$JOBDIR/exit_code.tmp" "$JOBDIR/exit_code"
if [ "$term_requested" -eq 1 ]; then
  state=terminated
elif [ "$rc" -eq 0 ]; then
  state=completed
else
  state=failed
fi
printf '%s\n' "$state" > "$JOBDIR/status.tmp"
mv -f "$JOBDIR/status.tmp" "$JOBDIR/status"
exit "$rc"
'''


class JobManager:
    def __init__(
        self,
        settings: Settings,
        ssh: SSHConnectionManager,
        paths: RemotePathAuthorizer | None = None,
    ):
        self.settings = settings
        self.ssh = ssh
        self.paths = paths or RemotePathAuthorizer(ssh)
        self.store = JobStore(settings.state_dir)

    def _get_authorized_row(self, job_id: str) -> dict[str, Any]:
        row = self.store.get(job_id)
        if not self.ssh.server(row["server"]).permissions.jobs:
            raise PermissionError(
                f"job permission is disabled for {row['server']!r}"
            )
        return row

    def _row_to_status(
        self,
        row: dict[str, Any],
        *,
        status: str | None = None,
        message: str | None = None,
        reachable: bool | None = None,
    ) -> JobStatusResult:
        return JobStatusResult(
            job_id=row["job_id"],
            server=row["server"],
            status=status or row["status"],
            exit_code=row.get("exit_code"),
            started_at=datetime.fromisoformat(row["started_at"]),
            ended_at=datetime.fromisoformat(row["ended_at"]) if row.get("ended_at") else None,
            remote_pid=row.get("remote_pid"),
            start_ticks=row.get("start_ticks"),
            remote_dir=row["remote_dir"],
            reachable=reachable,
            message=message if message is not None else row.get("message"),
        )

    async def _read_remote_text(
        self, client: Any, path: str, *, max_bytes: int = 4096
    ) -> str | None:
        try:
            handle = await client.open(path, "rb")
        except asyncssh.SFTPNoSuchFile:
            return None
        try:
            data = await handle.read(max_bytes + 1)
        finally:
            handle.close()
        raw = data if isinstance(data, bytes) else data.encode("utf-8")
        if len(raw) > max_bytes:
            raise ValueError(f"remote metadata file too large: {path}")
        return raw.decode("utf-8", errors="strict").strip()

    async def _write_new_file(
        self, client: Any, path: str, data: bytes, mode: int = 0o600
    ) -> None:
        handle = await client.open(path, "xb")
        try:
            await handle.write(data)
        finally:
            handle.close()
        await client.chmod(path, mode)

    async def _prepare_remote_job(
        self, server: str, job_id: str, command: str
    ) -> str:
        cfg = self.ssh.server(server)
        if not cfg.job_root:
            raise RuntimeError(
                f"jobs are enabled on {server!r} but job_root is not configured"
            )
        async with self.ssh.sftp(server) as client:
            canonical_root = await self.paths.canonicalize_with_client(
                client, server, cfg.job_root, allow_missing_leaf=True
            )
            job_dir = posixpath.join(canonical_root, job_id)
            await client.makedirs(job_dir, exist_ok=False)
            await client.chmod(job_dir, 0o700)
            # Re-resolve the directory after creation to close the missing-leaf
            # authorization gap before placing command material inside it.
            job_dir = await self.paths.canonicalize_with_client(client, server, job_dir)
            await self._write_new_file(
                client,
                posixpath.join(job_dir, "command.sh"),
                command.encode("utf-8"),
                0o600,
            )
            await self._write_new_file(
                client,
                posixpath.join(job_dir, "runner.sh"),
                _RUNNER.encode("utf-8"),
                0o700,
            )
            await self._write_new_file(
                client,
                posixpath.join(job_dir, "status"),
                b"unknown\n",
                0o600,
            )
            return job_dir

    async def start(
        self, server: str, command: str, cwd: str | None = None
    ) -> JobStartResult:
        cfg = self.ssh.server(server)
        if not cfg.permissions.jobs:
            raise PermissionError(f"job permission is disabled for {server!r}")
        if not command or "\x00" in command:
            raise ValueError("command must be non-empty and contain no NUL bytes")
        if len(command.encode("utf-8")) > self.settings.limits.command_max_bytes:
            raise ValueError("command exceeds configured command_max_bytes")
        job_id = str(uuid.uuid4())
        started = utcnow()
        remote_dir = await self._prepare_remote_job(server, job_id, command)
        row = {
            "job_id": job_id,
            "server": server,
            "cwd": cwd,
            "remote_dir": remote_dir,
            "status": "unknown",
            "exit_code": None,
            "remote_pid": None,
            "start_ticks": None,
            "started_at": started.isoformat(),
            "ended_at": None,
            "termination_requested": 0,
            "message": "launch prepared; awaiting acknowledgement",
        }
        self.store.insert(row)
        runner = shlex.quote(posixpath.join(remote_dir, "runner.sh"))
        launch = (
            f"nohup setsid /bin/sh {runner} >/dev/null 2>&1 </dev/null & "
            f"printf '{_LAUNCH_MARKER}%s\\n' \"$!\""
        )
        try:
            result = await self.ssh.run(
                server,
                launch,
                cwd=cwd,
                timeout=self.settings.jobs.launch_timeout_seconds,
                max_output_bytes=16 * 1024,
            )
        except CommandDispatchUncertainError:
            message = (
                "SSH failed after launch dispatch began; the job may be running and "
                "the launch was not retried"
            )
            self.store.update(job_id, status="unknown", message=message)
            return JobStartResult(
                job_id=job_id, server=server, cwd=cwd, remote_dir=remote_dir,
                status="unknown", started_at=started, message=message,
            )
        except (asyncio.TimeoutError, asyncssh.Error, OSError) as exc:
            message = f"launch failed before acknowledgement: {type(exc).__name__}: {exc}"
            self.store.update(
                job_id, status="failed", message=message, ended_at=utcnow().isoformat()
            )
            return JobStartResult(
                job_id=job_id, server=server, cwd=cwd, remote_dir=remote_dir,
                status="failed", started_at=started, message=message,
            )
        if result.timed_out or result.truncated:
            message = (
                "launch acknowledgement was not observed; remote execution state is "
                "uncertain and was not retried"
            )
            self.store.update(job_id, status="unknown", message=message)
            return JobStartResult(
                job_id=job_id,
                server=server,
                cwd=cwd,
                remote_dir=remote_dir,
                status="unknown",
                started_at=started,
                message=message,
            )
        match = re.search(rf"{re.escape(_LAUNCH_MARKER)}(\d+)", result.stdout)
        if result.exit_code != 0 or match is None:
            message = result.stderr.strip() or "launch returned without a valid acknowledgement"
            state = "failed" if result.exit_code not in (None, 0) else "unknown"
            self.store.update(
                job_id,
                status=state,
                message=message,
                ended_at=utcnow().isoformat() if state == "failed" else None,
            )
            return JobStartResult(
                job_id=job_id,
                server=server,
                cwd=cwd,
                remote_dir=remote_dir,
                status=state,
                started_at=started,
                message=message,
            )
        remote_pid = int(match.group(1))
        self.store.update(
            job_id, status="running", remote_pid=remote_pid, message=None
        )
        status = await self.status(job_id)
        return JobStartResult(
            job_id=job_id,
            remote_pid=status.remote_pid,
            server=server,
            cwd=cwd,
            remote_dir=remote_dir,
            status=status.status,
            started_at=started,
            message=status.message,
        )

    async def _pid_identity_matches(
        self, server: str, pid: int, start_ticks: int
    ) -> bool | None:
        if pid <= 0 or start_ticks <= 0:
            return False
        try:
            result = await self.ssh.run(
                server,
                f"awk '{{print $22}}' /proc/{pid}/stat 2>/dev/null",
                timeout=self.settings.jobs.status_timeout_seconds,
                max_output_bytes=4096,
            )
        except (CommandDispatchUncertainError, asyncssh.Error, OSError):
            return None
        if result.timed_out or result.truncated:
            return None
        if result.exit_code != 0:
            return False
        return result.stdout.strip() == str(start_ticks)

    async def status(self, job_id: str) -> JobStatusResult:
        row = self._get_authorized_row(job_id)
        server = row["server"]
        remote_dir = row["remote_dir"]
        try:
            async with self.ssh.sftp(server) as client:
                state = await self._read_remote_text(
                    client, posixpath.join(remote_dir, "status")
                )
                pid_text = await self._read_remote_text(
                    client, posixpath.join(remote_dir, "pid")
                )
                ticks_text = await self._read_remote_text(
                    client, posixpath.join(remote_dir, "start_ticks")
                )
                exit_text = await self._read_remote_text(
                    client, posixpath.join(remote_dir, "exit_code")
                )
        except (asyncssh.Error, OSError) as exc:
            return self._row_to_status(
                row,
                status=row["status"],
                reachable=False,
                message=f"remote host unreachable during reconciliation: {type(exc).__name__}",
            )

        pid = int(pid_text) if pid_text and pid_text.isdigit() else row.get("remote_pid")
        ticks = (
            int(ticks_text)
            if ticks_text and ticks_text.isdigit()
            else row.get("start_ticks")
        )
        exit_code = (
            int(exit_text)
            if exit_text and re.fullmatch(r"-?\d+", exit_text)
            else row.get("exit_code")
        )
        if state in {"completed", "failed", "terminated"}:
            ended = row.get("ended_at") or utcnow().isoformat()
            self.store.update(
                job_id,
                status=state,
                exit_code=exit_code,
                remote_pid=pid,
                start_ticks=ticks,
                ended_at=ended,
                message=None,
            )
            return self._row_to_status(self.store.get(job_id), reachable=True)

        if state == "running" and pid and ticks:
            matches = await self._pid_identity_matches(server, pid, ticks)
            if matches is None:
                return self._row_to_status(
                    row,
                    status="unknown",
                    reachable=True,
                    message="process identity could not be verified because the status probe was unavailable",
                )
            if matches:
                self.store.update(
                    job_id,
                    status="running",
                    remote_pid=pid,
                    start_ticks=ticks,
                    message=None,
                )
                return self._row_to_status(self.store.get(job_id), reachable=True)
            final_state = "terminated" if row.get("termination_requested") else "orphaned"
            message = (
                "recorded process identity is no longer alive and no final runner "
                "status was observed"
            )
            self.store.update(
                job_id,
                status=final_state,
                remote_pid=pid,
                start_ticks=ticks,
                ended_at=utcnow().isoformat(),
                message=message,
            )
            return self._row_to_status(self.store.get(job_id), reachable=True)

        message = "remote runner has not produced a verifiable running or final state"
        self.store.update(
            job_id,
            status="unknown",
            remote_pid=pid,
            start_ticks=ticks,
            exit_code=exit_code,
            message=message,
        )
        return self._row_to_status(self.store.get(job_id), reachable=True)

    async def logs(
        self,
        job_id: str,
        cursor: int = 0,
        max_bytes: int | None = None,
        max_lines: int | None = None,
    ) -> JobLogsResult:
        if cursor < 0:
            raise ValueError("cursor must be >= 0")
        row = self._get_authorized_row(job_id)
        limit = min(
            max_bytes or self.settings.limits.job_log_read_max_bytes,
            self.settings.limits.job_log_read_max_bytes,
        )
        line_limit = min(
            max_lines or self.settings.limits.job_log_max_lines,
            self.settings.limits.job_log_max_lines,
        )
        if limit <= 0 or line_limit <= 0:
            raise ValueError("log limits must be > 0")

        log_path = posixpath.join(row["remote_dir"], "job.log")
        missing = False
        async with self.ssh.sftp(row["server"]) as client:
            try:
                attrs = await client.stat(log_path)
            except asyncssh.SFTPNoSuchFile:
                missing = True
                size = 0
                data = b""
            else:
                size = attrs.size or 0
                if cursor > size:
                    raise ValueError(
                        f"cursor {cursor} is beyond current log size {size}"
                    )
                handle = await client.open(log_path, "rb")
                try:
                    data = await handle.read(limit + 1, cursor)
                finally:
                    handle.close()

        if missing:
            if cursor != 0:
                raise ValueError("cursor is beyond current log size 0")
            status = await self.status(job_id)
            return JobLogsResult(
                job_id=job_id, content="", cursor=0, next_cursor=0,
                size=0, eof=status.status != "running", truncated=False,
            )

        raw = data if isinstance(data, bytes) else data.encode("utf-8")
        candidate = raw[:limit]
        parts = candidate.splitlines(keepends=True)
        consumed = (
            b"".join(parts[:line_limit])
            if len(parts) > line_limit
            else candidate
        )
        next_cursor = cursor + len(consumed)
        status = await self.status(job_id)
        eof = (
            status.status in {"completed", "failed", "terminated", "orphaned"}
            and next_cursor >= size
        )
        return JobLogsResult(
            job_id=job_id,
            content=consumed.decode("utf-8", errors="replace"),
            cursor=cursor,
            next_cursor=next_cursor,
            size=size,
            eof=eof,
            truncated=next_cursor < size or len(raw) > len(consumed),
        )

    async def stdin(self, job_id: str, data: str) -> dict[str, Any]:
        raw = data.encode("utf-8")
        if len(raw) > self.settings.limits.job_stdin_max_bytes:
            raise ValueError("stdin payload exceeds configured job_stdin_max_bytes")
        status = await self.status(job_id)
        if status.status != "running":
            raise RuntimeError(f"job is not running (status={status.status})")
        fifo = shlex.quote(posixpath.join(status.remote_dir, "stdin.fifo"))
        sent = await self.ssh.write_process_stdin(
            status.server,
            f"cat > {fifo}",
            raw,
            timeout=self.settings.jobs.status_timeout_seconds,
        )
        return {"job_id": job_id, "bytes_sent": sent}

    async def terminate(
        self, job_id: str, grace_seconds: float | None = None
    ) -> dict[str, Any]:
        status = await self.status(job_id)
        if status.status == "unknown" or status.reachable is False:
            return {
                "job_id": job_id,
                "status": status.status,
                "already_finished": False,
                "message": status.message,
            }
        if status.status != "running":
            return {
                "job_id": job_id,
                "status": status.status,
                "already_finished": True,
            }

        row = self.store.get(job_id)
        pid = row.get("remote_pid")
        ticks = row.get("start_ticks")
        if not pid or not ticks:
            self.store.update(
                job_id, status="unknown",
                message="cannot terminate without verified PID identity",
            )
            return {
                "job_id": job_id, "status": "unknown",
                "already_finished": False,
            }
        configured_grace = self.settings.jobs.terminate_grace_seconds
        grace = (
            configured_grace
            if grace_seconds is None
            else min(grace_seconds, configured_grace)
        )
        if grace <= 0:
            raise ValueError("grace_seconds must be > 0")

        verify_and_term = (
            f"current=$(awk '{{print $22}}' /proc/{pid}/stat 2>/dev/null) || exit 44; "
            f"[ \"$current\" = {shlex.quote(str(ticks))} ] || exit 45; "
            f"kill -TERM -- -{pid}"
        )
        try:
            result = await self.ssh.run(
                status.server,
                verify_and_term,
                timeout=self.settings.jobs.status_timeout_seconds,
                max_output_bytes=4096,
            )
        except CommandDispatchUncertainError:
            message = "termination dispatch became uncertain and was not retried"
            self.store.update(job_id, status="unknown", message=message)
            return {
                "job_id": job_id, "status": "unknown",
                "already_finished": False, "message": message,
            }

        if result.timed_out or result.truncated or result.exit_code != 0:
            message = "termination request could not be confirmed; reconciliation required"
            self.store.update(job_id, status="unknown", message=message)
            return {
                "job_id": job_id, "status": "unknown",
                "already_finished": False, "message": message,
            }
        self.store.update(job_id, termination_requested=1)
        await asyncio.sleep(grace)
        after = await self.status(job_id)
        if after.status == "running":
            kill_command = (
                f"current=$(awk '{{print $22}}' /proc/{pid}/stat 2>/dev/null) || exit 0; "
                f"[ \"$current\" = {shlex.quote(str(ticks))} ] || exit 45; "
                f"kill -KILL -- -{pid}"
            )
            try:
                kill = await self.ssh.run(
                    status.server,
                    kill_command,
                    timeout=self.settings.jobs.status_timeout_seconds,
                    max_output_bytes=4096,
                )
            except CommandDispatchUncertainError:
                message = "kill dispatch became uncertain and was not retried"
                self.store.update(job_id, status="unknown", message=message)
                return {
                    "job_id": job_id, "status": "unknown",
                    "already_finished": False, "message": message,
                }

            if kill.exit_code == 0 and not kill.timed_out and not kill.truncated:
                self.store.update(
                    job_id, status="terminated",
                    ended_at=utcnow().isoformat(), message=None,
                )
                after = self._row_to_status(
                    self.store.get(job_id), reachable=True
                )
            else:
                message = "kill request could not be confirmed; reconciliation required"
                self.store.update(job_id, status="unknown", message=message)
                after = self._row_to_status(
                    self.store.get(job_id), status="unknown",
                    reachable=True, message=message,
                )
        return {
            "job_id": job_id,
            "status": after.status,
            "already_finished": False,
            **({"message": after.message} if after.message else {}),
        }
