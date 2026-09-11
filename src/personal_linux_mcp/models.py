from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel

JobState = Literal["running", "completed", "failed", "terminated", "unknown", "orphaned"]

class ShellResult(BaseModel):
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    timed_out: bool = False
    output_limited: bool = False
    truncated: bool = False
    cleanup_attempted: bool = False
    remote_state_uncertain: bool = False
    duration_ms: int = 0

class FileReadResult(BaseModel):
    path: str
    content: str
    offset: int
    bytes_read: int
    next_offset: int
    eof: bool
    truncated: bool = False

class JobStartResult(BaseModel):
    job_id: str
    server: str
    status: JobState
    started_at: datetime
    remote_pid: int | None = None
    start_ticks: int | None = None
    cwd: str | None = None
    remote_dir: str | None = None
    message: str | None = None

class JobStatusResult(BaseModel):
    job_id: str
    server: str
    status: JobState
    started_at: datetime
    exit_code: int | None = None
    ended_at: datetime | None = None
    remote_pid: int | None = None
    start_ticks: int | None = None
    remote_dir: str | None = None
    reachable: bool | None = None
    message: str | None = None

class JobLogsResult(BaseModel):
    job_id: str
    content: str
    cursor: int
    next_cursor: int
    eof: bool
    truncated: bool
    size: int | None = None

def utcnow() -> datetime:
    return datetime.now(timezone.utc)
