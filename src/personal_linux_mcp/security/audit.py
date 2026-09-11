from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Iterator

from .redaction import redact
from .state import harden_state_file, state_database_path


@dataclass
class AuditEvent:
    request_id: str
    tool: str
    server: str | None
    target: str | None
    started: float


class AuditLogger:
    def __init__(self, state_dir: str, log_commands: bool = False):
        self.path = str(state_database_path(state_dir))
        self.log_commands = log_commands
        self._lock = threading.Lock()
        self._initialize()

    def _initialize(self) -> None:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS audit (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT NOT NULL,
                  request_id TEXT NOT NULL,
                  tool TEXT NOT NULL,
                  server TEXT,
                  target TEXT,
                  duration_ms INTEGER NOT NULL,
                  status TEXT NOT NULL,
                  exit_code INTEGER,
                  returned_bytes INTEGER NOT NULL,
                  detail TEXT
                )
                """
            )
        harden_state_file(self.path)

    @contextmanager
    def event(self, tool: str, server: str | None = None, target: str | None = None) -> Iterator[AuditEvent]:
        event = AuditEvent(str(uuid.uuid4()), tool, server, target, monotonic())
        try:
            yield event
        except Exception:
            self.finish(event, "error")
            raise

    def finish(
        self,
        event: AuditEvent,
        status: str,
        exit_code: int | None = None,
        returned_bytes: int = 0,
        detail: str | None = None,
    ) -> None:
        if detail:
            detail = redact(detail)
        duration_ms = int((monotonic() - event.started) * 1000)
        with self._lock, closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "INSERT INTO audit(timestamp,request_id,tool,server,target,duration_ms,status,exit_code,returned_bytes,detail)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    event.request_id,
                    event.tool,
                    event.server,
                    event.target,
                    duration_ms,
                    status,
                    exit_code,
                    returned_bytes,
                    detail,
                ),
            )
