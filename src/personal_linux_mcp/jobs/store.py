from __future__ import annotations

import sqlite3
import threading
from contextlib import closing
from pathlib import Path

from ..security.state import harden_state_file, state_database_path
from typing import Any


_COLUMNS: dict[str, str] = {
    "remote_dir": "TEXT",
    "start_ticks": "INTEGER",
    "termination_requested": "INTEGER NOT NULL DEFAULT 0",
    "message": "TEXT",
}


class JobStore:
    def __init__(self, state_dir: str):
        self.path = str(state_database_path(state_dir))
        self._lock = threading.Lock()
        self._initialize()

    def _initialize(self) -> None:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                  job_id TEXT PRIMARY KEY,
                  server TEXT NOT NULL,
                  cwd TEXT,
                  remote_dir TEXT,
                  status TEXT NOT NULL,
                  exit_code INTEGER,
                  remote_pid INTEGER,
                  start_ticks INTEGER,
                  started_at TEXT NOT NULL,
                  ended_at TEXT,
                  termination_requested INTEGER NOT NULL DEFAULT 0,
                  message TEXT
                )
                """
            )
            existing = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
            for name, sql_type in _COLUMNS.items():
                if name not in existing:
                    db.execute(f"ALTER TABLE jobs ADD COLUMN {name} {sql_type}")
        harden_state_file(self.path)

    @staticmethod
    def _connect(path: str) -> sqlite3.Connection:
        db = sqlite3.connect(path)
        db.row_factory = sqlite3.Row
        return db

    def insert(self, row: dict[str, Any]) -> None:
        with self._lock, closing(self._connect(self.path)) as db, db:
            db.execute(
                """
                INSERT INTO jobs(
                  job_id,server,cwd,remote_dir,status,exit_code,remote_pid,start_ticks,
                  started_at,ended_at,termination_requested,message
                ) VALUES(
                  :job_id,:server,:cwd,:remote_dir,:status,:exit_code,:remote_pid,:start_ticks,
                  :started_at,:ended_at,:termination_requested,:message
                )
                """,
                row,
            )

    def update(self, job_id: str, **fields: Any) -> None:
        allowed = {
            "status", "exit_code", "remote_pid", "start_ticks", "ended_at",
            "termination_requested", "message", "remote_dir", "cwd",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unsupported job fields: {sorted(unknown)}")
        if not fields:
            return
        assignments = ",".join(f"{key}=?" for key in fields)
        values = list(fields.values()) + [job_id]
        with self._lock, closing(self._connect(self.path)) as db, db:
            cur = db.execute(f"UPDATE jobs SET {assignments} WHERE job_id=?", values)
            if cur.rowcount != 1:
                raise KeyError(f"unknown job_id: {job_id}")

    def get(self, job_id: str) -> dict[str, Any]:
        with self._lock, closing(self._connect(self.path)) as db, db:
            row = db.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown job_id: {job_id}")
        return dict(row)

    def list(self) -> list[dict[str, Any]]:
        with self._lock, closing(self._connect(self.path)) as db, db:
            rows = db.execute("SELECT * FROM jobs ORDER BY started_at").fetchall()
        return [dict(row) for row in rows]
