from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_ALLOWED_UPDATES = {
    "status", "stage", "vulnerable_sha256", "patched_sha256", "result_json", "error",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobStore:
    """Small SQLite-backed local job store; each operation owns a connection."""

    def __init__(self, database_path: str | Path):
        self.path = Path(database_path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._schema_lock = threading.Lock()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        return connection

    def _ensure_schema(self) -> None:
        with self._schema_lock, self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    vulnerable_name TEXT NOT NULL,
                    patched_name TEXT NOT NULL,
                    vulnerable_sha256 TEXT NOT NULL,
                    patched_sha256 TEXT NOT NULL,
                    vulnerable_size INTEGER NOT NULL,
                    patched_size INTEGER NOT NULL,
                    result_json TEXT,
                    error TEXT
                )
            """)

    def create(self, record: dict[str, Any]) -> None:
        now = utc_now()
        with self._connect() as connection:
            connection.execute("""
                INSERT INTO analyses
                (id,status,stage,created_at,updated_at,vulnerable_name,patched_name,
                 vulnerable_sha256,patched_sha256,vulnerable_size,patched_size)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (record["id"], "running", "VALIDATING", now, now,
                  record["vulnerable_name"], record["patched_name"],
                  record["vulnerable_sha256"], record["patched_sha256"],
                  record["vulnerable_size"], record["patched_size"]))

    def update(self, job_id: str, **values: Any) -> None:
        unknown = set(values) - _ALLOWED_UPDATES
        if unknown:
            raise ValueError(f"unsupported job fields: {sorted(unknown)}")
        assignments = [f"{key}=?" for key in values]
        params = [json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                  if key == "result_json" and value is not None else value
                  for key, value in values.items()]
        assignments.append("updated_at=?")
        params.extend((utc_now(), job_id))
        with self._connect() as connection:
            cursor = connection.execute(
                f"UPDATE analyses SET {', '.join(assignments)} WHERE id=?", params
            )
            if cursor.rowcount != 1:
                raise KeyError(job_id)

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM analyses WHERE id=?", (job_id,)).fetchone()
        return self._decode(row) if row else None

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM analyses ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._decode(row) for row in rows]

    def mark_interrupted(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE analyses SET status='failed', stage='FAILED', error=?, updated_at=? WHERE status='running'",
                ("Service restarted while this analysis was active; submit the pair again.", utc_now()),
            )

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        if result.get("result_json"):
            result["result"] = json.loads(result.pop("result_json"))
        else:
            result.pop("result_json", None)
            result["result"] = None
        return result
