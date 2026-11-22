from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
LITE_ROOT = REPO_ROOT / "lite"
BACKEND_ROOT = LITE_ROOT / "backend"


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    max_upload_bytes: int = 32 * 1024 * 1024
    worker_timeout_seconds: int = 300

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def database_path(self) -> Path:
        return self.data_dir / "jobs.sqlite3"


def get_settings(data_dir: str | Path | None = None) -> Settings:
    selected = data_dir or os.environ.get("VULNGENOME_LITE_DATA_DIR") or (LITE_ROOT / ".runtime")
    return Settings(data_dir=Path(selected).expanduser().resolve())
