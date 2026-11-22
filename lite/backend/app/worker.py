from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .config import REPO_ROOT, get_settings
from .elf import validate_elf64_amd64_shared_object
from .services.engine_adapter import PROFILE, run_pair_analysis
from .services.intelligence import build_explanation
from .store import JobStore


def execute(job_id: str, data_dir: str | Path) -> None:
    settings = get_settings(data_dir)
    store = JobStore(settings.database_path)
    if not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise ValueError("invalid job identifier")
    job = store.get(job_id)
    if not job:
        raise KeyError(job_id)
    job_dir = (settings.quarantine_dir / job_id).resolve()
    if job_dir.parent != settings.quarantine_dir.resolve():
        raise ValueError("job artifact directory escaped quarantine")
    vulnerable_path = job_dir / "vulnerable.elf"
    patched_path = job_dir / "patched.elf"

    def stage(name: str) -> None:
        store.update(job_id, status="running", stage=name, error=None)

    try:
        stage("VALIDATING")
        if not vulnerable_path.is_file() or not patched_path.is_file():
            raise FileNotFoundError("quarantined artifact missing")
        old = validate_elf64_amd64_shared_object(vulnerable_path.read_bytes())
        new = validate_elf64_amd64_shared_object(patched_path.read_bytes())
        if old.sha256 != job["vulnerable_sha256"] or new.sha256 != job["patched_sha256"]:
            raise ValueError("quarantined artifact hash changed after intake")
        result = run_pair_analysis(vulnerable_path, patched_path, PROFILE["id"], progress=stage)
        result["intelligence"] = build_explanation(result)
        terminal = "completed" if result["analysis_status"] == "COMPLETED" else "inconclusive"
        store.update(job_id, status=terminal, stage=terminal.upper(),
                     result_json=result, error=None)
    except Exception as exc:
        # Avoid exposing local paths, prompts, or environment values in a job response.
        store.update(job_id, status="failed", stage="FAILED",
                     error=f"{type(exc).__name__}: analysis worker could not complete")
        print(json.dumps({"job_id": job_id, "error_type": type(exc).__name__}), file=sys.stderr)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--data-dir", required=True)
    args = parser.parse_args()
    try:
        execute(args.job_id, args.data_dir)
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
