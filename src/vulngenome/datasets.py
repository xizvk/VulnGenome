"""Dataset manifest schema checks and CVE/patch leakage guards."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_FIELDS = {
    "sample_id", "project", "source_commit", "patch_id", "binary_sha256",
    "compiler", "flags", "optimization", "architecture", "partition",
    "invariant_family", "annotation_provenance", "inclusion_rationale",
}


def validate_manifest(records: Iterable[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    rows = list(records)
    seen: set[str] = set()
    partition_by_patch: dict[str, str] = {}
    cve_partition: dict[str, str] = {}
    for index, row in enumerate(rows):
        prefix = f"record[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        missing = REQUIRED_FIELDS - set(row)
        if missing:
            errors.append(f"{prefix}: missing required fields {sorted(missing)}")
            continue
        sid = row["sample_id"]
        if not isinstance(sid, str) or not sid:
            errors.append(f"{prefix}: sample_id must be a non-empty string")
        elif sid in seen:
            errors.append(f"{prefix}: duplicate sample_id {sid!r}")
        else:
            seen.add(sid)
        string_fields = ("project", "source_commit", "patch_id", "compiler", "optimization",
                         "architecture", "invariant_family", "annotation_provenance", "inclusion_rationale")
        for field in string_fields:
            if not isinstance(row[field], str) or not row[field]:
                errors.append(f"{prefix}: {field} must be a non-empty string")
        if not isinstance(row["partition"], str) or row["partition"] not in {"development", "validation", "test"}:
            errors.append(f"{prefix}: invalid partition {row['partition']!r}")
        hashes = row["binary_sha256"]
        if not isinstance(hashes, dict) or not hashes:
            errors.append(f"{prefix}: binary_sha256 must be a non-empty object")
            hashes = {}
        for key, digest in hashes.items():
            if not isinstance(key, str) or not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                errors.append(f"{prefix}: each binary_sha256 entry must map a name to a lowercase SHA-256 digest")
        if not isinstance(row["flags"], list) or any(not isinstance(flag, str) for flag in row["flags"]):
            errors.append(f"{prefix}: flags must be an array of strings")
        patch = row["patch_id"]
        if isinstance(patch, str) and isinstance(row["partition"], str):
            prior_partition = partition_by_patch.setdefault(patch, row["partition"])
            if prior_partition != row["partition"]:
                errors.append(f"{prefix}: patch {patch!r} leaks across partitions")
        cve = row.get("cve_id")
        if cve is not None and not isinstance(cve, str):
            errors.append(f"{prefix}: cve_id must be a string or null")
        if isinstance(cve, str) and cve:
            prior_cve = cve_partition.setdefault(cve, row["partition"])
            if prior_cve != row["partition"]:
                errors.append(f"{prefix}: CVE {cve!r} leaks across partitions")
    return errors


def load_manifest(path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    source = Path(path)
    try:
        records = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"could not read manifest: {exc}"]
    if not isinstance(records, list):
        return [], ["manifest root must be a JSON array"]
    return records, validate_manifest(records)
