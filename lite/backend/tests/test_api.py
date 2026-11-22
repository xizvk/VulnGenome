from __future__ import annotations

import hashlib
import os
import struct
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.elf import ELFValidationError, validate_elf64_amd64_shared_object
from app.main import create_app
from app.services.intelligence import _validate_explanation


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_BINARIES = ROOT / "work" / "annotation-free-invariants-20261021" / "binaries"
VULNERABLE = FIXTURE_BINARIES / "transfer_vulnerable.so"
PATCHED = FIXTURE_BINARIES / "transfer_patched.so"
VULNERABLE_SHA256 = "af5b3a669e147a4b9cd1f674c20ec5cbec73d1b54c57d66ac74ede8a26b1dd33"
PATCHED_SHA256 = "f5fc4b99929a4a6c0bb0bc57fc13a5ef495b5110218a87b540ae1fd7f2f0a8fc"


def _profile_elf() -> bytes:
    """Small well-bounded ELF64 ET_DYN used only to test intake validation."""
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + bytes(7)
    header = struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0,
                         64, 56, 2, 64, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 176, 0, 0, 20, 20, 1)
    dynamic = struct.pack("<IIQQQQQQ", 2, 4, 180, 4, 4, 16, 16, 1)
    return ident + header + load + dynamic + bytes(20)


def test_full_elf_profile_parser_rejects_truncation_and_bad_identity():
    with pytest.raises(ELFValidationError, match="shorter"):
        validate_elf64_amd64_shared_object(b"\x7fELF")
    data = bytearray(_profile_elf())
    data[5] = 2
    with pytest.raises(ELFValidationError, match="little-endian"):
        validate_elf64_amd64_shared_object(bytes(data))


def test_profile_parser_checks_segment_bounds():
    data = bytearray(_profile_elf())
    struct.pack_into("<Q", data, 64 + 8, len(data) + 10)
    with pytest.raises(ELFValidationError, match="extends beyond"):
        validate_elf64_amd64_shared_object(bytes(data))


def test_upload_rejects_unsupported_files_without_creating_a_job(tmp_path: Path):
    app = create_app(tmp_path / "runtime", worker_timeout_seconds=4)
    with TestClient(app) as client:
        response = client.post("/api/v1/analyses", files={
            "vulnerable": ("not-elf.bin", b"hello", "application/octet-stream"),
            "patched": ("not-elf.bin", b"hello", "application/octet-stream"),
        })
        assert response.status_code == 422
        assert "ELF" in response.json()["detail"]
        assert client.get("/api/v1/analyses").json()["items"] == []


def test_upload_requires_exactly_one_file_per_role(tmp_path: Path):
    app = create_app(tmp_path / "runtime", worker_timeout_seconds=4)
    valid = _profile_elf()
    with TestClient(app) as client:
        response = client.post("/api/v1/analyses", files=[
            ("vulnerable", ("first.so", valid, "application/octet-stream")),
            ("vulnerable", ("second.so", valid, "application/octet-stream")),
            ("patched", ("patched.so", valid, "application/octet-stream")),
        ])
        assert response.status_code == 422
        assert "exactly one" in response.json()["detail"]
        assert client.get("/api/v1/analyses").json()["items"] == []


def test_explanation_schema_rejects_unknown_citation_ids():
    proposal = {
        "summary": "summary", "mechanism": "mechanism", "patch_interpretation": "patch",
        "verification_scope": "scope", "limitations": [],
        "citations": [{"source_ids": ["source-foreign"], "evidence_ids": []}],
    }
    with pytest.raises(ValueError, match="unknown retrieval source"):
        _validate_explanation(proposal, {"source-valid"}, {"evidence-valid"})


@pytest.mark.skipif(not (VULNERABLE.is_file() and PATCHED.is_file()),
                    reason="local controlled fixture binaries are not present")
def test_controlled_pair_runs_through_upload_engine_and_report(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    app = create_app(tmp_path / "runtime", worker_timeout_seconds=300)
    with TestClient(app) as client, VULNERABLE.open("rb") as old_file, PATCHED.open("rb") as new_file:
        response = client.post("/api/v1/analyses", files={
            "vulnerable": (VULNERABLE.name, old_file, "application/octet-stream"),
            "patched": (PATCHED.name, new_file, "application/octet-stream"),
        })
        assert response.status_code == 202, response.text
        created = response.json()
        job_id = created["id"]
        assert created["artifacts"]["vulnerable"]["sha256"] == VULNERABLE_SHA256
        assert created["artifacts"]["patched"]["sha256"] == PATCHED_SHA256
        assert created["artifacts"]["vulnerable"]["elf"]["architecture"] == "x86-64"
        assert created["artifacts"]["patched"]["elf"]["object_type"] == "ET_DYN shared object"

        deadline = time.monotonic() + 285
        job = client.get(f"/api/v1/analyses/{job_id}").json()
        while job["status"] == "running" and time.monotonic() < deadline:
            time.sleep(0.25)
            job = client.get(f"/api/v1/analyses/{job_id}").json()
        assert job["status"] == "completed", job.get("error") or job.get("stage")
        result = job["result"]
        assert result["analysis_status"] == "COMPLETED"
        assert result["static_only"] is True
        assert result["artifacts"]["vulnerable"]["sha256"] == hashlib.sha256(VULNERABLE.read_bytes()).hexdigest()
        assert result["artifacts"]["patched"]["sha256"] == hashlib.sha256(PATCHED.read_bytes()).hexdigest()
        assert result["artifacts"]["vulnerable"]["analysis"]["capabilities"]["cfg"] is True
        assert result["artifacts"]["patched"]["analysis"]["capabilities"]["vex"] is True
        assert result["comparison"]["matches"]
        assert result["inference"]["selected"] is not None
        assert all(item["vulnerable"]["status"] == "INFERRED" for item in result["inference"]["attempts"])
        assert result["inference"]["attempts"][0]["vulnerable"]["capacity"] == 16
        assert result["inference"]["attempts"][0]["patched"]["capacity"] == 16
        assert result["verification"]["vulnerable"]["capacity_source"] == "inferred"
        assert result["verification"]["patched"]["capacity_source"] == "inferred"
        assert result["verification"]["vulnerable"]["status"] == "POTENTIAL_VIOLATION"
        assert result["verification"]["patched"]["status"] == "PROPERTY_HOLDS_WITHIN_MODEL"
        assert result["verification"]["vulnerable"]["solver_result"] == "sat"
        assert result["verification"]["patched"]["solver_result"] == "unsat"
        assert result["intelligence"]["provider"] == "deterministic_local_fallback"
        assert result["intelligence"]["explanation"]["citations"]
        assert result["evidence"]

        assert client.get(f"/api/v1/analyses/{job_id}/evidence").status_code == 200
        assert client.get(f"/api/v1/analyses/{job_id}/diff").json()["result"] == result["comparison"]
        assert client.get(f"/api/v1/analyses/{job_id}/verification").json()["result"] == result["verification"]
        assert client.get(f"/api/v1/analyses/{job_id}/intelligence").json()["provider"] == "deterministic_local_fallback"
        json_export = client.get(f"/api/v1/analyses/{job_id}/report?format=json")
        html_export = client.get(f"/api/v1/analyses/{job_id}/report?format=html")
        assert json_export.status_code == 200 and json_export.json()["result"]["artifacts"]
        assert html_export.status_code == 200 and "Controlled pair analysis" in html_export.text
        assert "artifact-" in html_export.text or "source-" in html_export.text
