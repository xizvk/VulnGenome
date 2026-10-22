from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from vulngenome.symbolic import verify_unsigned_argument_at_call_inferred
from vulngenome.transfer import create_transfer_proposal, evaluate_cross_build_transfer


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "cross-build"


def _compiler() -> str | None:
    configured = os.environ.get("VULNGENOME_CLANG")
    if configured and Path(configured).is_file():
        return str(Path(configured).resolve())
    return shutil.which("clang")


pytestmark = pytest.mark.skipif(_compiler() is None, reason="a working Clang is required for cross-build tests")


def _compile(source_name: str, output: Path, optimization: str) -> Path:
    clang = _compiler()
    assert clang is not None
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        clang, "--target=x86_64-linux-musl", f"-{optimization}", "-g",
        "-fno-stack-protector", "-fPIC", "-shared", "-nostdlib",
        "-fuse-ld=lld", "-Wl,-Bsymbolic", str(FIXTURES / source_name), "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
    return output


def _compile_workspace_source(source: Path, output: Path, optimization: str) -> Path:
    clang = _compiler()
    assert clang is not None
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        clang, "--target=x86_64-linux-musl", f"-{optimization}", "-g",
        "-fno-stack-protector", "-fPIC", "-shared", "-nostdlib",
        "-fuse-ld=lld", "-Wl,-Bsymbolic", str(source), "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
    return output


def _analyze(binary: Path):
    return verify_unsigned_argument_at_call_inferred(
        binary, function_name="accept_sample", call_name="commit_sample"
    )


def test_cross_build_transfer_reanalyzes_target_and_rejects_stale_source_evidence(tmp_path):
    vulnerable = _compile("telemetry_vulnerable.c", tmp_path / "vulnerable-o0.so", "O0")
    patched = _compile("telemetry_patched.c", tmp_path / "patched-o0.so", "O0")
    vulnerable_result = _analyze(vulnerable)
    patched_result = _analyze(patched)

    assert vulnerable_result.binary_sha256 == hashlib.sha256(vulnerable.read_bytes()).hexdigest()
    assert patched_result.binary_sha256 == hashlib.sha256(patched.read_bytes()).hexdigest()
    assert vulnerable_result.solver_result == "sat"
    assert vulnerable_result.status == "POTENTIAL_VIOLATION"
    assert patched_result.solver_result == "unsat"
    assert patched_result.status == "PROPERTY_HOLDS_WITHIN_MODEL"

    proposal = create_transfer_proposal(vulnerable, vulnerable_result)
    assert proposal["abstract_property"]["object_symbol_name"] == "sample_buffer"
    assert proposal["transfer_policy"]["raw_addresses_transferred"] is False
    assert proposal["transfer_policy"]["path_constraints_transferred"] is False
    assert "path_constraints" not in proposal

    result = evaluate_cross_build_transfer(proposal, patched, patched_result)
    assert result["transfer_status"] == "ACCEPTED"
    assert result["property_classification"] == "PROPERTY_HOLDS_WITHIN_MODEL"
    assert result["target_binary_sha256"] == patched_result.binary_sha256
    assert result["target_specific_evidence"]["all_path_hashes_match_target"] is True
    assert result["source_evidence_reused"] is False

    stale = evaluate_cross_build_transfer(proposal, patched, vulnerable_result)
    assert stale["transfer_status"] == "REJECTED"
    assert stale["target_evidence_validation"] == "FAILED"
    assert "hash does not match" in stale["reason"]

    unknown_target = replace(patched_result, status="INCONCLUSIVE", solver_result="unknown",
                             exploration_complete=False, reason="controlled unknown policy probe")
    unknown = evaluate_cross_build_transfer(proposal, patched, unknown_target)
    assert unknown["transfer_status"] == "INCONCLUSIVE"
    assert unknown["property_classification"] == "INCONCLUSIVE"
    assert unknown["solver_result"] == "unknown"

    reverse_proposal = create_transfer_proposal(patched, patched_result)
    reverse = evaluate_cross_build_transfer(reverse_proposal, vulnerable, vulnerable_result)
    assert reverse["transfer_status"] == "ACCEPTED"
    assert reverse["property_classification"] == "POTENTIAL_VIOLATION"
    assert reverse["solver_result"] == "sat"


def test_optimized_target_transfer_uses_its_own_binary_evidence(tmp_path):
    source = _compile("telemetry_vulnerable.c", tmp_path / "source-o0.so", "O0")
    target = _compile("telemetry_patched.c", tmp_path / "target-o2.so", "O2")
    source_result = _analyze(source)
    target_result = _analyze(target)
    proposal = create_transfer_proposal(source, source_result)

    transfer = evaluate_cross_build_transfer(proposal, target, target_result)
    assert transfer["target_binary_sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert transfer["source_evidence_reused"] is False
    if target_result.capacity_source == "inferred":
        assert transfer["target_evidence_validation"] in {"PASS", "PASS_HASH_ONLY"}
    else:
        assert transfer["transfer_status"] == "INCONCLUSIVE"
        assert transfer["property_classification"] == "INCONCLUSIVE"


@pytest.mark.parametrize("optimization", ["O1", "Os"])
def test_cross_build_transfer_accepts_supported_optimized_target_evidence(tmp_path, optimization):
    source = _compile_workspace_source(
        ROOT / "fixtures" / "transfer_vulnerable.c", tmp_path / "source-o0.so", "O0")
    target = _compile_workspace_source(
        ROOT / "fixtures" / "transfer_patched.c", tmp_path / f"target-{optimization}.so", optimization)
    source_result = verify_unsigned_argument_at_call_inferred(
        source, function_name="transfer", call_name="sensitive_sink")
    target_result = verify_unsigned_argument_at_call_inferred(
        target, function_name="transfer", call_name="sensitive_sink")

    assert source_result.status == "POTENTIAL_VIOLATION"
    assert target_result.status == "PROPERTY_HOLDS_WITHIN_MODEL"
    assert target_result.capacity == 16
    assert target_result.capacity_evidence["evidence"]["data_flow_relationship"]["status"] == (
        "PROVEN_SUPPORTED_OPTIMIZED_SCALAR_PATTERN")

    proposal = create_transfer_proposal(source, source_result)
    transfer = evaluate_cross_build_transfer(proposal, target, target_result)
    assert transfer["transfer_status"] == "ACCEPTED"
    assert transfer["property_classification"] == "PROPERTY_HOLDS_WITHIN_MODEL"
    assert transfer["source_evidence_reused"] is False
    assert transfer["target_evidence_validation"] == "PASS"
    assert transfer["target_specific_evidence"]["all_path_hashes_match_target"] is True

    optimized_source_proposal = create_transfer_proposal(target, target_result)
    reverse = evaluate_cross_build_transfer(optimized_source_proposal, source, source_result)
    assert reverse["transfer_status"] == "ACCEPTED"
    assert reverse["property_classification"] == "POTENTIAL_VIOLATION"
    assert reverse["source_evidence_reused"] is False
