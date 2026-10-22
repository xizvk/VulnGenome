from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vulngenome.capacity import infer_capacity_from_binary
from vulngenome.symbolic import (
    verify_unsigned_argument_at_call,
    verify_unsigned_argument_at_call_inferred,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from compile_fixture import compile_source  # noqa: E402


def _toolchain_ready() -> bool:
    configured = os.environ.get("VULNGENOME_CLANG")
    if not configured or not Path(configured).is_file():
        return False
    try:
        return subprocess.run([configured, "--version"], capture_output=True,
                              text=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.skipif(
    not _toolchain_ready(), reason="a working VULNGENOME_CLANG is required for binary-derived tests"
)


def _compile(source: Path, output_dir: Path, *, extra_flags: tuple[str, ...] = ()) -> Path:
    output = output_dir / (source.stem + ("-stripped" if "-Wl,-s" in extra_flags else "") + ".so")
    compile_source(source, output, extra_flags=extra_flags)
    return output


def _analyze(binary: Path):
    return verify_unsigned_argument_at_call_inferred(
        binary, function_name="transfer", call_name="sensitive_sink"
    )


def test_original_pair_supports_binary_inference_without_capacity_annotation(tmp_path):
    import pytest
    pytest.importorskip("angr")
    pytest.importorskip("z3")
    vulnerable = _compile(ROOT / "fixtures" / "transfer_vulnerable.c", tmp_path / "base")
    patched = _compile(ROOT / "fixtures" / "transfer_patched.c", tmp_path / "base")

    old_result = _analyze(vulnerable)
    new_result = _analyze(patched)
    baseline = json.loads((ROOT / "experiments" / "results" /
                           "controlled-fixture-clang-20261021.json").read_text(encoding="utf-8"))
    for key, binary, result in (("vulnerable", vulnerable, old_result),
                                ("patched", patched, new_result)):
        current_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        # Debug sections include the per-test scratch path, so a rebuild need
        # not have the same whole-file hash as the separately recorded build.
        # Check provenance against the exact artifact analyzed in this test.
        assert result.binary_sha256 == current_hash
        assert result.capacity_evidence["binary_sha256"] == current_hash
        assert result.capacity_evidence["evidence"]["binary_sha256"] == current_hash
    manual = {
        "vulnerable": verify_unsigned_argument_at_call(
            vulnerable, function_name="transfer", call_name="sensitive_sink", capacity=16,
            capacity_provenance="manual controlled-fixture annotation in fixtures/contract.json",
        ),
        "patched": verify_unsigned_argument_at_call(
            patched, function_name="transfer", call_name="sensitive_sink", capacity=16,
            capacity_provenance="manual controlled-fixture annotation in fixtures/contract.json",
        ),
    }
    for key, result in manual.items():
        recorded = baseline["symbolic_callsite_results"][key]
        assert result.status == recorded["status"]
        assert result.solver_result == recorded["solver_result"]
        assert result.capacity == recorded["capacity"] == 16
        assert result.capacity_provenance == recorded["capacity_provenance"]

    assert old_result.capacity == new_result.capacity == 16
    assert old_result.capacity_source == new_result.capacity_source == "inferred"
    assert old_result.analysis_mode == new_result.analysis_mode == "binary_inference"
    assert old_result.capacity_evidence["inferred"] is True
    assert old_result.capacity_evidence["supplied"] is False
    assert old_result.capacity_evidence["evidence"]["object_symbol"]["size_bytes"] == 16
    store_evidence = old_result.capacity_evidence["evidence"]["store_evidence"]
    assert store_evidence and any("STle" in item["vex_block"] for item in store_evidence)
    assert old_result.status == "POTENTIAL_VIOLATION"
    assert old_result.solver_result == "sat"
    assert new_result.status == "PROPERTY_HOLDS_WITHIN_MODEL"
    assert new_result.solver_result == "unsat"
    assert "bvule" in new_result.query_smt2
    assert any("bvule" in constraint for constraint in new_result.path_constraints)
    assert new_result.invariant_evidence["evidence_refs"]
    assert any(site["instructions"] for path in new_result.path_evidence
               for site in path["branch_sites"])


def test_changed_capacity_is_recovered_from_compiled_artifact(tmp_path):
    import pytest
    pytest.importorskip("angr")
    pytest.importorskip("z3")
    binary = _compile(ROOT / "fixtures" / "variants" / "transfer_capacity_24.c", tmp_path / "capacity24")
    result = _analyze(binary)
    assert result.capacity == 24
    assert result.status == "PROPERTY_HOLDS_WITHIN_MODEL"
    assert result.capacity_evidence["binary_sha256"] == result.binary_sha256


def test_removed_guard_and_oversized_guard_are_detected_from_binary_paths(tmp_path):
    import pytest
    pytest.importorskip("angr")
    pytest.importorskip("z3")
    removed_guard = _compile(ROOT / "fixtures" / "transfer_vulnerable.c", tmp_path / "unguarded")
    oversized_guard = _compile(ROOT / "fixtures" / "variants" / "transfer_guard_too_large.c", tmp_path / "oversized")

    unguarded_result = _analyze(removed_guard)
    oversized_result = _analyze(oversized_guard)

    assert unguarded_result.status == "POTENTIAL_VIOLATION"
    assert unguarded_result.solver_result == "sat"
    assert oversized_result.capacity == 16
    assert oversized_result.status == "POTENTIAL_VIOLATION"
    assert oversized_result.solver_result == "sat"


def test_changed_sink_argument_is_not_hidden_by_the_original_guard(tmp_path):
    import pytest
    pytest.importorskip("angr")
    pytest.importorskip("z3")
    binary = _compile(ROOT / "fixtures" / "variants" / "transfer_sink_plus_one.c", tmp_path / "sink-plus-one")
    result = _analyze(binary)
    assert result.capacity == 16
    assert result.status == "POTENTIAL_VIOLATION"
    assert result.solver_result == "sat"
    assert any("bvadd" in path["sink_argument_expression"] for path in result.path_evidence)


def test_missing_binary_object_metadata_abstains_and_manual_override_is_labeled(tmp_path):
    import pytest
    pytest.importorskip("angr")
    pytest.importorskip("z3")
    source = ROOT / "fixtures" / "transfer_patched.c"
    stripped = _compile(source, tmp_path / "stripped", extra_flags=("-Wl,-s",))

    automatic = infer_capacity_from_binary(
        stripped, function_name="transfer", call_name="sensitive_sink"
    )
    auto_result = _analyze(stripped)
    manual_result = verify_unsigned_argument_at_call(
        stripped, function_name="transfer", call_name="sensitive_sink",
        capacity=(1 << 64) - 1, capacity_provenance="deliberately misleading test annotation",
    )

    assert automatic.status == "INCONCLUSIVE"
    assert automatic.capacity is None
    assert "symbol" in automatic.reason.lower() or "referenced" in automatic.reason.lower()
    assert auto_result.status == "INCONCLUSIVE"
    assert auto_result.capacity is None
    assert auto_result.solver_result == "not-run"
    assert manual_result.status == "PROPERTY_HOLDS_WITHIN_MODEL"
    assert manual_result.capacity_source == "supplied"
    assert manual_result.analysis_mode == "manual_annotation"
    assert manual_result.capacity_evidence is None
