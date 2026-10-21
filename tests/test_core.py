from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import z3

from vulngenome.datasets import validate_manifest
from vulngenome.invariants import compile_property, validate
from vulngenome.metrics import calculate_metrics
from vulngenome.models import EvidenceBundle, InvariantSpec, SchemaError
from vulngenome.binary import BinaryAnalysis, BinaryMetadata
from vulngenome.patch import compare
from vulngenome.reporting import write_json
from vulngenome.verification import verify


def make_range_spec(**changes):
    raw = {
        "version": "1.0", "kind": "range_safety", "property": "offset_plus_length_le_capacity",
        "roles": {"offset": "expr_offset", "length": "expr_length", "capacity": "expr_capacity"},
        "program_point": "evidence_call_1", "evidence_refs": ["evidence_call_1"],
    }
    raw.update(changes)
    return InvariantSpec.from_dict(raw)


def make_evidence(width=8, signedness="unsigned", path_constraints=(), extra=None):
    exprs = {
        key: {"expr_id": key, "width": width, "signedness": signedness, "origin": "controlled test input"}
        for key in ("expr_offset", "expr_length", "expr_capacity")
    }
    if extra:
        exprs.update(extra)
    return EvidenceBundle.from_dict({"expressions": exprs, "evidence_ids": ["evidence_call_1"],
                                     "path_constraints": list(path_constraints)})


def test_valid_typed_range_and_extended_sum():
    spec, evidence = make_range_spec(), make_evidence()
    assert validate(spec, evidence).valid
    formula = compile_property(spec, evidence)
    assert "zero_extend 1" in formula
    assert "bvadd" in formula and "bvule" in formula


def test_rejects_unknown_evidence_reference():
    spec = make_range_spec(evidence_refs=["missing"])
    result = validate(spec, make_evidence())
    assert not result.valid
    assert "unknown evidence" in result.errors[0]


def test_rejects_missing_role_expression():
    spec = make_range_spec(roles={"offset": "expr_offset", "length": "missing", "capacity": "expr_capacity"})
    result = validate(spec, make_evidence())
    assert not result.valid
    assert any("unknown expression" in error for error in result.errors)


def test_rejects_mismatched_widths():
    evidence = make_evidence(extra={"expr_other": {"expr_id": "expr_other", "width": 32,
                                                   "signedness": "unsigned", "origin": "fixture"}})
    spec = make_range_spec(roles={"offset": "expr_offset", "length": "expr_length", "capacity": "expr_other"})
    assert any("equal machine widths" in error for error in validate(spec, evidence).errors)


def test_rejects_signed_range_operands():
    assert any("unsigned" in error for error in validate(make_range_spec(), make_evidence(signedness="signed")).errors)


def test_rejects_unknown_invariant_and_extra_field():
    with pytest.raises(SchemaError):
        make_range_spec(kind="llm_says_safe")
    with pytest.raises(SchemaError):
        InvariantSpec.from_dict({"version": "1.0", "kind": "range_safety", "extra": True})


def test_range_carry_violation_is_sat():
    evidence = make_evidence(path_constraints=("(= expr_offset #xff)", "(= expr_length #x01)", "(= expr_capacity #x00)"))
    result = verify(make_range_spec(), evidence)
    assert result.status == "POTENTIAL_VIOLATION"
    assert result.solver_result == "sat"
    assert "zero_extend 1" in result.query_smt2


def test_zero_range_is_unsat_for_violation_query():
    evidence = make_evidence(path_constraints=("(= expr_offset #x00)", "(= expr_length #x00)", "(= expr_capacity #x00)"))
    result = verify(make_range_spec(), evidence)
    assert result.status == "PROPERTY_HOLDS_WITHIN_MODEL"
    assert result.solver_result == "unsat"


def test_unknown_solver_result_is_inconclusive():
    evidence = make_evidence()
    solver = z3.Solver()
    solver.check = lambda: z3.unknown
    solver.reason_unknown = lambda: "test timeout"
    with patch("z3.Solver", return_value=solver):
        result = verify(make_range_spec(), evidence)
    assert result.status == "INCONCLUSIVE"
    assert result.solver_result == "unknown"


def test_unresolved_assumptions_force_inconclusive():
    spec = make_range_spec(assumptions=["capacity is the destination object's byte length"])
    result = verify(spec, make_evidence())
    assert result.status == "INCONCLUSIVE"
    assert result.solver_result == "not-run"


def test_malformed_solver_constraint_is_analysis_error():
    evidence = make_evidence(path_constraints=("(bvadd expr_offset #x0000)",))
    result = verify(make_range_spec(), evidence)
    assert result.status == "ANALYSIS_ERROR"
    assert result.solver_result == "error"


def test_malformed_expression_width_is_rejected():
    raw = {"expr_id": "expr_x", "width": 0, "signedness": "unsigned", "origin": "test"}
    from vulngenome.models import Expression
    with pytest.raises(SchemaError):
        Expression.from_dict(raw)


def test_guard_dominance_requires_boolean_role():
    spec = InvariantSpec.from_dict({"version": "1.0", "kind": "guard_dominance",
                                    "property": "condition_holds_at_sensitive_operation",
                                    "roles": {"condition": "expr_condition"},
                                    "program_point": "sink", "evidence_refs": ["evidence_call_1"]})
    evidence = EvidenceBundle.from_dict({"expressions": {"expr_condition": {"expr_id": "expr_condition", "width": 64,
        "signedness": "unsigned", "origin": "VEX"}}, "evidence_ids": ["evidence_call_1"]})
    assert any("one-bit boolean" in error for error in validate(spec, evidence).errors)


def test_representability_compiler_preserves_source_width():
    spec = InvariantSpec.from_dict({"version": "1.0", "kind": "representability", "property": "fits_target_type",
        "roles": {"value": "expr_value"}, "program_point": "cast", "evidence_refs": ["evidence_call_1"],
        "parameters": {"target_width": 8, "target_signedness": "unsigned"}})
    evidence = EvidenceBundle.from_dict({"expressions": {"expr_value": {"expr_id": "expr_value", "width": 16,
        "signedness": "unsigned", "origin": "machine expression"}}, "evidence_ids": ["evidence_call_1"]})
    assert validate(spec, evidence).valid
    assert "extract 15 8" in compile_property(spec, evidence)


def test_evidence_report_writes_portable_json(tmp_path):
    report = tmp_path / "report.json"
    write_json(report, {"result": "INCONCLUSIVE", "assumptions": ["unknown capacity"]})
    assert json.loads(report.read_text(encoding="utf-8"))["result"] == "INCONCLUSIVE"


def test_metrics_keep_inconclusive_out_of_accuracy_and_report_coverage():
    result = calculate_metrics([
        {"ground_truth": "VULNERABLE", "prediction": "VULNERABLE", "project": "p", "invariant_family": "range"},
        {"ground_truth": "PATCHED", "prediction": "INCONCLUSIVE", "project": "p", "invariant_family": "range"},
    ])
    assert result["n_total_labeled"] == 2
    assert result["n_decided"] == 1
    assert result["decision_coverage"] == 0.5
    assert result["accuracy_on_decided"] == 1.0
    assert result["n_inconclusive"] == 1


def test_dataset_split_leakage_is_rejected():
    base = {"project": "p", "source_commit": "a", "patch_id": "patch-a", "binary_sha256": {"v": "a" * 64},
            "compiler": "zig", "flags": ["-O0"], "optimization": "O0", "architecture": "x86-64",
            "invariant_family": "range_safety", "annotation_provenance": "controlled", "inclusion_rationale": "fixture"}
    records = [dict(base, sample_id="a", partition="development"), dict(base, sample_id="b", partition="test")]
    errors = validate_manifest(records)
    assert any("leaks across partitions" in error for error in errors)


def test_malformed_manifest_types_return_validation_errors():
    record = {"sample_id": [], "project": "p", "source_commit": "a", "patch_id": {},
              "binary_sha256": [], "compiler": "zig", "flags": "-O0", "optimization": "O0",
              "architecture": "x86-64", "partition": [], "invariant_family": "range_safety",
              "annotation_provenance": "controlled", "inclusion_rationale": "fixture"}
    errors = validate_manifest([record])
    assert any("sample_id" in error for error in errors)
    assert any("binary_sha256" in error for error in errors)
    assert any("partition" in error for error in errors)


def test_patch_comparison_reports_symbol_match_and_call_delta():
    def analysis(digest, function):
        metadata = BinaryMetadata("fixture", digest * 64, 1, "ELF64", "x86-64", "little")
        return BinaryAnalysis(metadata, "angr", "test", [function], {"metadata": True, "cfg": True, "vex": True})
    old = {"name": "transfer", "address": 4096, "size": 8, "blocks": [], "calls": [{"name": None, "target": 12288}]}
    new = {"name": "transfer", "address": 8192, "size": 12, "blocks": [], "calls": [{"name": "sensitive_sink", "target": 16384}]}
    result = compare(analysis("a", old), analysis("b", new))
    assert result["matches"][0]["classification"] == "symbol_supported"
    assert result["matches"][0]["evidence"][0]["kind"] == "call_target_counts"


def test_expression_evidence_reference_must_resolve():
    evidence = EvidenceBundle.from_dict({"expressions": {
        "expr_offset": {"expr_id": "expr_offset", "width": 8, "signedness": "unsigned", "origin": "test", "evidence_ref": "missing"},
        "expr_length": {"expr_id": "expr_length", "width": 8, "signedness": "unsigned", "origin": "test"},
        "expr_capacity": {"expr_id": "expr_capacity", "width": 8, "signedness": "unsigned", "origin": "test"}},
        "evidence_ids": ["controlled_query_1"]})
    assert any("unknown expression evidence references" in error for error in validate(make_range_spec(evidence_refs=["controlled_query_1"]), evidence).errors)


def test_duplicate_evidence_refs_are_invalid():
    with pytest.raises(SchemaError):
        make_range_spec(evidence_refs=["evidence_call_1", "evidence_call_1"])
