"""Run the independent, compile-only capacity-inference evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVALUATION_FIXTURES = ROOT / "fixtures" / "evaluation" / "capacity-inference"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from compile_fixture import build_compile_command, compile_source, compiler_metadata  # noqa: E402
from vulngenome.capacity import infer_capacity_from_binary  # noqa: E402
from vulngenome.symbolic import verify_unsigned_argument_at_call_inferred  # noqa: E402


CASES = {
    "independent_valid": {
        "source": "independent_valid.c",
        "extra_flags": (),
        "ground_truth": {
            "association": "one object is written through the argument-bounded loop",
            "object_symbol": "telemetry_region",
            "object_extent_bytes": 9,
            "expected_violation": False,
            "expected_status": "PROPERTY_HOLDS_WITHIN_MODEL",
            "provenance": "fixture source declares a 9-byte object and writes indices cursor in [0, amount); caller admits amount <= 9",
        },
    },
    "unrelated_decoy": {
        "source": "unrelated_decoy.c",
        "extra_flags": (),
        "ground_truth": {
            "association": "decoy object is written at fixed offset equal to its extent; sink argument controls only whether the out-of-bounds write executes",
            "decoy_symbol": "unrelated_marker",
            "decoy_extent_bytes": 17,
            "object_extent_bytes": None,
            "expected_violation": True,
            "expected_status": "INCONCLUSIVE",
            "provenance": "fixture source declares unrelated_marker[17] and writes index 17 when amount is nonzero; the caller guard permits requested values in [1,17]",
        },
    },
    "indirect_write_decoy": {
        "source": "indirect_write_decoy.c",
        "extra_flags": (),
        "ground_truth": {
            "association": "a safe argument-indexed object loop coexists with an unrelated dynamic-pointer write at the one-past-end address",
            "object_symbol": "primary_region",
            "object_extent_bytes": None,
            "expected_violation": True,
            "expected_status": "INCONCLUSIVE",
            "provenance": "fixture source passes primary_region + 9 to a second sink parameter and writes destination[0]; the inference API does not summarize that write",
        },
    },
    "multiple_candidate_decoy": {
        "source": "multiple_candidate_decoy.c",
        "extra_flags": (),
        "ground_truth": {
            "association": "one object is argument-indexed; second object receives only a constant-offset telemetry write",
            "object_symbol": "primary_region",
            "other_symbol": "telemetry_log",
            "object_extent_bytes": 7,
            "other_extent_bytes": 23,
            "expected_violation": False,
            "expected_status": "PROPERTY_HOLDS_WITHIN_MODEL",
            "provenance": "fixture source loop indexes primary_region by cursor < amount; telemetry_log is written only at index zero",
        },
    },
    "multiple_candidate_ambiguous": {
        "source": "multiple_candidate_ambiguous.c",
        "extra_flags": (),
        "ground_truth": {
            "association": "two differently sized objects are both indexed by the same argument-bounded loop",
            "candidate_symbols": {"primary_region": 7, "audit_region": 23},
            "object_extent_bytes": None,
            "expected_violation": None,
            "expected_status": "INCONCLUSIVE",
            "provenance": "fixture source proves both writes are relevant; no unique object extent is selected by this API",
        },
    },
    "extent_five": {
        "source": "extent_five.c",
        "extra_flags": (),
        "ground_truth": {
            "association": "one-byte zero-based loop over sample_five",
            "object_symbol": "sample_five",
            "object_extent_bytes": 5,
            "expected_violation": False,
            "expected_status": "PROPERTY_HOLDS_WITHIN_MODEL",
            "provenance": "fixture source declares sample_five[5] and caller admits requested <= 5",
        },
    },
    "extent_thirteen": {
        "source": "extent_thirteen.c",
        "extra_flags": (),
        "ground_truth": {
            "association": "one-byte zero-based loop over sample_thirteen",
            "object_symbol": "sample_thirteen",
            "object_extent_bytes": 13,
            "expected_violation": False,
            "expected_status": "PROPERTY_HOLDS_WITHIN_MODEL",
            "provenance": "fixture source declares sample_thirteen[13] and caller admits requested <= 13",
        },
    },
    "unguarded_independent": {
        "source": "unguarded_independent.c",
        "extra_flags": (),
        "ground_truth": {
            "association": "one-byte zero-based loop over unguarded_target",
            "object_symbol": "unguarded_target",
            "object_extent_bytes": 11,
            "expected_violation": True,
            "expected_status": "POTENTIAL_VIOLATION",
            "provenance": "fixture source declares unguarded_target[11] and calls sink without a caller range check",
        },
    },
    "changed_argument_independent": {
        "source": "changed_argument_independent.c",
        "extra_flags": (),
        "ground_truth": {
            "association": "sink loop is argument-bounded; caller checks requested but passes requested + 1",
            "object_symbol": "shifted_target",
            "object_extent_bytes": 7,
            "expected_violation": True,
            "expected_status": "POTENTIAL_VIOLATION",
            "provenance": "fixture source declares shifted_target[7], checks requested <= 7, then passes requested + 1",
        },
    },
    "weak_guard_or": {
        "source": "weak_guard_or.c",
        "extra_flags": (),
        "ground_truth": {
            "association": "an OR clause admits stores after amount is zero; the index is not bounded by the sink argument on every taken edge",
            "decoy_symbol": "weakly_guarded",
            "decoy_extent_bytes": 5,
            "object_extent_bytes": None,
            "expected_violation": True,
            "expected_status": "INCONCLUSIVE",
            "provenance": "fixture source loop condition is cursor < amount || amount == 0, which does not imply cursor < amount",
        },
    },
    "stripped_metadata": {
        "source": "independent_valid.c",
        "extra_flags": ("-Wl,-s",),
        "ground_truth": {
            "association": "same valid source relation as independent_valid, with ELF symbol metadata stripped",
            "object_symbol": "telemetry_region",
            "object_extent_bytes": 9,
            "expected_violation": False,
            "expected_status": "INCONCLUSIVE",
            "provenance": "the compile command strips symbol metadata; the source file is ground truth only and is not read by inference",
        },
    },
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _metrics(results: dict[str, dict]) -> dict:
    extent_cases = [
        item for item in results.values()
        if item["ground_truth"].get("object_extent_bytes") is not None
        and item["ground_truth"].get("expected_status") in {
            "PROPERTY_HOLDS_WITHIN_MODEL", "POTENTIAL_VIOLATION"
        }
    ]
    recovered = [item for item in extent_cases if item["inferred_property"]["capacity_source"] == "inferred"]
    correct_extents = sum(
        item["inferred_property"]["capacity"] == item["ground_truth"]["object_extent_bytes"]
        for item in recovered
    )
    tp = fp = tn = fn = abstain = 0
    for item in results.values():
        expected = item["ground_truth"].get("expected_violation")
        status = item["solver_conclusion"]["status"]
        if expected is None:
            if status == "INCONCLUSIVE":
                abstain += 1
            continue
        if status == "POTENTIAL_VIOLATION":
            if expected:
                tp += 1
            else:
                fp += 1
        elif status == "PROPERTY_HOLDS_WITHIN_MODEL":
            if expected:
                fn += 1
            else:
                tn += 1
        elif status == "INCONCLUSIVE":
            abstain += 1
    positive_truth = [item for item in results.values()
                      if item["ground_truth"].get("expected_violation") is True]
    negative_truth = [item for item in results.values()
                      if item["ground_truth"].get("expected_violation") is False]
    positive_abstentions = sum(item["solver_conclusion"]["status"] == "INCONCLUSIVE"
                               for item in positive_truth)
    negative_abstentions = sum(item["solver_conclusion"]["status"] == "INCONCLUSIVE"
                               for item in negative_truth)
    undefined_abstentions = sum(
        item["ground_truth"].get("expected_violation") is None
        and item["solver_conclusion"]["status"] == "INCONCLUSIVE"
        for item in results.values()
    )
    return {
        "expected_status_accuracy": {
            "case_denominator": len(results),
            "matched_count": sum(
                item["solver_conclusion"]["status"] == item["ground_truth"]["expected_status"]
                for item in results.values()
            ),
        },
        "extent_recovery": {
            "eligible_unique_relation_cases": len(extent_cases),
            "inferred_count": len(recovered),
            "correct_count": correct_extents,
            "accuracy_when_inferred": correct_extents / len(recovered) if recovered else None,
            "inference_abstentions_on_eligible_cases": len(extent_cases) - len(recovered),
        },
        "property_classification": {
            "denominator_excludes_non_boolean_or_ambiguous_ground_truth": True,
            "true_positive": tp,
            "false_positive": fp,
            "true_negative": tn,
            "false_negative_false_safe": fn,
            "classified_denominator": tp + fp + tn + fn,
            "correct_classified_count": tp + tn,
            "positive_ground_truth_cases": len(positive_truth),
            "classified_positive_cases": tp + fn,
            "positive_ground_truth_abstentions": positive_abstentions,
            "false_safe_rate_on_classified_positive_cases": fn / (fn + tp) if fn + tp else None,
            "negative_ground_truth_cases": len(negative_truth),
            "classified_negative_cases": tn + fp,
            "negative_ground_truth_abstentions": negative_abstentions,
            "inconclusive_total": abstain,
            "undefined_or_ambiguous_ground_truth_abstentions": undefined_abstentions,
        },
        "all_case_abstention_rate": sum(
            item["solver_conclusion"]["status"] == "INCONCLUSIVE" for item in results.values()
        ) / len(results) if results else None,
        "scope_note": "small synthetic Linux AMD64 ELF evaluation; these counts do not estimate real-world accuracy or cross-build generalization",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        print(f"refusing to overwrite existing evaluation record: {out}", file=sys.stderr)
        return 2

    work_dir = args.work_dir.resolve()
    binary_dir = work_dir / "binaries"
    results: dict[str, dict] = {}
    compile_commands: dict[str, list[str]] = {}
    source_hashes: dict[str, str] = {}
    runtimes: dict[str, float] = {}
    try:
        compiler = compiler_metadata()
        for case_name, case in CASES.items():
            source = EVALUATION_FIXTURES / case["source"]
            binary = binary_dir / f"{case_name}.so"
            if binary.exists():
                raise FileExistsError(f"refusing to overwrite existing binary artifact: {binary}")
            source_hashes[case["source"]] = _sha256(source)
            command = build_compile_command(source, binary, extra_flags=case["extra_flags"])
            compile_commands[case_name] = command
            compile_source(source, binary, extra_flags=case["extra_flags"])

            started = time.perf_counter()
            inference = infer_capacity_from_binary(
                binary, function_name="transfer", call_name="sensitive_sink", argument_index=0
            )
            verification = verify_unsigned_argument_at_call_inferred(
                binary, function_name="transfer", call_name="sensitive_sink", argument_index=0
            )
            runtimes[case_name] = round(time.perf_counter() - started, 6)
            results[case_name] = {
                "source_path": str(source),
                "source_sha256": source_hashes[case["source"]],
                "compile_command": command,
                "binary_path": str(binary),
                "binary_sha256": _sha256(binary),
                "binary_executed": False,
                "ground_truth": case["ground_truth"],
                "manual_annotations": [],
                "binary_derived_observations": {
                    "inference_status": inference.status,
                    "evidence": inference.evidence,
                    "reason": inference.reason,
                },
                "inferred_property": {
                    "capacity": verification.capacity,
                    "capacity_source": verification.capacity_source,
                    "capacity_evidence": verification.capacity_evidence,
                    "invariant_evidence": verification.invariant_evidence,
                },
                "solver_conclusion": {
                    "status": verification.status,
                    "solver_result": verification.solver_result,
                    "solver_version": verification.solver_version,
                    "query_smt2": verification.query_smt2,
                    "path_constraints": verification.path_constraints,
                    "path_evidence": verification.path_evidence,
                    "reason": verification.reason,
                    "paths_to_call": verification.paths_to_call,
                    "exploration_steps": verification.exploration_steps,
                    "exploration_complete": verification.exploration_complete,
                },
            }
    except Exception as exc:
        print(f"capacity-inference evaluation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    try:
        import angr
        import z3
        analysis_versions = {"angr": getattr(angr, "__version__", "unknown"),
                             "z3_solver": z3.get_version_string()}
    except ImportError as exc:
        analysis_versions = {"status": f"dependency unavailable: {exc}"}

    payload = {
        "record_schema": "1.0",
        "record_type": "independent_adversarial_capacity_inference_evaluation",
        "run_metadata": {
            "python": sys.version,
            "platform": platform.platform(),
            "target": "x86_64-linux-musl",
            "compiler": compiler,
            "analysis_tool_versions": analysis_versions,
            "experiment_command": [sys.executable, *sys.argv],
            "compile_commands": compile_commands,
            "analysis_runtime_seconds": runtimes,
            "binary_execution_policy": "generated fixtures are analyzed statically and never executed",
        },
        "source_hashes": source_hashes,
        "manual_annotations": {"used_as_inference_input": False, "entries": []},
        "cases": results,
        "metrics": _metrics(results),
        "test_results": None,
        "interpretation": (
            "narrow ELF STT_OBJECT extent recovery coupled to a supported VEX loop pattern; "
            "not real-world vulnerability evidence or a complete memory-safety proof"
        ),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "out": str(out),
        "sha256": _sha256(out),
        "statuses": {name: result["solver_conclusion"]["status"] for name, result in results.items()},
        "capacities": {name: result["inferred_property"]["capacity"] for name, result in results.items()},
        "metrics": payload["metrics"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
