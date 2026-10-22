"""Run the controlled binary-pair analysis and save raw results."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from compile_fixture import (  # noqa: E402
    build_compile_command,
    compile_pair,
    compile_source,
    compiler_metadata,
)
from vulngenome.binary import analyze_binary  # noqa: E402
from vulngenome.patch import compare  # noqa: E402
from vulngenome.reporting import write_json  # noqa: E402
from vulngenome.symbolic import (  # noqa: E402
    verify_unsigned_argument_at_call,
    verify_unsigned_argument_at_call_inferred,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        compiler = compiler_metadata()
        binaries = compile_pair(args.work_dir.resolve() / "binaries")
        variant_sources = {
            "capacity_24": ROOT / "fixtures" / "variants" / "transfer_capacity_24.c",
            "guard_too_large": ROOT / "fixtures" / "variants" / "transfer_guard_too_large.c",
            "sink_plus_one": ROOT / "fixtures" / "variants" / "transfer_sink_plus_one.c",
        }
        variant_binaries = {
            key: compile_source(source, args.work_dir.resolve() / "variants" / f"{key}.so")
            for key, source in variant_sources.items()
        }
        variant_binaries["metadata_stripped"] = compile_source(
            ROOT / "fixtures" / "transfer_patched.c",
            args.work_dir.resolve() / "variants" / "metadata_stripped.so",
            extra_flags=("-Wl,-s",),
        )
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"fixture experiment could not compile the controlled binaries: {exc}", file=sys.stderr)
        return 2

    timings: dict[str, float] = {}

    def timed_inference(path: str) -> dict:
        started = time.perf_counter()
        result = verify_unsigned_argument_at_call_inferred(
            path, function_name="transfer", call_name="sensitive_sink"
        )
        timings[str(Path(path).name)] = round(time.perf_counter() - started, 6)
        return result.to_dict()

    analysis = {key: analyze_binary(path).to_dict() for key, path in binaries.items()}
    pair_evidence = compare(
        analyze_binary(binaries["vulnerable"]), analyze_binary(binaries["patched"])
    )
    capacity_provenance = "manual controlled-fixture annotation in fixtures/contract.json"
    symbolic = {
        key: verify_unsigned_argument_at_call(
            path, function_name="transfer", call_name="sensitive_sink", capacity=16,
            capacity_provenance=capacity_provenance,
        ).to_dict()
        for key, path in binaries.items()
    }
    automatic = {key: timed_inference(path) for key, path in binaries.items()}
    automatic.update({key: timed_inference(path) for key, path in variant_binaries.items()})
    misleading_manual = verify_unsigned_argument_at_call(
        binaries["vulnerable"], function_name="transfer", call_name="sensitive_sink",
        capacity=(1 << 64) - 1,
        capacity_provenance="deliberately misleading negative-control annotation",
    ).to_dict()

    baseline_path = ROOT / "experiments" / "results" / "controlled-fixture-clang-20261021.json"
    baseline_record = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline_checks = {
        "record_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
        "binary_hashes_match": {},
        "manual_results_match": {},
    }
    for key, path in binaries.items():
        current_hash = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        baseline_checks["binary_hashes_match"][key] = (
            current_hash == baseline_record["binaries"][key]["sha256"]
        )
        old_result = baseline_record["symbolic_callsite_results"][key]
        new_result = symbolic[key]
        baseline_checks["manual_results_match"][key] = all(
            new_result.get(field) == old_result.get(field)
            for field in ("status", "solver_result", "capacity", "capacity_provenance")
        )
    baseline_checks["passed"] = all(baseline_checks["binary_hashes_match"].values()) and all(
        baseline_checks["manual_results_match"].values()
    )

    ground_truth = {
        "vulnerable": {"object_capacity": 16, "guard_present": False, "sink_argument": "length",
                       "expected_violation": True},
        "patched": {"object_capacity": 16, "guard_present": True, "guard_bound": 16,
                    "sink_argument": "length", "expected_violation": False},
        "capacity_24": {"object_capacity": 24, "guard_present": True, "guard_bound": 24,
                        "sink_argument": "length", "expected_violation": False},
        "guard_too_large": {"object_capacity": 16, "guard_present": True, "guard_bound": 32,
                             "sink_argument": "length", "expected_violation": True},
        "sink_plus_one": {"object_capacity": 16, "guard_present": True, "guard_bound": 16,
                          "sink_argument": "length + 1", "expected_violation": True},
        "metadata_stripped": {"object_capacity": 16, "guard_present": True, "guard_bound": 16,
                              "sink_argument": "length", "expected_violation": False,
                              "evaluation_note": "ground truth only; symbol metadata intentionally stripped"},
    }
    inference_cases = {**binaries, **variant_binaries}
    case_metrics = {}
    correct_capacity = 0
    inferred_capacity_count = 0
    true_positive = false_positive = true_negative = false_negative = 0
    abstentions = inference_abstentions = analysis_failures = timeouts = 0
    for key, path in inference_cases.items():
        observed = automatic[key]
        expected = ground_truth[key]["object_capacity"]
        expected_violation = ground_truth[key]["expected_violation"]
        capacity_ok = observed.get("capacity") == expected and observed.get("capacity_source") == "inferred"
        if observed.get("capacity_source") == "inferred":
            inferred_capacity_count += 1
            correct_capacity += int(capacity_ok)
        else:
            inference_abstentions += 1
        if observed.get("status") == "POTENTIAL_VIOLATION":
            if expected_violation:
                true_positive += 1
            else:
                false_positive += 1
        elif observed.get("status") == "PROPERTY_HOLDS_WITHIN_MODEL":
            if expected_violation:
                false_negative += 1
            else:
                true_negative += 1
        elif observed.get("status") == "INCONCLUSIVE":
            abstentions += 1
        elif observed.get("status") == "ANALYSIS_ERROR":
            analysis_failures += 1
        if observed.get("solver_result") == "unknown":
            timeouts += int("timeout" in str(observed.get("reason", "")).lower())
        case_metrics[key] = {
            "ground_truth": ground_truth[key],
            "inferred_capacity": observed.get("capacity"),
            "inference_status": observed.get("status"),
            "verification_status": observed.get("status"),
            "expected_violation": expected_violation,
            "capacity_correct_when_inferred": capacity_ok if observed.get("capacity_source") == "inferred" else None,
            "binary_sha256": observed.get("binary_sha256"),
            "runtime_seconds": timings.get(Path(path).name),
        }

    compile_inputs = {
        "vulnerable": (ROOT / "fixtures" / "transfer_vulnerable.c", binaries["vulnerable"], ()),
        "patched": (ROOT / "fixtures" / "transfer_patched.c", binaries["patched"], ()),
        **{key: (source, variant_binaries[key], ()) for key, source in variant_sources.items()},
        "metadata_stripped": (ROOT / "fixtures" / "transfer_patched.c",
                              variant_binaries["metadata_stripped"], ("-Wl,-s",)),
    }
    compile_commands = {
        key: build_compile_command(source, Path(output), extra_flags=extra_flags)
        for key, (source, output, extra_flags) in compile_inputs.items()
    }
    try:
        import angr
        import z3
        from angr import claripy
        analysis_versions = {
            "angr": getattr(angr, "__version__", "unknown"),
            "angr_claripy": getattr(claripy, "__version__", "version not exposed"),
            "z3_solver": z3.get_version_string(),
        }
    except ImportError as exc:
        analysis_versions = {"status": f"dependency unavailable: {exc}"}

    payload = {
        "record_schema": "2.0",
        "record_type": "annotation_free_capacity_inference_experiment",
        "run_metadata": {"python": sys.version, "platform": platform.platform(), "compiler": compiler,
                         "target": "x86_64-linux-musl", "flags": ["-O0", "-g", "-fno-stack-protector", "-fPIC", "-shared",
                                   "-nostdlib", "-fuse-ld=lld", "-Wl,-Bsymbolic"] if compiler["name"] == "clang" else
                                  ["-O0", "-g", "-fno-stack-protector", "-fPIC", "-shared"],
                         "analysis_tool_versions": analysis_versions,
                         "experiment_command": [sys.executable, *sys.argv],
                         "compile_commands": compile_commands,
                         "analysis_runtime_seconds": timings},
        "fixture_annotation": json.loads((ROOT / "fixtures" / "contract.json").read_text(encoding="utf-8")),
        "binaries": {
            key: {"path": path, "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}
            for key, path in {**binaries, **variant_binaries}.items()
        },
        "binary_analysis": analysis,
        "patch_evidence": pair_evidence,
        "manual_annotation_control": symbolic,
        "manual_misleading_capacity_control": misleading_manual,
        "baseline_consistency": baseline_checks,
        "automatic_inference_and_verification": automatic,
        "ground_truth_and_evaluation": {
            "labels_are_separate_from_analyzer_inputs": True,
            "cases": case_metrics,
            "capacity_recovery": {"inferred_count": inferred_capacity_count,
                                  "correct_count": correct_capacity,
                                  "accuracy_when_inferred": (correct_capacity / inferred_capacity_count
                                                             if inferred_capacity_count else None),
                                  "abstentions": inference_abstentions},
            "verification_metrics": {
                "true_positive": true_positive, "false_positive": false_positive,
                "true_negative": true_negative, "false_negative_false_safe": false_negative,
                "abstentions": abstentions, "analysis_failures": analysis_failures,
                "solver_timeouts_or_unknown_timeout_reasons": timeouts,
                "false_positive_rate_on_classified_cases": (
                    false_positive / (false_positive + true_negative)
                    if false_positive + true_negative else None
                ),
                "false_safe_rate_on_classified_cases": (
                    false_negative / (false_negative + true_positive)
                    if false_negative + true_positive else None
                ),
                "abstention_rate": abstentions / len(automatic) if automatic else None,
                "manual_misleading_annotation_false_safe": misleading_manual["status"] == "PROPERTY_HOLDS_WITHIN_MODEL",
            },
            "runtime_seconds": {"total": round(sum(timings.values()), 6),
                                "by_binary_basename": timings},
            "scope_note": "single controlled fixture family; these metrics do not estimate generalization",
        },
        "interpretation": "narrow binary-derived ELF object-extent inference and call-argument bound evaluation; not a real-world vulnerability result or general allocation-size inference",
    }
    write_json(args.out, payload)
    print(json.dumps({"out": str(args.out.resolve()), "sha256": payload["binaries"],
                      "manual_states": {key: value["status"] for key, value in symbolic.items()},
                      "automatic_states": {key: value["status"] for key, value in automatic.items()},
                      "baseline_consistency_passed": baseline_checks["passed"],
                      "misleading_manual_state": misleading_manual["status"]}, indent=2))
    return 0 if (baseline_checks["passed"] and
                  all(v["status"] != "ANALYSIS_ERROR" for v in [*symbolic.values(), *automatic.values()])) else 2


if __name__ == "__main__":
    raise SystemExit(main())
