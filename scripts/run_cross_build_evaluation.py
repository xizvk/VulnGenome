"""Compile-only optimization and cross-build invariant evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from compile_fixture import compiler_metadata  # noqa: E402
from vulngenome.binary import analyze_binary, parse_metadata  # noqa: E402
from vulngenome.capacity import infer_capacity_from_binary  # noqa: E402
from vulngenome.patch import compare  # noqa: E402
from vulngenome.symbolic import verify_unsigned_argument_at_call_inferred  # noqa: E402
from vulngenome.transfer import create_transfer_proposal, evaluate_cross_build_transfer  # noqa: E402


BASE_FLAGS = [
    "--target=x86_64-linux-musl", "-g", "-fno-stack-protector", "-fPIC",
    "-shared", "-nostdlib", "-fuse-ld=lld", "-Wl,-Bsymbolic",
]
OPT_LEVELS = ("O0", "O1", "O2", "O3", "Os")
MATRIX_CASES = (
    "original_vulnerable", "original_patched", "capacity_changed",
    "guard_too_large", "sink_plus_one", "unrelated_decoy",
    "ambiguous_objects", "stripped_symbols",
)
INDEPENDENT_CASES = (
    "frame_vulnerable", "frame_patched", "telemetry_vulnerable", "telemetry_patched",
)
CASES: dict[str, dict[str, Any]] = {
    "original_vulnerable": {
        "source": "fixtures/transfer_vulnerable.c", "function": "transfer", "sink": "sensitive_sink",
        "ground_truth": "VULNERABLE", "pair": "original-transfer",
        "provenance": "controlled original fixture has no caller guard before forwarding length",
    },
    "original_patched": {
        "source": "fixtures/transfer_patched.c", "function": "transfer", "sink": "sensitive_sink",
        "ground_truth": "PATCHED", "pair": "original-transfer",
        "provenance": "controlled original fixture rejects length above the 16-byte object extent",
    },
    "capacity_changed": {
        "source": "fixtures/variants/transfer_capacity_24.c", "function": "transfer", "sink": "sensitive_sink",
        "ground_truth": "PATCHED", "pair": None,
        "provenance": "existing 24-byte capacity control and caller guard are unchanged",
    },
    "guard_too_large": {
        "source": "fixtures/variants/transfer_guard_too_large.c", "function": "transfer", "sink": "sensitive_sink",
        "ground_truth": "VULNERABLE", "pair": None,
        "provenance": "existing caller guard permits values through 32 for a 16-byte object",
    },
    "sink_plus_one": {
        "source": "fixtures/variants/transfer_sink_plus_one.c", "function": "transfer", "sink": "sensitive_sink",
        "ground_truth": "VULNERABLE", "pair": None,
        "provenance": "existing caller checks length but passes length + 1 to the sink",
    },
    "unrelated_decoy": {
        "source": "fixtures/evaluation/capacity-inference/unrelated_decoy.c", "function": "transfer", "sink": "sensitive_sink",
        "ground_truth": "VULNERABLE", "pair": None,
        "provenance": "existing negative control writes a 17-byte global at fixed offset 17 for nonzero sink arguments",
    },
    "ambiguous_objects": {
        "source": "fixtures/evaluation/capacity-inference/multiple_candidate_ambiguous.c", "function": "transfer", "sink": "sensitive_sink",
        "ground_truth": "PATCHED", "pair": None,
        "provenance": "caller bounds the sink argument by 7; both argument-indexed destinations are at least 7 bytes, but object identity is ambiguous",
    },
    "stripped_symbols": {
        "source": "fixtures/transfer_patched.c", "function": "transfer", "sink": "sensitive_sink",
        "ground_truth": "PATCHED", "pair": None, "extra_flags": ("-Wl,-s",),
        "provenance": "same patched source, linked with symbol stripping to remove static object metadata",
    },
    "frame_vulnerable": {
        "source": "fixtures/cross-build/frame_vulnerable.c", "function": "receive_frame", "sink": "stage_frame",
        "ground_truth": "VULNERABLE", "pair": "frame-staging",
        "provenance": "independent frame-staging pair; no upper-bound check before the sink call",
    },
    "frame_patched": {
        "source": "fixtures/cross-build/frame_patched.c", "function": "receive_frame", "sink": "stage_frame",
        "ground_truth": "PATCHED", "pair": "frame-staging",
        "provenance": "independent frame-staging pair; rejects declared lengths above frame_slab extent",
    },
    "telemetry_vulnerable": {
        "source": "fixtures/cross-build/telemetry_vulnerable.c", "function": "accept_sample", "sink": "commit_sample",
        "ground_truth": "VULNERABLE", "pair": "telemetry-sample",
        "provenance": "independent pair checks requested <= 7 but passes requested + 1; same-sized telemetry_count is a fixed-index decoy",
    },
    "telemetry_patched": {
        "source": "fixtures/cross-build/telemetry_patched.c", "function": "accept_sample", "sink": "commit_sample",
        "ground_truth": "PATCHED", "pair": "telemetry-sample",
        "provenance": "independent pair checks requested <= 7 and passes requested; same-sized telemetry_count remains a fixed-index decoy",
    },
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _compile(clang: str, source: Path, binary: Path, optimization: str,
             extra_flags: tuple[str, ...] = ()) -> dict[str, Any]:
    if binary.exists():
        raise FileExistsError(f"refusing to overwrite existing binary: {binary}")
    binary.parent.mkdir(parents=True, exist_ok=True)
    command = [clang, *BASE_FLAGS[:1], f"-{optimization}", *BASE_FLAGS[1:],
               *extra_flags, str(source.resolve()), "-o", str(binary.resolve())]
    started = time.perf_counter()
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=90)
        elapsed = round(time.perf_counter() - started, 6)
        return {
            "command": command,
            "return_code": completed.returncode,
            "timed_out": False,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "runtime_seconds": elapsed,
            "binary_path": str(binary.resolve()) if completed.returncode == 0 else None,
            "binary_sha256": _sha256(binary) if completed.returncode == 0 and binary.is_file() else None,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command, "return_code": None, "timed_out": True,
            "stdout": _to_text(exc.stdout), "stderr": _to_text(exc.stderr),
            "runtime_seconds": round(time.perf_counter() - started, 6),
            "binary_path": None, "binary_sha256": None,
        }


def _to_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def _symbol_metadata(binary: Path, function_name: str, sink_name: str) -> dict[str, Any]:
    import angr

    project = angr.Project(str(binary), auto_load_libs=False)
    symbols = []
    for symbol in project.loader.main_object.symbols:
        symbol_type = getattr(getattr(symbol, "type", None), "name", str(getattr(symbol, "type", "")))
        is_function = symbol_type.endswith("TYPE_FUNCTION")
        is_object = symbol_type.endswith("TYPE_OBJECT")
        if ((is_function and symbol.name in {function_name, sink_name})
                or (is_object and int(getattr(symbol, "size", 0) or 0) > 0)):
            symbols.append({
                "name": str(symbol.name), "type": symbol_type,
                "size_bytes": int(getattr(symbol, "size", 0) or 0),
                "address": int(symbol.rebased_addr),
            })
    return {
        "extractor": "angr loader symbol table",
        "symbols_available": bool(symbols),
        "relevant_symbols": sorted(symbols, key=lambda item: (item["type"], item["name"], item["address"])),
    }


def _build_record(case_name: str, optimization: str, case: dict[str, Any],
                  build: dict[str, Any]) -> tuple[dict[str, Any], Any | None]:
    row: dict[str, Any] = {
        "case": case_name,
        "optimization_level": optimization,
        "source_path": str((ROOT / case["source"]).resolve()),
        "source_sha256": _sha256(ROOT / case["source"]),
        "source_level_ground_truth": {
            "security_class": case["ground_truth"],
            "pair": case.get("pair"),
            "provenance": case["provenance"],
        },
        "build": build,
        "artifact": None,
        "symbol_metadata": None,
        "independent_analysis": None,
        "analysis_runtime_seconds": None,
    }
    if build["return_code"] != 0:
        row["independent_analysis"] = {
            "classification": "ANALYSIS_ERROR", "solver_result": "not-run",
            "reason": "compile timeout" if build["timed_out"] else "compiler returned nonzero",
        }
        return row, None
    binary = Path(build["binary_path"])
    metadata = parse_metadata(binary, binary.read_bytes())
    row["artifact"] = {
        "path": str(binary), "sha256": build["binary_sha256"],
        "size_bytes": metadata.size_bytes, "file_format": metadata.file_format,
        "architecture": metadata.architecture, "endianness": metadata.endianness,
        "build_id": metadata.build_id,
    }
    started = time.perf_counter()
    result = None
    try:
        row["symbol_metadata"] = _symbol_metadata(binary, case["function"], case["sink"])
        inference = infer_capacity_from_binary(binary, function_name=case["function"], call_name=case["sink"])
        result = verify_unsigned_argument_at_call_inferred(
            binary, function_name=case["function"], call_name=case["sink"]
        )
        row["independent_analysis"] = {
            "classification": result.status,
            "solver_result": result.solver_result,
            "capacity_bytes": result.capacity,
            "capacity_source": result.capacity_source,
            "inference_status": inference.status,
            "inference_reason": inference.reason,
            "inference_evidence": inference.to_dict(),
            "binary_derived_path_constraints": list(result.path_constraints),
            "query_smt2": result.query_smt2,
            "path_evidence": list(result.path_evidence),
            "invariant_evidence": result.invariant_evidence,
            "paths_to_call": result.paths_to_call,
            "exploration_steps": result.exploration_steps,
            "exploration_complete": result.exploration_complete,
            "assumptions": (result.invariant_evidence or {}).get("assumptions", []),
            "reason": result.reason,
            "binary_hash_bound": result.binary_sha256 == build["binary_sha256"],
        }
    except Exception as exc:
        row["independent_analysis"] = {
            "classification": "ANALYSIS_ERROR", "solver_result": "error",
            "reason": f"{type(exc).__name__}: {exc}",
        }
    row["analysis_runtime_seconds"] = round(time.perf_counter() - started, 6)
    try:
        row["symbol_metadata"] = row["symbol_metadata"] or _symbol_metadata(binary, case["function"], case["sink"])
    except Exception as exc:
        row["symbol_metadata"] = {"error": f"{type(exc).__name__}: {exc}"}
    return row, result


def _prediction(status: str) -> str:
    return {
        "POTENTIAL_VIOLATION": "VULNERABLE",
        "PROPERTY_HOLDS_WITHIN_MODEL": "PATCHED",
        "INCONCLUSIVE": "INCONCLUSIVE",
    }.get(status, "ANALYSIS_ERROR")


def _classification_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labeled = [row for row in rows
               if row["source_level_ground_truth"]["security_class"] in {"VULNERABLE", "PATCHED"}]
    tp = sum(row["source_level_ground_truth"]["security_class"] == "VULNERABLE"
             and _prediction(row["independent_analysis"]["classification"]) == "VULNERABLE" for row in labeled)
    tn = sum(row["source_level_ground_truth"]["security_class"] == "PATCHED"
             and _prediction(row["independent_analysis"]["classification"]) == "PATCHED" for row in labeled)
    fp = sum(row["source_level_ground_truth"]["security_class"] == "PATCHED"
             and _prediction(row["independent_analysis"]["classification"]) == "VULNERABLE" for row in labeled)
    fn = sum(row["source_level_ground_truth"]["security_class"] == "VULNERABLE"
             and _prediction(row["independent_analysis"]["classification"]) == "PATCHED" for row in labeled)
    vulnerable = sum(row["source_level_ground_truth"]["security_class"] == "VULNERABLE" for row in labeled)
    patched = sum(row["source_level_ground_truth"]["security_class"] == "PATCHED" for row in labeled)
    classified = tp + tn + fp + fn
    inconclusive = sum(_prediction(row["independent_analysis"]["classification"]) == "INCONCLUSIVE" for row in labeled)
    failures = len(labeled) - classified - inconclusive
    return {
        "eligible_labeled_denominator": len(labeled),
        "vulnerable_ground_truth_count": vulnerable,
        "patched_ground_truth_count": patched,
        "classified_count": classified,
        "inconclusive_count": inconclusive,
        "failed_or_unbuilt_count": failures,
        "abstention_rate_on_eligible": inconclusive / len(labeled) if labeled else None,
        "decision_coverage": classified / len(labeled) if labeled else None,
        "tp": tp, "tn": tn, "fp": fp, "false_safe_fn": fn,
        "accuracy_on_classified": (tp + tn) / classified if classified else None,
        "vulnerable_precision": tp / (tp + fp) if tp + fp else None,
        "vulnerable_recall_on_classified_vulnerable": tp / (tp + fn) if tp + fn else None,
        "false_safe_rate_on_classified_vulnerable": fn / (tp + fn) if tp + fn else None,
        "vulnerable_detection_rate_over_all_eligible": tp / vulnerable if vulnerable else None,
        "false_safe_count": fn,
        "false_safe_rate_over_all_vulnerable": fn / vulnerable if vulnerable else None,
    }


def _target_evidence_summary(target_row: dict[str, Any] | None) -> dict[str, Any] | None:
    """Summarize the target build's own evidence, including reasons for abstention."""
    if target_row is None:
        return None
    analysis = target_row.get("independent_analysis") or {}
    inference = analysis.get("inference_evidence") or {}
    evidence = inference.get("evidence") or {}
    symbol = evidence.get("object_symbol") or {}
    relationship = evidence.get("data_flow_relationship") or {}
    call_site = evidence.get("call_site") or {}
    paths = analysis.get("path_evidence") or []
    digest = (target_row.get("artifact") or {}).get("sha256")
    return {
        "binary_sha256": digest,
        "binary_hash_bound": analysis.get("binary_hash_bound"),
        "independent_classification": analysis.get("classification"),
        "analysis_reason": analysis.get("reason"),
        "solver_result": analysis.get("solver_result"),
        "capacity_bytes": analysis.get("capacity_bytes"),
        "capacity_inference_status": analysis.get("inference_status"),
        "capacity_inference_reason": analysis.get("inference_reason"),
        "object_symbol": symbol.get("name"),
        "object_relation_status": relationship.get("status"),
        "argument_index": relationship.get("argument_index"),
        "call_instruction_address": call_site.get("instruction_address"),
        "binary_derived_path_count": len(paths),
        "path_hashes_match_target": (
            all(item.get("binary_sha256") == digest for item in paths) if paths else None
        ),
        "exploration_complete": analysis.get("exploration_complete"),
    }


def _transfer_attempt(source_row: dict[str, Any] | None, source_result: Any | None,
                      target_row: dict[str, Any] | None, target_result: Any | None,
                      source_label: str, target_label: str) -> dict[str, Any]:
    source_hash = (source_row or {}).get("artifact", {}).get("sha256")
    target_hash = (target_row or {}).get("artifact", {}).get("sha256")
    attempt = {
        "source_build": source_label, "target_build": target_label,
        "source_binary_sha256": source_hash, "target_binary_sha256": target_hash,
        "property_inferred_in_source": None, "matching_method": "not-run",
        "target_specific_evidence_recovered": _target_evidence_summary(target_row),
        "transfer_status": "INCONCLUSIVE", "property_classification": "INCONCLUSIVE",
        "solver_result": "not-run", "assumptions": [], "reason": None,
    }
    if source_result is None or target_result is None or source_row is None or target_row is None:
        attempt["transfer_status"] = "ANALYSIS_ERROR"
        attempt["reason"] = "source or target build/analysis is unavailable"
        return attempt
    try:
        proposal = create_transfer_proposal(Path(source_row["artifact"]["path"]), source_result)
    except (ValueError, KeyError, TypeError) as exc:
        attempt["reason"] = f"source property cannot be proposed: {exc}"
        return attempt
    target_path = Path(target_row["artifact"]["path"])
    result = evaluate_cross_build_transfer(proposal, target_path, target_result)
    attempt.update({
        "property_inferred_in_source": proposal["abstract_property"],
        "matching_method": "semantic names propose mapping; target must independently recover object-store-guard-call-path evidence",
        "target_evidence_validation": result["target_evidence_validation"],
        "transfer_status": result["transfer_status"],
        "property_classification": result["property_classification"],
        "solver_result": result["solver_result"],
        "target_evidence_validation": result["target_evidence_validation"],
        "source_evidence_reused": result["source_evidence_reused"],
        "assumptions": (target_result.invariant_evidence or {}).get("assumptions", []),
        "reason": result["reason"],
    })
    if result["target_specific_evidence"] is not None:
        attempt["target_specific_evidence_recovered"]["transfer_validation"] = result["target_specific_evidence"]
    return attempt


def _transfer_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for row in rows:
        key = row["transfer_status"]
        counts[key] = counts.get(key, 0) + 1
    return {
        "attempt_denominator": len(rows),
        "counts_by_transfer_status": counts,
        "accepted_rate_on_attempts": counts.get("ACCEPTED", 0) / len(rows) if rows else None,
        "abstention_rate_on_attempts": counts.get("INCONCLUSIVE", 0) / len(rows) if rows else None,
        "failed_count": counts.get("ANALYSIS_ERROR", 0),
        "property_classifications": {
            status: sum(row["property_classification"] == status for row in rows)
            for status in ("POTENTIAL_VIOLATION", "PROPERTY_HOLDS_WITHIN_MODEL", "INCONCLUSIVE")
        },
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
    if work_dir.exists() and any(work_dir.iterdir()):
        print(f"refusing to use non-empty work directory: {work_dir}", file=sys.stderr)
        return 2
    work_dir.mkdir(parents=True, exist_ok=True)

    compiler = compiler_metadata()
    clang = compiler["executable"]
    builds: dict[str, dict[str, Any]] = {}
    result_objects: dict[str, Any] = {}
    build_specs = [(name, level) for name in MATRIX_CASES for level in OPT_LEVELS]
    build_specs.extend((name, level) for name in INDEPENDENT_CASES for level in ("O0", "O2"))
    for name, level in build_specs:
        case = CASES[name]
        key = f"{name}@{level}"
        source = ROOT / case["source"]
        binary = work_dir / "binaries" / level / f"{name}.so"
        build = _compile(clang, source, binary, level, tuple(case.get("extra_flags", ())))
        row, result = _build_record(name, level, case, build)
        row["build"]["optimization_level"] = level
        row["build"]["compiler_version"] = compiler["version"]
        row["build"]["linker_version"] = compiler.get("linker_version")
        row["build"]["target"] = "x86_64-linux-musl"
        row["build"]["artifact_format_requested"] = "ELF64 AMD64 shared object"
        row["build"]["base_flags"] = ["--target=x86_64-linux-musl", f"-{level}", *BASE_FLAGS[1:]]
        row["build"]["extra_flags"] = list(case.get("extra_flags", ()))
        builds[key] = row
        result_objects[key] = result

    transfers: list[dict[str, Any]] = []
    for name in MATRIX_CASES:
        source_key = f"{name}@O0"
        for level in OPT_LEVELS[1:]:
            target_key = f"{name}@{level}"
            transfers.append(_transfer_attempt(
                builds[source_key], result_objects[source_key], builds[target_key], result_objects[target_key],
                source_key, target_key,
            ))
    for name in INDEPENDENT_CASES:
        source_key, target_key = f"{name}@O0", f"{name}@O2"
        transfers.append(_transfer_attempt(
            builds[source_key], result_objects[source_key], builds[target_key], result_objects[target_key],
            source_key, target_key,
        ))
    for vulnerable_name, patched_name, pair_name in (
        ("frame_vulnerable", "frame_patched", "frame-staging"),
        ("telemetry_vulnerable", "telemetry_patched", "telemetry-sample"),
    ):
        source_key, target_key = f"{vulnerable_name}@O0", f"{patched_name}@O2"
        transfer = _transfer_attempt(
            builds[source_key], result_objects[source_key], builds[target_key], result_objects[target_key],
            f"{pair_name}:vulnerable@O0", f"{pair_name}:patched@O2",
        )
        transfer["pair_transfer"] = pair_name
        transfers.append(transfer)

    stale_control: dict[str, Any] | None = None
    src_key, tgt_key = "original_vulnerable@O0", "original_patched@O2"
    try:
        proposal = create_transfer_proposal(Path(builds[src_key]["artifact"]["path"]), result_objects[src_key])
        stale = evaluate_cross_build_transfer(
            proposal, Path(builds[tgt_key]["artifact"]["path"]), result_objects[src_key]
        )
        stale_control = {
            "source_binary_sha256": builds[src_key]["artifact"]["sha256"],
            "target_binary_sha256": builds[tgt_key]["artifact"]["sha256"],
            "presented_target_result_binary_sha256": result_objects[src_key].binary_sha256,
            **stale,
            "purpose": "deliberately supply source-build result as target evidence; hash mismatch must reject it",
        }
    except Exception as exc:
        stale_control = {"transfer_status": "ANALYSIS_ERROR", "reason": f"{type(exc).__name__}: {exc}"}

    pair_comparisons: dict[str, Any] = {}
    pair_specs = [
        ("original-transfer", "original_vulnerable", "original_patched", OPT_LEVELS),
        ("frame-staging", "frame_vulnerable", "frame_patched", ("O0", "O2")),
        ("telemetry-sample", "telemetry_vulnerable", "telemetry_patched", ("O0", "O2")),
    ]
    for pair, vulnerable_name, patched_name, levels in pair_specs:
        pair_comparisons[pair] = {}
        for level in levels:
            left = Path(builds[f"{vulnerable_name}@{level}"]["artifact"]["path"])
            right = Path(builds[f"{patched_name}@{level}"]["artifact"]["path"])
            try:
                pair_comparisons[pair][level] = compare(
                    analyze_binary(left), analyze_binary(right)
                )
            except Exception as exc:
                pair_comparisons[pair][level] = {"error": f"{type(exc).__name__}: {exc}"}

    by_optimization = {}
    for level in OPT_LEVELS:
        rows = [row for key, row in builds.items() if key.endswith(f"@{level}")]
        by_optimization[level] = {
            "built_case_count": len(rows),
            "independent_inference_metrics": _classification_metrics(rows),
            "cases": {
                row["case"]: {
                    "ground_truth": row["source_level_ground_truth"]["security_class"],
                    "classification": row["independent_analysis"]["classification"],
                    "solver_result": row["independent_analysis"]["solver_result"],
                    "capacity_bytes": row["independent_analysis"].get("capacity_bytes"),
                    "reason": row["independent_analysis"].get("reason"),
                    "analysis_runtime_seconds": row["analysis_runtime_seconds"],
                } for row in rows
            },
            "cross_build_transfers_as_target": _transfer_metrics([
                row for row in transfers if row["target_build"].endswith(f"@{level}")
            ]),
        }

    overall_build_rows = list(builds.values())
    payload = {
        "record_schema": "1.0",
        "record_type": "cross_build_optimization_invariant_evaluation",
        "run_metadata": {
            "date": "2026-10-22",
            "python": sys.version,
            "platform": platform.platform(),
            "target": "x86_64-linux-musl",
            "artifact_format": "ELF64 AMD64 shared object",
            "compiler": compiler,
            "optimization_levels": list(OPT_LEVELS),
            "matrix_cases": list(MATRIX_CASES),
            "independent_fixture_cases": list(INDEPENDENT_CASES),
            "compiler_flags_except_optimization": BASE_FLAGS,
            "binary_execution_policy": "all generated ELFs are analyzed statically and never executed",
            "experiment_command": [sys.executable, *sys.argv],
        },
        "source_level_ground_truth_policy": "ground truth is stored separately and is not passed to compilation-independent inference or transfer APIs",
        "builds": builds,
        "patch_comparisons": pair_comparisons,
        "cross_build_transfers": transfers,
        "stale_evidence_negative_control": stale_control,
        "independent_inference_metrics_by_optimization": by_optimization,
        "independent_inference_metrics_pooled_repeated_builds": _classification_metrics(overall_build_rows),
        "cross_build_transfer_metrics": _transfer_metrics(transfers),
        "solver_policy": {
            "sat": "a target-specific counterexample is POTENTIAL_VIOLATION",
            "unsat": "PROPERTY_HOLDS_WITHIN_MODEL only when target exploration is complete",
            "unknown_or_incomplete": "INCONCLUSIVE; never treated as proof of safety",
        },
        "interpretation": "Optimization and cross-build conclusions are limited to this small synthetic Linux AMD64 ELF corpus and the recorded Clang/LLD build settings; accepted transfer always includes fresh target-specific analysis.",
        "test_results": None,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "out": str(out), "sha256": _sha256(out), "build_count": len(builds),
        "transfer_metrics": payload["cross_build_transfer_metrics"],
        "by_optimization": {
            level: item["independent_inference_metrics"]
            for level, item in by_optimization.items()
        },
        "stale_control": stale_control,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
