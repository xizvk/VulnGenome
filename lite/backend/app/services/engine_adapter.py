from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any, Callable

from ..config import REPO_ROOT
from ..elf import validate_elf64_amd64_shared_object

SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


PROFILE = {
    "id": "controlled-linux-amd64-shared-object-v1",
    "file_format": "ELF64",
    "endianness": "little",
    "architecture": "AMD64 / x86-64",
    "object_type": "ET_DYN shared object",
    "analysis": "static only; no uploaded binary is executed",
    "scope": "controlled Linux AMD64 fixtures and currently supported VulnGenome patterns",
}


def run_pair_analysis(
    vulnerable_path: str | Path,
    patched_path: str | Path,
    profile: str = "controlled-linux-amd64-shared-object-v1",
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run the existing binary engine over the two actual uploaded artifacts."""
    if profile != PROFILE["id"]:
        raise ValueError(f"unsupported analysis profile: {profile}")

    from vulngenome.binary import analyze_binary
    from vulngenome.capacity import infer_capacity_from_binary
    from vulngenome.patch import compare
    from vulngenome.symbolic import verify_unsigned_argument_at_call_inferred

    vulnerable_path = Path(vulnerable_path).resolve(strict=True)
    patched_path = Path(patched_path).resolve(strict=True)
    vulnerable_bytes = vulnerable_path.read_bytes()
    patched_bytes = patched_path.read_bytes()
    vulnerable_info = validate_elf64_amd64_shared_object(vulnerable_bytes)
    patched_info = validate_elf64_amd64_shared_object(patched_bytes)
    if (vulnerable_info.architecture, vulnerable_info.endianness, vulnerable_info.object_type) != (
        patched_info.architecture, patched_info.endianness, patched_info.object_type
    ):
        raise ValueError("The uploaded artifacts do not share the supported binary profile")

    def set_stage(name: str) -> None:
        if progress:
            progress(name)

    set_stage("IDENTIFYING")
    vulnerable_sha = hashlib.sha256(vulnerable_bytes).hexdigest()
    patched_sha = hashlib.sha256(patched_bytes).hexdigest()
    if vulnerable_info.sha256 != vulnerable_sha or patched_info.sha256 != patched_sha:
        raise RuntimeError("upload hash changed between intake and engine analysis")

    set_stage("ANALYZING")
    vulnerable_analysis = analyze_binary(vulnerable_path, use_angr=True)
    patched_analysis = analyze_binary(patched_path, use_angr=True)
    if vulnerable_analysis.metadata.sha256 != vulnerable_sha or patched_analysis.metadata.sha256 != patched_sha:
        raise RuntimeError("engine metadata hash does not match the quarantined upload")

    # Keep genuine engine records while replacing local quarantine paths with
    # user-supplied basenames before they enter a report or browser response.
    vulnerable_record = vulnerable_analysis.to_dict()
    patched_record = patched_analysis.to_dict()
    vulnerable_record["metadata"]["path"] = vulnerable_path.name
    patched_record["metadata"]["path"] = patched_path.name

    set_stage("COMPARING")
    comparison = compare(vulnerable_analysis, patched_analysis)
    candidates = _candidate_pairs(vulnerable_analysis.functions, patched_analysis.functions, comparison)

    set_stage("INFERRING")
    inference_attempts: list[dict[str, Any]] = []
    selected: dict[str, Any] | None = None
    for candidate in candidates[:12]:
        function_name = candidate["function"]
        call_name = candidate["call"]
        old_inference = infer_capacity_from_binary(
            vulnerable_path, function_name=function_name, call_name=call_name, argument_index=0
        ).to_dict()
        new_inference = infer_capacity_from_binary(
            patched_path, function_name=function_name, call_name=call_name, argument_index=0
        ).to_dict()
        attempt = {
            "function": function_name,
            "call": call_name,
            "vulnerable": old_inference,
            "patched": new_inference,
        }
        inference_attempts.append(attempt)
        if (old_inference.get("status") == "INFERRED" and old_inference.get("capacity") is not None
                and new_inference.get("status") == "INFERRED" and new_inference.get("capacity") is not None):
            selected = attempt
            break

    verification: dict[str, Any] | None = None
    abstentions: list[str] = []
    if selected is None:
        if not candidates:
            abstentions.append("No unique common caller-to-callee function pair was recovered from both binaries.")
        elif len(candidates) > 12:
            abstentions.append("Candidate search was capped at 12 actual caller-to-callee pairs.")
        else:
            abstentions.append("No common caller-to-callee pair satisfied the engine's automatic extent-inference obligations.")
        for attempt in inference_attempts:
            for variant in ("vulnerable", "patched"):
                reason = attempt[variant].get("reason")
                if reason:
                    abstentions.append(f"{attempt['function']} -> {attempt['call']} ({variant}): {reason}")
    else:
        set_stage("VERIFYING")
        function_name, call_name = selected["function"], selected["call"]
        old_result = verify_unsigned_argument_at_call_inferred(
            vulnerable_path, function_name=function_name, call_name=call_name,
            argument_index=0, timeout_ms=5000, max_steps=100,
        ).to_dict()
        new_result = verify_unsigned_argument_at_call_inferred(
            patched_path, function_name=function_name, call_name=call_name,
            argument_index=0, timeout_ms=5000, max_steps=100,
        ).to_dict()
        verification = {"function": function_name, "call": call_name,
                        "vulnerable": old_result, "patched": new_result}
        for variant, result in (("vulnerable", old_result), ("patched", new_result)):
            if result.get("status") in {"INCONCLUSIVE", "ANALYSIS_ERROR"}:
                abstentions.append(f"{variant} solver result: {result.get('reason') or result.get('status')}")

    set_stage("GENERATING_REPORT")
    complete = bool(verification) and all(
        verification[variant].get("status") in {"POTENTIAL_VIOLATION", "PROPERTY_HOLDS_WITHIN_MODEL"}
        for variant in ("vulnerable", "patched")
    )
    engine_status = "COMPLETED" if complete else "INCONCLUSIVE"
    evidence = _evidence_ledger(
        vulnerable_record, patched_record, comparison, inference_attempts, verification
    )
    return {
        "schema_version": "1.0",
        "analysis_status": engine_status,
        "profile": PROFILE,
        "static_only": True,
        "artifacts": {
            "vulnerable": {"sha256": vulnerable_sha, "size_bytes": len(vulnerable_bytes),
                           "elf": vulnerable_info.to_dict(), "analysis": vulnerable_record},
            "patched": {"sha256": patched_sha, "size_bytes": len(patched_bytes),
                        "elf": patched_info.to_dict(), "analysis": patched_record},
        },
        "comparison": comparison,
        "inference": {
            "selected": {"function": selected["function"], "call": selected["call"]} if selected else None,
            "attempts": inference_attempts,
            "candidate_count": len(candidates),
            "candidate_search_limit": 12,
        },
        "verification": verification,
        "evidence": evidence,
        "abstentions": list(dict.fromkeys(abstentions)),
        "limitations": [
            "Function matching uses unique exact symbol names only.",
            "CFG/call-target deltas do not establish semantic equivalence.",
            "A solver result is scoped to recovered evidence, explored paths, and the engine's assumptions.",
            "This profile does not claim support for PE, ARM64, arbitrary ELF inputs, or arbitrary vulnerability classes.",
        ],
    }


def _candidate_pairs(
    vulnerable_functions: list[dict[str, Any]],
    patched_functions: list[dict[str, Any]],
    comparison: dict[str, Any],
) -> list[dict[str, str]]:
    """Derive bounded inference targets from actual CFG call evidence."""
    old_by_name = _unique_functions(vulnerable_functions)
    new_by_name = _unique_functions(patched_functions)
    changed_callers = {
        item["name"] for item in comparison.get("matches", [])
        if item.get("classification") == "symbol_supported" and item.get("evidence")
    }
    old_pairs = _direct_internal_calls(vulnerable_functions, old_by_name)
    new_pairs = _direct_internal_calls(patched_functions, new_by_name)
    common = old_pairs & new_pairs
    rows = [{"function": caller, "call": callee} for caller, callee in common]
    rows.sort(key=lambda item: (item["function"] not in changed_callers, item["function"], item["call"]))
    return rows


def _unique_functions(functions: list[dict[str, Any]]) -> set[str]:
    counts: dict[str, int] = {}
    for function in functions:
        counts[function["name"]] = counts.get(function["name"], 0) + 1
    return {name for name, count in counts.items() if count == 1}


def _direct_internal_calls(functions: list[dict[str, Any]], names: set[str]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for function in functions:
        caller = function.get("name")
        if caller not in names:
            continue
        for call in function.get("calls", []):
            callee = call.get("name")
            if callee in names:
                pairs.add((caller, callee))
    return pairs


def _evidence_ledger(
    vulnerable: dict[str, Any],
    patched: dict[str, Any],
    comparison: dict[str, Any],
    attempts: list[dict[str, Any]],
    verification: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    ledger: list[dict[str, Any]] = []
    for variant, record in (("vulnerable", vulnerable), ("patched", patched)):
        digest = record["metadata"]["sha256"]
        ledger.append({"evidence_id": f"artifact-{digest[:20]}", "kind": "binary_artifact",
                       "binary_sha256": digest, "record_ref": f"artifacts.{variant}"})
        for function in record.get("functions", [])[:250]:
            evidence_id = f"cfg-{hashlib.sha256((digest + function['name'] + str(function['address'])).encode()).hexdigest()[:20]}"
            ledger.append({"evidence_id": evidence_id, "kind": "cfg_function",
                           "binary_sha256": digest, "function": function["name"],
                           "address": function["address"], "block_count": len(function.get("blocks", [])),
                           "call_count": len(function.get("calls", [])),
                           "record_ref": f"artifacts.{variant}.analysis.functions"})
    for match in comparison.get("matches", []):
        if match.get("classification") == "symbol_supported":
            raw = f"{comparison['vulnerable_sha256']}:{comparison['patched_sha256']}:{match['name']}"
            ledger.append({"evidence_id": f"diff-{hashlib.sha256(raw.encode()).hexdigest()[:20]}",
                           "kind": "function_comparison", "function": match["name"],
                           "record_ref": "comparison.matches"})
    for attempt in attempts:
        for variant in ("vulnerable", "patched"):
            inferred = attempt[variant]
            if inferred.get("evidence_id"):
                ledger.append({"evidence_id": inferred["evidence_id"], "kind": "extent_inference",
                               "binary_sha256": inferred.get("binary_sha256"),
                               "function": attempt["function"], "call": attempt["call"],
                               "record_ref": f"inference.attempts.{variant}.evidence"})
    if verification:
        for variant in ("vulnerable", "patched"):
            result = verification[variant]
            if result.get("invariant_evidence", {}).get("evidence_id"):
                ledger.append({"evidence_id": result["invariant_evidence"]["evidence_id"],
                               "kind": "invariant", "binary_sha256": result.get("binary_sha256"),
                               "record_ref": f"verification.{variant}.invariant_evidence"})
            for item in result.get("path_evidence", []):
                if item.get("evidence_id"):
                    ledger.append({"evidence_id": item["evidence_id"], "kind": "symbolic_path",
                                   "binary_sha256": result.get("binary_sha256"),
                                   "record_ref": f"verification.{variant}.path_evidence"})
    return ledger
