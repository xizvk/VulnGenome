"""Hash-bound, conservative cross-build invariant transfer prototype.

Only the abstract property and candidate semantic names are carried from the
source build. A target must be analyzed independently, and every target
inference/path-evidence digest must match the target file before transfer can
be accepted. Source addresses, VEX identifiers, and path constraints are never
copied into the target analysis.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROPERTY_KIND = "sensitive_call_argument_within_object_extent"


def create_transfer_proposal(source_binary: str | Path, source_result: Any) -> dict[str, Any]:
    """Create an abstract transfer proposal from a fresh source analysis."""
    source_path = Path(source_binary).resolve()
    source_digest = _sha256(source_path)
    _validate_result_binding(source_result, source_digest, role="source")
    capacity_evidence = source_result.capacity_evidence
    inference = capacity_evidence["evidence"]
    relationship = inference.get("data_flow_relationship", {})
    if (source_result.capacity_source != "inferred"
            or capacity_evidence.get("inferred") is not True
            or relationship.get("status") != "PROVEN_SUPPORTED_PATTERN"):
        raise ValueError("source build lacks a supported binary-derived object-to-sink relation")
    if source_result.analysis_mode != "binary_inference":
        raise ValueError("source result is not an independent binary inference")
    symbol = inference.get("object_symbol", {})
    call_site = inference.get("call_site", {})
    call_instruction = call_site.get("instruction", {})
    if (not symbol.get("name") or call_site.get("instruction_address") is None
            or call_instruction.get("address") != call_site.get("instruction_address")):
        raise ValueError("source result lacks a uniquely recorded object or actual call instruction")

    return {
        "schema_version": "1.0",
        "proposal_id": "vg-transfer-" + hashlib.sha256(
            f"{source_digest}:{source_result.function}:{source_result.sensitive_call}:"
            f"{symbol['name']}:{relationship.get('argument_index')}".encode("utf-8")
        ).hexdigest()[:20],
        "source_binary_sha256": source_digest,
        "abstract_property": {
            "kind": _PROPERTY_KIND,
            "predicate": "unsigned first sink argument <= target build's extent of the uniquely related destination object",
            "function_name": source_result.function,
            "sink_name": source_result.sensitive_call,
            "object_symbol_name": symbol["name"],
            "argument_index": relationship.get("argument_index"),
        },
        "source_observation": {
            "inferred_extent_bytes": source_result.capacity,
            "solver_result": source_result.solver_result,
            "classification": source_result.status,
            "assumptions": list((source_result.invariant_evidence or {}).get("assumptions", ())),
        },
        "transfer_policy": {
            "raw_addresses_transferred": False,
            "vex_identifiers_transferred": False,
            "path_constraints_transferred": False,
            "target_requires_independent_object_relation": True,
            "symbol_name_is_candidate_mapping_only": True,
        },
    }


def evaluate_cross_build_transfer(
    proposal: dict[str, Any],
    target_binary: str | Path,
    target_result: Any,
) -> dict[str, Any]:
    """Validate target-specific evidence before reporting a transfer outcome.

    ``target_result`` must come from ``verify_unsigned_argument_at_call_inferred``
    run on ``target_binary``. Passing a source result or an analysis record from
    another binary is rejected by the file-hash binding checks.
    """
    target_path = Path(target_binary).resolve()
    if not target_path.is_file():
        return {
            "proposal_id": proposal.get("proposal_id") if isinstance(proposal, dict) else None,
            "source_binary_sha256": proposal.get("source_binary_sha256") if isinstance(proposal, dict) else None,
            "target_binary_sha256": None,
            "transfer_status": "REJECTED",
            "property_classification": "INCONCLUSIVE",
            "solver_result": "not-run",
            "target_evidence_validation": "FAILED",
            "reason": "target binary does not exist",
            "source_evidence_reused": False,
            "target_specific_evidence": None,
        }
    target_digest = _sha256(target_path)
    source_digest = proposal.get("source_binary_sha256") if isinstance(proposal, dict) else None
    result: dict[str, Any] = {
        "proposal_id": proposal.get("proposal_id") if isinstance(proposal, dict) else None,
        "source_binary_sha256": source_digest,
        "target_binary_sha256": target_digest,
        "transfer_status": "INCONCLUSIVE",
        "property_classification": "INCONCLUSIVE",
        "solver_result": "not-run",
        "target_evidence_validation": "FAILED",
        "reason": None,
        "source_evidence_reused": False,
        "target_specific_evidence": None,
    }
    if proposal.get("schema_version") != "1.0" or not isinstance(source_digest, str) or not _SHA256.fullmatch(source_digest):
        result.update(transfer_status="REJECTED", reason="malformed transfer proposal or source hash")
        return result
    if source_digest == target_digest:
        result.update(transfer_status="REJECTED", reason="source and target are the same binary, not a cross-build transfer")
        return result
    if target_result is None or getattr(target_result, "binary_sha256", None) != target_digest:
        result.update(transfer_status="REJECTED", reason="target result hash does not match the target binary")
        return result
    try:
        _validate_result_binding(target_result, target_digest, role="target")
    except ValueError as exc:
        result.update(transfer_status="REJECTED", reason=str(exc))
        return result

    property_spec = proposal.get("abstract_property", {})
    if property_spec.get("kind") != _PROPERTY_KIND:
        result.update(transfer_status="REJECTED", reason="unsupported abstract property kind")
        return result
    target_capacity = target_result.capacity_evidence or {}
    target_evidence = target_capacity.get("evidence", {})
    target_symbol = target_evidence.get("object_symbol", {})
    target_relation = target_evidence.get("data_flow_relationship", {})
    target_call = target_evidence.get("call_site", {})
    if (target_result.analysis_mode != "binary_inference"
            or target_result.capacity_source != "inferred"
            or target_capacity.get("inferred") is not True
            or target_relation.get("status") != "PROVEN_SUPPORTED_PATTERN"
            or not target_result.path_evidence):
        result.update(transfer_status="INCONCLUSIVE", target_evidence_validation="PASS_HASH_ONLY",
                      reason="target lacks a complete independent inference and call-path evidence")
        return result
    expected_identity = (
        property_spec.get("function_name"), property_spec.get("sink_name"),
        property_spec.get("object_symbol_name"), property_spec.get("argument_index"),
    )
    observed_identity = (
        target_result.function, target_result.sensitive_call, target_symbol.get("name"),
        target_relation.get("argument_index"),
    )
    if observed_identity != expected_identity:
        result.update(transfer_status="REJECTED", target_evidence_validation="PASS_HASH_ONLY",
                      reason="target independently resolved a different function, sink, object, or argument identity")
        return result
    call_instruction = target_call.get("instruction", {})
    if (target_call.get("instruction_address") is None
            or call_instruction.get("address") != target_call.get("instruction_address")):
        result.update(transfer_status="INCONCLUSIVE", target_evidence_validation="PASS_HASH_ONLY",
                      reason="target call instruction identity was not independently recovered")
        return result

    solver = target_result.solver_result
    classification = target_result.status
    if solver == "sat" and classification == "POTENTIAL_VIOLATION":
        transfer_status = "ACCEPTED"
    elif (solver == "unsat" and classification == "PROPERTY_HOLDS_WITHIN_MODEL"
          and target_result.exploration_complete):
        transfer_status = "ACCEPTED"
    else:
        transfer_status = "INCONCLUSIVE"
        classification = "INCONCLUSIVE"
    result.update(
        transfer_status=transfer_status,
        property_classification=classification,
        solver_result=solver,
        target_evidence_validation="PASS",
        reason=(target_result.reason if transfer_status == "INCONCLUSIVE" else
                "abstract property mapped using names, then independently re-established from target object/store/guard/call/path evidence"),
        target_specific_evidence={
            "capacity_bytes": target_result.capacity,
            "object_symbol": target_symbol.get("name"),
            "relation_status": target_relation.get("status"),
            "call_instruction_address": target_call.get("instruction_address"),
            "target_path_count": target_result.paths_to_call,
            "target_path_evidence_ids": [item.get("evidence_id") for item in target_result.path_evidence],
            "all_path_hashes_match_target": all(item.get("binary_sha256") == target_digest
                                                for item in target_result.path_evidence),
        },
    )
    return result


def _validate_result_binding(result: Any, expected_digest: str, *, role: str) -> None:
    if getattr(result, "binary_sha256", None) != expected_digest:
        raise ValueError(f"{role} result hash does not match its binary")
    capacity = getattr(result, "capacity_evidence", None)
    if not isinstance(capacity, dict) or capacity.get("binary_sha256") != expected_digest:
        raise ValueError(f"{role} capacity evidence hash does not match its binary")
    nested = capacity.get("evidence", {})
    if (nested.get("binary_sha256") not in (None, expected_digest)
            or (capacity.get("status") == "INFERRED" and nested.get("binary_sha256") != expected_digest)):
        raise ValueError(f"{role} nested inference evidence hash does not match its binary")
    invariant = getattr(result, "invariant_evidence", None)
    if isinstance(invariant, dict) and invariant.get("binary_sha256") != expected_digest:
        raise ValueError(f"{role} invariant evidence hash does not match its binary")
    if (invariant is None
            and getattr(result, "solver_result", None) in {"sat", "unsat", "unknown"}):
        raise ValueError(f"{role} solver result has no binary-bound invariant evidence")
    paths = getattr(result, "path_evidence", ())
    if any(item.get("binary_sha256") != expected_digest for item in paths):
        raise ValueError(f"{role} path evidence contains a mismatched binary hash")
    if not paths and getattr(result, "solver_result", None) in {"sat", "unsat", "unknown"}:
        raise ValueError(f"{role} solver result has no binary-derived path evidence")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
