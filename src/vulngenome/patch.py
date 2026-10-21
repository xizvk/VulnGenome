"""Conservative function matching and patch evidence from real analysis records."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .binary import BinaryAnalysis


def compare(vulnerable: BinaryAnalysis, patched: BinaryAnalysis) -> dict[str, Any]:
    old_by_name: dict[str, list[dict[str, Any]]] = {}
    new_by_name: dict[str, list[dict[str, Any]]] = {}
    for function in vulnerable.functions:
        old_by_name.setdefault(function["name"], []).append(function)
    for function in patched.functions:
        new_by_name.setdefault(function["name"], []).append(function)
    matches = []
    unmatched_v = []
    unmatched_p = []
    for name in sorted(set(old_by_name) | set(new_by_name)):
        left, right = old_by_name.get(name, []), new_by_name.get(name, [])
        if len(left) == len(right) == 1:
            matches.append(_compare_function(left[0], right[0]))
        elif not left:
            unmatched_p.extend({"name": f["name"], "address": f["address"]} for f in right)
        elif not right:
            unmatched_v.extend({"name": f["name"], "address": f["address"]} for f in left)
        else:
            matches.append({"name": name, "classification": "ambiguous", "vulnerable_count": len(left), "patched_count": len(right)})
    return {
        "schema_version": "1.0",
        "vulnerable_sha256": vulnerable.metadata.sha256,
        "patched_sha256": patched.metadata.sha256,
        "matching_policy": "unique exact symbol name only",
        "matches": matches,
        "unmatched_vulnerable": unmatched_v,
        "unmatched_patched": unmatched_p,
        "capability_limitations": ["no stripped-function structural matcher", "similarity is not equivalence"],
    }


def _compare_function(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    old_calls = Counter(call.get("name") or call.get("target") for call in old.get("calls", []))
    new_calls = Counter(call.get("name") or call.get("target") for call in new.get("calls", []))
    old_branches = sum("Ijk_Boring" in block.get("vex", "") and "Ist_Exit" in block.get("vex", "") for block in old.get("blocks", []))
    new_branches = sum("Ijk_Boring" in block.get("vex", "") and "Ist_Exit" in block.get("vex", "") for block in new.get("blocks", []))
    old_blocks, new_blocks = old.get("blocks", []), new.get("blocks", [])
    evidence = []
    if old_branches != new_branches:
        evidence.append({"kind": "cfg_branch_block_count", "vulnerable": old_branches, "patched": new_branches})
    if old_calls != new_calls:
        evidence.append({"kind": "call_target_counts", "vulnerable": dict(old_calls), "patched": dict(new_calls)})
    return {
        "name": old["name"], "classification": "symbol_supported",
        "vulnerable_address": old["address"], "patched_address": new["address"],
        "vulnerable_cfg_blocks": len(old_blocks), "patched_cfg_blocks": len(new_blocks),
        "vulnerable_call_targets": dict(old_calls), "patched_call_targets": dict(new_calls),
        "evidence": evidence,
        "evidence_scope": "CFG and recovered call-target deltas; no semantic equivalence claim",
    }
