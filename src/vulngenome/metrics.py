"""Metrics calculated from sample-level decisions; abstentions stay visible."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable


SECURITY_CLASSES = {"VULNERABLE", "PATCHED"}


def calculate_metrics(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    samples = list(rows)
    counts: Counter[str] = Counter()
    decided: list[dict[str, Any]] = []
    by_project: dict[str, list[dict[str, Any]]] = {}
    by_family: dict[str, list[dict[str, Any]]] = {}
    for row in samples:
        truth, prediction = row.get("ground_truth"), row.get("prediction")
        if truth not in SECURITY_CLASSES:
            counts["invalid_ground_truth"] += 1
            continue
        counts["total_labeled"] += 1
        if prediction in SECURITY_CLASSES:
            counts["decided"] += 1
            decided.append(row)
        elif prediction == "INCONCLUSIVE":
            counts["inconclusive"] += 1
        else:
            counts["analysis_error"] += 1
        by_project.setdefault(str(row.get("project", "unknown")), []).append(row)
        by_family.setdefault(str(row.get("invariant_family", "unknown")), []).append(row)

    tp = sum(r["ground_truth"] == r["prediction"] == "VULNERABLE" for r in decided)
    tn = sum(r["ground_truth"] == r["prediction"] == "PATCHED" for r in decided)
    fp = sum(r["ground_truth"] == "PATCHED" and r["prediction"] == "VULNERABLE" for r in decided)
    fn = sum(r["ground_truth"] == "VULNERABLE" and r["prediction"] == "PATCHED" for r in decided)
    denom = tp + fp + fn
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    count = counts["total_labeled"]
    result: dict[str, Any] = {
        "metric_schema": "1.0",
        "n_total_labeled": count,
        "n_decided": counts["decided"],
        "n_inconclusive": counts["inconclusive"],
        "n_analysis_error": counts["analysis_error"],
        "decision_coverage": counts["decided"] / count if count else None,
        "accuracy_on_decided": (tp + tn) / counts["decided"] if counts["decided"] else None,
        "vulnerable_precision": precision,
        "vulnerable_recall": recall,
        "vulnerable_f1": f1,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "confusion_on_decided": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "by_project": {key: _slice_metrics(value) for key, value in sorted(by_project.items())},
        "by_invariant_family": {key: _slice_metrics(value) for key, value in sorted(by_family.items())},
        "definitions": {
            "decision_coverage": "decided predictions / all labeled samples; INCONCLUSIVE and analysis errors are not decisions",
            "accuracy_on_decided": "correct security classifications / decided predictions; always report with decision_coverage",
            "vulnerable_precision": "TP / (TP + FP) among decided predictions",
            "vulnerable_recall": "TP / (TP + FN) among decided predictions",
            "false_positive_rate": "FP / (FP + TN) among decided clean samples",
        },
    }
    return result


def _slice_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labeled = [r for r in rows if r.get("ground_truth") in SECURITY_CLASSES]
    decided = [r for r in labeled if r.get("prediction") in SECURITY_CLASSES]
    correct = sum(r["ground_truth"] == r["prediction"] for r in decided)
    return {"n_total": len(labeled), "n_decided": len(decided),
            "decision_coverage": len(decided) / len(labeled) if labeled else None,
            "accuracy_on_decided": correct / len(decided) if decided else None}
