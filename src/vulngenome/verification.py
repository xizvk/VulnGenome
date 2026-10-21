"""Solver backend and conservative result policy."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .invariants import compile_property, validate
from .models import EvidenceBundle, InvariantSpec


RESULT_STATES = {"POTENTIAL_VIOLATION", "PROPERTY_HOLDS_WITHIN_MODEL", "INCONCLUSIVE", "ANALYSIS_ERROR"}


@dataclass(frozen=True)
class VerificationResult:
    status: str
    backend: str
    query_smt2: str
    solver_result: str
    solver_version: str | None
    timeout_ms: int
    assumptions: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    model: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_query(spec: InvariantSpec, evidence: EvidenceBundle) -> str:
    prop = compile_property(spec, evidence)
    ids = set(evidence.expressions)
    declarations = []
    for expr_id in sorted(ids):
        expr = evidence.expressions[expr_id]
        declarations.append(f"(declare-fun {expr_id} () (_ BitVec {expr.width}))")
    constraints = [f"(assert {constraint})" for constraint in evidence.path_constraints]
    return "\n".join(["(set-logic QF_BV)", *declarations, *constraints,
                      f"(assert (not {prop}))", "(check-sat)"])


def verify(spec: InvariantSpec, evidence: EvidenceBundle, timeout_ms: int = 5000) -> VerificationResult:
    query = ""
    validation = validate(spec, evidence)
    if not validation.valid:
        return VerificationResult("INCONCLUSIVE", "none", query, "not-run", None, timeout_ms,
                                  validation.unresolved_assumptions, spec.evidence_refs,
                                  reason="; ".join(validation.errors))
    query = build_query(spec, evidence)
    if validation.unresolved_assumptions:
        return VerificationResult("INCONCLUSIVE", "z3-python", query, "not-run", None, timeout_ms,
                                  validation.unresolved_assumptions, spec.evidence_refs,
                                  reason="unresolved assumptions prevent a security conclusion")
    try:
        import z3  # type: ignore[import-not-found]
    except ImportError:
        return VerificationResult("INCONCLUSIVE", "unavailable", query, "not-run", None, timeout_ms,
                                  (), spec.evidence_refs, reason="z3-solver is not installed")
    try:
        solver = z3.Solver()
        solver.set(timeout=timeout_ms)
        solver.from_string(query[:query.rfind("(check-sat)")])
        outcome = solver.check()
        version = z3.get_version_string()
        if outcome == z3.sat:
            return VerificationResult("POTENTIAL_VIOLATION", "z3-python", query, "sat", version,
                                      timeout_ms, (), spec.evidence_refs, str(solver.model()))
        if outcome == z3.unsat:
            return VerificationResult("PROPERTY_HOLDS_WITHIN_MODEL", "z3-python", query, "unsat", version,
                                      timeout_ms, (), spec.evidence_refs,
                                      reason="the negated property is unsatisfiable under the recorded constraints")
        return VerificationResult("INCONCLUSIVE", "z3-python", query, "unknown", version,
                                  timeout_ms, (), spec.evidence_refs, reason=solver.reason_unknown())
    except Exception as exc:  # solver/parser operational failures are not security outcomes
        return VerificationResult("ANALYSIS_ERROR", "z3-python", query, "error", None,
                                  timeout_ms, (), spec.evidence_refs, reason=f"{type(exc).__name__}: {exc}")
