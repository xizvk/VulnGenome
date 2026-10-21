"""Small, strict, versioned data models used across the pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Mapping


class SchemaError(ValueError):
    """Raised when an input record does not match its declared schema."""


SIGNEDNESS = {"unsigned", "signed", "bool", "pointer", "unknown"}
INVARIANT_KINDS = {"bounds_safety", "range_safety", "representability", "guard_dominance"}


@dataclass(frozen=True)
class Expression:
    expr_id: str
    width: int
    signedness: str
    origin: str
    evidence_ref: str | None = None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Expression":
        allowed = {"expr_id", "width", "signedness", "origin", "evidence_ref"}
        _keys(raw, allowed, "expression")
        missing = {"expr_id", "width", "signedness", "origin"} - set(raw)
        if missing:
            raise SchemaError(f"missing expression fields: {sorted(missing)}")
        try:
            expr = cls(**raw)
        except TypeError as exc:
            raise SchemaError(f"invalid expression fields: {exc}") from exc
        if not isinstance(expr.expr_id, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr.expr_id):
            raise SchemaError("expr_id must be a safe SMT identifier")
        if expr.expr_id in {"true", "false", "let", "forall", "exists", "assert", "check-sat"}:
            raise SchemaError("expr_id cannot be a reserved SMT-LIB word")
        if not isinstance(expr.width, int) or isinstance(expr.width, bool) or not 1 <= expr.width <= 4096:
            raise SchemaError("expression width must be an integer in [1, 4096]")
        if not isinstance(expr.signedness, str) or expr.signedness not in SIGNEDNESS:
            raise SchemaError(f"unsupported signedness: {expr.signedness}")
        if not isinstance(expr.origin, str) or not expr.origin:
            raise SchemaError("expression origin is required")
        if expr.evidence_ref is not None and (not isinstance(expr.evidence_ref, str) or not expr.evidence_ref):
            raise SchemaError("evidence_ref must be a non-empty string or null")
        return expr


@dataclass(frozen=True)
class InvariantSpec:
    version: str
    kind: str
    roles: Mapping[str, str]
    property: str
    program_point: str
    evidence_refs: tuple[str, ...]
    assumptions: tuple[str, ...] = ()
    parameters: Mapping[str, Any] = field(default_factory=dict)
    provenance: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "InvariantSpec":
        allowed = {"version", "kind", "roles", "property", "program_point", "evidence_refs", "assumptions", "parameters", "provenance"}
        _keys(raw, allowed, "invariant")
        missing = {"version", "kind", "roles", "property", "program_point", "evidence_refs"} - set(raw)
        if missing:
            raise SchemaError(f"missing invariant fields: {sorted(missing)}")
        if not isinstance(raw["roles"], Mapping):
            raise SchemaError("roles must be an object")
        if not isinstance(raw["evidence_refs"], (list, tuple)):
            raise SchemaError("evidence_refs must be an array")
        if not isinstance(raw.get("assumptions", ()), (list, tuple)):
            raise SchemaError("assumptions must be an array")
        if not isinstance(raw.get("parameters", {}), Mapping) or not isinstance(raw.get("provenance", {}), Mapping):
            raise SchemaError("parameters and provenance must be objects")
        try:
            item = cls(
                version=raw["version"], kind=raw["kind"], roles=dict(raw["roles"]),
                property=raw["property"], program_point=raw["program_point"],
                evidence_refs=tuple(raw["evidence_refs"]), assumptions=tuple(raw.get("assumptions", ())),
                parameters=dict(raw.get("parameters", {})), provenance=dict(raw.get("provenance", {})),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SchemaError(f"invalid invariant fields: {exc}") from exc
        if not isinstance(item.version, str) or item.version != "1.0":
            raise SchemaError(f"unsupported invariant schema version: {item.version}")
        if not isinstance(item.kind, str) or item.kind not in INVARIANT_KINDS:
            raise SchemaError(f"unsupported invariant kind: {item.kind}")
        if not isinstance(item.property, str) or not item.property or not isinstance(item.program_point, str) or not item.program_point:
            raise SchemaError("property and program_point are required")
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in item.roles.items()):
            raise SchemaError("roles must map strings to expression identifiers")
        if any(not isinstance(ref, str) or not ref for ref in item.evidence_refs):
            raise SchemaError("evidence_refs must contain non-empty strings")
        if len(set(item.evidence_refs)) != len(item.evidence_refs):
            raise SchemaError("evidence_refs must be unique")
        if any(not isinstance(value, str) or not value for value in item.assumptions):
            raise SchemaError("assumptions must contain non-empty strings")
        return item


@dataclass(frozen=True)
class EvidenceBundle:
    expressions: Mapping[str, Expression]
    evidence_ids: frozenset[str]
    path_constraints: tuple[str, ...] = ()
    unresolved_assumptions: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "EvidenceBundle":
        _keys(raw, {"expressions", "evidence_ids", "path_constraints", "unresolved_assumptions", "metadata"}, "evidence bundle")
        expressions_raw = raw.get("expressions", {})
        if not isinstance(expressions_raw, Mapping):
            raise SchemaError("expressions must be an object")
        for key in ("evidence_ids", "path_constraints", "unresolved_assumptions"):
            if not isinstance(raw.get(key, ()), (list, tuple)):
                raise SchemaError(f"{key} must be an array")
        if not isinstance(raw.get("metadata", {}), Mapping):
            raise SchemaError("metadata must be an object")
        expressions = {key: Expression.from_dict(value) for key, value in expressions_raw.items()}
        if any(key != expr.expr_id for key, expr in expressions.items()):
            raise SchemaError("expression map keys must equal expr_id values")
        if any(not isinstance(item, str) or not item for item in raw.get("evidence_ids", ())):
            raise SchemaError("evidence_ids must contain non-empty strings")
        if any(not isinstance(item, str) for item in raw.get("path_constraints", ())):
            raise SchemaError("path_constraints must contain strings")
        if any(not isinstance(item, str) or not item for item in raw.get("unresolved_assumptions", ())):
            raise SchemaError("unresolved_assumptions must contain non-empty strings")
        return cls(
            expressions=expressions,
            evidence_ids=frozenset(raw.get("evidence_ids", ())),
            path_constraints=tuple(raw.get("path_constraints", ())),
            unresolved_assumptions=tuple(raw.get("unresolved_assumptions", ())),
            metadata=dict(raw.get("metadata", {})),
        )


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: tuple[str, ...] = ()
    unresolved_assumptions: tuple[str, ...] = ()


def _keys(raw: Mapping[str, Any], allowed: set[str], label: str) -> None:
    if not isinstance(raw, Mapping):
        raise SchemaError(f"{label} must be an object")
    extra = set(raw) - allowed
    if extra:
        raise SchemaError(f"unknown {label} fields: {sorted(extra)}")


def to_jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return {key: to_jsonable(val) for key, val in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [to_jsonable(v) for v in value]
    return value
