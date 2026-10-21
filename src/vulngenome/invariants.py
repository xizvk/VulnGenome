"""Typed invariant validation and finite-width SMT-LIB compilation."""

from __future__ import annotations

from .models import EvidenceBundle, InvariantSpec, ValidationResult


ROLE_NAMES = {
    "bounds_safety": {"index", "capacity"},
    "range_safety": {"offset", "length", "capacity"},
    "representability": {"value"},
    "guard_dominance": {"condition"},
}
PROPERTY_NAMES = {
    "bounds_safety": "index_lt_capacity",
    "range_safety": "offset_plus_length_le_capacity",
    "representability": "fits_target_type",
    "guard_dominance": "condition_holds_at_sensitive_operation",
}


def validate(spec: InvariantSpec, evidence: EvidenceBundle) -> ValidationResult:
    errors: list[str] = []
    if spec.property != PROPERTY_NAMES[spec.kind]:
        errors.append(f"property {spec.property!r} does not match invariant kind {spec.kind!r}")
    if set(spec.roles) != ROLE_NAMES[spec.kind]:
        errors.append(f"roles for {spec.kind} must be exactly {sorted(ROLE_NAMES[spec.kind])}")
    missing_refs = set(spec.evidence_refs) - set(evidence.evidence_ids)
    if missing_refs:
        errors.append(f"unknown evidence references: {sorted(missing_refs)}")
    expression_evidence_refs = {
        expr.evidence_ref for expr in evidence.expressions.values() if expr.evidence_ref is not None
    } - set(evidence.evidence_ids)
    if expression_evidence_refs:
        errors.append(f"unknown expression evidence references: {sorted(expression_evidence_refs)}")
    missing_expr = set(spec.roles.values()) - set(evidence.expressions)
    if missing_expr:
        errors.append(f"unknown expression references: {sorted(missing_expr)}")
    if errors:
        return ValidationResult(False, tuple(errors), tuple(spec.assumptions))

    exprs = [evidence.expressions[expr_id] for expr_id in spec.roles.values()]
    if spec.kind in {"bounds_safety", "range_safety"}:
        if any(expr.signedness != "unsigned" for expr in exprs):
            errors.append("bounds and range properties require unsigned expressions")
        if len({expr.width for expr in exprs}) != 1:
            errors.append("bounds and range operands must have equal machine widths")
    elif spec.kind == "representability":
        value = evidence.expressions[spec.roles["value"]]
        target_width = spec.parameters.get("target_width")
        target_sign = spec.parameters.get("target_signedness")
        if not isinstance(target_width, int) or isinstance(target_width, bool) or target_width < 1:
            errors.append("representability requires positive integer parameters.target_width")
        if target_sign not in {"unsigned", "signed"}:
            errors.append("representability requires target_signedness 'unsigned' or 'signed'")
        if value.signedness not in {"unsigned", "signed"}:
            errors.append("representability source must have signed or unsigned integer type")
    elif spec.kind == "guard_dominance":
        condition = evidence.expressions[spec.roles["condition"]]
        if condition.signedness != "bool" or condition.width != 1:
            errors.append("guard_dominance condition must be a one-bit boolean expression")

    return ValidationResult(not errors, tuple(errors), tuple(spec.assumptions) + tuple(evidence.unresolved_assumptions))


def compile_property(spec: InvariantSpec, evidence: EvidenceBundle) -> str:
    """Compile the invariant into an SMT-LIB bit-vector term.

    The caller must validate the spec first. Range sums are widened by one
    bit before addition, so a carry cannot be discarded.
    """
    role_expr = {role: evidence.expressions[expr_id] for role, expr_id in spec.roles.items()}
    symbol = {role: f"{role_expr[role].expr_id}" for role in role_expr}
    if spec.kind == "bounds_safety":
        return f"(bvult {symbol['index']} {symbol['capacity']})"
    if spec.kind == "range_safety":
        width = role_expr["offset"].width
        off = f"((_ zero_extend 1) {symbol['offset']})"
        length = f"((_ zero_extend 1) {symbol['length']})"
        capacity = f"((_ zero_extend 1) {symbol['capacity']})"
        return f"(bvule (bvadd {off} {length}) {capacity})"
    if spec.kind == "representability":
        return _representable(symbol["value"], role_expr["value"].width,
                              spec.parameters["target_width"], spec.parameters["target_signedness"],
                              role_expr["value"].signedness)
    if spec.kind == "guard_dominance":
        return f"(= {symbol['condition']} #b1)"
    raise ValueError(f"unsupported invariant kind: {spec.kind}")


def _representable(value: str, source_width: int, target_width: int,
                    target_sign: str, source_sign: str) -> str:
    if source_sign == "unsigned":
        if target_sign == "unsigned":
            if source_width <= target_width:
                return "true"
            return f"(= ((_ extract {source_width - 1} {target_width}) {value}) (_ bv0 {source_width - target_width}))"
        if source_width < target_width:
            return "true"
        return f"(= ((_ extract {source_width - 1} {target_width - 1}) {value}) (_ bv0 {source_width - target_width + 1}))"

    nonnegative = f"(= ((_ extract {source_width - 1} {source_width - 1}) {value}) #b0)"
    if target_sign == "unsigned":
        if source_width <= target_width:
            return nonnegative
        high_zero = f"(= ((_ extract {source_width - 1} {target_width}) {value}) (_ bv0 {source_width - target_width}))"
        return f"(and {nonnegative} {high_zero})"
    if source_width <= target_width:
        return "true"
    high_width = source_width - target_width + 1
    high = f"((_ extract {source_width - 1} {target_width - 1}) {value})"
    all_ones = f"(_ bv{(1 << high_width) - 1} {high_width})"
    zero = f"(_ bv0 {high_width})"
    return f"(or (and {nonnegative} (= {high} {zero})) (and (not {nonnegative}) (= {high} {all_ones})))"
