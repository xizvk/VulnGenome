# Invariant semantics, schema version 1.0

Every proposal contains a version, invariant kind, semantic roles mapped to expression IDs, property name, program point, evidence IDs, assumptions, parameters, and provenance. Expressions declare a machine width and signedness. Unknown fields, missing roles, unresolved evidence IDs, incompatible widths, and unsupported signedness are rejected.

## Supported forms

| Kind | Required roles | Property | Machine semantics |
|---|---|---|---|
| `bounds_safety` | `index`, `capacity` | `index_lt_capacity` | Unsigned `index < capacity`; the lower bound 0 is implicit in the unsigned type. |
| `range_safety` | `offset`, `length`, `capacity` | `offset_plus_length_le_capacity` | Each operand is unsigned and the same width `w`; both addends and capacity are zero-extended to `w+1` before addition/comparison. Carry is preserved. |
| `representability` | `value` | `fits_target_type` | Source width/signedness and target width/signedness are explicit. Narrowing checks inspect the discarded bits. |
| `guard_dominance` | `condition` | `condition_holds_at_sensitive_operation` | The condition must be a one-bit Boolean expression. Verification applies only to the recorded call/path constraints. |

Range checks with mixed operand widths or signed operands are rejected. Capacity needs an evidence-backed expression or an explicit, clearly labeled assumption. Unresolved assumptions force `INCONCLUSIVE`.

## Result interpretation

- `POTENTIAL_VIOLATION`: the recorded path constraints and negated property are satisfiable. A SAT model is not automatically an exploitable vulnerability.
- `PROPERTY_HOLDS_WITHIN_MODEL`: the violation query is UNSAT for the exact recorded model and explored paths. It is not a full-program safety proof.
- `INCONCLUSIVE`: missing/ambiguous evidence, unresolved assumptions, unsupported mapping, solver UNKNOWN/timeout, or incomplete exploration.
- `ANALYSIS_ERROR`: an operational or parser/solver failure.

An empty path-constraint set means the solver checked the property over the full symbolic input domain, not that any binary branch was proved to enforce it. Binary-linked claims must cite the call-site analysis output that provided the path constraints.
