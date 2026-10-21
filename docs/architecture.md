# Architecture and interfaces

The prototype separates the binary front end, patch evidence, invariant schema, solver, dataset integrity, and metric reporting. The CLI orchestrates these components without an LLM or dashboard dependency.

```text
binary bytes -> SHA-256 + PE/ELF metadata -> angr CFGFast -> block instructions + VEX
                                                |                         |
                                                +-> exact-symbol matching + patch deltas
                                                                          |
controlled ABI annotation + named sink call -----------------------------+
                                                                          v
                                                     symbolic call-site path constraints
                                                                          |
                                                                          v
                                                      Z3 query: path AND length > capacity
```

Implemented interfaces:

- `analyze_binary(path) -> BinaryAnalysis`: hashes and records PE/ELF metadata; if angr imports, also records recovered functions, block instructions, call targets, and VEX.
- `compare(vulnerable, patched) -> dict`: pairs unique exact symbol names and reports call-target/CFG branch-block deltas. It does not equate similarity with semantic equivalence.
- `InvariantSpec.from_dict`, `validate`, and `compile_property`: parse a strict, versioned property record, check evidence/expression links and types, and compile supported properties using finite-width bit-vectors.
- `verify(spec, evidence) -> VerificationResult`: asks Z3 whether recorded path conditions and the negated property are satisfiable; retains SAT/UNSAT/UNKNOWN as distinct states.
- `verify_unsigned_argument_at_call(...) -> CallSiteResult`: uses angr symbolic execution to capture path constraints at an actual named call in an analyzed binary and checks an unsigned bound using the Claripy Z3 backend.
- `validate_manifest`, `calculate_metrics`, and `write_json`: validate sample provenance/split leakage, calculate metrics from sample-level rows, and produce portable reports.

The fixture adapter intentionally requires explicit function/sink/argument/capacity annotations. It does not pretend that general object capacity or ABI argument roles are automatically recovered. LLM proposals, RAG, stripped-function matching, dependence slicing, arbitrary target mapping, and broad source-pair semantics are not implemented.
