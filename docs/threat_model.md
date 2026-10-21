# Threat model

## Scope

VulnGenome analyzes local binaries and compares a bounded subset of their semantics. The intended use is defensive research on authorized samples and controlled fixtures. The prototype does not generate exploits or execute analyzed binaries. The fixture test compiles native code but the integration test passes the resulting file to static and symbolic analysis only.

## Trust boundaries

- Binary files, symbols, debug records, and decompiler/lifter output are untrusted input. The parser may fail or omit unsupported code; warnings and errors must be preserved.
- Advisory, retrieval, and future LLM text are untrusted proposals. They cannot change solver policy or execute commands.
- Fixture annotations are manually authored ground truth for a controlled test. They must not be represented as recovered facts for arbitrary binaries.
- Solver conclusions depend on the modeled machine width, path constraints, external-call behavior, and explored paths.

## Known risks

Malformed binaries can exercise bugs in analysis dependencies. Use isolated environments for untrusted samples. Timeouts and path limits produce `INCONCLUSIVE`. An incorrect role/capacity annotation can make a well-formed solver query irrelevant to the actual operation. Function-name matching does not establish equivalence. This prototype currently has no sandboxing layer around angr.
