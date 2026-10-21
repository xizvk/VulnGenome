# TODO from verified state

- [ ] Verify a clean install of all pinned packages, including angr's source-only dependencies.
- [x] Compile fixtures and run the binary CFG/VEX + call-site symbolic integration test (Clang 23.1.4/LLD 23.1.4; controlled experiment recorded).
- [x] Record actual fixture hashes, tool versions, solver outcomes, and test counts in the experiment record and log.
- [ ] Add expression references from angr VEX nodes to typed machine expressions.
- [ ] Extract branch predicates and dependence slices; preserve node IDs in patch evidence.
- [ ] Recover object capacity from binary evidence or return `INCONCLUSIVE`.
- [ ] Expand transfer to candidate retrieval and conservative target-role mapping.
- [ ] Add real-world samples only after authoritative provenance and independent annotation.
- [ ] Implement LLM provider/RAG abstractions and freeze their model/configuration per experiment.
- [ ] Implement CVE-/patch-disjoint train/validation/test splits and baseline/ablation execution.
- [ ] Add cross-build and cross-architecture experiments, then independent implementation tests.
