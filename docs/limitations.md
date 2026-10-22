# Limitations and unsupported capabilities

- The implementation is an early controlled-fixture prototype, not a general binary invariant discovery system.
- The original experiment supplies capacity and argument role from `fixtures/contract.json`. A separate inference API now recovers only a positive-size ELF `STT_OBJECT` extent directly referenced by a VEX store in the named sensitive function. It requires preserved symbol metadata and a direct caller-to-sink call. Stack/local, heap, indirect, aliased, dynamic, and general allocation-size inference remain unsupported; stripped binaries abstain.
- Binary CFG/VEX depends on angr 10.0.4 importing successfully. Metadata-only PE/ELF parsing is not a substitute for disassembly.
- Function matching currently pairs only unique exact symbol names. It does not support robust stripped-binary matching or semantic equivalence claims.
- Patch evidence currently captures CFG branch-block counts and call-target count changes. It does not yet build data-dependence slices or normalize branch predicates.
- Bounds/range, integer representability, and one-bit guard properties have typed compilers. The binary call-site verifier checks an unsigned first-argument upper bound; its `PROPERTY_HOLDS_WITHIN_MODEL` result is not a full memory-safety proof. The first-argument role and its byte-count meaning remain assumptions, and analysis is limited to reached paths and Linux AMD64 ELF.
- There is no LLM, RAG, CVE corpus, BinKit/Juliet integration, baseline execution, ablation, cross-architecture, or cross-implementation experiment.
- No real-world CVE sample has been verified or included. No research advantage, accuracy, or statistical improvement is claimed.
- Windows WSL access was denied. Zig provides a cross-compiler, but the produced ELF is analyzed on Windows and is not run.
- Ghidra, BinDiff, Diaphora, YARA export, and a dashboard are not implemented.
