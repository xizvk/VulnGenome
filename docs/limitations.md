# Limitations and unsupported capabilities

- The implementation is an early controlled-fixture prototype, not a general binary invariant discovery system.
- Capacity and argument role in the test fixture are supplied by `fixtures/contract.json`. General object-size inference, stack/local layout recovery, and provenance of allocation sizes are not implemented.
- Binary CFG/VEX depends on angr 10.0.4 importing successfully. Metadata-only PE/ELF parsing is not a substitute for disassembly.
- Function matching currently pairs only unique exact symbol names. It does not support robust stripped-binary matching or semantic equivalence claims.
- Patch evidence currently captures CFG branch-block counts and call-target count changes. It does not yet build data-dependence slices or normalize branch predicates.
- Bounds/range, integer representability, and one-bit guard properties have typed compilers. The fixture's direct call-site verifier currently covers unsigned first-argument upper bounds only.
- There is no LLM, RAG, CVE corpus, BinKit/Juliet integration, baseline execution, ablation, cross-architecture, or cross-implementation experiment.
- No real-world CVE sample has been verified or included. No research advantage, accuracy, or statistical improvement is claimed.
- Windows WSL access was denied. Zig provides a cross-compiler, but the produced ELF is analyzed on Windows and is not run.
- Ghidra, BinDiff, Diaphora, YARA export, and a dashboard are not implemented.
