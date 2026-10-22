# VulnGenome

VulnGenome is an experimental research prototype for evidence-grounded binary invariant analysis. This checkout is a new implementation because the supplied workspace contained no prior repository. Current scope and tested capabilities are recorded in `docs/initial_assessment.md` and `docs/limitations.md`.

The controlled C vulnerable/patched pair has been compiled to x86-64 Linux-musl ELF with LLVM Clang/LLD 23.1.4 and analyzed with angr CFG/VEX. The original experiment remains an explicitly annotated control. Automatic inference now requires a narrow binary pattern: one ELF object must be written one byte at a time through a zero-based, unit-stride index, and VEX must show the same index guarded by an unsigned comparison with the sink's first argument at entry and on the loop back edge. The caller's actual call instruction and argument expression are recorded, then the solver checks that argument against the inferred extent using path conditions from the analyzed binary. Calls inside the sink, unclassified indirect writes, unsupported VEX memory effects, unrelated stores, multiple related destinations, stripped symbols, and unsupported loop shapes abstain. This is not general allocation-size inference or a complete memory-safety proof. The independent evaluation and exact outputs are recorded in `experiments/results/adversarial-capacity-inference-clang-20261022.json`; prior records remain preserved. Set `VULNGENOME_CLANG` to the verified compiler to select it; Zig remains the default otherwise and currently fails during temporary/cache writes in this sandbox.

## Quick start

Install Python 3.12, then from this directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,fixture]"
pytest -q
python scripts/run_fixture_experiment.py --work-dir ..\..\work\vulngenome --out experiments\results\controlled-fixture.json
```

See [reproduction instructions](docs/reproduction.md) for the commands, prerequisites, experiment scope, and current limitations.
