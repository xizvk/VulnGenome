# VulnGenome

VulnGenome is an experimental research prototype for evidence-grounded binary invariant analysis. This checkout is a new implementation because the supplied workspace contained no prior repository. Current scope and tested capabilities are recorded in `docs/initial_assessment.md` and `docs/limitations.md`.

The controlled C vulnerable/patched pair has been compiled to x86-64 Linux-musl ELF with LLVM Clang/LLD 23.1.4 and analyzed with angr CFG/VEX. The original experiment remains an explicitly annotated control. A separate narrow inference path now recovers a positive-size ELF object symbol only when its address is directly referenced by a VEX store in the named sensitive function; it then checks the observed call argument against that inferred extent using symbolic path conditions from the binary. The new controlled run recovered capacities 16 and 24, detected the removed/oversized guards and changed sink argument, and abstained when symbol metadata was stripped. This does not provide general allocation-size inference or prove complete memory safety. The full suite result for this branch is recorded in `experiments/experiment_log.md`. Set `VULNGENOME_CLANG` to the verified Clang executable to select that compiler; Zig remains the default otherwise and currently fails during temporary/cache writes in this sandbox. See `experiments/results/controlled-fixture-clang-20261021.json` for the original annotation-dependent record and `experiments/results/annotation-free-invariants-clang-20261021.json` for the new evidence.

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
