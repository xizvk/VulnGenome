# VulnGenome

VulnGenome is an experimental research prototype for evidence-grounded binary invariant analysis. This checkout is a new implementation because the supplied workspace contained no prior repository. Current scope and tested capabilities are recorded in `docs/initial_assessment.md` and `docs/limitations.md`.

The controlled C vulnerable/patched pair has been compiled to x86-64 Linux-musl ELF with LLVM Clang/LLD 23.1.4, analyzed with angr CFG/VEX, and checked at the sensitive call. In this workspace, set `VULNGENOME_CLANG` to the Clang executable to select that compiler; Zig remains the default otherwise and currently fails during temporary/cache writes in this sandbox. The full suite passed with Clang selected (22 passed). The capacity and argument-role mapping come from the explicit controlled-fixture contract; this is not a general binary object-size inference result. See `experiments/results/controlled-fixture-clang-20261021.json` and `experiments/experiment_log.md` for evidence and hashes.

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
