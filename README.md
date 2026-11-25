# VulnGenome

VulnGenome is an experimental research prototype for evidence-grounded binary invariant analysis. This checkout is a new implementation because the supplied workspace contained no prior repository. Current scope and tested capabilities are recorded in `docs/initial_assessment.md` and `docs/limitations.md`.

The controlled C vulnerable/patched pair has been compiled to x86-64 Linux-musl ELF with LLVM Clang/LLD 23.1.4 and analyzed with angr CFG/VEX. Automatic inference requires a binary-derived object extent, a supported object-to-sink write relation, and target-specific call/path evidence before the solver runs. A second VEX path handles one optimized scalar register loop with a nonzero entry check, a first write at `object[0]`, a unit-step index, and an equality exit tied to the sink argument. Other unsupported or ambiguous shapes abstain. See `docs/optimized-vex-inference.md` for the exact proof conditions and limits; this remains a narrow prototype, not a complete memory-safety proof.

The earlier 48-build result remains preserved at `experiments/results/cross-build-optimization-invariants-clang-20261022.json`. The follow-up record at `experiments/results/optimized-vex-dataflow-clang-20261022.json` contains 56 builds: 23/56 classified (TP=13, TN=10, FP=0, FN=0), 33 inconclusive, and no build or analysis failures. Decision coverage is 41.1%; vulnerable precision and recall among classified cases are each 13/13, while vulnerable detection coverage is 13/28. At O1 and Os the matcher classified 7/12 cases each; O2 and O3 remained inconclusive. It accepted 16/50 fresh, hash-bound transfer attempts and abstained on 34. Repeated optimization builds are regression observations, not independent vulnerability discoveries. The corpus is synthetic and does not establish real-world accuracy or broad compiler robustness. Set `VULNGENOME_CLANG` to the verified compiler to select it; Zig remains the default otherwise and currently fails during temporary/cache writes in this sandbox.

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

**Dependency note:** the root manifest currently pins `claripy==9.3.7`, which conflicts with the version required by `angr==10.0.4`. Until those pins are reconciled, use the compatible setup in [CONTRIBUTING.md](CONTRIBUTING.md) rather than installing the root extras directly.

## Repository collaboration

VulnGenome keeps the engine, Lite application, tests, fixtures, datasets, experiments, scripts, and documentation in this single repository. See [CONTRIBUTING.md](CONTRIBUTING.md) for Python 3.12 setup, module locations, branch and commit conventions, testing guidance, and the pull-request checklist. Repository CI runs the engine suite and deterministic Lite intake tests from a clean checkout. Pytest may report compiler-dependent engine cases as skipped because compiler availability varies; Lite controlled-pair and browser tests need ignored local ELF artifacts and are not run by CI.

### Existing project areas

- `src/vulngenome/`: binary analysis, inference, verification, reporting, and CLI engine modules.
- `lite/backend/` and `lite/frontend/`: local web application API and browser interface.
- `tests/` and `lite/backend/tests/`: engine and Lite tests, respectively.
- `fixtures/`: controlled C inputs, contracts, and evaluation cases.
- `datasets/`: dataset manifests and schema.
- `experiments/`: experiment configurations, records, and results.
- `scripts/`: fixture and evaluation utilities.
- `docs/`: architecture, semantics, limitations, threat model, and reproduction material.
- `work/`: ignored local build and analysis artifacts; do not commit generated binaries from this directory.

Local Lite settings are documented in [`lite/.env.example`](lite/.env.example). Keep actual credentials in an untracked local environment and never include them in issues or pull requests.
