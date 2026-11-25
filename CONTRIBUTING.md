# Contributing to VulnGenome

VulnGenome is a research prototype. Keep changes focused, preserve evidence and limitations, and work inside the existing repository areas. Do not move or rename project directories as part of a feature contribution.

## Development setup

Use Python 3.12. The engine manifest is `pyproject.toml`; the local Lite app has its own pinned dependency set in `lite/requirements.txt`. These environments are intentionally separate: the root manifest's `claripy==9.3.7` pin conflicts with the Claripy version required by `angr==10.0.4`. Do not install both sets into one environment or change pins simply to make setup appear successful.

### Engine

The current root `pyproject.toml` pins `claripy==9.3.7`, while `angr==10.0.4` requires a different Claripy release. A standard `pip install -e ".[dev,fixture]"` can therefore fail dependency resolution. Until those existing pins are reconciled in a separately reviewed change, use this compatibility setup in a fresh engine environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r lite/requirements.txt
python -m pip install "pydantic==2.13.5"
python -m pip install -e . --no-deps
pytest -q
```

On Linux/macOS, use `python3.12 -m venv .venv`, `source .venv/bin/activate`, then the same pip and pytest commands. This reuses Lite's angr-compatible dependency set and installs the root package without forcing its conflicting pins. Fixture compilation also requires the configured compiler; `docs/reproduction.md` documents the supported compiler setup and current limits. Compiler-dependent tests may skip when the required compiler or local artifacts are unavailable; report skips accurately.

### VulnGenome Lite

Follow [`lite/README.md`](lite/README.md). On Windows, run `lite\run.ps1`; on Linux, run `./lite/run.sh`. These scripts create and use `lite/.venv` without sharing the root engine environment. For deterministic Lite tests that do not require the ignored controlled ELF pair, run:

```powershell
Set-Location lite\backend
..\.venv\Scripts\python.exe -m pytest -q tests/test_api.py -k "not controlled_pair"
```

The controlled-pair acceptance and browser tests require the local pair under ignored `work/` and, for browser automation, Microsoft Edge. They are not clean-clone tests.

### Environment configuration

Lite reads `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_BASE_URL`, and `VULNGENOME_LITE_DATA_DIR` from the process environment. The hosted explanation provider is optional; the deterministic local fallback needs no key. The service binds to loopback by default. Never commit `.env` files, keys, personal data, analysis uploads, or local SQLite databases.

## Where to contribute

Use the current layout:

- Engine modules: `src/vulngenome/`.
- Lite API and services: `lite/backend/app/`.
- Lite browser UI: `lite/frontend/`.
- Engine tests: `tests/`; Lite tests: `lite/backend/tests/`.
- Controlled fixture C source and contracts: `fixtures/`.
- Dataset manifests: `datasets/manifests/`; do not commit private datasets without authorization and review.
- Research configurations and result records: `experiments/`.
- Developer utilities: `scripts/`.
- Technical documentation: `docs/`; Lite usage: `lite/README.md`.
- External integrations: the existing relevant service module; discuss broad changes before adding abstractions.

## Branches and commits

Create a focused branch using one of these prefixes: `feature/`, `fix/`, `docs/`, `test/`, `refactor/`, or `chore/`.

Use Conventional Commit subjects such as `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `build:`, and `ci:`. Keep each commit limited to the reviewed purpose.

## Pull requests

Before opening a pull request:

1. Run the relevant tests and state which tests passed, failed, skipped, or were not run. Do not describe skipped compiler/artifact tests as passing.
2. Update the existing docs when commands, evidence, supported patterns, or limitations change.
3. Keep the change focused and preserve existing data and experiment records.
4. Explain dependency changes and why the existing manifests cannot be used.
5. Check that no credentials, local databases, private data, or unreviewed binaries are included.
6. Request review and address feedback before merging.

For binary-analysis changes, identify the exact input hashes and evidence scope. Preserve abstention behavior and do not claim a general vulnerability proof from synthetic solver checks or a narrow fixture result.
