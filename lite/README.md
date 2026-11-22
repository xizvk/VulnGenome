# VulnGenome Lite

VulnGenome Lite is a local web application around the existing VulnGenome static binary-analysis engine. It accepts an actual vulnerable/patched binary pair, validates and hashes each upload, keeps the files in a private quarantine, and calls the existing angr/VEX, patch comparison, automatic extent inference, and symbolic verification functions. The service never executes an uploaded binary.

The extracted Phase 1 scaffold mentioned in the project request was not present in the workspace or in the inspected Downloads-root archives, so this repo-native `lite/` implementation is a fresh integration. No existing engine or research files were changed to build it.

The Lite environment pins `angr==10.0.4`, which provides the `angr.claripy` module used by this engine, plus its pinned PyVEX and Z3 components. It does not force the repository's separate `claripy==9.3.7` pin: pip reported that version requires Z3 4.13.0 while the pinned angr release requires Z3 5.1.0. The Lite environment also pins `pycparser==3.0`; pycparser 3.12 failed during angr import with an incompatible lexer API. The existing project `pyproject.toml` remains unchanged.

## Supported profile

- ELF64, little-endian, AMD64/x86-64, `ET_DYN` shared object.
- System V/Linux ELF ABI, with bounded load and dynamic segments.
- Static analysis only, for controlled fixtures and the current supported VulnGenome patterns.
- Function comparison uses unique exact symbol names. Solver claims stay scoped to recovered evidence and explored paths.

This is not a general-purpose malware or vulnerability scanner. PE, ARM64, arbitrary ELF inputs, stripped-function matching, dynamic execution, and arbitrary vulnerability classes are outside this MVP.

## Run locally on Windows

From PowerShell in this `lite` directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\run.ps1 -SkipInstall
```

Alternatively, `.\run.ps1` creates `.venv` if needed, installs `requirements.txt`, and starts the service. The dashboard opens at [http://127.0.0.1:8000](http://127.0.0.1:8000). The service binds to loopback by default.

## Run locally on Linux

```sh
cd lite
./run.sh
```

The script uses `python3.12` by default, creates `.venv`, installs `requirements.txt`, and binds to `127.0.0.1:8000`. Set `PYTHON=python3` to select another Python 3.12 executable if needed.

## Controlled demonstration

The known pair is stored locally under `work/annotation-free-invariants-20261021/binaries/` and is excluded from Git with the rest of local `work/`. If those artifacts are present, run:

```powershell
.\demo.ps1
```

or on Linux:

```sh
./demo.sh
```

The browser upload workflow performs the same analysis. The service computes the SHA-256 values; the controlled demonstration should identify these exact artifacts:

| Artifact | SHA-256 |
| --- | --- |
| Vulnerable | `af5b3a669e147a4b9cd1f674c20ec5cbec73d1b54c57d66ac74ede8a26b1dd33` |
| Patched | `f5fc4b99929a4a6c0bb0bc57fc13a5ef495b5110218a87b540ae1fd7f2f0a8fc` |

## API

- `GET /api/v1/health`
- `POST /api/v1/analyses` — multipart fields `vulnerable` and `patched`, exactly one file each.
- `GET /api/v1/analyses`
- `GET /api/v1/analyses/{id}`
- `GET /api/v1/analyses/{id}/evidence`
- `GET /api/v1/analyses/{id}/verification`
- `GET /api/v1/analyses/{id}/diff`
- `GET /api/v1/analyses/{id}/intelligence`
- `GET /api/v1/analyses/{id}/report?format=json|html`

Uploads are capped at 32 MiB per artifact and stored outside the static frontend under `lite/.runtime/quarantine/`. SQLite job records are stored under `lite/.runtime/`. Keep this local service restricted to trusted users; it is a course-project MVP, not a hardened multi-tenant service.

## Intelligence layer

The app retrieves full text from selected project documentation, the controlled fixture contract/source files, and a short attributed paraphrase of MITRE CWE-787. Each source is identified by its content hash. With no `OPENAI_API_KEY`, the service uses a clearly labeled deterministic local explanation. To opt into a hosted explanation, configure `OPENAI_API_KEY`, `OPENAI_MODEL`, and optionally `OPENAI_BASE_URL` in the service process environment. The service sends selected structured analysis results and retrieved text only; it never sends uploaded binary bytes. Model output is schema-checked and all source/evidence references must resolve to the current analysis record. The model cannot change solver status. CWE material is explanatory context only and cannot establish a finding or override the binary-derived record.

## Tests

From `lite/backend` with the Lite virtual environment active:

```powershell
..\.venv\Scripts\python.exe -m pytest -q tests
```

or:

```sh
../../lite/.venv/bin/python -m pytest -q tests
```

The controlled-pair acceptance test uploads the real local pair to the app and asserts actual angr/VEX, automatic inference, and symbolic results. The browser test uses an already-installed Microsoft Edge and is skipped if Edge or the local ignored binary artifacts are unavailable. A separate unsupported non-ELF case is rejected at intake with HTTP 422 and creates no analysis job. The existing research suite can be run from the repository root:

```powershell
.\lite\.venv\Scripts\python.exe -m pytest -q
```

## Deployment note

No Docker executable was available during implementation, so no Dockerfile is included. Local scripts bind only to loopback. The deterministic fallback needs no external service.
