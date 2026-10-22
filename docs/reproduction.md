# Reproduction guide

## Environment

Use 64-bit Python 3.12 and install the pinned project dependencies. The default fixture compiler is the `ziglang==0.15.2` package. In the recorded Windows workspace run, Zig launched but failed during compiler temporary/cache writes. LLVM Clang/LLD 23.1.4 was used instead, selected by setting `VULNGENOME_CLANG` to the Clang executable. It emitted x86-64 Linux-musl ELF shared objects without a Linux sysroot using `-nostdlib -fuse-ld=lld -Wl,-Bsymbolic` in addition to the fixture's `-O0 -g -fno-stack-protector -fPIC -shared` flags. The binaries are inspected, not executed. Toolchain location and hashes are recorded in `experiments/experiment_log.md`.

The Windows Store `python.exe` alias was not executable in this task. The bundled interpreter used for the recorded commands was `C:\Users\REDA NADIR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`. On another machine, replace `$PythonExe` with its Python 3.12 executable.

```powershell
$PythonExe = "C:\Users\REDA NADIR\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
& $PythonExe -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,fixture]"
```

The top-level package versions are pinned in `pyproject.toml`. The pip install must resolve the transitive dependencies; save the installed environment with `python -m pip freeze > experiments/environment-freeze.txt` before reporting an experiment.

## Tests

```powershell
pytest -q
```

The binary integration test compiles both fixtures, analyzes the compiled ELF objects with angr CFGFast/VEX, compares their symbol-supported function evidence, then queries the path to `sensitive_sink`. The original controlled run recorded 1 integration test passed and 22 tests in the full suite; after the annotation-free and independent adversarial cases were added, the latest full suite recorded **36 passed** (see `experiments/experiment_log.md`). If the configured compiler and required angr/Z3 dependencies are unavailable, binary tests may be skipped with the reported missing capability. Unit tests also exercise the typed DSL, bit-vector query construction, result policy, manifest leakage guard, and metrics.

## Controlled experiment

```powershell
python scripts/run_fixture_experiment.py `
  --work-dir ..\..\work\vulngenome `
  --out experiments\results\controlled-fixture-next.json
```

The output is raw per-binary analysis and solver evidence. The recorded run at `experiments/results/controlled-fixture-clang-20261021.json` produced one satisfiable violation for the vulnerable binary and an unsatisfiable violation query for the patched binary. The explicitly annotated capacity 16 and first argument role are controlled-fixture assumptions. The result does not establish general capacity inference or real-world transfer.

The separate annotation-free experiment at `experiments/results/annotation-free-invariants-clang-20261021.json` compiles the original pair and controlled variants, then calls `verify_unsigned_argument_at_call_inferred` without a capacity parameter. It records ELF/VEX capacity evidence, path constraints and branch sites, variant ground truth in a separate section, timings, commands, and hashes. Its supported case is limited to ELF object symbols directly used in a VEX store; stripped or ambiguous evidence must produce `INCONCLUSIVE`. Use a new output filename for each run so existing evidence is not overwritten.

The independent adversarial evaluation is reproducible with:

```powershell
python scripts/run_capacity_inference_evaluation.py `
  --work-dir work\capacity-inference-evaluation-next `
  --out experiments\results\adversarial-capacity-inference-next.json
```

The runner refuses to overwrite an existing output record or binary in the selected work directory. It compiles sources in `fixtures/evaluation/capacity-inference/`, analyzes the Linux AMD64 ELF artifacts statically, and never executes them. Ground truth remains separate from inference input. Use a new output filename for every run.

The extent matcher abstains when the sink contains unresolved writes or calls outside its supported pattern. The recorded evaluation is limited to its synthetic fixture set and Clang/LLD O0 build; it is not a real-world accuracy estimate.

## CLI

```powershell
python -m vulngenome.cli doctor
python -m vulngenome.cli analyze <binary> --out <analysis.json>
python -m vulngenome.cli compare <vulnerable-binary> <patched-binary> --out <pair.json>
python -m vulngenome.cli verify <spec.json> <evidence.json> --out <verification.json>
python -m vulngenome.cli validate-manifest <manifest.json>
python -m vulngenome.cli metrics <sample-results.jsonl> --out <metrics.json>
```

## Experiment integrity

Store every sample-level output and the environment freeze next to its configuration. The checked-in dataset manifest is empty because no benchmark case has been acquired and verified. Baseline/ablation files are protocol templates, not executed results. Do not report the controlled fixture as a real-world CVE result or as cross-implementation generalization.
