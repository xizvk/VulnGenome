"""Run the controlled binary-pair analysis and save raw results."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from compile_fixture import compile_pair, compiler_metadata  # noqa: E402
from vulngenome.binary import analyze_binary  # noqa: E402
from vulngenome.patch import compare  # noqa: E402
from vulngenome.reporting import write_json  # noqa: E402
from vulngenome.symbolic import verify_unsigned_argument_at_call  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        compiler = compiler_metadata()
        binaries = compile_pair(args.work_dir.resolve() / "binaries")
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"fixture experiment could not compile the controlled binaries: {exc}", file=sys.stderr)
        return 2
    analysis = {key: analyze_binary(path).to_dict() for key, path in binaries.items()}
    pair_evidence = compare(
        analyze_binary(binaries["vulnerable"]), analyze_binary(binaries["patched"])
    )
    capacity_provenance = "manual controlled-fixture annotation in fixtures/contract.json"
    symbolic = {
        key: verify_unsigned_argument_at_call(
            path, function_name="transfer", call_name="sensitive_sink", capacity=16,
            capacity_provenance=capacity_provenance,
        ).to_dict()
        for key, path in binaries.items()
    }
    payload = {
        "record_schema": "1.0",
        "record_type": "controlled_fixture_experiment",
        "run_metadata": {"python": sys.version, "platform": platform.platform(), "compiler": compiler,
                         "target": "x86_64-linux-musl", "flags": ["-O0", "-g", "-fno-stack-protector", "-fPIC", "-shared",
                                   "-nostdlib", "-fuse-ld=lld", "-Wl,-Bsymbolic"] if compiler["name"] == "clang" else
                                  ["-O0", "-g", "-fno-stack-protector", "-fPIC", "-shared"],
                         "commands": ["python scripts/compile_fixture.py --out-dir <work>/binaries",
                                      "python scripts/run_fixture_experiment.py --work-dir <work> --out <record.json>"]},
        "fixture_annotation": json.loads((ROOT / "fixtures" / "contract.json").read_text(encoding="utf-8")),
        "binaries": {key: {"path": path, "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()} for key, path in binaries.items()},
        "binary_analysis": analysis,
        "patch_evidence": pair_evidence,
        "symbolic_callsite_results": symbolic,
        "interpretation": "controlled-fixture machinery check only; not a real-world result and not a general capacity-inference result",
    }
    write_json(args.out, payload)
    print(json.dumps({"out": str(args.out.resolve()), "sha256": payload["binaries"],
                      "states": {key: value["status"] for key, value in symbolic.items()}}, indent=2))
    return 0 if all(v["status"] != "ANALYSIS_ERROR" for v in symbolic.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
