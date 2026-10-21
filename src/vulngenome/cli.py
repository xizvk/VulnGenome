"""Command-line interface for reproducible prototype operations."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .binary import analyze_binary
from .datasets import load_manifest
from .invariants import validate
from .metrics import calculate_metrics
from .models import EvidenceBundle, InvariantSpec, SchemaError
from .patch import compare
from .reporting import write_json
from .verification import verify


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulngenome", description="Evidence-grounded binary invariant research prototype")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="report available local capabilities")
    doctor.add_argument("--json", dest="json_path")
    analyze = sub.add_parser("analyze", help="record binary metadata and optional angr CFG/VEX evidence")
    analyze.add_argument("binary")
    analyze.add_argument("--out", required=True)
    compare_cmd = sub.add_parser("compare", help="analyze and compare a vulnerable/patched pair")
    compare_cmd.add_argument("vulnerable")
    compare_cmd.add_argument("patched")
    compare_cmd.add_argument("--out", required=True)
    verify_cmd = sub.add_parser("verify", help="validate and solve a typed invariant JSON record")
    verify_cmd.add_argument("spec")
    verify_cmd.add_argument("evidence")
    verify_cmd.add_argument("--timeout-ms", type=int, default=5000)
    verify_cmd.add_argument("--out", required=True)
    manifest = sub.add_parser("validate-manifest", help="validate manifest provenance and split leakage")
    manifest.add_argument("path")
    metrics = sub.add_parser("metrics", help="compute metrics from sample-level JSONL results")
    metrics.add_argument("jsonl")
    metrics.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            result = _doctor()
            if args.json_path:
                write_json(args.json_path, result)
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "analyze":
            result = analyze_binary(args.binary).to_dict()
            write_json(args.out, result)
            print(json.dumps({"sha256": result["metadata"]["sha256"], "capabilities": result["capabilities"], "warnings": result["warnings"], "errors": result["errors"]}, indent=2))
            return 0 if not result["errors"] else 2
        if args.command == "compare":
            old = analyze_binary(args.vulnerable)
            new = analyze_binary(args.patched)
            result = {"vulnerable": old.to_dict(), "patched": new.to_dict(), "patch_evidence": compare(old, new)}
            write_json(args.out, result)
            print(json.dumps({"matches": len(result["patch_evidence"]["matches"]), "out": args.out}, indent=2))
            return 0
        if args.command == "verify":
            spec = InvariantSpec.from_dict(json.loads(Path(args.spec).read_text(encoding="utf-8")))
            evidence = EvidenceBundle.from_dict(json.loads(Path(args.evidence).read_text(encoding="utf-8")))
            verdict = verify(spec, evidence, args.timeout_ms)
            write_json(args.out, verdict.to_dict())
            print(json.dumps(verdict.to_dict(), indent=2))
            return 0 if verdict.status != "ANALYSIS_ERROR" else 2
        if args.command == "validate-manifest":
            _, errors = load_manifest(args.path)
            print(json.dumps({"valid": not errors, "errors": errors}, indent=2))
            return 0 if not errors else 2
        if args.command == "metrics":
            rows = [json.loads(line) for line in Path(args.jsonl).read_text(encoding="utf-8").splitlines() if line.strip()]
            result = calculate_metrics(rows)
            write_json(args.out, result)
            print(json.dumps(result, indent=2))
            return 0
    except (OSError, json.JSONDecodeError, SchemaError, ValueError) as exc:
        print(f"vulngenome: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 2


def _doctor() -> dict[str, Any]:
    modules: dict[str, bool] = {}
    for name in ("angr", "claripy", "z3", "pytest", "pydantic"):
        try:
            __import__(name)
            modules[name] = True
        except ImportError:
            modules[name] = False
    zig_version = None
    zig_error = None
    try:
        import importlib.util
        import subprocess
        zig_path = shutil.which("zig")
        if zig_path is None and importlib.util.find_spec("ziglang") is not None:
            import ziglang  # type: ignore[import-not-found]
            candidate = Path(ziglang.__file__).with_name("zig.exe")
            zig_path = str(candidate) if candidate.is_file() else None
        if zig_path:
            version = subprocess.run([zig_path, "version"], capture_output=True, text=True, timeout=15)
            operational = subprocess.run([zig_path, "env"], capture_output=True, text=True, timeout=15)
            zig_version = version.stdout.strip() if version.returncode == 0 else None
            if operational.returncode:
                zig_error = (operational.stderr or operational.stdout).strip()
        else:
            zig_error = "not installed"
    except Exception as exc:
        zig_error = f"{type(exc).__name__}: {exc}"
    return {"version": __version__, "python": sys.version, "platform": sys.platform,
            "modules": modules, "executables": {"zig": bool(shutil.which("zig")),
                                                   "ghidra": bool(shutil.which("analyzeHeadless")),
                                                   "rizin": bool(shutil.which("rizin")),
                                                   "objdump": bool(shutil.which("objdump"))},
            "fixture_compiler": {"zig_version": zig_version, "operational": zig_error is None, "error": zig_error},
            "supported_analysis": ["PE/ELF metadata via stdlib", "CFG/VEX only when angr imports successfully"],
            "unsupported_claims": ["no CVE dataset results are currently measured", "no LLM/RAG provider configured"]}


if __name__ == "__main__":
    raise SystemExit(main())
