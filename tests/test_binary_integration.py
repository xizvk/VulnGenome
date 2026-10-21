from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from vulngenome.binary import analyze_binary
from vulngenome.patch import compare
from vulngenome.symbolic import verify_unsigned_argument_at_call


ROOT = Path(__file__).resolve().parents[1]
ANGR_IMPORTABLE = False
try:
    import angr  # noqa: F401
    from angr import claripy  # noqa: F401
    import z3  # noqa: F401
    ANGR_IMPORTABLE = True
except Exception:
    pass


def compiler_status():
    clang = os.environ.get("VULNGENOME_CLANG")
    if clang:
        try:
            result = subprocess.run([clang, "--version"], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"configured Clang is not operational: {exc}"
        if result.returncode:
            return False, f"configured Clang is not operational: {(result.stderr or result.stdout).strip()}"
        return True, ""
    zig = shutil.which("zig")
    if zig:
        command = [zig]
    elif importlib.util.find_spec("ziglang") is not None:
        import ziglang
        command = [str(Path(ziglang.__file__).with_name("zig.exe"))]
    else:
        return False, "pinned Zig compiler is not installed"
    try:
        result = subprocess.run(command + ["env"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Zig compiler is not operational: {exc}"
    if result.returncode:
        return False, f"Zig compiler is not operational: {(result.stderr or result.stdout).strip()}"
    return True, ""


COMPILER_AVAILABLE, COMPILER_REASON = compiler_status()


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason=COMPILER_REASON)
@pytest.mark.skipif(not ANGR_IMPORTABLE, reason="angr/Claripy/Z3 did not import successfully")
def test_compiled_binary_pair_to_symbolic_result(tmp_path):
    script = ROOT / "scripts" / "compile_fixture.py"
    subprocess.run([sys.executable, str(script), "--out-dir", str(tmp_path / "bin")], check=True, capture_output=True, text=True)
    vulnerable = tmp_path / "bin" / "transfer_vulnerable.so"
    patched = tmp_path / "bin" / "transfer_patched.so"
    old_analysis, new_analysis = analyze_binary(vulnerable), analyze_binary(patched)
    assert old_analysis.capabilities["cfg"] and old_analysis.capabilities["vex"]
    assert new_analysis.capabilities["cfg"] and new_analysis.capabilities["vex"]
    assert any(f["name"] == "transfer" for f in old_analysis.functions)
    evidence = compare(old_analysis, new_analysis)
    assert any(item.get("name") == "transfer" and item["classification"] == "symbol_supported" for item in evidence["matches"])

    old_result = verify_unsigned_argument_at_call(vulnerable, function_name="transfer", call_name="sensitive_sink",
        capacity=16, capacity_provenance="controlled fixture contract")
    new_result = verify_unsigned_argument_at_call(patched, function_name="transfer", call_name="sensitive_sink",
        capacity=16, capacity_provenance="controlled fixture contract")
    assert old_result.status == "POTENTIAL_VIOLATION", old_result.to_dict()
    assert new_result.status == "PROPERTY_HOLDS_WITHIN_MODEL", new_result.to_dict()
