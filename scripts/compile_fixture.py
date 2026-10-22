"""Compile the controlled C pair into real x86-64 ELF shared objects."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def compiler_command() -> list[str]:
    configured_clang = os.environ.get("VULNGENOME_CLANG")
    if configured_clang:
        executable = Path(configured_clang)
        if not executable.is_file():
            raise RuntimeError(f"VULNGENOME_CLANG does not name an existing file: {configured_clang}")
        return [str(executable.resolve())]
    configured = shutil.which("zig")
    if configured:
        return [configured]
    try:
        import ziglang  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("Zig is required; install the pinned fixture extra: pip install -e '.[fixture]'") from exc
    executable = Path(ziglang.__file__).with_name("zig.exe")
    if executable.is_file():
        return [str(executable)]
    return [sys.executable, "-m", "ziglang"]


def compiler_version() -> str:
    command = compiler_command()
    args = ["--version"] if os.environ.get("VULNGENOME_CLANG") else ["version"]
    result = subprocess.run(command + args, check=True, capture_output=True, text=True, timeout=15)
    return (result.stdout or result.stderr).strip().splitlines()[0]


def compiler_metadata() -> dict[str, str]:
    command = compiler_command()
    is_clang = bool(os.environ.get("VULNGENOME_CLANG"))
    metadata = {
        "name": "clang" if is_clang else "zig cc",
        "executable": command[0],
        "version": compiler_version(),
    }
    if is_clang:
        linker = Path(command[0]).with_name("ld.lld.exe")
        if linker.is_file():
            result = subprocess.run([str(linker), "--version"], check=True,
                                    capture_output=True, text=True, timeout=15)
            metadata["linker_executable"] = str(linker.resolve())
            metadata["linker_version"] = (result.stdout or result.stderr).strip().splitlines()[0]
    return metadata


def compile_pair(output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, str] = {}
    for label in ("vulnerable", "patched"):
        source = ROOT / "fixtures" / f"transfer_{label}.c"
        binary = output_dir / f"transfer_{label}.so"
        result[label] = compile_source(source, binary)
    return result


def compile_source(source: Path, binary: Path, *, extra_flags: tuple[str, ...] = ()) -> str:
    """Compile a controlled C input with the fixture toolchain and flags."""
    source = source.resolve()
    binary = binary.resolve()
    binary.parent.mkdir(parents=True, exist_ok=True)
    cmd = build_compile_command(source, binary, extra_flags=extra_flags)
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        raise RuntimeError(f"compiler command failed ({exc.returncode}): {detail}") from exc
    return str(binary)


def build_compile_command(source: Path, binary: Path, *, extra_flags: tuple[str, ...] = ()) -> list[str]:
    """Return the exact compiler argv used for a fixture source."""
    source = source.resolve()
    binary = binary.resolve()
    command = compiler_command()
    use_clang = bool(os.environ.get("VULNGENOME_CLANG"))
    if use_clang:
        cmd = command + ["--target=x86_64-linux-musl", "-O0", "-g", "-fno-stack-protector",
                         "-fPIC", "-shared", "-nostdlib", "-fuse-ld=lld", "-Wl,-Bsymbolic",
                         *extra_flags, str(source), "-o", str(binary)]
    else:
        cmd = command + ["cc", "-target", "x86_64-linux-musl", "-O0", "-g", "-fno-stack-protector",
                         "-fPIC", "-shared", *extra_flags, str(source), "-o", str(binary)]
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = compile_pair(args.out_dir.resolve())
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"fixture compilation failed: {exc}", file=sys.stderr)
        return 2
    for label, path in result.items():
        print(f"{label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
