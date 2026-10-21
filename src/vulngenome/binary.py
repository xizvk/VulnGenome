"""Binary provenance and optional angr-based CFG/VEX extraction."""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BinaryMetadata:
    path: str
    sha256: str
    size_bytes: int
    file_format: str
    architecture: str
    endianness: str
    image_base: int | None = None
    entry_point: int | None = None
    build_id: str | None = None
    symbols_available: bool = False
    sections: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class BinaryAnalysis:
    metadata: BinaryMetadata
    analyzer: str | None
    analyzer_version: str | None
    functions: list[dict[str, Any]] = field(default_factory=list)
    capabilities: dict[str, bool] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def analyze_binary(path: str | Path, *, use_angr: bool = True) -> BinaryAnalysis:
    file_path = Path(path).resolve()
    data = file_path.read_bytes()
    metadata = parse_metadata(file_path, data)
    analysis = BinaryAnalysis(metadata, None, None,
                              capabilities={"metadata": True, "cfg": False, "vex": False,
                                            "symbols": metadata.symbols_available})
    if not use_angr:
        return analysis
    try:
        import angr  # type: ignore[import-not-found]
    except ImportError:
        analysis.warnings.append("angr is not installed; metadata-only analysis was produced")
        return analysis
    try:
        project = angr.Project(str(file_path), auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True, data_references=True)
        analysis.analyzer = "angr"
        analysis.analyzer_version = getattr(angr, "__version__", "unknown")
        analysis.capabilities["cfg"] = True
        analysis.capabilities["vex"] = True
        functions: list[dict[str, Any]] = []
        for function in sorted(cfg.kb.functions.values(), key=lambda f: (f.addr, f.name)):
            blocks = []
            calls = []
            vex_blocks = []
            for block_addr in sorted(function.block_addrs_set):
                try:
                    block = project.factory.block(block_addr)
                    vex_blocks.append(str(block.vex))
                    blocks.append({
                        "address": int(block_addr),
                        "size": int(block.size),
                        "instruction_count": len(block.capstone.insns),
                        "instructions": [
                            {"address": int(insn.address), "mnemonic": insn.mnemonic,
                             "op_str": insn.op_str, "bytes": bytes(insn.bytes).hex()}
                            for insn in block.capstone.insns
                        ],
                        "vex": str(block.vex),
                    })
                except Exception as exc:
                    analysis.warnings.append(f"block 0x{block_addr:x} could not be lifted: {type(exc).__name__}: {exc}")
            for callsite in function.get_call_sites() or ():
                target = function.get_call_target(callsite)
                callee = cfg.kb.functions.get(target) if target is not None else None
                calls.append({"address": int(callsite), "target": int(target) if target is not None else None,
                              "name": callee.name if callee else None})
            functions.append({
                "name": function.name,
                "address": int(function.addr),
                "size": int(function.size),
                "is_simprocedure": bool(function.is_simprocedure),
                "blocks": blocks,
                "calls": calls,
                "vex_block_count": len(vex_blocks),
            })
        analysis.functions = functions
    except Exception as exc:
        analysis.errors.append(f"angr analysis failed: {type(exc).__name__}: {exc}")
    return analysis


def parse_metadata(path: Path, data: bytes) -> BinaryMetadata:
    meta = BinaryMetadata(str(path), hashlib.sha256(data).hexdigest(), len(data), "unknown", "unknown", "unknown")
    if data.startswith(b"\x7fELF"):
        _parse_elf(meta, data)
    elif data.startswith(b"MZ"):
        _parse_pe(meta, data)
    else:
        meta.warnings.append("unrecognized file header; only size and hash are reliable")
    return meta


def _parse_elf(meta: BinaryMetadata, data: bytes) -> None:
    if len(data) < 52:
        meta.warnings.append("truncated ELF header")
        return
    bits = {1: 32, 2: 64}.get(data[4])
    endian = {1: "little", 2: "big"}.get(data[5])
    if bits is None or endian is None:
        meta.warnings.append("invalid ELF class or byte order")
        return
    meta.file_format = f"ELF{bits}"
    meta.endianness = endian
    prefix = "<" if endian == "little" else ">"
    machine = struct.unpack_from(prefix + "H", data, 18)[0]
    meta.architecture = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}.get(machine, f"ELF-machine-{machine}")
    if bits == 64 and len(data) >= 64:
        meta.entry_point = struct.unpack_from(prefix + "Q", data, 24)[0]
        phoff = struct.unpack_from(prefix + "Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from(prefix + "HH", data, 54)
        for index in range(phnum):
            off = phoff + index * phentsize
            if off + phentsize > len(data) or phentsize < 56:
                meta.warnings.append("truncated ELF program header table")
                break
            p_type = struct.unpack_from(prefix + "I", data, off)[0]
            if p_type == 1:
                vaddr = struct.unpack_from(prefix + "Q", data, off + 16)[0]
                meta.image_base = vaddr if meta.image_base is None else min(meta.image_base, vaddr)
    meta.warnings.append("ELF section/symbol and build-id extraction is not implemented by the stdlib parser")


def _parse_pe(meta: BinaryMetadata, data: bytes) -> None:
    if len(data) < 0x40:
        meta.warnings.append("truncated DOS header")
        return
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
        meta.warnings.append("invalid or truncated PE header")
        return
    machine, section_count, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    opt = pe_off + 24
    if opt + optional_size > len(data) or optional_size < 60:
        meta.warnings.append("truncated PE optional header")
        return
    magic = struct.unpack_from("<H", data, opt)[0]
    meta.file_format = "PE32+" if magic == 0x20B else "PE32" if magic == 0x10B else "PE"
    meta.architecture = {0x8664: "x86-64", 0x14C: "x86", 0xAA64: "AArch64"}.get(machine, f"PE-machine-{machine:#x}")
    meta.endianness = "little"
    if magic == 0x20B and optional_size >= 32:
        meta.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        meta.entry_point = meta.image_base + struct.unpack_from("<I", data, opt + 16)[0]
    elif magic == 0x10B and optional_size >= 32:
        meta.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        meta.entry_point = meta.image_base + struct.unpack_from("<I", data, opt + 16)[0]
    sec_off = opt + optional_size
    for index in range(section_count):
        off = sec_off + 40 * index
        if off + 40 > len(data):
            meta.warnings.append("truncated PE section table")
            break
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        meta.sections.append({"name": name, "virtual_address": virtual_address,
                              "virtual_size": virtual_size, "raw_offset": raw_ptr, "raw_size": raw_size})
    meta.warnings.append("PE symbol/PDB and build-id extraction is not implemented by the stdlib parser")
