"""Narrow binary-derived object-capacity recovery for Linux AMD64 ELF files.

The current inference is intentionally limited to a positive-size ELF object
symbol whose address is used by a VEX store in the named sensitive function.
It does not consult fixture source, a manifest, or caller-supplied capacity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
from typing import Any

from .binary import parse_metadata


@dataclass(frozen=True)
class CapacityInferenceResult:
    status: str
    binary_sha256: str
    binary_format: str
    architecture: str
    function: str
    function_address: int | None
    sensitive_call: str
    sensitive_call_address: int | None
    capacity: int | None
    evidence_id: str | None
    evidence: dict[str, Any]
    method: str
    assumptions: tuple[str, ...]
    inferred: bool
    supplied: bool
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def infer_capacity_from_binary(
    binary_path: str | Path,
    *,
    function_name: str,
    call_name: str,
) -> CapacityInferenceResult:
    """Infer an object extent only when ELF and VEX evidence agree.

    Supported evidence is an ELF ``STT_OBJECT`` symbol with a positive size,
    directly referenced by the address expression of a VEX store in
    ``call_name``. The named caller must have one direct call site to that
    function. Everything else abstains rather than falling back to a constant.
    """
    path = Path(binary_path).resolve()
    data = path.read_bytes()
    metadata = parse_metadata(path, data)
    digest = metadata.sha256
    method = "ELF STT_OBJECT extent cross-referenced to VEX Store address"
    assumptions = (
        "the ELF object symbol size describes the allocated object extent",
        "the VEX store address expression references the object symbol directly",
        "the named sensitive function and caller are uniquely resolved in this binary",
        "this inference does not establish alias safety or generalize to indirect/dynamic allocations",
    )

    def abstain(reason: str, *, caller_addr: int | None = None,
                sink_addr: int | None = None, evidence: dict[str, Any] | None = None) -> CapacityInferenceResult:
        return CapacityInferenceResult(
            "INCONCLUSIVE", digest, metadata.file_format, metadata.architecture,
            function_name, caller_addr, call_name, sink_addr, None, None,
            evidence or {}, method, assumptions, False, False, reason,
        )

    if metadata.file_format != "ELF64" or metadata.architecture != "x86-64":
        return abstain("automatic capacity inference currently supports ELF64 x86-64 only")

    try:
        import angr  # type: ignore[import-not-found]
        import pyvex  # type: ignore[import-not-found]
    except ImportError as exc:
        return abstain(f"required binary-analysis dependency unavailable: {exc}")

    try:
        project = angr.Project(str(path), auto_load_libs=False)
        if project.loader.main_object.os not in ("linux", "UNIX - System V"):
            return abstain("automatic capacity inference requires a Linux/System V ELF binary")
        cfg = project.analyses.CFGFast(normalize=True, data_references=True)
    except Exception as exc:
        return abstain(f"binary analysis failed: {type(exc).__name__}: {exc}")

    caller = _resolve_unique(cfg, function_name)
    sink = _resolve_unique(cfg, call_name)
    if caller is None or sink is None:
        return abstain("caller or sensitive function is missing or ambiguous",
                       caller_addr=caller.addr if caller else None,
                       sink_addr=sink.addr if sink else None)

    call_sites = []
    for call_site in caller.get_call_sites() or ():
        if caller.get_call_target(call_site) == sink.addr:
            call_sites.append(int(call_site))
    if len(call_sites) != 1:
        return abstain(f"expected one direct call site from {function_name} to {call_name}; found {len(call_sites)}",
                       caller_addr=int(caller.addr), sink_addr=int(sink.addr))

    object_symbols: dict[tuple[str, int, int], Any] = {}
    for symbol in project.loader.main_object.symbols:
        symbol_type = getattr(getattr(symbol, "type", None), "name", str(getattr(symbol, "type", "")))
        if symbol_type.endswith("TYPE_OBJECT") and int(getattr(symbol, "size", 0) or 0) > 0:
            key = (str(symbol.name), int(symbol.rebased_addr), int(symbol.size))
            object_symbols[key] = symbol
    if not object_symbols:
        return abstain("no positive-size ELF object symbols are available; capacity cannot be inferred",
                       caller_addr=int(caller.addr), sink_addr=int(sink.addr))

    stores_by_symbol: dict[tuple[str, int, int], list[dict[str, Any]]] = {
        key: [] for key in object_symbols
    }
    for block_addr in sorted(sink.block_addrs_set):
        try:
            block = project.factory.block(block_addr)
        except Exception:
            continue
        tmp_defs = {
            statement.tmp: statement.data
            for statement in block.vex.statements
            if isinstance(statement, pyvex.stmt.WrTmp)
        }
        current_instruction: int | None = None
        for statement in block.vex.statements:
            if isinstance(statement, pyvex.stmt.IMark):
                current_instruction = int(statement.addr)
            elif isinstance(statement, pyvex.stmt.Store):
                constants = _resolved_constants(statement.addr, tmp_defs)
                matched = [key for key in object_symbols if key[1] in constants]
                if not matched:
                    continue
                instruction = next((item for item in block.capstone.insns
                                    if int(item.address) == current_instruction), None)
                item = {
                    "block_address": int(block_addr),
                    "instruction_address": current_instruction,
                    "instruction": ({"address": int(instruction.address),
                                     "mnemonic": instruction.mnemonic,
                                     "op_str": instruction.op_str,
                                     "bytes": bytes(instruction.bytes).hex()}
                                    if instruction is not None else None),
                    "store_statement": str(statement),
                    "vex_block": str(block.vex),
                }
                for key in matched:
                    stores_by_symbol[key].append(item)

    referenced = {key: stores for key, stores in stores_by_symbol.items() if stores}
    if len(referenced) != 1:
        reason = ("no ELF object symbol is directly referenced by a VEX store in the sensitive function"
                  if not referenced else
                  f"multiple ELF object symbols are referenced by stores in the sensitive function: {len(referenced)}")
        return abstain(reason, caller_addr=int(caller.addr), sink_addr=int(sink.addr))

    (symbol_name, symbol_address, capacity), stores = next(iter(referenced.items()))
    if capacity <= 0:
        return abstain("referenced object has a non-positive symbol size",
                       caller_addr=int(caller.addr), sink_addr=int(sink.addr))

    call_site = call_sites[0]
    call_instruction = _instruction_at(project, call_site)
    evidence = {
        "binary_sha256": digest,
        "binary_format": metadata.file_format,
        "architecture": metadata.architecture,
        "function": {"name": function_name, "address": int(caller.addr)},
        "sensitive_function": {"name": call_name, "address": int(sink.addr)},
        "call_site": {"address": call_site, "instruction": call_instruction},
        "object_symbol": {"name": symbol_name, "address": symbol_address,
                          "size_bytes": capacity, "symbol_type": "STT_OBJECT"},
        "store_evidence": stores,
        "analysis": "CFGFast function recovery; VEX Store address resolved through same-block temporary definitions",
    }
    evidence_id = "vg-cap-" + hashlib.sha256(
        f"{digest}:{symbol_name}:{symbol_address:x}:{capacity}:{call_site:x}".encode("utf-8")
    ).hexdigest()[:20]
    return CapacityInferenceResult(
        "INFERRED", digest, metadata.file_format, metadata.architecture,
        function_name, int(caller.addr), call_name, int(sink.addr), capacity,
        evidence_id, evidence, method, assumptions, True, False,
    )


def _resolve_unique(cfg: Any, name: str) -> Any | None:
    matches = [function for function in cfg.kb.functions.values() if function.name == name]
    return matches[0] if len(matches) == 1 else None


def _resolved_constants(expression: Any, tmp_defs: dict[int, Any]) -> set[int]:
    """Collect constants from an expression while resolving same-block VEX temps."""
    import pyvex  # type: ignore[import-not-found]

    found: set[int] = set()
    pending = [expression]
    seen_temps: set[int] = set()
    while pending:
        node = pending.pop()
        if isinstance(node, pyvex.expr.RdTmp):
            if node.tmp not in seen_temps:
                seen_temps.add(node.tmp)
                definition = tmp_defs.get(node.tmp)
                if definition is not None:
                    pending.append(definition)
        elif isinstance(node, pyvex.expr.Const):
            found.add(int(node.con.value))
        else:
            pending.extend(getattr(node, "child_expressions", ()) or ())
    return found


def _instruction_at(project: Any, address: int) -> dict[str, Any] | None:
    try:
        block = project.factory.block(address)
        instruction = next((item for item in block.capstone.insns if int(item.address) == address), None)
    except Exception:
        return None
    if instruction is None:
        return None
    return {"address": int(instruction.address), "mnemonic": instruction.mnemonic,
            "op_str": instruction.op_str, "bytes": bytes(instruction.bytes).hex()}
