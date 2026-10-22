"""Conservative ELF object-extent inference tied to a verified sink loop.

This module supports a deliberately narrow Linux AMD64 pattern. A positive
size ELF object is accepted only when the sink function contains one byte
store at ``object[index]`` and recovered VEX shows that ``index`` starts at
zero, is incremented by one, and is stored only on the true edge of an
unsigned ``index < first_argument`` loop. Unsupported or ambiguous relations
abstain; symbol-size recovery alone is never treated as a verified capacity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
from typing import Any

from .binary import parse_metadata
from .optimized_vex import infer_optimized_scalar_loop


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
    argument_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def infer_capacity_from_binary(
    binary_path: str | Path,
    *,
    function_name: str,
    call_name: str,
    argument_index: int = 0,
) -> CapacityInferenceResult:
    """Recover an object size only when a narrow binary data-flow pattern holds.

    The current proof pattern is an unsigned zero-based unit-stride loop whose
    loop variable indexes a one-byte store into exactly one candidate object.
    The loop compares that same variable with the named sink's first argument.
    The caller and sink must resolve uniquely and have one direct call site.
    """
    path = Path(binary_path).resolve()
    data = path.read_bytes()
    metadata = parse_metadata(path, data)
    digest = metadata.sha256
    method = "ELF STT_OBJECT extent + VEX sink-loop argument/data-flow match"
    assumptions = (
        "the ELF STT_OBJECT symbol size describes the allocated object extent",
        "the recognized VEX loop is the complete write pattern for this sink function",
        "the System V AMD64 first integer argument is the sink's size_t byte count",
        "each recognized loop iteration writes exactly one byte at its zero-based index",
        "this matcher does not prove alias safety or support indirect/dynamic allocations",
    )

    def abstain(
        reason: str,
        *,
        caller_addr: int | None = None,
        sink_addr: int | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> CapacityInferenceResult:
        return CapacityInferenceResult(
            "INCONCLUSIVE", digest, metadata.file_format, metadata.architecture,
            function_name, caller_addr, call_name, sink_addr, None, None,
            evidence or {}, method, assumptions, False, False, reason, argument_index,
        )

    if argument_index != 0:
        return abstain("only the first System V AMD64 integer argument is supported")
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

    call_blocks = [
        int(site) for site in caller.get_call_sites() or ()
        if caller.get_call_target(site) == sink.addr
    ]
    if len(call_blocks) != 1:
        return abstain(
            f"expected one direct call site from {function_name} to {call_name}; found {len(call_blocks)}",
            caller_addr=int(caller.addr), sink_addr=int(sink.addr),
        )
    call_block_address = call_blocks[0]
    call_instruction = _direct_call_instruction(project, call_block_address, int(sink.addr))
    if call_instruction is None:
        return abstain("the direct call instruction could not be uniquely recovered",
                       caller_addr=int(caller.addr), sink_addr=int(sink.addr))
    call_evidence = {
        "block_address": call_block_address,
        "instruction_address": call_instruction["address"],
        "instruction": call_instruction,
        "target_function": {"name": call_name, "address": int(sink.addr)},
    }
    base_evidence = {
        "binary_sha256": digest,
        "binary_format": metadata.file_format,
        "architecture": metadata.architecture,
        "function": {"name": function_name, "address": int(caller.addr)},
        "sensitive_function": {"name": call_name, "address": int(sink.addr)},
        "call_site": call_evidence,
        "sink_argument": {"index": argument_index, "abi_register": "rdi",
                          "width_bits": 64},
    }

    symbols_by_address: dict[int, list[tuple[str, int, int]]] = {}
    for symbol in project.loader.main_object.symbols:
        symbol_type = getattr(getattr(symbol, "type", None), "name", str(getattr(symbol, "type", "")))
        size = int(getattr(symbol, "size", 0) or 0)
        if symbol_type.endswith("TYPE_OBJECT") and size > 0:
            item = (str(symbol.name), int(symbol.rebased_addr), size)
            if item not in symbols_by_address.setdefault(item[1], []):
                symbols_by_address[item[1]].append(item)
    if not symbols_by_address:
        return abstain("no positive-size ELF object symbols are available; capacity cannot be inferred",
                       caller_addr=int(caller.addr), sink_addr=int(sink.addr), evidence=base_evidence)

    block_info: dict[int, dict[str, Any]] = {}
    candidate_stores: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
    all_store_records: list[dict[str, Any]] = []
    unsupported_memory_writes: list[dict[str, Any]] = []
    sink_calls: list[dict[str, Any]] = []
    try:
        for block_address in sorted(sink.block_addrs_set):
            block = project.factory.block(block_address)
            sink_calls.extend(
                {"address": int(insn.address), "mnemonic": insn.mnemonic, "op_str": insn.op_str}
                for insn in block.capstone.insns
                if insn.mnemonic.lower().startswith("call")
            )
            definitions = {
                statement.tmp: statement.data
                for statement in block.vex.statements
                if isinstance(statement, pyvex.stmt.WrTmp)
            }
            block_info[int(block_address)] = {"block": block, "definitions": definitions}
            instruction_address: int | None = None
            for index, statement in enumerate(block.vex.statements):
                if isinstance(statement, pyvex.stmt.IMark):
                    instruction_address = int(statement.addr)
                elif _is_unsupported_memory_write(statement, pyvex):
                    unsupported_memory_writes.append({
                        "block_address": int(block_address),
                        "instruction_address": instruction_address,
                        "statement_kind": type(statement).__name__,
                        "statement": str(statement),
                    })
                elif isinstance(statement, pyvex.stmt.Store):
                    address_expr = _resolve_expr(statement.addr, definitions, block.vex.tyenv)
                    symbol_base, offset_expr = _global_store_address(
                        address_expr, set(symbols_by_address)
                    )
                    store_record = {
                        "block_address": int(block_address),
                        "statement_index": index,
                        "statement": statement,
                        "definitions": definitions,
                        "block": block,
                        "instruction_address": instruction_address,
                        "address_expression": address_expr,
                        "symbol_base": symbol_base,
                    }
                    all_store_records.append(store_record)
                    if symbol_base is None:
                        continue
                    for symbol in symbols_by_address[symbol_base]:
                        insn = _instruction_at(project, instruction_address) if instruction_address is not None else None
                        candidate_stores.setdefault(symbol, []).append({
                            **store_record,
                            "block_address": int(block_address),
                            "instruction": insn,
                            "offset_expression": offset_expr,
                            "width_bits": int(statement.data.result_size(block.vex.tyenv)),
                            "store_statement": str(statement),
                            "vex_block": str(block.vex),
                        })
    except Exception as exc:
        return abstain(f"VEX store recovery failed: {type(exc).__name__}: {exc}",
                       caller_addr=int(caller.addr), sink_addr=int(sink.addr), evidence=base_evidence)

    if unsupported_memory_writes:
        return abstain("unsupported VEX memory-write operations exist in the sensitive function",
                       caller_addr=int(caller.addr), sink_addr=int(sink.addr), evidence={
                           **base_evidence,
                           "unsupported_memory_write_sites": unsupported_memory_writes,
                       })

    if sink_calls:
        return abstain("calls inside the sensitive function are unsupported because their writes are not summarized",
                       caller_addr=int(caller.addr), sink_addr=int(sink.addr), evidence={
                           **base_evidence, "unsupported_sink_calls": sink_calls,
                       })

    entry_info = block_info.get(int(sink.addr))
    if entry_info is None:
        return abstain("the sensitive function entry block could not be recovered",
                       caller_addr=int(caller.addr), sink_addr=int(sink.addr), evidence=base_evidence)
    entry_block = entry_info["block"]
    entry_defs = entry_info["definitions"]
    frame_expr = _entry_frame_expression(entry_block, entry_defs, entry_block.vex.tyenv,
                                        project.arch.registers["rbp"][0])
    if frame_expr is None or not candidate_stores:
        try:
            optimized = infer_optimized_scalar_loop(
                project, sink, symbols_by_address,
                int(project.arch.registers["rdi"][0]),
            )
        except Exception as exc:
            return abstain(
                f"optimized VEX recovery failed: {type(exc).__name__}: {exc}",
                caller_addr=int(caller.addr), sink_addr=int(sink.addr),
                evidence=base_evidence,
            )
        if optimized.candidate is not None and optimized.relation is not None:
            symbol_name, symbol_address, capacity = optimized.candidate
            relation = optimized.relation
            optimized_method = (
                "ELF STT_OBJECT extent + VEX register-constant propagation, scalar induction, "
                "and equality-exit proof"
            )
            optimized_assumptions = (
                *assumptions,
                "the recovered optimized scalar loop has a binary-derived nonzero entry guard",
                "the prefix and loop stores are the complete dynamic write pattern for the sensitive function",
                "the loop's 64-bit equality exit is reached before unsigned counter wrap",
            )
            evidence = {
                **base_evidence,
                "object_symbol": {"name": symbol_name, "address": symbol_address,
                                  "size_bytes": capacity, "symbol_type": "STT_OBJECT"},
                "store_evidence": [
                    {"block_address": item["block_address"],
                     "instruction_address": item["instruction"]["address"] if item["instruction"] else None,
                     "instruction": item["instruction"],
                     "store_statement": item["address_expression"],
                     "vex_block": item["vex_block"],
                     "data_width_bits": item["width_bits"],
                     "role": role}
                    for role, item in (("first iteration", relation["prefix_store"]),
                                       ("loop iteration", relation["loop_store"]))
                ],
                "data_flow_relationship": relation,
                "candidate_assessments": list(optimized.assessments),
                "optimized_vex_diagnostics": optimized.diagnostics,
            }
            evidence_id = "vg-cap-" + hashlib.sha256(
                f"{digest}:{symbol_name}:{symbol_address:x}:{capacity}:{call_instruction['address']:x}:{argument_index}".encode("utf-8")
            ).hexdigest()[:20]
            return CapacityInferenceResult(
                "INFERRED", digest, metadata.file_format, metadata.architecture,
                function_name, int(caller.addr), call_name, int(sink.addr), capacity,
                evidence_id, evidence, optimized_method, optimized_assumptions,
                True, False, argument_index=argument_index,
            )
        return abstain(
            optimized.reason,
            caller_addr=int(caller.addr), sink_addr=int(sink.addr), evidence={
                **base_evidence,
                "optimized_vex_diagnostics": optimized.diagnostics,
                "candidate_assessments": list(optimized.assessments),
            },
        )

    unclassified_stores = [
        {"block_address": item["block_address"],
         "instruction_address": item["instruction_address"],
         "store_statement": str(item["statement"])}
        for item in all_store_records
        if item["symbol_base"] is None and not _is_stack_memory_address(
            item["address_expression"], frame_expr,
            int(project.arch.registers["rbp"][0]),
            int(project.arch.registers["rsp"][0]),
        )
    ]
    if unclassified_stores:
        return abstain("unclassified non-stack stores exist in the sensitive function",
                       caller_addr=int(caller.addr), sink_addr=int(sink.addr), evidence={
                           **base_evidence, "unclassified_store_sites": unclassified_stores,
                       })

    argument_register = "rdi"
    argument_offset = int(project.arch.registers[argument_register][0])
    argument_slots: list[int] = []
    zero_slots: set[int] = set()
    for statement in entry_block.vex.statements:
        if not isinstance(statement, pyvex.stmt.Store):
            continue
        slot = _stack_slot(statement.addr, entry_defs, entry_block.vex.tyenv,
                           frame_expr, int(project.arch.registers["rbp"][0]))
        if slot is None:
            continue
        value = _resolve_expr(statement.data, entry_defs, entry_block.vex.tyenv)
        if value == ("get", argument_offset, 64):
            argument_slots.append(slot)
        if value == ("const", 0, 64):
            zero_slots.add(slot)
    if len(set(argument_slots)) != 1:
        return abstain("the first sink argument is not uniquely spilled to a recovered stack slot",
                       caller_addr=int(caller.addr), sink_addr=int(sink.addr), evidence=base_evidence)
    argument_slot = argument_slots[0]

    related: list[tuple[tuple[str, int, int], dict[str, Any]]] = []
    rejected: list[dict[str, Any]] = []
    for symbol, stores in candidate_stores.items():
        if len(stores) != 1:
            rejected.append({"object_symbol": symbol[0], "reason": "object has multiple store sites"})
            continue
        store = stores[0]
        relation, relation_reason = _verify_argument_bounded_store(
            store, block_info, entry_block, frame_expr,
            int(project.arch.registers["rbp"][0]), argument_slot, zero_slots,
        )
        if relation is None:
            rejected.append({"object_symbol": symbol[0], "reason": relation_reason})
        else:
            related.append((symbol, relation))

    if len(related) != 1:
        reason = ("no object store was proven to be indexed by the sink argument's supported loop"
                  if not related else
                  f"multiple object extents are related to the sink argument; ambiguous candidates: {len(related)}")
        return abstain(reason, caller_addr=int(caller.addr), sink_addr=int(sink.addr), evidence={
            **base_evidence,
            "candidate_assessments": rejected + [
                {"object_symbol": item[0][0], "relation": item[1]} for item in related
            ],
        })

    (symbol_name, symbol_address, capacity), relation = related[0]
    evidence = {
        **base_evidence,
        "sink_argument": {"index": argument_index, "abi_register": argument_register,
                          "width_bits": 64, "stack_slot": relation["argument_stack_slot"]},
        "object_symbol": {"name": symbol_name, "address": symbol_address,
                          "size_bytes": capacity, "symbol_type": "STT_OBJECT"},
        "store_evidence": [{
            "block_address": relation["store_block_address"],
            "instruction_address": (relation["store_instruction"]["address"]
                                    if relation["store_instruction"] else None),
            "instruction": relation["store_instruction"],
            "store_statement": relation["store_address_vex"],
            "vex_block": relation["store_vex_block"],
            "data_width_bits": relation["store_width_bits"],
        }],
        "data_flow_relationship": relation,
        "candidate_assessments": rejected,
        "analysis": "CFGFast + VEX stack-slot, unsigned-loop, unit-stride, and byte-store pattern match",
    }
    evidence_id = "vg-cap-" + hashlib.sha256(
        f"{digest}:{symbol_name}:{symbol_address:x}:{capacity}:{call_instruction['address']:x}:{argument_index}".encode("utf-8")
    ).hexdigest()[:20]
    return CapacityInferenceResult(
        "INFERRED", digest, metadata.file_format, metadata.architecture,
        function_name, int(caller.addr), call_name, int(sink.addr), capacity,
        evidence_id, evidence, method, assumptions, True, False,
        argument_index=argument_index,
    )


def _verify_argument_bounded_store(
    store: dict[str, Any],
    block_info: dict[int, dict[str, Any]],
    entry_block: Any,
    frame_expr: Any,
    rbp_offset: int,
    argument_slot: int,
    zero_slots: set[int],
) -> tuple[dict[str, Any] | None, str]:
    import pyvex  # type: ignore[import-not-found]

    entry_defs = block_info[int(entry_block.addr)]["definitions"]
    if store["width_bits"] != 8:
        return None, "candidate store is not exactly one byte wide"
    body_address = int(store["block_address"])
    body_block = store["block"]
    counter_slot = _loaded_stack_slot(
        store["offset_expression"], store["definitions"], body_block.vex.tyenv,
        frame_expr, rbp_offset,
    )
    if counter_slot is None or counter_slot not in zero_slots:
        return None, "store index is not a uniquely initialized zero-based stack counter"
    if counter_slot == argument_slot:
        return None, "store index aliases the sink argument stack slot"

    # The counter and argument must remain stable except for the recognized
    # counter increment. No extra write to the argument slot is supported.
    arg_slot_writes = _stack_slot_writes(
        block_info, argument_slot, frame_expr, rbp_offset
    )
    if len(arg_slot_writes) != 1:
        return None, "sink argument stack slot is overwritten or has ambiguous definitions"

    counter_writes = _stack_slot_writes(block_info, counter_slot, frame_expr, rbp_offset)
    updates = []
    for item in counter_writes:
        expression = item["value"]
        if _is_unit_increment(expression, counter_slot, item["definitions"],
                              item["block"].vex.tyenv, frame_expr, rbp_offset):
            updates.append(item)
    if (len(updates) != 1 or updates[0]["block_address"] != body_address
            or updates[0]["statement_index"] <= store["statement_index"]):
        return None, "counter is not incremented exactly once after the object store"
    if len(counter_writes) != 2:
        return None, "loop counter has additional or ambiguous writes"
    init_writes = [item for item in counter_writes
                   if item["block_address"] == int(entry_block.addr)
                   and item["value"] == ("const", 0, 64)]
    if len(init_writes) != 1:
        return None, "loop counter does not have one entry-block zero initialization"
    if arg_slot_writes[0]["block_address"] != int(entry_block.addr):
        return None, "sink argument is not spilled in the function entry block"

    # Verify both the initial check and the loop-back check. The true edge of
    # each check enters the store block, and the body unconditionally returns
    # to the repeated check.
    body_next = _resolve_expr(body_block.vex.next, store["definitions"], body_block.vex.tyenv)
    loop_header = _const_value(body_next)
    if loop_header is None or loop_header not in block_info:
        return None, "store block has no recovered direct back edge to a loop check"
    if any(isinstance(stmt, pyvex.stmt.Exit) for stmt in body_block.vex.statements):
        return None, "conditional control flow inside the store block is unsupported"
    branch_true = _guard_edge(entry_block, entry_defs, frame_expr, rbp_offset,
                              counter_slot, argument_slot, body_address)
    if branch_true is None:
        return None, "entry block does not guard the first store with unsigned index < argument"
    loop_info = block_info[loop_header]
    loop_guard_edge = _guard_edge(loop_info["block"], loop_info["definitions"], frame_expr,
                                  rbp_offset, counter_slot, argument_slot, body_address)
    if loop_guard_edge is None:
        return None, "loop back edge does not return to an unsigned index < argument check"
    if (init_writes[0]["statement_index"] >= branch_true["statement_index"]
            or arg_slot_writes[0]["statement_index"] >= branch_true["statement_index"]):
        return None, "counter initialization and argument spill must precede the entry guard"
    if (_can_reach_block(block_info, branch_true["false_target"], body_address)
            or _can_reach_block(block_info, loop_guard_edge["false_target"], body_address)):
        return None, "the false edge of a loop guard can reach the object store"
    relation = {
        "status": "PROVEN_SUPPORTED_PATTERN",
        "argument_index": 0,
        "argument_stack_slot": f"rbp{argument_slot:+#x}",
        "counter_stack_slot": f"rbp{counter_slot:+#x}",
        "loop_condition": "unsigned counter < sink_argument",
        "initial_counter_value": 0,
        "counter_step": 1,
        "entry_argument_spill_statement": arg_slot_writes[0]["statement_index"],
        "entry_counter_init_statement": init_writes[0]["statement_index"],
        "store_width_bits": store["width_bits"],
        "store_block_address": body_address,
        "store_instruction": store["instruction"],
        "store_address_vex": store["store_statement"],
        "store_vex_block": store["vex_block"],
        "entry_guard": branch_true,
        "back_edge_target": loop_header,
        "back_edge_guard": loop_guard_edge,
        "claim": "for every reached loop iteration, the one-byte object offset is in [0, sink_argument)",
    }
    return relation, ""


def _guard_edge(
    block: Any,
    definitions: dict[int, Any],
    frame_expr: Any,
    rbp_offset: int,
    counter_slot: int,
    argument_slot: int,
    body_address: int,
) -> dict[str, Any] | None:
    import pyvex  # type: ignore[import-not-found]

    next_expr = _resolve_expr(block.vex.next, definitions, block.vex.tyenv)
    false_target = _const_value(next_expr)
    if false_target is None or false_target == body_address:
        return None
    current_instruction: int | None = None
    instruction_by_address = {int(insn.address): insn for insn in block.capstone.insns}
    for statement_index, statement in enumerate(block.vex.statements):
        if isinstance(statement, pyvex.stmt.IMark):
            current_instruction = int(statement.addr)
        elif isinstance(statement, pyvex.stmt.Exit):
            condition = _resolve_expr(statement.guard, definitions, block.vex.tyenv)
            compare = _direct_unsigned_lt(condition)
            if compare is None:
                continue
            left_slot = _loaded_stack_slot(compare[0], definitions, block.vex.tyenv,
                                           frame_expr, rbp_offset)
            right_slot = _loaded_stack_slot(compare[1], definitions, block.vex.tyenv,
                                            frame_expr, rbp_offset)
            if left_slot != counter_slot or right_slot != argument_slot:
                continue
            true_target = _const_value(_resolve_expr(statement.dst, definitions, block.vex.tyenv))
            if true_target != body_address:
                continue
            insn = instruction_by_address.get(current_instruction)
            return {
                "block_address": int(block.addr),
                "statement_index": statement_index,
                "branch_instruction": ({"address": int(insn.address), "mnemonic": insn.mnemonic,
                                        "op_str": insn.op_str,
                                        "bytes": bytes(insn.bytes).hex()} if insn else None),
                "condition": str(condition),
                "true_target": true_target,
                "false_target": false_target,
            }
    return None


def _can_reach_block(block_info: dict[int, dict[str, Any]], start: int, target: int) -> bool:
    """Conservatively check direct VEX branch/fallthrough reachability.

    An unresolved successor is treated as reachable: the inference must abstain
    when it cannot establish that a false guard edge exits the sink function.
    """
    import pyvex  # type: ignore[import-not-found]

    pending = [start]
    seen: set[int] = set()
    while pending:
        address = pending.pop()
        if address == target:
            return True
        if address in seen:
            continue
        if address not in block_info:
            return True
        seen.add(address)
        block = block_info[address]["block"]
        definitions = block_info[address]["definitions"]
        next_target = _const_value(_resolve_expr(block.vex.next, definitions, block.vex.tyenv))
        if next_target is not None:
            pending.append(next_target)
        elif str(getattr(block.vex, "jumpkind", "")) != "Ijk_Ret":
            return True
        for statement in block.vex.statements:
            if isinstance(statement, pyvex.stmt.Exit):
                branch_target = _const_value(_resolve_expr(statement.dst, definitions, block.vex.tyenv))
                if branch_target is None:
                    return True
                pending.append(branch_target)
    return False


def _is_stack_memory_address(
    expression: Any,
    frame_expr: Any,
    rbp_offset: int,
    rsp_offset: int,
) -> bool:
    """Recognize only direct frame-pointer or stack-pointer relative addresses."""
    normalized = _normalize_frame(expression, frame_expr, rbp_offset)
    if normalized == ("frame",):
        return True
    if (isinstance(normalized, tuple) and len(normalized) >= 3
            and normalized[0] == "get" and normalized[1] == rsp_offset):
        return True
    if not (isinstance(normalized, tuple) and len(normalized) == 3
            and normalized[0] == "op"
            and normalized[1] in {"Iop_Add64", "Iop_Sub64"}
            and len(normalized[2]) == 2):
        return False
    left, right = normalized[2]
    if (isinstance(left, tuple) and len(left) >= 3 and left[0] == "get"
            and left[1] == rsp_offset and right and right[0] == "const"):
        return True
    if left == ("frame",) and right and right[0] == "const":
        return True
    if (normalized[1] == "Iop_Add64" and isinstance(right, tuple)
            and len(right) >= 3 and right[0] == "get" and right[1] == rsp_offset
            and left and left[0] == "const"):
        return True
    if normalized[1] == "Iop_Add64" and right == ("frame",) and left and left[0] == "const":
        return True
    return False


def _is_unsupported_memory_write(statement: Any, pyvex: Any) -> bool:
    """Reject VEX memory effects that are not ordinary, fully inspected stores."""
    unsupported_names = {"StoreG", "CAS", "LLSC", "Dirty"}
    statement_type = getattr(pyvex.stmt, type(statement).__name__, None)
    return type(statement).__name__ in unsupported_names and statement_type is not None


def _stack_slot_writes(
    block_info: dict[int, dict[str, Any]],
    wanted_slot: int,
    frame_expr: Any,
    rbp_offset: int,
) -> list[dict[str, Any]]:
    import pyvex  # type: ignore[import-not-found]

    writes = []
    for address, info in block_info.items():
        block, definitions = info["block"], info["definitions"]
        for index, statement in enumerate(block.vex.statements):
            if not isinstance(statement, pyvex.stmt.Store):
                continue
            slot = _stack_slot(statement.addr, definitions, block.vex.tyenv,
                               frame_expr, rbp_offset)
            if slot == wanted_slot:
                writes.append({
                    "block_address": address,
                    "statement_index": index,
                    "value": _resolve_expr(statement.data, definitions, block.vex.tyenv),
                    "definitions": definitions,
                    "block": block,
                })
    return writes


def _entry_frame_expression(block: Any, definitions: dict[int, Any], tyenv: Any,
                             rbp_offset: int) -> Any | None:
    import pyvex  # type: ignore[import-not-found]

    for statement in block.vex.statements:
        if isinstance(statement, pyvex.stmt.Put) and int(statement.offset) == rbp_offset:
            return _resolve_expr(statement.data, definitions, tyenv)
    return None


def _stack_slot(expression: Any, definitions: dict[int, Any], tyenv: Any,
                frame_expr: Any, rbp_offset: int) -> int | None:
    resolved = _normalize_frame(_resolve_expr(expression, definitions, tyenv),
                                 frame_expr, rbp_offset)
    if not (isinstance(resolved, tuple) and len(resolved) == 3 and resolved[0] == "op"):
        return None
    op, children = resolved[1], resolved[2]
    if op not in {"Iop_Add64", "Iop_Sub64"} or len(children) != 2:
        return None
    left, right = children
    if left == ("frame",) and right and right[0] == "const":
        value = _signed_const(right[1], right[2])
        return value if op == "Iop_Add64" else -value
    if op == "Iop_Add64" and right == ("frame",) and left and left[0] == "const":
        return _signed_const(left[1], left[2])
    return None


def _loaded_stack_slot(expression: Any, definitions: dict[int, Any], tyenv: Any,
                       frame_expr: Any, rbp_offset: int) -> int | None:
    resolved = _resolve_expr(expression, definitions, tyenv)
    if not (isinstance(resolved, tuple) and len(resolved) == 3 and resolved[0] == "load"):
        return None
    return _stack_slot(resolved[1], {}, tyenv, frame_expr, rbp_offset)


def _is_unit_increment(expression: Any, counter_slot: int, definitions: dict[int, Any],
                       tyenv: Any, frame_expr: Any, rbp_offset: int) -> bool:
    if not (isinstance(expression, tuple) and len(expression) == 3 and expression[0] == "op"
            and expression[1] == "Iop_Add64" and len(expression[2]) == 2):
        return False
    left, right = expression[2]
    candidates = ((left, right), (right, left))
    for load_expr, const_expr in candidates:
        if not (isinstance(const_expr, tuple) and const_expr[:2] == ("const", 1)):
            continue
        if _loaded_stack_slot(load_expr, definitions, tyenv, frame_expr, rbp_offset) == counter_slot:
            return True
    return False


def _direct_unsigned_lt(expression: Any) -> tuple[Any, Any] | None:
    """Accept only width/boolean casts directly around an unsigned less-than.

    A comparison nested in an AND/OR or another predicate is insufficient:
    the taken edge would not necessarily imply ``index < argument``.
    """
    current = expression
    while (isinstance(current, tuple) and len(current) == 3 and current[0] == "op"
           and current[1] in {"Iop_64to1", "Iop_1Uto64"} and len(current[2]) == 1):
        current = current[2][0]
    if not (isinstance(current, tuple) and len(current) == 3 and current[0] == "op"
            and current[1] == "Iop_CmpLT64U" and len(current[2]) == 2):
        return None
    return current[2][0], current[2][1]


def _global_store_address(expression: Any, symbol_addresses: set[int]) -> tuple[int | None, Any]:
    if (isinstance(expression, tuple) and len(expression) >= 2
            and expression[0] == "const" and int(expression[1]) in symbol_addresses):
        return int(expression[1]), ("const", 0, int(expression[2]) if len(expression) > 2 else 64)
    if not (isinstance(expression, tuple) and len(expression) == 3 and expression[0] == "op"
            and expression[1] == "Iop_Add64" and len(expression[2]) == 2):
        return None, None
    left, right = expression[2]
    for base, offset in ((left, right), (right, left)):
        if isinstance(base, tuple) and len(base) >= 2 and base[0] == "const" and int(base[1]) in symbol_addresses:
            return int(base[1]), offset
    return None, None


def _normalize_frame(expression: Any, frame_expr: Any, rbp_offset: int) -> Any:
    if expression == frame_expr:
        return ("frame",)
    if isinstance(expression, tuple):
        if len(expression) >= 3 and expression[0] == "get" and expression[1] == rbp_offset:
            return ("frame",)
        return tuple(_normalize_frame(item, frame_expr, rbp_offset) for item in expression)
    return expression


def _resolve_expr(expression: Any, definitions: dict[int, Any], tyenv: Any,
                  seen: frozenset[int] = frozenset()) -> Any:
    import pyvex  # type: ignore[import-not-found]

    if isinstance(expression, tuple):
        return expression
    if hasattr(expression, "value") and not hasattr(expression, "op"):
        return ("const", int(expression.value), 64)
    if isinstance(expression, pyvex.expr.RdTmp):
        if expression.tmp in seen or expression.tmp not in definitions:
            return ("tmp", int(expression.tmp))
        return _resolve_expr(definitions[expression.tmp], definitions, tyenv,
                             seen | {int(expression.tmp)})
    if isinstance(expression, pyvex.expr.Const):
        return ("const", int(expression.con.value), int(expression.result_size(tyenv)))
    if isinstance(expression, pyvex.expr.Get):
        return ("get", int(expression.offset), int(expression.result_size(tyenv)))
    if isinstance(expression, pyvex.expr.Load):
        return ("load", _resolve_expr(expression.addr, definitions, tyenv, seen), str(expression.ty))
    op = getattr(expression, "op", None)
    if op is not None:
        children = getattr(expression, "child_expressions", ()) or ()
        return ("op", str(op), tuple(_resolve_expr(child, definitions, tyenv, seen) for child in children))
    return ("unknown", type(expression).__name__, str(expression))


def _signed_const(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    return value - (1 << width) if value & sign else value


def _const_value(expression: Any) -> int | None:
    if isinstance(expression, tuple) and len(expression) >= 2 and expression[0] == "const":
        return int(expression[1])
    return None


def _direct_call_instruction(project: Any, block_address: int, sink_address: int) -> dict[str, Any] | None:
    try:
        block = project.factory.block(block_address)
    except Exception:
        return None
    matches = []
    for instruction in block.capstone.insns:
        if not instruction.mnemonic.lower().startswith("call"):
            continue
        try:
            target = int(instruction.op_str.split(",", 1)[0].strip(), 0)
        except (TypeError, ValueError):
            continue
        if target == sink_address:
            matches.append(instruction)
    if len(matches) != 1:
        return None
    instruction = matches[0]
    return {"address": int(instruction.address), "mnemonic": instruction.mnemonic,
            "op_str": instruction.op_str, "bytes": bytes(instruction.bytes).hex()}


def _resolve_unique(cfg: Any, name: str) -> Any | None:
    matches = [function for function in cfg.kb.functions.values() if function.name == name]
    return matches[0] if len(matches) == 1 else None


def _instruction_at(project: Any, address: int | None) -> dict[str, Any] | None:
    if address is None:
        return None
    try:
        block = project.factory.block(address)
        instruction = next((item for item in block.capstone.insns if int(item.address) == address), None)
    except Exception:
        return None
    if instruction is None:
        return None
    return {"address": int(instruction.address), "mnemonic": instruction.mnemonic,
            "op_str": instruction.op_str, "bytes": bytes(instruction.bytes).hex()}
