"""Narrow VEX recovery for optimized scalar byte loops.

This module deliberately supports one optimized shape: a nonzero input guard,
an initial byte store at object offset zero, a 64-bit induction register set to
one, then a loop which stores at ``object[index]``, increments by one, and
exits when the incremented value equals the original length.  It does not try
to interpret vectorized or unrolled loops.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class OptimizedLoopRecovery:
    candidate: tuple[str, int, int] | None
    relation: dict[str, Any] | None
    reason: str
    assessments: tuple[dict[str, Any], ...]
    diagnostics: dict[str, Any]


_TOP = object()


def infer_optimized_scalar_loop(
    project: Any,
    function: Any,
    symbols_by_address: dict[int, list[tuple[str, int, int]]],
    argument_register_offset: int,
) -> OptimizedLoopRecovery:
    """Recover the supported register-induction loop from target VEX.

    The data-flow proof requires a uniquely identified static object, exactly
    one zero-offset prefix store, a register-indexed one-byte loop store, a
    unit increment, an equality exit tied to the ABI argument, and a binary-
    derived nonzero entry check.  Any unresolved memory write or extra
    argument-indexed object makes the result inconclusive.
    """
    import pyvex  # type: ignore[import-not-found]

    addresses = sorted(int(item) for item in function.block_addrs_set)
    blocks = {address: project.factory.block(address) for address in addresses}
    entry = int(function.addr)
    if entry not in blocks:
        return _failure("optimized VEX function entry is not in the recovered CFG", {})

    def run(block: Any, input_constants: dict[int, int]) -> dict[str, Any]:
        registers = dict(input_constants)
        temporaries: dict[int, Any] = {}
        stores: list[dict[str, Any]] = []
        puts: list[dict[str, Any]] = []
        exits: list[dict[str, Any]] = []
        instruction_address: int | None = None

        def resolve(expression: Any, seen: frozenset[int] = frozenset()) -> Any:
            if isinstance(expression, pyvex.expr.RdTmp):
                index = int(expression.tmp)
                if index in seen:
                    return ("tmp", index)
                return temporaries.get(index, ("tmp", index))
            if isinstance(expression, pyvex.expr.Const):
                return ("const", int(expression.con.value),
                        int(expression.result_size(block.vex.tyenv)))
            if hasattr(expression, "value") and not hasattr(expression, "op"):
                return ("const", int(expression.value), 64)
            if isinstance(expression, pyvex.expr.Get):
                offset = int(expression.offset)
                width = int(expression.result_size(block.vex.tyenv))
                if offset in registers:
                    return ("const", registers[offset], width)
                return ("get", offset, width)
            if isinstance(expression, pyvex.expr.Load):
                return ("load", resolve(expression.addr), str(expression.ty))
            operation = getattr(expression, "op", None)
            if operation is not None:
                children = getattr(expression, "child_expressions", ()) or ()
                return ("op", str(operation), tuple(resolve(child) for child in children))
            if isinstance(expression, tuple):
                return expression
            return ("unknown", type(expression).__name__, str(expression))

        for index, statement in enumerate(block.vex.statements):
            kind = type(statement).__name__
            if kind == "IMark":
                instruction_address = int(statement.addr)
            elif kind == "WrTmp":
                temporaries[int(statement.tmp)] = resolve(statement.data)
            elif kind == "Put":
                value = resolve(statement.data)
                offset = int(statement.offset)
                puts.append({"statement_index": index, "offset": offset, "value": value,
                             "instruction_address": instruction_address})
                if isinstance(value, tuple) and len(value) >= 2 and value[0] == "const":
                    registers[offset] = int(value[1])
                else:
                    registers.pop(offset, None)
            elif kind == "Store":
                stores.append({
                    "block_address": int(block.addr),
                    "statement_index": index,
                    "instruction_address": instruction_address,
                    "address": resolve(statement.addr),
                    "data": resolve(statement.data),
                    "width_bits": int(statement.data.result_size(block.vex.tyenv)),
                })
            elif kind == "Exit":
                exits.append({
                    "block_address": int(block.addr),
                    "statement_index": index,
                    "instruction_address": instruction_address,
                    "condition": resolve(statement.guard),
                    "true_target": _const(resolve(statement.dst)),
                })

        return {
            "block": block,
            "out_constants": registers,
            "stores": stores,
            "puts": puts,
            "exits": exits,
            "next_target": _const(resolve(block.vex.next)),
            "vex": str(block.vex),
        }

    # Build a conservative intraprocedural CFG from VEX direct successors.
    initial_runs = {address: run(block, {}) for address, block in blocks.items()}
    successors: dict[int, set[int]] = {address: set() for address in addresses}
    for address, result in initial_runs.items():
        targets = [result["next_target"],
                   *(item["true_target"] for item in result["exits"])]
        successors[address].update(int(target) for target in targets
                                   if target is not None and int(target) in blocks)
    reachable = _reachable(entry, successors)
    predecessors: dict[int, set[int]] = {address: set() for address in reachable}
    for source in reachable:
        for target in successors[source]:
            if target in predecessors:
                predecessors[target].add(source)

    # Constant propagation is used only to recover object-base registers.
    # Unknown and nonconstant register values are never guessed.
    out_constants: dict[int, dict[int, int] | None] = {address: None for address in reachable}
    for _ in range(max(8, len(reachable) * 4)):
        changed = False
        for address in sorted(reachable):
            if address == entry:
                input_constants: dict[int, int] = {}
            else:
                known_predecessors = [out_constants[p] for p in predecessors[address]
                                      if out_constants[p] is not None]
                input_constants = _meet_constants(known_predecessors)
            result = run(blocks[address], input_constants)
            output = result["out_constants"]
            if output != out_constants[address]:
                out_constants[address] = output
                changed = True
        if not changed:
            break

    final_runs: dict[int, dict[str, Any]] = {}
    for address in reachable:
        if address == entry:
            input_constants = {}
        else:
            input_constants = _meet_constants(
                [out_constants[p] for p in predecessors[address]
                 if out_constants[p] is not None]
            )
        final_runs[address] = run(blocks[address], input_constants)

    object_addresses = set(symbols_by_address)
    all_stores: list[dict[str, Any]] = []
    for address, result in final_runs.items():
        for store in result["stores"]:
            base, offset = _global_store(store["address"], object_addresses)
            all_stores.append({**store, "symbol_base": base, "offset": offset,
                               "block_vex": result["vex"]})

    dynamic_candidates: set[tuple[str, int, int]] = set()
    candidate_sites: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
    for store in all_stores:
        base = store["symbol_base"]
        offset = store["offset"]
        if base is None or not _is_register(offset) or store["width_bits"] != 8:
            continue
        for symbol in symbols_by_address[base]:
            dynamic_candidates.add(symbol)
            candidate_sites.setdefault(symbol, []).append(store)

    diagnostics = {
        "function_address": entry,
        "reachable_block_addresses": sorted(reachable),
        "block_instruction_sequences": [
            {"block_address": address,
             "instructions": [
                 {"address": int(item.address), "mnemonic": item.mnemonic,
                  "op_str": item.op_str}
                 for item in final_runs[address]["block"].capstone.insns
             ]}
            for address in sorted(reachable)
        ],
        "block_control_evidence": [
            {"block_address": address,
             "next_target": final_runs[address]["next_target"],
             "register_writes": [
                 {"statement_index": item["statement_index"], "register_offset": item["offset"],
                  "value": repr(item["value"])}
                 for item in final_runs[address]["puts"]
             ],
             "branches": [
                 {"statement_index": item["statement_index"],
                  "instruction_address": item["instruction_address"],
                  "condition": repr(item["condition"]), "true_target": item["true_target"]}
                 for item in final_runs[address]["exits"]
             ]}
            for address in sorted(reachable)
        ],
        "symbol_object_stores": [
            {"block_address": item["block_address"],
             "instruction_address": item["instruction_address"],
             "instruction": _instruction(final_runs[item["block_address"]]["block"],
                                          item["instruction_address"]),
             "symbol_base": item["symbol_base"],
             "offset_expression": item["offset"],
             "width_bits": item["width_bits"]}
            for item in all_stores if item["symbol_base"] is not None
        ],
        "unresolved_store_evidence": [
            {"block_address": item["block_address"],
             "instruction_address": item["instruction_address"],
             "instruction": _instruction(final_runs[item["block_address"]]["block"],
                                          item["instruction_address"]),
             "address_expression": repr(item["address"]),
             "width_bits": item["width_bits"]}
            for item in all_stores if item["symbol_base"] is None
        ],
        "dynamic_candidate_count": len(dynamic_candidates),
    }

    supported: list[tuple[tuple[str, int, int], dict[str, Any]]] = []
    assessments: list[dict[str, Any]] = []
    for symbol in sorted(dynamic_candidates):
        relation, reason = _prove_scalar_relation(
            symbol, candidate_sites[symbol], all_stores, final_runs,
            successors, predecessors, entry, argument_register_offset,
        )
        if relation is None:
            assessments.append({"object_symbol": symbol[0], "reason": reason})
        else:
            supported.append((symbol, relation))

    if len(supported) > 1:
        return OptimizedLoopRecovery(
            None, None,
            f"multiple optimized register-indexed object relationships are ambiguous ({len(supported)} candidates)",
            tuple(assessments), diagnostics,
        )
    if not supported:
        if assessments:
            assessment_reasons = {item["reason"] for item in assessments}
            if assessment_reasons == {"object has multiple register-indexed store instructions"}:
                reason = ("optimized scalar recovery abstained because the object has multiple "
                          "register-indexed store instructions; unrolled/chunked loops are unsupported")
            else:
                reason = "optimized register-indexed stores did not satisfy the supported scalar loop and guard proof"
        elif any(item["symbol_base"] is not None for item in all_stores):
            reason = "optimized stores are constant-offset or chunked; no supported register-indexed scalar loop was recovered"
        else:
            reason = "optimized VEX did not expose a supported object-based scalar store"
        return OptimizedLoopRecovery(None, None, reason, tuple(assessments), diagnostics)

    symbol, relation = supported[0]
    # Every other global store must be demonstrably fixed within its own
    # object. Dynamic writes to another object or unresolved writes abstain.
    for store in all_stores:
        if store["symbol_base"] is None:
            return OptimizedLoopRecovery(
                None, None, "optimized function contains an unresolved non-object store",
                tuple(assessments), diagnostics,
            )
        offset = store["offset"]
        if _is_register(offset):
            loop_instruction = relation["loop_store"]["instruction"]
            if (store["symbol_base"] != symbol[1]
                    or store["block_address"] != relation["store_block_address"]
                    or loop_instruction is None
                    or store["instruction_address"] != loop_instruction["address"]):
                return OptimizedLoopRecovery(
                    None, None, "additional dynamic object stores prevent unique sink-object attribution",
                    tuple(assessments), diagnostics,
                )
            continue
        fixed_offset = _const(offset)
        sizes = [item[2] for item in symbols_by_address[store["symbol_base"]]]
        if fixed_offset is None or not sizes or fixed_offset < 0 or fixed_offset + store["width_bits"] // 8 > min(sizes):
            return OptimizedLoopRecovery(
                None, None, "a constant object store exceeds or cannot be checked against its symbol extent",
                tuple(assessments), diagnostics,
            )

    evidence = {
        "status": "PROVEN_SUPPORTED_OPTIMIZED_SCALAR_PATTERN",
        "analysis": "CFGFast + VEX register constant propagation + scalar induction and equality-exit proof",
        "argument_index": 0,
        "argument_register": "rdi",
        "argument_width_bits": 64,
        "index_register_offset": relation["index_register_offset"],
        "index_width_bits": relation["index_width_bits"],
        "index_signedness": "64-bit bit-vector; the recovered exit relation uses equality, not signed ordering",
        "initial_store_offset": 0,
        "counter_value_after_prefix_store": 1,
        "counter_step": 1,
        "loop_exit_condition": "equality: incremented_index == sink_argument",
        "entry_guard": relation["entry_guard"],
        "prefix_exit_guard": relation["prefix_exit_guard"],
        "loop_exit_guard": relation["loop_exit_guard"],
        "prefix_store": relation["prefix_store"],
        "loop_store": relation["loop_store"],
        "preheader_block_address": relation["preheader_block_address"],
        "store_block_address": relation["store_block_address"],
        "back_edge_target": relation["back_edge_target"],
        "fixed_object_store_evidence": [
            {"block_address": item["block_address"],
             "instruction_address": item["instruction_address"],
             "symbol_base": item["symbol_base"],
             "offset_expression": item["offset"],
             "width_bits": item["width_bits"]}
            for item in all_stores
            if item["symbol_base"] is not None and not _is_register(item["offset"])
            and not (item["symbol_base"] == symbol[1]
                     and item["block_address"] == relation["preheader_block_address"]
                     and item["instruction_address"] == relation["prefix_store"]["instruction"]["address"])
        ],
        "claim": "for nonzero 64-bit sink arguments, the prefix writes object[0], then each loop write uses indices 1 through argument-1; equality exits before a wrapped increment can occur",
    }
    return OptimizedLoopRecovery(symbol, evidence, "", tuple(assessments), diagnostics)


def _prove_scalar_relation(
    symbol: tuple[str, int, int],
    dynamic_stores: list[dict[str, Any]],
    all_stores: list[dict[str, Any]],
    runs: dict[int, dict[str, Any]],
    successors: dict[int, set[int]],
    predecessors: dict[int, set[int]],
    entry: int,
    argument_register_offset: int,
) -> tuple[dict[str, Any] | None, str]:
    if len(dynamic_stores) != 1:
        return None, "object has multiple register-indexed store instructions"
    loop_store = dynamic_stores[0]
    body = int(loop_store["block_address"])
    index_offset = int(loop_store["offset"][1])
    if loop_store["width_bits"] != 8 or runs[body]["next_target"] != body:
        return None, "register-indexed store is not a one-byte self-loop store"
    if predecessors.get(body, set()) == {body}:
        return None, "loop store has no unique first-iteration predecessor"
    preheaders = predecessors.get(body, set()) - {body}
    if len(preheaders) != 1:
        return None, "loop store does not have one unique preheader"
    preheader = next(iter(preheaders))
    if runs[preheader]["next_target"] != body:
        return None, "preheader does not flow directly to the scalar loop"

    prefix_stores = [item for item in all_stores
                     if item["symbol_base"] == symbol[1]
                     and item["block_address"] == preheader
                     and _const(item["offset"]) == 0
                     and item["width_bits"] == 8]
    if len(prefix_stores) != 1:
        return None, "unique zero-offset first-iteration byte store was not recovered"
    prefix_store = prefix_stores[0]

    increments = [item for item in runs[body]["puts"]
                  if item["offset"] == index_offset and _is_unit_increment(item["value"], index_offset)]
    if len(increments) != 1 or increments[0]["statement_index"] <= loop_store["statement_index"]:
        return None, "loop index is not incremented exactly once after its byte store"
    increment = increments[0]

    arg_get = ("get", argument_register_offset, 64)
    next_index = ("op", "Iop_Add64", (("get", index_offset, 64), ("const", 1, 64)))
    loop_exits = [item for item in runs[body]["exits"]
                  if item["statement_index"] > increment["statement_index"]
                  and _is_equality(item["condition"], arg_get, next_index)]
    loop_exits = [item for item in loop_exits
                  if not _can_reach(item["true_target"], body, successors)]
    if len(loop_exits) != 1:
        return None, "loop exit is not a unique equality check between argument and incremented index"
    loop_exit = loop_exits[0]

    prefix_ones = [item for item in runs[preheader]["puts"]
                   if item["offset"] == index_offset and _const(item["value"]) == 1
                   and item["statement_index"] > prefix_store["statement_index"]]
    if len(prefix_ones) != 1:
        return None, "the first store is not followed by a recovered index value of one"
    prefix_one = prefix_ones[0]
    prefix_exits = [item for item in runs[preheader]["exits"]
                    if item["statement_index"] > prefix_one["statement_index"]
                    and _is_equality(item["condition"], arg_get, ("const", 1, 64))]
    prefix_exits = [item for item in prefix_exits
                    if not _can_reach(item["true_target"], body, successors)]
    if len(prefix_exits) != 1:
        return None, "the prefix path does not exit when the first increment equals the argument"
    prefix_exit = prefix_exits[0]

    if predecessors.get(body, set()) != {preheader, body}:
        return None, "the scalar loop has additional or unresolved incoming paths"
    entry_guards = [item for item in runs[entry]["exits"]
                    if _is_equality(item["condition"], arg_get, ("const", 0, 64))
                    and item["true_target"] is not None
                    and not _can_reach(item["true_target"], preheader, successors)
                    and not _can_reach(item["true_target"], body, successors)]
    if runs[entry]["next_target"] != preheader or len(entry_guards) != 1:
        return None, "a binary-derived nonzero argument guard does not dominate the first store"
    entry_guard = entry_guards[0]
    if prefix_store["statement_index"] >= prefix_one["statement_index"]:
        return None, "the prefix index update does not follow the zero-offset first store"
    if loop_exit["true_target"] is None or prefix_exit["true_target"] is None:
        return None, "a loop exit target could not be recovered"

    def branch_evidence(item: dict[str, Any]) -> dict[str, Any]:
        instruction = _instruction(runs[item["block_address"]]["block"], item["instruction_address"])
        return {"block_address": item["block_address"],
                "statement_index": item["statement_index"],
                "instruction": instruction,
                "condition": repr(item["condition"]),
                "true_target": item["true_target"],
                "false_target": runs[item["block_address"]]["next_target"]}

    return {
        "index_register_offset": index_offset,
        "index_width_bits": 64,
        "entry_guard": branch_evidence(entry_guard),
        "prefix_exit_guard": branch_evidence(prefix_exit),
        "loop_exit_guard": branch_evidence(loop_exit),
        "prefix_store": _store_evidence(prefix_store, runs[preheader]["block"]),
        "loop_store": _store_evidence(loop_store, runs[body]["block"]),
        "preheader_block_address": preheader,
        "store_block_address": body,
        "back_edge_target": runs[body]["next_target"],
    }, ""


def _store_evidence(store: dict[str, Any], block: Any) -> dict[str, Any]:
    return {"block_address": store["block_address"],
            "statement_index": store["statement_index"],
            "instruction": _instruction(block, store["instruction_address"]),
            "address_expression": repr(store["address"]),
            "data_expression": repr(store["data"]),
            "width_bits": store["width_bits"],
            "vex_block": store["block_vex"]}


def _instruction(block: Any, address: int | None) -> dict[str, Any] | None:
    if address is None:
        return None
    for item in block.capstone.insns:
        if int(item.address) == int(address):
            return {"address": int(item.address), "mnemonic": item.mnemonic,
                    "op_str": item.op_str, "bytes": bytes(item.bytes).hex()}
    return None


def _global_store(expression: Any, object_addresses: set[int]) -> tuple[int | None, Any]:
    if isinstance(expression, tuple) and len(expression) >= 2 and expression[0] == "const":
        address = int(expression[1])
        if address in object_addresses:
            return address, ("const", 0, int(expression[2]) if len(expression) > 2 else 64)
    if not (isinstance(expression, tuple) and len(expression) == 3
            and expression[0] == "op" and expression[1] == "Iop_Add64"
            and len(expression[2]) == 2):
        return None, None
    left, right = expression[2]
    for base, offset in ((left, right), (right, left)):
        if (isinstance(base, tuple) and len(base) >= 2 and base[0] == "const"
                and int(base[1]) in object_addresses):
            return int(base[1]), offset
    return None, None


def _is_register(expression: Any) -> bool:
    return isinstance(expression, tuple) and len(expression) == 3 and expression[0] == "get"


def _const(expression: Any) -> int | None:
    if isinstance(expression, tuple) and len(expression) >= 2 and expression[0] == "const":
        return int(expression[1])
    return None


def _is_unit_increment(expression: Any, register_offset: int) -> bool:
    return expression == ("op", "Iop_Add64",
                          (("get", register_offset, 64), ("const", 1, 64)))


def _is_equality(expression: Any, left: Any, right: Any) -> bool:
    while (isinstance(expression, tuple) and len(expression) == 3
           and expression[0] == "op" and expression[1] in {"Iop_64to1", "Iop_1Uto64"}
           and len(expression[2]) == 1):
        expression = expression[2][0]
    if not (isinstance(expression, tuple) and len(expression) == 3
            and expression[0] == "op" and expression[1] in {"Iop_CmpEQ64"}
            and len(expression[2]) == 2):
        return False
    return expression[2] in ((left, right), (right, left))


def _meet_constants(inputs: list[dict[int, int] | None]) -> dict[int, int]:
    if not inputs:
        return {}
    result: dict[int, int] = {}
    keys = set().union(*(set(item) for item in inputs))
    for key in keys:
        values = [item.get(key, _TOP) for item in inputs]
        known = [value for value in values if value is not _TOP]
        if known and all(isinstance(value, int) and value == known[0] for value in known) and len(known) == len(values):
            result[key] = int(known[0])
    return result


def _reachable(start: int, successors: dict[int, set[int]]) -> set[int]:
    pending = [start]
    seen: set[int] = set()
    while pending:
        address = pending.pop()
        if address in seen or address not in successors:
            continue
        seen.add(address)
        pending.extend(successors[address] - seen)
    return seen


def _can_reach(start: int | None, target: int, successors: dict[int, set[int]]) -> bool:
    if start is None:
        return True
    return target in _reachable(int(start), successors)


def _failure(reason: str, diagnostics: dict[str, Any]) -> OptimizedLoopRecovery:
    return OptimizedLoopRecovery(None, None, reason, (), diagnostics)
