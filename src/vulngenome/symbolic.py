"""angr symbolic tracing at a named sensitive call site.

The manual API retains an explicitly labeled capacity annotation workflow. The
inference API accepts no capacity and requires separate ELF/VEX evidence before
it invokes the call-site solver.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
from pathlib import Path
from typing import Any

from .capacity import infer_capacity_from_binary


@dataclass(frozen=True)
class CallSiteResult:
    status: str
    binary_sha256: str
    function: str
    sensitive_call: str
    argument_width: int | None
    capacity: int | None
    capacity_provenance: str
    path_constraints: tuple[str, ...]
    query_smt2: str
    solver_result: str
    solver_version: str | None
    timeout_ms: int
    counterexample: str | None = None
    reason: str | None = None
    coverage_note: str = "only the paths explored to the named call site are considered"
    paths_to_call: int = 0
    exploration_steps: int = 0
    exploration_complete: bool = False
    capacity_evidence: dict[str, Any] | None = None
    capacity_source: str = "supplied"
    analysis_mode: str = "manual_annotation"
    path_evidence: tuple[dict[str, Any], ...] = ()
    invariant_evidence: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def verify_unsigned_argument_at_call(
    binary_path: str | Path,
    *,
    function_name: str,
    call_name: str,
    capacity: int,
    capacity_provenance: str,
    argument_index: int = 0,
    timeout_ms: int = 5000,
    max_steps: int = 100,
) -> CallSiteResult:
    """Check `argument <= capacity` on paths to a named call in a binary.

    The query is `path_constraints AND argument > capacity`. A satisfiable
    query is a potential violation; an unsatisfiable query is scoped to this
    call site and the paths angr reached within its exploration budget.
    """
    import hashlib

    data = Path(binary_path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    try:
        import angr  # type: ignore[import-not-found]
        from angr import claripy  # type: ignore[import-not-found]
        import z3  # type: ignore[import-not-found]
    except ImportError as exc:
        return CallSiteResult("INCONCLUSIVE", digest, function_name, call_name, None, capacity,
                              capacity_provenance, (), "", "not-run", None, timeout_ms,
                              reason=f"required symbolic-analysis dependency unavailable: {exc}")

    try:
        project = angr.Project(str(Path(binary_path).resolve()), auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True, data_references=True)
    except Exception as exc:
        return CallSiteResult("ANALYSIS_ERROR", digest, function_name, call_name, None, capacity,
                              capacity_provenance, (), "", "error", z3.get_version_string(), timeout_ms,
                              reason=f"binary analysis failed: {type(exc).__name__}: {exc}")
    function = _resolve_function(cfg, function_name)
    sink = _resolve_function(cfg, call_name)
    if function is None or sink is None:
        missing = []
        for name, item in ((function_name, function), (call_name, sink)):
            if item is None:
                count = sum(candidate.name == name for candidate in cfg.kb.functions.values())
                missing.append(f"{name} ({'missing' if count == 0 else f'ambiguous: {count} matches'})")
        return CallSiteResult("INCONCLUSIVE", digest, function_name, call_name, None, capacity,
                              capacity_provenance, (), "", "not-run", z3.get_version_string(), timeout_ms,
                              reason=f"unresolved function symbol(s): {', '.join(missing)}")
    call_site_addresses = tuple(
        address for call_site in function.get_call_sites() or ()
        if function.get_call_target(call_site) == sink.addr
        for address in _direct_call_instruction_addresses(project, int(call_site), int(sink.addr))
    )
    width = project.arch.bits
    if (project.arch.name != "AMD64"
            or project.loader.main_object.os not in ("linux", "UNIX - System V")):
        return CallSiteResult("INCONCLUSIVE", digest, function_name, call_name, width, capacity,
                              capacity_provenance, (), "", "not-run", z3.get_version_string(), timeout_ms,
                              reason="the current call-argument adapter supports Linux AMD64 binaries only")
    if argument_index != 0:
        return CallSiteResult("INCONCLUSIVE", digest, function_name, call_name, width, capacity,
                              capacity_provenance, (), "", "not-run", z3.get_version_string(), timeout_ms,
                              reason="only the first integer argument is currently supported")
    if not isinstance(capacity, int) or isinstance(capacity, bool) or not 0 <= capacity < (1 << width):
        return CallSiteResult("INCONCLUSIVE", digest, function_name, call_name, width, capacity,
                              capacity_provenance, (), "", "not-run", z3.get_version_string(), timeout_ms,
                              reason=f"capacity does not fit the {width}-bit target width")
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or timeout_ms <= 0:
        return CallSiteResult("ANALYSIS_ERROR", digest, function_name, call_name, width, capacity,
                              capacity_provenance, (), "", "not-run", z3.get_version_string(), timeout_ms,
                              reason="timeout_ms must be a positive integer")

    captures: list[tuple[Any, Any, tuple[int, ...]]] = []

    class CaptureCall(angr.SimProcedure):
        def run(self, value):  # type: ignore[no-untyped-def]
            captures.append((self.state.copy(), value, _history_block_addresses(self.state)))
            return claripy.BVV(0, self.state.arch.bits)

    try:
        project.hook(sink.addr, CaptureCall())
        argument = claripy.BVS("vg_length", width)
        # Use angr's Rust-backed ASTs and initialize the Linux AMD64 first
        # integer argument directly; call_state's type inference treats these
        # ASTs as Python FFI values in angr 10.
        state = project.factory.call_state(function.addr)
        state.regs.rdi = argument
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        manager = project.factory.simgr(state)
    except Exception as exc:
        return CallSiteResult("ANALYSIS_ERROR", digest, function_name, call_name, width, capacity,
                              capacity_provenance, (), "", "error", z3.get_version_string(), timeout_ms,
                              reason=f"symbolic call state setup failed: {type(exc).__name__}: {exc}")
    steps = 0
    state_limit_exceeded = False
    try:
        while steps < max_steps and manager.active:
            manager.step()
            steps += 1
            if len(manager.active) > 128:
                state_limit_exceeded = True
                break
    except Exception as exc:
        return CallSiteResult("ANALYSIS_ERROR", digest, function_name, call_name, width, capacity,
                              capacity_provenance, (), "", "error", z3.get_version_string(), timeout_ms,
                              reason=f"symbolic exploration failed: {type(exc).__name__}: {exc}",
                              paths_to_call=len(captures), exploration_steps=steps)
    errored_count = len(getattr(manager, "errored", ()))
    unconstrained_count = len(manager.stashes.get("unconstrained", ()))
    complete = not manager.active and errored_count == 0 and unconstrained_count == 0 and not state_limit_exceeded
    if not captures:
        reason = f"no path reached {call_name} within {steps} steps"
        if state_limit_exceeded:
            reason = "active-state limit exceeded before reaching the call"
        elif errored_count or unconstrained_count:
            reason = f"exploration had {errored_count} errored and {unconstrained_count} unconstrained states"
        return CallSiteResult("INCONCLUSIVE", digest, function_name, call_name, width, capacity,
                              capacity_provenance, (), "", "not-run", z3.get_version_string(), timeout_ms,
                              reason=reason,
                              exploration_steps=steps, exploration_complete=complete)

    try:
        path_terms: list[str] = []
        query_expressions: list[Any] = []
        path_strings = []
        path_evidence: list[dict[str, Any]] = []
        for index, (observed_state, observed_argument, block_addresses) in enumerate(captures):
            if observed_argument.size() != width:
                return CallSiteResult("INCONCLUSIVE", digest, function_name, call_name, width, capacity,
                                      capacity_provenance, tuple(path_strings), "", "not-run", z3.get_version_string(), timeout_ms,
                                      reason="sensitive-call argument width differs from the annotated function argument",
                                      paths_to_call=len(captures), exploration_steps=steps,
                                      exploration_complete=complete)
            if not any(name.startswith("vg_length_") for name in observed_argument.variables):
                return CallSiteResult("INCONCLUSIVE", digest, function_name, call_name, width, capacity,
                                      capacity_provenance, tuple(path_strings), "", "not-run", z3.get_version_string(), timeout_ms,
                                      reason="sensitive-call length could not be tied to the annotated input argument",
                                      paths_to_call=len(captures), exploration_steps=steps,
                                      exploration_complete=complete)
            current_constraints = list(observed_state.solver.constraints)
            violation = claripy.UGT(observed_argument, claripy.BVV(capacity, width))
            path_parts = [constraint.smtlib() for constraint in current_constraints]
            path_parts.append(violation.smtlib())
            path_terms.append(f"(and {' '.join(path_parts)})" if len(path_parts) > 1 else path_parts[0])
            query_expressions.extend(current_constraints)
            query_expressions.extend((observed_argument, violation))
            path_strings.extend(f"path_{index}: {constraint.smtlib()}" for constraint in current_constraints)
            branch_sites = _branch_sites(project, block_addresses, set(function.block_addrs_set))
            path_evidence.append({
                "evidence_id": "vg-path-" + hashlib.sha256(
                    f"{digest}:{function_name}:{index}:{','.join(hex(item) for item in block_addresses)}".encode("utf-8")
                ).hexdigest()[:20],
                "binary_sha256": digest,
                "function": function_name,
                "call": call_name,
                "call_site_addresses": [hex(address) for address in call_site_addresses],
                "argument_index": argument_index,
                "argument_register": "rdi",
                "path_index": index,
                "path_block_addresses": [hex(address) for address in block_addresses],
                "branch_sites": branch_sites,
                "constraints": [constraint.smtlib() for constraint in current_constraints],
                "sink_argument_expression": observed_argument.smtlib(),
            })
        query = _smtlib_query(path_terms, query_expressions)
        z3_solver = z3.Solver()
        z3_solver.set(timeout=timeout_ms)
        assertions = z3.parse_smt2_string(query.rsplit("\n(check-sat)", 1)[0])
        z3_solver.add(*assertions)
        outcome = z3_solver.check()
        model = str(z3_solver.model()) if outcome == z3.sat else None
        unknown_reason = z3_solver.reason_unknown() if outcome == z3.unknown else None
    except Exception as exc:
        return CallSiteResult("ANALYSIS_ERROR", digest, function_name, call_name, width, capacity,
                              capacity_provenance, (), "", "error", z3.get_version_string(), timeout_ms,
                              reason=f"solver query construction/check failed: {type(exc).__name__}: {exc}",
                              paths_to_call=len(captures), exploration_steps=steps,
                              exploration_complete=complete)
    version = z3.get_version_string()
    if outcome == z3.sat:
        result = CallSiteResult("POTENTIAL_VIOLATION", digest, function_name, call_name, width, capacity,
                              capacity_provenance, tuple(path_strings), query, "sat", version, timeout_ms,
                              counterexample=model, paths_to_call=len(captures), exploration_steps=steps,
                              exploration_complete=complete)
        return replace(result, path_evidence=tuple(path_evidence))
    if outcome == z3.unsat:
        if not complete:
            reason = f"the explored paths are UNSAT, but exploration was incomplete ({steps} steps"
            if state_limit_exceeded:
                reason += ", active-state limit reached"
            if errored_count:
                reason += f", {errored_count} errored states"
            if unconstrained_count:
                reason += f", {unconstrained_count} unconstrained states"
            reason += ")"
            return CallSiteResult("INCONCLUSIVE", digest, function_name, call_name, width, capacity,
                                  capacity_provenance, tuple(path_strings), query, "unsat", version, timeout_ms,
                                  reason=reason,
                                  paths_to_call=len(captures), exploration_steps=steps,
                                  exploration_complete=False)
        result = CallSiteResult("PROPERTY_HOLDS_WITHIN_MODEL", digest, function_name, call_name, width, capacity,
                              capacity_provenance, tuple(path_strings), query, "unsat", version, timeout_ms,
                              reason=("all explored paths to this call satisfy the recorded unsigned bound; "
                                      "this is not a complete memory-safety proof"),
                              paths_to_call=len(captures), exploration_steps=steps,
                              exploration_complete=True)
        return replace(result, path_evidence=tuple(path_evidence))
    result = CallSiteResult("INCONCLUSIVE", digest, function_name, call_name, width, capacity,
                          capacity_provenance, tuple(path_strings), query, "unknown", version, timeout_ms,
                          reason=unknown_reason, paths_to_call=len(captures), exploration_steps=steps,
                          exploration_complete=complete)
    return replace(result, path_evidence=tuple(path_evidence))


def verify_unsigned_argument_at_call_inferred(
    binary_path: str | Path,
    *,
    function_name: str,
    call_name: str,
    argument_index: int = 0,
    timeout_ms: int = 5000,
    max_steps: int = 100,
) -> CallSiteResult:
    """Infer object capacity from binary evidence, then check the call argument.

    This API deliberately has no capacity parameter and never reads fixture
    contracts or experiment configuration. If evidence is missing or ambiguous,
    it returns INCONCLUSIVE without invoking the solver.
    """
    inference = infer_capacity_from_binary(
        binary_path, function_name=function_name, call_name=call_name,
        argument_index=argument_index,
    )
    if inference.status != "INFERRED" or inference.capacity is None:
        return CallSiteResult(
            "INCONCLUSIVE", inference.binary_sha256, function_name, call_name,
            None, None, "automatic binary inference", (), "", "not-run", None,
            timeout_ms, reason=inference.reason or "capacity inference did not produce a value",
            capacity_evidence=inference.to_dict(), capacity_source="unavailable",
            analysis_mode="binary_inference",
        )

    result = verify_unsigned_argument_at_call(
        binary_path, function_name=function_name, call_name=call_name,
        capacity=inference.capacity,
        capacity_provenance="inferred from ELF object extent correlated with VEX store evidence",
        argument_index=argument_index, timeout_ms=timeout_ms, max_steps=max_steps,
    )
    invariant_id = "vg-inv-" + hashlib.sha256(
        f"{inference.binary_sha256}:{function_name}:{call_name}:{inference.capacity}".encode("utf-8")
    ).hexdigest()[:20]
    invariant_evidence = {
        "evidence_id": invariant_id,
        "binary_sha256": inference.binary_sha256,
        "kind": "sensitive_call_argument_within_object_extent",
        "property": "unsigned_sensitive_call_argument <= inferred_object_extent",
        "argument_index": argument_index,
        "argument_register": "rdi",
        "program_point": {"function": function_name,
                           "function_address": inference.function_address,
                           "sensitive_call": call_name,
                           "call_address": inference.evidence.get("call_site", {}).get("address")},
        "evidence_refs": [inference.evidence_id,
                           *[item["evidence_id"] for item in result.path_evidence]],
        "analysis_method": "angr symbolic execution to call site plus ELF/VEX object extent recovery",
        "assumptions": [
            *inference.assumptions,
            "the first integer ABI argument is the byte count relevant to this sensitive operation",
            "the solver result is scoped to explored paths and the recorded finite-width model",
        ],
        "inferred": True,
        "supplied": False,
    }
    return replace(result, capacity_evidence=inference.to_dict(),
                   capacity_source="inferred", analysis_mode="binary_inference",
                   invariant_evidence=invariant_evidence)


def _resolve_function(cfg: Any, name: str) -> Any | None:
    functions = cfg.kb.functions
    by_name = [function for function in functions.values() if function.name == name]
    return by_name[0] if len(by_name) == 1 else None


def _history_block_addresses(state: Any) -> tuple[int, ...]:
    try:
        sequence = state.history.bbl_addrs
        addresses = sequence.hardcopy if hasattr(sequence, "hardcopy") else sequence
        return tuple(int(address) for address in addresses)
    except Exception:
        return ()


def _direct_call_instruction_addresses(project: Any, block_address: int,
                                       target_address: int) -> tuple[int, ...]:
    """Return addresses of direct call instructions, not CFG block starts."""
    try:
        block = project.factory.block(block_address)
    except Exception:
        return ()
    matches = []
    for instruction in block.capstone.insns:
        if not instruction.mnemonic.lower().startswith("call"):
            continue
        try:
            target = int(instruction.op_str.split(",", 1)[0].strip(), 0)
        except (TypeError, ValueError):
            continue
        if target == target_address:
            matches.append(int(instruction.address))
    return tuple(matches)


def _branch_sites(project: Any, block_addresses: tuple[int, ...],
                  allowed_blocks: set[int]) -> list[dict[str, Any]]:
    sites = []
    seen: set[int] = set()
    for address in block_addresses:
        if address in seen or address not in allowed_blocks:
            continue
        seen.add(address)
        try:
            block = project.factory.block(address)
            instructions = [
                {"address": int(item.address), "mnemonic": item.mnemonic,
                 "op_str": item.op_str, "bytes": bytes(item.bytes).hex()}
                for item in block.capstone.insns
                if item.mnemonic.startswith("j") and item.mnemonic not in {"jmp", "jmpq"}
            ]
        except Exception:
            continue
        if instructions:
            sites.append({"block_address": address, "instructions": instructions,
                          "vex": str(block.vex)})
    return sites


def _smtlib_query(path_terms: list[str], expressions: list[Any]) -> str:
    """Serialize an angr 10 Claripy expression as standalone QF_BV SMT-LIB."""
    stack = list(expressions)
    seen: set[int] = set()
    variables: dict[str, int] = {}
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if getattr(node, "op", None) == "BVS":
            name, width = node.args
            variables[str(name)] = int(width)
        for child in getattr(node, "args", ()):
            if hasattr(child, "op"):
                stack.append(child)
    declarations = "".join(
        f"(declare-fun {name} () (_ BitVec {width}))\n"
        for name, width in sorted(variables.items())
    )
    body = path_terms[0] if len(path_terms) == 1 else f"(or {' '.join(path_terms)})"
    return ("(set-logic QF_BV)\n" + declarations
            + f"(assert {body})\n(check-sat)")
