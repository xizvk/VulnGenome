# Optimized VEX capacity inference

The default capacity matcher recognizes a zero-based unit-stride loop whose
byte store and unsigned `index < length` checks are tied to stack slots. Clang
can remove that frame and change the loop structure, so `capacity.py` has a
second, intentionally narrow VEX path for one scalar register-loop form.

## Supported optimized form

The optimized path requires all of the following from the target ELF and its
VEX CFG:

1. A unique positive-size `STT_OBJECT` symbol identifies the destination and
   supplies its extent.
2. The sink's first System V AMD64 integer argument is the 64-bit value in
   `rdi`; the caller-to-sink call must still be uniquely identified.
3. A binary-derived entry branch sends a zero argument away from the first
   store.
4. The first executed store is one byte at object offset zero. The index
   register is then set to one; equality between that value and the argument
   exits before the repeated loop.
5. The loop body has one byte store at `object[index]`, one 64-bit `index + 1`
   update after the store, and a binary-derived equality check between the
   incremented index and the original argument. The false edge returns to the
   body; the equality edge cannot reach the store.
6. Register constant propagation identifies the object base in VEX, the body
   has only the proven preheader and loop back edge, and no unresolved or
   additional dynamic memory write undermines the object relationship.

The first store covers index zero. For a nonzero 64-bit argument, the repeated
loop stores indices one through `argument - 1` and exits when the incremented
index equals the argument. Because the counter starts below that nonzero
argument and advances by one, it reaches equality before wrapping. The proof
uses equality and finite-width arithmetic; it does not reinterpret the value
as signed. The actual caller argument is then checked by the existing
binary-derived symbolic execution and solver query.

The result records the binary hash, object symbol and size, VEX store
expressions, instruction addresses, branch conditions and targets, register
width, and the accepted data-flow relation. It does not accept a fixture
contract capacity or source-level expected classification.

## Explicitly unsupported forms

Vectorized or unrolled chunks, multiple indexed stores, pointer-induction
loops where the store address is only a changing pointer register, countdown
loops whose flag semantics are not recovered, stripped object symbols,
indirect writes, calls in the sink, and ambiguous destinations remain
`INCONCLUSIVE`. In particular, a store in the same function as a known object
does not establish a relationship. Unsupported forms do not reach the solver
through automatic inference.

The inference still assumes the ELF symbol size describes the allocated
object and that all relevant writes in the named sink have been recovered. It
does not prove alias safety, dynamic allocation bounds, whole-program memory
safety, or behavior outside the analyzed paths. `PROPERTY_HOLDS_WITHIN_MODEL`
is not a complete safety proof.

## Transfer boundary

Cross-build transfer can accept either the original stack-slot relation or
this optimized scalar relation as source or target evidence. Transfer carries
only the abstract property and candidate names. The target must independently
recover its object, store, guard, call, path, and solver evidence, all bound to
the target binary hash. A fresh independent target analysis and an accepted
cross-build transfer are reported separately.
