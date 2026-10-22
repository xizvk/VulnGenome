# Independent capacity-inference evaluation fixtures

These fixtures were designed separately from the original `transfer_*`
controlled family. They are compile-only inputs; the generated ELF files are
analyzed statically and are never executed. The analyzer receives only each
compiled binary. This directory and the evaluation record keep ground truth
separate from binary-derived observations and solver conclusions.

| Fixture | Ground-truth purpose |
| --- | --- |
| `independent_valid.c` | Different global name and write expression; one-byte writes use a zero-based unit-stride loop bounded by the sink argument. |
| `unrelated_decoy.c` | A global object is written at its one-past-end offset while the sink argument controls only whether that write executes. |
| `indirect_write_decoy.c` | A safe argument-indexed object loop coexists with an out-of-bounds dynamic-pointer write that is not summarized by the extent matcher. |
| `multiple_candidate_decoy.c` | Two globals are written; only one is indexed by the sink argument's bounded loop. |
| `multiple_candidate_ambiguous.c` | Two differently sized globals are both indexed by the same sink argument loop. |
| `extent_five.c`, `extent_thirteen.c` | Independent objects with different extents and independently written sinks. |
| `unguarded_independent.c` | A valid argument-to-object relation with no caller guard. |
| `changed_argument_independent.c` | Caller checks `requested` but passes `requested + 1` to the sink. |
| `weak_guard_or.c` | Sink loop guard contains an OR condition that permits stores not bounded by the argument. |

The names and labels in this README are evaluation metadata only. They are not
provided to the inference function.
