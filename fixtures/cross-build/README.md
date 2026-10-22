# Independent cross-build fixture pairs

All sources here are controlled evaluation inputs, not real-world vulnerability
claims. Compile and analyze them statically; never execute the generated ELFs.
The vulnerable/patched source pairs are the ground truth and are not passed to
binary inference or cross-build transfer.

## Frame staging pair

`frame_vulnerable.c` stages a caller-selected number of transformed wire bytes
into `frame_slab[13]` using a `while` loop. `frame_patched.c` adds an upper
bound check against the slab extent before calling the same sink. The intended
property is that the first argument to `stage_frame` must be no greater than
the extent of `frame_slab`. The difference is the caller guard; the sink data
flow and byte transformation are unchanged.

## Telemetry/sample pair

`telemetry_vulnerable.c` and `telemetry_patched.c` model a sample commit path.
The sink writes `sample_buffer` in an argument-bounded loop and also updates
`telemetry_count[0]`, a same-sized decoy global that merely co-occurs in the
sink. The caller checks `requested <= sizeof sample_buffer`. The vulnerable
pair passes `requested + 1`; the patched pair passes `requested`. This tests
whether inference associates the extent with the loop-indexed object and the
actual sink argument rather than selecting a convenient co-occurring symbol.

The matrix builds every existing regression control at `-O0`, `-O1`, `-O2`,
`-O3`, and `-Os`. These independent pairs are built at `-O0` and `-O2`.
