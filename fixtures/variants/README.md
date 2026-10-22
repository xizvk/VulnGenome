# Controlled binary-analysis variants

These C files are separate ground-truth inputs for focused inference tests.
The analyzer receives only the compiled ELF artifacts; it does not read these
sources or their expected labels.

| Fixture | Ground truth for evaluation |
| --- | --- |
| `transfer_capacity_24.c` | Object extent and protective guard are both 24 bytes. |
| `transfer_guard_too_large.c` | Object extent is 16 bytes; the caller guard permits values through 32. |
| `transfer_sink_plus_one.c` | Object extent is 16 bytes; the caller checks `length` but passes `length + 1` to the sink. |

The existing `fixtures/transfer_vulnerable.c` is the removed-guard control.
These labels are evaluation metadata, never inference inputs.
