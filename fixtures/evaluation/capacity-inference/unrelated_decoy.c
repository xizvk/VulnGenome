/* Negative control: the global write is unrelated to the sink argument. */
#include <stddef.h>

static volatile unsigned char unrelated_marker[17];

__attribute__((noinline, visibility("default")))
void sensitive_sink(size_t amount) {
    size_t fixed_offset = sizeof unrelated_marker;
    if (amount != 0) {
        unrelated_marker[fixed_offset] = 0x41;
    }
}

__attribute__((noinline, visibility("default")))
int transfer(size_t requested) {
    if (requested > sizeof unrelated_marker) {
        return -1;
    }
    sensitive_sink(requested);
    return 0;
}
