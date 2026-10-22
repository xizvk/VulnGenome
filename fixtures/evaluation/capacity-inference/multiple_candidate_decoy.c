/* One argument-indexed destination plus a second, unrelated global write. */
#include <stddef.h>

static volatile unsigned char primary_region[7];
static volatile unsigned char telemetry_log[23];

__attribute__((noinline, visibility("default")))
void sensitive_sink(size_t amount) {
    for (size_t cursor = 0; cursor < amount; ++cursor) {
        primary_region[cursor] = (unsigned char)(amount - cursor);
    }
    telemetry_log[0] = (unsigned char)amount;
}

__attribute__((noinline, visibility("default")))
int transfer(size_t requested) {
    if (requested > sizeof primary_region) {
        return -1;
    }
    sensitive_sink(requested);
    return 0;
}
