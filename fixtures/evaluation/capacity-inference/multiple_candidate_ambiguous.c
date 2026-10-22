/* Both candidate objects are indexed by the same argument-bounded loop. */
#include <stddef.h>

static volatile unsigned char primary_region[7];
static volatile unsigned char audit_region[23];

__attribute__((noinline, visibility("default")))
void sensitive_sink(size_t amount) {
    for (size_t cursor = 0; cursor < amount; ++cursor) {
        primary_region[cursor] = (unsigned char)cursor;
        audit_region[cursor] = (unsigned char)(amount - cursor);
    }
}

__attribute__((noinline, visibility("default")))
int transfer(size_t requested) {
    if (requested > sizeof primary_region) {
        return -1;
    }
    sensitive_sink(requested);
    return 0;
}
