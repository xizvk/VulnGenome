/* Independent valid relation without a protective caller guard. */
#include <stddef.h>

static volatile unsigned char unguarded_target[11];

__attribute__((noinline, visibility("default")))
void sensitive_sink(size_t amount) {
    for (size_t cursor = 0; cursor < amount; ++cursor) {
        unguarded_target[cursor] = (unsigned char)cursor;
    }
}

__attribute__((noinline, visibility("default")))
int transfer(size_t requested) {
    sensitive_sink(requested);
    return 0;
}
