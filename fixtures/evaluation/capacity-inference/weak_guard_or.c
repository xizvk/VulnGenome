/* Negative control: an OR clause admits stores outside the index bound. */
#include <stddef.h>

static volatile unsigned char weakly_guarded[5];

__attribute__((noinline, visibility("default")))
void sensitive_sink(size_t amount) {
    size_t cursor = 0;
    while (cursor < amount || amount == 0) {
        weakly_guarded[cursor] = (unsigned char)cursor;
        cursor += 1;
    }
}

__attribute__((noinline, visibility("default")))
int transfer(size_t requested) {
    if (requested > sizeof weakly_guarded) return -1;
    sensitive_sink(requested);
    return 0;
}
