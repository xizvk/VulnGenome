/* Caller checks one value but passes a larger expression to the sink. */
#include <stddef.h>

static volatile unsigned char shifted_target[7];

__attribute__((noinline, visibility("default")))
void sensitive_sink(size_t amount) {
    for (size_t cursor = 0; cursor < amount; ++cursor) {
        shifted_target[cursor] = (unsigned char)(cursor ^ amount);
    }
}

__attribute__((noinline, visibility("default")))
int transfer(size_t requested) {
    if (requested > sizeof shifted_target) {
        return -1;
    }
    sensitive_sink(requested + 1);
    return 0;
}
