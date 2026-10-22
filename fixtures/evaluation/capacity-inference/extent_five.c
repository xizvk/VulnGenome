/* Independent 5-byte extent control. Compile and analyze; never execute. */
#include <stddef.h>

static volatile unsigned char sample_five[5];

__attribute__((noinline, visibility("default")))
void sensitive_sink(size_t amount) {
    for (size_t cursor = 0; cursor < amount; cursor += 1) {
        sample_five[cursor] = (unsigned char)(cursor + 3);
    }
}

__attribute__((noinline, visibility("default")))
int transfer(size_t requested) {
    if (requested > 5) return -1;
    sensitive_sink(requested);
    return 0;
}
