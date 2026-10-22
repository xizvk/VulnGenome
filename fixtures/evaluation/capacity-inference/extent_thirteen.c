/* Independent 13-byte extent control with a differently written sink. */
#include <stddef.h>

static volatile unsigned char sample_thirteen[13];

__attribute__((noinline, visibility("default")))
void sensitive_sink(size_t amount) {
    size_t position = 0;
    while (position < amount) {
        sample_thirteen[position] = (unsigned char)(position * 3);
        position += 1;
    }
}

__attribute__((noinline, visibility("default")))
int transfer(size_t requested) {
    if (requested > 13) return -1;
    sensitive_sink(requested);
    return 0;
}
