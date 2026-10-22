/* Independent positive control. Compile and analyze; never execute. */
#include <stddef.h>

static volatile unsigned char telemetry_region[9];

__attribute__((noinline, visibility("default")))
void sensitive_sink(size_t amount) {
    size_t cursor = 0;
    while (cursor < amount) {
        telemetry_region[cursor] = (unsigned char)(cursor ^ (amount - cursor));
        cursor = cursor + 1;
    }
}

__attribute__((noinline, visibility("default")))
int transfer(size_t requested) {
    if (requested > sizeof telemetry_region) {
        return -1;
    }
    sensitive_sink(requested);
    return 0;
}
