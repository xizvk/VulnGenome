/* Negative control: a second dynamic-pointer write is outside the modeled object relation. */
#include <stddef.h>

static volatile unsigned char primary_region[9];

__attribute__((noinline, visibility("default")))
void sensitive_sink(size_t amount, volatile unsigned char *destination) {
    size_t cursor = 0;
    while (cursor < amount) {
        primary_region[cursor] = (unsigned char)cursor;
        cursor = cursor + 1;
    }
    destination[0] = 0x42;
}

__attribute__((noinline, visibility("default")))
int transfer(size_t requested) {
    if (requested > sizeof primary_region) {
        return -1;
    }
    sensitive_sink(requested, primary_region + sizeof primary_region);
    return 0;
}
