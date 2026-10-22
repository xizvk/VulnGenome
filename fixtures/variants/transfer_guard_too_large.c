/* Controlled negative control: guard permits lengths larger than the object. */
#include <stddef.h>

#define BUFFER_CAPACITY ((size_t)16)
static volatile unsigned char bounded_object[BUFFER_CAPACITY];

__attribute__((noinline, visibility("default")))
void sensitive_sink(size_t length) {
    for (size_t index = 0; index < length; ++index) {
        bounded_object[index] = (unsigned char)index;
    }
}

__attribute__((noinline, visibility("default")))
int transfer(size_t length) {
    if (length > 32) {
        return -1;
    }
    sensitive_sink(length);
    return 0;
}
