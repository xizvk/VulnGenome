/* Independent relation challenge, patched sink argument; compile and analyze only. */
#include <stddef.h>

#define SAMPLE_CAPACITY ((size_t)7)
static volatile unsigned char sample_buffer[SAMPLE_CAPACITY];
static volatile unsigned char telemetry_count[SAMPLE_CAPACITY];

__attribute__((noinline, visibility("default")))
void commit_sample(size_t sample_count) {
    size_t position = 0;
    while (position < sample_count) {
        sample_buffer[position] = (unsigned char)(sample_count - position);
        position = position + 1;
    }
    telemetry_count[0] = (unsigned char)sample_count;
}

__attribute__((noinline, visibility("default")))
int accept_sample(size_t requested) {
    if (requested > sizeof sample_buffer) {
        return -1;
    }
    commit_sample(requested);
    return 0;
}
