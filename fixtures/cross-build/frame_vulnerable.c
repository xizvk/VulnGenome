/* Independent controlled pair: vulnerable frame staging; compile and analyze only. */
#include <stddef.h>

#define FRAME_SLAB_BYTES ((size_t)13)
static volatile unsigned char frame_slab[FRAME_SLAB_BYTES];

__attribute__((noinline, visibility("default")))
void stage_frame(size_t wire_octets) {
    size_t write_head = 0;
    while (write_head < wire_octets) {
        frame_slab[write_head] = (unsigned char)(write_head ^ 0x5aU);
        write_head = write_head + 1;
    }
}

__attribute__((noinline, visibility("default")))
int receive_frame(size_t declared_octets) {
    stage_frame(declared_octets);
    return 0;
}
