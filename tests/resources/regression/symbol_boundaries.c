/* Both a data relocation and a GOT reference to the linker's zero-sized,
 * one-past-the-image marker. The address is a value, never dereferenced. */
#include <stdint.h>

extern char _end[];
void *end_pointer = _end;
volatile unsigned char boundary_bss[17];

int check_end(void) {
    boundary_bss[16] = 42;
    return end_pointer == (void *)_end &&
           (uintptr_t)_end >= (uintptr_t)(boundary_bss + sizeof(boundary_bss)) &&
           boundary_bss[16] == 42 ? 42 : 0;
}
