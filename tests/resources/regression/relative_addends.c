#include <stdint.h>

static int state = 21;
void *relative_slot = &state;
extern const char __ehdr_start[];

int check_zero(void) {
    return (uintptr_t)relative_slot == (uintptr_t)__ehdr_start ? 42 : 0;
}

int check_negative(void) {
    return (uintptr_t)relative_slot == (uintptr_t)__ehdr_start - 8 ? 42 : 0;
}
