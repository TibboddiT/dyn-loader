/* Resolve and call a freshly initialized dependency during the outer load. */
#include <dlfcn.h>
#include "abi.h"

unsigned constructor_count;
int constructor_status;
unsigned nested_value;

__attribute__((constructor)) static void initialize(void) {
    ++constructor_count;
    void *handle = dlopen("target.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        constructor_status = 1;
        return;
    }

    void (*read_state)(struct LibraryState *) = dlsym(handle, "readState");
    if (read_state) {
        struct LibraryState state;
        read_state(&state);
        nested_value = state.initialized_global + state.tls_value + state.constructor_count;
    } else {
        constructor_status = 2;
    }

    if (dlclose(handle) != 0) constructor_status = 3;
}
