#ifndef DYNLOADER_REGRESSION_ABI_H
#define DYNLOADER_REGRESSION_ABI_H
/* Shared with `abi.zig`: fixed-width, caller-owned snapshots. They deliberately
 * expose observed state instead of the loader's private object representation. */
#include <stdint.h>

struct LibraryState {
    uint32_t initialized_global;
    uint32_t zeroed_global;
    uint32_t tls_value;
    uint32_t constructor_count;
};

struct FinalizationEvents {
    uint32_t finalizer_count;
    uint32_t initialized_global;
    uint32_t zeroed_global;
    uint32_t tls_value;
};
#endif
