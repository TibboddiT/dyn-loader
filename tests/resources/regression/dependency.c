#include "abi.h"

extern void readState(struct LibraryState *);

static uint32_t *observed;
static struct FinalizationEvents *provider_events;

void readBoundState(struct LibraryState *out) {
    readState(out);
}

void observeFinalization(uint32_t *out, struct FinalizationEvents *events) {
    observed = out;
    provider_events = events;
}

__attribute__((destructor)) static void finalize(void) {
    if (observed) *observed = provider_events->finalizer_count;
}
