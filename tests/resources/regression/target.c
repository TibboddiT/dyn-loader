#include "abi.h"

#ifndef TLS_BYTES
#define TLS_BYTES 1
#endif

static uint32_t initialized = 7;
static uint32_t zeroed;
static _Thread_local uint32_t tls_value = 11;
static _Thread_local unsigned char large_tls[TLS_BYTES];
static uint32_t constructor_count;
static struct FinalizationEvents *events;

unsigned char *largeTlsAddress(void) { return large_tls; }

__attribute__((constructor)) static void initialize(void) {
    ++constructor_count;
}

__attribute__((destructor)) static void finalize(void) {
    if (events) {
        ++events->finalizer_count;
        events->initialized_global = initialized;
        events->zeroed_global = zeroed;
        events->tls_value = tls_value;
    }
}

void readState(struct LibraryState *out) {
    *out = (struct LibraryState){initialized, zeroed, tls_value, constructor_count};
}

void mutate(struct FinalizationEvents *out) {
    events = out;
    initialized = 42;
    zeroed = 99;
    tls_value = 55;
}

void setTls(uint32_t value) { tls_value = value; }
