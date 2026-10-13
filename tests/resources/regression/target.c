/* Reload fixture with initialized globals, BSS, initialized TLS, and a scalable
 * TLS reservation. Exporting `largeTlsAddress` keeps the reservation observable
 * even in the optimized fixture. */
#include "abi.h"

#ifndef TLS_BYTES
#define TLS_BYTES 1
#endif

static uint32_t initialized = 7;
static uint32_t zeroed;
_Thread_local uint32_t tls_value = 11;
_Thread_local unsigned char large_tls[TLS_BYTES];
/* Export the final byte as a TLS symbol too: in the large fixture its st_value
 * lies beyond the PT_LOAD mappings, although it is a valid TLS offset. */
#define STRINGIFY_INNER(x) #x
#define STRINGIFY(x) STRINGIFY_INNER(x)
__asm__(".globl tls_tail\n"
        ".type tls_tail, @tls_object\n"
        ".set tls_tail, large_tls + " STRINGIFY(TLS_BYTES) " - 1\n"
        ".size tls_tail, 1\n");
static uint32_t constructor_count;
static struct FinalizationEvents *events;

unsigned char *largeTlsAddress(void) { return large_tls; }
uint32_t *tlsValueAddress(void) { return &tls_value; }
unsigned char *tlsTailAddress(void) { return &large_tls[TLS_BYTES - 1]; }
extern _Thread_local unsigned char tls_tail;
unsigned char *tlsTailAliasAddress(void) { return &tls_tail; }

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
    // Borrow the observer until finalization; the caller keeps it outside the DSO.
    events = out;
    initialized = 42;
    zeroed = 99;
    tls_value = 55;
}

void setTls(uint32_t value) { tls_value = value; }
