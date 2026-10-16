#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

static _Thread_local int tls_value = 23;
static _Thread_local int tls_zero;
static atomic_int stop_worker;
static atomic_int worker_ready;
static pthread_t owned_worker;
static void *growth_handles[12];
static unsigned constructor_count;
static unsigned *finalization_result;
static atomic_uint tls_destructor_count;
static int (*register_tls_destructor)(void (*)(void *), void *, void *);

/* A local definition keeps this probe usable on runtimes without the public
 * glibc symbol. Resolve through dlsym: some SDKs bind local calls directly. */
int __cxa_thread_atexit_impl(void (*function)(void *), void *argument, void *owner) {
    (void)function;
    (void)argument;
    (void)owner;
    abort();
}

static void tls_cleanup(void *argument) {
    if (argument != &constructor_count || tls_value != 42 || tls_zero != 7) abort();
    atomic_fetch_add_explicit(&tls_destructor_count, 1, memory_order_relaxed);
}

static void *ordinary_work(void *argument) {
    if (tls_value != 23 || tls_zero != 0) abort();
    tls_value = 42;
    tls_zero = 7;

    void *allocation = malloc(128);
    if (!allocation) abort();
    free(allocation);
    if (register_tls_destructor(tls_cleanup, &constructor_count, &constructor_count)) abort();
    return argument;
}

static void *persistent_work(void *argument) {
    ordinary_work(argument);
    atomic_store_explicit(&worker_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&stop_worker, memory_order_acquire)) sched_yield();
    if (tls_value != 42 || tls_zero != 7) abort();
    return argument;
}

__attribute__((constructor)) static void initialize(void) {
    if (++constructor_count != 1) abort();
    register_tls_destructor = dlsym(RTLD_DEFAULT, "__cxa_thread_atexit_impl");
    if (!register_tls_destructor) abort();

    pthread_t joined;
    void *result = NULL;
    if (pthread_create(&joined, NULL, ordinary_work, &constructor_count)) abort();
    if (pthread_join(joined, &result) || result != &constructor_count) abort();
    if (tls_value != 23 || tls_zero != 0) abort();

    void *nested = dlopen("target.so", RTLD_NOW);
    if (!nested || !dlsym(nested, "readState")) abort();
    if (dlclose(nested)) abort();

    void *self = dlopen("constructor_workers.so", RTLD_NOW);
    if (!self || dlclose(self)) abort();

    /* Distinct file identities force registry growth while the outer constructor
     * is suspended in recursive loads. TLS module IDs must stay independent. */
    for (unsigned index = 0; index < 12; ++index) {
        char path[32];
        if (snprintf(path, sizeof(path), "growth_%u.so", index) < 0) abort();
        growth_handles[index] = dlopen(path, RTLD_NOW);
        if (!growth_handles[index]) abort();
    }

    if (pthread_create(&owned_worker, NULL, persistent_work, &constructor_count)) abort();
    while (!atomic_load_explicit(&worker_ready, memory_order_acquire)) sched_yield();
}

void observeFinalization(unsigned *result) {
    finalization_result = result;
}

unsigned constructorCount(void) {
    return constructor_count;
}

__attribute__((destructor)) static void finalize(void) {
    atomic_store_explicit(&stop_worker, 1, memory_order_release);
    if (pthread_join(owned_worker, NULL)) abort();
    if (atomic_load_explicit(&tls_destructor_count, memory_order_relaxed) != 2) abort();
    for (unsigned index = 0; index < 12; ++index) {
        if (dlclose(growth_handles[index])) abort();
    }
    if (finalization_result) *finalization_result += 1;
}
