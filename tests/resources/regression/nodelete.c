#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>

extern int nodeleteDependencyValue(void);
extern void nodeleteDependencyObserve(int *);
static int constructors;
static int value = 7;
static _Thread_local int tls_value = 11;
static int *finalizations;
static atomic_int phase;
static pthread_t worker;
static void *internal_handle;

#ifdef NODELETE_UNRESOLVED
extern int nodeleteMissingSymbol(void);
int (*nodeleteUnresolvedRelocation)(void) = nodeleteMissingSymbol;
#endif

__attribute__((constructor)) static void initialize(void) { ++constructors; }
__attribute__((destructor)) static void finalize(void) {
    if (finalizations) ++*finalizations;
}

void nodeleteObserve(int *own, int *dependency) {
    finalizations = own;
    value = 42;
    tls_value = 55;
    nodeleteDependencyObserve(dependency);
}

int nodeleteCheck(void) {
    return constructors == 1 && value == 42 && tls_value == 55 && nodeleteDependencyValue() == 29;
}

static void *runWorker(void *unused) {
    (void)unused;
    int *allocation = malloc(sizeof *allocation);
    if (!allocation) { atomic_store(&phase, -1); return NULL; }
    *allocation = 123;
    tls_value = 99;
    atomic_store(&phase, 1);
    while (atomic_load(&phase) == 1) sched_yield();
    int ok = *allocation == 123 && tls_value == 99;
    free(allocation);
    void *handle = dlopen("nodelete_dep.so", RTLD_NOW | RTLD_NOLOAD);
    int (*read_value)(void) = handle ? dlsym(handle, "nodeleteDependencyValue") : NULL;
    ok = ok && read_value && read_value() == 29;
    if (handle) ok = ok && dlclose(handle) == 0;
    atomic_store(&phase, ok ? 3 : -1);
    return NULL;
}

int nodeleteStart(void) {
    atomic_store(&phase, 0);
    int rc = pthread_create(&worker, NULL, runWorker, NULL);
    if (rc) return rc;
    while (atomic_load(&phase) == 0) sched_yield();
    return atomic_load(&phase) == 1 ? 0 : -1;
}

int nodeleteFinish(void) {
    atomic_store(&phase, 2);
    int rc = pthread_join(worker, NULL);
    return rc ? rc : (atomic_load(&phase) == 3 ? 0 : -1);
}

int nodeleteHold(const char *path) {
    internal_handle = dlopen(path, RTLD_NOW);
    return internal_handle ? 0 : -1;
}

int nodeleteRelease(void) {
    if (!internal_handle || !dlsym(internal_handle, "readState")) return -1;
    int rc = dlclose(internal_handle);
    internal_handle = NULL;
    return rc;
}

int nodeleteClose(void *handle) { return dlclose(handle); }
