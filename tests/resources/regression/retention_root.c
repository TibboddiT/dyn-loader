#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>

extern int retentionRead(void);
int retentionValue(void) { return 19; }
int retentionProtected(void) { return 99; }
int retentionCheck(void) { return retentionRead(); }

static pthread_t worker;
static atomic_int ready;
static atomic_int stop;
static int *finalizations;
static void *run(void *unused) {
    (void)unused;
    atomic_store(&ready, 1);
    while (!atomic_load(&stop)) sched_yield();
    return 0;
}
void retentionObserve(int *out) { finalizations = out; }
int retentionStart(void) {
    int result = pthread_create(&worker, 0, run, 0);
    if (result) return result;
    while (!atomic_load(&ready)) sched_yield();
    return 0;
}
int retentionStop(void) {
    atomic_store(&stop, 1);
    return pthread_join(worker, 0);
}
__attribute__((destructor)) static void finalize(void) {
    if (finalizations) ++*finalizations;
}
