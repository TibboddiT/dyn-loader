#define _POSIX_C_SOURCE 200809L
/* Call native APIs from a loaded DSO so tests exercise relocation substitution
 * and caller-address-based scope resolution. Zig invokes these typed wrappers. */
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <unistd.h>

void *openProbe(const char *path) { return dlopen(path, RTLD_NOW); }
void *openFlagsProbe(const char *path, int flags) { return dlopen(path, flags); }
void *openGlobalProbe(const char *path) { return dlopen(path, RTLD_NOW | RTLD_GLOBAL); }
void *symbolProbe(void *handle, const char *name) { return dlsym(handle, name); }
int closeProbe(void *handle) { return dlclose(handle); }
int startProbe(pthread_t *thread, void *(*routine)(void *), void *argument) {
    return pthread_create(thread, NULL, routine, argument);
}
int joinProbe(pthread_t thread) { return pthread_join(thread, NULL); }

static void *attributeWorker(void *argument) { return argument; }

int threadAttributesProbe(void) {
    for (int mode = 0; mode < 6; ++mode) {
        pthread_attr_t attr;
        int rc = pthread_attr_init(&attr);
        if (rc != 0) return rc;
        size_t default_guard;
        rc = pthread_attr_getguardsize(&attr, &default_guard);
        if (rc == 0 && mode != 0)
            rc = pthread_attr_setguardsize(&attr, (size_t)sysconf(_SC_PAGESIZE));
        if (rc != 0) { pthread_attr_destroy(&attr); return rc; }
        switch (mode) {
        case 1: rc = pthread_attr_setstacksize(&attr, 2 * 1024 * 1024); break;
        case 2: rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED); break;
        case 3: rc = pthread_attr_setguardsize(&attr, 2 * (size_t)sysconf(_SC_PAGESIZE)); break;
        case 4: rc = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED); break;
        }
        if (rc != 0) { pthread_attr_destroy(&attr); return rc; }
        pthread_t thread;
        rc = pthread_create(&thread, &attr, attributeWorker, &mode);
        pthread_attr_destroy(&attr);
        if ((mode >= 2 && mode <= 4) || (mode == 0 && default_guard != (size_t)sysconf(_SC_PAGESIZE))) {
            if (rc != EOPNOTSUPP) return -mode;
        } else {
            if (rc != 0) return rc;
            void *result = NULL;
            rc = pthread_join(thread, &result);
            if (rc != 0) return rc;
            if (result != &mode) return -10;
        }
    }
    return 0;
}

static struct sigaction previous_signal_action;
static atomic_int signal_phase;
static _Thread_local volatile sig_atomic_t signal_tls;

enum SignalPhase {
    SIGNAL_WAITING,
    SIGNAL_READY,
    SIGNAL_RECEIVED,
    SIGNAL_WRONG_THREAD,
    SIGNAL_STOPPED,
    SIGNAL_MASK_FAILED
};

static void signal_handler(int signal_number) {
    (void)signal_number;
    atomic_store_explicit(&signal_phase,
        signal_tls == 71 ? SIGNAL_RECEIVED : SIGNAL_WRONG_THREAD, memory_order_release);
}

int installSignalProbe(void) {
    struct sigaction action = {0};
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    int result = sigaction(SIGUSR1, &action, &previous_signal_action);
    if (result == 0) atomic_store_explicit(&signal_phase, SIGNAL_WAITING, memory_order_release);
    return result;
}

void signalWorkerProbe(void) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    signal_tls = 71;
    if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) {
        atomic_store_explicit(&signal_phase, SIGNAL_MASK_FAILED, memory_order_release);
        return;
    }

    /* Cleanup can request stop before this routine starts. Never overwrite it. */
    int expected = SIGNAL_WAITING;
    atomic_compare_exchange_strong_explicit(&signal_phase, &expected, SIGNAL_READY,
        memory_order_release, memory_order_relaxed);
    while (atomic_load_explicit(&signal_phase, memory_order_acquire) == SIGNAL_READY) sched_yield();

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0) {
        atomic_store_explicit(&signal_phase, SIGNAL_MASK_FAILED, memory_order_release);
    }
}

void stopSignalProbe(void) {
    atomic_store_explicit(&signal_phase, SIGNAL_STOPPED, memory_order_release);
}

int signalPhaseProbe(void) {
    return atomic_load_explicit(&signal_phase, memory_order_acquire);
}

int deliverSignalProbe(void) { return kill(getpid(), SIGUSR1); }
int restoreSignalProbe(void) { return sigaction(SIGUSR1, &previous_signal_action, NULL); }

int signalProbeRestored(void) {
    struct sigaction current = {0};
    if (sigaction(SIGUSR1, NULL, &current) != 0) return -1;
    return current.sa_handler == previous_signal_action.sa_handler;
}
