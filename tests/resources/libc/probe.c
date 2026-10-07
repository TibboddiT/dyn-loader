#include "probe_api.h"
#include "tls_object.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <iconv.h>
#include <locale.h>
#include <mqueue.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

extern int consumer_value(void);
static int constructor_count;
static int constructor_dependency;
static uint32_t current_case;

__attribute__((constructor)) static void initialize(void) {
    ++constructor_count;
    constructor_dependency = consumer_value();
}

static void copyText(char *destination, size_t capacity, const char *source) {
    size_t index = 0;
    while (index + 1 < capacity && source[index]) {
        destination[index] = source[index];
        ++index;
    }
    destination[index] = 0;
}

static void recordFailure(struct probe_result *result, unsigned line, const char *detail,
                          int64_t expected, int64_t observed, int saved_errno) {
    result->status = PROBE_FAIL;
    result->line = line;
    result->saved_errno = saved_errno;
    result->expected = expected;
    result->observed = observed;
    copyText(result->detail, sizeof result->detail, detail);
}

#define EXPECT(result, actual, wanted) do { \
    int64_t observed_ = (int64_t)(actual); \
    int64_t expected_ = (int64_t)(wanted); \
    int saved_errno_ = errno; \
    if (observed_ != expected_) { \
        recordFailure((result), __LINE__, #actual, expected_, observed_, saved_errno_); \
        return; \
    } \
} while (0)
#define UNUSED_HOST() ((void)host)

static void constructors(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    EXPECT(result, constructor_count, 1);
    EXPECT(result, constructor_dependency, 42);
    EXPECT(result, consumer_value(), 42);
}

static void runpathChain(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    void *library = dlopen("/fixtures/runpath/chain/top.so", RTLD_NOW | RTLD_LOCAL);
    EXPECT(result, library != NULL, 1);
    int (*value)(void) = (int (*)(void))dlsym(library, "runpath_value");
    if (!value) {
        dlclose(library);
        EXPECT(result, value != NULL, 1);
    }
    int observed = value();
    int close_result = dlclose(library);
    EXPECT(result, observed, 42);
    EXPECT(result, close_result, 0);
}

static void runpathScope(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    void *library = dlopen("/fixtures/runpath/scope/top.so", RTLD_NOW | RTLD_LOCAL);
#ifdef __GLIBC__
    int unexpectedly_loaded = library != NULL;
    if (library) dlclose(library);
    EXPECT(result, unexpectedly_loaded, 0);
#else
    EXPECT(result, library != NULL, 1);
    int (*value)(void) = (int (*)(void))dlsym(library, "runpath_value");
    if (!value) {
        dlclose(library);
        EXPECT(result, value != NULL, 1);
    }
    int observed = value();
    int close_result = dlclose(library);
    EXPECT(result, observed, 42);
    EXPECT(result, close_result, 0);
#endif
}

static void errnoFailure(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    errno = 0;
    int fd = open("/__dynloader_matrix_missing__/file", O_RDONLY);
    int saved_errno = errno;
    if (fd >= 0) close(fd);
    EXPECT(result, fd, -1);
    EXPECT(result, saved_errno, ENOENT);
}

struct ErrnoWorker {
    atomic_int *arrived;
    int wanted;
    int observed;
    int returned_null;
};

static void *errnoThread(void *argument) {
    struct ErrnoWorker *worker = argument;
    errno = worker->wanted;
    if (worker->wanted == ENOMEM) {
        volatile size_t element_count = SIZE_MAX / 2 + 1;
        errno = 0;
        void *buffer = calloc(element_count, 2);
        int saved_errno = errno;
        worker->returned_null = buffer == NULL;
        free(buffer);
        errno = saved_errno;
    }
    atomic_fetch_add(worker->arrived, 1);
    while (atomic_load(worker->arrived) != 2) {}
    worker->observed = errno;
    return worker;
}

static void errnoIsolation(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    static atomic_int arrived;
    static struct ErrnoWorker workers[2] = {
        {.arrived = &arrived, .wanted = ENOMEM},
        {.arrived = &arrived, .wanted = ERANGE},
    };
    pthread_t threads[2];
    errno = E2BIG;
    EXPECT(result, pthread_create(&threads[0], NULL, errnoThread, &workers[0]), 0);
    EXPECT(result, pthread_create(&threads[1], NULL, errnoThread, &workers[1]), 0);
    EXPECT(result, pthread_join(threads[0], NULL), 0);
    EXPECT(result, pthread_join(threads[1], NULL), 0);
    int saved_errno = errno;
    EXPECT(result, workers[0].observed, ENOMEM);
    EXPECT(result, workers[0].returned_null, 1);
    EXPECT(result, workers[1].observed, ERANGE);
    EXPECT(result, saved_errno, E2BIG);
}

static void allocation(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    const size_t initial_size_bytes = 73;
    unsigned char *buffer = malloc(initial_size_bytes);
    EXPECT(result, buffer != NULL, 1);
    EXPECT(result, (uintptr_t)buffer % _Alignof(max_align_t), 0);
    for (size_t index = 0; index < initial_size_bytes; ++index) {
        buffer[index] = (unsigned char)index;
    }
    unsigned char *resized_buffer = realloc(buffer, 4097);
    if (!resized_buffer) {
        free(buffer);
        EXPECT(result, resized_buffer != NULL, 1);
    }
    buffer = resized_buffer;
    for (size_t index = 0; index < initial_size_bytes; ++index) {
        EXPECT(result, buffer[index], index);
    }
    free(buffer);

    buffer = calloc(19, 7);
    EXPECT(result, buffer != NULL, 1);
    for (size_t index = 0; index < 19 * 7; ++index) {
        EXPECT(result, buffer[index], 0);
    }
    free(buffer);

    void *aligned_buffer = NULL;
    EXPECT(result, posix_memalign(&aligned_buffer, 64, 257), 0);
    EXPECT(result, (uintptr_t)aligned_buffer % 64, 0);
    free(aligned_buffer);
}

static void allocationOverflow(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    volatile size_t element_count = SIZE_MAX / 2 + 1;
    errno = 0;
    void *buffer = calloc(element_count, 2);
    int saved_errno = errno;
    int returned_null = buffer == NULL;
    free(buffer);
    EXPECT(result, returned_null, 1);
    EXPECT(result, saved_errno, ENOMEM);

    // The product fits, but adding allocator alignment padding does not.
    volatile size_t oversized = SIZE_MAX;
    errno = 0;
    buffer = calloc(1, oversized);
    saved_errno = errno;
    returned_null = buffer == NULL;
    free(buffer);
    EXPECT(result, returned_null, 1);
    EXPECT(result, saved_errno, ENOMEM);

    unsigned char *recovered = calloc(7, 9);
    EXPECT(result, recovered != NULL, 1);
    for (size_t index = 0; index < 63; ++index) {
        EXPECT(result, recovered[index], 0);
    }
    free(recovered);
}

static void allocationInvalidAlignment(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    const size_t invalid_alignments[] = {0, 3, sizeof(void *) / 2};
    int sentinel;
    for (size_t index = 0; index < sizeof(invalid_alignments) / sizeof(invalid_alignments[0]); ++index) {
        void *buffer = &sentinel;
        errno = EDOM;
        int error_code = posix_memalign(&buffer, invalid_alignments[index], 64);
        int saved_errno = errno;
        if (error_code == 0) free(buffer);
        EXPECT(result, error_code, EINVAL);
        EXPECT(result, buffer == &sentinel, 1);
        EXPECT(result, saved_errno, EDOM);
    }

    void *buffer = NULL;
    EXPECT(result, posix_memalign(&buffer, 64, 257), 0);
    EXPECT(result, (uintptr_t)buffer % 64, 0);
    free(buffer);
}

static void allocationLibcBuffer(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    char *buffer = strdup("libc-created buffer");
    EXPECT(result, buffer != NULL, 1);
    EXPECT(result, strcmp(buffer, "libc-created buffer"), 0);
    free(buffer);
}

static _Thread_local int tls_initialized = 11;
static _Thread_local int tls_zeroed;

struct TlsWorker {
    int initialized;
    int zeroed;
    int changed;
    uintptr_t address;
};

static void *tlsThread(void *argument) {
    struct TlsWorker *worker = argument;
    worker->initialized = tls_initialized;
    worker->zeroed = tls_zeroed;
    worker->address = (uintptr_t)&tls_initialized;
    tls_initialized = 77;
    tls_zeroed = 88;
    worker->changed = tls_initialized == 77 && tls_zeroed == 88;
    return worker;
}

static void tlsIsolation(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    EXPECT(result, tls_initialized, 11);
    EXPECT(result, tls_zeroed, 0);
    tls_initialized = 55;
    tls_zeroed = 66;
    static struct TlsWorker worker;
    pthread_t thread;
    EXPECT(result, pthread_create(&thread, NULL, tlsThread, &worker), 0);
    EXPECT(result, pthread_join(thread, NULL), 0);
    EXPECT(result, worker.initialized, 11);
    EXPECT(result, worker.zeroed, 0);
    EXPECT(result, worker.changed, 1);
    EXPECT(result, worker.address != (uintptr_t)&tls_initialized, 1);
    EXPECT(result, tls_initialized, 55);
    EXPECT(result, tls_zeroed, 66);
}

static void *returnArgument(void *argument) {
    return argument;
}

static void threadJoin(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    int token;
    pthread_t thread;
    void *joined_value = NULL;
    EXPECT(result, pthread_create(&thread, NULL, returnArgument, &token), 0);
    EXPECT(result, pthread_join(thread, &joined_value), 0);
    EXPECT(result, joined_value == &token, 1);
}

static void threadNull(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    pthread_t thread;
    int token;
    void *joined_value = &token;
    EXPECT(result, pthread_create(&thread, NULL, returnArgument, NULL), 0);
    EXPECT(result, pthread_join(thread, &joined_value), 0);
    EXPECT(result, joined_value == NULL, 1);
}

struct CallbackWorker {
    const struct probe_host_api *host;
    uint32_t result;
    int tls_ok;
};

static void *callbackThread(void *argument) {
    struct CallbackWorker *worker = argument;
    tls_initialized = 91;
    worker->result = worker->host->callback(worker->host->context, 123);
    worker->tls_ok = tls_initialized == 91;
    return worker;
}

static void threadCallback(const struct probe_host_api *host, struct probe_result *result) {
    EXPECT(result, host->callback != NULL, 1);
    static struct CallbackWorker worker;
    worker.host = host;
    pthread_t thread;
    EXPECT(result, pthread_create(&thread, NULL, callbackThread, &worker), 0);
    EXPECT(result, pthread_join(thread, NULL), 0);
    EXPECT(result, worker.result, 124);
    EXPECT(result, worker.tls_ok, 1);
    EXPECT(result, tls_initialized, 11);
}

struct MutexState {
    pthread_mutex_t mutex;
    atomic_int ready;
    int counter;
    atomic_int error;
};

static void *mutexThread(void *argument) {
    struct MutexState *state = argument;
    atomic_fetch_add(&state->ready, 1);
    for (int iteration = 0; iteration < 2000; ++iteration) {
        int error_code = pthread_mutex_lock(&state->mutex);
        if (error_code) {
            atomic_store(&state->error, error_code);
            return state;
        }
        ++state->counter;
        error_code = pthread_mutex_unlock(&state->mutex);
        if (error_code) {
            atomic_store(&state->error, error_code);
            return state;
        }
    }
    return state;
}

static void mutexContention(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    static struct MutexState state = {.mutex = PTHREAD_MUTEX_INITIALIZER};
    pthread_t threads[2];
    EXPECT(result, pthread_mutex_lock(&state.mutex), 0);
    EXPECT(result, pthread_create(&threads[0], NULL, mutexThread, &state), 0);
    EXPECT(result, pthread_create(&threads[1], NULL, mutexThread, &state), 0);
    while (atomic_load(&state.ready) != 2) sched_yield();
    const useconds_t contention_delay_us = 10000;
    usleep(contention_delay_us);
    EXPECT(result, pthread_mutex_unlock(&state.mutex), 0);
    EXPECT(result, pthread_join(threads[0], NULL), 0);
    EXPECT(result, pthread_join(threads[1], NULL), 0);
    EXPECT(result, atomic_load(&state.error), 0);
    EXPECT(result, state.counter, 4000);
    EXPECT(result, pthread_mutex_destroy(&state.mutex), 0);
}

struct ConditionState {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    atomic_int waiting;
    int ready;
    int observed;
    int error;
};

static void *conditionThread(void *argument) {
    struct ConditionState *state = argument;
    state->error = pthread_mutex_lock(&state->mutex);
    if (state->error) return state;
    atomic_store(&state->waiting, 1);
    while (!state->ready) {
        state->error = pthread_cond_wait(&state->condition, &state->mutex);
        if (state->error) {
            pthread_mutex_unlock(&state->mutex);
            return state;
        }
    }
    state->observed = state->ready;
    state->error = pthread_mutex_unlock(&state->mutex);
    return state;
}

static void conditionSignal(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    static struct ConditionState state = {
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .condition = PTHREAD_COND_INITIALIZER,
    };
    pthread_t thread;
    EXPECT(result, pthread_create(&thread, NULL, conditionThread, &state), 0);
    while (!atomic_load(&state.waiting)) sched_yield();
    EXPECT(result, pthread_mutex_lock(&state.mutex), 0);
    state.ready = 42;
    EXPECT(result, pthread_cond_signal(&state.condition), 0);
    EXPECT(result, pthread_mutex_unlock(&state.mutex), 0);
    EXPECT(result, pthread_join(thread, NULL), 0);
    EXPECT(result, state.error, 0);
    EXPECT(result, state.observed, 42);
    EXPECT(result, pthread_cond_destroy(&state.condition), 0);
    EXPECT(result, pthread_mutex_destroy(&state.mutex), 0);
}

static pthread_once_t once_control = PTHREAD_ONCE_INIT;
static atomic_int once_count;
static atomic_int once_error;
static atomic_int once_ready;
static int once_value;

static void initializeOnce(void) {
    atomic_fetch_add(&once_count, 1);
    once_value = 1234;
}

static void *onceThread(void *argument) {
    atomic_fetch_add(&once_ready, 1);
    while (atomic_load(&once_ready) != 8) sched_yield();
    int error_code = pthread_once(&once_control, initializeOnce);
    if (error_code || once_value != 1234) {
        atomic_store(&once_error, error_code ? error_code : -1);
    }
    return argument;
}

static void onceConcurrent(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    pthread_t threads[8];
    for (int index = 0; index < 8; ++index) {
        EXPECT(result, pthread_create(&threads[index], NULL, onceThread, result), 0);
    }
    for (int index = 0; index < 8; ++index) {
        EXPECT(result, pthread_join(threads[index], NULL), 0);
    }
    EXPECT(result, atomic_load(&once_error), 0);
    EXPECT(result, atomic_load(&once_count), 1);
}

static void dependencyLookup(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    void *handle = dlopen("/fixtures/libprobe_consumer.so", RTLD_NOW | RTLD_LOCAL);
    EXPECT(result, handle != NULL, 1);
    int (*provider_value)(void) = (int (*)(void))dlsym(handle, "provider_value");
    EXPECT(result, provider_value != NULL, 1);
    EXPECT(result, provider_value(), 17);
    EXPECT(result, dlclose(handle), 0);
}

struct KeyCleanup {
    pthread_key_t key;
    unsigned calls;
    int value;
    int observed;
    int error;
    int explicit_exit;
};

static void keyDestructor(void *argument) {
    struct KeyCleanup *state = argument;
    ++state->calls;
    state->observed += state->value;
    // POSIX allows a destructor to rearm its key for another iteration.
    if (state->calls == 1) state->error = pthread_setspecific(state->key, state);
}

static void *keyCleanupThread(void *argument) {
    struct KeyCleanup *state = argument;
    state->error = pthread_setspecific(state->key, state);
    if (!state->error && pthread_getspecific(state->key) != state) state->error = -1;
    if (state->explicit_exit) pthread_exit(state);
    return state;
}

static void keyCleanup(struct probe_result *result, int explicit_exit) {
    pthread_key_t key;
    EXPECT(result, pthread_key_create(&key, keyDestructor), 0);
    struct KeyCleanup main_value = {.key = key, .value = 99};
    EXPECT(result, pthread_setspecific(key, &main_value), 0);
    for (int value = 17; value <= 18; ++value) {
        struct KeyCleanup state = {.key = key, .value = value, .explicit_exit = explicit_exit};
        pthread_t thread;
        EXPECT(result, pthread_create(&thread, NULL, keyCleanupThread, &state), 0);
        void *returned = NULL;
        EXPECT(result, pthread_join(thread, &returned), 0);
        EXPECT(result, returned == &state, 1);
        EXPECT(result, state.error, 0);
        EXPECT(result, state.calls, 2);
        EXPECT(result, state.observed, value * 2);
        EXPECT(result, pthread_getspecific(key) == &main_value, 1);
        EXPECT(result, main_value.calls, 0);
    }
    EXPECT(result, pthread_setspecific(key, NULL), 0);
    EXPECT(result, pthread_key_delete(key), 0);
}

static void keyCleanupReturn(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    keyCleanup(result, 0);
}

static void keyCleanupExit(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    keyCleanup(result, 1);
}

typedef void (*TouchTlsObjects)(struct tls_object_events *, unsigned);
struct CppWorker {
    TouchTlsObjects touch;
    struct tls_object_events events;
    atomic_int ready;
    atomic_int release;
    unsigned value;
    int explicit_exit;
};

static void *cppThread(void *argument) {
    struct CppWorker *worker = argument;
    worker->touch(&worker->events, worker->value);
    worker->touch(&worker->events, worker->value); // No second construction.
    atomic_store(&worker->ready, 1);
    while (!atomic_load(&worker->release)) sched_yield();
    if (worker->explicit_exit) pthread_exit(worker);
    return worker;
}

static void cppCleanup(struct probe_result *result, int explicit_exit, int close_pending) {
    void *library = dlopen("/fixtures/libtls_object.so", RTLD_NOW | RTLD_LOCAL);
    EXPECT(result, library != NULL, 1);
    TouchTlsObjects touch = (TouchTlsObjects)dlsym(library, "touchTlsObjects");
    EXPECT(result, touch != NULL, 1);
    struct CppWorker workers[2] = {
        {.touch = touch, .value = 17, .explicit_exit = explicit_exit},
        {.touch = touch, .value = 29, .explicit_exit = explicit_exit},
    };
    pthread_t threads[2];
    int error = pthread_create(&threads[0], NULL, cppThread, &workers[0]);
    EXPECT(result, error, 0);
    error = pthread_create(&threads[1], NULL, cppThread, &workers[1]);
    if (error) {
        atomic_store(&workers[0].release, 1);
        pthread_join(threads[0], NULL);
        EXPECT(result, error, 0);
    }
    for (unsigned index = 0; index < 2; ++index) {
        while (!atomic_load(&workers[index].ready)) sched_yield();
    }

    int close_error = close_pending ? dlclose(library) : 0;
    for (unsigned index = 0; index < 2; ++index) atomic_store(&workers[index].release, 1);
    int join_errors[2];
    void *returned[2] = {NULL, NULL};
    for (unsigned index = 0; index < 2; ++index) {
        join_errors[index] = pthread_join(threads[index], &returned[index]);
    }
    EXPECT(result, close_error, 0);
    for (unsigned index = 0; index < 2; ++index) {
        EXPECT(result, join_errors[index], 0);
        EXPECT(result, returned[index] == &workers[index], 1);
        EXPECT(result, workers[index].events.constructed, 2);
        EXPECT(result, workers[index].events.destroyed, 2);
        EXPECT(result, workers[index].events.destruction_order, 21);
        EXPECT(result, workers[index].events.value_sum, 2 * workers[index].value);
    }
    if (!close_pending) EXPECT(result, dlclose(library), 0);
}

static void cppCleanupReturn(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    cppCleanup(result, 0, 0);
}

static void cppCleanupExit(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    cppCleanup(result, 1, 0);
}

static void cppCleanupPending(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    cppCleanup(result, 0, 1);
}

static void cppProcessExit(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    void *library = dlopen("/fixtures/libtls_object.so", RTLD_NOW | RTLD_LOCAL);
    EXPECT(result, library != NULL, 1);
    void (*prepare)(unsigned) = (void (*)(unsigned))dlsym(library, "prepareTlsProcessExit");
    EXPECT(result, prepare != NULL, 1);
    prepare(current_case);

    // This case reports its result from an atexit observer, after
    // normal main-thread TLS cleanup. The runner's usual _exit is bypassed.
    exit(0);
}

struct KeyStorage {
    pthread_key_t keys[3];
    atomic_int ready;
};

struct KeyWorker {
    struct KeyStorage *storage;
    int values[3];
    int error;
};

static void *keyStorageWorker(void *argument) {
    struct KeyWorker *worker = argument;
    struct KeyStorage *storage = worker->storage;
    for (unsigned index = 0; index < 3; ++index) {
        int error = pthread_setspecific(storage->keys[index], &worker->values[index]);
        if (error) {
            worker->error = error;
        }
    }

    atomic_fetch_add(&storage->ready, 1);
    while (atomic_load(&storage->ready) != 2) sched_yield();

    for (unsigned index = 0; index < 3; ++index) {
        if (pthread_getspecific(storage->keys[index]) != &worker->values[index]) {
            worker->error = -1;
        }
    }
    return NULL;
}

static void keyStorageIsolation(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    static struct KeyStorage storage;
    static struct KeyWorker workers[2];
    static int main_values[3];
    for (unsigned index = 0; index < 3; ++index) {
        EXPECT(result, pthread_key_create(&storage.keys[index], NULL), 0);
        EXPECT(result, pthread_setspecific(storage.keys[index], &main_values[index]), 0);
    }

    pthread_t threads[2];
    for (unsigned index = 0; index < 2; ++index) {
        workers[index].storage = &storage;
        EXPECT(result, pthread_create(&threads[index], NULL, keyStorageWorker, &workers[index]), 0);
    }
    for (unsigned index = 0; index < 2; ++index) {
        EXPECT(result, pthread_join(threads[index], NULL), 0);
        EXPECT(result, workers[index].error, 0);
    }

    for (unsigned index = 0; index < 3; ++index) {
        EXPECT(result, pthread_getspecific(storage.keys[index]) == &main_values[index], 1);
        EXPECT(result, pthread_setspecific(storage.keys[index], NULL), 0);
        EXPECT(result, pthread_key_delete(storage.keys[index]), 0);
    }
}

struct RobustState {
    pthread_mutex_t mutex;
    int lock_error;
    int value;
};

static void *abandonMutex(void *argument) {
    struct RobustState *state = argument;
    state->lock_error = pthread_mutex_lock(&state->mutex);
    if (!state->lock_error) {
        state->value = 17;
    }
    // Returning with the mutex held models a worker abandoning a transaction.
    return NULL;
}

static void robustRecovery(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    static struct RobustState state;
    pthread_mutexattr_t attributes;
    EXPECT(result, pthread_mutexattr_init(&attributes), 0);
    EXPECT(result, pthread_mutexattr_setrobust(&attributes, PTHREAD_MUTEX_ROBUST), 0);
    EXPECT(result, pthread_mutex_init(&state.mutex, &attributes), 0);
    EXPECT(result, pthread_mutexattr_destroy(&attributes), 0);

    pthread_t thread;
    EXPECT(result, pthread_create(&thread, NULL, abandonMutex, &state), 0);
    EXPECT(result, pthread_join(thread, NULL), 0);
    EXPECT(result, state.lock_error, 0);

    EXPECT(result, pthread_mutex_lock(&state.mutex), EOWNERDEAD);
    EXPECT(result, state.value, 17);
    state.value = 42;
    EXPECT(result, pthread_mutex_consistent(&state.mutex), 0);
    EXPECT(result, pthread_mutex_unlock(&state.mutex), 0);

    EXPECT(result, pthread_mutex_lock(&state.mutex), 0);
    EXPECT(result, state.value, 42);
    EXPECT(result, pthread_mutex_unlock(&state.mutex), 0);
    EXPECT(result, pthread_mutex_destroy(&state.mutex), 0);
}

static _Thread_local volatile sig_atomic_t signal_received;

static void receiveSignal(int signal_number) {
    signal_received = signal_number;
}

struct SignalWorker {
    int error;
    int received;
};

static void *raiseSignal(void *argument) {
    struct SignalWorker *worker = argument;
    worker->error = raise(SIGUSR1);
    worker->received = signal_received;
    return NULL;
}

static void signalWorkerRaise(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    struct sigaction action = {.sa_handler = receiveSignal};
    struct sigaction previous;
    EXPECT(result, sigemptyset(&action.sa_mask), 0);
    EXPECT(result, sigaction(SIGUSR1, &action, &previous), 0);

    static struct SignalWorker worker;
    pthread_t thread;
    EXPECT(result, pthread_create(&thread, NULL, raiseSignal, &worker), 0);
    EXPECT(result, pthread_join(thread, NULL), 0);
    EXPECT(result, sigaction(SIGUSR1, &previous, NULL), 0);
    EXPECT(result, worker.error, 0);
    EXPECT(result, worker.received, SIGUSR1);
    EXPECT(result, signal_received, 0);
}

static void timerNotificationModes(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    struct sigevent event = {.sigev_notify = SIGEV_NONE};
    timer_t timer;
    EXPECT(result, timer_create(CLOCK_MONOTONIC, &event, &timer), 0);

    struct itimerspec deadline = {
        .it_value.tv_sec = 10,
        .it_interval.tv_sec = 10,
    };
    struct itimerspec observed;
    EXPECT(result, timer_settime(timer, 0, &deadline, NULL), 0);
    EXPECT(result, timer_gettime(timer, &observed), 0);
    EXPECT(result, timer_delete(timer), 0);
    EXPECT(result, observed.it_interval.tv_sec, 10);
    EXPECT(result, observed.it_interval.tv_nsec, 0);

    // These timers stay disarmed: creating and releasing them verifies that
    // signal notification and the default null-event form remain available.
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = SIGUSR1;
    EXPECT(result, timer_create(CLOCK_MONOTONIC, &event, &timer), 0);
    EXPECT(result, timer_delete(timer), 0);
    EXPECT(result, timer_create(CLOCK_MONOTONIC, NULL, &timer), 0);
    EXPECT(result, timer_delete(timer), 0);
}

static void queueNotificationCancel(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    char name[64];
    snprintf(name, sizeof name, "/dynloader-notify-%ld", (long)getpid());
    struct mq_attr attributes = {.mq_maxmsg = 1, .mq_msgsize = 1};
    mqd_t queue = mq_open(name, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0600, &attributes);
    EXPECT(result, queue != (mqd_t)-1, 1);
    EXPECT(result, mq_unlink(name), 0);

    struct sigevent event = {.sigev_notify = SIGEV_NONE};
    EXPECT(result, mq_notify(queue, &event), 0);
    EXPECT(result, mq_notify(queue, NULL), 0);
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = SIGUSR1;
    EXPECT(result, mq_notify(queue, &event), 0);
    EXPECT(result, mq_notify(queue, NULL), 0);

    const char sent = 'Q';
    char received = 0;
    EXPECT(result, mq_send(queue, &sent, 1, 0), 0);
    EXPECT(result, mq_receive(queue, &received, 1, NULL), 1);
    EXPECT(result, mq_close(queue), 0);
    EXPECT(result, received, sent);
}

static void convertJapanese(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    iconv_t converter = iconv_open("SHIFT_JIS", "UTF-8");
    if (converter == (iconv_t)-1 && errno == EINVAL) {
        result->status = PROBE_UNAVAILABLE;
        copyText(result->detail, sizeof result->detail, "Runtime lacks UTF-8 to SHIFT_JIS conversion");
        return;
    }
    EXPECT(result, converter != (iconv_t)-1, 1);

    // The text is 日本. Compare encoded bytes, independent of the process locale.
    char input[] = "\xe6\x97\xa5\xe6\x9c\xac";
    const unsigned char expected[] = {0x93, 0xfa, 0x96, 0x7b};
    char output[32] = {0};
    char *input_cursor = input;
    char *output_cursor = output;
    size_t input_remaining = sizeof input - 1;
    size_t output_remaining = sizeof output;
    size_t converted = iconv(converter, &input_cursor, &input_remaining, &output_cursor, &output_remaining);
    size_t flushed = iconv(converter, NULL, NULL, &output_cursor, &output_remaining);
    int close_error = iconv_close(converter);

    EXPECT(result, converted, 0);
    EXPECT(result, flushed, 0);
    EXPECT(result, input_remaining, 0);
    EXPECT(result, sizeof output - output_remaining, sizeof expected);
    EXPECT(result, memcmp(output, expected, sizeof expected), 0);
    EXPECT(result, close_error, 0);
}

struct LocaleWorker {
    locale_t locale;
    atomic_int *ready;
    const char *text;
    size_t max_character_bytes;
    size_t converted;
    wchar_t character;
    int restored;
};

static void *convertWithLocale(void *argument) {
    struct LocaleWorker *worker = argument;
    locale_t previous = uselocale(worker->locale);
    atomic_fetch_add(worker->ready, 1);
    while (atomic_load(worker->ready) != 2) sched_yield();

    mbstate_t state = {0};
    worker->max_character_bytes = MB_CUR_MAX;
    worker->converted = mbrtowc(&worker->character, worker->text, strlen(worker->text), &state);

    if (previous != (locale_t)0) {
        locale_t replaced = uselocale(previous);
        worker->restored = replaced == worker->locale;
    }
    return NULL;
}

static void localeThreadIsolation(const struct probe_host_api *host, struct probe_result *result) {
    UNUSED_HOST();
    locale_t utf8 = newlocale(LC_CTYPE_MASK, "C.UTF-8", (locale_t)0);
    if (!utf8 && errno == ENOENT) {
        result->status = PROBE_UNAVAILABLE;
        copyText(result->detail, sizeof result->detail, "Runtime lacks C.UTF-8 locale");
        return;
    }
    EXPECT(result, utf8 != (locale_t)0, 1);
    locale_t ascii = newlocale(LC_CTYPE_MASK, "C", (locale_t)0);
    EXPECT(result, ascii != (locale_t)0, 1);
    locale_t main_locale = uselocale((locale_t)0);

    static atomic_int ready;
    static struct LocaleWorker workers[2];
    workers[0].locale = utf8;
    workers[0].text = "\xc3\xa9";
    workers[1].locale = ascii;
    workers[1].text = "A";
    pthread_t threads[2];
    for (unsigned index = 0; index < 2; ++index) {
        workers[index].ready = &ready;
        EXPECT(result, pthread_create(&threads[index], NULL, convertWithLocale, &workers[index]), 0);
    }
    for (unsigned index = 0; index < 2; ++index) {
        EXPECT(result, pthread_join(threads[index], NULL), 0);
    }
    freelocale(utf8);
    freelocale(ascii);

    EXPECT(result, workers[0].converted, 2);
    EXPECT(result, workers[0].character, 0xe9);
    EXPECT(result, workers[0].max_character_bytes >= 2, 1);
    EXPECT(result, workers[1].converted, 1);
    EXPECT(result, workers[1].character, L'A');
    EXPECT(result, workers[1].max_character_bytes, 1);
    EXPECT(result, workers[0].restored, 1);
    EXPECT(result, workers[1].restored, 1);
    EXPECT(result, uselocale((locale_t)0) == main_locale, 1);
}

static const struct {
    const char *name;
    void (*run)(const struct probe_host_api *, struct probe_result *);
} cases[] = {
    {"startup.constructors_dependencies", constructors},
    {"errno.failure", errnoFailure},
    {"errno.thread_isolation", errnoIsolation},
    {"allocation.basic", allocation},
    {"allocation.overflow", allocationOverflow},
    {"allocation.invalid_alignment", allocationInvalidAlignment},
    {"allocation.libc_buffer", allocationLibcBuffer},
    {"tls.initialization_isolation", tlsIsolation},
    {"thread.join_value", threadJoin},
    {"thread.join_null", threadNull},
    {"thread.host_callback", threadCallback},
    {"synchronization.mutex_contention", mutexContention},
    {"synchronization.condition_signal", conditionSignal},
    {"synchronization.once_concurrent", onceConcurrent},
    {"loader.dependency_lookup", dependencyLookup},
    {"loader.runpath_chain", runpathChain},
    {"loader.runpath_scope", runpathScope},
    {"thread.key_cleanup_return", keyCleanupReturn},
    {"thread.key_cleanup_exit", keyCleanupExit},
    {"cpp.tls_destructor_return", cppCleanupReturn},
    {"cpp.tls_destructor_exit", cppCleanupExit},
    {"cpp.pending_tls_destructor", cppCleanupPending},
    {"cpp.tls_process_exit", cppProcessExit},
    {"thread.key_storage_isolation", keyStorageIsolation},
    {"synchronization.robust_recovery", robustRecovery},
    {"signal.worker_raise", signalWorkerRaise},
    {"async.timer_notification_modes", timerNotificationModes},
    {"async.queue_notification_cancel", queueNotificationCancel},
    {"conversion.shift_jis", convertJapanese},
    {"locale.thread_isolation", localeThreadIsolation},
};

uint32_t probe_abi_version(void) { return PROBE_ABI_VERSION; }
uint32_t probe_case_count(void) { return sizeof cases / sizeof cases[0]; }
uint32_t probe_result_size(void) { return sizeof(struct probe_result); }
uint32_t probe_case_info_size(void) { return sizeof(struct probe_case_info); }
uint32_t probe_host_api_size(void) { return sizeof(struct probe_host_api); }

int probe_describe(uint32_t index, struct probe_case_info *info) {
    if (index >= probe_case_count() || info->struct_size != sizeof *info) return -1;
    info->id = index;
    copyText(info->name, sizeof info->name, cases[index].name);
    return 0;
}

int probe_run(uint32_t id, const struct probe_host_api *host, struct probe_result *result) {
    if (id >= probe_case_count() || host->abi_version != PROBE_ABI_VERSION ||
        host->struct_size != sizeof *host || result->struct_size != sizeof *result) {
        return -1;
    }
    memset(result, 0, sizeof *result);
    result->struct_size = sizeof *result;
    result->status = PROBE_PASS;
    current_case = id;
    cases[id].run(host, result);
    return 0;
}
