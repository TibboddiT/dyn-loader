#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>

/* The catalog marks this fixture's tests as glibc-only. Musl SDKs reject
 * IFUNC attributes; keep their artifact valid without claiming resolver coverage. */
#ifdef __GLIBC__
static int early_reentry_rejected;
static int late_reentry_rejected;
typedef int (*ValueFunction)(void);

static int resolved_value(void) { return 41; }

static ValueFunction early_resolver(void) {
    early_reentry_rejected = dlopen(NULL, RTLD_NOW) == NULL;
    return resolved_value;
}

static ValueFunction late_resolver(void) {
    late_reentry_rejected = dlopen(NULL, RTLD_NOW) == NULL;
    return resolved_value;
}

static int earlyValue(void) __attribute__((ifunc("early_resolver")));
int lateValue(void) __attribute__((ifunc("late_resolver")));
static ValueFunction volatile early_binding = earlyValue;

int earlyResult(void) { return early_binding(); }
int earlyReentryRejected(void) { return early_reentry_rejected; }
int lateReentryRejected(void) { return late_reentry_rejected; }
#else
int resolverProbeUnavailable(void) { return 1; }
#endif
