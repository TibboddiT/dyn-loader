/* Build roles selected by SCOPE_*:
 *   root / other -> child -> leaf
 *                -> sibling
 *   nested -> nested_child
 *   unrelated (a separate local group)
 *
 * child needs root's function/TLS and sibling's function. Both sibling and leaf
 * define scope_choice; breadth-first lookup must choose sibling. Root's
 * constructor opens the independent nested group. "other" reuses the same child.
 */
#if defined(SCOPE_ROOT)
#include <dlfcn.h>
#include <stdlib.h>

#ifndef PARENT_VALUE
#define PARENT_VALUE 11
#endif

_Thread_local int scope_tls = 7;
extern int scope_child(void);

static int nested_ok;
static int *finalizations;

int scope_parent(void) { return PARENT_VALUE; }
void scope_observe(int *count) { finalizations = count; }

__attribute__((constructor)) static void initialize(void) {
    const char *path = getenv("DYNLOADER_TEST_SCOPE_NESTED");
    if (!path) return;

    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) return;

    int (*check)(void) = (int (*)(void))dlsym(handle, "scope_nested_check");
    nested_ok = check && check() == 57;

    if (dlclose(handle)) nested_ok = 0;
}

__attribute__((destructor)) static void finalize(void) {
    if (finalizations) ++*finalizations;
}

int scope_check(void) { return nested_ok ? scope_child() : -1; }

#elif defined(SCOPE_CHILD)
extern int scope_parent(void);
extern int scope_sibling(void);
extern int scope_choice(void);
extern int scope_leaf_anchor(void);
extern _Thread_local int scope_tls;

static int *finalizations;

void scope_child_observe(int *count) { finalizations = count; }

__attribute__((destructor)) static void finalize(void) {
    if (finalizations) ++*finalizations;
}

int scope_child(void) {
    return scope_parent() + scope_tls + scope_sibling() + scope_choice() + scope_leaf_anchor();
}

#elif defined(SCOPE_SIBLING)
int scope_sibling(void) { return 13; }
int scope_choice(void) { return 17; }

#elif defined(SCOPE_LEAF)
int scope_choice(void) { return 99; }
int scope_leaf_anchor(void) { return 0; }

#elif defined(SCOPE_UNRELATED)
int scope_parent(void) { return 800; }
int scope_sibling(void) { return 700; }
int scope_choice(void) { return 600; }
_Thread_local int scope_tls = 900;

#elif defined(SCOPE_NESTED)
extern int scope_nested_child(void);
int scope_nested_provider(void) { return 57; }
int scope_nested_check(void) { return scope_nested_child(); }

#elif defined(SCOPE_NESTED_CHILD)
extern int scope_nested_provider(void);
int scope_nested_child(void) { return scope_nested_provider(); }
#endif
