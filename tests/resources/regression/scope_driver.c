/* The same scenario runs through native dlopen or DynLoader's substitutes. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        const char *loader_error = dlerror(); \
        fprintf(stderr, "scope check failed at line %d: %s (%s)\n", \
                __LINE__, #condition, loader_error ? loader_error : "no loader error"); \
        return __LINE__; \
    } \
} while (0)

typedef int (*Probe)(void);
typedef void (*Observe)(int *finalization_count);

/* Parent function (11) + parent TLS (7) + sibling (13) + sibling choice (17).
 * Choosing the leaf's definition (99) or the other root's parent (21) differs. */
static const int expected_group_value = 48;

static void *openInDirectory(const char *directory, const char *name, int flags) {
    char path[4096];
    int size = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (size < 0 || (size_t)size >= sizeof(path)) return NULL;

    return dlopen(path, flags);
}

int scopeRun(const char *directory) {
    const int flags = RTLD_NOW | RTLD_LOCAL;
    char nested_path[4096];
    int length = snprintf(nested_path, sizeof(nested_path), "%s/scope_nested.so", directory);
    CHECK(length > 0 && (size_t)length < sizeof(nested_path));
    CHECK(setenv("DYNLOADER_TEST_SCOPE_NESTED", nested_path, 1) == 0);

    void *unrelated = openInDirectory(directory, "scope_unrelated.so", flags);
    CHECK(unrelated);

    /* An unrelated local provider must not make a standalone child loadable. */
    CHECK(!openInDirectory(directory, "scope_child.so", flags));

    void *root = openInDirectory(directory, "scope_root.so", flags);
    CHECK(root);

    Probe check = (Probe)dlsym(root, "scope_check");
    CHECK(check && check() == expected_group_value);

    void *child = openInDirectory(directory, "scope_child.so", flags);
    CHECK(child);

    Probe child_check = (Probe)dlsym(child, "scope_child");
    CHECK(child_check && child_check() == expected_group_value);

    /* Handle lookup still follows the handle's dependency tree, not relocation scope. */
    CHECK(!dlsym(child, "scope_parent"));

    static int root_finalized, child_finalized;
    root_finalized = child_finalized = 0;
    Observe observe = (Observe)dlsym(root, "scope_observe");
    Observe observe_child = (Observe)dlsym(child, "scope_child_observe");
    CHECK(observe && observe_child);
    observe(&root_finalized);
    observe_child(&child_finalized);

    /* Sharing the child with another root must not rebind existing relocations. */
    void *other_root = openInDirectory(directory, "scope_other.so", flags);
    CHECK(other_root);

    Probe other_check = (Probe)dlsym(other_root, "scope_check");
    CHECK(other_check && other_check() == expected_group_value);

    CHECK(dlclose(root) == 0);
    CHECK(root_finalized == 0 && child_finalized == 0);
    CHECK(child_check() == expected_group_value && other_check() == expected_group_value);

    CHECK(dlclose(other_root) == 0);
    CHECK(root_finalized == 0 && child_finalized == 0);
    CHECK(child_check() == expected_group_value);

    CHECK(dlclose(child) == 0);
#if !defined(SCOPE_NATIVE_MAIN) || defined(__GLIBC__)
    /* musl's native dlclose deliberately does not unload DSOs. DynLoader does. */
    CHECK(root_finalized == 1 && child_finalized == 1);
    CHECK(!openInDirectory(directory, "scope_root.so", flags | RTLD_NOLOAD));
    CHECK(!openInDirectory(directory, "scope_child.so", flags | RTLD_NOLOAD));
    CHECK(!openInDirectory(directory, "scope_sibling.so", flags | RTLD_NOLOAD));
#endif

    root = openInDirectory(directory, "scope_root.so", flags);
    CHECK(root);
    check = (Probe)dlsym(root, "scope_check");
    CHECK(check && check() == expected_group_value);
    CHECK(dlclose(root) == 0);
    CHECK(dlclose(unrelated) == 0);
    CHECK(unsetenv("DYNLOADER_TEST_SCOPE_NESTED") == 0);

    return 0;
}

#ifdef SCOPE_NATIVE_MAIN
int main(int argc, char **argv) { return argc == 2 ? scopeRun(argv[1]) : 2; }
#endif
