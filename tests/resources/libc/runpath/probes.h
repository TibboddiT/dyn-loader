/* Included after EXPECT by probe.c. Each catalog entry runs in a fresh process;
 * environment-sensitive cases receive startup settings from the coordinator. */
#include "search_result.h"

#define SEARCH_ROOT "/fixtures/runpath/search/"

static int searchValue(const char *path) {
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library) return SEARCH_LOAD_FAILED;

    int (*value)(void) = (int (*)(void))dlsym(library, "search_value");
    int observed = value ? value() : SEARCH_SYMBOL_MISSING;

    if (dlclose(library)) return SEARCH_CLOSE_FAILED;
    return observed;
}

static void searchInDirectory(struct probe_result *result, const char *directory,
                              const char *path, int expected) {
    int saved_directory = open(".", O_RDONLY | O_DIRECTORY);
    EXPECT(result, saved_directory >= 0, 1);

    int changed = chdir(directory);
    int observed = changed == 0 ? searchValue(path) : SEARCH_DIRECTORY_FAILED;

    int restored = fchdir(saved_directory);
    close(saved_directory);

    EXPECT(result, changed, 0);
    EXPECT(result, restored, 0);
    EXPECT(result, observed, expected);
}

#ifdef __GLIBC__
#define SEARCH_INHERITED_RUNPATH SEARCH_LOAD_FAILED
#define SEARCH_ENV_RPATH 11
#define SEARCH_RELOADED 1122
#define SEARCH_DYNAMIC_DIRECT 11
#define SEARCH_EMPTY_COMPONENT 11
#define SEARCH_RESIDENT_NAME 1111
#else
/* musl inherits RUNPATH, searches the environment first, and retains dlclosed
 * objects. These are reference expectations, not assumptions imposed on glibc. */
#define SEARCH_INHERITED_RUNPATH 11
#define SEARCH_ENV_RPATH 22
#define SEARCH_RELOADED 1111
#define SEARCH_DYNAMIC_DIRECT SEARCH_LOAD_FAILED
#define SEARCH_EMPTY_COMPONENT SEARCH_LOAD_FAILED
#define SEARCH_RESIDENT_NAME 1122
#endif

#define SEARCH_CASE(function, directory, path, expected) \
    static void function(const struct probe_host_api *host, struct probe_result *result) { \
        UNUSED_HOST(); \
        searchInDirectory(result, directory, path, expected); \
    }
SEARCH_CASE(searchRpath, "/fixtures", SEARCH_ROOT "rpath.so", 11)
SEARCH_CASE(searchRunpath, "/fixtures", SEARCH_ROOT "runpath.so", 11)
SEARCH_CASE(searchEnvRpath, "/fixtures", SEARCH_ROOT "rpath.so", SEARCH_ENV_RPATH)
SEARCH_CASE(searchEnvRunpath, "/fixtures", SEARCH_ROOT "runpath.so", 22)
SEARCH_CASE(searchInherited, "/fixtures", SEARCH_ROOT "inherited.so", 11)
SEARCH_CASE(searchScoped, "/fixtures", SEARCH_ROOT "scoped.so", SEARCH_INHERITED_RUNPATH)
SEARCH_CASE(searchBlocked, "/fixtures", SEARCH_ROOT "blocked.so", SEARCH_INHERITED_RUNPATH)
SEARCH_CASE(searchOwner, "/fixtures", SEARCH_ROOT "owner.so", 11)
SEARCH_CASE(searchBoth, "/fixtures", SEARCH_ROOT "both.so", 22)
SEARCH_CASE(searchRelativeRequest, SEARCH_ROOT, "./runpath.so", 11)
SEARCH_CASE(searchEnvRelative, "/fixtures", SEARCH_ROOT "bare.so", 11)
SEARCH_CASE(searchEnvComponent, SEARCH_ROOT "leaf", SEARCH_ROOT "bare.so", SEARCH_EMPTY_COMPONENT)
SEARCH_CASE(searchEnvEmpty, SEARCH_ROOT "leaf", SEARCH_ROOT "bare.so", SEARCH_LOAD_FAILED)
SEARCH_CASE(searchRelativeRunpath, "/fixtures", SEARCH_ROOT "relative.so", 11)
SEARCH_CASE(searchEmptyRunpath, SEARCH_ROOT "leaf", SEARCH_ROOT "empty.so", SEARCH_LOAD_FAILED)
SEARCH_CASE(searchRunpathComponent, SEARCH_ROOT "leaf", SEARCH_ROOT "empty-component.so", SEARCH_EMPTY_COMPONENT)
SEARCH_CASE(searchAliasOrigin, "/fixtures", SEARCH_ROOT "alias/runpath.so", 33)
SEARCH_CASE(searchDynamicDirect, "/fixtures", SEARCH_ROOT "dynamic-direct.so", SEARCH_DYNAMIC_DIRECT)
SEARCH_CASE(searchDynamicRpath, "/fixtures", SEARCH_ROOT "dynamic-rpath.so", SEARCH_LOAD_FAILED)
SEARCH_CASE(searchDynamicRunpath, "/fixtures", SEARCH_ROOT "dynamic-runpath.so", SEARCH_LOAD_FAILED)
SEARCH_CASE(searchReload, SEARCH_ROOT, "./reload.so", SEARCH_RELOADED)
SEARCH_CASE(searchResidentName, SEARCH_ROOT, "./change-cwd.so", SEARCH_RESIDENT_NAME)
#undef SEARCH_CASE
