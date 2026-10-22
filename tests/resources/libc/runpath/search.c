/* SDK-built, deliberately tiny graphs for the libc reference comparisons. */
#include "search_result.h"

#if defined(SEARCH_LEAF)
int search_answer(void) { return SEARCH_VALUE; }
#elif defined(SEARCH_MIDDLE)
extern int search_answer(void);
int search_middle(void) { return search_answer(); }
#elif defined(SEARCH_INDIRECT)
extern int search_middle(void);
int search_value(void) { return search_middle(); }
#elif defined(SEARCH_CONSTANT)
int search_value(void) { return SEARCH_VALUE; }
#elif defined(SEARCH_DYNAMIC)
#include <dlfcn.h>
int search_value(void) {
    void *handle = dlopen(SEARCH_LIBRARY, RTLD_NOW | RTLD_LOCAL);
    if (!handle) return SEARCH_LOAD_FAILED;

    int (*value)(void) = (int (*)(void))dlsym(handle, SEARCH_SYMBOL);
    int result = value ? value() : SEARCH_SYMBOL_MISSING;

    if (dlclose(handle)) return SEARCH_CLOSE_FAILED;
    return result;
}
#elif defined(SEARCH_RELOAD)
#include <dlfcn.h>
static int loadSearchValue(const char *path) {
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) return SEARCH_LOAD_FAILED;

    int (*value)(void) = (int (*)(void))dlsym(handle, "search_value");
    int result = value ? value() : SEARCH_SYMBOL_MISSING;

    if (dlclose(handle)) return SEARCH_CLOSE_FAILED;
    return result;
}

int search_value(void) {
    int first = loadSearchValue("./inherited.so");
    int second = loadSearchValue("./alternate.so");
    return first * 100 + second;
}
#elif defined(SEARCH_CWD)
#include <dlfcn.h>
#include <unistd.h>
int search_value(void) {
    if (chdir("leaf")) return -1;

    void *first = dlopen("./relative-root.so", RTLD_NOW | RTLD_LOCAL);
    if (!first || chdir("../override")) return -2;

    void *second = dlopen("./relative-root.so", RTLD_NOW | RTLD_LOCAL);
    if (!second) return -3;

    void *resident = dlopen("./relative-root.so", RTLD_NOW | RTLD_NOLOAD);
    if (!resident || resident != second) return -4;

    int (*first_value)(void) = (int (*)(void))dlsym(first, "search_value");
    int (*second_value)(void) = (int (*)(void))dlsym(second, "search_value");
    if (!first_value || !second_value) return -5;

    int result = first_value() * 100 + second_value();
    dlclose(resident);
    dlclose(second);
    dlclose(first);

    return result;
}
#else
extern int search_answer(void);
int search_value(void) { return search_answer(); }
#endif
