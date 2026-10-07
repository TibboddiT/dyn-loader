#include <dlfcn.h>
#include <pthread.h>

void *openProbe(const char *path) { return dlopen(path, RTLD_NOW); }
void *openGlobalProbe(const char *path) { return dlopen(path, RTLD_NOW | RTLD_GLOBAL); }
void *symbolProbe(void *handle, const char *name) { return dlsym(handle, name); }
int closeProbe(void *handle) { return dlclose(handle); }
int startProbe(pthread_t *thread, void *(*routine)(void *), void *argument) {
    return pthread_create(thread, NULL, routine, argument);
}
int joinProbe(pthread_t thread) { return pthread_join(thread, NULL); }
