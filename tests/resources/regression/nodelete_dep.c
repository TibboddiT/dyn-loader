static int value;
static int *finalizations;
__attribute__((constructor)) static void initialize(void) { value = 17; }
__attribute__((destructor)) static void finalize(void) {
    if (finalizations) ++*finalizations;
}
int nodeleteDependencyValue(void) { return value; }
void nodeleteDependencyObserve(int *out) { finalizations = out; value = 29; }
