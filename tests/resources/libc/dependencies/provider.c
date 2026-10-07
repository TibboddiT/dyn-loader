static int initialized;
__attribute__((constructor)) static void initialize(void) { initialized = 17; }
int provider_value(void) { return initialized; }
