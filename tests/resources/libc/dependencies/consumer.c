extern int provider_value(void);
static int constructor_value;
__attribute__((constructor)) static void initialize(void) {
    constructor_value = provider_value() + 25;
}
int consumer_value(void) { return constructor_value; }
