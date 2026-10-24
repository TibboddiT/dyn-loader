/* Explicit ELF binding keeps this fixture independent of compiler C++ defaults. */
__asm__(".pushsection .data\n"
        ".globl uniqueValue\n.type uniqueValue, @gnu_unique_object\n"
        ".size uniqueValue, 4\nuniqueValue: .long 17\n.popsection\n");
extern int uniqueValue;

#ifndef UNIQUE_LOOKUP_ONLY
int *uniqueAddress(void) { return &uniqueValue; }
#endif

static int constructors;
static int *finalizations;
__attribute__((constructor)) static void initialize(void) { ++constructors; }
__attribute__((destructor)) static void finalize(void) {
    if (finalizations) ++*finalizations;
}
void uniqueObserve(int *out) { finalizations = out; }
int uniqueConstructors(void) { return constructors; }

#ifdef UNIQUE_BROKEN
extern int uniqueMissing(void);
int uniqueFail(void) { return uniqueMissing(); }
#endif
