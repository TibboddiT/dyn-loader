// The root exports 42 only if both RUNPATH-dependent edges resolve correctly.
extern int runpath_middle(void);

int runpath_value(void) {
    return runpath_middle() + 1;
}
