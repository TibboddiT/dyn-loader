// This intermediate object's own RUNPATH differs between the two fixture graphs.
extern int runpath_leaf(void);

int runpath_middle(void) {
    return runpath_leaf() + 1;
}
