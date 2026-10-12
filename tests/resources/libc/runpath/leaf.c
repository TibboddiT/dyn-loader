// Keep the leaf independent of libc so only the intended dependency path matters.
int runpath_leaf(void) {
    return 40;
}
