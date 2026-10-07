static int state = 21;
// The overflow test needs a writable segment with BSS after its file data.
char relr_bss[16];
static int *pointers[] = { &state, &state, &state, &state };
int answer(void) { return *pointers[0] + *pointers[3]; }
