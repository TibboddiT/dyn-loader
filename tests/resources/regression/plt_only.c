// Build without startup objects: the external call requires a PLT relocation,
// while avoiding an ordinary RELA table supplied by constructors or data pointers.
extern int puts(const char *);
int answer(void) { return puts("") >= 0 ? 42 : 0; }
