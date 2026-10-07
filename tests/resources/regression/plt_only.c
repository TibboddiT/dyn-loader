extern int puts(const char *);
int answer(void) { return puts("") >= 0 ? 42 : 0; }
