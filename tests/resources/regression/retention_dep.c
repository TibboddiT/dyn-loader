__asm__(".pushsection .data\n"
        ".globl retentionIdentity\n.type retentionIdentity, @gnu_unique_object\n"
        ".size retentionIdentity, 4\nretentionIdentity: .long 5\n.popsection\n");
extern int retentionIdentity;

__attribute__((weak)) int retentionValue(void) { return 7; }
__attribute__((visibility("protected"))) int retentionProtected(void) { return 11; }
int retentionRead(void) {
    return retentionValue() + retentionProtected() + retentionIdentity;
}
