/* glibc loads a gconv module here; musl performs the same conversion internally. */
#include <iconv.h>
#include <stddef.h>

unsigned constructor_count;
int constructor_status;
unsigned char converted[12];

__attribute__((constructor)) static void initialize(void) {
    ++constructor_count;
    iconv_t descriptor = iconv_open("UTF-32LE", "UTF-8");
    if (descriptor == (iconv_t)-1) {
        constructor_status = 1;
        return;
    }

    char input[] = "A\xc3\xa9\xf0\x9f\x99\x82";
    char *input_pointer = input;
    size_t input_left = sizeof(input) - 1;
    char *output_pointer = (char *)converted;
    size_t output_left = sizeof(converted);
    size_t result = iconv(descriptor, &input_pointer, &input_left, &output_pointer, &output_left);
    if (result != 0 || input_left != 0 || output_left != 0) constructor_status = 2;

    if (iconv_close(descriptor) != 0) constructor_status = 3;
}
