/* Replace SONAME with RUNPATH, either keeping the supplied string (both tags)
 * or selecting dynstr[0] (an empty RUNPATH). */
#include <elf.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

enum ExitStatus {
    INVALID_ARGUMENTS = 1,
    OPEN_FAILED = 2,
    INVALID_HEADER = 3,
    PROGRAM_HEADER_READ_FAILED = 4,
    DYNAMIC_ENTRY_READ_FAILED = 5,
    DYNAMIC_ENTRY_WRITE_FAILED = 6,
};

int main(int argc, char **argv) {
    bool empty_runpath = argc == 3 && strcmp(argv[2], "empty") == 0;
    if (argc != 2 && !empty_runpath) return INVALID_ARGUMENTS;

    FILE *file = fopen(argv[1], "r+b");
    if (!file) return OPEN_FAILED;

    Elf64_Ehdr header;
    if (fread(&header, sizeof header, 1, file) != 1 ||
        memcmp(header.e_ident, ELFMAG, SELFMAG) ||
        header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_phentsize != sizeof(Elf64_Phdr)) return INVALID_HEADER;

    int changed_count = 0;
    for (unsigned index = 0; index < header.e_phnum; ++index) {
        Elf64_Phdr program_header;
        long header_position = (long)(header.e_phoff + index * sizeof program_header);
        if (fseek(file, header_position, SEEK_SET) ||
            fread(&program_header, sizeof program_header, 1, file) != 1) return PROGRAM_HEADER_READ_FAILED;
        if (program_header.p_type != PT_DYNAMIC) continue;

        for (Elf64_Xword offset = 0; offset + sizeof(Elf64_Dyn) <= program_header.p_filesz; offset += sizeof(Elf64_Dyn)) {
            Elf64_Dyn entry;
            long position = (long)(program_header.p_offset + offset);
            if (fseek(file, position, SEEK_SET) ||
                fread(&entry, sizeof entry, 1, file) != 1) return DYNAMIC_ENTRY_READ_FAILED;
            if (entry.d_tag != DT_SONAME) continue;

            entry.d_tag = DT_RUNPATH;
            if (empty_runpath) entry.d_un.d_val = 0; /* dynstr[0] is the empty string */

            if (fseek(file, position, SEEK_SET) ||
                fwrite(&entry, sizeof entry, 1, file) != 1) return DYNAMIC_ENTRY_WRITE_FAILED;
            ++changed_count;
        }
    }
    return fclose(file) || changed_count != 1;
}
