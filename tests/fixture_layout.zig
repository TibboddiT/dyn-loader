//! Adds a 4 KiB file prefix without changing mapped addresses or relocations.
const std = @import("std");
const elf = std.elf;

pub const revision = 1;

const prefix_size_bytes = 4096;
const elf_header_size = @sizeOf(elf.Elf64_Ehdr);
const program_header_size = @sizeOf(elf.Elf64.Phdr);
const section_header_size = @sizeOf(elf.Elf64.Shdr);

pub fn createNonIdentityLayout(allocator: std.mem.Allocator, source_bytes: []const u8) ![]u8 {
    if (source_bytes.len < elf_header_size) return error.InvalidFixtureElf;

    const source_header = std.mem.bytesToValue(elf.Elf64_Ehdr, source_bytes[0..elf_header_size]);

    const valid_format = std.mem.eql(u8, source_header.e_ident[0..4], elf.MAGIC) and
        source_header.e_ident[elf.EI_CLASS] == elf.ELFCLASS64 and
        source_header.e_ident[elf.EI_DATA] == elf.ELFDATA2LSB and
        source_header.e_type == elf.ET.DYN and
        source_header.e_machine == elf.EM.X86_64;

    if (!valid_format) return error.InvalidFixtureElf;

    if (source_header.e_phentsize != program_header_size or source_header.e_shentsize != section_header_size) {
        return error.InvalidFixtureElf;
    }

    const program_table_size_bytes = @as(u64, source_header.e_phnum) * source_header.e_phentsize;
    const section_table_size_bytes = @as(u64, source_header.e_shnum) * source_header.e_shentsize;

    try validateFileRange(source_bytes.len, source_header.e_phoff, program_table_size_bytes);
    try validateFileRange(source_bytes.len, source_header.e_shoff, section_table_size_bytes);

    const output_bytes = try allocator.alloc(u8, source_bytes.len + prefix_size_bytes);
    errdefer allocator.free(output_bytes);

    @memset(output_bytes[0..prefix_size_bytes], 0);
    @memcpy(output_bytes[prefix_size_bytes..], source_bytes);

    // The reader uses the new header. The mapped image keeps the original
    // header so its program-header address stays valid.
    @memcpy(output_bytes[0..elf_header_size], source_bytes[0..elf_header_size]);

    const file_header = std.mem.bytesAsValue(elf.Elf64_Ehdr, output_bytes[0..elf_header_size]);
    file_header.e_phoff += prefix_size_bytes;
    if (file_header.e_shoff != 0) {
        file_header.e_shoff += prefix_size_bytes;
    }

    for (0..source_header.e_phnum) |index| {
        const header_file_offset = file_header.e_phoff + index * source_header.e_phentsize;
        const header_bytes = output_bytes[header_file_offset..][0..program_header_size];
        const program_header = std.mem.bytesAsValue(elf.Elf64.Phdr, header_bytes);

        try validateFileRange(source_bytes.len, program_header.offset, program_header.filesz);

        if (program_header.type == .LOAD and program_header.@"align" > 1) {
            if (prefix_size_bytes % program_header.@"align" != 0) return error.UnsupportedFixtureAlignment;
        }

        program_header.offset += prefix_size_bytes;
    }

    for (0..source_header.e_shnum) |index| {
        const header_file_offset = file_header.e_shoff + index * source_header.e_shentsize;
        const header_bytes = output_bytes[header_file_offset..][0..section_header_size];
        const section_header = std.mem.bytesAsValue(elf.Elf64.Shdr, header_bytes);

        if (section_header.type != .NOBITS) {
            try validateFileRange(source_bytes.len, section_header.offset, section_header.size);
        }

        if (section_header.offset != 0) {
            section_header.offset += prefix_size_bytes;
        }
    }

    return output_bytes;
}

fn validateFileRange(file_size_bytes: usize, offset_bytes: u64, size_bytes: u64) !void {
    if (offset_bytes > file_size_bytes or size_bytes > file_size_bytes - offset_bytes) {
        return error.InvalidFixtureElf;
    }
}

test "layout transform preserves payload and virtual addresses, rejects truncated tables" {
    var source_bytes: [512]u8 = @splat(0);
    const program_header_offset = elf_header_size;
    const payload_offset = 128;

    const header = std.mem.bytesAsValue(elf.Elf64_Ehdr, source_bytes[0..elf_header_size]);
    @memcpy(header.e_ident[0..4], elf.MAGIC);
    header.e_ident[elf.EI_CLASS] = elf.ELFCLASS64;
    header.e_ident[elf.EI_DATA] = elf.ELFDATA2LSB;
    header.e_type = elf.ET.DYN;
    header.e_machine = elf.EM.X86_64;
    header.e_phoff = program_header_offset;
    header.e_phnum = 1;
    header.e_phentsize = program_header_size;
    header.e_shentsize = section_header_size;

    const program_header_bytes = source_bytes[program_header_offset..][0..program_header_size];
    const program_header = std.mem.bytesAsValue(elf.Elf64.Phdr, program_header_bytes);
    program_header.type = .LOAD;
    program_header.offset = payload_offset;
    program_header.vaddr = payload_offset;
    program_header.filesz = 4;
    program_header.memsz = 8;
    program_header.@"align" = 4096;

    @memcpy(source_bytes[payload_offset..][0..4], "data");

    const output_bytes = try createNonIdentityLayout(std.testing.allocator, &source_bytes);
    defer std.testing.allocator.free(output_bytes);

    const shifted_header_offset = program_header_offset + prefix_size_bytes;
    const shifted_header_bytes = output_bytes[shifted_header_offset..][0..program_header_size];
    const shifted_header = std.mem.bytesToValue(elf.Elf64.Phdr, shifted_header_bytes);

    try std.testing.expectEqual(program_header.vaddr, shifted_header.vaddr);
    try std.testing.expectEqual(program_header.offset + prefix_size_bytes, shifted_header.offset);
    try std.testing.expectEqualSlices(u8, "data", output_bytes[shifted_header.offset..][0..4]);

    header.e_phoff = 500;
    try std.testing.expectError(error.InvalidFixtureElf, createNonIdentityLayout(std.testing.allocator, &source_bytes));
}
