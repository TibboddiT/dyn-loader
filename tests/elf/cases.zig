const std = @import("std");
const elf = std.elf;

const runner = @import("elf_runner");
const expectReturn = runner.expectReturn;
const expectOutParam = runner.expectOutParam;
const LibraryState = @import("regression_abi").LibraryState;

const initial_state: LibraryState = .{
    .initialized_global = 7,
    .zeroed_global = 0,
    .tls_value = 11,
    .constructor_count = 1,
};

pub const cases: []const runner.Case = &.{
    .{
        .name = "non-identity-layout",
        .expect = .{ .loaded = &.{expectOutParam(LibraryState, "readState", initial_state)} },
    },
    .{
        .name = "rela-entry-zero",
        .mutation = .{ .tag_value = .{ .tag = elf.DT_RELAENT, .value = 0 } },
        .expect = .{ .load_error = error.InvalidRelocationEntrySize },
    },
    .{
        .name = "rela-entry-wrong",
        .mutation = .{ .tag_value = .{ .tag = elf.DT_RELAENT, .value = 8 } },
        .expect = .{ .load_error = error.InvalidRelocationEntrySize },
    },
    .{
        .name = "rela-size",
        .mutation = .{ .tag_value = .{ .tag = elf.DT_RELASZ, .value = 1 } },
        .expect = .{ .load_error = error.InvalidRelocationTableSize },
    },
    .{
        .name = "rela-missing-entry",
        .mutation = .{ .remove_tag = elf.DT_RELAENT },
        .expect = .{ .load_error = error.MissingRelocationEntrySize },
    },
    .{
        .name = "rela-missing-size",
        .mutation = .{ .remove_tag = elf.DT_RELASZ },
        .expect = .{ .load_error = error.MissingRelocationTableSize },
    },
    .{
        .name = "rela-missing-address",
        .mutation = .{ .remove_tag = elf.DT_RELA },
        .expect = .{ .load_error = error.MissingRelocationTableAddress },
    },
    .{
        .name = "rela-outside",
        .mutation = .{ .tag_value = .{ .tag = elf.DT_RELA, .value = std.math.maxInt(u64) - 15 } },
        .expect = .{ .load_error = error.AddressNotInFileSegments },
    },
    .{
        .name = "rela-in-bss",
        .mutation = .{ .rela_file_end = 0 },
        .expect = .{ .load_error = error.AddressNotInFileSegments },
    },
    .{
        .name = "rela-crossing-end",
        .mutation = .{ .rela_file_end = 8 },
        .expect = .{ .load_error = error.AddressNotInFileSegments },
    },
    .{
        .name = "rela-unknown-type",
        .mutation = .{ .rela_type = std.math.maxInt(u32) },
        .expect = .{ .load_error = error.UnsupportedRelocationType },
    },
    .{
        .name = "rela-unknown-symbol",
        .mutation = .{ .rela_symbol = std.math.maxInt(u32) },
        .expect = .{ .load_error = error.InvalidSymbolIndex },
    },
    .{
        .name = "rela-bad-destination",
        .mutation = .{ .rela_destination = std.math.maxInt(u64) - 7 },
        .expect = .{ .load_error = error.AddressNotInMappedSegments },
    },
    .{
        .name = "rela-readonly-destination",
        .mutation = .{ .rela_destination = 0 },
        .expect = .{ .load_error = error.UnsupportedTextRelocation },
    },
    .{
        .name = "relative-nonzero-symbol",
        .mutation = .{ .rela_symbol = 1 },
        .expect = .{ .load_error = error.InvalidRelocationSymbol },
    },
    .{
        .name = "irelative-non-executable",
        .mutation = .irelative_data,
        .expect = .{ .load_error = error.InvalidRelocationResolver },
    },
    .{
        .name = "plt-rel",
        .mutation = .{ .tag_value = .{ .tag = elf.DT_PLTREL, .value = elf.DT_REL } },
        .expect = .{ .load_error = error.UnsupportedRelocationFormat },
    },
    .{
        .name = "plt-missing-format",
        .mutation = .{ .remove_tag = elf.DT_PLTREL },
        .expect = .{ .load_error = error.UnsupportedRelocationFormat },
    },
    .{
        .name = "plt-size",
        .mutation = .{ .tag_value = .{ .tag = elf.DT_PLTRELSZ, .value = 1 } },
        .expect = .{ .load_error = error.InvalidRelocationTableSize },
    },
    .{
        .name = "plt-outside",
        .mutation = .{ .tag_value = .{ .tag = elf.DT_JMPREL, .value = std.math.maxInt(u64) - 15 } },
        .expect = .{ .load_error = error.AddressNotInFileSegments },
    },
    .{
        .name = "ordinary-rel",
        .mutation = .ordinary_rel,
        .expect = .{ .load_error = error.UnsupportedRelocationFormat },
    },
    .{
        .name = "dynamic-unterminated",
        .mutation = .dynamic_unterminated,
        .expect = .{ .load_error = error.UnterminatedDynamicSection },
    },
    .{
        .name = "dynamic-inconsistent-address",
        .mutation = .dynamic_address,
        .expect = .{ .load_error = error.InvalidDynamicSection },
    },
    .{
        .name = "phdr-outside-file",
        .mutation = .phdr_outside,
        .expect = .{ .load_error = error.InvalidElfFileRange },
    },
    .{
        .name = "fini-array-size",
        .mutation = .{ .tag_value = .{ .tag = elf.DT_FINI_ARRAYSZ, .value = 9 } },
        .expect = .{ .load_error = error.InvalidFiniArraySize },
    },
    .{
        .name = "init-array-outside",
        .mutation = .{ .tag_value = .{ .tag = elf.DT_INIT_ARRAY, .value = std.math.maxInt(u64) - 15 } },
        .expect = .{ .load_error = error.AddressNotInFileSegments },
    },
    .{
        .name = "dynamic-before-load",
        .mutation = .dynamic_first,
        .expect = .{ .loaded = &.{expectOutParam(LibraryState, "readState", initial_state)} },
    },
    .{
        .name = "relr-valid",
        .library = .relr,
        .expect = .{ .loaded = &.{expectReturn(c_int, "answer", 42)} },
    },
    .{
        .name = "relr-entry-zero",
        .library = .relr,
        .mutation = .{ .tag_value = .{ .tag = elf.DT_RELRENT, .value = 0 } },
        .expect = .{ .load_error = error.InvalidRelocationEntrySize },
    },
    .{
        .name = "relr-size",
        .library = .relr,
        .mutation = .{ .tag_value = .{ .tag = elf.DT_RELRSZ, .value = 1 } },
        .expect = .{ .load_error = error.InvalidRelocationTableSize },
    },
    .{
        .name = "relr-missing-entry",
        .library = .relr,
        .mutation = .{ .remove_tag = elf.DT_RELRENT },
        .expect = .{ .load_error = error.MissingRelocationEntrySize },
    },
    .{
        .name = "relr-outside",
        .library = .relr,
        .mutation = .{ .tag_value = .{ .tag = elf.DT_RELR, .value = std.math.maxInt(u64) - 15 } },
        .expect = .{ .load_error = error.AddressNotInFileSegments },
    },
    .{
        .name = "relr-first-bitmap",
        .library = .relr,
        .mutation = .{ .relr_first = 1 },
        .expect = .{ .load_error = error.InvalidRelrBitmap },
    },
    .{
        .name = "relr-bad-destination",
        .library = .relr,
        .mutation = .{ .relr_first = std.math.maxInt(u64) - 7 },
        .expect = .{ .load_error = error.AddressNotInMappedSegments },
    },
    .{
        .name = "relr-cursor-overflow",
        .library = .relr,
        .mutation = .relr_overflow,
        .expect = .{ .load_error = error.InvalidRelrAddress },
    },
    .{
        .name = "plt-only",
        .library = .plt_only,
        .mutation = .plt_only,
        .expect = .{ .loaded = &.{expectReturn(c_int, "answer", 42)} },
    },
    .{
        .name = "relative-zero-addend",
        .library = .relative_addends,
        .mutation = .{ .relative_addend = 0 },
        .expect = .{ .loaded = &.{expectReturn(c_int, "check_zero", 42)} },
    },
    .{
        .name = "relative-negative-addend",
        .library = .relative_addends,
        .mutation = .{ .relative_addend = -8 },
        .expect = .{ .loaded = &.{expectReturn(c_int, "check_negative", 42)} },
    },
};
