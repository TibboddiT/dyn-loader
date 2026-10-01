const std = @import("std");
const elf = std.elf;
const dll = @import("dll");

pub const Library = enum {
    non_identity,
    relr,
    plt_only,
    relative_addends,

    fn fileName(library: Library) []const u8 {
        return switch (library) {
            .non_identity => "target.so",
            .relr => "relr.so",
            .plt_only => "plt_only.so",
            .relative_addends => "relative_addends.so",
        };
    }
};

pub const Mutation = union(enum) {
    none,
    tag_value: struct { tag: u64, value: u64 },
    remove_tag: u64,
    rela_file_end: usize,
    rela_type: u32,
    rela_symbol: u32,
    rela_destination: u64,
    irelative_data,
    ordinary_rel,
    dynamic_unterminated,
    dynamic_address,
    phdr_outside,
    dynamic_first,
    relr_first: u64,
    relr_overflow,
    plt_only,
    relative_addend: i64,
};

pub const Case = struct {
    name: []const u8,
    library: Library = .non_identity,
    mutation: Mutation = .none,
    expect: Expectation,
};

pub const Expectation = union(enum) {
    load_error: anyerror,
    loaded: []const SymbolCheck,

    pub fn checkLoad(expect: Expectation, path: []const u8) !void {
        const library = dll.load(path) catch |err| {
            switch (expect) {
                .load_error => |expected| return std.testing.expectEqual(expected, err),
                .loaded => {
                    std.debug.print("expected {s} to load successfully, got {s}\n", .{ path, @errorName(err) });
                    return err;
                },
            }
        };
        switch (expect) {
            .load_error => |expected| {
                std.debug.print("expected {s}, but loading {s} succeeded\n", .{ @errorName(expected), path });
                return error.ExpectedLoadError;
            },
            .loaded => |checks| for (checks) |check| try check.run(library),
        }
    }
};

pub const SymbolCheck = struct {
    symbol: []const u8,
    verify: *const fn (usize) anyerror!void,

    pub fn run(check: SymbolCheck, library: dll.DynamicLibrary) !void {
        const symbol = library.getSymbol(check.symbol) catch |err| {
            std.debug.print("unable to resolve symbol '{s}': {s}\n", .{ check.symbol, @errorName(err) });
            return err;
        };
        check.verify(symbol.addr) catch |err| {
            std.debug.print("verification of symbol '{s}' failed: {s}\n", .{ check.symbol, @errorName(err) });
            return err;
        };
    }
};

// Checks the return value of a function with no arguments.
pub fn expectReturn(comptime T: type, comptime symbol: []const u8, comptime expected: T) SymbolCheck {
    return .{
        .symbol = symbol,
        .verify = struct {
            fn verify(address: usize) !void {
                const function: *const fn () callconv(.c) T = @ptrFromInt(address);
                try std.testing.expectEqualDeep(expected, function());
            }
        }.verify,
    };
}

// Checks the value written by a function taking one output pointer.
pub fn expectOutParam(comptime T: type, comptime symbol: []const u8, comptime expected: T) SymbolCheck {
    return .{
        .symbol = symbol,
        .verify = struct {
            fn verify(address: usize) !void {
                const function: *const fn (*T) callconv(.c) void = @ptrFromInt(address);
                var actual: T = undefined;
                function(&actual);
                try std.testing.expectEqualDeep(expected, actual);
            }
        }.verify,
    };
}

pub fn run(runner: anytype, cases: []const Case) void {
    for (cases) |case| runner.runCase("elf", case.name);
}

pub fn runCase(init: std.process.Init, cases: []const Case, name: []const u8, resources: []const u8, temporary: []const u8) !void {
    const case = for (cases) |case| {
        if (std.mem.eql(u8, name, case.name)) break case;
    } else return error.UnknownCase;

    const path = try std.fs.path.join(init.gpa, &.{ resources, case.library.fileName() });
    defer init.gpa.free(path);

    const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(4 * 1024 * 1024));
    defer init.gpa.free(bytes);

    const image = try ElfImage.init(bytes);

    try image.checkLayout(case.library);
    try image.mutate(case.mutation);

    const mutated_path = try std.fmt.allocPrint(init.gpa, "{s}/{s}.so", .{ temporary, case.name });
    defer init.gpa.free(mutated_path);

    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = mutated_path, .data = bytes });

    try dll.init(.{ .allocator = init.gpa, .io = init.io, .args = init.minimal.args, .environ = init.minimal.environ, .log_level = .none });
    defer dll.deinit();

    try case.expect.checkLoad(mutated_path);
}

// Used to inspect and mutate the fixed reference binaries.
const ElfImage = struct {
    bytes: []u8,
    header: *align(1) elf.Elf64_Ehdr,

    fn init(bytes: []u8) !ElfImage {
        if (bytes.len < @sizeOf(elf.Elf64_Ehdr)) return error.InvalidReferenceLibrary;
        const header = std.mem.bytesAsValue(elf.Elf64_Ehdr, bytes[0..@sizeOf(elf.Elf64_Ehdr)]);
        try std.testing.expectEqualSlices(u8, elf.MAGIC, header.e_ident[0..4]);
        try std.testing.expectEqual(elf.ELFCLASS64, header.e_ident[elf.EI_CLASS]);
        try std.testing.expectEqual(elf.ELFDATA2LSB, header.e_ident[elf.EI_DATA]);
        try std.testing.expectEqual(elf.EM.X86_64, header.e_machine);
        try std.testing.expectEqual(elf.ET.DYN, header.e_type);
        return .{ .bytes = bytes, .header = header };
    }

    fn range(image: ElfImage, offset: usize, size: usize) ![]u8 {
        if (offset > image.bytes.len or size > image.bytes.len - offset) return error.InvalidReferenceLibrary;
        return image.bytes[offset..][0..size];
    }

    fn programHeaders(image: ElfImage) ![]align(1) elf.Elf64.Phdr {
        try std.testing.expectEqual(@sizeOf(elf.Elf64.Phdr), image.header.e_phentsize);
        return std.mem.bytesAsSlice(elf.Elf64.Phdr, try image.range(image.header.e_phoff, @as(usize, image.header.e_phnum) * @sizeOf(elf.Elf64.Phdr)));
    }

    fn dynamicHeader(image: ElfImage) !*align(1) elf.Elf64.Phdr {
        for (try image.programHeaders()) |*header| {
            if (header.type == .DYNAMIC) return header;
        }
        return error.MissingReferenceDynamicSection;
    }

    fn dynamics(image: ElfImage) ![]align(1) elf.Dyn {
        const header = try image.dynamicHeader();
        try std.testing.expectEqual(@as(u64, 0), header.filesz % @sizeOf(elf.Dyn));
        return std.mem.bytesAsSlice(elf.Dyn, try image.range(header.offset, header.filesz));
    }

    fn findTag(image: ElfImage, value: u64) !?*align(1) elf.Dyn {
        for (try image.dynamics()) |*entry| {
            if (entry.d_tag == value) return entry;
            if (entry.d_tag == elf.DT_NULL) break;
        }
        return null;
    }

    fn tag(image: ElfImage, value: u64) !*align(1) elf.Dyn {
        return try image.findTag(value) orelse error.MissingReferenceDynamicTag;
    }

    fn virtualOffset(image: ElfImage, address: u64) !usize {
        for (try image.programHeaders()) |header| {
            if (header.type == .LOAD and address >= header.vaddr and address - header.vaddr < header.filesz) {
                return header.offset + (address - header.vaddr);
            }
        }
        return error.ReferenceAddressNotMapped;
    }

    fn relaEntries(image: ElfImage) ![]align(1) elf.Elf64_Rela {
        const offset = try image.virtualOffset((try image.tag(elf.DT_RELA)).d_val);
        return std.mem.bytesAsSlice(elf.Elf64_Rela, try image.range(offset, (try image.tag(elf.DT_RELASZ)).d_val));
    }

    fn relrEntries(image: ElfImage) ![]align(1) elf.Elf64_Relr {
        const offset = try image.virtualOffset((try image.tag(elf.DT_RELR)).d_val);
        return std.mem.bytesAsSlice(elf.Elf64_Relr, try image.range(offset, (try image.tag(elf.DT_RELRSZ)).d_val));
    }

    fn bssSegment(image: ElfImage) !*align(1) elf.Elf64.Phdr {
        for (try image.programHeaders()) |*header| {
            if (header.type == .LOAD and header.flags.W and header.memsz > header.filesz) return header;
        }
        return error.MissingReferenceBss;
    }

    fn symbolValue(image: ElfImage, name: []const u8) !u64 {
        try std.testing.expectEqual(@sizeOf(elf.Elf64.Shdr), image.header.e_shentsize);
        const sections = std.mem.bytesAsSlice(elf.Elf64.Shdr, try image.range(image.header.e_shoff, @as(usize, image.header.e_shnum) * @sizeOf(elf.Elf64.Shdr)));
        for (sections) |section| {
            if (section.type != .DYNSYM) continue;
            if (section.link >= sections.len) return error.InvalidReferenceLibrary;
            const strings_header = sections[section.link];
            const strings = try image.range(strings_header.offset, strings_header.size);
            for (std.mem.bytesAsSlice(elf.Elf64.Sym, try image.range(section.offset, section.size))) |symbol| {
                if (symbol.name >= strings.len) return error.InvalidReferenceLibrary;
                const end = std.mem.findScalar(u8, strings[symbol.name..], 0) orelse return error.InvalidReferenceLibrary;
                if (std.mem.eql(u8, strings[symbol.name..][0..end], name)) return symbol.value;
            }
        }
        return error.MissingReferenceSymbol;
    }

    fn checkLayout(image: ElfImage, library: Library) !void {
        switch (library) {
            .non_identity => {
                const address = (try image.tag(elf.DT_RELA)).d_val;
                try std.testing.expect((try image.virtualOffset(address)) > address);
                const entries = try image.relaEntries();
                try std.testing.expect(entries.len > 0);
                try std.testing.expectEqual(@backingInt(elf.R_X86_64.RELATIVE), entries[0].r_type());
                const bss = try image.bssSegment();
                try std.testing.expect(bss.filesz >= 8);
                try std.testing.expect((try image.tag(elf.DT_RELASZ)).d_val > 8);
            },
            .relr => {
                try std.testing.expectEqual(@sizeOf(elf.Elf64_Relr), (try image.tag(elf.DT_RELRENT)).d_val);
                try std.testing.expect((try image.relrEntries()).len >= 2);
            },
            .plt_only => {
                try std.testing.expect(try image.findTag(elf.DT_RELA) == null);
                try std.testing.expectEqual(elf.DT_RELA, (try image.tag(elf.DT_PLTREL)).d_val);
                try std.testing.expect((try image.tag(elf.DT_PLTRELSZ)).d_val > 0);
            },
            .relative_addends => _ = try image.symbolValue("relative_slot"),
        }
    }

    fn mutate(image: ElfImage, mutation: Mutation) !void {
        switch (mutation) {
            .none => {},
            .tag_value => |value| (try image.tag(value.tag)).d_val = value.value,
            .remove_tag => |value| (try image.tag(value)).d_tag = elf.DT_DEBUG,
            .rela_file_end => |backwards| {
                const segment = try image.bssSegment();
                (try image.tag(elf.DT_RELA)).d_val = segment.vaddr + segment.filesz - backwards;
            },
            .rela_type => |value| (try image.relaEntries())[0].r_info = value,
            .rela_symbol => |value| {
                const entry = &(try image.relaEntries())[0];
                entry.r_info = (@as(u64, value) << 32) | entry.r_type();
            },
            .rela_destination => |value| (try image.relaEntries())[0].r_offset = value,
            .irelative_data => {
                const entry = &(try image.relaEntries())[0];
                entry.r_info = @backingInt(elf.R_X86_64.IRELATIVE);
                entry.r_addend = @intCast((try image.bssSegment()).vaddr);
            },
            .ordinary_rel => (try image.tag(elf.DT_RELA)).d_tag = elf.DT_REL,
            .dynamic_unterminated => {
                for (try image.dynamics()) |*entry| {
                    if (entry.d_tag == elf.DT_NULL) entry.d_tag = elf.DT_DEBUG;
                }
            },
            .dynamic_address => (try image.dynamicHeader()).vaddr += 8,
            .phdr_outside => image.header.e_phoff = std.math.maxInt(u64) - 15,
            .dynamic_first => {
                const headers = try image.programHeaders();
                const idx = for (headers, 0..) |header, i| {
                    if (header.type == .DYNAMIC) break i;
                } else return error.MissingReferenceDynamicSection;
                try std.testing.expect(idx > 1);
                const dynamic = headers[idx];
                std.mem.copyBackwards(u8, std.mem.sliceAsBytes(headers[2 .. idx + 1]), std.mem.sliceAsBytes(headers[1..idx]));
                headers[1] = dynamic;
            },
            .relr_first => |value| (try image.relrEntries())[0] = value,
            .relr_overflow => {
                const segment = try image.bssSegment();
                segment.memsz = std.math.maxInt(u64) - segment.vaddr;

                const entries = try image.relrEntries();
                entries[0] = std.math.maxInt(u64) - 9;
                entries[1] = 1;
            },
            .plt_only => {
                if (try image.findTag(elf.DT_RELAENT)) |entry| entry.d_tag = elf.DT_DEBUG;
            },
            .relative_addend => |value| {
                const address = try image.symbolValue("relative_slot");
                for (try image.relaEntries()) |*entry| {
                    if (entry.r_offset != address) continue;
                    try std.testing.expectEqual(@backingInt(elf.R_X86_64.RELATIVE), entry.r_type());
                    entry.r_addend = value;
                    return;
                }
                return error.MissingReferenceRelocation;
            },
        }
    }
};
