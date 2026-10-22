//! Metadata and mapping operations for an ELF object owned by the loader.

const std = @import("std");

const logger = @import("logger.zig");

const DynObject = @This();

/// Loader-assigned identity, distinct from an object-registry index.
pub const TlsModuleId = struct {
    value: usize,
};

pub const LoadSegmentFlags = struct {
    read: bool,
    write: bool,
    exec: bool,

    mem_offset: usize,
    mem_size: usize,

    pub fn toStr(flags: LoadSegmentFlags, out: []u8) ![]const u8 {
        return std.fmt.bufPrint(out, "{s}{s}{s}", .{
            @as([]const u8, if (flags.read) "R" else ""),
            @as([]const u8, if (flags.write) "W" else ""),
            @as([]const u8, if (flags.exec) "X" else ""),
        });
    }
};

pub const LoadSegment = struct {
    // File coordinates name bytes in the original ELF; memory coordinates name
    // ELF virtual addresses. `loaded_at` is the host address after mapping.
    file_offset: usize,
    file_size: usize,
    mem_offset: usize,
    mem_size: usize,
    mem_align: usize,
    mapped_from_file: bool,
    flags_first: LoadSegmentFlags, // Whole-segment permissions during relocation.
    flags_last: LoadSegmentFlags, // Final range, possibly narrowed by GNU_RELRO.
    loaded_at: usize,
};

pub const LoadSegmentList = std.AutoArrayHashMapUnmanaged(usize, LoadSegment);

pub const DynSym = struct {
    // Strings borrow the retained ELF file mapping. `value` is `st_value`: it
    // can be an ELF address, TLS offset, or absolute value depending on the symbol.
    name: []const u8,
    version: []const u8,
    hidden: bool,
    default_version: bool,
    offset: usize,
    type: std.elf.STT,
    bind: std.elf.STB,
    shidx: std.elf.Section,
    value: usize,
    size: usize,

    pub fn sectionNameOrValue(self: DynSym, buf: []u8) ![]const u8 {
        return switch (self.shidx) {
            std.elf.SHN_UNDEF => try std.fmt.bufPrint(buf, "UNDEF", .{}),
            std.elf.SHN_LORESERVE => try std.fmt.bufPrint(buf, "LORESERVE/LOPROC ", .{}),
            std.elf.SHN_HIPROC => try std.fmt.bufPrint(buf, "HIPROC ", .{}),
            std.elf.SHN_LIVEPATCH => try std.fmt.bufPrint(buf, "LIVEPATCH ", .{}),
            std.elf.SHN_ABS => try std.fmt.bufPrint(buf, "ABS ", .{}),
            std.elf.SHN_COMMON => try std.fmt.bufPrint(buf, "COMMON ", .{}),
            std.elf.SHN_HIRESERVE => try std.fmt.bufPrint(buf, "HIRESERVE ", .{}),
            else => |shidx| try std.fmt.bufPrint(buf, "0x{x}", .{shidx}),
        };
    }
};

/// Names map to ranges in one owned index buffer, preserving ELF symbol order.
/// Name keys borrow the symbol strings; returned ranges borrow the index buffer.
pub const DynSymList = struct {
    const Range = struct { start: usize = 0, len: usize = 0 };

    names: std.StringArrayHashMapUnmanaged(Range) = .empty,
    indices: std.ArrayList(usize) = .empty,

    pub const empty: DynSymList = .{};

    /// Invalidates previous ranges. Failure leaves an empty index with capacity retained.
    pub fn build(self: *DynSymList, allocator: std.mem.Allocator, symbols: []const DynSym) !void {
        self.clearRetainingCapacity();
        errdefer self.clearRetainingCapacity();
        try self.names.ensureTotalCapacity(allocator, symbols.len);
        try self.indices.ensureTotalCapacityPrecise(allocator, symbols.len);

        for (symbols) |symbol| {
            const entry = self.names.getOrPutAssumeCapacity(symbol.name);
            if (!entry.found_existing) entry.value_ptr.* = .{};
            entry.value_ptr.len += 1;
        }

        var start: usize = 0;
        for (self.names.values()) |*range| {
            range.start = start;
            start += range.len;
            range.len = 0;
        }
        self.indices.items.len = symbols.len;
        for (symbols, 0..) |symbol, index| {
            const range = self.names.getPtr(symbol.name).?;
            self.indices.items[range.start + range.len] = index;
            range.len += 1;
        }
    }

    pub fn get(self: *const DynSymList, name: []const u8) ?[]const usize {
        const range = self.names.get(name) orelse return null;
        return self.indices.items[range.start..][0..range.len];
    }

    pub fn count(self: *const DynSymList) usize {
        return self.names.count();
    }

    pub fn clearRetainingCapacity(self: *DynSymList) void {
        self.names.clearRetainingCapacity();
        self.indices.clearRetainingCapacity();
    }

    pub fn deinit(self: *DynSymList, allocator: std.mem.Allocator) void {
        self.names.deinit(allocator);
        self.indices.deinit(allocator);
        self.* = .empty;
    }
};

pub const ResolvedSymbol = struct {
    // `value` preserves st_value: an ELF value or a module-relative TLS offset.
    // Indices avoid registry-entry pointers; names and versions borrow the ELF file mapping.
    value: usize,
    location: union(enum) {
        address: usize,
        tls,
    },
    name: []const u8,
    version: []const u8,
    dyn_object_idx: usize,
    sym_idx: usize,

    /// Returns a thread-independent address. TLS requires runtime materialization.
    pub fn getStaticAddress(self: ResolvedSymbol) error{TlsSymbolHasNoStaticAddress}!usize {
        return switch (self.location) {
            .address => |address| address,
            .tls => error.TlsSymbolHasNoStaticAddress,
        };
    }
};

pub const Reloc = struct {
    type: std.elf.R_X86_64,
    is_relr: bool, // The addend comes from the relocation target, not `addend`.
    sym_idx: usize,
    offset: usize,
    addend: isize,
};

pub const RelocList = std.ArrayList(Reloc);

pub const DynObjectId = struct {
    ino: std.os.linux.ino_t,
    retired_slot: usize = 0, // Separates retired entries from a new live inode key.
};

pub const DynObjectSegmentResult = struct {
    dyn_object: *DynObject,
    segment_index: usize,
    sym_index: ?usize,
};

/// A borrowed symbol definition. Finish inspection before any registry mutation.
pub const Definition = struct {
    object: *const DynObject,
    symbol: *const DynSym,
};

/// An object and lookup callback borrowed during inspection.
/// Lookup may resolve a dependency; check the owner when local code is required.
pub const Inspection = struct {
    object: *DynObject,
    lookup: *const fn (object: *DynObject, name: []const u8) anyerror!Definition,
};

// Strings and containers are owned by the loader through this entry. The file
// mapping supplies borrowed header/symbol data; the separate reservation holds
// loaded segments. Registry growth can move this struct without moving mappings.
key: DynObjectId,
name: []const u8,
path: []const u8,
runpath: ?[]const u8,
rpath: ?[]const u8,
inherited_rpath: ?[]const u8,
file_handle: i32,
mapped_at: usize,
mapped_size: usize,
segments: LoadSegmentList,

// Initializer coordinates come from PT_TLS. `tls_offset` is a positive distance
// below TP; capacity/alignment survive retirement to permit compatible reuse.
tls_init_file_offset: usize,
tls_init_file_size: usize,
tls_init_mem_offset: usize,
tls_init_mem_size: usize,
tls_align: usize,
tls_offset: usize,
tls_mapped_at: usize,
tls_module_id: ?TlsModuleId = null,
tls_published: bool = false,

eh: *std.elf.Elf64_Ehdr,
eh_init_file_offset: usize,
eh_init_file_size: usize,
eh_init_mem_offset: usize,
eh_init_mem_size: usize,
eh_align: usize,

dyn_section_offset: usize,
plt_got_section_offset: usize,
plt_got_section_size: usize,
syms: DynSymList,
syms_array: std.ArrayList(DynSym),
dependencies: std.ArrayList(usize),
deps_breadth_first: std.ArrayList(usize),
relocs: RelocList,

init_addr: usize,
fini_addr: usize,
init_array_addr: usize,
init_array_size: usize,
fini_array_addr: usize,
fini_array_size: usize,

// These flags describe separate phases, not interchangeable "loaded" states.
loaded: bool, // Final permissions and debug publication are complete.
initializing: bool = false,
initialization_failed: bool = false,
execution_started: bool = false,
init_called: bool,
current_epoch: u30,
ref_count: usize,
host_open_count: usize = 0,
nodelete_requested: bool = false,
nodelete: bool = false,
loaded_at: ?usize,
loaded_size: usize,
reservation: ?[]align(std.heap.pageSize()) u8,
tls_capacity: usize,
tls_slot_align: usize,
load_requested: bool,
finalizing: bool,
pinned: bool,
runtime_pinned: bool = false,
tls_destructors: usize,
binding_dependencies: std.ArrayList(usize),
phdr_info: ?*std.posix.dl_phdr_info,
phdr_name: ?[:0]u8,
relocated: bool,

/// Creates an unmapped registry entry without allocating. The loader transfers
/// owned `name`/`path` strings into it and later supplies mappings and metadata.
pub fn init(key: DynObjectId, name: []const u8, path: []const u8) DynObject {
    return .{
        .key = key,
        .name = name,
        .path = path,
        .runpath = null,
        .rpath = null,
        .inherited_rpath = null,
        .file_handle = -1,
        .mapped_at = 0,
        .mapped_size = 0,
        .segments = .empty,
        .tls_init_file_offset = 0,
        .tls_init_file_size = 0,
        .tls_init_mem_offset = 0,
        .tls_init_mem_size = 0,
        .tls_align = 0,
        .tls_offset = 0,
        .tls_mapped_at = 0,
        .eh = undefined,
        .eh_init_file_offset = 0,
        .eh_init_file_size = 0,
        .eh_init_mem_offset = 0,
        .eh_init_mem_size = 0,
        .eh_align = 0,
        .dyn_section_offset = 0,
        .plt_got_section_offset = 0,
        .plt_got_section_size = 0,
        .syms = .empty,
        .syms_array = .empty,
        .relocs = .empty,
        .dependencies = .empty,
        .deps_breadth_first = .empty,
        .init_addr = 0,
        .fini_addr = 0,
        .init_array_addr = 0,
        .init_array_size = 0,
        .fini_array_addr = 0,
        .fini_array_size = 0,
        .loaded = false,
        .init_called = false,
        .current_epoch = 0,
        .ref_count = 0,
        .loaded_at = null,
        .loaded_size = 0,
        .reservation = null,
        .tls_capacity = 0,
        .tls_slot_align = 0,
        .load_requested = true,
        .finalizing = false,
        .pinned = false,
        .tls_destructors = 0,
        .binding_dependencies = .empty,
        .phdr_info = null,
        .phdr_name = null,
        .relocated = false,
    };
}

/// Finds a segment in this object using a mapped host address.
pub fn findSegment(self: *const DynObject, mapped_address: usize) ?usize {
    for (self.segments.values(), 0..) |segment, segment_index| {
        if (mapped_address >= segment.loaded_at and mapped_address - segment.loaded_at < segment.mem_size) {
            return segment_index;
        }
    }
    return null;
}

/// Translates an ELF virtual address to a host address.
/// `allow_outside` permits base-relative translation outside the object's segments.
pub fn virtualToLoadedAddress(self: *const DynObject, virtual_address: usize, allow_outside: bool) !usize {
    for (self.segments.values()) |segment| {
        if (virtual_address >= segment.mem_offset and virtual_address - segment.mem_offset < segment.mem_size) {
            return segment.loaded_at + (virtual_address - segment.mem_offset);
        }
    }

    if (!allow_outside) {
        logger.err("address.translate: object={s} address_elf=0x{x} result=outside_mapped_segments", .{ self.name, virtual_address });
        return error.AddressNotInMappedSegments;
    }

    logger.debug("address.translate: object={s} address_elf=0x{x} action=allow_outside_mapped_segments base_host=0x{x}", .{ self.name, virtual_address, self.loaded_at.? });
    return self.loaded_at.? + virtual_address;
}

/// Resolves a section-relative, non-TLS symbol without dereferencing it.
/// Zero-sized data/NOTYPE markers (such as `_end`) may denote the exclusive
/// segment end. Memory accesses still use the strict address/range helpers.
pub fn symbolToLoadedAddress(self: *const DynObject, symbol: DynSym) !usize {
    if (symbol.size == 0 and (symbol.type == .NOTYPE or symbol.type == .OBJECT) and
        symbol.shidx != std.elf.SHN_UNDEF and symbol.shidx < std.elf.SHN_LORESERVE)
    {
        for (self.segments.values()) |segment| {
            if (symbol.value >= segment.mem_offset and symbol.value - segment.mem_offset == segment.mem_size) {
                return std.math.add(usize, segment.loaded_at, segment.mem_size);
            }
        }
    }

    return self.virtualToLoadedAddress(symbol.value, false);
}

/// Returns a host address in the original file mapping, not the loaded image.
pub fn virtualToFileAddress(self: *const DynObject, virtual_address: usize, size_bytes: usize) !usize {
    const file_bytes = @as([*]const u8, @ptrFromInt(self.mapped_at))[0..self.mapped_size];
    const headers = try programHeaders(file_bytes, self.eh);
    return @intFromPtr((try virtualFileRange(file_bytes, headers, virtual_address, size_bytes)).ptr);
}

/// Borrows a readable, executable range at an ELF virtual address.
/// The object must remain mapped while the bytes are in use.
pub fn mappedCodeBytes(self: *const DynObject, virtual_address: usize, size_bytes: usize) ![]const u8 {
    for (self.segments.values()) |segment| {
        if (!segment.flags_first.read or !segment.flags_first.exec) continue;
        if (virtual_address < segment.mem_offset) continue;

        const segment_offset = virtual_address - segment.mem_offset;
        if (segment_offset > segment.mem_size or size_bytes > segment.mem_size - segment_offset) continue;

        const mapped_address = std.math.add(usize, segment.loaded_at, segment_offset) catch return error.InvalidCodeAddress;
        const mapped_bytes: [*]const u8 = @ptrFromInt(mapped_address);
        return mapped_bytes[0..size_bytes];
    }

    return error.InvalidCodeAddress;
}

/// Returns the host address of a readable, non-executable data range.
/// Validates the entire range. The result borrows the mapping and does not
/// guarantee write permission.
pub fn mappedDataAddress(self: *const DynObject, virtual_address: usize, size_bytes: usize) !usize {
    for (self.segments.values()) |segment| {
        if (!segment.flags_first.read or segment.flags_first.exec) continue;
        if (virtual_address < segment.mem_offset) continue;

        const offset = virtual_address - segment.mem_offset;
        if (offset > segment.mem_size or size_bytes > segment.mem_size - offset) continue;

        return std.math.add(usize, segment.loaded_at, offset) catch error.InvalidDataAddress;
    }

    return error.InvalidDataAddress;
}

/// Adds initial write-permission and host-alignment checks to `mappedDataAddress`.
/// Final RELRO permissions may still require a temporary permission change.
pub fn mappedWritableDataAddress(self: *const DynObject, virtual_address: usize, size_bytes: usize, alignment: usize) !usize {
    if (!std.math.isPowerOfTwo(alignment)) return error.InvalidDataAlignment;

    const mapped_address = try self.mappedDataAddress(virtual_address, size_bytes);
    if (self.findSegment(mapped_address)) |segment_index| {
        if (!self.segments.values()[segment_index].flags_first.write) return error.InvalidDataPermissions;
    }
    if (mapped_address % alignment != 0) return error.InvalidDataAlignment;

    return mapped_address;
}

/// Applies final page-rounded permissions after relocation.
/// Failure may leave earlier segments updated. The loader owns cleanup.
pub fn updateSegmentsPermissions(self: *const DynObject) !void {
    logger.debug("updating segment permissions for {s}", .{self.name});

    for (self.segments.values(), 0..) |segment, segment_index| {
        const flags = segment.flags_last;
        const mapped_start = segment.loaded_at + (flags.mem_offset - segment.mem_offset);
        const aligned_start = std.mem.alignBackward(usize, mapped_start, std.heap.pageSize());
        const aligned_end = std.mem.alignForward(usize, mapped_start + flags.mem_size, std.heap.pageSize());
        const protection: std.posix.PROT = .{ .READ = flags.read, .WRITE = flags.write, .EXEC = flags.exec };

        logger.debug("  updating segment {d}: from 0x{x} to 0x{x}, prot: 0x{x}", .{ segment_index, aligned_start, aligned_end, @as(u32, @bitCast(protection)) });
        try protectRange(aligned_start, aligned_end, protection);
    }

    logger.debug("successfully updated {d} segments for {s}", .{ self.segments.count(), self.name });
}

/// Temporarily makes the whole segment readable/writable and non-executable.
pub fn unprotectSegment(self: *const DynObject, segment_index: usize) !void {
    const segment = self.segments.values()[segment_index];
    const aligned_start = std.mem.alignBackward(usize, segment.loaded_at, std.heap.pageSize());
    const aligned_end = std.mem.alignForward(usize, segment.loaded_at + segment.mem_size, std.heap.pageSize());
    const protection: std.posix.PROT = .{ .READ = true, .WRITE = true };

    logger.debug("{s}: unprotecting segment {d}: from 0x{x} to 0x{x}, prot: 0x{x}", .{ self.name, segment_index, aligned_start, aligned_end, @as(u32, @bitCast(protection)) });
    protectRange(aligned_start, aligned_end, protection) catch return error.UnprotectSegmentFailed;
    logger.debug("successfully unprotected segment {d} for {s}", .{ segment_index, self.name });
}

/// Restores initial permissions, then final subrange permissions for a loaded object.
pub fn reprotectSegment(self: *const DynObject, segment_index: usize) !void {
    const segment = self.segments.values()[segment_index];
    const aligned_start = std.mem.alignBackward(usize, segment.loaded_at, std.heap.pageSize());
    const aligned_end = std.mem.alignForward(usize, segment.loaded_at + segment.mem_size, std.heap.pageSize());
    const initial = segment.flags_first;
    const protection: std.posix.PROT = .{ .READ = initial.read, .WRITE = initial.write, .EXEC = initial.exec };

    logger.debug("{s}: reprotecting segment {d}: from 0x{x} to 0x{x}, prot: 0x{x}", .{ self.name, segment_index, aligned_start, aligned_end, @as(u32, @bitCast(protection)) });
    try protectRange(aligned_start, aligned_end, protection);

    if (self.loaded) {
        const final = segment.flags_last;
        const mapped_start = segment.loaded_at + (final.mem_offset - segment.mem_offset);
        const final_start = std.mem.alignBackward(usize, mapped_start, std.heap.pageSize());
        const final_end = std.mem.alignForward(usize, mapped_start + final.mem_size, std.heap.pageSize());
        const final_protection: std.posix.PROT = .{ .READ = final.read, .WRITE = final.write, .EXEC = final.exec };

        logger.debug("{s}: reapplying segment {d} permissions: from 0x{x} to 0x{x}, prot: 0x{x}", .{ self.name, segment_index, final_start, final_end, @as(u32, @bitCast(final_protection)) });
        try protectRange(final_start, final_end, final_protection);
    }

    logger.debug("successfully reprotected segment {d} for {s}", .{ segment_index, self.name });
}

fn protectRange(aligned_start: usize, aligned_end: usize, protection: std.posix.PROT) !void {
    const address: [*]align(std.heap.pageSize()) u8 = @ptrFromInt(aligned_start);
    const result = std.os.linux.mprotect(address, aligned_end - aligned_start, protection);
    switch (std.os.linux.errno(result)) {
        .SUCCESS => {},
        else => |err| {
            logger.err("failed to update segment permissions: {t}", .{err});
            return error.ProtectSegmentFailed;
        },
    }
}

/// Borrows `size` bytes starting at `offset`.
/// An empty range at the end is valid. Returns `error.InvalidElfFileRange`
/// if the range extends beyond `bytes`.
pub fn checkedSliceRange(bytes: []const u8, offset: usize, size: usize) ![]const u8 {
    // Subtract to avoid overflow in untrusted `offset + size`.
    if (offset > bytes.len or size > bytes.len - offset) return error.InvalidElfFileRange;
    return bytes[offset..][0..size];
}

/// Validates table stride and bounds, returning an unaligned view of file bytes.
pub fn programHeaders(bytes: []const u8, eh: *const std.elf.Elf64_Ehdr) ![]align(1) const std.elf.Elf64.Phdr {
    if (eh.e_phentsize != @sizeOf(std.elf.Elf64.Phdr)) return error.InvalidProgramHeaderSize;
    const table = try checkedSliceRange(bytes, eh.e_phoff, @as(usize, eh.e_phnum) * @sizeOf(std.elf.Elf64.Phdr));
    return std.mem.bytesAsSlice(std.elf.Elf64.Phdr, table);
}

/// Resolves an ELF address only through the file-backed part of a load segment.
/// Zero-filled memory beyond `filesz` has no corresponding file bytes.
pub fn virtualFileRange(bytes: []const u8, headers: []align(1) const std.elf.Elf64.Phdr, virtual_address: usize, size_bytes: usize) ![]const u8 {
    for (headers) |header| {
        if (header.type != .LOAD or virtual_address < header.vaddr) continue;

        const offset = virtual_address - header.vaddr;
        if (offset > header.filesz or size_bytes > header.filesz - offset) continue;

        const file_offset = std.math.add(usize, header.offset, offset) catch return error.InvalidElfFileRange;
        return checkedSliceRange(bytes, file_offset, size_bytes);
    }

    return error.AddressNotInFileSegments;
}

test "zero-sized symbol endpoints do not permit out-of-segment memory accesses" {
    const previous_log_level = logger.level;
    logger.level = .none;
    defer logger.level = previous_log_level;

    var object = DynObject.init(.{ .ino = 1 }, "boundary", "boundary");
    defer object.segments.deinit(std.testing.allocator);

    var segment = std.mem.zeroes(LoadSegment);
    segment.mem_offset = 0x100;
    segment.mem_size = 0x20;
    segment.loaded_at = 0x2100;
    segment.flags_first.read = true;
    try object.segments.put(std.testing.allocator, segment.mem_offset, segment);

    var symbol = std.mem.zeroes(DynSym);
    symbol.type = .NOTYPE;
    symbol.shidx = 1;
    symbol.value = 0x120;
    try std.testing.expectEqual(@as(usize, 0x2120), try object.symbolToLoadedAddress(symbol));

    symbol.type = .OBJECT;
    try std.testing.expectEqual(@as(usize, 0x2120), try object.symbolToLoadedAddress(symbol));
    try std.testing.expectError(error.AddressNotInMappedSegments, object.virtualToLoadedAddress(symbol.value, false));
    try std.testing.expectError(error.InvalidDataAddress, object.mappedDataAddress(symbol.value, 1));

    symbol.size = 1;
    try std.testing.expectError(error.AddressNotInMappedSegments, object.symbolToLoadedAddress(symbol));

    symbol.size = 0;
    symbol.value += 1;
    try std.testing.expectError(error.AddressNotInMappedSegments, object.symbolToLoadedAddress(symbol));

    symbol.value -= 1;
    symbol.type = .GNU_IFUNC;
    try std.testing.expectError(error.AddressNotInMappedSegments, object.symbolToLoadedAddress(symbol));
}
