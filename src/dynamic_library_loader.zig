const std = @import("std");
const builtin = @import("builtin");

pub const CustomSelfInfo = @import("CustomSelfInfo.zig");

const LoadSegmentFlags = struct {
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

const LoadSegment = struct {
    file_offset: usize,
    file_size: usize,
    mem_offset: usize,
    mem_size: usize,
    mem_align: usize,
    mapped_from_file: bool,
    flags_first: LoadSegmentFlags,
    flags_last: LoadSegmentFlags,
    loaded_at: usize,
};

const LoadSegmentList = std.AutoArrayHashMapUnmanaged(usize, LoadSegment);

const DynSym = struct {
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

    fn sectionNameOrValue(self: DynSym, buf: []u8) ![]const u8 {
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

const DynSymList = std.StringArrayHashMapUnmanaged(std.ArrayList(usize));

const ResolvedSymbol = struct {
    value: usize,
    address: usize,
    name: []const u8,
    version: []const u8,
    dyn_object_idx: usize,
    sym_idx: usize,
};

const Reloc = struct {
    type: std.elf.R_X86_64,
    is_relr: bool,
    sym_idx: usize,
    offset: usize,
    addend: isize,
};

const RelocList = std.ArrayList(Reloc);

const DlHandle = packed struct(u64) {
    tag: u2,
    epoch: u30,
    index: u32,

    const rtld_main: DlHandle = .{
        .tag = 0b10,
        .epoch = 0,
        .index = std.math.maxInt(u32),
    };

    const rtld_default: DlHandle = @bitCast(@as(u64, 0));
    const rtld_next: DlHandle = @bitCast(~@as(u64, 0));

    fn fromInt(raw: u64) DlHandle {
        return @bitCast(raw);
    }

    fn toInt(handle: DlHandle) u64 {
        return @bitCast(handle);
    }
};

const DlHandleMetadata = struct {
    dyn_object_idx: usize,
    epoch: u30,
    open_count: usize,
};

const DlHandleMap = std.AutoArrayHashMapUnmanaged(u64, DlHandleMetadata);

// TODO global state
var ifunc_resolved_addrs: std.AutoArrayHashMapUnmanaged(usize, usize) = .empty;
var irel_resolved_targets: std.AutoArrayHashMapUnmanaged(usize, usize) = .empty;

const DynObject = struct {
    key: DynObjectId,
    name: []const u8,
    path: []const u8,
    runpath: ?[]const u8,
    file_handle: i32,
    mapped_at: usize,
    mapped_size: usize,
    segments: LoadSegmentList,
    tls_init_file_offset: usize,
    tls_init_file_size: usize,
    tls_init_mem_offset: usize,
    tls_init_mem_size: usize,
    tls_align: usize,
    tls_offset: usize,
    tls_mapped_at: usize,
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
    loaded: bool,
    init_called: bool,
    current_epoch: u30,
    ref_count: usize,
    loaded_at: ?usize,
    loaded_size: usize,
    reservation: ?[]align(std.heap.pageSize()) u8,
    tls_capacity: usize,
    tls_slot_align: usize,
    load_requested: bool,
    finalizing: bool,
    pinned: bool,
    tls_destructors: usize,
    binding_dependencies: std.ArrayList(usize),
    phdr_info: ?*std.posix.dl_phdr_info,
    phdr_name: ?[:0]u8,
    relocated: bool,

    fn init(key: DynObjectId, name: []const u8, path: []const u8) DynObject {
        return .{
            .key = key,
            .name = name,
            .path = path,
            .runpath = null,
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
};

const DynObjectId = struct {
    ino: std.os.linux.ino_t,
    retired_slot: usize = 0,
};

const DynObjectList = std.AutoArrayHashMapUnmanaged(DynObjectId, DynObject);

const Symbol = struct {
    addr: usize,
};

pub const DynamicLibrary = struct {
    index: usize,

    pub fn getSymbol(lib: DynamicLibrary, sym_name: []const u8) !Symbol {
        for (preload_root_indices.items) |preload_idx| {
            const preload_dyn_obj = &dyn_objects.values()[preload_idx];
            const preload_sym = getResolvedSymbolByName(preload_dyn_obj, sym_name, false, false, true) catch |err| switch (err) {
                error.UnresolvedSymbol => continue,
                else => |e| return e,
            };

            return .{
                .addr = preload_sym.address,
            };
        }

        const dyn_obj = &dyn_objects.values()[lib.index];
        const sym = try getResolvedSymbolByName(dyn_obj, sym_name, false, false, true);
        return .{
            .addr = sym.address,
        };
    }

    // pub fn unload(lib: DynamicLibrary, ) void {
    //     const dyn_obj = &dyn_objects.values()[lib.index];
    //     unloadDso(dyn_obj, allocator);
    // }
};

// TODO global state
var dyn_objects: DynObjectList = .empty;
var dyn_objects_sorted_indices: std.ArrayList(usize) = .empty;
var dyn_objects_init_indices: std.ArrayList(usize) = .empty;
var dll_deinitializing = false;
var preload_root_indices: std.ArrayList(usize) = .empty;
var dl_handles: DlHandleMap = .empty;
var load_request_cache: std.StringArrayHashMapUnmanaged(usize) = .empty;

const Logger = struct {
    const Level = enum {
        debug,
        info,
        warn,
        err,
        none,
    };

    const inner_logger = std.log.scoped(.dynamic_library_loader);
    var level: Level = .debug;

    fn debug(comptime format: []const u8, args: anytype) void {
        switch (level) {
            .debug => inner_logger.debug(format, args),
            else => {},
        }
    }

    fn info(comptime format: []const u8, args: anytype) void {
        switch (level) {
            .debug, .info => inner_logger.info(format, args),
            else => {},
        }
    }

    fn warn(comptime format: []const u8, args: anytype) void {
        switch (level) {
            .debug, .info, .warn => inner_logger.warn(format, args),
            else => {},
        }
    }

    fn err(comptime format: []const u8, args: anytype) void {
        switch (level) {
            .debug, .info, .warn, .err => inner_logger.err(format, args),
            else => {},
        }
    }
};

export fn _dl_debug_state() callconv(.c) void {
    Logger.debug("_dl_debug_state called", .{});
}

// TODO global state
var dll_initialized: bool = false;
var dll_allocator: std.mem.Allocator = undefined;
var dll_io: std.Io = undefined;
var dll_args: std.process.Args = undefined;
var dll_environ: std.process.Environ = undefined;

const LibcSpecifics = struct {
    const WriteOps = struct {
        const ValueKind = enum {
            auxv,
            tls_size,
            tls_align,
            tls_count,
            page_size,
            tp,
            tid,
            self,
            addr,
        };

        addr: usize,
        relative_to: enum { zero, tp },
        value: union(ValueKind) {
            auxv: void,
            tls_size: void,
            tls_align: void,
            tls_count: void,
            page_size: void,
            tp: void,
            tid: void,
            self: void,
            addr: usize,
        },
    };

    kind: enum { custom, glibc, musl },
    write_ops: std.ArrayList(WriteOps),
};

// TODO global state
var libc_specifics: ?LibcSpecifics = null;

const InitOptions = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    args: std.process.Args,
    environ: std.process.Environ,
    log_level: Logger.Level = .err,
};

// TODO thread safety
pub fn init(options: InitOptions) !void {
    if (dll_initialized) {
        return error.AlreadyInitialized;
    }

    dll_allocator = options.allocator;
    dll_io = options.io;
    Logger.level = options.log_level;

    dll_alloc_allocator = dll_allocator;

    dll_args = options.args;
    dll_environ = options.environ;

    // TODO
    // - pre restructure TLS early
    // - assert linux x86_64
    // - assert statically linked
    // - assert only one thread

    dll_initialized = true;
}

// TODO thread safety
pub fn deinit() void {
    if (!dll_initialized or dll_deinitializing) {
        return;
    }

    dll_deinitializing = true;
    defer dll_deinitializing = false;

    runThreadDestructors(currentThreadPointer());
    for (dyn_objects.values()) |*dyn_object| dyn_object.finalizing = true;

    var nb_dyn_objects = dyn_objects_init_indices.items.len;
    while (nb_dyn_objects > 0) {
        nb_dyn_objects -= 1;

        const dyn_object_idx = dyn_objects_init_indices.items[nb_dyn_objects];
        const dyn_object = &dyn_objects.values()[dyn_object_idx];

        if (!dyn_object.init_called) {
            dyn_object.ref_count = 0;
            continue;
        }

        dyn_object.init_called = false;

        var finalizing_object = dyn_object.*;
        callFiniFunctions(&finalizing_object) catch |err| {
            Logger.warn("deinit: unable to close library {s}: {}", .{ finalizing_object.name, err });
        };

        dyn_objects.values()[dyn_object_idx].ref_count = 0;
    }

    CustomSelfInfo.clearExtraElfs(dll_allocator);

    for (dyn_objects.values()) |*dyn_object| {
        dyn_object.binding_dependencies.deinit(dll_allocator);
        if (dyn_object.phdr_name) |name| dll_allocator.free(name);

        if (dyn_object.mapped_at != 0) {
            std.posix.munmap(@as([*]align(std.heap.pageSize()) u8, @ptrFromInt(dyn_object.mapped_at))[0..dyn_object.mapped_size]);
        }
        if (dyn_object.reservation) |reservation| std.posix.munmap(reservation);

        dyn_object.syms_array.deinit(dll_allocator);

        for (dyn_object.syms.values()) |*v| {
            v.deinit(dll_allocator);
        }
        dyn_object.syms.deinit(dll_allocator);

        dyn_object.relocs.deinit(dll_allocator);
        dyn_object.dependencies.deinit(dll_allocator);
        dyn_object.deps_breadth_first.deinit(dll_allocator);
        dyn_object.segments.deinit(dll_allocator);

        dll_allocator.free(dyn_object.name);
        dll_allocator.free(dyn_object.path);
        if (dyn_object.runpath) |runpath| {
            dll_allocator.free(runpath);
        }

        if (dyn_object.file_handle != -1) {
            _ = std.os.linux.close(dyn_object.file_handle);
        }
    }

    dyn_objects.clearAndFree(dll_allocator);
    dyn_objects_sorted_indices.deinit(dll_allocator);
    dyn_objects_init_indices.deinit(dll_allocator);
    preload_root_indices.deinit(dll_allocator);
    dl_handles.clearAndFree(dll_allocator);

    for (load_request_cache.keys()) |key| {
        dll_allocator.free(key);
    }
    load_request_cache.deinit(dll_allocator);

    ifunc_resolved_addrs.clearAndFree(dll_allocator);
    irel_resolved_targets.clearAndFree(dll_allocator);

    const current_tls_area_desc = std.os.linux.tls.area_desc;
    if (current_tls_area_desc.gdt_entry_number != @as(usize, @bitCast(@as(isize, -1)))) {
        dll_allocator.free(current_tls_area_desc.block.init);
    }

    for (extra_strs.items) |e| {
        dll_allocator.free(e);
    }
    extra_strs.deinit(dll_allocator);

    for (extra_phdrs.items) |e| {
        dll_allocator.destroy(e);
    }
    extra_phdrs.deinit(dll_allocator);

    for (extra_link_maps.items) |e| {
        dll_allocator.destroy(e);
    }
    extra_link_maps.deinit(dll_allocator);

    for (extra_threads.items) |e| {
        dll_allocator.destroy(e);
    }
    extra_threads.deinit(dll_allocator);

    if (last_dl_error) |dle| {
        dll_allocator.free(dle);
        last_dl_error = null;
    }

    thread_infos.clearAndFree(dll_allocator);

    thread_destructors.deinit(dll_allocator);

    if (libc_specifics != null) {
        libc_specifics.?.write_ops.deinit(dll_allocator);
    }

    if (extra_allocations.count() > 0) {
        var not_freed: usize = 0;
        for (extra_allocations.values()) |ea| {
            not_freed += ea.r_size;
            dll_alloc_allocator.free(@as([*]u8, @ptrFromInt(ea.addr))[0..ea.size]);
        }

        Logger.info("{B:.2} of memory allocated ({d} allocations) from libraries not freed", .{ not_freed, extra_allocations.count() });
    }
    extra_allocations.clearAndFree(dll_allocator);

    for (extra_strs_z.items) |e| {
        dll_allocator.free(e);
    }
    extra_strs_z.deinit(dll_allocator);

    dll_initialized = false;

    // TODO restore the TLS initial setup
}

fn logSummary() void {
    if (Logger.level != .debug) {
        return;
    }

    var buf: [16]u8 = undefined;

    for (dyn_objects.values()) |*dyn_object| {
        if (dyn_object.loaded or dyn_object.mapped_at == 0) {
            continue;
        }

        Logger.debug("name: {s}", .{dyn_object.name});
        Logger.debug("  path: {s}", .{dyn_object.path});
        Logger.debug("  mapped_at: 0x{x}", .{dyn_object.mapped_at});
        Logger.debug("  segments:  {d} segments loaded", .{dyn_object.segments.count()});
        for (dyn_object.segments.values(), 1..) |segment, s| {
            Logger.debug("  - {d}:", .{s});
            Logger.debug("    file_offset: 0x{x}", .{segment.file_offset});
            Logger.debug("    file_size: 0x{x}", .{segment.file_size});
            Logger.debug("    mem_offset: 0x{x}", .{segment.mem_offset});
            Logger.debug("    mem_size: 0x{x}", .{segment.mem_size});
            Logger.debug("    mem_align: 0x{x}", .{segment.mem_align});
            Logger.debug("    loadedAt: 0x{x}", .{segment.loaded_at});
            Logger.debug("    flags_first: {s}", .{segment.flags_first.toStr(&buf) catch unreachable});
            Logger.debug("    flags_last: {s}", .{segment.flags_last.toStr(&buf) catch unreachable});
        }
        Logger.debug("  tls_init_file_offset: 0x{x}", .{dyn_object.tls_init_file_offset});
        Logger.debug("  tls_init_file_size: 0x{x}", .{dyn_object.tls_init_file_size});
        Logger.debug("  tls_init_mem_offset: 0x{x}", .{dyn_object.tls_init_mem_offset});
        Logger.debug("  tls_init_mem_size: 0x{x}", .{dyn_object.tls_init_mem_size});
        Logger.debug("  init: {s} init fn, {d} init_array fns", .{ if (dyn_object.init_addr != 0x0) "1" else "no", dyn_object.init_array_size });
        Logger.debug("    init_addr: 0x{x}", .{dyn_object.init_addr});
        Logger.debug("    init_array_addr: 0x{x}, size: 0x{x}", .{ dyn_object.init_array_addr, dyn_object.init_array_size });
        Logger.debug("  fini: {s} fini fn, {d} fini_array fns", .{ if (dyn_object.fini_addr != 0x0) "1" else "no", dyn_object.fini_array_size });
        Logger.debug("    fini_addr: 0x{x}", .{dyn_object.fini_addr});
        Logger.debug("    fini_array_addr: 0x{x}, size: 0x{x}", .{ dyn_object.fini_array_addr, dyn_object.fini_array_size });
        Logger.debug("  symbols:  {d} symbols", .{dyn_object.syms_array.items.len});
        for (dyn_object.syms_array.items, 0..) |sym, s| {
            Logger.debug("  - index: {d}:", .{s});
            Logger.debug("    name: {s}", .{sym.name});
            Logger.debug("    version: {s}", .{sym.version});
            Logger.debug("    hidden: {}", .{sym.hidden});
            Logger.debug("    offset: 0x{x}", .{sym.offset});
            if (@backingInt(sym.type) <= 6) {
                Logger.debug("    type: {s}", .{@tagName(sym.type)});
            } else {
                Logger.debug("    type: {d}", .{@backingInt(sym.type)});
            }
            if (@backingInt(sym.bind) <= 2) {
                Logger.debug("    bind: {s}", .{@tagName(sym.bind)});
            } else {
                Logger.debug("    bind: {d}", .{@backingInt(sym.bind)});
            }
            Logger.debug("    shidx: {s}", .{sym.sectionNameOrValue(&buf) catch unreachable});
            Logger.debug("    value: 0x{x}", .{sym.value});
            Logger.debug("    size: 0x{x}", .{sym.size});
        }
        Logger.debug("  relocs: {d} relocs", .{dyn_object.relocs.items.len});
        for (dyn_object.relocs.items, 1..) |reloc, s| {
            Logger.debug("  - {d}:", .{s});
            Logger.debug("    type: {s}", .{@tagName(reloc.type)});
            Logger.debug("    sym_idx: 0x{x}", .{reloc.sym_idx});
            Logger.debug("    offset: 0x{x}", .{reloc.offset});
            Logger.debug("    addend: 0x{x}", .{reloc.addend});
        }
    }
}

// TODO thread safety
pub fn resolve(name: []const u8) !?[]const u8 {
    if (!dll_initialized) {
        return error.Uninitialized;
    }

    return resolvePath(name, true, null, null, null) catch |err| switch (err) {
        error.LibraryNotFound => null,
        else => |e| return e,
    };
}

// TODO thread safety
// TODO handle errors gracefully
pub fn loadSystemLibC() !DynamicLibrary {
    if (!dll_initialized) {
        return error.Uninitialized;
    }

    const candidates = [_][]const u8{
        "libc.so.6",
        "libc.so",
    };

    Logger.debug("libc: searching system libc", .{});

    for (candidates) |c| {
        Logger.debug("libc: trying {s}", .{c});

        const path = resolvePath(c, true, null, null, null) catch |err| switch (err) {
            error.LibraryNotFound => continue,
            else => |e| return e,
        };
        defer dll_allocator.free(path);

        const f = try std.Io.Dir.openFileAbsolute(dll_io, path, .{ .mode = .read_only });
        defer f.close(dll_io);

        const stat = try f.stat(dll_io);
        const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;

        if (size < 4) continue;

        var buf: [4]u8 = undefined;
        const read = try f.readPositional(dll_io, &.{&buf}, 0);

        if (read != 4 or !std.mem.eql(u8, &buf, std.elf.MAGIC)) continue;

        return load(c);
    }

    return error.SystemLibcNotFound;
}

// TODO global state
var preloads_processed: bool = false;

fn appendLdExpansions(list: *std.ArrayList([]const u8), value: []const u8, origin_dir: ?[]const u8) !void {
    // TODO max len?
    var expanded_buf: [std.fs.max_path_bytes]u8 = @splat(0);
    var expanded = try std.fmt.bufPrint(&expanded_buf, "{s}", .{value});

    var expanded_tmp_buf: [std.fs.max_path_bytes]u8 = @splat(0);

    // TODO what if `value` contains the same token multiple times?

    var owned_origin: ?[]const u8 = null;
    defer if (owned_origin) |origin| dll_allocator.free(origin);

    const origin = origin_dir orelse blk: {
        owned_origin = try std.process.executableDirPathAlloc(dll_io, dll_allocator);
        break :blk owned_origin.?;
    };

    if (std.mem.find(u8, expanded, "$ORIGIN")) |idx| {
        @memcpy(expanded_tmp_buf[0..expanded.len], expanded);
        expanded = try std.fmt.bufPrint(&expanded_buf, "{s}{s}{s}", .{ expanded_tmp_buf[0..idx], origin, expanded_tmp_buf[idx + "$ORIGIN".len .. expanded.len] });
    }

    if (std.mem.find(u8, expanded, "${ORIGIN}")) |idx| {
        @memcpy(expanded_tmp_buf[0..expanded.len], expanded);
        expanded = try std.fmt.bufPrint(&expanded_buf, "{s}{s}{s}", .{ expanded_tmp_buf[0..idx], origin, expanded_tmp_buf[idx + "${ORIGIN}".len .. expanded.len] });
    }

    if (std.mem.find(u8, expanded, "$PLATFORM")) |idx| {
        const platform_ptr = std.os.linux.getauxval(std.elf.AT.PLATFORM);
        const platform = if (platform_ptr == 0) try dll_allocator.dupe(u8, "x86_64") else try dll_allocator.dupe(u8, std.mem.span(@as([*:0]const u8, @ptrFromInt(platform_ptr))));
        defer dll_allocator.free(platform);
        @memcpy(expanded_tmp_buf[0..expanded.len], expanded);
        expanded = try std.fmt.bufPrint(&expanded_buf, "{s}{s}{s}", .{ expanded_tmp_buf[0..idx], platform, expanded_tmp_buf[idx + "$PLATFORM".len .. expanded.len] });
    }

    if (std.mem.find(u8, expanded, "${PLATFORM}")) |idx| {
        const platform_ptr = std.os.linux.getauxval(std.elf.AT.PLATFORM);
        const platform = if (platform_ptr == 0) try dll_allocator.dupe(u8, "x86_64") else try dll_allocator.dupe(u8, std.mem.span(@as([*:0]const u8, @ptrFromInt(platform_ptr))));
        defer dll_allocator.free(platform);
        @memcpy(expanded_tmp_buf[0..expanded.len], expanded);
        expanded = try std.fmt.bufPrint(&expanded_buf, "{s}{s}{s}", .{ expanded_tmp_buf[0..idx], platform, expanded_tmp_buf[idx + "${PLATFORM}".len .. expanded.len] });
    }

    if (std.mem.find(u8, expanded, "$LIB") == null and std.mem.find(u8, expanded, "${LIB}") == null) {
        try list.append(dll_allocator, try dll_allocator.dupe(u8, expanded));
        return;
    }

    const lib_values = [_][]const u8{ "lib/x86_64-linux-gnu", "lib64", "lib" };

    var expanded_candidate_buf: [std.fs.max_path_bytes]u8 = @splat(0);

    if (std.mem.find(u8, expanded, "$LIB")) |idx| {
        for (lib_values) |lv| {
            const expanded_candidate = try std.fmt.bufPrint(&expanded_candidate_buf, "{s}{s}{s}", .{ expanded[0..idx], lv, expanded[idx + "$LIB".len ..] });
            try list.append(dll_allocator, try dll_allocator.dupe(u8, expanded_candidate));
        }
    }

    if (std.mem.find(u8, expanded, "${LIB}")) |idx| {
        for (lib_values) |lv| {
            const expanded_candidate = try std.fmt.bufPrint(&expanded_candidate_buf, "{s}{s}{s}", .{ expanded[0..idx], lv, expanded[idx + "${LIB}".len ..] });
            try list.append(dll_allocator, try dll_allocator.dupe(u8, expanded_candidate));
        }
    }
}

fn loadPreloads() void {
    if (preloads_processed) {
        return;
    }
    preloads_processed = true;

    const preload_list = dll_environ.getPosix("LD_PRELOAD") orelse return;

    var candidates: std.ArrayList([]const u8) = .empty;
    defer candidates.deinit(dll_allocator);

    var it = std.mem.tokenizeAny(u8, preload_list, ": \t\n\r");
    while (it.next()) |entry| {
        defer {
            for (candidates.items) |candidate| {
                dll_allocator.free(candidate);
            }
            candidates.clearRetainingCapacity();
        }

        appendLdExpansions(&candidates, entry, null) catch |err| {
            Logger.err("preload: cannot expand {s}: {}", .{ entry, err });
            continue;
        };

        var last_err: ?anyerror = null;
        var loaded = false;
        for (candidates.items) |candidate| {
            var real_candidate_buf: [std.fs.max_path_bytes]u8 = undefined;
            const slash_pos = std.mem.findScalar(u8, candidate, '/');
            const real_candidate = blk_rc: {
                if (slash_pos != null and slash_pos.? != 0) {
                    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
                    const cwd_len = std.process.currentPath(dll_io, &cwd_buf) catch |err| {
                        last_err = err;
                        continue;
                    };
                    const cwd = cwd_buf[0..cwd_len];
                    break :blk_rc std.fmt.bufPrint(&real_candidate_buf, "{s}/{s}", .{ cwd, candidate }) catch |err| {
                        last_err = err;
                        continue;
                    };
                } else {
                    break :blk_rc candidate;
                }
            };

            const preload_lib = load(real_candidate) catch |err| {
                last_err = err;
                continue;
            };

            if (std.mem.findScalar(usize, preload_root_indices.items, preload_lib.index) == null) {
                preload_root_indices.append(dll_allocator, preload_lib.index) catch @panic("OOM");
            }

            Logger.info("preload: loaded {s} for {s}", .{ candidate, entry });

            loaded = true;
            break;
        }

        if (!loaded) {
            Logger.warn("preload: unable to load {s}: {}", .{ entry, last_err orelse error.LibraryNotFound });
        }
    }
}

// TODO thread safety
// TODO handle errors gracefully
pub fn load(f_path: []const u8) !DynamicLibrary {
    return loadWithRootResolveContext(f_path, null, null);
}

fn loadWithRootResolveContext(f_path: []const u8, root_runpath: ?[]const u8, root_origin_dir: ?[]const u8) !DynamicLibrary {
    if (!dll_initialized) return error.Uninitialized;
    if (dll_deinitializing) return error.LoaderDeinitializing;

    errdefer unloadUnreferencedObjects() catch |err| Logger.warn("load rollback: {}", .{err});

    loadPreloads();

    const lib: DynamicLibrary = blk: {
        if (load_request_cache.get(f_path)) |cached_lib_idx| {
            break :blk .{ .index = cached_lib_idx };
        }

        const loaded_lib = try loadDepTree(f_path, root_runpath, root_origin_dir);

        const owned_cache_key = try dll_allocator.dupe(u8, f_path);
        errdefer dll_allocator.free(owned_cache_key);

        try load_request_cache.putNoClobber(dll_allocator, owned_cache_key, loaded_lib.index);
        break :blk loaded_lib;
    };

    for (dyn_objects.values()[lib.index].deps_breadth_first.items) |dep_idx| {
        if (dyn_objects.values()[dep_idx].finalizing) return error.LibraryFinalizing;
    }

    const root_dyn_object = &dyn_objects.values()[lib.index];
    for (root_dyn_object.deps_breadth_first.items) |dep_idx| {
        const dep_dyn_object = &dyn_objects.values()[dep_idx];
        dep_dyn_object.ref_count += 1;
    }

    errdefer for (dyn_objects.values()[lib.index].deps_breadth_first.items) |dep_idx| {
        dyn_objects.values()[dep_idx].ref_count -= 1;
    };

    logSummary();

    const relocation_order = try dll_allocator.dupe(usize, dyn_objects_sorted_indices.items);
    defer dll_allocator.free(relocation_order);

    for (relocation_order) |idx| {
        const dyn_obj = &dyn_objects.values()[idx];

        if (dyn_obj.relocated or dyn_obj.mapped_at == 0) {
            continue;
        }

        dyn_obj.pinned = isLibcName(dyn_obj.name) or isLdLinuxName(dyn_obj.name);
        try detectLibC(dyn_obj);

        computeTcbOffset(dyn_obj);
        try processRelocations(dyn_obj);
        try mapTlsBlock(dyn_obj);
        _dl_debug_state();
        try processIRelativeRelocations(dyn_obj);
        dyn_objects.values()[idx].relocated = true;
    }

    const initialization_order = try dll_allocator.dupe(usize, dyn_objects_sorted_indices.items);
    defer dll_allocator.free(initialization_order);

    for (initialization_order) |idx| {
        const dyn_obj = &dyn_objects.values()[idx];
        if (dyn_obj.mapped_at == 0) continue;

        if (!dyn_obj.loaded) {
            try updateSegmentsPermissions(dyn_obj);
            _dl_debug_state();

            dyn_obj.loaded = true;

            const dl_phdr_info = try dll_allocator.create(std.posix.dl_phdr_info);
            var dl_phdr_info_registered = false;
            errdefer if (!dl_phdr_info_registered) dll_allocator.destroy(dl_phdr_info);

            const owned_path_z = try dll_allocator.dupeSentinel(u8, dyn_obj.path, 0);
            errdefer dll_allocator.free(owned_path_z);

            dl_phdr_info.* = .{
                .addr = dyn_obj.loaded_at.?,
                .name = owned_path_z.ptr,
                .phdr = @ptrFromInt(dyn_obj.mapped_at + dyn_obj.eh.e_phoff),
                .phnum = dyn_obj.eh.e_phnum,
            };

            Logger.debug("unwinding: registering {s} at 0x{x}", .{ dyn_obj.name, dyn_obj.loaded_at.? });

            try CustomSelfInfo.addExtraElf(dll_allocator, dl_phdr_info);
            dl_phdr_info_registered = true;
            dyn_obj.phdr_info = dl_phdr_info;
            dyn_obj.phdr_name = owned_path_z;
        }

        if (dyn_obj.ref_count == 0 or dyn_obj.init_called) {
            continue;
        }

        if (dyn_obj.current_epoch == std.math.maxInt(u30)) return error.LibraryGenerationExhausted;

        try dyn_objects_init_indices.ensureUnusedCapacity(dll_allocator, 1);
        dyn_obj.current_epoch += 1;

        dyn_obj.init_called = true;
        var initializing_object = dyn_obj.*;
        callInitFunctions(&initializing_object) catch |err| {
            dyn_objects.values()[idx].init_called = false;
            return err;
        };

        try dyn_objects_init_indices.append(dll_allocator, idx);
    }

    return lib;
}

pub fn getSymbol(sym_name: []const u8) !Symbol {
    if (!dll_initialized) {
        return error.Uninitialized;
    }

    const sym = try getResolvedSymbolByName(null, sym_name, false, false, true);
    return .{
        .addr = sym.address,
    };
}

// TODO inefficient strategy
fn loadDepTree(o_path: []const u8, root_runpath: ?[]const u8, root_origin_dir: ?[]const u8) !DynamicLibrary {
    Logger.debug("dep tree: checking {s}", .{o_path});

    const lib_idx = try loadDso(o_path, root_runpath, root_origin_dir);
    if (dyn_objects.values()[lib_idx].mapped_at != 0) {
        return .{
            .index = lib_idx,
        };
    }

    var has_unloaded = true;
    while (has_unloaded) {
        has_unloaded = false;
        var mapped_count: usize = 0;

        const do_count = dyn_objects.count();

        for (0..do_count) |dyn_object_idx| {
            {
                const dyn_object = &dyn_objects.values()[dyn_object_idx];

                if (!dyn_object.load_requested) continue;

                Logger.debug("dep tree: {d}: checking {s}", .{ dyn_object_idx, dyn_object.name });

                if (dyn_object.mapped_at != 0) {
                    Logger.debug("dep tree: {s} is mapped", .{dyn_object.name});
                    continue;
                }
            }

            has_unloaded = true;

            const dyn_object_path = dyn_objects.values()[dyn_object_idx].path;
            const idx = try loadDso(
                if (dyn_object_idx == lib_idx) o_path else dyn_object_path,
                if (dyn_object_idx == lib_idx) root_runpath else null,
                if (dyn_object_idx == lib_idx) root_origin_dir else null,
            );

            // TODO these two checks are potentially over defensive, maybe we can assert `idx == dyn_object_idx`
            if (dyn_objects.values()[idx].mapped_at != 0) {
                Logger.debug("dep tree: {s} has been mapped", .{dyn_objects.values()[idx].name});
            }
            if (dyn_objects.values()[dyn_object_idx].mapped_at != 0) {
                mapped_count += 1;
            }
        }

        if (has_unloaded and mapped_count == 0 and dyn_objects.count() == do_count) {
            for (dyn_objects.values(), 0..) |dyn_object, dyn_object_idx| {
                if (dyn_object.mapped_at == 0) {
                    Logger.err("dep tree stalled at {d}: {s} => {s}", .{ dyn_object_idx, dyn_object.name, dyn_object.path });
                    break;
                }
            }
            return error.DependencyLoadStalled;
        }
    }

    try logDepTree(&dyn_objects.values()[lib_idx]);

    return .{
        .index = lib_idx,
    };
}

// TODO these two functions should be factorized
fn validateSupportedElfHeader(path: []const u8, eh: *const std.elf.Elf64_Ehdr) !void {
    if (!std.mem.eql(u8, eh.e_ident[0..4], std.elf.MAGIC)) return error.NotAnElfFile;
    if (eh.e_ident[std.elf.EI_CLASS] != std.elf.ELFCLASS64) {
        Logger.err("unsupported ELF class for {s}: class={d} data={d} version={d} type={} machine=0x{x} expected_machine=0x{x}", .{ path, eh.e_ident[std.elf.EI_CLASS], eh.e_ident[std.elf.EI_DATA], eh.e_ident[std.elf.EI_VERSION], eh.e_type, @backingInt(eh.e_machine), @backingInt(std.elf.EM.X86_64) });
        return error.UnsupportedElfClass;
    }
    if (eh.e_ident[std.elf.EI_DATA] != std.elf.ELFDATA2LSB) {
        Logger.err("unsupported ELF data encoding for {s}: class={d} data={d} version={d} type={} machine=0x{x} expected_machine=0x{x}", .{ path, eh.e_ident[std.elf.EI_CLASS], eh.e_ident[std.elf.EI_DATA], eh.e_ident[std.elf.EI_VERSION], eh.e_type, @backingInt(eh.e_machine), @backingInt(std.elf.EM.X86_64) });
        return error.UnsupportedElfEndian;
    }
    if (eh.e_machine != std.elf.EM.X86_64) {
        Logger.err("unsupported ELF machine for {s}: class={d} data={d} version={d} type={} machine=0x{x} expected_machine=0x{x}", .{ path, eh.e_ident[std.elf.EI_CLASS], eh.e_ident[std.elf.EI_DATA], eh.e_ident[std.elf.EI_VERSION], eh.e_type, @backingInt(eh.e_machine), @backingInt(std.elf.EM.X86_64) });
        return error.UnsupportedElfMachine;
    }
    if (eh.e_type != .DYN) {
        Logger.err("unsupported ELF type for {s}: class={d} data={d} version={d} type={} machine=0x{x} expected_type={}", .{ path, eh.e_ident[std.elf.EI_CLASS], eh.e_ident[std.elf.EI_DATA], eh.e_ident[std.elf.EI_VERSION], eh.e_type, @backingInt(eh.e_machine), std.elf.ET.DYN });
        return error.UnsupportedElfType;
    }
}

fn isSupportedElfPath(path: []const u8) bool {
    const f = std.Io.Dir.openFileAbsolute(dll_io, path, .{ .mode = .read_only }) catch return false;
    defer f.close(dll_io);

    var eh: std.elf.Elf64_Ehdr = undefined;
    const read = f.readPositional(dll_io, &.{std.mem.asBytes(&eh)}, 0) catch return false;
    if (read != @sizeOf(std.elf.Elf64_Ehdr)) return false;

    return std.mem.eql(u8, eh.e_ident[0..4], std.elf.MAGIC) and
        eh.e_ident[std.elf.EI_CLASS] == std.elf.ELFCLASS64 and
        eh.e_ident[std.elf.EI_DATA] == std.elf.ELFDATA2LSB and
        eh.e_machine == std.elf.EM.X86_64 and
        eh.e_type == .DYN;
}

fn isLdLinuxName(name: []const u8) bool {
    return std.mem.eql(u8, name, "ld-linux-x86-64.so.2") or
        std.mem.eql(u8, name, "ld-linux.so.2");
}

fn findDynObjectIndexByName(name: []const u8) ?usize {
    for (dyn_objects.values(), 0..) |dyn_object, dyn_object_idx| {
        if (std.mem.eql(u8, name, dyn_object.name)) {
            return dyn_object_idx;
        }
    }

    return null;
}

// TODO mimic path resolution of linux-ld better
fn resolvePath(requested_path: []const u8, check_mode: bool, requester_name: ?[]const u8, runpath: ?[]const u8, origin_dir: ?[]const u8) ![]const u8 {
    // TODO max path len
    var buf: [std.fs.max_path_bytes]u8 = @splat(0);

    if (dll_environ.getPosix("LD_LIBRARY_PATH")) |dir_list| {
        var dirs_it = std.mem.splitScalar(u8, dir_list, ':');
        while (dirs_it.next()) |dir| {
            if (dir.len == 0) {
                continue;
            }

            const a_path = if (std.mem.startsWith(u8, dir, "/")) try std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir, requested_path }) else try std.fmt.bufPrint(&buf, "/{s}/{s}", .{ dir, requested_path });

            std.Io.Dir.accessAbsolute(dll_io, a_path, .{ .read = true }) catch continue;
            if (!isSupportedElfPath(a_path)) {
                Logger.debug("skipping unsupported library candidate {s}", .{a_path});
                continue;
            }

            const path = try std.fmt.allocPrint(dll_allocator, "{s}", .{a_path});
            Logger.debug("found {s} via LD_LIBRARY_PATH: {s}", .{ requested_path, path });
            return path;
        }
    }

    if (requester_name) |name| {
        if (isLibcName(name) and isLdLinuxName(requested_path)) {
            if (origin_dir) |dir| {
                const a_path = try std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir, requested_path });

                std.Io.Dir.accessAbsolute(dll_io, a_path, .{ .read = true }) catch {};
                if (isSupportedElfPath(a_path)) {
                    const path = try std.fmt.allocPrint(dll_allocator, "{s}", .{a_path});
                    Logger.debug("found {s} next to libc: {s}", .{ requested_path, path });
                    return path;
                }
            }
        }
    }

    if (runpath) |dir_list| {
        var dirs_it = std.mem.splitScalar(u8, dir_list, ':');
        while (dirs_it.next()) |dir| {
            if (dir.len == 0) {
                continue;
            }

            var candidates: std.ArrayList([]const u8) = .empty;
            defer {
                for (candidates.items) |candidate| {
                    dll_allocator.free(candidate);
                }
                candidates.deinit(dll_allocator);
            }

            try appendLdExpansions(&candidates, dir, origin_dir);
            for (candidates.items) |candidate| {
                const a_path = if (std.mem.startsWith(u8, candidate, "/")) try std.fmt.bufPrint(&buf, "{s}/{s}", .{ candidate, requested_path }) else try std.fmt.bufPrint(&buf, "{s}/{s}", .{ candidate, requested_path });

                std.Io.Dir.accessAbsolute(dll_io, a_path, .{ .read = true }) catch continue;
                if (!isSupportedElfPath(a_path)) {
                    Logger.debug("skipping unsupported library candidate {s}", .{a_path});
                    continue;
                }

                const path = try std.fmt.allocPrint(dll_allocator, "{s}", .{a_path});
                Logger.debug("found {s} via RUNPATH: {s}", .{ requested_path, path });
                return path;
            }
        }
    }

    const lib_dirs = [_][]const u8{
        "/usr/local/lib/x86_64-linux-gnu",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu64",
        "/usr/local/lib64",
        "/lib64",
        "/usr/lib64",
        "/usr/local/lib",
        "/lib",
        "/usr/lib",
        "/usr/x86_64-linux-gnu/lib64",
        "/usr/x86_64-linux-gnu/lib",
    };

    var path: ?[]const u8 = null;
    for (lib_dirs) |dir| {
        const a_path = try std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir, requested_path });

        std.Io.Dir.accessAbsolute(dll_io, a_path, .{ .read = true }) catch continue;
        if (!isSupportedElfPath(a_path)) {
            Logger.debug("skipping unsupported library candidate {s}", .{a_path});
            continue;
        }

        path = try std.fmt.allocPrint(dll_allocator, "{s}", .{a_path});

        Logger.debug("found {s}: {s}", .{ requested_path, path.? });

        break;
    }

    if (path == null) {
        if (check_mode) {
            Logger.debug("cannot find library {s}", .{requested_path});
        } else {
            Logger.err("cannot find library {s}", .{requested_path});
        }
    }

    return path orelse error.LibraryNotFound;
}

const ResolvedDynObjectInfos = struct {
    key: DynObjectId,
    path: []const u8,
};

fn resolveDynObjectInfosByNameOrPath(nameOrPath: []const u8, requester_name: ?[]const u8, runpath: ?[]const u8, origin_dir: ?[]const u8) !ResolvedDynObjectInfos {
    const path: []const u8 = if (std.mem.findScalar(u8, nameOrPath, '/') != null) try dll_allocator.dupe(u8, nameOrPath) else try resolvePath(nameOrPath, false, requester_name, runpath, origin_dir);
    errdefer dll_allocator.free(path);

    const f = try std.Io.Dir.openFileAbsolute(dll_io, path, .{ .mode = .read_only });
    defer f.close(dll_io);

    const stat = try f.stat(dll_io);
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;
    if (size < @sizeOf(std.elf.Elf64_Ehdr)) return error.NotAnElfFile;

    var eh: std.elf.Elf64_Ehdr = undefined;
    const read = try f.readPositional(dll_io, &.{std.mem.asBytes(&eh)}, 0);
    if (read != @sizeOf(std.elf.Elf64_Ehdr)) return error.NotAnElfFile;
    try validateSupportedElfHeader(path, &eh);

    return .{
        .key = .{ .ino = stat.inode },
        .path = path,
    };
}

fn reuseRetiredObjectSlot(key: DynObjectId, path: []const u8) void {
    if (dyn_objects.contains(key)) return;
    for (dyn_objects.values(), 0..) |*dyn_object, idx| {
        if (dyn_object.mapped_at == 0 and !dyn_object.finalizing and std.mem.eql(u8, dyn_object.path, path)) {
            dyn_objects.setKey(idx, key);
            dyn_object.key = key;
            return;
        }
    }
}

fn checkedFileRange(bytes: []const u8, offset: usize, size: usize) ![]const u8 {
    if (offset > bytes.len or size > bytes.len - offset) return error.InvalidElfFileRange;
    return bytes[offset..][0..size];
}

fn elfProgramHeaders(bytes: []const u8, eh: *const std.elf.Elf64_Ehdr) ![]align(1) const std.elf.Elf64.Phdr {
    if (eh.e_phentsize != @sizeOf(std.elf.Elf64.Phdr)) return error.InvalidProgramHeaderSize;
    const table = try checkedFileRange(bytes, eh.e_phoff, @as(usize, eh.e_phnum) * @sizeOf(std.elf.Elf64.Phdr));
    return std.mem.bytesAsSlice(std.elf.Elf64.Phdr, table);
}

fn elfVirtualFileRange(bytes: []const u8, phdrs: []align(1) const std.elf.Elf64.Phdr, address: usize, size: usize) ![]const u8 {
    for (phdrs) |ph| {
        if (ph.type != .LOAD or address < ph.vaddr) continue;
        const offset = address - ph.vaddr;
        if (offset > ph.filesz or size > ph.filesz - offset) continue;
        const file_offset = std.math.add(usize, ph.offset, offset) catch return error.InvalidElfFileRange;
        return checkedFileRange(bytes, file_offset, size);
    }

    return error.AddressNotInFileSegments;
}

fn validateElfMemoryRange(phdrs: []align(1) const std.elf.Elf64.Phdr, address: usize, size: usize, access: enum { write, execute }) !void {
    for (phdrs) |ph| {
        if (ph.type != .LOAD or address < ph.vaddr) continue;
        const offset = address - ph.vaddr;
        if (offset <= ph.memsz and size <= ph.memsz - offset) {
            if (access == .write and !ph.flags.W) return error.UnsupportedTextRelocation;
            if (access == .execute and !ph.flags.X) return error.InvalidRelocationResolver;
            return;
        }
    }

    return error.AddressNotInMappedSegments;
}

fn elfDynamicEntries(bytes: []const u8, phdrs: []align(1) const std.elf.Elf64.Phdr, ph: std.elf.Elf64.Phdr) ![]align(1) const std.elf.Dyn {
    if (ph.filesz % @sizeOf(std.elf.Dyn) != 0) return error.InvalidDynamicSection;
    const table = try checkedFileRange(bytes, ph.offset, ph.filesz);
    if ((try elfVirtualFileRange(bytes, phdrs, ph.vaddr, ph.filesz)).ptr != table.ptr) return error.InvalidDynamicSection;
    const entries = std.mem.bytesAsSlice(std.elf.Dyn, table);
    for (entries, 0..) |entry, idx| {
        if (entry.d_tag == std.elf.DT_NULL) return entries[0..idx];
    }

    return error.UnterminatedDynamicSection;
}

const RelocationTable = struct {
    address: ?usize = null,
    size: ?usize = null,
    entry_size: ?usize = null,

    fn entries(table: RelocationTable, comptime T: type, bytes: []const u8, phdrs: []align(1) const std.elf.Elf64.Phdr) ![]align(1) const T {
        if (table.entry_size) |size| {
            if (size != @sizeOf(T)) return error.InvalidRelocationEntrySize;
        }

        const size = table.size orelse {
            if (table.address != null) return error.MissingRelocationTableSize;
            return &.{};
        };

        if (size == 0) return &.{};

        const address = table.address orelse return error.MissingRelocationTableAddress;
        if (table.entry_size == null) return error.MissingRelocationEntrySize;
        if (size % @sizeOf(T) != 0) return error.InvalidRelocationTableSize;

        return std.mem.bytesAsSlice(T, try elfVirtualFileRange(bytes, phdrs, address, size));
    }
};

fn appendRelaRelocations(relocs: *RelocList, entries: []align(1) const std.elf.Elf64_Rela, phdrs: []align(1) const std.elf.Elf64.Phdr, sym_count: usize) !void {
    for (entries) |entry| {
        const kind: std.elf.R_X86_64 = switch (entry.r_type()) {
            @backingInt(std.elf.R_X86_64.NONE) => continue,
            inline @backingInt(std.elf.R_X86_64.RELATIVE),
            @backingInt(std.elf.R_X86_64.@"64"),
            @backingInt(std.elf.R_X86_64.GLOB_DAT),
            @backingInt(std.elf.R_X86_64.JUMP_SLOT),
            @backingInt(std.elf.R_X86_64.TPOFF64),
            @backingInt(std.elf.R_X86_64.DTPOFF64),
            @backingInt(std.elf.R_X86_64.DTPMOD64),
            @backingInt(std.elf.R_X86_64.TLSDESC),
            @backingInt(std.elf.R_X86_64.IRELATIVE),
            => |value| @fromBackingInt(value),
            else => {
                Logger.err("unsupported relocation type: 0x{x}", .{entry.r_type()});
                return error.UnsupportedRelocationType;
            },
        };

        if (entry.r_sym() >= sym_count) return error.InvalidSymbolIndex;
        if ((kind == .RELATIVE or kind == .IRELATIVE) and entry.r_sym() != 0) return error.InvalidRelocationSymbol;

        try validateElfMemoryRange(phdrs, entry.r_offset, if (kind == .TLSDESC) @sizeOf(TlsDesc) else @sizeOf(usize), .write);

        if (kind == .IRELATIVE) {
            const resolver = std.math.cast(usize, entry.r_addend) orelse return error.InvalidRelocationAddend;
            try validateElfMemoryRange(phdrs, resolver, 1, .execute);
        }

        Logger.debug("  RELA: {s}, sym: 0x{x}, offset: 0x{x}, addend: 0x{x}", .{ @tagName(kind), entry.r_sym(), entry.r_offset, entry.r_addend });

        try relocs.append(dll_allocator, .{
            .type = kind,
            .is_relr = false,
            .sym_idx = entry.r_sym(),
            .offset = entry.r_offset,
            .addend = entry.r_addend,
        });
    }
}

fn appendRelrRelocations(relocs: *RelocList, entries: []align(1) const std.elf.Elf64_Relr, phdrs: []align(1) const std.elf.Elf64.Phdr) !void {
    var next: ?usize = null;
    for (entries) |entry| {
        if (entry & 1 == 0) {
            try appendRelrTarget(relocs, phdrs, entry);
            next = std.math.add(usize, entry, @sizeOf(usize)) catch return error.InvalidRelrAddress;
        } else {
            const start = next orelse return error.InvalidRelrBitmap;
            next = std.math.add(usize, start, 63 * @sizeOf(usize)) catch return error.InvalidRelrAddress;
            for (0..63) |bit| {
                if ((entry >> @as(u6, @intCast(bit + 1))) & 1 != 0) {
                    try appendRelrTarget(relocs, phdrs, start + bit * @sizeOf(usize));
                }
            }
        }
    }
}

fn appendRelrTarget(relocs: *RelocList, phdrs: []align(1) const std.elf.Elf64.Phdr, address: usize) !void {
    try validateElfMemoryRange(phdrs, address, @sizeOf(usize), .write);

    Logger.debug("  RELR: offset: 0x{x}", .{address});

    try relocs.append(dll_allocator, .{ .type = .RELATIVE, .is_relr = true, .sym_idx = 0, .offset = address, .addend = 0 });
}

fn loadDso(o_path: []const u8, root_runpath: ?[]const u8, root_origin_dir: ?[]const u8) !usize {
    const path: []const u8 = if (std.mem.findScalar(u8, o_path, '/') != null) try dll_allocator.dupe(u8, o_path) else try resolvePath(o_path, false, null, root_runpath, root_origin_dir);
    defer dll_allocator.free(path);

    const dyn_object_name = try dll_allocator.dupe(u8, std.fs.path.basename(path));
    defer dll_allocator.free(dyn_object_name);

    if (isLibcName(dyn_object_name)) {
        for (dyn_objects.values()) |*do| {
            if (do.loaded and isLibcName(do.name) and !std.mem.eql(u8, do.path, path)) {
                return error.MultipleLibcs;
            }
        }
    }

    const f = try std.Io.Dir.openFileAbsolute(dll_io, path, .{ .mode = .read_only });
    var file_open = true;
    errdefer if (file_open) f.close(dll_io);

    const stat = try f.stat(dll_io);
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;

    const dyn_object_key: DynObjectId = .{ .ino = stat.inode };

    reuseRetiredObjectSlot(dyn_object_key, path);

    if (dyn_objects.getPtr(dyn_object_key)) |dyn_object| {
        if (dyn_object.finalizing) return error.LibraryFinalizing;
        dyn_object.load_requested = true;
    }

    if (dyn_objects.get(dyn_object_key)) |dyn_object| if (dyn_object.mapped_at != 0) {
        f.close(dll_io);
        file_open = false;

        return dyn_objects.getIndex(dyn_object_key).?;
    };

    if (size < @sizeOf(std.elf.Elf64_Ehdr)) return error.InvalidElfFileRange;

    Logger.debug("loading: {s} [{s}]", .{ o_path, path });

    const file_bytes = try std.posix.mmap(
        null,
        size,
        .{ .READ = true },
        .{ .TYPE = .PRIVATE },
        f.handle,
        0,
    );
    errdefer std.posix.munmap(file_bytes);

    const file_addr = @intFromPtr(file_bytes.ptr);

    const eh: *std.elf.Elf64_Ehdr = @ptrCast(file_bytes);
    try validateSupportedElfHeader(path, eh);

    const phdrs = try elfProgramHeaders(file_bytes, eh);
    if (eh.e_phoff % @alignOf(std.elf.Elf64.Phdr) != 0) return error.InvalidProgramHeaderAlignment;

    for (phdrs) |ph| {
        if (ph.type == .LOAD) {
            if (ph.filesz > ph.memsz) return error.InvalidLoadSegment;
            _ = try checkedFileRange(file_bytes, ph.offset, ph.filesz);
            _ = std.math.add(usize, ph.vaddr, ph.memsz) catch return error.InvalidLoadSegment;
        }
    }

    if (eh.e_shentsize != @sizeOf(std.elf.Elf64.Shdr) or eh.e_shstrndx >= eh.e_shnum) return error.InvalidSectionHeaders;
    if (eh.e_shoff % @alignOf(std.elf.Elf64.Shdr) != 0) return error.InvalidSectionHeaders;
    _ = try checkedFileRange(file_bytes, eh.e_shoff, @as(usize, eh.e_shnum) * @sizeOf(std.elf.Elf64.Shdr));

    if (!dyn_objects.contains(dyn_object_key)) {
        const owned_name = try dll_allocator.dupe(u8, dyn_object_name);
        errdefer dll_allocator.free(owned_name);

        const owned_path = try dll_allocator.dupe(u8, path);
        errdefer dll_allocator.free(owned_path);

        try dyn_objects.putNoClobber(dll_allocator, dyn_object_key, .init(dyn_object_key, owned_name, owned_path));
    }

    Logger.debug("elf type: {s}", .{@tagName(eh.e_type)});

    Logger.debug("sections headers offset: 0x{x}", .{eh.e_shoff});
    Logger.debug("sections headers string table index: {d}", .{eh.e_shstrndx});

    const sh_section_strtbl_addr = file_addr + eh.e_shoff + (eh.e_shstrndx * eh.e_shentsize);
    const sh_strtbl: *std.elf.Shdr = @ptrFromInt(sh_section_strtbl_addr);
    _ = try checkedFileRange(file_bytes, sh_strtbl.sh_offset, sh_strtbl.sh_size);
    const sh_strtab_addr: usize = file_addr + sh_strtbl.sh_offset;

    var maybe_dyn_strtab_addr: ?usize = null;
    var versym_tab_addr: ?usize = null;
    var verdef_tab_addr: usize = undefined;
    var verneed_tab_addr: usize = undefined;

    var plt_got_addr: usize = 0;
    var plt_got_size: usize = 0;

    var maybe_dyn_symtab_addr: ?usize = null;
    var maybe_dyn_symtab_size: ?usize = null;

    var segments: LoadSegmentList = .empty;
    var dependencies: std.ArrayList(usize) = .empty;
    var relocs: RelocList = .empty;

    {
        const reusable = dyn_objects.getPtr(dyn_object_key).?;
        std.mem.swap(LoadSegmentList, &segments, &reusable.segments);
        std.mem.swap(std.ArrayList(usize), &dependencies, &reusable.dependencies);
        std.mem.swap(RelocList, &relocs, &reusable.relocs);
        dependencies.clearRetainingCapacity();
    }

    errdefer {
        relocs.deinit(dll_allocator);
        dependencies.deinit(dll_allocator);
        segments.deinit(dll_allocator);
    }

    Logger.debug("sections headers:", .{});

    var scratch_buf: [1024]u8 = undefined;
    var sh_addr: usize = file_addr + eh.e_shoff;

    var i: usize = 0;
    while (i < eh.e_shnum) : ({
        i += 1;
        sh_addr += eh.e_shentsize;
    }) {
        const sh: *std.elf.Elf64.Shdr = @ptrFromInt(sh_addr);

        if (sh.type != .NOBITS) _ = try checkedFileRange(file_bytes, sh.offset, sh.size);

        const name: [*:0]const u8 = @ptrFromInt(sh_strtab_addr + sh.name);
        Logger.debug("  - {d}:", .{i});
        Logger.debug("    name: {s}", .{name});
        Logger.debug("    link: {d}", .{sh.link});
        Logger.debug("    type: 0x{x}", .{sh.type});
        Logger.debug("    flags: {b}", .{@as(std.elf.Word, @bitCast(sh.flags.shf))});
        Logger.debug("    offset: 0x{x}", .{sh.offset});
        Logger.debug("    size: 0x{x}", .{sh.size});

        if (sh.type == .STRTAB) {
            if (Logger.level == .debug) {
                Logger.debug("    content:", .{});

                const strtab_addr: usize = file_addr + sh.offset;
                const strs: [*]u8 = @ptrFromInt(strtab_addr);

                var j: usize = 0;
                while (j < sh.size) : (j += 1) {
                    var k: usize = 0;
                    while (j < sh.size) : ({
                        k += 1;
                        j += 1;
                    }) {
                        scratch_buf[k] = strs[j];
                        if (strs[j] == 0) {
                            break;
                        }
                    }
                    if (k > 0) {
                        Logger.debug("      - {s}", .{scratch_buf[0..k]});
                    }
                }
            }

            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".dynstr")) {
                maybe_dyn_strtab_addr = file_addr + sh.offset;
            } else if (!std.mem.eql(u8, std.mem.sliceTo(name, 0), ".shstrtab")) {
                Logger.debug("    == TODO: STRTAB: {s}", .{std.mem.sliceTo(name, 0)});
            }
        } else if (sh.type == .DYNSYM) {
            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".dynsym")) {
                maybe_dyn_symtab_addr = file_addr + sh.offset;
                maybe_dyn_symtab_size = sh.size;
            } else {
                Logger.debug("    == TODO: DYNSYM: {s}", .{std.mem.sliceTo(name, 0)});
            }
        } else if (sh.type == std.elf.SHT.GNU_VERSYM) {
            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".gnu.version")) {
                versym_tab_addr = file_addr + sh.offset;
            } else {
                Logger.debug("    == TODO: GNU_VERSYM: {s}", .{std.mem.sliceTo(name, 0)});
            }
        } else if (sh.type == std.elf.SHT.GNU_VERDEF) {
            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".gnu.version_d")) {
                verdef_tab_addr = file_addr + sh.offset;
            } else {
                Logger.debug("    == TODO: GNU_VERDEF: {s}", .{std.mem.sliceTo(name, 0)});
            }
        } else if (sh.type == std.elf.SHT.GNU_VERNEED) {
            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".gnu.version_r")) {
                verneed_tab_addr = file_addr + sh.offset;
            } else {
                Logger.debug("    == TODO: GNU_VERDEF: {s}", .{std.mem.sliceTo(name, 0)});
            }
        } else if (sh.type == std.elf.SHT.PROGBITS) {
            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".plt.got")) {
                plt_got_addr = sh.addr;
                plt_got_size = sh.size;
            } else {
                // Logger.debug("    == TODO: PROGBITS: {s}", .{std.mem.sliceTo(name, 0)});
            }
        } else {
            switch (sh.type) {
                .NULL,
                .PROGBITS,
                .INIT_ARRAY,
                .NOBITS,
                .RELA,
                .RELR,
                .DYNAMIC,
                .FINI_ARRAY,
                => {},
                std.elf.SHT.GNU_HASH => Logger.debug("    == TODO: section type GNU_HASH: {s}", .{name}),
                else => |t| {
                    Logger.debug("    == TODO: section type {s}: {s}", .{ if (@backingInt(t) <= 19) @tagName(t) else try std.fmt.bufPrint(&scratch_buf, "0x{x}", .{t}), name });
                },
            }
        }
    }

    const dyn_strtab_addr = maybe_dyn_strtab_addr orelse {
        Logger.err("missing .dynstr for {s} => {s}", .{ dyn_object_name, path });
        return error.DynamicStringTableNotFound;
    };

    var dyn_runpath: ?[]const u8 = null;
    var ph_addr: usize = file_addr + eh.e_phoff;
    var dyn_addr: usize = undefined;
    var found_dynamic = false;

    i = 0;
    while (i < eh.e_phnum) : ({
        i += 1;
        ph_addr += eh.e_phentsize;
    }) {
        const ph: *std.elf.Elf64.Phdr = @ptrFromInt(ph_addr);

        if (ph.type == .DYNAMIC) {
            found_dynamic = true;
            dyn_addr = ph.vaddr;
            const dyns = try elfDynamicEntries(file_bytes, phdrs, ph.*);

            var runpath_scan_idx: usize = 0;
            while (runpath_scan_idx < dyns.len) : (runpath_scan_idx += 1) {
                if (dyns[runpath_scan_idx].d_tag == std.elf.DT_RUNPATH) {
                    const runpath_z: [*:0]const u8 = @ptrFromInt(dyn_strtab_addr + dyns[runpath_scan_idx].d_val);
                    dyn_runpath = std.mem.span(runpath_z);
                    Logger.debug("dep tree: found RUNPATH: {s} => {s}", .{ dyn_object_name, dyn_runpath.? });
                    break;
                }
            }

            var has_unloaded_deps = false;
            var j: usize = 0;
            while (j < dyns.len) : (j += 1) {
                if (dyns[j].d_tag == std.elf.DT_NEEDED) {
                    const libName: [*:0]u8 = @ptrFromInt(dyn_strtab_addr + dyns[j].d_val);

                    Logger.debug("dep tree: found dependency: {s} => {s}", .{ dyn_object_name, libName });

                    const libNameLen = std.mem.len(libName);
                    const dep_name = libName[0..libNameLen];

                    if (findDynObjectIndexByName(dep_name)) |dep_idx| {
                        const dep = &dyn_objects.values()[dep_idx];
                        if (dep.finalizing) return error.LibraryFinalizing;
                        dep.load_requested = true;
                        if (dep.mapped_at != 0) {
                            Logger.debug("dep tree: registering dependency: {s} => {s}", .{ dyn_object_name, libName });
                            try dependencies.append(dll_allocator, dep_idx);
                        } else {
                            Logger.debug("dep tree: {s} loading deferred", .{dyn_object_name});
                            has_unloaded_deps = true;
                        }
                        continue;
                    }

                    const origin_dir = std.fs.path.dirname(path) orelse "/";
                    const resolved_dep = resolveDynObjectInfosByNameOrPath(dep_name, dyn_object_name, dyn_runpath, origin_dir) catch |err| {
                        Logger.err("unresolved {s} dependency: {s}: {}", .{ dyn_object_name, libName, err });
                        return err;
                    };
                    var resolved_dep_path: ?[]const u8 = resolved_dep.path;
                    errdefer if (resolved_dep_path) |p| dll_allocator.free(p);

                    reuseRetiredObjectSlot(resolved_dep.key, resolved_dep.path);

                    const maybe_dep = dyn_objects.getPtr(resolved_dep.key);
                    if (maybe_dep == null) {
                        // TODO assert DT_NEEDED is not a path
                        const owned_dep_name = try dll_allocator.dupe(u8, dep_name);
                        errdefer dll_allocator.free(owned_dep_name);

                        try dyn_objects.putNoClobber(dll_allocator, resolved_dep.key, .init(resolved_dep.key, owned_dep_name, resolved_dep.path));
                        resolved_dep_path = null;

                        Logger.debug("dep tree: {s} loading deferred", .{dyn_object_name});
                        has_unloaded_deps = true;
                    } else {
                        dll_allocator.free(resolved_dep_path.?);
                        resolved_dep_path = null;

                        const dep = maybe_dep.?;
                        if (dep.finalizing) return error.LibraryFinalizing;
                        dep.load_requested = true;
                        if (dep.mapped_at != 0) {
                            Logger.debug("dep tree: registering dependency: {s} => {s}", .{ dyn_object_name, libName });
                            try dependencies.append(dll_allocator, dyn_objects.getIndex(dep.key).?);
                        } else {
                            Logger.debug("dep tree: {s} loading deferred", .{dyn_object_name});
                            has_unloaded_deps = true;
                        }
                    }
                }
            }

            if (has_unloaded_deps) {
                segments.deinit(dll_allocator);
                relocs.deinit(dll_allocator);
                dependencies.deinit(dll_allocator);

                std.posix.munmap(file_bytes);
                f.close(dll_io);
                file_open = false;

                return dyn_objects.getIndex(dyn_object_key).?;
            }

            break;
        }
    }

    var syms_array: std.ArrayList(DynSym) = .empty;
    var syms: DynSymList = .empty;

    {
        const reusable = dyn_objects.getPtr(dyn_object_key).?;
        std.mem.swap(std.ArrayList(DynSym), &syms_array, &reusable.syms_array);
        std.mem.swap(DynSymList, &syms, &reusable.syms);
    }

    errdefer {
        syms_array.deinit(dll_allocator);

        for (syms.values()) |*v| {
            v.deinit(dll_allocator);
        }
        syms.deinit(dll_allocator);
    }

    if (versym_tab_addr) |vst_addr| {
        Logger.debug("versym table addr: 0x{x}", .{vst_addr});
    }

    const versym_table: ?[*]std.elf.Half = if (versym_tab_addr) |vst| @ptrFromInt(vst) else null;

    if (!found_dynamic) {
        Logger.err("no PT_DYNAMIC segment for {s} => {s}", .{ dyn_object_name, path });
        return error.DynamicSectionNotFound;
    }

    const dyn_symtab_addr = maybe_dyn_symtab_addr orelse {
        Logger.err("missing .dynsym for {s} => {s} (found_dynamic={})", .{ dyn_object_name, path, found_dynamic });
        return error.DynamicSymbolTableNotFound;
    };
    const dyn_symtab_size = maybe_dyn_symtab_size orelse {
        Logger.err("missing .dynsym size for {s} => {s} (found_dynamic={})", .{ dyn_object_name, path, found_dynamic });
        return error.DynamicSymbolTableSizeNotFound;
    };

    Logger.debug("dynamic string table addr: 0x{x}", .{dyn_strtab_addr});
    Logger.debug("dynamic sym table addr: 0x{x}", .{dyn_symtab_addr});

    Logger.debug("{s}: symbols: ", .{dyn_object_name});

    const dyn_sym_count = dyn_symtab_size / @sizeOf(std.elf.Sym);
    Logger.debug("{s}: dynamic symbol count: {d}", .{ dyn_object_name, dyn_sym_count });

    try syms_array.ensureTotalCapacity(dll_allocator, dyn_sym_count);
    try syms.ensureTotalCapacity(dll_allocator, dyn_sym_count);

    for (0..dyn_sym_count) |j| {
        const sym: *std.elf.Elf64.Sym = @ptrFromInt(dyn_symtab_addr + j * @sizeOf(std.elf.Elf64.Sym));

        const strs: [*]u8 = @ptrFromInt(dyn_strtab_addr);
        const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(strs + sym.name)), 0);

        var version: []const u8 = "";
        var ver_sym: ?std.elf.Versym = null;
        var ver_idx: ?u15 = null;

        if (versym_table != null) {
            ver_sym = @bitCast(versym_table.?[j]);
            ver_idx = ver_sym.?.VERSION;

            if (ver_sym == std.elf.Versym.GLOBAL) {
                version = "GLOBAL";
            } else if (ver_sym == std.elf.Versym.LOCAL) {
                version = "LOCAL";
            } else {
                if (sym.shndx == std.elf.SHN_UNDEF) {
                    const ver_table_addr = verneed_tab_addr;

                    var ver_table_cursor = ver_table_addr;
                    var curr_def: *std.elf.Elf64_Verneed = @ptrFromInt(ver_table_cursor);

                    outer: while (true) {
                        var aux: *std.elf.Vernaux = @ptrFromInt(ver_table_cursor + curr_def.vn_aux);
                        while (true) {
                            if (aux.other == ver_idx.?) {
                                version = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(strs + aux.name)), 0);
                                break :outer;
                            }

                            if (aux.next == 0) {
                                break;
                            }
                            aux = @ptrFromInt(@intFromPtr(aux) + aux.next);
                        }

                        if (curr_def.vn_next == 0) {
                            Logger.err("symbol version {d} not found", .{ver_idx.?});
                            return error.SymbolVersionNotFound;
                        }

                        ver_table_cursor += curr_def.vn_next;
                        curr_def = @ptrFromInt(ver_table_cursor);
                    }
                } else {
                    const ver_table_addr = verdef_tab_addr;

                    var ver_table_cursor = ver_table_addr;
                    var curr_def: *std.elf.Verdef = @ptrFromInt(ver_table_cursor);

                    while (true) {
                        if (curr_def.ndx == @as(std.elf.VER_NDX, @fromBackingInt(@intCast(ver_idx.?)))) {
                            const aux: *std.elf.Verdaux = @ptrFromInt(ver_table_cursor + curr_def.aux);

                            version = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(strs + aux.name)), 0);
                            break;
                        }

                        if (curr_def.next == 0) {
                            Logger.err("symbol version {d} not found", .{ver_idx.?});
                            return error.SymbolVersionNotFound;
                        }

                        ver_table_cursor += curr_def.next;
                        curr_def = @ptrFromInt(ver_table_cursor);
                    }
                }
            }
        }

        const hidden = sym.other.visibility != .DEFAULT;
        if (Logger.level == .debug) {
            Logger.debug("{s}  - {d}:", .{ dyn_object_name, j });
            Logger.debug("{s}    name: {s}", .{ dyn_object_name, name });
            Logger.debug("{s}    ver idx: {?d}", .{ dyn_object_name, if (ver_sym) |vs| vs.VERSION else null });
            Logger.debug("{s}    version: {s}", .{ dyn_object_name, version });
            Logger.debug("{s}    hidden: {}", .{ dyn_object_name, hidden });
            if (@backingInt(sym.info.type) <= 6) {
                Logger.debug("{s}    type: {s}", .{ dyn_object_name, @tagName(sym.info.type) });
            } else {
                Logger.debug("{s}    type: {d}", .{ dyn_object_name, @backingInt(sym.info.type) });
            }
            if (@backingInt(sym.info.bind) <= 2) {
                Logger.debug("{s}    bind: {s}", .{ dyn_object_name, @tagName(sym.info.bind) });
            } else {
                Logger.debug("{s}    bind: {d}", .{ dyn_object_name, @backingInt(sym.info.bind) });
            }
            Logger.debug("{s}    value: 0x{x}", .{ dyn_object_name, sym.value });
            Logger.debug("{s}    sh idx: 0x{x}", .{ dyn_object_name, sym.shndx });
            Logger.debug("{s}    size: 0x{x}", .{ dyn_object_name, sym.size });
        }

        const s: DynSym = .{
            .name = name,
            .version = version,
            .hidden = hidden,
            .default_version = if (ver_sym) |vs| !vs.HIDDEN else true,
            .offset = j * @sizeOf(std.elf.Sym),
            .type = sym.info.type,
            .bind = sym.info.bind,
            .shidx = sym.shndx,
            .value = sym.value,
            .size = sym.size,
        };

        const ent = try syms.getOrPut(dll_allocator, s.name);
        if (!ent.found_existing) {
            ent.value_ptr.* = .empty;
        }

        try ent.value_ptr.append(dll_allocator, syms_array.items.len);
        try syms_array.append(dll_allocator, s);
    }

    Logger.debug("program headers offset: 0x{x}", .{eh.e_phoff});
    Logger.debug("program headers:", .{});

    var tls_init_file_offset: usize = 0;
    var tls_init_file_size: usize = 0;
    var tls_init_mem_offset: usize = 0;
    var tls_init_mem_size: usize = 0;
    var tls_align: usize = 0;

    var eh_init_file_offset: usize = 0;
    var eh_init_file_size: usize = 0;
    var eh_init_mem_offset: usize = 0;
    var eh_init_mem_size: usize = 0;
    var eh_align: usize = 0;

    var init_addr: usize = 0;
    var fini_addr: usize = 0;
    var init_array_addr: usize = 0;
    var init_array_size: usize = 0;
    var fini_array_addr: usize = 0;
    var fini_array_size: usize = 0;

    ph_addr = file_addr + eh.e_phoff;

    i = 0;
    while (i < eh.e_phnum) : ({
        i += 1;
        ph_addr += eh.e_phentsize;
    }) {
        const ph: *std.elf.Elf64.Phdr = @ptrFromInt(ph_addr);

        if (Logger.level == .debug) {
            Logger.debug("  - {d}", .{i});
            Logger.debug("    type: 0x{x}", .{ph.type});
            Logger.debug("    flags: {b}", .{@as(std.elf.Word, @bitCast(ph.flags))});
            Logger.debug("    offset: 0x{x}", .{ph.offset});
            Logger.debug("    v_addr: 0x{x}", .{ph.vaddr});
            Logger.debug("    fsize: 0x{x}", .{ph.filesz});
            Logger.debug("    msize: 0x{x}", .{ph.memsz});
        }

        if (ph.type == .LOAD) {
            const segment: LoadSegment = .{
                .file_offset = ph.offset,
                .file_size = ph.filesz,
                .mem_offset = ph.vaddr,
                .mem_size = ph.memsz,
                .mem_align = ph.@"align",
                .mapped_from_file = false,
                .flags_first = .{
                    .read = ph.flags.R,
                    .write = ph.flags.W,
                    .exec = ph.flags.X,
                    .mem_offset = ph.vaddr,
                    .mem_size = ph.memsz,
                },
                .flags_last = .{
                    .read = ph.flags.R,
                    .write = ph.flags.W,
                    .exec = ph.flags.X,
                    .mem_offset = ph.vaddr,
                    .mem_size = ph.memsz,
                },
                .loaded_at = 0,
            };

            try segments.put(dll_allocator, segment.mem_offset, segment);
        } else if (ph.type == std.elf.PT.GNU_RELRO) {
            var segment = segments.get(ph.vaddr) orelse return error.SegmentNotFound;

            std.debug.assert(segment.flags_last.mem_offset == segment.flags_first.mem_offset and segment.flags_last.mem_size == segment.flags_first.mem_size);

            segment.flags_last = .{
                .read = ph.flags.R,
                .write = ph.flags.W,
                .exec = ph.flags.X,
                .mem_offset = ph.vaddr,
                .mem_size = ph.memsz,
            };

            try segments.put(dll_allocator, segment.mem_offset, segment);
        } else if (ph.type == .TLS) {
            tls_init_file_offset = ph.offset;
            tls_init_file_size = ph.filesz;
            tls_init_mem_offset = ph.vaddr;
            tls_init_mem_size = ph.memsz;
            tls_align = ph.@"align";
        } else if (ph.type == std.elf.PT.GNU_EH_FRAME) {
            eh_init_file_offset = ph.offset;
            eh_init_file_size = ph.filesz;
            eh_init_mem_offset = ph.vaddr;
            eh_init_mem_size = ph.memsz;
            eh_align = ph.@"align";
        } else if (ph.type == .DYNAMIC) {
            dyn_addr = ph.vaddr;
            const dyns = try elfDynamicEntries(file_bytes, phdrs, ph.*);

            var runpath: [*:0]u8 = undefined;
            var rela_reloc_nb_entry: usize = 0;
            var rela_table: RelocationTable = .{};
            var relr_table: RelocationTable = .{};
            var plt_table: RelocationTable = .{ .entry_size = @sizeOf(std.elf.Elf64_Rela) };
            var plt_reloc_type: usize = 0;
            var dt_plt_got_addr: usize = 0;

            var j: usize = 0;
            while (j < dyns.len) : (j += 1) {
                Logger.debug("      DT type 0x{x}: 0x{x}", .{ dyns[j].d_tag, dyns[j].d_val });

                if (dyns[j].d_tag == std.elf.DT_RUNPATH) {
                    runpath = @ptrFromInt(dyn_strtab_addr + dyns[j].d_val);
                    Logger.debug("        => lib RUNPATH: {s}", .{runpath});
                } else if (dyns[j].d_tag == std.elf.DT_RELA) {
                    rela_table.address = dyns[j].d_val;
                    Logger.debug("        => rela reloc table vaddr: 0x{x}", .{rela_table.address.?});
                } else if (dyns[j].d_tag == std.elf.DT_RELASZ) {
                    rela_table.size = dyns[j].d_val;
                } else if (dyns[j].d_tag == std.elf.DT_RELAENT) {
                    rela_table.entry_size = dyns[j].d_val;
                } else if (dyns[j].d_tag == std.elf.DT_RELACOUNT) {
                    rela_reloc_nb_entry = dyns[j].d_val;
                    Logger.debug("        => rela reloc nb entry: {d}", .{rela_reloc_nb_entry});
                } else if (dyns[j].d_tag == std.elf.DT_RELR) {
                    relr_table.address = dyns[j].d_val;
                    Logger.debug("        => relr reloc table vaddr: 0x{x}", .{relr_table.address.?});
                } else if (dyns[j].d_tag == std.elf.DT_RELRSZ) {
                    relr_table.size = dyns[j].d_val;
                } else if (dyns[j].d_tag == std.elf.DT_RELRENT) {
                    relr_table.entry_size = dyns[j].d_val;
                } else if (dyns[j].d_tag == std.elf.DT_REL or dyns[j].d_tag == std.elf.DT_RELSZ) {
                    if (dyns[j].d_val != 0) return error.UnsupportedRelocationFormat;
                } else if (dyns[j].d_tag == std.elf.DT_PLTREL) {
                    plt_reloc_type = dyns[j].d_val;
                    Logger.debug("        => plt reloc type: 0x{x}", .{plt_reloc_type});
                } else if (dyns[j].d_tag == std.elf.DT_PLTRELSZ) {
                    plt_table.size = dyns[j].d_val;
                } else if (dyns[j].d_tag == std.elf.DT_JMPREL) {
                    plt_table.address = dyns[j].d_val;
                    Logger.debug("        => plt reloc table vaddr: 0x{x}", .{plt_table.address.?});
                } else if (dyns[j].d_tag == std.elf.DT_PLTGOT) {
                    dt_plt_got_addr = dyns[j].d_val;
                    Logger.debug("        => plt got vaddr: 0x{x}", .{dt_plt_got_addr});
                } else if (dyns[j].d_tag == std.elf.DT_INIT) {
                    init_addr = dyns[j].d_val;
                    Logger.debug("        => init addr: 0x{x}", .{init_addr});
                } else if (dyns[j].d_tag == std.elf.DT_FINI) {
                    fini_addr = dyns[j].d_val;
                    Logger.debug("        => fini addr: 0x{x}", .{fini_addr});
                } else if (dyns[j].d_tag == std.elf.DT_INIT_ARRAY) {
                    init_array_addr = dyns[j].d_val;
                    Logger.debug("        => init array addr: 0x{x}", .{init_array_addr});
                } else if (dyns[j].d_tag == std.elf.DT_INIT_ARRAYSZ) {
                    init_array_size = dyns[j].d_val;
                    Logger.debug("        => init array size: 0x{x}", .{init_array_size});
                } else if (dyns[j].d_tag == std.elf.DT_FINI_ARRAY) {
                    fini_array_addr = dyns[j].d_val;
                    Logger.debug("        => fini array addr: 0x{x}", .{fini_array_addr});
                } else if (dyns[j].d_tag == std.elf.DT_FINI_ARRAYSZ) {
                    fini_array_size = dyns[j].d_val;
                    Logger.debug("        => fini array size: 0x{x}", .{fini_array_size});
                } else if (dyns[j].d_tag == std.elf.DT_FLAGS) {
                    Logger.debug("        => TODO: DT_FLAGS: 0x{x}", .{dyns[j].d_val});
                } else if (dyns[j].d_tag == std.elf.DT_FLAGS_1) {
                    Logger.debug("        => TODO: DT_FLAGS_1: 0x{x}", .{dyns[j].d_val});
                } else if (dyns[j].d_tag == std.elf.DT_SONAME) {
                    Logger.debug("        => TODO: DT_SONAME: 0x{x}", .{dyns[j].d_val});
                } else if (dyns[j].d_tag == std.elf.DT_HASH) {
                    Logger.debug("        => TODO: DT_HASH: 0x{x}", .{dyns[j].d_val});
                } else if (dyns[j].d_tag == std.elf.DT_SYMENT) {
                    Logger.debug("        => TODO: DT_SYMENT: 0x{x}", .{dyns[j].d_val});
                } else if (dyns[j].d_tag == std.elf.DT_GNU_HASH) {
                    Logger.debug("        => TODO: DT_GNU_HASH: 0x{x}", .{dyns[j].d_val});
                } else {
                    switch (dyns[j].d_tag) {
                        std.elf.DT_NEEDED,
                        std.elf.DT_STRTAB,
                        std.elf.DT_SYMTAB,
                        std.elf.DT_STRSZ,
                        std.elf.DT_VERSYM,
                        std.elf.DT_VERNEED,
                        std.elf.DT_VERNEEDNUM,
                        std.elf.DT_VERDEF,
                        std.elf.DT_VERDEFNUM,
                        => {},
                        else => {
                            Logger.debug("        == TODO: DT type 0x{x}: 0x{x}", .{ dyns[j].d_tag, dyns[j].d_val });
                        },
                    }
                }
            }

            const rela_entries = try rela_table.entries(std.elf.Elf64_Rela, file_bytes, phdrs);
            if (rela_reloc_nb_entry > rela_entries.len) return error.InvalidRelativeRelocationCount;
            for (rela_entries[0..rela_reloc_nb_entry]) |entry| {
                if (entry.r_type() != @backingInt(std.elf.R_X86_64.RELATIVE)) return error.InvalidRelativeRelocationCount;
            }
            try appendRelaRelocations(&relocs, rela_entries, phdrs, dyn_sym_count);

            if ((plt_table.size orelse 0) != 0 and plt_reloc_type != std.elf.DT_RELA) return error.UnsupportedRelocationFormat;
            try appendRelaRelocations(&relocs, try plt_table.entries(std.elf.Elf64_Rela, file_bytes, phdrs), phdrs, dyn_sym_count);
            try appendRelrRelocations(&relocs, try relr_table.entries(std.elf.Elf64_Relr, file_bytes, phdrs), phdrs);
        } else {
            Logger.debug("    => TODO: PT type {s}", .{pht_blk: {
                if (@backingInt(ph.type) <= 8) {
                    break :pht_blk @tagName(ph.type);
                } else if (ph.type == std.elf.PT.GNU_STACK) {
                    break :pht_blk "GNU_STACK";
                }
                break :pht_blk try std.fmt.bufPrint(&scratch_buf, "0x{x}", .{@backingInt(ph.type)});
            }});
        }
    }

    if (init_array_size != 0) {
        if (init_array_size % @sizeOf(usize) != 0) return error.InvalidInitArraySize;
        _ = try elfVirtualFileRange(file_bytes, phdrs, init_array_addr, init_array_size);
    }
    if (fini_array_size != 0) {
        if (fini_array_size % @sizeOf(usize) != 0) return error.InvalidFiniArraySize;
        _ = try elfVirtualFileRange(file_bytes, phdrs, fini_array_addr, fini_array_size);
    }

    const do_entry = try dyn_objects.getOrPut(dll_allocator, dyn_object_key);
    const previous_dyn_object: ?DynObject = if (do_entry.found_existing) do_entry.value_ptr.* else null;

    {
        const owned_name = try dll_allocator.dupe(u8, dyn_object_name);
        errdefer dll_allocator.free(owned_name);

        const owned_path = try dll_allocator.dupe(u8, path);
        errdefer dll_allocator.free(owned_path);

        const owned_runpath = if (dyn_runpath) |runpath| try dll_allocator.dupe(u8, runpath) else null;
        errdefer if (owned_runpath) |runpath| dll_allocator.free(runpath);

        do_entry.value_ptr.* = .{
            .key = dyn_object_key,
            .name = owned_name,
            .path = owned_path,
            .runpath = owned_runpath,
            .file_handle = f.handle,
            .mapped_at = file_addr,
            .mapped_size = file_bytes.len,
            .segments = segments,
            .tls_init_file_offset = tls_init_file_offset,
            .tls_init_file_size = tls_init_file_size,
            .tls_init_mem_offset = tls_init_mem_offset,
            .tls_init_mem_size = tls_init_mem_size,
            .tls_align = tls_align,
            .tls_mapped_at = 0,
            .tls_offset = if (previous_dyn_object) |previous| previous.tls_offset else 0,
            .eh = eh,
            .eh_init_file_offset = eh_init_file_offset,
            .eh_init_file_size = eh_init_file_size,
            .eh_init_mem_offset = eh_init_mem_offset,
            .eh_init_mem_size = eh_init_mem_size,
            .eh_align = eh_align,
            .dyn_section_offset = dyn_addr,
            .plt_got_section_offset = plt_got_addr,
            .plt_got_section_size = plt_got_size,
            .syms = syms,
            .syms_array = syms_array,
            .relocs = relocs,
            .dependencies = dependencies,
            .deps_breadth_first = .empty,
            .init_addr = init_addr,
            .fini_addr = fini_addr,
            .init_array_addr = init_array_addr,
            .init_array_size = init_array_size,
            .fini_array_addr = fini_array_addr,
            .fini_array_size = fini_array_size,
            .loaded = false,
            .init_called = false,
            .current_epoch = if (previous_dyn_object) |previous| previous.current_epoch else 0,
            .ref_count = 0,
            .loaded_at = null,
            .loaded_size = 0,
            .reservation = if (previous_dyn_object) |previous| previous.reservation else null,
            .tls_capacity = if (previous_dyn_object) |previous| previous.tls_capacity else 0,
            .tls_slot_align = if (previous_dyn_object) |previous| previous.tls_slot_align else 0,
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

    segments = .empty;
    dependencies = .empty;
    relocs = .empty;
    syms_array = .empty;
    syms = .empty;

    var dyn_object_installed = true;
    errdefer if (dyn_object_installed) {
        const current_dyn_object = do_entry.value_ptr;
        const current_name = current_dyn_object.name;
        const current_path = current_dyn_object.path;

        current_dyn_object.syms_array.deinit(dll_allocator);
        for (current_dyn_object.syms.values()) |*v| {
            v.deinit(dll_allocator);
        }
        current_dyn_object.syms.deinit(dll_allocator);
        current_dyn_object.relocs.deinit(dll_allocator);
        current_dyn_object.dependencies.deinit(dll_allocator);
        current_dyn_object.deps_breadth_first.deinit(dll_allocator);
        current_dyn_object.segments.deinit(dll_allocator);

        if (previous_dyn_object) |previous| {
            dll_allocator.free(current_name);
            dll_allocator.free(current_path);
            if (current_dyn_object.runpath) |runpath| dll_allocator.free(runpath);
            current_dyn_object.* = previous;
        } else {
            if (current_dyn_object.runpath) |runpath| dll_allocator.free(runpath);
            current_dyn_object.* = .init(dyn_object_key, current_name, current_path);
        }
    };

    const dyn_object = do_entry.value_ptr;

    try collectDepsBreadthFirst(dyn_object);
    try dyn_objects_sorted_indices.ensureUnusedCapacity(dll_allocator, 1);

    try mapSegments(dyn_object, file_bytes);

    f.close(dll_io);
    file_open = false;
    dyn_object.file_handle = -1;

    processRelativeRelocationsFast(dyn_object);

    dyn_objects_sorted_indices.appendAssumeCapacity(dyn_objects.getIndex(dyn_object_key).?);

    Logger.info("{s} loaded => {s}", .{ dyn_object_name, dyn_object.path });

    if (previous_dyn_object) |previous| {
        var previous_to_free = previous;
        previous_to_free.syms_array.deinit(dll_allocator);
        for (previous_to_free.syms.values()) |*v| {
            v.deinit(dll_allocator);
        }
        previous_to_free.syms.deinit(dll_allocator);
        previous_to_free.relocs.deinit(dll_allocator);
        previous_to_free.dependencies.deinit(dll_allocator);
        previous_to_free.deps_breadth_first.deinit(dll_allocator);
        previous_to_free.segments.deinit(dll_allocator);
        previous_to_free.binding_dependencies.deinit(dll_allocator);
        dll_allocator.free(previous_to_free.name);
        dll_allocator.free(previous_to_free.path);
        if (previous_to_free.runpath) |runpath| dll_allocator.free(runpath);
    }

    dyn_object_installed = false;

    return dyn_objects.getIndex(dyn_object_key).?;
}

fn collectDepsBreadthFirst(dyn_object: *DynObject) !void {
    var queue: std.ArrayList(usize) = .empty;
    defer queue.deinit(dll_allocator);

    try queue.append(dll_allocator, dyn_objects.getIndex(dyn_object.key).?);

    while (queue.items.len > 0) {
        const dep_idx = queue.orderedRemove(0);
        if (std.mem.findScalar(usize, dyn_object.deps_breadth_first.items, dep_idx)) |_| {} else try dyn_object.deps_breadth_first.append(dll_allocator, dep_idx);
        const dep = &dyn_objects.values()[dep_idx];
        for (dep.dependencies.items) |sdep_idx| {
            if (std.mem.findScalar(usize, dyn_object.deps_breadth_first.items, sdep_idx)) |_| continue;
            if (std.mem.findScalar(usize, queue.items, sdep_idx)) |_| continue;
            try queue.append(dll_allocator, sdep_idx);
        }
    }

    if (dyn_object.deps_breadth_first.items.len > 0) {
        Logger.debug("deps breadth first: {s} => {s}", .{ dyn_object.name, dyn_object.path });
        for (dyn_object.deps_breadth_first.items) |dep_idx| {
            const dep = &dyn_objects.values()[dep_idx];
            Logger.debug("deps breadth first:   - {s} => {s}", .{ dep.name, dyn_object.path });
        }
    }
}

const indent_buf: [64]u8 = @splat(' ');

fn logDepTree(dyn_object: *const DynObject) !void {
    if (Logger.level != .debug) {
        return;
    }

    var already_visited: std.ArrayList(usize) = .empty;
    defer already_visited.deinit(dll_allocator);

    try logDepTreeInner(dyn_object, 0, &already_visited);
}

fn logDepTreeInner(dyn_object: *const DynObject, level: usize, already_visited: *std.ArrayList(usize)) !void {
    std.debug.assert(level < 32);

    Logger.debug("loaded dep tree:{s} - {s} => {s}", .{ indent_buf[0 .. 2 * level], dyn_object.name, dyn_object.path });

    if (std.mem.findScalar(usize, already_visited.items, dyn_objects.getIndex(dyn_object.key).?)) |_| {
        return;
    }

    try already_visited.append(dll_allocator, dyn_objects.getIndex(dyn_object.key).?);

    if (dyn_object.dependencies.items.len > 0) {
        for (dyn_object.dependencies.items) |dep_idx| {
            const dep = &dyn_objects.values()[dep_idx];
            try logDepTreeInner(dep, level + 1, already_visited);
        }
    }

    // const jdx = already_visited.pop().?;
    // std.debug.assert(jdx == dyn_objects.getIndex(dyn_object.name).?);
}

fn mapSegments(dyn_object: *DynObject, file_bytes: []const u8) !void {
    _ = file_bytes;

    Logger.debug("mapping library {s} with {d} segments", .{ dyn_object.name, dyn_object.segments.count() });

    var mem_end: usize = 0;
    var max_align: usize = 0x1000;

    for (dyn_object.segments.values()) |*segment| {
        std.debug.assert(segment.mem_align >= std.heap.pageSize() and segment.mem_align % std.heap.pageSize() == 0);
        const aligned_mem_end = std.mem.alignForward(usize, segment.mem_offset + segment.mem_size, segment.mem_align);
        mem_end = @max(mem_end, aligned_mem_end);
        max_align = @max(max_align, segment.mem_align);
    }

    const original_mem_end = mem_end;

    mem_end += 0x1000; // add space in case we would want to use it

    const total_mem_size = mem_end;

    Logger.debug("mapping segments: from file, library loaded size: 0x{x} (0x{x} to 0x{x})", .{ total_mem_size, 0, mem_end });

    const previous_reservation = dyn_object.reservation;
    const reusable_reservation = if (previous_reservation) |reservation| blk: {
        const aligned_base = std.mem.alignForward(usize, @intFromPtr(reservation.ptr), max_align);
        break :blk aligned_base + total_mem_size <= @intFromPtr(reservation.ptr) + reservation.len;
    } else false;

    const mapped_space = if (reusable_reservation) previous_reservation.? else std.posix.mmap(
        null,
        total_mem_size + max_align,
        .{},
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    ) catch |err| {
        Logger.err("failed to allocate library space: {s}", .{@errorName(err)});
        return err;
    };
    var mapped_space_owned = true;
    errdefer if (mapped_space_owned) {
        if (!reusable_reservation) std.posix.munmap(mapped_space);
        dyn_object.loaded_at = null;
        dyn_object.loaded_size = 0;
    };

    const base_addr = std.mem.alignForward(usize, @intFromPtr(mapped_space.ptr), max_align);

    dyn_object.loaded_at = base_addr;
    dyn_object.loaded_size = total_mem_size;

    const extra_segment: LoadSegment = .{
        .file_offset = 0,
        .file_size = 0,
        .mem_offset = original_mem_end,
        .mem_size = 0x1000,
        .mem_align = 0x1000,
        .mapped_from_file = false,
        .flags_first = .{
            .read = true,
            .write = true,
            .exec = true,
            .mem_offset = original_mem_end,
            .mem_size = 0x1000,
        },
        .flags_last = .{
            .read = true,
            .write = false,
            .exec = true,
            .mem_offset = original_mem_end,
            .mem_size = 0x1000,
        },
        .loaded_at = dyn_object.loaded_at.? + original_mem_end,
    };

    try dyn_object.segments.put(dll_allocator, original_mem_end, extra_segment);

    Logger.debug("mapping segments: reserved 0x{x} bytes from 0x{x} to 0x{x}", .{ total_mem_size, base_addr, base_addr + total_mem_size });

    var prev_end: usize = 0;

    for (dyn_object.segments.values(), 0..) |*segment, s| {
        Logger.debug("  segment {d}: foff: 0x{x}, moff: 0x{x}, fsize: 0x{x}, msize: 0x{x}", .{ s, segment.file_offset, segment.mem_offset, segment.file_size, segment.mem_size });

        var prot: std.posix.PROT = .{};
        if (segment.flags_first.read) prot.READ = true;
        if (segment.flags_first.write) prot.WRITE = true;
        if (segment.flags_first.exec) prot.EXEC = true;

        const aligned_ptr: [*]align(std.heap.pageSize()) u8 = @ptrFromInt(std.mem.alignBackward(usize, base_addr + segment.mem_offset, segment.mem_align));
        const aligned_end: usize = std.mem.alignForward(usize, base_addr + segment.mem_offset + segment.mem_size, segment.mem_align);
        const aligned_size = aligned_end - @intFromPtr(aligned_ptr);
        const aligned_file_offset = std.mem.alignBackward(usize, segment.file_offset, segment.mem_align);

        segment.loaded_at = base_addr + segment.mem_offset;
        segment.mapped_from_file = true;

        Logger.debug("  segment {d}: mapping: foff: 0x{x}, aligned foff: 0x{x}, from 0x{x} to 0x{x}, size: 0x{x}", .{ s, segment.file_offset, aligned_file_offset, @as(usize, @intFromPtr(aligned_ptr)), aligned_end, aligned_size });
        Logger.debug("  segment {d}: data: from 0x{x} to 0x{x}, size: 0x{x}", .{ s, segment.loaded_at, segment.loaded_at + segment.mem_size, segment.mem_size });

        std.debug.assert(prev_end <= @intFromPtr(aligned_ptr));
        prev_end = aligned_end;

        _ = try std.posix.mmap(
            aligned_ptr,
            aligned_size,
            prot,
            .{
                .TYPE = .PRIVATE,
                .FIXED = true,
            },
            dyn_object.file_handle,
            aligned_file_offset,
        );

        if (segment.file_size != segment.mem_size) {
            Logger.debug("  segment {d}: zeroing from 0x{x} (0x{x}) to 0x{x} (0x{x})", .{
                s,
                segment.mem_offset + segment.file_size,
                segment.loaded_at + segment.file_size,
                segment.mem_offset + segment.mem_size,
                segment.loaded_at + segment.mem_size,
            });

            const zero_start = std.mem.alignForward(usize, segment.loaded_at + segment.file_size, std.heap.pageSize());
            const zero_end: usize = std.mem.alignForward(usize, segment.loaded_at + segment.mem_size, std.heap.pageSize());
            const zero_size = zero_end - zero_start;

            std.debug.assert(zero_end <= base_addr + total_mem_size);

            if (zero_start > segment.loaded_at + segment.file_size) {
                const zero_sub_size = zero_start - (segment.loaded_at + segment.file_size);
                Logger.debug("  segment {d}: memory: zeroing from 0x{x} to 0x{x}, size: 0x{x}", .{ s, segment.loaded_at + segment.file_size, zero_start, zero_sub_size });
                @memset(@as([*]u8, @ptrFromInt(segment.loaded_at))[segment.file_size..][0..zero_sub_size], 0);
            }

            if (zero_size > 0) {
                const zero_ptr: [*]align(std.heap.pageSize()) u8 = @ptrFromInt(zero_start);
                Logger.debug("  segment {d}: mapping: zeroing from 0x{x} to 0x{x}, size: 0x{x}", .{ s, @intFromPtr(zero_ptr), zero_end, zero_size });
                _ = try std.posix.mmap(
                    zero_ptr,
                    zero_size,
                    prot,
                    .{
                        .TYPE = .PRIVATE,
                        .FIXED = true,
                        .ANONYMOUS = true,
                    },
                    -1,
                    0,
                );
            }
        }
    }

    if (!reusable_reservation) if (previous_reservation) |reservation| std.posix.munmap(reservation);
    dyn_object.reservation = mapped_space;
    mapped_space_owned = false;

    Logger.debug("successfully mapped {d} segments for {s} at base 0x{x}", .{ dyn_object.segments.count(), dyn_object.name, base_addr });
}

fn processRelativeRelocationsFast(dyn_object: *DynObject) void {
    const base_addr = dyn_object.loaded_at.?;
    for (dyn_object.relocs.items) |reloc| {
        if (reloc.type != .RELATIVE) continue;

        const ptr: *align(1) usize = @ptrFromInt(base_addr + reloc.offset);
        ptr.* = base_addr +% if (reloc.is_relr) ptr.* else @as(usize, @bitCast(reloc.addend));
    }
}

const AbiTcb = extern struct {
    self: *AbiTcb,
};

const ZigTcb = extern struct {
    dummy: usize,
};

const Dtv = extern struct {
    len: usize = 1,
    tls_block: [*]u8,
};

// What libpthread expects at FS:
//
// typedef struct
// {
//   void *tcb; /* Pointer to the TCB.  Not necessarily the
//                 thread descriptor used by libpthread. */
//   dtv_t *dtv;
//   void *self; /* Pointer to the thread descriptor.  */
//   int multiple_threads;
//   int gscope_flag;
//   uintptr_t sysinfo;
//   uintptr_t stack_guard;
//   uintptr_t pointer_guard;
//   unsigned long int unused_vgetcpu_cache[2];
//   /* Bit 0: X86_FEATURE_1_IBT.
//      Bit 1: X86_FEATURE_1_SHSTK.
//    */
//   unsigned int feature_1;
//   int __glibc_unused1;
//   /* Reservation of some values for the TM ABI.  */
//   void *__private_tm[4];
//   /* GCC split stack support.  */
//   void *__private_ss;
//   /* The marker for the current shadow stack.  */
//   unsigned long long int ssp_base;
//   /* Must be kept even if it is no longer used by glibc since programs,
//      like AddressSanitizer, depend on the size of tcbhead_t.  */
//   __128bits __glibc_unused2[8][4] __attribute__ ((aligned (32)));
//
//   void *__padding[8];
// } tcbhead_t;
//
// typedef union dtv
// {
//   size_t counter;
//   struct dtv_pointer pointer;
// } dtv_t;
//
// struct dtv_pointer
// {
//   void *val;                    /* Pointer to data, or TLS_DTV_UNALLOCATED.  */
//   void *to_free;                /* Unaligned pointer, for deallocation.  */
// };
//
// #define TLS_DTV_UNALLOCATED ((void *) -1l)

// TODO global state
var initial_tls_init_file_size: usize = undefined;
var initial_tls_init_mem_size: usize = undefined;
var initial_tls_offset: usize = undefined;
var initial_tls_align: ?usize = null;
var initial_tls_init_block: []const u8 = undefined;

fn computeTcbOffset(dyn_object: *DynObject) void {
    Logger.debug("computing tcb offset of library {s}", .{dyn_object.name});

    if (dyn_object.tls_capacity >= dyn_object.tls_init_mem_size and
        dyn_object.tls_slot_align >= dyn_object.tls_align and
        dyn_object.tls_capacity != 0) return;

    dyn_object.tls_capacity = 0;

    const current_tls_area_desc = normal_current_tls_area_desc orelse std.os.linux.tls.area_desc;

    var new_area_size: usize = 0;
    new_area_size += dyn_object.tls_init_mem_size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, dyn_object.tls_align) else new_area_size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, current_tls_area_desc.alignment) else new_area_size;
    new_area_size += current_tls_area_desc.block.size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, initial_tls_align orelse current_tls_area_desc.alignment) else new_area_size;
    const new_abi_tcb_offset = new_area_size;

    dyn_object.tls_offset = new_abi_tcb_offset;
}

// TODO global state
var current_surplus_size: usize = 0x100000;
var normal_current_tls_area_desc: ?@TypeOf(std.os.linux.tls.area_desc) = null;

fn isLibcName(name: []const u8) bool {
    // alpine use architecture-qualified libc name
    return std.mem.startsWith(u8, name, "libc.so") or
        std.mem.eql(u8, name, "libc.musl-x86_64.so.1") or
        std.mem.eql(u8, name, "ld-musl-x86_64.so.1");
}

const CodeView = struct {
    bytes: []const u8,
    address: usize,

    fn slice(code: CodeView, offset: usize, size: usize) !CodeView {
        if (offset > code.bytes.len or size > code.bytes.len - offset) return error.TruncatedCodePattern;

        const virtual_address = std.math.add(usize, code.address, offset) catch return error.InvalidCodeAddress;
        return .{
            .bytes = code.bytes[offset..][0..size],
            .address = virtual_address,
        };
    }

    fn readI32(code: CodeView, offset: usize) !i32 {
        const operand = try code.slice(offset, 4);
        return std.mem.readInt(i32, operand.bytes[0..4], .little);
    }

    fn relativeTarget(code: CodeView, operand_offset: usize) !usize {
        const operand = try code.slice(operand_offset, 4);
        const next_instruction_address = std.math.add(usize, operand.address, 4) catch return error.InvalidCodeAddress;
        const displacement = try code.readI32(operand_offset);

        return addDisplacement(next_instruction_address, displacement);
    }

    fn addDisplacement(address: usize, displacement: i32) !usize {
        // Widen before negating so the minimum i32 displacement is representable.
        const signed_displacement: i64 = displacement;
        if (signed_displacement < 0) {
            return std.math.sub(usize, address, @intCast(-signed_displacement)) catch error.InvalidCodeAddress;
        }

        return std.math.add(usize, address, @intCast(signed_displacement)) catch error.InvalidCodeAddress;
    }

    // Only the gap is variable. Callers supply complete known opcode sequences
    // around operands rather than searching for individual call-opcode bytes.
    fn findUnique(code: CodeView, prefix: []const u8, gap_bytes: usize, suffix: []const u8) !?usize {
        const suffix_offset = std.math.add(usize, prefix.len, gap_bytes) catch return error.TruncatedCodePattern;
        const pattern_size = std.math.add(usize, suffix_offset, suffix.len) catch return error.TruncatedCodePattern;
        if (pattern_size == 0 or pattern_size > code.bytes.len) return null;

        var match_offset: ?usize = null;
        for (0..code.bytes.len - pattern_size + 1) |offset| {
            const candidate = code.bytes[offset..][0..pattern_size];
            if (!std.mem.eql(u8, candidate[0..prefix.len], prefix)) continue;
            if (!std.mem.eql(u8, candidate[suffix_offset..], suffix)) continue;

            if (match_offset != null) return error.AmbiguousCodePattern;
            match_offset = offset;
        }

        return match_offset;
    }
};

fn objectCode(dyn_object: *const DynObject, virtual_address: usize, size_bytes: usize) !CodeView {
    for (dyn_object.segments.values()) |segment| {
        if (!segment.flags_first.read or !segment.flags_first.exec) continue;
        if (virtual_address < segment.mem_offset) continue;

        const segment_offset = virtual_address - segment.mem_offset;
        if (segment_offset > segment.mem_size or size_bytes > segment.mem_size - segment_offset) continue;

        const mapped_address = std.math.add(usize, segment.loaded_at, segment_offset) catch return error.InvalidCodeAddress;
        const mapped_bytes: [*]const u8 = @ptrFromInt(mapped_address);
        return .{
            .address = virtual_address,
            .bytes = mapped_bytes[0..size_bytes],
        };
    }

    return error.InvalidCodeAddress;
}

fn symbolCode(dyn_object: *DynObject, name: []const u8) !CodeView {
    const resolved = try getResolvedSymbolByName(dyn_object, name, false, false, true);
    if (&dyn_objects.values()[resolved.dyn_object_idx] != dyn_object) return error.InvalidCodeAddress;

    const symbol = dyn_object.syms_array.items[resolved.sym_idx];
    return objectCode(dyn_object, symbol.value, symbol.size);
}

fn findPltSlot(dyn_object: *const DynObject, target_address: usize, symbol_name: []const u8) !?usize {
    const code = try objectCode(dyn_object, target_address, 6);
    if (!std.mem.eql(u8, code.bytes[0..2], "\xff\x25")) return null; // jmp [rip + disp32]

    const slot_address = try code.relativeTarget(2);
    for (dyn_object.relocs.items) |reloc| {
        if (reloc.offset != slot_address) continue;

        if (reloc.type != .JUMP_SLOT) return error.UnexpectedPltRelocation;

        const symbol = dyn_object.syms_array.items[reloc.sym_idx];
        if (!std.mem.eql(u8, symbol.name, symbol_name)) {
            return error.UnexpectedPltRelocation;
        }

        return slot_address;
    }

    return error.MissingPltRelocation;
}

fn resolveEntryJump(dyn_object: *const DynObject, entry_address: usize) !usize {
    const entry = try objectCode(dyn_object, entry_address, 5);
    if (entry.bytes[0] == 0xe9) return entry.relativeTarget(1); // jmp rel32

    const frame_pointer_wrapper =
        "\x55" ++ // push rbp
        "\x48\x89\xe5" ++ // mov rbp,rsp
        "\x5d" ++ // pop rbp
        "\xe9"; // jmp rel32

    const wrapper = try objectCode(dyn_object, entry_address, frame_pointer_wrapper.len + 4);
    if (std.mem.startsWith(u8, wrapper.bytes, frame_pointer_wrapper)) {
        return wrapper.relativeTarget(frame_pointer_wrapper.len);
    }

    return error.UnrecognizedEntryJump;
}

const CallBinding = union(enum) {
    relocated: struct {
        slot_address: usize,
    },
    internal: struct {
        target_address: usize,
    },
};

const CallProbe = struct {
    edi_value: i32,
    esi_value: ?i32 = null,
};

fn hasPointerResultCheck(bytes: []const u8) bool {
    if (std.mem.startsWith(u8, bytes, "\x48\x85\xc0")) return true; // test rax,rax
    if (bytes.len < 3) return false;

    // mov saved_register,rax
    const rex = bytes[0];
    const opcode = bytes[1];
    const modrm = bytes[2];

    if ((rex & 0xfe) != 0x48 or opcode != 0x89) return false;
    if ((modrm & 0xf8) != 0xc0) return false;

    const destination_index = modrm & 0b111;
    const destination_extension = (rex & 0b0001) << 3;
    const saved_register = destination_index | destination_extension;

    if (saved_register == 0 or saved_register == 4) return false; // rax or rsp

    var following_bytes = bytes[3..];
    if (std.mem.startsWith(u8, following_bytes, "\x83\xc8\xff")) { // or eax,-1
        following_bytes = following_bytes[3..];
    }
    if (std.mem.startsWith(u8, following_bytes, "\xb8\xff\xff\xff\xff")) { // mov eax,-1
        following_bytes = following_bytes[5..];
    }

    // test saved_register,saved_register
    const register_index = saved_register & 0b111;
    const source_field = register_index << 3;
    const destination_field = register_index;
    const test_modrm = 0b11000000 | source_field | destination_field;
    const test_rex: u8 = if (saved_register < 8) 0x48 else 0x4d;
    const test_pointer = [_]u8{ test_rex, 0x85, test_modrm };

    return std.mem.startsWith(u8, following_bytes, &test_pointer);
}

fn findCheckedCallOperand(code: CodeView, probe: CallProbe) !usize {
    const instruction_limit = 16;
    const search_span_bytes = 64;
    var call_operand_offset: ?usize = null;

    for (0..code.bytes.len) |anchor_offset| {
        if (code.bytes.len - anchor_offset < 5) break;

        const opcode = code.bytes[anchor_offset];
        const edi_anchor = opcode == 0xbf and try code.readI32(anchor_offset + 1) == probe.edi_value;
        const esi_anchor = if (probe.esi_value) |expected_value|
            opcode == 0xbe and try code.readI32(anchor_offset + 1) == expected_value
        else
            false;

        if (!edi_anchor and !esi_anchor) continue;

        var edi_value_ready = false;
        var esi_value_ready = probe.esi_value == null;
        var cursor = anchor_offset;

        for (0..instruction_limit) |_| {
            if (cursor >= code.bytes.len or cursor - anchor_offset >= search_span_bytes) break;

            const bytes = code.bytes[cursor..];

            if (bytes[0] == 0xe8) {
                if (bytes.len < 5 or !edi_value_ready or !esi_value_ready) break;
                if (!hasPointerResultCheck(bytes[5..])) break;

                const operand_offset = cursor + 1;
                if (call_operand_offset) |previous_offset| {
                    if (previous_offset != operand_offset) return error.AmbiguousCodePattern;
                }

                call_operand_offset = operand_offset;
                break;
            }

            // mov r32,imm32
            if (bytes.len >= 5 and bytes[0] >= 0xb8 and bytes[0] <= 0xbf) {
                if (bytes[0] == 0xbf) {
                    edi_value_ready = try code.readI32(cursor + 1) == probe.edi_value;
                }
                if (bytes[0] == 0xbe) {
                    if (probe.esi_value) |expected_value| {
                        esi_value_ready = try code.readI32(cursor + 1) == expected_value;
                    }
                }
                cursor += 5;
                continue;
            }

            const is_push = bytes[0] >= 0x50 and bytes[0] <= 0x57;
            if (is_push or bytes[0] == 0x90) {
                cursor += 1;
                continue;
            }
            if (bytes.len >= 2 and bytes[0] == 0x41 and bytes[1] >= 0x50 and bytes[1] <= 0x57) {
                cursor += 2; // push r8..r15
                continue;
            }

            // mov r64,r64
            if (bytes.len >= 3) {
                const rex = bytes[0];
                const modrm = bytes[2];
                const is_register_move = (rex & 0xfa) == 0x48 and bytes[1] == 0x89 and modrm >= 0xc0;
                if (is_register_move) {
                    const destination_index = modrm & 0b111;
                    const destination_extension = (rex & 0b0001) << 3;
                    const destination_register = destination_index | destination_extension;

                    if (destination_register == 7) {
                        edi_value_ready = false;
                    }
                    if (destination_register == 6 and probe.esi_value != null) {
                        esi_value_ready = false;
                    }
                    cursor += 3;
                    continue;
                }
            }

            if (bytes.len >= 4 and std.mem.startsWith(u8, bytes, "\x48\x83\xec")) {
                cursor += 4; // sub rsp,imm8
                continue;
            }
            if (bytes.len >= 7 and std.mem.startsWith(u8, bytes, "\x48\x81\xec")) {
                cursor += 7; // sub rsp,imm32
                continue;
            }

            break;
        }
    }

    return call_operand_offset orelse error.UnrecognizedCheckedCall;
}

fn detectMuslAllocatorCall(dyn_object: *DynObject, name: []const u8) !CallBinding {
    const is_malloc = std.mem.eql(u8, name, "malloc");
    const probe_name = if (is_malloc) "pthread_atfork" else "__cxa_atexit";
    const probe = try symbolCode(dyn_object, probe_name);
    const arguments: CallProbe = if (is_malloc) .{ .edi_value = 40 } else .{ .edi_value = 520, .esi_value = 1 };
    const call_operand_offset = try findCheckedCallOperand(probe, arguments);
    const target_address = try probe.relativeTarget(call_operand_offset);

    if (try findPltSlot(dyn_object, target_address, name)) |slot_address| {
        return .{ .relocated = .{ .slot_address = slot_address } };
    }

    const public_code = try symbolCode(dyn_object, name);
    if (is_malloc) {
        const internal_implementation = try resolveEntryJump(dyn_object, target_address);
        const public_implementation = try resolveEntryJump(dyn_object, public_code.address);

        if (internal_implementation != public_implementation) return error.UnrecognizedAllocatorTarget;

        // To be sure that the jump destination is in an RW segment
        _ = try objectCode(dyn_object, internal_implementation, 1);

        return .{ .internal = .{ .target_address = target_address } };
    }

    // Chimera's public calloc tail-calls its internal allocator after restoring rsi and the saved registers.
    const calloc_tail_call =
        "\x4c\x89\xf6" ++ // mov rsi,r14
        "\x5b" ++ // pop rbx
        "\x41\x5e" ++ // pop r14
        "\x5d" ++ // pop rbp
        "\xe9"; // jmp rel32

    if (try public_code.findUnique(calloc_tail_call, 4, "")) |tail_call_offset| {
        const jump_operand_offset = tail_call_offset + calloc_tail_call.len;
        const tail_call_target = try public_code.relativeTarget(jump_operand_offset);

        if (target_address != tail_call_target) return error.UnrecognizedAllocatorTarget;
    } else {
        // GCC builds separate public/internal calloc. Check the shared
        // overflow-check/multiplication sequence.
        const allocation_prefix =
            "\x41\x54" ++ // push r12
            "\x49\x89\xf4" ++ // mov r12,rsi
            "\x55" ++ // push rbp
            "\x53" ++ // push rbx
            "\x48\x85\xf6" ++ // test rsi,rsi
            "\x74\x08" ++ // je past overflow check
            "\x48\x89\xf0" ++ // mov rax,rsi
            "\x48\xf7\xe7" ++ // mul rdi
            "\x70\x3f" ++ // jo allocation failure
            "\x4c\x0f\xaf\xe7" ++ // imul r12,rdi
            "\x4c\x89\xe7" ++ // mov rdi,r12
            "\xe8"; // call rel32
        const result_check =
            "\x48\x89\xc3" ++ // mov rbx,rax
            "\x48\x85\xc0"; // test rax,rax

        const sequence_size = allocation_prefix.len + 4 + result_check.len;
        const internal_code = try objectCode(dyn_object, target_address, sequence_size);

        const public_match = try public_code.findUnique(allocation_prefix, 4, result_check);
        if (public_match != 0) return error.UnrecognizedAllocatorTarget;

        const internal_match = try internal_code.findUnique(allocation_prefix, 4, result_check);
        if (internal_match != 0) return error.UnrecognizedAllocatorTarget;

        const public_malloc_target = try public_code.relativeTarget(allocation_prefix.len);
        const malloc_slot = try findPltSlot(dyn_object, public_malloc_target, "malloc");
        if (malloc_slot == null) return error.UnrecognizedAllocatorTarget;

        const malloc_code = try symbolCode(dyn_object, "malloc");
        const internal_malloc_target = try internal_code.relativeTarget(allocation_prefix.len);
        const internal_implementation = try resolveEntryJump(dyn_object, internal_malloc_target);
        const public_implementation = try resolveEntryJump(dyn_object, malloc_code.address);

        if (internal_implementation != public_implementation) return error.UnrecognizedAllocatorTarget;

        _ = try objectCode(dyn_object, internal_implementation, 1);
    }

    return .{ .internal = .{ .target_address = target_address } };
}

const GlibcTlsOffsets = struct {
    tls_size_offset: u32,
    tls_align_offset: u32,
};

fn detectGlibcTlsOffsets(code: CodeView) !GlibcTlsOffsets {
    const division_patterns = [_][]const u8{
        "\x49\xf7\xf0", // div r8
        "\x48\xf7\xf6", // div rsi
    };
    var division_offset: ?usize = null;
    for (division_patterns) |pattern| {
        if (try code.findUnique(pattern, 0, "")) |offset| {
            if (division_offset != null) return error.AmbiguousCodePattern;
            division_offset = offset;
        }
    }

    const search_end = division_offset orelse return error.UnableToDetectGlibcRtldGlobalFieldOffset;
    const search_start = search_end -| 64;
    const loads = try code.slice(search_start, search_end - search_start);

    const LoadPattern = struct {
        prefix: []const u8,
        suffix: []const u8,
        layout: enum { scalar, vector },
    };
    const load_patterns = [_]LoadPattern{
        .{
            .prefix = "\x4c\x8b\x80", // mov r8,[rax + align_offset]
            .suffix = "\x48\x8b\x88", // mov rcx,[rax + size_offset]
            .layout = .scalar,
        },
        .{
            .prefix = "\x48\x8b\xb0", // mov rsi,[rax + align_offset]
            .suffix = "\x48\x8b\x88", // mov rcx,[rax + size_offset]
            .layout = .scalar,
        },
        .{
            .prefix = "\xf3\x0f\x6f\x80", // movdqu xmm0,[rax + size_offset]
            .suffix = "\x48\x8b\x70\x18", // mov rsi,[rax + 24]
            .layout = .vector,
        },
    };

    var result: ?GlibcTlsOffsets = null;
    for (load_patterns) |pattern| {
        const match_offset = (try loads.findUnique(pattern.prefix, 4, pattern.suffix)) orelse continue;
        if (result != null) return error.AmbiguousCodePattern;

        const first_operand_offset = match_offset + pattern.prefix.len;
        const first_field_offset = try loads.readI32(first_operand_offset);
        var size_offset: i32 = undefined;
        var alignment_offset: i32 = undefined;

        switch (pattern.layout) {
            .scalar => {
                const second_operand_offset = first_operand_offset + 4 + pattern.suffix.len;
                size_offset = try loads.readI32(second_operand_offset);
                alignment_offset = first_field_offset;
            },
            .vector => {
                size_offset = first_field_offset;
                alignment_offset = std.math.add(i32, first_field_offset, 8) catch return error.InvalidCodeAddress;
            },
        }

        if (size_offset < 0 or alignment_offset < 0 or
            @mod(size_offset, 8) != 0 or @mod(alignment_offset, 8) != 0 or
            size_offset == alignment_offset)
        {
            return error.UnableToDetectGlibcRtldGlobalFieldOffset;
        }

        result = .{
            .tls_size_offset = @intCast(size_offset),
            .tls_align_offset = @intCast(alignment_offset),
        };
    }

    return result orelse error.UnableToDetectGlibcRtldGlobalFieldOffset;
}

const MuslLayout = struct {
    mapped_address: usize,
    auxv_offset: usize,
    tls_size_offset: usize,
    tls_align_offset: usize,
    page_size_offset: usize,
};

const LibcLayout = union(enum) {
    musl: MuslLayout,
    glibc: struct {
        rtld_mapped_address: usize,
        tls_offsets: ?GlibcTlsOffsets,
    },
};

fn findLibcSymbol(dyn_object: *DynObject, name: []const u8) !?ResolvedSymbol {
    return getResolvedSymbolByName(dyn_object, name, false, false, true) catch |err| switch (err) {
        error.UnresolvedSymbol => null,
        else => return err,
    };
}

fn mappedDataAddress(dyn_object: *const DynObject, virtual_address: usize, size_bytes: usize) !usize {
    for (dyn_object.segments.values()) |segment| {
        if (!segment.flags_first.read or segment.flags_first.exec) continue;
        if (virtual_address < segment.mem_offset) continue;

        const offset = virtual_address - segment.mem_offset;
        if (offset > segment.mem_size or size_bytes > segment.mem_size - offset) continue;

        return std.math.add(usize, segment.loaded_at, offset) catch error.InvalidLibcDataAddress;
    }

    return error.InvalidLibcDataAddress;
}

fn detectMuslLayout(dyn_object: *DynObject) !MuslLayout {
    const code = try symbolCode(dyn_object, "issetugid");

    const Pattern = struct {
        prefix: []const u8,
        suffix: []const u8,
        layout: enum { int_flags, byte_flags },
    };

    const patterns = [_]Pattern{
        .{
            .prefix = "\x8b\x05", // mov eax,[rip + disp32]
            .suffix = "\xc3", // ret
            .layout = .int_flags,
        },
        .{
            .prefix = "\x0f\xbe\x05", // movsx eax,byte [rip + disp32]
            .suffix = "\xc3", // ret
            .layout = .byte_flags,
        },
        .{
            .prefix = "\x55" ++ // push rbp
                "\x48\x89\xe5" ++ // mov rbp,rsp
                "\x0f\xbe\x05", // movsx eax,byte [rip + disp32]
            .suffix = "\x5d\xc3", // pop rbp; ret
            .layout = .byte_flags,
        },
    };

    var detected: ?MuslLayout = null;
    for (patterns) |pattern| {
        const match_offset = (try code.findUnique(pattern.prefix, 4, pattern.suffix)) orelse continue;
        if (match_offset != 0 or pattern.prefix.len + 4 + pattern.suffix.len != code.bytes.len) continue;
        if (detected != null) return error.AmbiguousCodePattern;

        const secure_address = try code.relativeTarget(pattern.prefix.len);
        const secure_offset: usize = switch (pattern.layout) {
            .int_flags => 8,
            .byte_flags => 2,
        };

        const virtual_address = std.math.sub(usize, secure_address, secure_offset) catch return error.InvalidLibcDataAddress;

        var layout: MuslLayout = switch (pattern.layout) {
            .int_flags => .{
                .mapped_address = 0,
                .auxv_offset = 16,
                .tls_size_offset = 32,
                .tls_align_offset = 40,
                .page_size_offset = 56,
            },
            .byte_flags => .{
                .mapped_address = 0,
                .auxv_offset = 8,
                .tls_size_offset = 24,
                .tls_align_offset = 32,
                .page_size_offset = 48,
            },
        };

        layout.mapped_address = try mappedDataAddress(dyn_object, virtual_address, layout.page_size_offset + @sizeOf(usize));

        if (try findLibcSymbol(dyn_object, "__libc")) |symbol| {
            if (symbol.address != layout.mapped_address) return error.InconsistentMuslLayout;
        }

        detected = layout;
    }

    return detected orelse error.UnrecognizedMuslLayout;
}

fn detectLibcLayout(dyn_object: *DynObject) !LibcLayout {
    const musl_marker = try findLibcSymbol(dyn_object, "issetugid");
    const glibc_marker = try findLibcSymbol(dyn_object, "_rtld_global_ro");

    if (musl_marker != null and glibc_marker != null) return error.AmbiguousLibc;

    if (musl_marker != null) {
        return .{ .musl = try detectMuslLayout(dyn_object) };
    }

    if (glibc_marker) |marker| {
        var tls_offsets: ?GlibcTlsOffsets = null;
        if (try findLibcSymbol(dyn_object, "__libc_early_init")) |_| {
            const code = try symbolCode(dyn_object, "__libc_early_init");
            tls_offsets = try detectGlibcTlsOffsets(code);
        }

        return .{ .glibc = .{
            .rtld_mapped_address = marker.address,
            .tls_offsets = tls_offsets,
        } };
    }

    return error.UnableToDetectLibc;
}

fn getLibcSpecifics(layout: LibcLayout) !LibcSpecifics {
    var specifics: LibcSpecifics = .{
        .kind = switch (layout) {
            .musl => .musl,
            .glibc => .glibc,
        },
        .write_ops = .empty,
    };
    errdefer specifics.write_ops.deinit(dll_allocator);

    switch (layout) {
        .musl => |musl| {
            const program_name = try resolveSymbolByName("program_invocation_name");
            const environment = try resolveSymbolByName("environ");
            const argv: [*c]const [*c]const u8 = @ptrCast(dll_args.vector);

            try specifics.write_ops.appendSlice(dll_allocator, &.{
                .{
                    .addr = musl.mapped_address + musl.auxv_offset,
                    .relative_to = .zero,
                    .value = .auxv,
                },
                .{
                    .addr = musl.mapped_address + musl.tls_size_offset,
                    .relative_to = .zero,
                    .value = .tls_size,
                },
                .{
                    .addr = musl.mapped_address + musl.tls_align_offset,
                    .relative_to = .zero,
                    .value = .tls_align,
                },
                .{
                    .addr = musl.mapped_address + musl.page_size_offset,
                    .relative_to = .zero,
                    .value = .page_size,
                },
                .{
                    .addr = program_name.address,
                    .relative_to = .zero,
                    .value = .{ .addr = @intFromPtr(argv[0]) },
                },
                .{
                    .addr = environment.address,
                    .relative_to = .zero,
                    .value = .{ .addr = @intFromPtr(dll_environ.block.slice.ptr) },
                },
            });

            try specifics.write_ops.appendSlice(dll_allocator, &.{
                .{
                    .addr = 0,
                    .relative_to = .tp,
                    .value = .tp,
                },
                .{
                    .addr = 48,
                    .relative_to = .tp,
                    .value = .tid,
                },
                .{
                    .addr = 136,
                    .relative_to = .tp,
                    .value = .self,
                },
            });
        },
        .glibc => |glibc| {
            const auxv_address = std.math.add(usize, glibc.rtld_mapped_address, 104) catch return error.InvalidLibcDataAddress;
            try specifics.write_ops.append(dll_allocator, .{
                .addr = auxv_address,
                .relative_to = .zero,
                .value = .auxv,
            });

            if (glibc.tls_offsets) |offsets| {
                const size_address = std.math.add(usize, glibc.rtld_mapped_address, offsets.tls_size_offset) catch return error.InvalidLibcDataAddress;
                const align_address = std.math.add(usize, glibc.rtld_mapped_address, offsets.tls_align_offset) catch return error.InvalidLibcDataAddress;

                try specifics.write_ops.appendSlice(dll_allocator, &.{
                    .{
                        .addr = size_address,
                        .relative_to = .zero,
                        .value = .tls_size,
                    },
                    .{
                        .addr = align_address,
                        .relative_to = .zero,
                        .value = .tls_align,
                    },
                });
            }

            // TODO detect the fixed glibc auxv and thread-field offsets too.
            try specifics.write_ops.appendSlice(dll_allocator, &.{
                .{
                    .addr = 0,
                    .relative_to = .tp,
                    .value = .tp,
                },
                .{
                    .addr = 16,
                    .relative_to = .tp,
                    .value = .tp,
                },
                .{
                    .addr = 720,
                    .relative_to = .tp,
                    .value = .tid,
                },
            });
        },
    }

    for (specifics.write_ops.items) |op| {
        switch (op.relative_to) {
            .tp => {},
            .zero => {
                const location = try findDynObjectSegmentForLoadedAddr(op.addr);
                const segment = location.dyn_object.segments.values()[location.segment_index];
                const offset = op.addr - segment.loaded_at;

                if (!segment.flags_first.read or segment.flags_first.exec or offset > segment.mem_size or @sizeOf(usize) > segment.mem_size - offset) {
                    return error.InvalidLibcDataAddress;
                }
            },
        }
    }

    return specifics;
}

const LibcCodePatch = struct {
    address: usize,
    segment_index: usize,
    size: usize,
    original: [12]u8,
    replacement: [12]u8,
};

fn appendLibcCodePatch(dyn_object: *DynObject, patches: *std.ArrayList(LibcCodePatch), address: usize, replacement: []const u8) !void {
    std.debug.assert(replacement.len > 0 and replacement.len <= 12);

    const location = try findDynObjectSegmentForLoadedAddr(address);
    if (location.dyn_object != dyn_object) return error.InvalidCodeAddress;

    const segment = dyn_object.segments.values()[location.segment_index];
    const offset = address - segment.loaded_at;

    if (!segment.flags_first.read or !segment.flags_first.exec or offset > segment.mem_size or replacement.len > segment.mem_size - offset) {
        return error.InvalidCodeAddress;
    }

    const end_address = std.math.add(usize, address, replacement.len) catch return error.InvalidCodeAddress;
    for (patches.items) |patch| {
        if (address < patch.address + patch.size and patch.address < end_address) return error.OverlappingLibcPatches;
    }

    var patch: LibcCodePatch = .{
        .address = address,
        .segment_index = location.segment_index,
        .size = replacement.len,
        .original = @splat(0),
        .replacement = @splat(0),
    };

    const original: [*]const u8 = @ptrFromInt(address);

    @memcpy(patch.original[0..patch.size], original[0..patch.size]);
    @memcpy(patch.replacement[0..patch.size], replacement);

    try patches.append(dll_allocator, patch);
}

fn hasPointerResultUse(bytes: []const u8) bool {
    const instruction_limit = 8;
    const search_span_bytes = 64;
    var cursor: usize = 0;

    for (0..instruction_limit) |_| {
        if (cursor >= bytes.len or cursor >= search_span_bytes) return false;

        const remaining = bytes[cursor..];

        if (hasPointerResultCheck(remaining)) return true;
        if (remaining.len < 3) return false;

        const rex = remaining[0];
        const opcode = remaining[1];
        const modrm = remaining[2];

        if (rex < 0x40 or rex > 0x4f) return false;
        if (opcode != 0x89 and opcode != 0x8b and opcode != 0x8d) return false;
        if (opcode != 0x8d and rex & 8 == 0) return false;

        const mode: u2 = @intCast(modrm >> 6);
        const rm_index = modrm & 0b111;
        const register_index = (modrm >> 3) & 0b111;
        const register_extension = (rex & 0b0100) << 1;
        const register_operand = register_index | register_extension;
        var instruction_size: usize = 3;
        var displacement_size: usize = switch (mode) {
            0 => if (rm_index == 5) 4 else 0, // RIP-relative or no displacement
            1 => 1, // disp8
            2 => 4, // disp32
            3 => 0, // register operand
        };

        if (mode != 3 and rm_index == 4) {
            if (remaining.len < 4) return false;

            const base_index = remaining[3] & 0b111;
            instruction_size += 1;
            if (mode == 0 and base_index == 5) {
                displacement_size = 4;
            }
        }

        instruction_size += displacement_size;
        if (remaining.len < instruction_size) return false;

        if (opcode == 0x89) {
            if (register_operand == 0) return true;

            const destination_extension = (rex & 0b0001) << 3;
            const destination_register = rm_index | destination_extension;

            if (mode == 3 and destination_register == 0) return false;
        } else {
            if (register_operand == 0 or (opcode == 0x8d and mode == 3)) return false;
        }

        cursor += instruction_size;
    }

    return false;
}

/// Prepares a trampoline and patches direct call rel32 with pointer-result uses.
fn preparePatches(dyn_object: *DynObject, patches: *std.ArrayList(LibcCodePatch), target_virtual_address: usize, substitute_address: usize, trampoline_offset: usize) !void {
    const loaded_address = dyn_object.loaded_at orelse return error.InvalidCodeAddress;
    const extra_offset = std.math.sub(usize, dyn_object.loaded_size, 0x1000) catch return error.InvalidCodeAddress;
    const extra_address = std.math.add(usize, loaded_address, extra_offset) catch return error.InvalidCodeAddress;
    const trampoline_address = std.math.add(usize, extra_address, trampoline_offset) catch return error.InvalidCodeAddress;

    const extra_location = try findDynObjectSegmentForLoadedAddr(trampoline_address);
    const extra_segment = extra_location.dyn_object.segments.values()[extra_location.segment_index];

    if (extra_segment.file_size != 0 or extra_segment.mem_size != 0x1000) return error.InvalidCodeAddress;

    var trampoline = ("\x48\xb8" ++ // mov rax,imm64
        "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // substitute address
        "\xff\xe0").*; // jmp rax
    std.mem.writeInt(usize, trampoline[2..10], substitute_address, .little);
    try appendLibcCodePatch(dyn_object, patches, trampoline_address, &trampoline);

    var call_count: usize = 0;
    for (dyn_object.segments.values()) |segment| {
        if (!segment.flags_first.read or !segment.flags_first.exec or segment.mem_size < 5) continue;

        const code = try objectCode(dyn_object, segment.mem_offset, segment.mem_size);

        for (0..code.bytes.len - 4) |offset| {
            if (code.bytes[offset] != 0xe8) continue;

            const candidate_target = code.relativeTarget(offset + 1) catch continue;
            if (candidate_target != target_virtual_address) continue;
            if (!hasPointerResultUse(code.bytes[offset + 5 ..])) return error.UnrecognizedCallSite;

            const operand_address = std.math.add(usize, segment.loaded_at, offset + 1) catch return error.InvalidCodeAddress;
            const next_address = std.math.add(usize, operand_address, 4) catch return error.InvalidCodeAddress;
            const distance = @as(i128, trampoline_address) - @as(i128, next_address);
            const displacement = std.math.cast(i32, distance) orelse return error.TrampolineOutOfRange;

            var replacement: [4]u8 = undefined;
            std.mem.writeInt(i32, &replacement, displacement, .little);

            try appendLibcCodePatch(dyn_object, patches, operand_address, &replacement);

            call_count += 1;
        }
    }

    if (call_count == 0) return error.MissingCallSites;
}

fn applyLibcCodePatches(dyn_object: *DynObject, patches: []const LibcCodePatch) !void {
    var applied_count: usize = 0;

    errdefer {
        while (applied_count > 0) {
            applied_count -= 1;
            const patch = patches[applied_count];
            unprotectSegment(dyn_object, patch.segment_index) catch |err| {
                Logger.err("libc patch rollback: {t}", .{err});
                continue;
            };

            const destination: [*]u8 = @ptrFromInt(patch.address);
            @memcpy(destination[0..patch.size], patch.original[0..patch.size]);
            reprotectSegment(dyn_object, patch.segment_index) catch |err| {
                Logger.err("libc patch protection rollback: {t}", .{err});
            };
        }
    }

    for (patches) |patch| {
        try unprotectSegment(dyn_object, patch.segment_index);

        const destination: [*]u8 = @ptrFromInt(patch.address);
        @memcpy(destination[0..patch.size], patch.replacement[0..patch.size]);

        applied_count += 1;

        try reprotectSegment(dyn_object, patch.segment_index);
    }
}

fn detectLibC(dyn_object: *DynObject) !void {
    if (!isLibcName(dyn_object.name)) return;
    std.debug.assert(libc_specifics == null);

    // Detect libc
    const layout = try detectLibcLayout(dyn_object);

    // Prepare specifics
    var specifics = try getLibcSpecifics(layout);
    errdefer specifics.write_ops.deinit(dll_allocator);

    // Prepare allocator patches
    var patches: std.ArrayList(LibcCodePatch) = .empty;
    defer patches.deinit(dll_allocator);

    switch (layout) {
        .musl => {
            const malloc_call = try detectMuslAllocatorCall(dyn_object, "malloc");
            const calloc_call = try detectMuslAllocatorCall(dyn_object, "calloc");

            switch (malloc_call) {
                .relocated => {},
                .internal => |binding| {
                    try preparePatches(dyn_object, &patches, binding.target_address, @intFromPtr(&mallocSubstitute), 0);
                },
            }

            switch (calloc_call) {
                .relocated => {},
                .internal => |binding| {
                    try preparePatches(dyn_object, &patches, binding.target_address, @intFromPtr(&callocSubstitute), 16);
                },
            }
        },
        .glibc => {},
    }

    // Apply patches
    try applyLibcCodePatches(dyn_object, patches.items);

    // Save specifics
    libc_specifics = specifics;
}

// TODO global state
var loader_thread_pointer: usize = 0;

fn mapTlsBlock(dyn_object: *DynObject) !void {
    Logger.debug("mapping tls block of library {s}", .{dyn_object.name});

    if (dyn_object.tls_capacity != 0) {
        try resetTlsSlot(dyn_object);
        return;
    }
    if (dyn_object.tls_init_mem_size == 0 and normal_current_tls_area_desc != null) return;

    const current_tls_area_desc = normal_current_tls_area_desc orelse std.os.linux.tls.area_desc;

    var new_area_size: usize = 0;
    new_area_size += dyn_object.tls_init_mem_size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, dyn_object.tls_align) else new_area_size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, current_tls_area_desc.alignment) else new_area_size;
    const prev_block_offset = new_area_size;
    new_area_size += current_tls_area_desc.block.size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, initial_tls_align orelse current_tls_area_desc.alignment) else new_area_size;
    const new_abi_tcb_offset = new_area_size;
    new_area_size += @sizeOf(AbiTcb);
    new_area_size += @sizeOf(ZigTcb);
    new_area_size = std.mem.alignForward(usize, new_area_size, @alignOf(Dtv));
    const new_dtv_offset = new_area_size;
    new_area_size += @sizeOf(Dtv);

    std.debug.assert(new_abi_tcb_offset == dyn_object.tls_offset);
    std.debug.assert(current_tls_area_desc.abi_tcb.offset - current_tls_area_desc.block.offset == new_abi_tcb_offset - prev_block_offset);
    std.debug.assert(prev_block_offset % current_tls_area_desc.alignment == 0);

    Logger.debug("tls: ({s}) tdata size: 0x{x}", .{ dyn_object.name, dyn_object.tls_init_file_size });
    Logger.debug("tls: ({s}) tbss size: 0x{x}", .{ dyn_object.name, dyn_object.tls_init_mem_size - dyn_object.tls_init_file_size });

    const sizeof_pthread: usize = sp: {
        const sym = resolveSymbolByName("_thread_db_sizeof_pthread") catch {
            Logger.info("no _thread_db_sizeof_pthread symbol found, using defaut 4096", .{});
            break :sp 0x2000 + std.heap.pageSize();
        };
        const sizeof_pthread_ptr: *u32 = @ptrFromInt(sym.address);
        break :sp sizeof_pthread_ptr.* + std.heap.pageSize();
    };
    Logger.debug("tls: size of pthread struct: 0x{x} ({d})", .{ sizeof_pthread, sizeof_pthread });

    const old_tp = currentThreadPointer();
    const prev_area_addr = old_tp - (new_abi_tcb_offset - prev_block_offset);

    Logger.debug("tls: old_tp: 0x{x}, prev area: 0x{x}", .{ old_tp, prev_area_addr });

    var new_area: ?[]u8 = null;
    var owned_tls_mapping: ?[]align(std.heap.pageSize()) u8 = null;
    errdefer if (owned_tls_mapping) |mapping| std.posix.munmap(mapping);

    var area_was_extended = false;

    if (current_tls_area_desc.gdt_entry_number == @as(usize, @bitCast(@as(isize, -1)))) {
        Logger.debug("tls: mapping new area (first time): size: 0x{x} (surplus) + 0x{x} (new_area_size) + 0x{x} (size of pthread struct)", .{ current_surplus_size, new_area_size, sizeof_pthread });
        const space = std.posix.mmap(null, current_surplus_size + new_area_size + sizeof_pthread, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0) catch |err| {
            Logger.err("failed to allocate tls space: {s}", .{@errorName(err)});
            return err;
        };
        owned_tls_mapping = space;
        Logger.debug("tls: setting new area start at 0x{x} (0x{x})", .{ current_surplus_size, @intFromPtr(space.ptr) + current_surplus_size });
        new_area = space[current_surplus_size..];
    } else if (new_area_size > current_tls_area_desc.size and new_area_size <= current_tls_area_desc.size + current_surplus_size) {
        Logger.debug("tls: extending old area: size: 0x{x} (new_area_size) = 0x{x} (surplus) + 0x{x} (current_area_size)", .{ new_area_size, new_area_size - current_tls_area_desc.size, current_tls_area_desc.size });
        Logger.debug("tls: setting new area start at -0x{x} (0x{x})", .{ new_area_size - current_tls_area_desc.size, prev_area_addr - (new_area_size - current_tls_area_desc.size) });
        new_area = @as([*]u8, @ptrFromInt(prev_area_addr - (new_area_size - current_tls_area_desc.size)))[0..new_area_size];
        Logger.debug("tls: setting new surplus size: 0x{x}", .{current_surplus_size - (new_area_size - current_tls_area_desc.size)});
        current_surplus_size -= (new_area_size - current_tls_area_desc.size);
        area_was_extended = true;
    } else if (new_area_size > current_tls_area_desc.size) {
        // Logger.warn("tls: mapping new area (surplus exhausted, dangerous): size: 0x{x} (new_area_size) + 0x{x} (size of pthread struct)", .{ new_area_size, sizeof_pthread });
        // new_area = std.posix.mmap(null, new_area_size + sizeof_pthread, std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0) catch |err| {
        //     Logger.err("failed to allocate tls space: {s}", .{@errorName(err)});
        //     return err;
        // };

        // the goal is to avoid unstable thread pointer
        Logger.err("tls: surplus exhausted: wanted size: 0x{x} (new_area_size) + 0x{x} (size of pthread struct)", .{ new_area_size, sizeof_pthread });
        @panic("unsupported tls area extension");
    }

    if (new_area != null and dyn_object.tls_init_file_size > 0) {
        Logger.debug("tls: copying new block data: from 0x{x} to 0x{x} (size: 0x{x})", .{
            0,
            dyn_object.tls_init_file_size,
            dyn_object.tls_init_file_size,
        });
        @memcpy(new_area.?[0..dyn_object.tls_init_file_size], @as([*]u8, @ptrFromInt(try vAddressToLoadedAddress(dyn_object, dyn_object.tls_init_mem_offset, false))));
    }

    if (new_area != null and current_tls_area_desc.block.size > 0 and !area_was_extended) {
        Logger.debug("tls: copying previous area block data: from 0x{x} to 0x{x} (size: 0x{x})", .{
            prev_block_offset,
            prev_block_offset + current_tls_area_desc.block.size,
            current_tls_area_desc.block.size,
        });
        @memcpy(new_area.?[prev_block_offset .. prev_block_offset + current_tls_area_desc.block.size], @as([*]u8, @ptrFromInt(old_tp - (new_abi_tcb_offset - prev_block_offset))));
    }

    if (current_tls_area_desc.gdt_entry_number != @as(usize, @bitCast(@as(isize, -1)))) {
        if (new_area != null and !area_was_extended) {
            // TODO we should not have to do that
            Logger.debug("tls: copying previous pthread data: from 0x{x} to 0x{x} (size: 0x{x})", .{
                new_abi_tcb_offset,
                new_area_size + sizeof_pthread,
                new_area_size + sizeof_pthread - new_abi_tcb_offset,
            });
            @memcpy(new_area.?[new_abi_tcb_offset .. new_area_size + sizeof_pthread], @as([*]u8, @ptrFromInt(old_tp)));
        }
    } else {
        initial_tls_init_file_size = current_tls_area_desc.block.init.len;
        initial_tls_init_mem_size = current_tls_area_desc.block.size;
        initial_tls_offset = current_tls_area_desc.abi_tcb.offset;
        initial_tls_align = current_tls_area_desc.alignment;
        initial_tls_init_block = current_tls_area_desc.block.init;

        Logger.debug("tls: copying previous area metadata: from 0x{x} to 0x{x} (size: 0x{x})", .{
            new_abi_tcb_offset,
            new_abi_tcb_offset + current_tls_area_desc.size - current_tls_area_desc.abi_tcb.offset,
            current_tls_area_desc.size - current_tls_area_desc.abi_tcb.offset,
        });
        @memcpy(new_area.?[new_abi_tcb_offset..][0 .. current_tls_area_desc.size - current_tls_area_desc.abi_tcb.offset], @as([*]u8, @ptrFromInt(old_tp)));
    }

    // TODO this allocation could easily be avoided if loaded dyn object has no static tls data
    Logger.debug("tls: allocating new init block: size: 0x{x}", .{new_abi_tcb_offset});
    const new_initial_block = init_blk: {
        const block = try dll_allocator.alloc(u8, new_abi_tcb_offset);
        errdefer dll_allocator.free(block);

        @memset(block, 0);

        Logger.debug("tls: copying initial tdata: from 0x{x} to 0x{x} (size: 0x{x})", .{
            new_abi_tcb_offset - initial_tls_offset,
            new_abi_tcb_offset - initial_tls_offset + initial_tls_init_file_size,
            initial_tls_init_file_size,
        });
        if (initial_tls_init_file_size > 0) {
            @memcpy(block[new_abi_tcb_offset - initial_tls_offset ..][0..initial_tls_init_file_size], initial_tls_init_block);
        }

        Logger.debug("tls: zeroing initial tbss: from 0x{x} to 0x{x} (size: 0x{x})", .{
            new_abi_tcb_offset - initial_tls_offset + initial_tls_init_file_size,
            new_abi_tcb_offset - initial_tls_offset + initial_tls_init_mem_size,
            initial_tls_init_mem_size - initial_tls_init_file_size,
        });
        if (initial_tls_init_mem_size > 0) {
            @memset(block[new_abi_tcb_offset - initial_tls_offset + initial_tls_init_file_size ..][0 .. initial_tls_init_mem_size - initial_tls_init_file_size], 0);
        }

        for (dyn_objects.values()) |*do| {
            if (do.tls_mapped_at != 0) {
                Logger.debug("tls: copying {s} tdata: from 0x{x} to 0x{x} (size: 0x{x})", .{
                    do.name,
                    new_abi_tcb_offset - do.tls_offset,
                    new_abi_tcb_offset - do.tls_offset + do.tls_init_file_size,
                    do.tls_init_file_size,
                });
                if (do.tls_init_file_size > 0) {
                    @memcpy(block[new_abi_tcb_offset - do.tls_offset ..][0..do.tls_init_file_size], @as([*]u8, @ptrFromInt(try vAddressToLoadedAddress(do, do.tls_init_mem_offset, false))));
                }

                Logger.debug("tls: zeroing {s} tbss: from 0x{x} to 0x{x} (size: 0x{x})", .{
                    do.name,
                    new_abi_tcb_offset - do.tls_offset + do.tls_init_file_size,
                    new_abi_tcb_offset - do.tls_offset + do.tls_init_mem_size,
                    do.tls_init_mem_size - do.tls_init_file_size,
                });
                if (do.tls_init_mem_size > 0) {
                    @memset(block[new_abi_tcb_offset - do.tls_offset + do.tls_init_file_size ..][0 .. do.tls_init_mem_size - do.tls_init_file_size], 0);
                }
            }
        }

        Logger.debug("tls: copying {s} tdata: from 0x{x} to 0x{x} (size: 0x{x})", .{
            dyn_object.name,
            0,
            dyn_object.tls_init_file_size,
            dyn_object.tls_init_file_size,
        });
        if (dyn_object.tls_init_file_size > 0) {
            @memcpy(block[0..dyn_object.tls_init_file_size], @as([*]u8, @ptrFromInt(try vAddressToLoadedAddress(dyn_object, dyn_object.tls_init_mem_offset, false))));
        }

        Logger.debug("tls: zeroing {s} tbss: from 0x{x} to 0x{x} (size: 0x{x})", .{
            dyn_object.name,
            dyn_object.tls_init_file_size,
            dyn_object.tls_init_mem_size,
            dyn_object.tls_init_mem_size - dyn_object.tls_init_file_size,
        });
        if (dyn_object.tls_init_mem_size > 0) {
            @memset(block[dyn_object.tls_init_file_size..dyn_object.tls_init_mem_size], 0);
        }

        break :init_blk block;
    };

    // TODO area desc type is not really compliant.
    //
    // currently:
    //
    //-----------------------------------------------
    //| TLS Blocks | ABI TCB | Zig TCB | DTV struct |
    //-------------^---------------------------------
    //              `-- The TP register points here.
    //
    // it should be:
    //
    //             | POTENTIAL PTHREAD STRUCT ====>
    //----------------------------------------------
    //| TLS Blocks | ABI TCB | *DTV | *SELF | SPACE
    //-------------^--------------------------------
    //              `-- The TP register points here.
    //
    const new_block_init = new_initial_block;
    const new_block_offset: usize = 0;
    const new_block_size = new_block_init.len;
    const new_align_factor = @max(dyn_object.tls_align, current_tls_area_desc.alignment);

    var new_tls_area_desc: @TypeOf(current_tls_area_desc) = .{
        .size = new_area_size,
        .alignment = new_align_factor,

        .dtv = .{
            .offset = new_dtv_offset,
        },

        .abi_tcb = .{
            .offset = new_abi_tcb_offset,
        },

        .block = .{
            .init = new_block_init,
            .offset = new_block_offset,
            .size = new_block_size,
        },

        .gdt_entry_number = 1,
    };

    owned_tls_mapping = null;

    if (current_tls_area_desc.gdt_entry_number != @as(usize, @bitCast(@as(isize, -1)))) {
        dll_allocator.free(current_tls_area_desc.block.init);
    }

    // keep a copy of the normal area desc,
    // and create another one to be set to `std.os.linux.tls.area_desc`
    // that is adapted to the `std.os.linux.tls.prepareArea` call
    // when spawning a thread
    normal_current_tls_area_desc = new_tls_area_desc;

    new_tls_area_desc.size = current_surplus_size + new_area_size + sizeof_pthread;
    new_tls_area_desc.dtv.offset += current_surplus_size;
    new_tls_area_desc.abi_tcb.offset += current_surplus_size;
    new_tls_area_desc.block.offset += current_surplus_size;
    std.os.linux.tls.area_desc = new_tls_area_desc;

    if (new_area != null) {
        const new_tp = @intFromPtr(new_area.?.ptr) + new_abi_tcb_offset;

        const new_tcb: *usize = @ptrFromInt(new_tp);
        new_tcb.* = new_tp;

        Logger.debug("tls: tls space mapped, new TP: 0x{x}", .{new_tp});

        const e_set_fs = std.os.linux.syscall2(.arch_prctl, std.os.linux.ARCH.SET_FS, new_tp);
        std.debug.assert(e_set_fs == 0);
        if (loader_thread_pointer == 0) loader_thread_pointer = new_tp;

        if (libc_specifics != null) {
            try applyLibcWriteOps(new_tp, false);
        }

        dyn_object.tls_offset = new_abi_tcb_offset;
        Logger.debug("tls: tls offset: 0x{x}", .{new_abi_tcb_offset});

        dyn_object.tls_mapped_at = @as(usize, @intFromPtr(new_area.?.ptr));
    } else {
        Logger.debug("tls: {s}: no change to TLS area", .{dyn_object.name});
    }

    dyn_object.tls_capacity = dyn_object.tls_init_mem_size;
    dyn_object.tls_slot_align = dyn_object.tls_align;

    if (dyn_object.tls_capacity != 0) try resetTlsSlot(dyn_object);
}

fn resetTlsSlot(dyn_object: *DynObject) !void {
    const desc = normal_current_tls_area_desc.?;
    const template = @as([*]u8, @constCast(desc.block.init.ptr))[desc.abi_tcb.offset - dyn_object.tls_offset ..][0..dyn_object.tls_capacity];
    @memset(template, 0);

    if (dyn_object.tls_init_file_size != 0) {
        const source: [*]const u8 = @ptrFromInt(try vAddressToLoadedAddress(dyn_object, dyn_object.tls_init_mem_offset, false));
        @memcpy(template[0..dyn_object.tls_init_file_size], source[0..dyn_object.tls_init_file_size]);
    }

    const tp = currentThreadPointer();
    @memcpy(@as([*]u8, @ptrFromInt(tp - dyn_object.tls_offset))[0..template.len], template);
    dyn_object.tls_mapped_at = tp - dyn_object.tls_offset;

    thread_mutex.lock(dll_io) catch @panic("error locking mutex");
    defer thread_mutex.unlock(dll_io);

    for (thread_infos.values()) |entry| {
        if (entry.handle == tp) continue;
        @memcpy(@as([*]u8, @ptrFromInt(entry.handle - dyn_object.tls_offset))[0..template.len], template);
    }

    if (loader_thread_pointer != 0 and loader_thread_pointer != tp) {
        @memcpy(@as([*]u8, @ptrFromInt(loader_thread_pointer - dyn_object.tls_offset))[0..template.len], template);
    }
}

fn currentThreadPointer() usize {
    var tp: usize = undefined;
    const result = std.os.linux.syscall2(.arch_prctl, std.os.linux.ARCH.GET_FS, @intFromPtr(&tp));
    std.debug.assert(result == 0);
    return tp;
}

fn staticTlsSize() usize {
    return normal_current_tls_area_desc.?.size + current_surplus_size;
}

fn staticTlsAlignment() usize {
    return normal_current_tls_area_desc.?.alignment;
}

fn applyLibcWriteOps(thread_pointer: usize, only_tp_relative: bool) !void {
    Logger.debug("libc: setting details for libc: {t}", .{libc_specifics.?.kind});

    for (libc_specifics.?.write_ops.items) |op| {
        if (only_tp_relative and op.relative_to != .tp) {
            continue;
        }

        const addr = op.addr + if (op.relative_to == .tp) thread_pointer else 0;
        const val: usize = switch (op.value) {
            .auxv => @intFromPtr(std.os.linux.elf_aux_maybe.?),
            .page_size => std.heap.pageSize(),
            .tid => std.Thread.getCurrentId(),
            .tls_size => staticTlsSize(),
            .tls_align => staticTlsAlignment(),
            .tls_count => 1, // TODO,
            .tp => thread_pointer,
            .self => addr,
            .addr => |a| a,
        };

        Logger.debug("libc: writing {t} [0x{x}] at 0x{x}", .{ op.value, val, addr });

        const seg_infos = findDynObjectSegmentForLoadedAddr(addr) catch null;
        if (seg_infos != null) {
            try unprotectSegment(seg_infos.?.dyn_object, seg_infos.?.segment_index);
        }

        const ptr: *volatile usize = @ptrFromInt(addr);
        ptr.* = val;

        if (seg_infos != null) {
            try reprotectSegment(seg_infos.?.dyn_object, seg_infos.?.segment_index);
        }
    }
}

// this function has a special callconv
fn tlsDescResolver() callconv(.naked) void {
    asm volatile (
        \\ movq 8(%%rax), %%rax
        \\ ret
    );
}

const TlsDesc = extern struct {
    tls_desc_resolver: *const fn () callconv(.naked) void,
    tls_desc_resolver_arg: isize,
};

fn processRelocations(dyn_object: *DynObject) !void {
    Logger.debug("processing relocations for {s}", .{dyn_object.name});

    var reloc_count: usize = 0;

    for (dyn_object.relocs.items) |reloc| {
        if (reloc.type == .RELATIVE) continue; // applied by processRelativeRelocationsFast() after mapping

        const reloc_addr = try vAddressToLoadedAddress(dyn_object, reloc.offset, false);
        const ptr: *align(1) usize = @ptrFromInt(reloc_addr);

        switch (reloc.type) {
            .@"64" => {
                reloc_count += 1;
                // R_X86_64_64: S + A
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const value = r64_blk: {
                    if (reloc.addend != 0) break :r64_blk sym.address +% @as(usize, @bitCast(reloc.addend));
                    break :r64_blk if (getSubstituteAddress(sym, dyn_object, true)) |a| a else sym.address;
                };
                Logger.debug("  64: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} + 0x{x})", .{ reloc_addr, reloc.offset, ptr.*, value, sym.value, sym.name, sym.version, reloc.addend });
                ptr.* = value;
            },
            .GLOB_DAT => {
                reloc_count += 1;
                // R_X86_64_GLOB_DAT: S
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const value = if (getSubstituteAddress(sym, dyn_object, true)) |a| a else sym.address;
                Logger.debug("  GLOB_DAT: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} + 0x{x})", .{ reloc_addr, reloc.offset, ptr.*, value, sym.value, sym.name, sym.version, reloc.addend });
                ptr.* = value;
            },
            .JUMP_SLOT => {
                reloc_count += 1;
                // R_X86_64_JUMP_SLOT: S
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const value = if (getSubstituteAddress(sym, dyn_object, true)) |a| a else sym.address;
                Logger.debug("  JUMP_SLOT: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} + 0x{x})", .{ reloc_addr, reloc.offset, ptr.*, value, sym.value, sym.name, sym.version, reloc.addend });
                ptr.* = value;
            },
            .TPOFF64 => {
                reloc_count += 1;
                // R_X86_64_TPOFF64: S + A (TLS offset)
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const tls_offset = dyn_objects.values()[sym.dyn_object_idx].tls_offset;
                const value = sym.value +% @as(usize, @bitCast(reloc.addend)) -% tls_offset;
                Logger.debug("  TPOFF64: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} - [MODULE_TLS_OFFSET]0x{x} + 0x{x})", .{
                    reloc_addr,
                    reloc.offset,
                    ptr.*,
                    value,
                    sym.value,
                    sym.name,
                    sym.version,
                    dyn_object.tls_offset,
                    reloc.addend,
                });
                ptr.* = @bitCast(value);
            },
            .DTPOFF64 => {
                reloc_count += 1;
                // R_X86_64_DTPOFF64: S + A
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const value = sym.value +% @as(usize, @bitCast(reloc.addend));
                Logger.debug("  DTPOFF64: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} + 0x{x})", .{
                    reloc_addr,
                    reloc.offset,
                    ptr.*,
                    value,
                    sym.value,
                    sym.name,
                    sym.version,
                    reloc.addend,
                });
                ptr.* = @bitCast(value);
            },
            .DTPMOD64 => {
                reloc_count += 1;
                // R_X86_64_DTPMOD64: S (TLS module ID)
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const tls_module_id = sym.dyn_object_idx + 1;
                const value = @as(isize, @intCast(tls_module_id));
                Logger.debug("  DTPMOD64: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} => [MODULE_TLS_ID]0x{x})", .{
                    reloc_addr,
                    reloc.offset,
                    ptr.*,
                    value,
                    sym.value,
                    sym.name,
                    sym.version,
                    dyn_object.tls_offset,
                });
                ptr.* = @bitCast(value);
            },
            .TLSDESC => {
                reloc_count += 1;
                // R_X86_64_TLSDESC: S + A (TLS offset)
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const tls_offset = dyn_objects.values()[sym.dyn_object_idx].tls_offset;
                const value: TlsDesc = .{
                    .tls_desc_resolver_arg = @bitCast(sym.value +% @as(usize, @bitCast(reloc.addend)) -% tls_offset),
                    .tls_desc_resolver = &tlsDescResolver,
                };
                Logger.debug("  TLSDESC: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} - [MODULE_TLS_OFFSET]0x{x} + 0x{x})", .{
                    reloc_addr,
                    reloc.offset,
                    ptr.*,
                    value.tls_desc_resolver_arg,
                    sym.value,
                    sym.name,
                    sym.version,
                    dyn_object.tls_offset,
                    reloc.addend,
                });
                const casted_ptr: *align(1) TlsDesc = @ptrCast(ptr);
                casted_ptr.* = value;
            },
            .IRELATIVE => {
                // R_X86_64_IRELATIVE: indirect relative (function pointer)
                // Will be handled in a second pass
                continue;
            },
            else => {
                Logger.err("{s}: unhandled relocation type: {s}", .{ dyn_object.name, @tagName(reloc.type) });
                return error.UnhandledReloctationType;
            },
        }
    }

    // patch .plt.got
    // TODO this whole branch is theoritically unnecessary, we keep it only temporarily to prove that fact
    if (dyn_object.plt_got_section_size > 0) {
        const PltGotEntry = packed struct {
            inst: u16,
            offset: u32,
            rem: u16,
        };

        std.debug.assert(dyn_object.plt_got_section_size % @sizeOf(PltGotEntry) == 0);

        const nb_entries = dyn_object.plt_got_section_size / @sizeOf(PltGotEntry);

        const entries: []PltGotEntry = @as([*]PltGotEntry, @ptrFromInt(try vAddressToLoadedAddress(dyn_object, dyn_object.plt_got_section_offset, false)))[0..nb_entries];

        for (entries, 0..) |*entry, i| {
            const entry_address = dyn_object.plt_got_section_offset + i * @sizeOf(PltGotEntry);
            const target_address = entry_address + @offsetOf(PltGotEntry, "offset") + entry.offset + 4;
            Logger.debug(".PLT.GOT entry {d}: faddr: 0x{x}, offset: 0x{x}, target: 0x{x}", .{ i, entry_address, entry.offset, target_address });

            // TODO extremely inefficient
            for (dyn_object.relocs.items) |r| {
                if (r.offset == target_address) {
                    const sym = dyn_object.syms_array.items[r.sym_idx];
                    const r_sym = try resolveSymbol(dyn_object, r.sym_idx);

                    const substitute_addr = getSubstituteAddress(r_sym, dyn_object, true);
                    if (substitute_addr == null) {
                        break;
                    }

                    const loaded_target_addr = try vAddressToLoadedAddress(dyn_object, target_address, false);
                    const actual_target: *const usize = @ptrFromInt(loaded_target_addr);

                    if (actual_target.* == substitute_addr.?) {
                        @branchHint(.likely);
                        break;
                    }

                    Logger.warn(".PLT.GOT target mismatch for {s}: relocation {s}, actual 0x{x}, expected 0x{x}; patching executable stub", .{
                        sym.name,
                        @tagName(r.type),
                        actual_target.*,
                        substitute_addr.?,
                    });

                    // replace `jmp *{offset}(%rip)`

                    const write_addr = @intFromPtr(entry);

                    const seg_infos = findDynObjectSegmentForLoadedAddr(write_addr) catch null;

                    if (seg_infos != null) {
                        try unprotectSegment(seg_infos.?.dyn_object, seg_infos.?.segment_index);
                    }

                    const entry_bytes = @as([*]volatile u8, @ptrFromInt(write_addr));
                    entry_bytes[0] = 0xb8; // mov eax
                    entry_bytes[1] = @intCast(substitute_addr.? & 0xff); // imm
                    entry_bytes[2] = @intCast((substitute_addr.? >> 8) & 0xff);
                    entry_bytes[3] = @intCast((substitute_addr.? >> 16) & 0xff);
                    entry_bytes[4] = @intCast((substitute_addr.? >> 24) & 0xff);
                    entry_bytes[5] = 0xff; // jmp rax
                    entry_bytes[6] = 0xe0;

                    if (seg_infos != null) {
                        try reprotectSegment(seg_infos.?.dyn_object, seg_infos.?.segment_index);
                    }

                    break;
                }
            }
        }
    }

    Logger.debug("processed {d} relocations for {s}", .{ reloc_count, dyn_object.name });
}

fn processIRelativeRelocations(dyn_object: *DynObject) !void {
    Logger.debug("processing IRELATIVE relocations for {s}", .{dyn_object.name});

    var reloc_count: usize = 0;

    for (dyn_object.relocs.items) |reloc| {
        const reloc_addr = try vAddressToLoadedAddress(dyn_object, reloc.offset, false);
        const ptr: *align(1) usize = @ptrFromInt(reloc_addr);

        switch (reloc.type) {
            .RELATIVE, .@"64", .GLOB_DAT, .JUMP_SLOT, .TPOFF64, .DTPOFF64, .DTPMOD64, .TLSDESC => {},
            .IRELATIVE => {
                reloc_count += 1;
                const resolver_addr = try vAddressToLoadedAddress(dyn_object, @intCast(reloc.addend), false);
                const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                Logger.debug("  IRELATIVE: calling resolver at 0x{x} (0x{x})", .{ resolver_addr, reloc.addend });
                const value = resolver();
                Logger.debug("  IRELATIVE: 0x{x} (0x{x}): 0x{x} -> 0x{x}", .{ reloc_addr, reloc.offset, ptr.*, value });
                try recordBindingDependency(dyn_object, value);
                ptr.* = value;
                if (ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                    std.debug.assert(res_val == value);
                }
                try ifunc_resolved_addrs.put(dll_allocator, resolver_addr, value);
                try irel_resolved_targets.putNoClobber(dll_allocator, reloc_addr, value);
            },
            else => {
                Logger.err("unhandled relocation type: {s}", .{@tagName(reloc.type)});
                return error.UnhandledReloctationType;
            },
        }
    }

    Logger.debug("processed {d} IRELATIVE relocations for {s}", .{ reloc_count, dyn_object.name });
}

fn resolveSymbolByName(sym_name: []const u8) !ResolvedSymbol {
    var it = dyn_objects.iterator();
    while (it.next()) |entry| {
        const dep_object = entry.value_ptr;

        if (dep_object.syms.get(sym_name)) |dep_sym_list| {
            for (dep_sym_list.items) |dep_sym_idx| {
                const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                if (dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                    if (dep_sym.shidx == std.elf.SHN_ABS) {
                        Logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                    }

                    const dep_sym_address = dep_sym.value;

                    var dep_addr = try vAddressToLoadedAddress(dep_object, dep_sym_address, false);
                    if (ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                        dep_addr = res_addr;
                    }

                    return .{
                        .value = dep_sym.value,
                        .address = dep_addr,
                        .name = dep_sym.name,
                        .version = dep_sym.version,
                        .dyn_object_idx = dyn_objects.getIndex(dep_object.key).?,
                        .sym_idx = dep_sym_idx,
                    };
                }

                if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                    Logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                }
            }
        }
    }

    return error.UnresolvedSymbol;
}

// TODO the next 3 functions are very ugly and need factorization

// TODO thread safety (called from Symbol)
fn getResolvedSymbolByName(maybe_dyn_object: ?*DynObject, sym_name: []const u8, find_next: bool, only_preload: bool, allow_preload_override: bool) !ResolvedSymbol {
    std.debug.assert(!(find_next and only_preload));
    std.debug.assert(!(find_next and allow_preload_override));
    std.debug.assert(!(only_preload and allow_preload_override));

    if (only_preload and !find_next) {
        for (preload_root_indices.items) |preload_idx| {
            const dep_object = &dyn_objects.values()[preload_idx];

            if (dep_object.mapped_at == 0) {
                continue;
            }

            if (dep_object.syms.get(sym_name)) |dep_sym_list| {
                for (dep_sym_list.items) |dep_sym_idx| {
                    const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                    if (dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                        if (dep_sym.shidx == std.elf.SHN_ABS) {
                            Logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try vAddressToLoadedAddress(dep_object, dep_sym_address, false);

                        if (ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            Logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            Logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            Logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try ifunc_resolved_addrs.put(dll_allocator, resolver_addr, value);
                            try irel_resolved_targets.putNoClobber(dll_allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        return .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        Logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }

        return error.UnresolvedSymbol;
    }

    if (maybe_dyn_object) |dyn_object| {
        for (dyn_object.deps_breadth_first.items, 0..) |dep_idx, dep_order| {
            const dep_object = &dyn_objects.values()[dep_idx];

            if (find_next and dep_order == 0) {
                continue;
            }

            if (dep_object.mapped_at == 0) {
                continue;
            }

            if (dep_object.syms.get(sym_name)) |dep_sym_list| {
                for (dep_sym_list.items) |dep_sym_idx| {
                    const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                    if (dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                        if (dep_sym.shidx == std.elf.SHN_ABS) {
                            Logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try vAddressToLoadedAddress(dep_object, dep_sym_address, false);

                        if (ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            Logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            Logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            Logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try ifunc_resolved_addrs.put(dll_allocator, resolver_addr, value);
                            try irel_resolved_targets.putNoClobber(dll_allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };

                        if (!only_preload) {
                            if (getSubstituteAddress(res_sym, dep_object, allow_preload_override)) |a| {
                                res_sym.address = a;
                            }
                        }

                        return res_sym;
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        Logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }
    } else {
        for (dyn_objects_sorted_indices.items) |dep_idx| {
            const dep_object = &dyn_objects.values()[dep_idx];

            if (dep_object.mapped_at == 0) {
                continue;
            }

            if (dep_object.syms.get(sym_name)) |dep_sym_list| {
                for (dep_sym_list.items) |dep_sym_idx| {
                    const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                    if (dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                        if (dep_sym.shidx == std.elf.SHN_ABS) {
                            Logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try vAddressToLoadedAddress(dep_object, dep_sym_address, false);

                        if (ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            Logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            Logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            Logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try ifunc_resolved_addrs.put(dll_allocator, resolver_addr, value);
                            try irel_resolved_targets.putNoClobber(dll_allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };

                        if (!only_preload) {
                            if (getSubstituteAddress(res_sym, dep_object, allow_preload_override)) |a| {
                                res_sym.address = a;
                            }
                        }

                        return res_sym;
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        Logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }
    }

    // if (skip_first) {
    //     Logger.warn("retrying non skipped first getResolvedSymbolByName for {s}", .{sym_name});
    //     return getResolvedSymbolByName(maybe_dyn_object, sym_name, false);
    // }

    return error.UnresolvedSymbol;
}

// TODO thread safety (called from Symbol)
fn getResolvedSymbolByNameAndVersion(maybe_dyn_object: ?*DynObject, sym_name: []const u8, version: []const u8, find_next: bool, only_preload: bool, allow_preload_override: bool) !ResolvedSymbol {
    std.debug.assert(!(find_next and only_preload));
    std.debug.assert(!(find_next and allow_preload_override));
    std.debug.assert(!(only_preload and allow_preload_override));

    if (only_preload and !find_next) {
        for (preload_root_indices.items) |preload_idx| {
            const dep_object = &dyn_objects.values()[preload_idx];

            if (dep_object.mapped_at == 0) {
                continue;
            }

            if (dep_object.syms.get(sym_name)) |dep_sym_list| {
                for (dep_sym_list.items) |dep_sym_idx| {
                    const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                    if (std.mem.eql(u8, dep_sym.version, version) and dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                        if (dep_sym.shidx == std.elf.SHN_ABS) {
                            Logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try vAddressToLoadedAddress(dep_object, dep_sym_address, false);

                        if (ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            Logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            Logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            Logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try ifunc_resolved_addrs.put(dll_allocator, resolver_addr, value);
                            try irel_resolved_targets.putNoClobber(dll_allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        return .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        Logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }

        return error.UnresolvedSymbol;
    }

    if (maybe_dyn_object) |dyn_object| {
        for (dyn_object.deps_breadth_first.items, 0..) |dep_idx, dep_order| {
            const dep_object = &dyn_objects.values()[dep_idx];

            if (find_next and dep_order == 0) {
                continue;
            }

            if (dep_object.mapped_at == 0) {
                continue;
            }

            if (dep_object.syms.get(sym_name)) |dep_sym_list| {
                for (dep_sym_list.items) |dep_sym_idx| {
                    const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                    if (std.mem.eql(u8, dep_sym.version, version) and dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                        if (dep_sym.shidx == std.elf.SHN_ABS) {
                            Logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try vAddressToLoadedAddress(dep_object, dep_sym_address, false);

                        if (ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            Logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            Logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            Logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try ifunc_resolved_addrs.put(dll_allocator, resolver_addr, value);
                            try irel_resolved_targets.putNoClobber(dll_allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };

                        if (!only_preload) {
                            if (getSubstituteAddress(res_sym, dep_object, allow_preload_override)) |a| {
                                res_sym.address = a;
                            }
                        }

                        return res_sym;
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        Logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }
    } else {
        for (dyn_objects_sorted_indices.items) |dep_idx| {
            const dep_object = &dyn_objects.values()[dep_idx];

            if (dep_object.mapped_at == 0) {
                continue;
            }

            if (dep_object.syms.get(sym_name)) |dep_sym_list| {
                for (dep_sym_list.items) |dep_sym_idx| {
                    const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                    if (std.mem.eql(u8, dep_sym.version, version) and dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                        if (dep_sym.shidx == std.elf.SHN_ABS) {
                            Logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try vAddressToLoadedAddress(dep_object, dep_sym_address, false);

                        if (ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            Logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            Logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            Logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try ifunc_resolved_addrs.put(dll_allocator, resolver_addr, value);
                            try irel_resolved_targets.putNoClobber(dll_allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };

                        if (!only_preload) {
                            if (getSubstituteAddress(res_sym, dep_object, allow_preload_override)) |a| {
                                res_sym.address = a;
                            }
                        }

                        return res_sym;
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        Logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }
    }

    // if (skip_first) {
    //     Logger.warn("retrying non skipped first getResolvedSymbolByNameAndVersion for {s}", .{sym_name});
    //     return getResolvedSymbolByNameAndVersion(maybe_dyn_object, sym_name, version, false);
    // }

    return error.UnresolvedSymbol;
}

// TODO rules for symbol resolution should be rigorously implemented
fn resolveSymbol(dyn_object: *DynObject, sym_idx: usize) !ResolvedSymbol {
    const sym = try resolveSymbolInner(dyn_object, sym_idx);
    try recordBindingDependency(dyn_object, sym.address);
    return sym;
}

fn recordBindingDependency(dyn_object: *DynObject, address: usize) !void {
    // IFUNCs can return address belonging to an object outside DT_NEEDED.
    if (findDynObjectForLoadedAddr(address)) |target| {
        if (target.dyn_object_index != dyn_objects.getIndex(dyn_object.key).? and
            std.mem.findScalar(usize, dyn_object.binding_dependencies.items, target.dyn_object_index) == null)
        {
            try dyn_object.binding_dependencies.append(dll_allocator, target.dyn_object_index);
        }
    }
}

fn resolveSymbolInner(dyn_object: *DynObject, sym_idx: usize) !ResolvedSymbol {
    if (sym_idx >= dyn_object.syms_array.items.len) {
        return error.InvalidSymbolIndex;
    }

    const sym = dyn_object.syms_array.items[sym_idx];

    if (sym_idx == 0 or sym.shidx != std.elf.SHN_UNDEF) {
        if (sym.bind == .WEAK) {
            Logger.debug("WARNING: WEAK SYMBOL: {s}", .{if (sym_idx == 0) "ZERO" else sym.name});
        }

        if (sym.shidx == std.elf.SHN_ABS) {
            Logger.debug("WARNING: ABSOLUTE SYMBOL: {s}", .{if (sym_idx == 0) "ZERO" else sym.name});
        }

        const sym_address = sym.value;

        var addr = try vAddressToLoadedAddress(dyn_object, sym_address, false);

        if (ifunc_resolved_addrs.get(addr)) |res_addr| {
            Logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ sym.name, addr, res_addr });
            addr = res_addr;
        } else if (sym.type == std.elf.STT.GNU_IFUNC) {
            const resolver_addr = addr;
            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
            Logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ sym.name, resolver_addr, sym_address });
            const value = resolver();
            Logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ sym.name, resolver_addr, sym_address, value });
            if (ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                std.debug.assert(res_val == value);
            }
            try ifunc_resolved_addrs.put(dll_allocator, resolver_addr, value);
            try irel_resolved_targets.putNoClobber(dll_allocator, resolver_addr, value);
            addr = value;
        }

        return .{
            .value = sym.value,
            .address = addr,
            .name = sym.name,
            .version = sym.version,
            .dyn_object_idx = dyn_objects.getIndex(dyn_object.key).?,
            .sym_idx = sym_idx,
        };
    }

    for (dyn_object.deps_breadth_first.items) |dep_idx| {
        const dep_object = &dyn_objects.values()[dep_idx];

        if (std.mem.eql(u8, dep_object.name, dyn_object.name)) {
            continue;
        }

        if (dep_object.syms.get(sym.name)) |dep_sym_list| {
            for (dep_sym_list.items) |dep_sym_idx| {
                const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                const unversioned = sym.version.len == 0 or std.mem.eql(u8, sym.version, "GLOBAL") or
                    (sym.shidx == std.elf.SHN_UNDEF and sym.bind != .LOCAL and std.mem.eql(u8, sym.version, "LOCAL"));
                const version_matches = dep_sym.version.len == 0 or std.mem.eql(u8, dep_sym.version, "GLOBAL") or
                    std.mem.eql(u8, dep_sym.version, sym.version) or (unversioned and dep_sym.default_version);
                if (dep_sym.shidx != std.elf.SHN_UNDEF and version_matches and !dep_sym.hidden) {
                    if (dep_sym.bind == .WEAK) {
                        Logger.debug("WARNING: WEAK SYMBOL from dep: {s}", .{if (sym_idx == 0) "ZERO" else dep_sym.name});
                    }

                    if (dep_sym.shidx == std.elf.SHN_ABS) {
                        Logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{if (sym_idx == 0) "ZERO" else dep_sym.name});
                    }

                    const dep_sym_address = dep_sym.value;

                    var dep_addr = try vAddressToLoadedAddress(dep_object, dep_sym_address, false);

                    if (ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                        Logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                        dep_addr = res_addr;
                    } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                        const resolver_addr = dep_addr;
                        const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                        Logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                        const value = resolver();
                        Logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                        if (ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                            std.debug.assert(res_val == value);
                        }
                        try ifunc_resolved_addrs.put(dll_allocator, resolver_addr, value);
                        try irel_resolved_targets.putNoClobber(dll_allocator, resolver_addr, value);
                        dep_addr = value;
                    }

                    return .{
                        .value = dep_sym.value,
                        .address = dep_addr,
                        .name = dep_sym.name,
                        .version = dep_sym.version,
                        .dyn_object_idx = dep_idx,
                        .sym_idx = dep_sym_idx,
                    };
                }

                if (dep_sym.shidx == std.elf.SHN_UNDEF) Logger.debug("WARNING: SKIPPING UNDEF SYMBOL from dep: {s} | {s}@{s}", .{ dep_object.name, dep_sym.name, dep_sym.version });
                if (dep_sym.hidden) Logger.debug("WARNING: SKIPPING HIDDEN SYMBOL from dep: {s} | {s}@{s}", .{ dep_object.name, dep_sym.name, dep_sym.version });
                if (!version_matches) Logger.debug("WARNING: SKIPPING MISVERSIONED SYMBOL from dep: {s} | {s} ({s} vs {s})", .{ dep_object.name, dep_sym.name, sym.version, dep_sym.version });
            }
        }
    }

    if (sym.bind == .WEAK) {
        Logger.debug("WARNING: UNRESOLVED WEAK SYMBOL: {s}", .{if (sym_idx == 0) "ZERO" else sym.name});

        if (sym.shidx == std.elf.SHN_ABS) {
            Logger.debug("WARNING: UNRESOLVED WEAK ABSOLUTE SYMBOL: {s}", .{if (sym_idx == 0) "ZERO" else sym.name});
        }

        return .{
            .value = 0,
            .address = 0,
            .name = sym.name,
            .version = sym.version,
            .dyn_object_idx = std.math.maxInt(usize),
            .sym_idx = std.math.maxInt(usize),
        };
    }

    Logger.err("unresolved symbol: {s} in {s}", .{ sym.name, dyn_object.name });
    Logger.err("searched:", .{});
    for (dyn_object.deps_breadth_first.items) |dep_idx| {
        const dep_object = &dyn_objects.values()[dep_idx];
        Logger.err("  - {s}", .{dep_object.name});
    }
    return error.UnresolvedSymbol;
}

fn updateSegmentsPermissions(dyn_object: *DynObject) !void {
    Logger.debug("updating segment permissions for {s}", .{dyn_object.name});

    for (dyn_object.segments.values(), 0..) |*segment, s| {
        var prot: std.posix.PROT = .{};
        if (segment.flags_last.read) prot.READ = true;
        if (segment.flags_last.write) prot.WRITE = true;
        if (segment.flags_last.exec) prot.EXEC = true;

        const aligned_start = std.mem.alignBackward(usize, segment.loaded_at + (segment.flags_last.mem_offset - segment.mem_offset), std.heap.pageSize());
        const aligned_end = std.mem.alignForward(usize, segment.loaded_at + (segment.flags_last.mem_offset - segment.mem_offset) + segment.flags_last.mem_size, std.heap.pageSize());
        Logger.debug("  updating segment {d}: from 0x{x} to 0x{x}, prot: 0x{x}", .{ s, aligned_start, aligned_end, @as(u32, @bitCast(prot)) });

        const segment_slice = @as([*]align(std.heap.pageSize()) u8, @ptrFromInt(aligned_start))[0 .. aligned_end - aligned_start];
        const r = std.os.linux.mprotect(segment_slice.ptr, segment_slice.len, prot);
        switch (std.os.linux.errno(r)) {
            .SUCCESS => {},
            else => |err| {
                Logger.err("failed to update segment permissions: {t}", .{err});
                return error.ProtectSegmentFailed;
            },
        }
    }

    Logger.debug("successfully updated {d} segments for {s}", .{ dyn_object.segments.count(), dyn_object.name });
}

fn unprotectSegment(dyn_object: *DynObject, segment_index: usize) !void {
    const segment = dyn_object.segments.values()[segment_index];

    const aligned_start = std.mem.alignBackward(usize, segment.loaded_at, std.heap.pageSize());
    const aligned_end = std.mem.alignForward(usize, segment.loaded_at + segment.mem_size, std.heap.pageSize());
    const prot: std.posix.PROT = .{ .READ = true, .WRITE = true };

    Logger.debug("{s}: unprotecting segment {d}: from 0x{x} to 0x{x}, prot: 0x{x}", .{ dyn_object.name, segment_index, aligned_start, aligned_end, @as(u32, @bitCast(prot)) });

    const segment_slice = @as([*]align(std.heap.pageSize()) u8, @ptrFromInt(aligned_start))[0 .. aligned_end - aligned_start];
    const r = std.os.linux.mprotect(segment_slice.ptr, segment_slice.len, prot);
    switch (std.os.linux.errno(r)) {
        .SUCCESS => {},
        else => |err| {
            Logger.err("failed to update segment permissions: {t}", .{err});
            return error.UnprotectSegmentFailed;
        },
    }

    Logger.debug("successfully unprotected segment {d} for {s}", .{ segment_index, dyn_object.name });
}

fn reprotectSegment(dyn_object: *DynObject, segment_index: usize) !void {
    const segment = dyn_object.segments.values()[segment_index];

    var aligned_start = std.mem.alignBackward(usize, segment.loaded_at, std.heap.pageSize());
    var aligned_end = std.mem.alignForward(usize, segment.loaded_at + segment.mem_size, std.heap.pageSize());

    var prot: std.posix.PROT = .{};
    if (segment.flags_first.read) prot.READ = true;
    if (segment.flags_first.write) prot.WRITE = true;
    if (segment.flags_first.exec) prot.EXEC = true;

    Logger.debug("{s}: reprotecting segment {d}: from 0x{x} to 0x{x}, prot: 0x{x}", .{ dyn_object.name, segment_index, aligned_start, aligned_end, @as(u32, @bitCast(prot)) });

    var segment_slice = @as([*]align(std.heap.pageSize()) u8, @ptrFromInt(aligned_start))[0 .. aligned_end - aligned_start];
    const r1 = std.os.linux.mprotect(segment_slice.ptr, segment_slice.len, prot);
    switch (std.os.linux.errno(r1)) {
        .SUCCESS => {},
        else => |err| {
            Logger.err("failed to update segment permissions: {t}", .{err});
            return error.ProtectSegmentFailed;
        },
    }

    if (dyn_object.loaded) {
        prot = .{};
        if (segment.flags_last.read) prot.READ = true;
        if (segment.flags_last.write) prot.WRITE = true;
        if (segment.flags_last.exec) prot.EXEC = true;

        aligned_start = std.mem.alignBackward(usize, segment.loaded_at + (segment.flags_last.mem_offset - segment.mem_offset), std.heap.pageSize());
        aligned_end = std.mem.alignForward(usize, segment.loaded_at + (segment.flags_last.mem_offset - segment.mem_offset) + segment.flags_last.mem_size, std.heap.pageSize());

        Logger.debug("{s}: reapplying segment {d} permissions: from 0x{x} to 0x{x}, prot: 0x{x}", .{ dyn_object.name, segment_index, aligned_start, aligned_end, @as(u32, @bitCast(prot)) });

        segment_slice = @as([*]align(std.heap.pageSize()) u8, @ptrFromInt(aligned_start))[0 .. aligned_end - aligned_start];
        const r2 = std.os.linux.mprotect(segment_slice.ptr, segment_slice.len, prot);
        switch (std.os.linux.errno(r2)) {
            .SUCCESS => {},
            else => |err| {
                Logger.err("failed to update segment permissions: {t}", .{err});
                return error.ProtectSegmentFailed;
            },
        }
    }

    Logger.debug("successfully reprotected segment {d} for {s}", .{ segment_index, dyn_object.name });
}

const DynObjectSegmentResult = struct {
    dyn_object: *DynObject,
    segment_index: usize,
    sym_index: ?usize,
};

const DynObjectAddressResult = struct {
    dyn_object_index: usize,
    segment_index: usize,
};

fn findDynObjectForLoadedAddr(addr: usize) ?DynObjectAddressResult {
    for (dyn_objects.values(), 0..) |*dyn_object, dyn_object_idx| {
        for (dyn_object.segments.values(), 0..) |*s, s_idx| {
            const segment_start = s.loaded_at;
            const segment_end = segment_start + s.mem_size;
            if (addr >= segment_start and addr < segment_end) {
                return .{
                    .dyn_object_index = dyn_object_idx,
                    .segment_index = s_idx,
                };
            }
        }
    }

    // TODO also search the main executable, in case it is c++ that wants to unwind an exception

    return null;
}

fn findDynObjectSegmentForLoadedAddr(addr: usize) !DynObjectSegmentResult {
    const object_result = findDynObjectForLoadedAddr(addr) orelse return error.LoadedAddressNotMapped;
    const dyn_object = &dyn_objects.values()[object_result.dyn_object_index];

    for (dyn_object.syms_array.items, 0..) |*sym, sym_idx| {
        const sym_addr = try vAddressToLoadedAddress(dyn_object, sym.value, false);
        if (sym_addr <= addr and sym_addr + sym.size > addr) {
            return .{
                .dyn_object = dyn_object,
                .segment_index = object_result.segment_index,
                .sym_index = sym_idx,
            };
        }
    }

    return .{
        .dyn_object = dyn_object,
        .segment_index = object_result.segment_index,
        .sym_index = null,
    };
}

fn vAddressToLoadedAddress(dyn_object: *DynObject, addr: usize, allow_outside: bool) !usize {
    var containing_segment: ?*LoadSegment = null;
    for (dyn_object.segments.values()) |*s| {
        const segment_start = s.mem_offset;
        const segment_end = segment_start + s.mem_size;
        if (addr >= segment_start and addr < segment_end) {
            containing_segment = s;
            break;
        }
    }
    if (containing_segment == null) {
        if (!allow_outside) {
            Logger.err("addr 0x{x} not in any mapped segment", .{addr});
            return error.AddressNotInMappedSegments;
        }

        Logger.debug("warning: offset 0x{x} was requested to be resolved to a loaded address, but is not in any mapped segment", .{addr});
        return dyn_object.loaded_at.? + addr;
    }

    const segment = containing_segment.?;

    return segment.loaded_at + addr - segment.mem_offset;
}

fn vAddressToFileAddress(dyn_object: *DynObject, addr: usize, size: usize) !usize {
    const bytes = @as([*]const u8, @ptrFromInt(dyn_object.mapped_at))[0..dyn_object.mapped_size];
    const phdrs = try elfProgramHeaders(bytes, dyn_object.eh);
    return @intFromPtr((try elfVirtualFileRange(bytes, phdrs, addr, size)).ptr);
}

fn dumpSegments(dyn_obj: *DynObject) !void {
    var bufName: [256]u8 = undefined;

    for (dyn_obj.segments.values()) |*s| {
        const mem_start = s.loaded_at;
        const mem_size = s.mem_size;

        const segment_file_name = try std.fmt.bufPrint(&bufName, "{s}_0x{x}_0x{x}__0x{x}", .{ dyn_obj.name, mem_start, mem_start + mem_size, s.file_offset });
        const segment_file = try std.fs.cwd().createFile(segment_file_name, .{});
        defer segment_file.close();

        const data: []const u8 = (@as([*]const u8, @ptrFromInt(mem_start)))[0..mem_size];

        var writer = segment_file.writer(&.{});
        try writer.interface.writeAll(data);
    }
}

fn callInitFunctions(dyn_obj: *DynObject) !void {
    const is_libc_so = isLibcName(dyn_obj.name);

    if (is_libc_so) {
        // TODO use libc_specifics.call_ops
        const maybe_sym = resolveSymbolByName("__libc_early_init") catch null;
        if (maybe_sym) |sym| {
            Logger.debug("libc: found early init: 0x{x}", .{sym.address});
            const early_init: *const fn (bool) callconv(.c) void = @ptrFromInt(sym.address);

            Logger.debug("libc: calling early_init at 0x{x}", .{sym.address});
            early_init(false);
        }
    }

    if (dyn_obj.init_addr != 0) {
        const initial_addr = dyn_obj.init_addr;
        const actual_addr = try vAddressToLoadedAddress(dyn_obj, dyn_obj.init_addr, false);

        if (!is_libc_so) {
            Logger.debug("calling init function for {s} at 0x{x} (initial address: 0x{x})", .{ dyn_obj.name, actual_addr, initial_addr });
            const func = @as(*const fn () callconv(.c) void, @ptrFromInt(actual_addr));
            func();
        } else {
            Logger.debug("libc: calling init function for {s} at 0x{x} (initial address: 0x{x})", .{ dyn_obj.name, actual_addr, initial_addr });

            const argc: c_int = @intCast(dll_args.vector.len);
            const argv: [*c]const [*c]const u8 = @ptrCast(dll_args.vector);
            const env: [*c]const [*c]const u8 = @ptrCast(dll_environ.block.slice);

            const func = @as(*const fn (
                c_int,
                [*c]const [*c]const u8,
                [*c]const [*c]const u8,
            ) callconv(.c) void, @ptrFromInt(actual_addr));
            func(argc, argv, env);
        }
    }

    if (dyn_obj.init_array_addr != 0 and dyn_obj.init_array_size > 0) {
        const num_funcs = dyn_obj.init_array_size / @sizeOf(usize);
        Logger.debug("calling {d} init_array functions for {s} (0x{x})", .{ num_funcs, dyn_obj.name, dyn_obj.init_array_addr });

        if (dyn_obj.init_array_size % @sizeOf(usize) != 0) return error.InvalidInitArraySize;

        const initial_init_array: [*]align(1) const usize = @ptrFromInt(try vAddressToFileAddress(dyn_obj, dyn_obj.init_array_addr, dyn_obj.init_array_size));
        const actual_init_array: [*]align(1) const usize = @ptrFromInt(try vAddressToLoadedAddress(dyn_obj, dyn_obj.init_array_addr, false));

        for (0..num_funcs) |i| {
            const initial_addr = initial_init_array[i];
            const actual_addr = actual_init_array[i];

            if (actual_addr == 0) {
                Logger.debug("skipping call to init_array[{d}]: null addr (initial address: 0x{x})", .{ i, initial_addr });
                continue;
            }

            if (!is_libc_so) {
                Logger.debug("calling init_array[{d}] for {s} at 0x{x} (initial address: 0x{x})", .{ i, dyn_obj.name, actual_addr, initial_addr });
                const func = @as(*const fn () callconv(.c) void, @ptrFromInt(actual_addr));
                func();
            } else {
                Logger.debug("libc: calling init_array[{d}] for {s} at 0x{x} (initial address: 0x{x})", .{ i, dyn_obj.name, actual_addr, initial_addr });

                const argc: c_int = @intCast(dll_args.vector.len);
                const argv: [*c]const [*c]const u8 = @ptrCast(dll_args.vector);
                const env: [*c]const [*c]const u8 = @ptrCast(dll_environ.block.slice);

                const func = @as(*const fn (
                    c_int,
                    [*c]const [*c]const u8,
                    [*c]const [*c]const u8,
                ) callconv(.c) void, @ptrFromInt(actual_addr));
                func(argc, argv, env);
            }
        }
    }
}

fn callFiniFunctions(dyn_obj: *DynObject) !void {
    const is_libc_so = isLibcName(dyn_obj.name);

    if (dyn_obj.fini_array_addr != 0 and dyn_obj.fini_array_size > 0) {
        const num_funcs = dyn_obj.fini_array_size / @sizeOf(usize);
        Logger.debug("calling {d} fini_array functions for {s} (0x{x})", .{ num_funcs, dyn_obj.name, dyn_obj.fini_array_addr });

        if (dyn_obj.fini_array_size % @sizeOf(usize) != 0) return error.InvalidFiniArraySize;

        const initial_fini_array: [*]align(1) const usize = @ptrFromInt(try vAddressToFileAddress(dyn_obj, dyn_obj.fini_array_addr, dyn_obj.fini_array_size));
        const actual_fini_array: [*]align(1) const usize = @ptrFromInt(try vAddressToLoadedAddress(dyn_obj, dyn_obj.fini_array_addr, false));

        var i: usize = num_funcs;
        while (i > 0) {
            i -= 1;

            const initial_addr = initial_fini_array[i];
            const actual_addr = actual_fini_array[i];

            if (actual_addr == 0) {
                Logger.debug("skipping call to fini_array[{d}]: null addr (initial address: 0x{x})", .{ i, initial_addr });
                continue;
            }

            if (!is_libc_so) {
                Logger.debug("calling fini_array[{d}] for {s} at 0x{x} (initial address: 0x{x})", .{ i, dyn_obj.name, actual_addr, initial_addr });
            } else {
                Logger.debug("libc: calling fini_array[{d}] for {s} at 0x{x} (initial address: 0x{x})", .{ i, dyn_obj.name, actual_addr, initial_addr });
            }

            const func = @as(*const fn () callconv(.c) void, @ptrFromInt(actual_addr));
            func();
        }
    }

    if (dyn_obj.fini_addr != 0) {
        const initial_addr = dyn_obj.fini_addr;
        const actual_addr = try vAddressToLoadedAddress(dyn_obj, dyn_obj.fini_addr, false);

        if (!is_libc_so) {
            Logger.debug("calling fini function for {s} at 0x{x} (initial address: 0x{x})", .{ dyn_obj.name, actual_addr, initial_addr });
        } else {
            Logger.debug("libc: calling fini function for {s} at 0x{x} (initial address: 0x{x})", .{ dyn_obj.name, actual_addr, initial_addr });
        }

        const func = @as(*const fn () callconv(.c) void, @ptrFromInt(actual_addr));
        func();
    }
}

fn getSubstituteAddress(sym: ResolvedSymbol, for_obj: *DynObject, allow_preload_override: bool) ?usize {
    if (sym.dyn_object_idx == std.math.maxInt(usize)) {
        return null;
    }

    const dyn_object = &dyn_objects.values()[sym.dyn_object_idx];

    var for_obj_is_preload_root = false;
    if (dyn_objects.getIndex(for_obj.key)) |for_obj_idx| {
        for_obj_is_preload_root = std.mem.findScalar(usize, preload_root_indices.items, for_obj_idx) != null;
    }

    if (allow_preload_override and !for_obj_is_preload_root) {
        const preload_sym = getResolvedSymbolByName(null, sym.name, false, true, false) catch null;
        if (preload_sym) |psym| {
            if (std.mem.findScalar(usize, for_obj.binding_dependencies.items, psym.dyn_object_idx) == null) {
                for_obj.binding_dependencies.append(dll_allocator, psym.dyn_object_idx) catch @panic("OOM");
            }
            Logger.info("substitutes: preload override for {s}: 0x{x} => 0x{x}", .{ sym.name, sym.address, psym.address });
            return psym.address;
        }
    }

    var addr: ?usize = null;

    // alloc functions
    // TODO errno handling
    if (std.mem.eql(u8, sym.name, "malloc")) {
        addr = @intFromPtr(&mallocSubstitute);
    } else if (std.mem.eql(u8, sym.name, "free")) {
        addr = @intFromPtr(&freeSubstitute);
    } else if (std.mem.eql(u8, sym.name, "calloc")) {
        addr = @intFromPtr(&callocSubstitute);
    } else if (std.mem.eql(u8, sym.name, "realloc")) {
        addr = @intFromPtr(&reallocSubstitute);
    } else if (std.mem.eql(u8, sym.name, "reallocarray")) {
        addr = @intFromPtr(&reallocarraySubstitute);
    } else if (std.mem.eql(u8, sym.name, "aligned_alloc")) {
        addr = @intFromPtr(&alignedAllocSubstitute);
    } else if (std.mem.eql(u8, sym.name, "posix_memalign")) {
        addr = @intFromPtr(&posixMemalignSubstitute);
    } else if (std.mem.eql(u8, sym.name, "memalign")) {
        addr = @intFromPtr(&alignedAllocSubstitute);
    } else if (std.mem.eql(u8, sym.name, "valloc")) {
        if (isLibcName(for_obj.name)) {
            Logger.warn("substitutes: {s}: dangerous unsubstituted valloc function [{s}] {s} at 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
        }
        addr = @intFromPtr(&unsubstitutedTrap);
    } else if (std.mem.eql(u8, sym.name, "palloc")) {
        if (isLibcName(for_obj.name)) {
            Logger.warn("substitutes: {s}: dangerous unsubstituted palloc function [{s}] {s} at 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
        }
        addr = @intFromPtr(&unsubstitutedTrap);
    }

    // dl functions
    if (std.mem.eql(u8, sym.name, "__cxa_thread_atexit_impl") or std.mem.eql(u8, sym.name, "__cxa_thread_atexit")) {
        addr = @intFromPtr(&cxaThreadAtExitSubstitute);
    } else if (std.mem.eql(u8, sym.name, "dlopen")) {
        addr = @intFromPtr(&dlopenSubstitute);
    } else if (std.mem.eql(u8, sym.name, "dlclose")) {
        addr = @intFromPtr(&dlcloseSubstitute);
    } else if (std.mem.eql(u8, sym.name, "dlsym")) {
        addr = @intFromPtr(&dlsymSubstitute);
    } else if (std.mem.eql(u8, sym.name, "dladdr")) {
        addr = @intFromPtr(&dladdrSubstitute);
    } else if (std.mem.eql(u8, sym.name, "dlerror")) {
        addr = @intFromPtr(&dlerrorSubstitute);
    } else if (std.mem.eql(u8, sym.name, "dlvsym")) {
        addr = @intFromPtr(&dlvsymSubstitute);
    } else if (std.mem.eql(u8, sym.name, "dladdr1")) {
        addr = @intFromPtr(&dladdr1Substitute);
    } else if (std.mem.eql(u8, sym.name, "dlinfo")) {
        addr = @intFromPtr(&dlinfoSubstitute);
    } else if (std.mem.eql(u8, sym.name, "dlmopen")) {
        addr = @intFromPtr(&dlmopenSubstitute);
    } else if (std.mem.eql(u8, sym.name, "_dl_get_tls_static_info")) {
        addr = @intFromPtr(&dlGetTlsStaticInfoSubstitute);
    } else if (std.mem.eql(u8, sym.name, "_dl_find_object")) {
        addr = @intFromPtr(&dlFindObjectSubstitute);
    } else if (std.mem.eql(u8, sym.name, "_dl_find_dso_for_object")) {
        addr = @intFromPtr(&dlFindDsoForObjectSubstitute);
    } else if (std.mem.eql(u8, sym.name, "dl_iterate_phdr")) {
        addr = @intFromPtr(&dlIteratePhdrSubstitute);
    } else if (std.mem.startsWith(u8, sym.name, "dl") or std.mem.startsWith(u8, sym.name, "_dl")) {
        if (isLibcName(for_obj.name)) {
            Logger.warn("substitutes: {s}: dangerous unsubstituted dl function [{s}] {s} at 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
        }
        addr = @intFromPtr(&unsubstitutedTrap);
    }

    // pthreads functions
    if (std.mem.eql(u8, sym.name, "pthread_create")) {
        addr = @intFromPtr(&pthreadCreateSubstitute);
    } else if (std.mem.eql(u8, sym.name, "pthread_exit")) {
        addr = @intFromPtr(&pthreadExitSubstitute);
    } else if (std.mem.eql(u8, sym.name, "pthread_cancel")) {
        addr = @intFromPtr(&pthreadCancelSubstitute);
    } else if (std.mem.eql(u8, sym.name, "pthread_detach")) {
        addr = @intFromPtr(&pthreadDetachSubstitute);
    } else if (std.mem.eql(u8, sym.name, "pthread_join")) {
        addr = @intFromPtr(&pthreadJoinSubstitute);
    } else if (std.mem.eql(u8, sym.name, "pthread_kill")) {
        addr = @intFromPtr(&pthreadKillSubstitute);
    }
    // TODO substitution not really needed, but keep it in mind
    // else if (std.mem.eql(u8, sym.name, "pthread_once")) {
    //     addr = @intFromPtr(&pthreadOnceSubstitute);
    // }
    // TODO check if those functions really needs to be subsituted, it seems they only acts on the pthread struct
    // else if (std.mem.eql(u8, sym.name, "pthread_key_create")) {
    //     Logger.warn("substitutes: {s}: dangerous unsubstituted pthread function [{s}] {s} as 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
    //     addr = @intFromPtr(&unsubstitutedTrap);
    // } else if (std.mem.eql(u8, sym.name, "pthread_key_delete")) {
    //     Logger.warn("substitutes: {s}: dangerous unsubstituted pthread function [{s}] {s} as 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
    //     addr = @intFromPtr(&unsubstitutedTrap);
    // } else if (std.mem.eql(u8, sym.name, "pthread_setspecific")) {
    //     Logger.warn("substitutes: {s}: dangerous unsubstituted pthread function [{s}] {s} as 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
    //     addr = @intFromPtr(&unsubstitutedTrap);
    // } else if (std.mem.eql(u8, sym.name, "pthread_getspecific")) {
    //     Logger.warn("substitutes: {s}: dangerous unsubstituted pthread function [{s}] {s} as 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
    //     addr = @intFromPtr(&unsubstitutedTrap);
    // }

    // special functions
    if (std.mem.eql(u8, sym.name, "__tls_get_addr")) {
        addr = @intFromPtr(&tlsGetAddressSubstitute);
    }

    if (addr != null) {
        Logger.debug("substitutes: {s}: found for {s}: 0x{x} => 0x{x}", .{ dyn_object.name, sym.name, sym.address, addr.? });
    }

    return addr;
}

fn unsubstitutedTrap() void {
    @panic("unsupported call to a dangerous function");
}

const ExtraAlloc = struct {
    addr: usize,
    size: usize,
    r_size: usize,
};

const alloc_zero_val: usize = 0xffffffffffffffff;

// TODO global state
var extra_strs: std.ArrayList([]const u8) = .empty;
var extra_strs_z: std.ArrayList([:0]const u8) = .empty;
var extra_phdrs: std.ArrayList(*std.posix.dl_phdr_info) = .empty;
var extra_link_maps: std.ArrayList(*DlLinkMap) = .empty;
var thread_mutex: std.Io.Mutex = .init;
var extra_threads: std.ArrayList(*std.Thread) = .empty;
var last_dl_error: ?[:0]const u8 = null;
var extra_allocations: std.AutoArrayHashMapUnmanaged(usize, ExtraAlloc) = .empty;
var alloc_mutex: std.Io.Mutex = .init;
var dll_alloc_allocator: std.mem.Allocator = undefined;
// var extra_onces: std.AutoHashMapUnmanaged(usize, void) = .empty;

// TODO general thread safety for the substitutes

fn mallocSubstitute(size: usize) callconv(.c) ?*anyopaque {
    alloc_mutex.lock(dll_io) catch @panic("error locking mutex");

    Logger.debug("intercepted call: malloc({d})", .{size});

    const result = dll_alloc_allocator.alloc(u8, 16 + size) catch @panic("OOM");
    const aligned_result = @as([*]u8, @ptrFromInt(std.mem.alignForward(usize, @intFromPtr(result.ptr), 16)));

    extra_allocations.put(dll_allocator, @intFromPtr(aligned_result), .{
        .addr = @intFromPtr(result.ptr),
        .size = 16 + size,
        .r_size = size,
    }) catch @panic("OOM");

    Logger.info("intercepted call: success: malloc({d}) = 0x{x}", .{ size, @intFromPtr(aligned_result) });

    alloc_mutex.unlock(dll_io);

    return aligned_result;
}

fn alignedAllocSubstitute(alignment: usize, size: usize) callconv(.c) ?*anyopaque {
    alloc_mutex.lock(dll_io) catch @panic("error locking mutex");

    Logger.debug("intercepted call: aligned_alloc({d}, {d})", .{ alignment, size });

    const result = dll_alloc_allocator.alloc(u8, alignment + size) catch @panic("OOM");
    const aligned_result = @as([*]u8, @ptrFromInt(std.mem.alignForward(usize, @intFromPtr(result.ptr), alignment)));

    extra_allocations.put(dll_allocator, @intFromPtr(aligned_result), .{
        .addr = @intFromPtr(result.ptr),
        .size = alignment + size,
        .r_size = size,
    }) catch @panic("OOM");

    Logger.info("intercepted call: success: aligned_alloc({d}, {d}) = 0x{x}", .{ alignment, size, @intFromPtr(aligned_result) });

    alloc_mutex.unlock(dll_io);

    return aligned_result;
}

fn posixMemalignSubstitute(memptr: **anyopaque, alignment: usize, size: usize) callconv(.c) c_int {
    if (alignment == 0 or !std.math.isPowerOfTwo(alignment) or alignment % @sizeOf(*anyopaque) != 0) {
        return @backingInt(std.os.linux.E.INVAL);
    }

    alloc_mutex.lock(dll_io) catch @panic("error locking mutex");

    Logger.debug("intercepted call: posix_memalign(0x{x}, {d}, {d})", .{ @intFromPtr(memptr), alignment, size });

    const result = dll_alloc_allocator.alloc(u8, alignment + size) catch @panic("OOM");
    const aligned_result = @as([*]u8, @ptrFromInt(std.mem.alignForward(usize, @intFromPtr(result.ptr), alignment)));

    extra_allocations.put(dll_allocator, @intFromPtr(aligned_result), .{
        .addr = @intFromPtr(result.ptr),
        .size = alignment + size,
        .r_size = size,
    }) catch @panic("OOM");

    Logger.info("intercepted call: success: posix_memalign(0x{x} [-> 0x{x}], {d}, {d}) = 0", .{ @intFromPtr(memptr), @intFromPtr(aligned_result), alignment, size });

    memptr.* = aligned_result;

    alloc_mutex.unlock(dll_io);

    return 0;
}

fn freeSubstitute(p: ?*anyopaque) callconv(.c) void {
    alloc_mutex.lock(dll_io) catch @panic("error locking mutex");

    Logger.debug("intercepted call: free(0x{x})", .{@intFromPtr(p)});

    if (p != null) {
        const maybe_alloc = extra_allocations.get(@intFromPtr(p));

        if (maybe_alloc) |alloc| {
            const arr = @as([*]u8, @ptrFromInt(alloc.addr));
            const slice = arr[0..alloc.size];

            dll_alloc_allocator.free(slice);

            if (@intFromPtr(p) != alloc_zero_val) {
                _ = extra_allocations.swapRemove(@intFromPtr(p));
            }
        } else {
            Logger.err("free(0x{x}) failed: externally allocated memory", .{@intFromPtr(p)});
            @panic("free failed: externally allocated memory");
        }
    }

    Logger.info("intercepted call: success: free(0x{x}) [{d} allocs remaining", .{ @intFromPtr(p), extra_allocations.count() });

    alloc_mutex.unlock(dll_io);
}

fn allocationFailure() ?*anyopaque {
    const sym = getResolvedSymbolByName(null, "__errno_location", false, false, false) catch @panic("libc errno accessor unavailable");
    const errno_location: *const fn () callconv(.c) *c_int = @ptrFromInt(sym.address);
    errno_location().* = @backingInt(std.os.linux.E.NOMEM);
    return null;
}

fn callocSubstitute(n: usize, size: usize) callconv(.c) ?*anyopaque {
    alloc_mutex.lock(dll_io) catch @panic("error locking mutex");
    defer alloc_mutex.unlock(dll_io);

    Logger.debug("intercepted call: calloc({d}, {d})", .{ n, size });

    const requested_size = std.math.mul(usize, n, size) catch return allocationFailure();
    const allocation_size = std.math.add(usize, 16, requested_size) catch return allocationFailure();
    const result = dll_alloc_allocator.alloc(u8, allocation_size) catch return allocationFailure();
    @memset(result, 0x0);
    const aligned_result = @as([*]u8, @ptrFromInt(std.mem.alignForward(usize, @intFromPtr(result.ptr), 16)));

    extra_allocations.put(dll_allocator, @intFromPtr(aligned_result), .{
        .addr = @intFromPtr(result.ptr),
        .size = allocation_size,
        .r_size = requested_size,
    }) catch {
        dll_alloc_allocator.free(result);
        return allocationFailure();
    };

    Logger.info("intercepted call: success: calloc({d}, {d}) = 0x{x}", .{ n, size, @intFromPtr(aligned_result) });

    return aligned_result;
}

fn reallocSubstitute(p: ?*anyopaque, size: usize) callconv(.c) *anyopaque {
    alloc_mutex.lock(dll_io) catch @panic("error locking mutex");

    Logger.debug("intercepted call: realloc(0x{x}, {d})", .{ @intFromPtr(p), size });

    var result: []u8 = undefined;
    var aligned_result: [*]u8 = undefined;

    if (p != null) {
        const maybe_prev_alloc = extra_allocations.get(@intFromPtr(p));

        if (maybe_prev_alloc) |prev_alloc| {
            Logger.debug("REALLOC: PREV: size: {d}, content: {x}", .{ prev_alloc.r_size, @as([*]u8, @ptrCast(p))[0..@min(@min(size, prev_alloc.r_size), 20)] });

            const n_prev_bad_bytes = @intFromPtr(p) - prev_alloc.addr;

            const prev_arr = @as([*]u8, @ptrFromInt(prev_alloc.addr));
            const prev_slice = prev_arr[0..prev_alloc.size];

            if (n_prev_bad_bytes > 0) {
                @memmove(prev_slice.ptr, @as([*]u8, @ptrCast(p))[0..prev_alloc.r_size]);
            }

            result = dll_alloc_allocator.realloc(prev_slice, size + 16) catch @panic("OOM");
            aligned_result = @as([*]u8, @ptrFromInt(std.mem.alignForward(usize, @intFromPtr(result.ptr), 16)));

            _ = extra_allocations.swapRemove(@intFromPtr(p));

            const n_post_bad_bytes = @intFromPtr(aligned_result) - @intFromPtr(result.ptr);

            if (n_post_bad_bytes > 0) {
                @memmove(aligned_result, result[0..size]);
            }

            Logger.debug("REALLOC: POST: size: {d},: {x}", .{ size, @as([*]u8, @ptrCast(aligned_result))[0..@min(@min(size, prev_alloc.r_size), 20)] });
        } else {
            Logger.err("realloc(0x{x}, {d}) failed: externally allocated memory", .{ @intFromPtr(p), size });
            @panic("realloc failed: externally allocated memory");
        }
    } else {
        result = dll_alloc_allocator.alloc(u8, size + 16) catch @panic("OOM");
        aligned_result = @as([*]u8, @ptrFromInt(std.mem.alignForward(usize, @intFromPtr(result.ptr), 16)));
    }

    extra_allocations.put(dll_allocator, @intFromPtr(aligned_result), .{
        .addr = @intFromPtr(result.ptr),
        .r_size = size,
        .size = size + 16,
    }) catch @panic("OOM");

    Logger.info("intercepted call: success: realloc(0x{x}, {d}) = 0x{x}", .{ @intFromPtr(p), size, @intFromPtr(aligned_result) });

    alloc_mutex.unlock(dll_io);

    return aligned_result;
}

fn reallocarraySubstitute(p: ?*anyopaque, n: usize, size: usize) callconv(.c) *anyopaque {
    alloc_mutex.lock(dll_io) catch @panic("error locking mutex");

    Logger.debug("intercepted call: reallocarray(0x{x}, {d}, {d})", .{ @intFromPtr(p), n, size });

    var result: []u8 = undefined;
    var aligned_result: [*]u8 = undefined;

    if (p != null) {
        const maybe_prev_alloc = extra_allocations.get(@intFromPtr(p));

        if (maybe_prev_alloc) |prev_alloc| {
            Logger.debug("REALLOCARRAY: PREV: size: {d}, content: {x}", .{ prev_alloc.r_size, @as([*]u8, @ptrCast(p))[0..@min(@min(n * size, prev_alloc.r_size), 20)] });

            const n_prev_bad_bytes = @intFromPtr(p) - prev_alloc.addr;

            const prev_arr = @as([*]u8, @ptrFromInt(prev_alloc.addr));
            const prev_slice = prev_arr[0..prev_alloc.size];

            if (n_prev_bad_bytes > 0) {
                @memmove(prev_slice.ptr, @as([*]u8, @ptrCast(p))[0..prev_alloc.r_size]);
            }

            result = dll_alloc_allocator.realloc(prev_slice, n * size + 16) catch @panic("OOM");
            aligned_result = @as([*]u8, @ptrFromInt(std.mem.alignForward(usize, @intFromPtr(result.ptr), 16)));

            _ = extra_allocations.swapRemove(@intFromPtr(p));

            const n_post_bad_bytes = @intFromPtr(aligned_result) - @intFromPtr(result.ptr);

            if (n_post_bad_bytes > 0) {
                @memmove(aligned_result, result[0 .. n * size]);
            }

            Logger.debug("REALLOCARRAY: POST: size: {d}, content: {x}", .{ n * size, @as([*]u8, @ptrCast(aligned_result))[0..@min(@min(n * size, prev_alloc.r_size), 20)] });
        } else {
            Logger.err("reallocarray(0x{x}, {d}. {d}) failed: externally allocated memory", .{ @intFromPtr(p), n, size });
            @panic("reallocarray failed: externally allocated memory");
        }
    } else {
        result = dll_alloc_allocator.alloc(u8, n * size + 16) catch @panic("OOM");
        aligned_result = @as([*]u8, @ptrFromInt(std.mem.alignForward(usize, @intFromPtr(result.ptr), 16)));
    }

    extra_allocations.put(dll_allocator, @intFromPtr(aligned_result), .{
        .addr = @intFromPtr(result.ptr),
        .size = n * size + 16,
        .r_size = n * size,
    }) catch @panic("OOM");

    Logger.info("intercepted call: success: reallocarray(0x{x}, {d}, {d}) = 0x{x}", .{ @intFromPtr(p), n, size, @intFromPtr(aligned_result) });

    alloc_mutex.unlock(dll_io);

    return aligned_result;
}

const rtld_flags = struct {
    const lazy: c_int = 0x00001;
    const now: c_int = 0x00002;
    const noload: c_int = 0x00004;
    const global: c_int = 0x00100;
    const local: c_int = 0x00000;
};

fn dlopenSubstitute(path: ?[*:0]const u8, flags: c_int) callconv(.c) ?*anyopaque {
    const caller_addr = @returnAddress();
    Logger.debug("intercepted call: dlopen(\"{?s}\", 0x{x})", .{ path, flags });

    if (path == null) {
        Logger.info("intercepted call: success: dlopen(NULL, 0x{x}) = 0x{x}", .{ flags, DlHandle.rtld_main.toInt() });
        return @ptrFromInt(@as(usize, @intCast(DlHandle.rtld_main.toInt())));
    }

    const owned_path = dll_allocator.dupe(u8, std.mem.span(path.?)) catch @panic("OOM");
    extra_strs.append(dll_allocator, owned_path) catch @panic("OOM");

    var caller_runpath: ?[]const u8 = null;
    var caller_origin_dir: ?[]const u8 = null;
    if (findDynObjectForLoadedAddr(caller_addr)) |caller_result| {
        const caller = &dyn_objects.values()[caller_result.dyn_object_index];
        caller_runpath = caller.runpath;
        caller_origin_dir = std.fs.path.dirname(caller.path) orelse "/";
        Logger.debug("dlopen caller: {s} at 0x{x}", .{ caller.name, caller_addr });
    } else {
        Logger.debug("dlopen caller at 0x{x} is not a dynamically loaded object", .{caller_addr});
    }

    // TODO we should not try to load the library if RTLD_NOLOAD is set
    const lib = loadWithRootResolveContext(owned_path, caller_runpath, caller_origin_dir) catch |err| {
        if ((flags & rtld_flags.noload) == 0) {
            if (last_dl_error != null) {
                dll_allocator.free(last_dl_error.?);
            }
            last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to load library {s}: {}", .{ owned_path, err }, 0) catch @panic("OOM");
            dlerror_cleared = false;

            Logger.err("dlopen(\"{s}\", 0x{x}) failed: {}", .{ owned_path, flags, err });
        }

        return null;
    };

    std.debug.assert(lib.index <= std.math.maxInt(u32));

    const dyn_object = &dyn_objects.values()[lib.index];
    const handle: DlHandle = .{
        .tag = 0b10,
        .epoch = dyn_object.current_epoch,
        .index = @intCast(lib.index),
    };
    const handle_raw = handle.toInt();
    const gop = dl_handles.getOrPut(dll_allocator, handle_raw) catch @panic("OOM");
    if (gop.found_existing) {
        std.debug.assert(gop.value_ptr.dyn_object_idx == lib.index);
        std.debug.assert(gop.value_ptr.epoch == dyn_object.current_epoch);
        gop.value_ptr.open_count += 1;
    } else {
        gop.value_ptr.* = .{
            .dyn_object_idx = lib.index,
            .epoch = dyn_object.current_epoch,
            .open_count = 1,
        };
    }

    Logger.info("intercepted call: success: dlopen(\"{?s}\", 0x{x}) = 0x{x}", .{ path, flags, handle_raw });

    return @ptrFromInt(@as(usize, @intCast(handle_raw)));
}

fn dlcloseSubstitute(lib: *anyopaque) callconv(.c) c_int {
    Logger.debug("intercepted call: dlclose(0x{x})", .{@intFromPtr(lib)});

    const handle_raw: u64 = @intCast(@intFromPtr(lib));
    const handle = DlHandle.fromInt(handle_raw);

    if (handle == DlHandle.rtld_main) {
        Logger.info("intercepted call: success: dlclose(0x{x} [MAIN]) = 0", .{handle_raw});
        return 0;
    }

    if (handle == DlHandle.rtld_default or handle == DlHandle.rtld_next or handle.tag != 0b10) {
        if (last_dl_error != null) {
            dll_allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "invalid library handle 0x{x}", .{handle_raw}, 0) catch @panic("OOM");
        dlerror_cleared = false;

        Logger.warn("dlclose(0x{x}) failed: invalid library handle", .{handle_raw});

        return 1;
    }

    const metadata = dl_handles.getPtr(handle_raw) orelse {
        if (last_dl_error != null) {
            dll_allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "invalid library handle 0x{x}", .{handle_raw}, 0) catch @panic("OOM");
        dlerror_cleared = false;

        Logger.warn("dlclose(0x{x}) failed: invalid library handle", .{handle_raw});

        return 1;
    };

    if (metadata.open_count == 0) {
        if (last_dl_error != null) {
            dll_allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "library handle 0x{x} is already closed", .{handle_raw}, 0) catch @panic("OOM");
        dlerror_cleared = false;

        Logger.warn("dlclose(0x{x}) failed: already closed", .{handle_raw});

        return 1;
    }

    if (metadata.epoch != handle.epoch) {
        if (last_dl_error != null) {
            dll_allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "invalid library handle 0x{x}: stale epoch", .{handle_raw}, 0) catch @panic("OOM");
        dlerror_cleared = false;

        Logger.warn("dlclose(0x{x}) failed: stale handle epoch", .{handle_raw});

        return 1;
    }

    const dyn_object_idx = metadata.dyn_object_idx;
    const dyn_object = &dyn_objects.values()[dyn_object_idx];

    if (dyn_object.current_epoch != metadata.epoch) {
        if (last_dl_error != null) {
            dll_allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "library handle 0x{x} is stale", .{handle_raw}, 0) catch @panic("OOM");
        dlerror_cleared = false;

        Logger.warn("dlclose(0x{x} [{s}]) failed: stale handle", .{ handle_raw, dyn_object.name });

        return 1;
    }

    if (dyn_object.ref_count == 0) {
        metadata.open_count -= 1;
        Logger.info("intercepted call: success: dlclose(0x{x} [{s}]) = 0 (already unloaded)", .{ handle_raw, dyn_object.name });
        return 0;
    }

    for (dyn_object.deps_breadth_first.items) |dep_idx| {
        const dep_dyn_object = &dyn_objects.values()[dep_idx];

        std.debug.assert(dep_dyn_object.ref_count > 0);
        dep_dyn_object.ref_count -= 1;
    }

    metadata.open_count -= 1;
    unloadUnreferencedObjects() catch |err| {
        if (last_dl_error) |message| dll_allocator.free(message);
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to close library handle 0x{x}: {}", .{ handle_raw, err }, 0) catch @panic("OOM");
        dlerror_cleared = false;
        return 1;
    };

    Logger.info("intercepted call: success: dlclose(0x{x}) = 0", .{handle_raw});

    return 0;
}

fn unloadUnreferencedObjects() !void {
    const keep = try dll_allocator.alloc(bool, dyn_objects.count());
    defer dll_allocator.free(keep);

    for (dyn_objects.values(), keep) |dyn_object, *live| {
        live.* = dyn_object.ref_count != 0 or dyn_object.pinned or dyn_object.finalizing or dyn_object.tls_destructors != 0;
    }

    var changed = true;
    while (changed) {
        changed = false;
        for (dyn_objects.values(), keep) |dyn_object, live| {
            if (!live) continue;
            for (dyn_object.dependencies.items) |idx| {
                if (!keep[idx]) {
                    keep[idx] = true;
                    changed = true;
                }
            }
            for (dyn_object.binding_dependencies.items) |idx| {
                if (!keep[idx]) {
                    keep[idx] = true;
                    changed = true;
                }
            }
        }
    }

    var retiring: std.ArrayList(usize) = .empty;
    defer retiring.deinit(dll_allocator);

    try retiring.ensureTotalCapacity(dll_allocator, dyn_objects.count());

    var remaining = dyn_objects_init_indices.items.len;
    while (remaining != 0) {
        remaining -= 1;
        const idx = dyn_objects_init_indices.items[remaining];
        if (!keep[idx]) retiring.appendAssumeCapacity(idx);
    }

    for (dyn_objects_sorted_indices.items) |idx| {
        if (!keep[idx] and std.mem.findScalar(usize, retiring.items, idx) == null) retiring.appendAssumeCapacity(idx);
    }

    for (retiring.items) |idx| dyn_objects.values()[idx].finalizing = true;

    var fini_error: ?anyerror = null;
    for (retiring.items) |idx| {
        const dyn_object = &dyn_objects.values()[idx];
        if (!dyn_object.init_called) continue;

        dyn_object.init_called = false;
        var finalizing_object = dyn_object.*;
        callFiniFunctions(&finalizing_object) catch |err| {
            fini_error = err;
        };
    }

    for (retiring.items) |idx| try retireObject(idx);

    for (dyn_objects.values(), 0..) |*dyn_object, idx| {
        if (dyn_object.mapped_at == 0) {
            dyn_object.load_requested = false;
            dyn_object.key.retired_slot = idx + 1;
            dyn_objects.setKey(idx, dyn_object.key);
        }
    }

    if (fini_error) |err| return err;
}

fn retireObject(idx: usize) !void {
    const dyn_object = &dyn_objects.values()[idx];

    if (dyn_object.phdr_info) |info| CustomSelfInfo.removeExtraElf(dll_allocator, info);
    dyn_object.phdr_info = null;

    if (dyn_object.phdr_name) |name| dll_allocator.free(name);
    dyn_object.phdr_name = null;

    const base = dyn_object.loaded_at.?;
    const end = base + dyn_object.loaded_size;
    invalidateAddressCache(&ifunc_resolved_addrs, base, end);
    invalidateAddressCache(&irel_resolved_targets, base, end);

    var i: usize = 0;
    while (i < load_request_cache.count()) {
        if (load_request_cache.values()[i] == idx) {
            const key = load_request_cache.keys()[i];
            load_request_cache.swapRemoveAt(i);
            dll_allocator.free(key);
        } else i += 1;
    }

    i = 0;
    while (i < dl_handles.count()) {
        if (dl_handles.values()[i].dyn_object_idx == idx) {
            dl_handles.swapRemoveAt(i);
        } else i += 1;
    }

    if (std.mem.findScalar(usize, dyn_objects_init_indices.items, idx)) |pos| _ = dyn_objects_init_indices.orderedRemove(pos);
    if (std.mem.findScalar(usize, dyn_objects_sorted_indices.items, idx)) |pos| _ = dyn_objects_sorted_indices.orderedRemove(pos);

    const reservation = dyn_object.reservation.?;
    _ = try std.posix.mmap(reservation.ptr, reservation.len, .{}, .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = true }, -1, 0);

    std.posix.munmap(@as([*]align(std.heap.pageSize()) u8, @ptrFromInt(dyn_object.mapped_at))[0..dyn_object.mapped_size]);
    dyn_object.mapped_at = 0;
    dyn_object.mapped_size = 0;

    dyn_object.key.retired_slot = idx + 1;
    dyn_objects.setKey(idx, dyn_object.key);

    dyn_object.loaded_at = null;
    dyn_object.loaded_size = 0;
    dyn_object.loaded = false;
    dyn_object.relocated = false;
    dyn_object.load_requested = false;
    dyn_object.finalizing = false;
    dyn_object.tls_mapped_at = 0;

    dyn_object.syms_array.clearRetainingCapacity();
    for (dyn_object.syms.values()) |*indices| indices.deinit(dll_allocator);
    dyn_object.syms.clearRetainingCapacity();

    dyn_object.relocs.clearRetainingCapacity();
    dyn_object.segments.clearRetainingCapacity();
    dyn_object.binding_dependencies.clearRetainingCapacity();

    if (dyn_object.tls_capacity != 0) {
        const desc = normal_current_tls_area_desc.?;
        @memset(@as([*]u8, @constCast(desc.block.init.ptr))[desc.abi_tcb.offset - dyn_object.tls_offset ..][0..dyn_object.tls_capacity], 0);
    }
}

fn invalidateAddressCache(cache: *std.AutoArrayHashMapUnmanaged(usize, usize), base: usize, end: usize) void {
    var i: usize = 0;
    while (i < cache.count()) {
        const key = cache.keys()[i];
        const value = cache.values()[i];
        if ((key >= base and key < end) or (value >= base and value < end)) {
            cache.swapRemoveAt(i);
        } else i += 1;
    }
}

fn dlsymSubstitute(lib_handle: ?*anyopaque, sym_name: [*:0]const u8) callconv(.c) ?*anyopaque {
    Logger.debug("intercepted call: dlsym({d}, \"{s}\")", .{ @intFromPtr(lib_handle), sym_name });

    const caller_addr = @returnAddress();
    const maybe_caller_infos = findDynObjectSegmentForLoadedAddr(caller_addr) catch null;
    var caller_is_preload_root = false;
    if (maybe_caller_infos) |caller_infos| {
        if (dyn_objects.getIndex(caller_infos.dyn_object.key)) |caller_idx| {
            caller_is_preload_root = std.mem.findScalar(usize, preload_root_indices.items, caller_idx) != null;
        }
    }

    const handle_raw: u64 = if (lib_handle) |h| @intCast(@intFromPtr(h)) else DlHandle.rtld_default.toInt();
    const handle = DlHandle.fromInt(handle_raw);
    const find_next = lib_handle != null and handle == DlHandle.rtld_next;

    var dyn_object: ?*DynObject = null;

    if (find_next) {
        const infos = maybe_caller_infos orelse {
            if (last_dl_error != null) {
                dll_allocator.free(last_dl_error.?);
            }
            last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to resolve RTLD_NEXT caller for symbol {s} at 0x{x}", .{ sym_name, caller_addr }, 0) catch @panic("OOM");
            dlerror_cleared = false;

            Logger.warn("dlsym(RTLD_NEXT, \"{s}\") failed: unable to resolve caller at 0x{x}", .{ sym_name, caller_addr });

            return null;
        };

        dyn_object = infos.dyn_object;
    } else if (lib_handle != null and handle != DlHandle.rtld_default and handle != DlHandle.rtld_main) {
        if (handle.tag != 0b10) {
            if (last_dl_error != null) {
                dll_allocator.free(last_dl_error.?);
            }
            last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s}: invalid library handle 0x{x}", .{ sym_name, handle_raw }, 0) catch @panic("OOM");
            dlerror_cleared = false;

            Logger.warn("dlsym({d}, \"{s}\") failed: invalid library handle", .{ @intFromPtr(lib_handle), sym_name });

            return null;
        }

        const metadata = dl_handles.getPtr(handle_raw) orelse {
            if (last_dl_error != null) {
                dll_allocator.free(last_dl_error.?);
            }
            last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s}: invalid library handle 0x{x}", .{ sym_name, handle_raw }, 0) catch @panic("OOM");
            dlerror_cleared = false;

            Logger.warn("dlsym({d}, \"{s}\") failed: invalid library handle", .{ @intFromPtr(lib_handle), sym_name });

            return null;
        };

        if (metadata.open_count == 0) {
            if (last_dl_error != null) {
                dll_allocator.free(last_dl_error.?);
            }
            last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s}: library handle 0x{x} is closed", .{ sym_name, handle_raw }, 0) catch @panic("OOM");
            dlerror_cleared = false;

            Logger.warn("dlsym({d}, \"{s}\") failed: library handle is closed", .{ @intFromPtr(lib_handle), sym_name });

            return null;
        }

        dyn_object = &dyn_objects.values()[metadata.dyn_object_idx];

        if (dyn_object.?.current_epoch != metadata.epoch) {
            if (last_dl_error != null) {
                dll_allocator.free(last_dl_error.?);
            }
            last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s}: library handle 0x{x} is stale", .{ sym_name, handle_raw }, 0) catch @panic("OOM");
            dlerror_cleared = false;

            Logger.warn("dlsym({d}, \"{s}\") failed: library handle is stale", .{ @intFromPtr(lib_handle), sym_name });

            return null;
        }
    }

    if (dyn_object != null and dyn_object.?.ref_count == 0) {
        if (last_dl_error != null) {
            dll_allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s} for library {s}: library handle is closed", .{ sym_name, dyn_object.?.name }, 0) catch @panic("OOM");
        dlerror_cleared = false;

        Logger.warn("dlsym({d} [{s}], \"{s}\") failed: library handle is closed", .{ @intFromPtr(lib_handle), dyn_object.?.name, sym_name });

        return null;
    }

    const allow_preload_override = !find_next and !caller_is_preload_root;

    const sym = getResolvedSymbolByName(dyn_object, std.mem.span(sym_name), find_next, false, allow_preload_override) catch |err| {
        if (last_dl_error != null) {
            dll_allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s} for library {s}: {}", .{ sym_name, if (dyn_object) |do| do.name else "NULL", err }, 0) catch @panic("OOM");
        dlerror_cleared = false;

        Logger.warn("dlsym({d} [{s}], \"{s}\") failed: {}", .{ @intFromPtr(lib_handle), if (dyn_object) |do| do.name else "NULL", sym_name, err });

        return null;
    };

    Logger.info("intercepted call: success: dlsym({d} [{s}], \"{s}\") = 0x{x}", .{ @intFromPtr(lib_handle), if (dyn_object) |do| do.name else "NULL", sym_name, sym.address });

    return @ptrFromInt(sym.address);
}

fn dlvsymSubstitute(lib_handle: ?*anyopaque, sym_name: [*:0]const u8, version: [*:0]const u8) callconv(.c) ?*anyopaque {
    Logger.debug("intercepted call: dlvsym({d}, \"{s}\", \"{s}\")", .{ @intFromPtr(lib_handle), sym_name, version });

    const caller_addr = @returnAddress();
    const maybe_caller_infos = findDynObjectSegmentForLoadedAddr(caller_addr) catch null;
    var caller_is_preload_root = false;
    if (maybe_caller_infos) |caller_infos| {
        if (dyn_objects.getIndex(caller_infos.dyn_object.key)) |caller_idx| {
            caller_is_preload_root = std.mem.findScalar(usize, preload_root_indices.items, caller_idx) != null;
        }
    }

    const handle_raw: u64 = if (lib_handle) |h| @intCast(@intFromPtr(h)) else DlHandle.rtld_default.toInt();
    const handle = DlHandle.fromInt(handle_raw);
    const find_next = lib_handle != null and handle == DlHandle.rtld_next;

    var dyn_object: ?*DynObject = null;

    if (find_next) {
        const infos = maybe_caller_infos orelse {
            if (last_dl_error != null) {
                dll_allocator.free(last_dl_error.?);
            }
            last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to resolve RTLD_NEXT caller for symbol {s}@{s} at 0x{x}", .{ sym_name, version, caller_addr }, 0) catch @panic("OOM");
            dlerror_cleared = false;

            Logger.warn("dlvsym(RTLD_NEXT, \"{s}\", \"{s}\") failed: unable to resolve caller at 0x{x}", .{ sym_name, version, caller_addr });

            return null;
        };

        dyn_object = infos.dyn_object;
    } else if (lib_handle != null and handle != DlHandle.rtld_default and handle != DlHandle.rtld_main) {
        if (handle.tag != 0b10) {
            if (last_dl_error != null) {
                dll_allocator.free(last_dl_error.?);
            }
            last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s}@{s}: invalid library handle 0x{x}", .{ sym_name, version, handle_raw }, 0) catch @panic("OOM");
            dlerror_cleared = false;

            Logger.warn("dlvsym({d}, \"{s}\", \"{s}\") failed: invalid library handle", .{ @intFromPtr(lib_handle), sym_name, version });

            return null;
        }

        const metadata = dl_handles.getPtr(handle_raw) orelse {
            if (last_dl_error != null) {
                dll_allocator.free(last_dl_error.?);
            }
            last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s}@{s}: invalid library handle 0x{x}", .{ sym_name, version, handle_raw }, 0) catch @panic("OOM");
            dlerror_cleared = false;

            Logger.warn("dlvsym({d}, \"{s}\", \"{s}\") failed: invalid library handle", .{ @intFromPtr(lib_handle), sym_name, version });

            return null;
        };

        if (metadata.open_count == 0) {
            if (last_dl_error != null) {
                dll_allocator.free(last_dl_error.?);
            }
            last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s}@{s}: library handle 0x{x} is closed", .{ sym_name, version, handle_raw }, 0) catch @panic("OOM");
            dlerror_cleared = false;

            Logger.warn("dlvsym({d}, \"{s}\", \"{s}\") failed: library handle is closed", .{ @intFromPtr(lib_handle), sym_name, version });

            return null;
        }

        dyn_object = &dyn_objects.values()[metadata.dyn_object_idx];

        if (dyn_object.?.current_epoch != metadata.epoch) {
            if (last_dl_error != null) {
                dll_allocator.free(last_dl_error.?);
            }
            last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s}@{s}: library handle 0x{x} is stale", .{ sym_name, version, handle_raw }, 0) catch @panic("OOM");
            dlerror_cleared = false;

            Logger.warn("dlvsym({d}, \"{s}\", \"{s}\") failed: library handle is stale", .{ @intFromPtr(lib_handle), sym_name, version });

            return null;
        }
    }

    if (dyn_object != null and dyn_object.?.ref_count == 0) {
        if (last_dl_error != null) {
            dll_allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s}@{s} for library {s}: library handle is closed", .{ sym_name, version, dyn_object.?.name }, 0) catch @panic("OOM");
        dlerror_cleared = false;

        Logger.warn("dlvsym({d} [{s}], \"{s}\", \"{s}\") failed: library handle is closed", .{ @intFromPtr(lib_handle), dyn_object.?.name, sym_name, version });

        return null;
    }

    const allow_preload_override = !find_next and !caller_is_preload_root;

    const sym = getResolvedSymbolByNameAndVersion(dyn_object, std.mem.span(sym_name), std.mem.span(version), find_next, false, allow_preload_override) catch |err| {
        if (last_dl_error != null) {
            dll_allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get symbol {s}@{s} for library {s}: {}", .{ sym_name, version, if (dyn_object) |do| do.name else "NULL", err }, 0) catch @panic("OOM");
        dlerror_cleared = false;

        Logger.warn("dlvsym({d} [{s}], \"{s}\", \"{s}\") failed: {}", .{ @intFromPtr(lib_handle), if (dyn_object) |do| do.name else "NULL", sym_name, version, err });

        return null;
    };

    Logger.info("intercepted call: success: dlvsym({d} [{s}], \"{s}\", \"{s}\") = 0x{x}", .{ @intFromPtr(lib_handle), if (dyn_object) |do| do.name else "NULL", sym_name, version, sym.address });

    return @ptrFromInt(sym.address);
}

// typedef struct {
//     const char *dli_fname;  /* Pathname of shared object that contains address */
//     void       *dli_fbase;  /* Base address at which shared object is loaded */
//     const char *dli_sname;  /* Name of symbol whose definition overlaps addr */
//     void       *dli_saddr;  /* Exact address of symbol named in dli_sname */
// } Dl_info;

const DlInfo = extern struct {
    dli_fname: [*:0]const u8,
    dli_fbase: *anyopaque,
    dli_fsname: ?[*:0]const u8,
    dli_fsaddr: ?*anyopaque,
};

const DlLinkMap = extern struct {
    l_addr: usize,
    l_name: [*:0]const u8,
    l_ld: *std.elf.Dyn,
    l_next: ?*DlLinkMap,
    l_prev: ?*DlLinkMap,
    _others: [1168]u8, // TODO implementation dependent
};

const DlFindObject = extern struct {
    dlfo_flags: c_ulonglong,
    dlfo_map_start: ?*anyopaque,
    dlfo_map_end: ?*anyopaque,
    dlfo_link_map: ?*DlLinkMap,
    dlfo_eh_frame: ?*anyopaque,
    __dlfo_reserved: [7]c_ulonglong, // TODO implementation dependent
};

fn dladdrSubstitute(addr: *anyopaque, dl_info: *DlInfo) callconv(.c) c_int {
    Logger.debug("intercepted call: dladdr(0x{x}, dl_info: *DlInfo [0x{x}])", .{ @intFromPtr(addr), @intFromPtr(dl_info) });

    const infos = findDynObjectSegmentForLoadedAddr(@intFromPtr(addr)) catch |err| {
        if (last_dl_error != null) {
            dll_allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get infos for address 0x{x}: {}", .{ @intFromPtr(addr), err }, 0) catch @panic("OOM");

        Logger.warn("dladdr(0x{x}, {}) failed: {}", .{ @intFromPtr(addr), dl_info.*, err });

        return 0;
    };

    const owned_name = dll_allocator.dupeSentinel(u8, infos.dyn_object.name, 0) catch @panic("OOM");
    extra_strs_z.append(dll_allocator, owned_name) catch @panic("OOM");

    dl_info.dli_fname = owned_name.ptr;
    dl_info.dli_fbase = @ptrFromInt(infos.dyn_object.loaded_at.?);

    if (infos.sym_index) |sidx| {
        const sym = infos.dyn_object.syms_array.items[sidx];
        const sym_addr = vAddressToLoadedAddress(infos.dyn_object, sym.value, false) catch unreachable;

        const owned_sym_name = dll_allocator.dupeSentinel(u8, sym.name, 0) catch @panic("OOM");
        extra_strs_z.append(dll_allocator, owned_sym_name) catch @panic("OOM");

        dl_info.dli_fsname = owned_sym_name.ptr;
        dl_info.dli_fsaddr = @ptrFromInt(sym_addr);
    } else {
        dl_info.dli_fsname = null;
        dl_info.dli_fsaddr = null;
    }

    Logger.info("intercepted call: success: dladdr(0x{x}, .{{.dli_fname = {s}, .dli_fbase = 0x{x}, .dli_fsname = {?s}, .dli_fs_addr = 0x{x}}}) = 1", .{
        @intFromPtr(addr),
        dl_info.dli_fname,
        @intFromPtr(dl_info.dli_fbase),
        dl_info.dli_fsname,
        if (dl_info.dli_fsaddr) |fsa| @intFromPtr(fsa) else 0,
    });

    return 1;
}

// TODO global state
// TODO dlerror should be threadlocal
var dlerror_cleared: bool = true;

fn dlerrorSubstitute() callconv(.c) ?[*:0]const u8 {
    Logger.debug("intercepted call: dlerror()", .{});
    Logger.info("intercepted call: success: dlerror() = {?s}", .{last_dl_error});

    const err = if (!dlerror_cleared and last_dl_error != null) last_dl_error.?.ptr else null;
    dlerror_cleared = true;

    return err;
}

fn dladdr1Substitute(addr: *anyopaque, dl_info: *DlInfo, extra_infos: *anyopaque, flags: c_int) callconv(.c) c_int {
    Logger.debug("intercepted call: dladdr1(0x{x}, dl_info: *DlInfo [0x{x}], extra_infos: 0x{x}, flags: 0x{x})", .{
        @intFromPtr(addr),
        @intFromPtr(dl_info),
        @intFromPtr(extra_infos),
        if (flags == 1) "RTLD_DL_SYMENT" else if (flags == 2) "RTLD_DL_LINKMAP" else "UNKNOWN_FLAGS",
    });

    const infos = findDynObjectSegmentForLoadedAddr(@intFromPtr(addr)) catch |err| {
        if (last_dl_error != null) {
            dll_allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(dll_allocator, "unable to get infos for address 0x{x}: {}", .{ @intFromPtr(addr), err }, 0) catch @panic("OOM");
        dlerror_cleared = false;

        Logger.warn("dladdr1(0x{x}, dl_info: *DlInfo [0x{x}], extra_infos: 0x{x}, flags: 0x{x}) failed: {}", .{
            @intFromPtr(addr),
            @intFromPtr(dl_info),
            @intFromPtr(extra_infos),
            if (flags == 1) "RTLD_DL_SYMENT" else if (flags == 2) "RTLD_DL_LINKMAP" else "UNKNOWN_FLAGS",
            err,
        });

        return 0;
    };

    const owned_name = dll_allocator.dupeSentinel(u8, infos.dyn_object.name, 0) catch @panic("OOM");
    extra_strs_z.append(dll_allocator, owned_name) catch @panic("OOM");

    dl_info.dli_fname = owned_name.ptr;
    dl_info.dli_fbase = @ptrFromInt(infos.dyn_object.loaded_at.?);

    if (infos.sym_index) |sidx| {
        const sym = infos.dyn_object.syms_array.items[sidx];
        const sym_addr = vAddressToLoadedAddress(infos.dyn_object, sym.value, false) catch unreachable;

        const owned_sym_name = dll_allocator.dupeSentinel(u8, sym.name, 0) catch @panic("OOM");
        extra_strs_z.append(dll_allocator, owned_sym_name) catch @panic("OOM");

        dl_info.dli_fsname = owned_sym_name.ptr;
        dl_info.dli_fsaddr = @ptrFromInt(sym_addr);
    } else {
        dl_info.dli_fsname = null;
        dl_info.dli_fsaddr = null;
    }

    if (flags == 2) {
        const extra_infos_impl: **DlLinkMap = @ptrCast(@alignCast(extra_infos));

        var curr: ?*DlLinkMap = null;
        for (dyn_objects.values()) |*dyn_obj| {
            if (!dyn_obj.loaded) {
                continue;
            }

            // TODO we should cache and reuse produced link maps (store them in a hasmap, keyed by dyn object name)
            const link_map = dll_allocator.create(DlLinkMap) catch @panic("OOM");
            extra_link_maps.append(dll_allocator, link_map) catch @panic("OOM");

            link_map.l_addr = dyn_obj.loaded_at.?;
            link_map.l_name = owned_name;
            link_map.l_ld = @ptrFromInt(dyn_obj.loaded_at.? + dyn_obj.dyn_section_offset);
            link_map.l_prev = curr;
            link_map.l_next = null;
            link_map._others = @splat(0);

            if (curr == null) {
                extra_infos_impl.* = link_map;
            }
            curr = link_map;
        }
    } else {
        Logger.err("dladdr1(0x{x}, .{{.dli_fname = {s}, .dli_fbase = 0x{x}, .dli_fsname = {?s}, .dli_fs_addr = 0x{x}}}) = 1, extra_infos: 0x{x}, flags: {s}) failed: {s}", .{
            @intFromPtr(addr),
            dl_info.dli_fname,
            @intFromPtr(dl_info.dli_fbase),
            dl_info.dli_fsname,
            if (dl_info.dli_fsaddr) |fsa| @intFromPtr(fsa) else 0,
            @intFromPtr(extra_infos),
            if (flags == 1) "RTLD_DL_SYMENT" else if (flags == 2) "RTLD_DL_LINKMAP" else "UNKNOWN_FLAGS",
            "implementation incomplete: flags = RTLD_DL_SYMENT",
        });

        @panic("dladdr1 implementation incomplete: flags = RTLD_DL_SYMENT");
    }

    Logger.info("intercepted call: success: dladdr1(0x{x}, .{{.dli_fname = {s}, .dli_fbase = 0x{x}, .dli_fsname = {?s}, .dli_fs_addr = 0x{x}}}) = 1, extra_infos: 0x{x}, flags: {s}) = 1", .{
        @intFromPtr(addr),
        dl_info.dli_fname,
        @intFromPtr(dl_info.dli_fbase),
        dl_info.dli_fsname,
        if (dl_info.dli_fsaddr) |fsa| @intFromPtr(fsa) else 0,
        @intFromPtr(extra_infos),
        if (flags == 1) "RTLD_DL_SYMENT" else if (flags == 2) "RTLD_DL_LINKMAP" else "UNKNOWN_FLAGS",
    });

    return 1;
}

fn dlinfoSubstitute(lib: *anyopaque, request: c_int, info: *anyopaque) callconv(.c) c_int {
    // TODO real implementation
    Logger.err("unimplemented: dlinfo(0x{x}, 0x{x}, 0x{x})", .{ @intFromPtr(lib), request, @intFromPtr(info) });
    @panic("unimplemented dlinfo");
}

fn dlmopenSubstitute(lmid: c_long, path: ?[*:0]u8, flags: c_int) callconv(.c) ?*anyopaque {
    // TODO real implementation
    Logger.err("unimplemented: dlmopen({d}, \"{s}\", 0x{x})", .{ lmid, path orelse "NULL", flags });
    @panic("unimplemented dlmopen");
}

fn dlFindObjectSubstitute(pc: *anyopaque, result: *DlFindObject) callconv(.c) c_int {
    Logger.debug("intercepted call: _dl_find_object(0x{x}, *DlFindObject [0x{x}])", .{ @intFromPtr(pc), @intFromPtr(result) });

    const infos = findDynObjectSegmentForLoadedAddr(@intFromPtr(pc)) catch |err| {
        Logger.warn("_dl_find_object(0x{x}, *DlFindObject [0x{x}]) failed: {}", .{ @intFromPtr(pc), @intFromPtr(result), err });
        return 1;
    };

    result.dlfo_eh_frame = @ptrFromInt(infos.dyn_object.loaded_at.? + infos.dyn_object.eh_init_mem_offset);

    Logger.warn("_dl_find_object: partial implementation: only `dl_info_result.dlfo_eh_frame` field supported", .{});

    Logger.info("intercepted call: success: _dl_find_object(0x{x}, .{{ .dflo_eh_frame = 0x{x} }})", .{ @intFromPtr(pc), @intFromPtr(result.dlfo_eh_frame) });

    return 0;
}

fn dlFindDsoForObjectSubstitute(addr: *anyopaque) callconv(.c) ?*DlLinkMap {
    Logger.debug("intercepted call: _dl_find_dso_for_object(0x{x})", .{@intFromPtr(addr)});

    const infos = findDynObjectSegmentForLoadedAddr(@intFromPtr(addr)) catch |err| {
        Logger.warn("_dl_find_dso_for_object(0x{x}) failed: {}", .{ @intFromPtr(addr), err });
        return null;
    };

    const owned_name = dll_allocator.dupeSentinel(u8, infos.dyn_object.name, 0) catch @panic("OOM");
    extra_strs_z.append(dll_allocator, owned_name) catch @panic("OOM");

    Logger.warn("_dl_find_dso_for_object: partial implementation: link maps should be reused as they can be compared by address", .{});

    // TODO we should cache and reuse produced link maps (store them in a hasmap, keyed by dyn object name)
    const link_map = dll_allocator.create(DlLinkMap) catch @panic("OOM");
    extra_link_maps.append(dll_allocator, link_map) catch @panic("OOM");

    link_map.l_addr = infos.dyn_object.loaded_at.?;
    link_map.l_name = owned_name;
    link_map.l_ld = @ptrFromInt(infos.dyn_object.loaded_at.? + infos.dyn_object.dyn_section_offset);
    link_map.l_prev = null;
    link_map.l_next = null;
    link_map._others = @splat(0);

    Logger.info("intercepted call: success: _dl_find_object(0x{x}) = 0x{x}", .{ @intFromPtr(addr), @intFromPtr(link_map) });

    return link_map;
}

fn dlIteratePhdrSubstitute(callback: *const fn (*anyopaque, c_uint, *anyopaque) callconv(.c) c_int, data: *anyopaque) callconv(.c) c_int {
    Logger.debug("intercepted call: dl_iterate_phdr(callback: 0x{x}, data: 0x{x})", .{ @intFromPtr(callback), @intFromPtr(data) });

    for (dyn_objects.values()) |*dyn_obj| {
        if (!dyn_obj.loaded) {
            continue;
        }

        const dl_phdr_info = dll_allocator.create(std.posix.dl_phdr_info) catch @panic("OOM");
        extra_phdrs.append(dll_allocator, dl_phdr_info) catch @panic("OOM");

        const owned_path_z = dll_allocator.dupeSentinel(u8, dyn_obj.path, 0) catch @panic("OOM");
        extra_strs_z.append(dll_allocator, owned_path_z) catch @panic("OOM");

        dl_phdr_info.* = .{
            .addr = dyn_obj.loaded_at.?,
            .name = owned_path_z.ptr,
            .phdr = @ptrFromInt(dyn_obj.mapped_at + dyn_obj.eh.e_phoff),
            .phnum = dyn_obj.eh.e_phnum,
        };

        const ret = callback(dl_phdr_info, @sizeOf(std.posix.dl_phdr_info), data);
        if (ret != 0) {
            Logger.info("intercepted call: success: dl_iterate_phdr(callback: 0x{x}, data: 0x{x}), callback() != 0 for {s}", .{ @intFromPtr(callback), @intFromPtr(data), dyn_obj.name });
            return ret;
        }
    }

    Logger.info("intercepted call: success: dl_iterate_phdr(callback: 0x{x}, data: 0x{x})", .{ @intFromPtr(callback), @intFromPtr(data) });

    return 0;
}

// In glibc < 2.34 libpthread asks the loader for these values during initialization.
// Newer glibc initialization reads the patched TLS fields.
fn dlGetTlsStaticInfoSubstitute(size: *usize, alignment: *usize) callconv(.c) void {
    size.* = staticTlsSize();
    alignment.* = staticTlsAlignment();
}

const ThreadInfos = struct {
    idx: usize,
    t: *std.Thread,
    ret: *anyopaque,
    handle: c_ulong,
};
const ThreadInfosMap = std.AutoArrayHashMapUnmanaged(usize, ThreadInfos);

const ThreadRoutineContext = struct {
    idx: usize,
    thread: *std.Thread,
    f: *const fn (?*anyopaque) callconv(.c) *anyopaque,
    arg: ?*anyopaque,
};

const ThreadDestructor = struct {
    tp: usize,
    object_idx: usize,
    function: *const fn (?*anyopaque) callconv(.c) void,
    argument: ?*anyopaque,
};

// TODO global state
var thread_infos: ThreadInfosMap = .empty;
var thread_current_idx: usize = 1;
var thread_destructors: std.ArrayList(ThreadDestructor) = .empty;

fn cxaThreadAtExitSubstitute(function: *const fn (?*anyopaque) callconv(.c) void, argument: ?*anyopaque, dso: ?*anyopaque) callconv(.c) c_int {
    const object = findDynObjectForLoadedAddr(@intFromPtr(dso)) orelse findDynObjectForLoadedAddr(@intFromPtr(function)) orelse return -1;

    thread_mutex.lock(dll_io) catch @panic("error locking mutex");
    defer thread_mutex.unlock(dll_io);

    thread_destructors.append(dll_allocator, .{
        .tp = currentThreadPointer(),
        .object_idx = object.dyn_object_index,
        .function = function,
        .argument = argument,
    }) catch return -1;
    dyn_objects.values()[object.dyn_object_index].tls_destructors += 1;

    return 0;
}

fn runThreadDestructors(tp: usize) void {
    while (true) {
        thread_mutex.lock(dll_io) catch @panic("error locking mutex");

        var remaining = thread_destructors.items.len;
        const entry = blk: {
            while (remaining != 0) {
                remaining -= 1;
                if (thread_destructors.items[remaining].tp == tp) break :blk thread_destructors.orderedRemove(remaining);
            }
            thread_mutex.unlock(dll_io);
            return;
        };
        thread_mutex.unlock(dll_io);

        entry.function(entry.argument);
        dyn_objects.values()[entry.object_idx].tls_destructors -= 1;
    }
}

fn threadRoutine(ctx: ThreadRoutineContext) void {
    const new_tp = currentThreadPointer();

    Logger.info("new thread spawned: {d} [0x{x}]", .{ ctx.idx, new_tp });

    applyLibcWriteOps(new_tp, true) catch @panic("error setting tp fields");

    // TODO should be lib_specifics.call_ops
    const maybe_sym = getResolvedSymbolByName(null, "__ctype_init", false, false, true) catch null;
    if (maybe_sym) |sym| {
        const ctypeInit: *const fn () callconv(.c) void = @ptrFromInt(sym.address);
        Logger.debug("thread {d}: call __ctype_init", .{ctx.idx});
        ctypeInit();
    }

    thread_mutex.lock(dll_io) catch @panic("error locking mutex");

    const entry = thread_infos.getOrPut(dll_allocator, ctx.idx) catch @panic("OOM");
    if (!entry.found_existing) {
        entry.value_ptr.* = .{ .idx = ctx.idx, .handle = new_tp, .t = ctx.thread, .ret = undefined };
    } else {
        std.debug.assert(entry.value_ptr.idx == ctx.idx);
        std.debug.assert(entry.value_ptr.handle == new_tp);
        std.debug.assert(entry.value_ptr.t == ctx.thread);
    }

    thread_mutex.unlock(dll_io);

    const ret = ctx.f(ctx.arg);
    runThreadDestructors(new_tp);

    thread_mutex.lock(dll_io) catch @panic("error locking mutex");
    const entry_after = thread_infos.getPtr(ctx.idx).?;
    entry_after.ret = ret;
    thread_mutex.unlock(dll_io);

    Logger.info("thread {d} completed: 0x{x}", .{ ctx.idx, @intFromPtr(ret) });
}

fn pthreadCreateSubstitute(newthread: *c_ulong, attr: ?*const anyopaque, start_routine: *const fn (?*anyopaque) callconv(.c) *anyopaque, arg: ?*anyopaque) callconv(.c) c_int {
    Logger.debug("intercepted call: pthread_create(0x{x}, 0x{x}, 0x{x}, 0x{x})", .{ @intFromPtr(newthread), @intFromPtr(attr), @intFromPtr(start_routine), @intFromPtr(arg) });

    const page_size = std.heap.pageSize();
    const default_stack_size = std.Thread.SpawnConfig.default_stack_size;

    var bytes: usize = page_size;
    bytes += @max(page_size, default_stack_size);
    bytes = std.mem.alignForward(usize, bytes, page_size);
    bytes = std.mem.alignForward(usize, bytes, std.os.linux.tls.area_desc.alignment);
    const tls_offset = bytes + std.os.linux.tls.area_desc.abi_tcb.offset;

    const thread = dll_allocator.create(std.Thread) catch @panic("OOM");

    thread_mutex.lock(dll_io) catch @panic("error locking mutex");
    extra_threads.append(dll_allocator, thread) catch @panic("OOM");
    thread_mutex.unlock(dll_io);

    const idx = @atomicRmw(usize, &thread_current_idx, .Add, 1, .seq_cst);
    thread.* = std.Thread.spawn(.{}, threadRoutine, .{ThreadRoutineContext{ .idx = idx, .thread = thread, .f = start_routine, .arg = arg }}) catch |err| {
        Logger.warn("pthread_create(0x{x}, 0x{x}, 0x{x}, 0x{x}) failed: {}", .{ @intFromPtr(newthread), @intFromPtr(attr), @intFromPtr(start_routine), @intFromPtr(arg), err });
        return 1;
    };

    const newthread_handle: *c_ulong = @ptrCast(@alignCast(newthread));
    newthread_handle.* = @intFromPtr(thread.impl.thread.mapped.ptr) + tls_offset;

    thread_mutex.lock(dll_io) catch @panic("error locking mutex");

    const entry = thread_infos.getOrPut(dll_allocator, idx) catch @panic("OOM");
    if (!entry.found_existing) {
        entry.value_ptr.* = .{ .idx = idx, .handle = newthread_handle.*, .t = thread, .ret = undefined };
    } else {
        std.debug.assert(entry.value_ptr.idx == idx);
        std.debug.assert(entry.value_ptr.handle == newthread_handle.*);
        std.debug.assert(entry.value_ptr.t == thread);
    }

    thread_mutex.unlock(dll_io);

    Logger.info("intercepted call: success: pthread_create(0x{x}, 0x{x}, 0x{x}, 0x{x}) = 0", .{ @intFromPtr(newthread), @intFromPtr(attr), @intFromPtr(start_routine), @intFromPtr(arg) });

    return 0;
}

fn pthreadExitSubstitute() callconv(.c) void {
    // TODO real implementation
    Logger.err("unimplemented: pthread_exit()", .{});
    @panic("unimplemented pthread_exit");
}

fn pthreadCancelSubstitute() callconv(.c) void {
    // TODO real implementation
    Logger.err("unimplemented: pthread_cancel()", .{});
    @panic("unimplemented pthread_cancel");
}

fn pthreadDetachSubstitute() callconv(.c) void {
    // TODO real implementation
    Logger.err("unimplemented: pthread_detach()", .{});
    @panic("unimplemented pthread_detach");
}

fn pthreadJoinSubstitute(thread_handle: c_ulong, retval: ?**anyopaque) callconv(.c) c_int {
    Logger.debug("intercepted call: pthread_join(0x{x}, 0x{x})", .{ thread_handle, @intFromPtr(retval) });

    thread_mutex.lock(dll_io) catch @panic("error locking mutex");

    for (thread_infos.values()) |*entry| {
        if (entry.handle != thread_handle) {
            continue;
        }

        const thread = entry.t;
        const idx = entry.idx;
        thread_mutex.unlock(dll_io);

        thread.join();

        thread_mutex.lock(dll_io) catch @panic("error locking mutex");

        if (retval) |result| result.* = thread_infos.get(idx).?.ret;
        _ = thread_infos.swapRemove(idx);
        if (std.mem.findScalar(*std.Thread, extra_threads.items, thread)) |pos| _ = extra_threads.swapRemove(pos);

        thread_mutex.unlock(dll_io);

        dll_allocator.destroy(thread);

        unloadUnreferencedObjects() catch |err| Logger.warn("pthread_join: deferred unload failed: {}", .{err});

        Logger.info("intercepted call: success: pthread_join(0x{x}, 0x{x})", .{ thread_handle, @intFromPtr(retval) });

        return 0;
    }

    thread_mutex.unlock(dll_io);

    Logger.err("pthread_join(0x{x}, 0x{x}) failed: thread not found", .{ thread_handle, @intFromPtr(retval) });
    @panic("pthread_join: thread not found");
}

fn pthreadKillSubstitute() callconv(.c) void {
    // TODO real implementation
    Logger.err("unimplemented: pthread_kill()", .{});
    @panic("unimplemented pthread_kill");
}

// fn pthreadOnceSubstitute(once_control: *anyopaque, init_routine: *const fn () callconv(.c) void) callconv(.c) void {
//     Logger.debug("intercepted call: pthread_once(0x{x}, 0x{x})", .{ @intFromPtr(once_control), @intFromPtr(init_routine) });

//     if (!extra_onces.contains(@intFromPtr(init_routine))) {
//         extra_onces.putNoClobber(allocator, @intFromPtr(init_routine), {}) catch @panic("OOM");
//         init_routine();
//     }

//     Logger.debug("intercepted call: success: pthread_once(0x{x}, 0x{x})", .{ @intFromPtr(once_control), @intFromPtr(init_routine) });
// }

const TlsIndex = extern struct {
    ti_module: usize,
    ti_offset: usize,
};

fn tlsGetAddressSubstitute(tls_index: *TlsIndex) callconv(.c) ?*anyopaque {
    Logger.debug("intercepted call: __tls_get_addr({})", .{tls_index});

    const dyn_object_idx = tls_index.ti_module - 1;

    const tp = currentThreadPointer();

    const dyn_object = &dyn_objects.values()[dyn_object_idx];
    const addr = tp - dyn_object.tls_offset + tls_index.ti_offset;

    Logger.info("intercepted call: success: __tls_get_addr({{.module = {s}, .offset = 0x{x}}}) = 0x{x}", .{ dyn_object.name, tls_index.ti_offset, addr });

    return @ptrFromInt(addr);
}
