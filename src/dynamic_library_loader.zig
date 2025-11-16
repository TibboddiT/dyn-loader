const std = @import("std");
const builtin = @import("builtin");

pub const CustomSelfInfo = struct {
    rwlock: std.Thread.RwLock,

    modules: std.ArrayList(Module),
    ranges: std.ArrayList(Module.Range),

    unwind_cache: if (can_unwind) ?[]std.debug.Dwarf.SelfUnwinder.CacheEntry else ?noreturn,

    var extra_phdr_infos: std.ArrayList(*std.posix.dl_phdr_info) = .empty;

    pub const init: SelfInfo = .{
        .rwlock = .{},
        .modules = .empty,
        .ranges = .empty,
        .unwind_cache = null,
    };
    pub fn deinit(si: *SelfInfo, gpa: std.mem.Allocator) void {
        for (si.modules.items) |*mod| {
            unwind: {
                const u = &(mod.unwind orelse break :unwind catch break :unwind);
                for (u.buf[0..u.len]) |*unwind| unwind.deinit(gpa);
            }
            loaded: {
                const l = &(mod.loaded_elf orelse break :loaded catch break :loaded);
                l.file.deinit(gpa);
            }
        }

        si.modules.deinit(gpa);
        si.ranges.deinit(gpa);
        if (si.unwind_cache) |cache| gpa.free(cache);
    }

    pub fn addExtraElf(gpa: std.mem.Allocator, dl_phdr_info: *std.posix.dl_phdr_info) !void {
        // TODO thread safety
        try extra_phdr_infos.append(gpa, dl_phdr_info);
    }

    pub fn clearExtraElfs(gpa: std.mem.Allocator) void {
        // TODO thread safety
        for (extra_phdr_infos.items) |e| {
            gpa.destroy(e);
        }

        extra_phdr_infos.clearAndFree(gpa);
    }

    pub fn getSymbol(si: *SelfInfo, gpa: std.mem.Allocator, io: std.Io, address: usize) std.debug.SelfInfoError!std.debug.Symbol {
        _ = io;
        const module = try si.findModule(gpa, address, .exclusive);
        defer si.rwlock.unlock();

        const vaddr = address - module.load_offset;

        const loaded_elf = try module.getLoadedElf(gpa);
        if (loaded_elf.file.dwarf) |*dwarf| {
            if (!loaded_elf.scanned_dwarf) {
                dwarf.open(gpa, builtin.target.cpu.arch.endian()) catch |err| switch (err) {
                    error.InvalidDebugInfo,
                    error.MissingDebugInfo,
                    error.OutOfMemory,
                    => |e| return e,
                    error.EndOfStream,
                    error.Overflow,
                    error.ReadFailed,
                    error.StreamTooLong,
                    => return error.InvalidDebugInfo,
                };
                loaded_elf.scanned_dwarf = true;
            }
            if (dwarf.getSymbol(gpa, builtin.target.cpu.arch.endian(), vaddr)) |sym| {
                return sym;
            } else |err| switch (err) {
                error.MissingDebugInfo => {},

                error.InvalidDebugInfo,
                error.OutOfMemory,
                => |e| return e,

                error.ReadFailed,
                error.EndOfStream,
                error.Overflow,
                error.StreamTooLong,
                => return error.InvalidDebugInfo,
            }
        }
        // When DWARF is unavailable, fall back to searching the symtab.
        return loaded_elf.file.searchSymtab(gpa, vaddr) catch |err| switch (err) {
            error.NoSymtab, error.NoStrtab => return error.MissingDebugInfo,
            error.BadSymtab => return error.InvalidDebugInfo,
            error.OutOfMemory => |e| return e,
        };
    }
    pub fn getModuleName(si: *SelfInfo, gpa: std.mem.Allocator, address: usize) std.debug.SelfInfoError![]const u8 {
        const module = try si.findModule(gpa, address, .shared);
        defer si.rwlock.unlockShared();
        if (module.name.len == 0) return error.MissingDebugInfo;
        return module.name;
    }

    pub const can_unwind: bool = s: {
        // The DWARF code can't deal with ILP32 ABIs yet: https://github.com/ziglang/zig/issues/25447
        switch (builtin.target.abi) {
            .gnuabin32,
            .muslabin32,
            .gnux32,
            .muslx32,
            => break :s false,
            else => {},
        }

        // Notably, we are yet to support unwinding on ARM. There, unwinding is not done through
        // `.eh_frame`, but instead with the `.ARM.exidx` section, which has a different format.
        const archs: []const std.Target.Cpu.Arch = switch (builtin.target.os.tag) {
            // Not supported yet: arm
            .haiku => &.{
                .aarch64,
                .m68k,
                .riscv64,
                .x86,
                .x86_64,
            },
            // Not supported yet: arm/armeb/thumb/thumbeb, xtensa/xtensaeb
            .linux => &.{
                .aarch64,
                .aarch64_be,
                .arc,
                .csky,
                .loongarch64,
                .m68k,
                .mips,
                .mipsel,
                .mips64,
                .mips64el,
                .or1k,
                .riscv32,
                .riscv64,
                .s390x,
                .x86,
                .x86_64,
            },
            .serenity => &.{
                .aarch64,
                .x86_64,
                .riscv64,
            },

            .dragonfly => &.{
                .x86_64,
            },
            // Not supported yet: arm
            .freebsd => &.{
                .aarch64,
                .riscv64,
                .x86_64,
            },
            // Not supported yet: arm/armeb, mips64/mips64el
            .netbsd => &.{
                .aarch64,
                .aarch64_be,
                .m68k,
                .mips,
                .mipsel,
                .x86,
                .x86_64,
            },
            // Not supported yet: arm
            .openbsd => &.{
                .aarch64,
                .mips64,
                .mips64el,
                .riscv64,
                .x86,
                .x86_64,
            },

            .illumos => &.{
                .x86,
                .x86_64,
            },

            else => unreachable,
        };
        for (archs) |a| {
            if (builtin.target.cpu.arch == a) break :s true;
        }
        break :s false;
    };
    comptime {
        if (can_unwind) {
            std.debug.assert(std.debug.Dwarf.supportsUnwinding(&builtin.target));
        }
    }
    pub const UnwindContext = std.debug.Dwarf.SelfUnwinder;
    pub fn unwindFrame(si: *SelfInfo, gpa: std.mem.Allocator, context: *UnwindContext) std.debug.SelfInfoError!usize {
        comptime std.debug.assert(can_unwind);

        {
            si.rwlock.lockShared();
            defer si.rwlock.unlockShared();
            if (si.unwind_cache) |cache| {
                if (std.debug.Dwarf.SelfUnwinder.CacheEntry.find(cache, context.pc)) |entry| {
                    return context.next(gpa, entry);
                }
            }
        }

        const module = try si.findModule(gpa, context.pc, .exclusive);
        defer si.rwlock.unlock();

        if (si.unwind_cache == null) {
            si.unwind_cache = try gpa.alloc(std.debug.Dwarf.SelfUnwinder.CacheEntry, 2048);
            @memset(si.unwind_cache.?, .empty);
        }

        const unwind_sections = try module.getUnwindSections(gpa);
        for (unwind_sections) |*unwind| {
            if (context.computeRules(gpa, unwind, module.load_offset, null)) |entry| {
                entry.populate(si.unwind_cache.?);
                return context.next(gpa, &entry);
            } else |err| switch (err) {
                error.MissingDebugInfo => continue,

                error.InvalidDebugInfo,
                error.UnsupportedDebugInfo,
                error.OutOfMemory,
                => |e| return e,

                error.EndOfStream,
                error.StreamTooLong,
                error.ReadFailed,
                error.Overflow,
                error.InvalidOpcode,
                error.InvalidOperation,
                error.InvalidOperand,
                => return error.InvalidDebugInfo,

                error.UnimplementedUserOpcode,
                error.UnsupportedAddrSize,
                => return error.UnsupportedDebugInfo,
            }
        }
        return error.MissingDebugInfo;
    }

    const Module = struct {
        load_offset: usize,
        name: []const u8,
        build_id: ?[]const u8,
        gnu_eh_frame: ?[]const u8,

        /// `null` means unwind information has not yet been loaded.
        unwind: ?(std.debug.SelfInfoError!UnwindSections),

        /// `null` means the ELF file has not yet been loaded.
        loaded_elf: ?(std.debug.SelfInfoError!LoadedElf),

        const LoadedElf = struct {
            file: std.debug.ElfFile,
            scanned_dwarf: bool,
        };

        const UnwindSections = struct {
            buf: [2]std.debug.Dwarf.Unwind,
            len: usize,
        };

        const Range = struct {
            start: usize,
            len: usize,
            /// Index into `modules`
            module_index: usize,
        };

        /// Assumes we already hold an exclusive lock.
        fn getUnwindSections(mod: *Module, gpa: std.mem.Allocator) std.debug.SelfInfoError![]std.debug.Dwarf.Unwind {
            if (mod.unwind == null) mod.unwind = loadUnwindSections(mod, gpa);
            const us = &(mod.unwind.? catch |err| return err);
            return us.buf[0..us.len];
        }
        fn loadUnwindSections(mod: *Module, gpa: std.mem.Allocator) std.debug.SelfInfoError!UnwindSections {
            var us: UnwindSections = .{
                .buf = undefined,
                .len = 0,
            };
            if (mod.gnu_eh_frame) |section_bytes| {
                const section_vaddr: u64 = @intFromPtr(section_bytes.ptr) - mod.load_offset;
                const header = std.debug.Dwarf.Unwind.EhFrameHeader.parse(section_vaddr, section_bytes, @sizeOf(usize), builtin.target.cpu.arch.endian()) catch |err| switch (err) {
                    error.ReadFailed => unreachable, // it's all fixed buffers
                    error.InvalidDebugInfo => |e| return e,
                    error.EndOfStream, error.Overflow => return error.InvalidDebugInfo,
                    error.UnsupportedAddrSize => return error.UnsupportedDebugInfo,
                };
                us.buf[us.len] = .initEhFrameHdr(header, section_vaddr, @ptrFromInt(@as(usize, @intCast(mod.load_offset + header.eh_frame_vaddr))));
                us.len += 1;
            } else {
                // There is no `.eh_frame_hdr` section. There may still be an `.eh_frame` or `.debug_frame`
                // section, but we'll have to load the binary to get at it.
                const loaded = try mod.getLoadedElf(gpa);
                // If both are present, we can't just pick one -- the info could be split between them.
                // `.debug_frame` is likely to be the more complete section, so we'll prioritize that one.
                if (loaded.file.debug_frame) |*debug_frame| {
                    us.buf[us.len] = .initSection(.debug_frame, debug_frame.vaddr, debug_frame.bytes);
                    us.len += 1;
                }
                if (loaded.file.eh_frame) |*eh_frame| {
                    us.buf[us.len] = .initSection(.eh_frame, eh_frame.vaddr, eh_frame.bytes);
                    us.len += 1;
                }
            }
            errdefer for (us.buf[0..us.len]) |*u| u.deinit(gpa);
            for (us.buf[0..us.len]) |*u| u.prepare(gpa, @sizeOf(usize), builtin.target.cpu.arch.endian(), true, false) catch |err| switch (err) {
                error.ReadFailed => unreachable, // it's all fixed buffers
                error.InvalidDebugInfo,
                error.MissingDebugInfo,
                error.OutOfMemory,
                => |e| return e,
                error.EndOfStream,
                error.Overflow,
                error.StreamTooLong,
                error.InvalidOperand,
                error.InvalidOpcode,
                error.InvalidOperation,
                => return error.InvalidDebugInfo,
                error.UnsupportedAddrSize,
                error.UnsupportedDwarfVersion,
                error.UnimplementedUserOpcode,
                => return error.UnsupportedDebugInfo,
            };
            return us;
        }

        /// Assumes we already hold an exclusive lock.
        fn getLoadedElf(mod: *Module, gpa: std.mem.Allocator) std.debug.SelfInfoError!*LoadedElf {
            if (mod.loaded_elf == null) mod.loaded_elf = loadElf(mod, gpa);
            return if (mod.loaded_elf.?) |*elf| elf else |err| err;
        }
        fn loadElf(mod: *Module, gpa: std.mem.Allocator) std.debug.SelfInfoError!LoadedElf {
            const load_result = if (mod.name.len > 0) res: {
                var file = std.fs.cwd().openFile(mod.name, .{}) catch return error.MissingDebugInfo;
                defer file.close();
                break :res std.debug.ElfFile.load(gpa, file, mod.build_id, &.native(mod.name));
            } else res: {
                const path = std.fs.selfExePathAlloc(gpa) catch |err| switch (err) {
                    error.OutOfMemory => |e| return e,
                    else => return error.ReadFailed,
                };
                defer gpa.free(path);
                var file = std.fs.cwd().openFile(path, .{}) catch return error.MissingDebugInfo;
                defer file.close();
                break :res std.debug.ElfFile.load(gpa, file, mod.build_id, &.native(path));
            };

            var elf_file = load_result catch |err| switch (err) {
                error.OutOfMemory,
                error.Unexpected,
                error.Canceled,
                => |e| return e,

                error.Overflow,
                error.TruncatedElfFile,
                error.InvalidCompressedSection,
                error.InvalidElfMagic,
                error.InvalidElfVersion,
                error.InvalidElfClass,
                error.InvalidElfEndian,
                => return error.InvalidDebugInfo,

                error.SystemResources,
                error.MemoryMappingNotSupported,
                error.AccessDenied,
                error.LockedMemoryLimitExceeded,
                error.ProcessFdQuotaExceeded,
                error.SystemFdQuotaExceeded,
                error.Streaming,
                => return error.ReadFailed,
            };
            errdefer elf_file.deinit(gpa);

            if (elf_file.endian != builtin.target.cpu.arch.endian()) return error.InvalidDebugInfo;
            if (elf_file.is_64 != (@sizeOf(usize) == 8)) return error.InvalidDebugInfo;

            return .{
                .file = elf_file,
                .scanned_dwarf = false,
            };
        }
    };

    fn findModule(si: *SelfInfo, gpa: std.mem.Allocator, address: usize, lock: enum { shared, exclusive }) std.debug.SelfInfoError!*Module {
        // With the requested lock, scan the module ranges looking for `address`.
        switch (lock) {
            .shared => si.rwlock.lockShared(),
            .exclusive => si.rwlock.lock(),
        }
        for (si.ranges.items) |*range| {
            if (address >= range.start and address < range.start + range.len) {
                return &si.modules.items[range.module_index];
            }
        }
        // The address wasn't in a known range. We will rebuild the module/range lists, since it's possible
        // a new module was loaded. Upgrade to an exclusive lock if necessary.
        switch (lock) {
            .shared => {
                si.rwlock.unlockShared();
                si.rwlock.lock();
            },
            .exclusive => {},
        }
        // Rebuild module list with the exclusive lock.
        {
            errdefer si.rwlock.unlock();
            for (si.modules.items) |*mod| {
                unwind: {
                    const u = &(mod.unwind orelse break :unwind catch break :unwind);
                    for (u.buf[0..u.len]) |*unwind| unwind.deinit(gpa);
                }
                loaded: {
                    const l = &(mod.loaded_elf orelse break :loaded catch break :loaded);
                    l.file.deinit(gpa);
                }
            }
            si.modules.clearRetainingCapacity();
            si.ranges.clearRetainingCapacity();
            var ctx: DlIterContext = .{ .si = si, .gpa = gpa };
            try std.posix.dl_iterate_phdr(&ctx, error{OutOfMemory}, DlIterContext.callback);

            for (extra_phdr_infos.items) |info| {
                try DlIterContext.callback(info, @sizeOf(std.posix.dl_phdr_info), &ctx);
            }
        }
        // Downgrade the lock back to shared if necessary.
        switch (lock) {
            .shared => {
                si.rwlock.unlock();
                si.rwlock.lockShared();
            },
            .exclusive => {},
        }
        // Scan the newly rebuilt module ranges.
        for (si.ranges.items) |*range| {
            if (address >= range.start and address < range.start + range.len) {
                return &si.modules.items[range.module_index];
            }
        }
        // Still nothing; unlock and error.
        switch (lock) {
            .shared => si.rwlock.unlockShared(),
            .exclusive => si.rwlock.unlock(),
        }

        std.log.err("No module found for address 0x{x}", .{address});

        return error.MissingDebugInfo;
    }
    const DlIterContext = struct {
        si: *SelfInfo,
        gpa: std.mem.Allocator,

        fn callback(info: *std.posix.dl_phdr_info, size: usize, context: *@This()) !void {
            _ = size;

            var build_id: ?[]const u8 = null;
            var gnu_eh_frame: ?[]const u8 = null;

            // Populate `build_id` and `gnu_eh_frame`
            for (info.phdr[0..info.phnum]) |phdr| {
                switch (phdr.type) {
                    std.elf.PT.NOTE => {
                        // Look for .note.gnu.build-id
                        const segment_ptr: [*]const u8 = @ptrFromInt(info.addr + phdr.vaddr);
                        var r: std.Io.Reader = .fixed(segment_ptr[0..phdr.memsz]);
                        const name_size = r.takeInt(u32, builtin.target.cpu.arch.endian()) catch continue;
                        const desc_size = r.takeInt(u32, builtin.target.cpu.arch.endian()) catch continue;
                        const note_type = r.takeInt(u32, builtin.target.cpu.arch.endian()) catch continue;
                        const name = r.take(name_size) catch continue;
                        if (note_type != std.elf.NT_GNU_BUILD_ID) continue;
                        if (!std.mem.eql(u8, name, "GNU\x00")) continue;
                        const desc = r.take(desc_size) catch continue;
                        build_id = desc;
                    },
                    std.elf.PT.GNU_EH_FRAME => {
                        const segment_ptr: [*]const u8 = @ptrFromInt(info.addr + phdr.vaddr);
                        gnu_eh_frame = segment_ptr[0..phdr.memsz];
                    },
                    else => {},
                }
            }

            const gpa = context.gpa;
            const si = context.si;

            const module_index = si.modules.items.len;
            try si.modules.append(gpa, .{
                .load_offset = info.addr,
                // Android libc uses NULL instead of "" to mark the main program
                .name = std.mem.sliceTo(info.name, 0) orelse "",
                .build_id = build_id,
                .gnu_eh_frame = gnu_eh_frame,
                .unwind = null,
                .loaded_elf = null,
            });

            for (info.phdr[0..info.phnum]) |phdr| {
                if (phdr.type != std.elf.PT.LOAD) continue;
                try context.si.ranges.append(gpa, .{
                    // Overflowing addition handles VSDOs having p_vaddr = 0xffffffffff700000
                    .start = info.addr +% phdr.vaddr,
                    .len = phdr.memsz,
                    .module_index = module_index,
                });
            }
        }
    };

    const SelfInfo = @This();
};

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
};

const Reloc = struct {
    type: std.elf.R_X86_64,
    is_relr: bool,
    sym_idx: usize,
    offset: usize,
    addend: isize,
};

const RelocList = std.ArrayList(Reloc);

var ifunc_resolved_addrs: std.AutoArrayHashMapUnmanaged(usize, usize) = .empty;
var irel_resolved_targets: std.AutoArrayHashMapUnmanaged(usize, usize) = .empty;

const DynObject = struct {
    name_is_key: bool,
    name: []const u8,
    path: []const u8,
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
    loaded_at: ?usize,
    loaded_size: usize,

    fn init(key: []const u8) DynObject {
        return .{
            .name_is_key = true,
            .name = key,
            .path = key,
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
            .loaded_at = null,
            .loaded_size = 0,
        };
    }
};

const DynObjectList = std.StringArrayHashMapUnmanaged(DynObject);

const Symbol = struct {
    addr: usize,
};

pub const DynamicLibrary = struct {
    index: usize,

    pub fn getSymbol(lib: DynamicLibrary, sym_name: []const u8) !Symbol {
        const dyn_obj = &dyn_objects.values()[lib.index];
        const sym = try getResolvedSymbolByName(dyn_obj, sym_name);
        return .{
            .addr = sym.address,
        };
    }

    // pub fn unload(lib: DynamicLibrary, ) void {
    //     const dyn_obj = &dyn_objects.values()[lib.index];
    //     unloadDso(dyn_obj, allocator);
    // }
};

var dyn_objects: DynObjectList = .empty;
var dyn_objects_sorted_indices: std.ArrayList(usize) = .empty;

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

var initialized: bool = false;
var allocator: std.mem.Allocator = undefined;

const InitOptions = struct {
    allocator: std.mem.Allocator,
    log_level: Logger.Level = .warn,
};

// TODO thread safety
pub fn init(options: InitOptions) !void {
    if (initialized) {
        return error.AlreadyInitialized;
    }

    allocator = options.allocator;
    Logger.level = options.log_level;

    // TODO
    // - pre restructure TLS
    // - assert linux x86_64
    // - assert statically linked
    // - assert only one thread

    initialized = true;
}

// TODO thread safety
pub fn deinit() void {
    for (dyn_objects.values()) |*dyn_object| {
        for (dyn_object.syms_array.items) |*sym| {
            allocator.free(sym.name);
            allocator.free(sym.version);
        }
        dyn_object.syms_array.deinit(allocator);

        for (dyn_object.syms.values()) |*v| {
            v.deinit(allocator);
        }
        dyn_object.syms.deinit(allocator);

        dyn_object.relocs.deinit(allocator);
        dyn_object.dependencies.deinit(allocator);
        dyn_object.deps_breadth_first.deinit(allocator);
        dyn_object.segments.deinit(allocator);

        if (!dyn_object.name_is_key) {
            allocator.free(dyn_object.name);
            allocator.free(dyn_object.path);
        }
    }

    for (dyn_objects.keys()) |k| {
        allocator.free(k);
    }

    dyn_objects.clearAndFree(allocator);
    dyn_objects_sorted_indices.deinit(allocator);

    ifunc_resolved_addrs.clearAndFree(allocator);
    irel_resolved_targets.clearAndFree(allocator);

    const current_tls_area_desc = std.os.linux.tls.area_desc;
    if (current_tls_area_desc.gdt_entry_number != @as(usize, @bitCast(@as(isize, -1)))) {
        allocator.free(current_tls_area_desc.block.init);
    }

    for (extra_bytes.items) |e| {
        allocator.free(e);
    }
    extra_bytes.deinit(allocator);

    if (last_dl_error) |dle| {
        allocator.free(dle);
    }

    CustomSelfInfo.clearExtraElfs(allocator);

    // TODO
    // - unmap unnecessary maps
    // - call fini / fini_array
}

fn logSummary() void {
    if (Logger.level != .debug) {
        return;
    }

    var buf: [16]u8 = undefined;

    for (dyn_objects.values()) |*dyn_object| {
        if (dyn_object.loaded) {
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
            if (@intFromEnum(sym.type) <= 6) {
                Logger.debug("    type: {s}", .{@tagName(sym.type)});
            } else {
                Logger.debug("    type: {d}", .{@intFromEnum(sym.type)});
            }
            if (@intFromEnum(sym.bind) <= 2) {
                Logger.debug("    bind: {s}", .{@tagName(sym.bind)});
            } else {
                Logger.debug("    bind: {d}", .{@intFromEnum(sym.bind)});
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
// TODO handle errors gracefully
pub fn load(f_path: []const u8) !DynamicLibrary {
    if (!initialized) {
        return error.Unitialized;
    }

    // TODO
    // - open flags
    // - rpath
    // - LD_* env vars

    const lib = try loadDepTree(f_path);

    logSummary();

    for (dyn_objects_sorted_indices.items) |idx| {
        const dyn_obj = &dyn_objects.values()[idx];

        if (dyn_obj.loaded) {
            continue;
        }

        computeTcbOffset(dyn_obj);
        try processRelocations(dyn_obj);
        try mapTlsBlock(dyn_obj);
        _dl_debug_state();
        try processIRelativeRelocations(dyn_obj);
    }

    for (dyn_objects_sorted_indices.items) |idx| {
        const dyn_obj = &dyn_objects.values()[idx];

        if (dyn_obj.loaded) {
            continue;
        }

        try updateSegmentsPermissions(dyn_obj);
        _dl_debug_state();

        dyn_obj.loaded = true;

        const dl_phdr_info = try allocator.create(std.posix.dl_phdr_info);

        dl_phdr_info.* = .{
            .addr = dyn_obj.loaded_at.?,
            .name = @ptrCast(dyn_obj.path),
            .phdr = @ptrFromInt(dyn_obj.loaded_at.? + dyn_obj.eh.e_phoff),
            .phnum = dyn_obj.eh.e_phnum,
        };

        Logger.debug("unwinding: registering {s} at 0x{x}", .{ dyn_obj.name, dyn_obj.loaded_at.? });

        try CustomSelfInfo.addExtraElf(allocator, dl_phdr_info);

        try callInitFunctions(dyn_obj);
    }

    for (dyn_objects.values()) |*dyn_obj| {
        if (dyn_obj.loaded) {
            continue;
        }
    }

    return lib;
}

// TODO inefficient strategy
fn loadDepTree(o_path: []const u8) !DynamicLibrary {
    Logger.debug("dep tree: checking {s}", .{o_path});

    const lib_idx = try loadDso(o_path);
    if (dyn_objects.values()[lib_idx].mapped_at != 0) {
        return .{
            .index = lib_idx,
        };
    }

    var has_unloaded = true;
    while (has_unloaded) {
        has_unloaded = false;

        const do_count = dyn_objects.count();

        for (0..do_count) |dyn_object_idx| {
            const dyn_object_name = dyn_objects.values()[dyn_object_idx].name;

            {
                const dyn_object = &dyn_objects.values()[dyn_object_idx];

                Logger.debug("dep tree: {d}: checking {s}", .{ dyn_object_idx, dyn_object.name });

                if (dyn_object.mapped_at != 0) {
                    Logger.debug("dep tree: {s} is mapped", .{dyn_object.name});
                    continue;
                }
            }

            has_unloaded = true;

            const idx = try loadDso(if (dyn_object_idx == lib_idx) o_path else dyn_object_name);
            if (dyn_objects.values()[idx].mapped_at != 0) {
                Logger.debug("dep tree: {s} has been mapped", .{dyn_object_name});
            }
        }
    }

    try logDepTree(&dyn_objects.values()[lib_idx]);

    return .{
        .index = lib_idx,
    };
}

// TODO mimic path resolution of linux-ld better
fn resolvePath(r_path: []const u8) ![]const u8 {
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

    // TODO max path len
    var buf: [2048]u8 = @splat(0);

    var path: ?[]const u8 = null;

    for (lib_dirs) |dir| {
        const a_path = try std.fmt.bufPrint(&buf, "{s}/{s}", .{
            dir,
            r_path,
        });

        std.fs.accessAbsolute(a_path, .{ .read = true }) catch continue;

        path = try std.fmt.allocPrint(allocator, "{s}", .{a_path});

        Logger.debug("found {s}: {s}", .{ r_path, path.? });

        break;
    }

    if (path == null) {
        Logger.err("cannot find library {s}", .{r_path});
    }

    return path orelse error.LibraryNotFound;
}

fn loadDso(o_path: []const u8) !usize {
    var scratch_buf: [1024]u8 = undefined;

    const path: []const u8 = if (std.mem.findScalar(u8, o_path, '/') != null) try allocator.dupe(u8, o_path) else try resolvePath(o_path);
    defer allocator.free(path);

    Logger.debug("loading: {s} [{s}]", .{ o_path, path });

    const dyn_object_name = try allocator.dupe(u8, std.fs.path.basename(path));
    errdefer allocator.free(dyn_object_name);

    if (std.mem.find(u8, dyn_object_name, "libc.so") != null) {
        for (dyn_objects.values()) |*do| {
            if (do.loaded and std.mem.find(u8, do.name, "libc.so") != null and !std.mem.eql(u8, do.path, path)) {
                return error.MultipleLibcs;
            }
        }
    }

    const f = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    const stat = try f.stat();
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;

    const file_bytes = try std.posix.mmap(
        null,
        std.mem.alignForward(usize, size, std.heap.pageSize()),
        std.posix.PROT.READ,
        .{ .TYPE = .PRIVATE },
        f.handle,
        0,
    );
    errdefer std.posix.munmap(file_bytes);

    const file_addr = @intFromPtr(file_bytes.ptr);

    if (!dyn_objects.contains(dyn_object_name)) {
        const key = try std.fmt.allocPrint(allocator, "{s}", .{dyn_object_name});
        try dyn_objects.putNoClobber(allocator, key, .init(key));
    } else if (dyn_objects.get(dyn_object_name).?.loaded) {
        defer allocator.free(dyn_object_name);
        return dyn_objects.getIndex(dyn_object_name).?;
    }

    const eh: *std.elf.Elf64_Ehdr = @ptrCast(file_bytes);
    if (!std.mem.eql(u8, eh.e_ident[0..4], std.elf.MAGIC)) return error.NotAnElfFile;

    Logger.debug("elf type: {s}", .{@tagName(eh.e_type)});

    var i: usize = 0;

    Logger.debug("sections headers offset: 0x{x}", .{eh.e_shoff});
    Logger.debug("sections headers string table index: {d}", .{eh.e_shstrndx});

    const sh_section_strtbl_addr = file_addr + eh.e_shoff + (eh.e_shstrndx * eh.e_shentsize);
    const sh_strtbl: *std.elf.Shdr = @ptrFromInt(sh_section_strtbl_addr);
    const sh_strtab_addr: usize = file_addr + sh_strtbl.sh_offset;

    var dyn_strtab_addr: usize = undefined;
    var versym_tab_addr: ?usize = null;
    var verdef_tab_addr: usize = undefined;
    var verneed_tab_addr: usize = undefined;

    var dyn_symtab_addr: usize = undefined;
    var dyn_symtab_size: usize = undefined;

    var segments: LoadSegmentList = .empty;
    var dependencies: std.ArrayList(usize) = .empty;
    var relocs: RelocList = .empty;
    errdefer {
        relocs.deinit(allocator);
        dependencies.deinit(allocator);
        segments.deinit(allocator);
    }

    Logger.debug("sections headers:", .{});

    var sh_addr: usize = file_addr + eh.e_shoff;

    i = 0;
    while (i < eh.e_shnum) : ({
        i += 1;
        sh_addr += eh.e_shentsize;
    }) {
        const sh: *std.elf.Elf64.Shdr = @ptrFromInt(sh_addr);
        const name: [*:0]const u8 = @ptrFromInt(sh_strtab_addr + sh.name);
        Logger.debug("  - {d}:", .{i});
        Logger.debug("    name: {s}", .{name});
        Logger.debug("    link: {d}", .{sh.link});
        Logger.debug("    type: 0x{x}", .{sh.type});
        Logger.debug("    flags: {b}", .{@as(std.elf.Word, @bitCast(sh.flags.shf))});
        Logger.debug("    offset: 0x{x}", .{sh.offset});
        Logger.debug("    size: 0x{x}", .{sh.size});

        if (sh.type == .STRTAB) {
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

            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".dynstr")) {
                dyn_strtab_addr = file_addr + sh.offset;
            } else if (!std.mem.eql(u8, std.mem.sliceTo(name, 0), ".shstrtab")) {
                Logger.debug("    == TODO: STRTAB: {s}", .{std.mem.sliceTo(name, 0)});
            }
        } else if (sh.type == .DYNSYM) {
            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".dynsym")) {
                dyn_symtab_addr = file_addr + sh.offset;
                dyn_symtab_size = sh.size;
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
                    Logger.debug("    == TODO: section type {s}: {s}", .{ if (@intFromEnum(t) <= 19) @tagName(t) else try std.fmt.bufPrint(&scratch_buf, "0x{x}", .{t}), name });
                },
            }
        }
    }

    var ph_addr: usize = file_addr + eh.e_phoff;
    var dyn_addr: usize = undefined;

    i = 0;
    while (i < eh.e_phnum) : ({
        i += 1;
        ph_addr += eh.e_phentsize;
    }) {
        const ph: *std.elf.Elf64.Phdr = @ptrFromInt(ph_addr);

        dyn_addr = file_addr + ph.offset;
        const dyns: [*]std.elf.Dyn = @ptrFromInt(dyn_addr);

        var libName: [*:0]u8 = undefined;

        if (ph.type == .DYNAMIC) {
            var has_unloaded_deps = false;
            var j: usize = 0;
            while (dyns[j].d_tag != 0) : (j += 1) {
                if (dyns[j].d_tag == std.elf.DT_NEEDED) {
                    libName = @ptrFromInt(dyn_strtab_addr + dyns[j].d_val);

                    Logger.debug("dep tree: found dependency: {s} => {s}", .{ dyn_object_name, libName });

                    const libNameLen = std.mem.len(libName);

                    if (!dyn_objects.contains(libName[0..libNameLen])) {
                        const key = try std.fmt.allocPrint(allocator, "{s}", .{libName[0..libNameLen]});
                        try dyn_objects.putNoClobber(allocator, key, .init(key));
                        Logger.debug("dep tree: {s} loading deferred", .{dyn_object_name});
                        has_unloaded_deps = true;
                    } else {
                        const dep = dyn_objects.get(libName[0..libNameLen]).?;
                        if (dep.mapped_at != 0) {
                            Logger.debug("dep tree: registering dependency: {s} => {s}", .{ dyn_object_name, libName });
                            try dependencies.append(allocator, dyn_objects.getIndex(libName[0..libNameLen]).?);
                        } else {
                            Logger.debug("dep tree: {s} loading deferred", .{dyn_object_name});
                            has_unloaded_deps = true;
                        }
                    }
                }
            }

            if (has_unloaded_deps) {
                dependencies.deinit(allocator);
                defer allocator.free(dyn_object_name);
                return dyn_objects.getIndex(dyn_object_name).?;
            }

            break;
        }
    }

    var syms_array: std.ArrayList(DynSym) = .empty;
    var syms: DynSymList = .empty;
    errdefer {
        for (syms_array.items) |*sym| {
            allocator.free(sym.name);
            allocator.free(sym.version);
        }
        syms_array.deinit(allocator);

        for (syms.values()) |*v| {
            v.deinit(allocator);
        }
        syms.deinit(allocator);
    }

    if (versym_tab_addr) |vst_addr| {
        Logger.debug("versym table addr: 0x{x}", .{vst_addr});
    }

    const versym_table: ?[*]std.elf.Half = if (versym_tab_addr) |vst| @ptrFromInt(vst) else null;

    Logger.debug("dynamic string table addr: 0x{x}", .{dyn_strtab_addr});
    Logger.debug("dynamic sym table addr: 0x{x}", .{dyn_symtab_addr});

    Logger.debug("{s}: symbols: ", .{dyn_object_name});

    for (0..dyn_symtab_size / @sizeOf(std.elf.Sym)) |j| {
        const sym: *std.elf.Elf64.Sym = @ptrFromInt(dyn_symtab_addr + j * @sizeOf(std.elf.Elf64.Sym));

        // TODO max len of sym name / aux name ?
        var buf_str: [2048]u8 = @splat(0);
        const strs: [*]u8 = @ptrFromInt(dyn_strtab_addr);
        var k: usize = 0;
        while (strs[k + sym.name] != 0) : (k += 1) {
            buf_str[k] = strs[k + sym.name];
        }

        const name = try std.fmt.allocPrint(allocator, "{s}", .{buf_str[0..k]});

        const hidden = sym.other.visibility != .DEFAULT;

        var version: []const u8 = "";
        var ver_sym: ?std.elf.Versym = null;
        var ver_idx: ?u15 = null;

        if (versym_table != null) {
            ver_sym = @bitCast(versym_table.?[j]);
            ver_idx = ver_sym.?.VERSION;

            if (ver_sym == std.elf.Versym.GLOBAL) {
                version = try allocator.dupe(u8, "GLOBAL");
            } else if (ver_sym == std.elf.Versym.LOCAL) {
                version = try allocator.dupe(u8, "LOCAL");
            } else {
                if (sym.shndx == std.elf.SHN_UNDEF) {
                    const ver_table_addr = verneed_tab_addr;

                    var ver_table_cursor = ver_table_addr;
                    var curr_def: *std.elf.Elf64_Verneed = @ptrFromInt(ver_table_cursor);

                    outer: while (true) {
                        var aux: *std.elf.Vernaux = @ptrFromInt(ver_table_cursor + curr_def.vn_aux);
                        while (true) {
                            if (aux.other == ver_idx.?) {
                                k = 0;
                                while (strs[k + aux.name] != 0) : (k += 1) {
                                    buf_str[k] = strs[k + aux.name];
                                }

                                version = try std.fmt.allocPrint(allocator, "{s}", .{buf_str[0..k]});
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
                        if (curr_def.ndx == @as(std.elf.VER_NDX, @enumFromInt(ver_idx.?))) {
                            const aux: *std.elf.Verdaux = @ptrFromInt(ver_table_cursor + curr_def.aux);

                            k = 0;
                            while (strs[k + aux.name] != 0) : (k += 1) {
                                buf_str[k] = strs[k + aux.name];
                            }

                            version = try std.fmt.allocPrint(allocator, "{s}", .{buf_str[0..k]});
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

        if (Logger.level == .debug) {
            Logger.debug("{s}  - {d}:", .{ dyn_object_name, j });
            Logger.debug("{s}    name: {s}", .{ dyn_object_name, name });
            Logger.debug("{s}    ver idx: {?d}", .{ dyn_object_name, if (ver_sym) |vs| vs.VERSION else null });
            Logger.debug("{s}    version: {s}", .{ dyn_object_name, version });
            Logger.debug("{s}    hidden: {}", .{ dyn_object_name, hidden });
            if (@intFromEnum(sym.info.type) <= 6) {
                Logger.debug("{s}    type: {s}", .{ dyn_object_name, @tagName(sym.info.type) });
            } else {
                Logger.debug("{s}    type: {d}", .{ dyn_object_name, @intFromEnum(sym.info.type) });
            }
            if (@intFromEnum(sym.info.bind) <= 2) {
                Logger.debug("{s}    bind: {s}", .{ dyn_object_name, @tagName(sym.info.bind) });
            } else {
                Logger.debug("{s}    bind: {d}", .{ dyn_object_name, @intFromEnum(sym.info.bind) });
            }
            Logger.debug("{s}    value: 0x{x}", .{ dyn_object_name, sym.value });
            Logger.debug("{s}    sh idx: 0x{x}", .{ dyn_object_name, sym.shndx });
            Logger.debug("{s}    size: 0x{x}", .{ dyn_object_name, sym.size });
        }

        const s: DynSym = .{
            .name = name,
            .version = version,
            .hidden = hidden,
            .offset = j * @sizeOf(std.elf.Sym),
            .type = sym.info.type,
            .bind = sym.info.bind,
            .shidx = sym.shndx,
            .value = sym.value,
            .size = sym.size,
        };

        const ent = try syms.getOrPut(allocator, s.name);
        if (!ent.found_existing) {
            ent.value_ptr.* = .empty;
        }

        try ent.value_ptr.append(allocator, syms_array.items.len);
        try syms_array.append(allocator, s);
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

        Logger.debug("  - {d}", .{i});
        Logger.debug("    type: 0x{x}", .{ph.type});
        Logger.debug("    flags: {b}", .{@as(std.elf.Word, @bitCast(ph.flags))});
        Logger.debug("    offset: 0x{x}", .{ph.offset});
        Logger.debug("    v_addr: 0x{x}", .{ph.vaddr});
        Logger.debug("    fsize: 0x{x}", .{ph.filesz});
        Logger.debug("    msize: 0x{x}", .{ph.memsz});

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

            try segments.put(allocator, segment.mem_offset, segment);
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

            try segments.put(allocator, segment.mem_offset, segment);
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
            dyn_addr = file_addr + ph.offset;
            const dyns: [*]std.elf.Dyn = @ptrFromInt(dyn_addr);

            var runpath: [*:0]u8 = undefined;

            var rela_reloc_tbl_addr: usize = 0;
            var rela_reloc_tbl_size: usize = 0;
            var rela_reloc_tbl_entry_size: usize = 0;
            var rela_reloc_nb_entry: usize = 0;

            var relr_reloc_tbl_addr: usize = 0;
            var relr_reloc_tbl_size: usize = 0;
            var relr_reloc_tbl_entry_size: usize = 0;

            var plt_reloc_type: usize = 0;
            var plt_reloc_tbl_size: usize = 0;
            var plt_reloc_tbl_addr: usize = 0;

            var plt_got_addr: usize = 0;

            var j: usize = 0;
            while (dyns[j].d_tag != 0) : (j += 1) {
                Logger.debug("      DT type 0x{x}: 0x{x}", .{ dyns[j].d_tag, dyns[j].d_val });

                if (dyns[j].d_tag == std.elf.DT_RUNPATH) {
                    runpath = @ptrFromInt(dyn_strtab_addr + dyns[j].d_val);
                    Logger.debug("        => lib rpath: {s}", .{runpath});
                } else if (dyns[j].d_tag == std.elf.DT_RELA) {
                    rela_reloc_tbl_addr = file_addr + dyns[j].d_val;
                    Logger.debug("        => rela reloc table addr: 0x{x}", .{rela_reloc_tbl_addr});
                } else if (dyns[j].d_tag == std.elf.DT_RELASZ) {
                    rela_reloc_tbl_size = dyns[j].d_val;
                    Logger.debug("        => rela reloc table size: 0x{x}", .{rela_reloc_tbl_size});
                } else if (dyns[j].d_tag == std.elf.DT_RELAENT) {
                    rela_reloc_tbl_entry_size = dyns[j].d_val;
                    Logger.debug("        => rela reloc table entry size: 0x{x}", .{rela_reloc_tbl_entry_size});
                } else if (dyns[j].d_tag == std.elf.DT_RELACOUNT) {
                    rela_reloc_nb_entry = dyns[j].d_val;
                    Logger.debug("        => rela reloc nb entry: {d}", .{rela_reloc_nb_entry});
                } else if (dyns[j].d_tag == std.elf.DT_RELR) {
                    relr_reloc_tbl_addr = file_addr + dyns[j].d_val;
                    Logger.debug("        => relr reloc table addr: 0x{x}", .{relr_reloc_tbl_addr});
                } else if (dyns[j].d_tag == std.elf.DT_RELRSZ) {
                    relr_reloc_tbl_size = dyns[j].d_val;
                    Logger.debug("        => relr reloc table size: 0x{x}", .{relr_reloc_tbl_size});
                } else if (dyns[j].d_tag == std.elf.DT_RELRENT) {
                    relr_reloc_tbl_entry_size = dyns[j].d_val;
                    Logger.debug("        => relr reloc table entry size: 0x{x}", .{relr_reloc_tbl_entry_size});
                } else if (dyns[j].d_tag == std.elf.DT_PLTREL) {
                    plt_reloc_type = dyns[j].d_val;
                    Logger.debug("        => plt reloc type: 0x{x}", .{plt_reloc_type});
                } else if (dyns[j].d_tag == std.elf.DT_PLTRELSZ) {
                    plt_reloc_tbl_size = dyns[j].d_val;
                    Logger.debug("        => plt reloc table size: 0x{x}", .{plt_reloc_tbl_size});
                } else if (dyns[j].d_tag == std.elf.DT_JMPREL) {
                    plt_reloc_tbl_addr = file_addr + dyns[j].d_val;
                    Logger.debug("        => plt reloc table addr: 0x{x}", .{plt_reloc_tbl_addr});
                } else if (dyns[j].d_tag == std.elf.DT_PLTGOT) {
                    plt_got_addr = file_addr + dyns[j].d_val;
                    Logger.debug("        => plt got addr: 0x{x}", .{plt_got_addr});
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

            // TODO handle old Elf64_Rel relocs

            if (rela_reloc_tbl_addr > 0) {
                const nb_entries = rela_reloc_tbl_size / rela_reloc_tbl_entry_size;
                Logger.debug("        => nb rela relocs: {d}", .{nb_entries});
                for (0..nb_entries) |r| {
                    const rela_reloc_addr = rela_reloc_tbl_addr + r * rela_reloc_tbl_entry_size;
                    const rela_reloc: *std.elf.Elf64_Rela = @ptrFromInt(rela_reloc_addr);
                    // logger.debug("           0x{x}: {d}", .{ rela_reloc_addr - file_addr, rela_reloc.r_type() });
                    Logger.debug("          - [{d}] rela reloc: {s}, sym: 0x{x}, offset: 0x{x}, addend: 0x{x}", .{
                        r,
                        @tagName(@as(std.elf.R_X86_64, @enumFromInt(rela_reloc.r_type()))),
                        rela_reloc.r_sym(),
                        rela_reloc.r_offset,
                        rela_reloc.r_addend,
                    });

                    try relocs.append(allocator, .{
                        .type = @as(std.elf.R_X86_64, @enumFromInt(rela_reloc.r_type())),
                        .is_relr = false,
                        .sym_idx = rela_reloc.r_sym(),
                        .offset = rela_reloc.r_offset,
                        .addend = rela_reloc.r_addend,
                    });

                    if (@as(std.elf.R_X86_64, @enumFromInt(rela_reloc.r_type())) == .RELATIVE) {
                        std.debug.assert(rela_reloc.r_addend != 0);
                    }
                }
            }

            if (plt_reloc_tbl_addr > 0) {
                // TODO entry size might be rel_reloc_tabl_entry_size
                const entry_size = rela_reloc_tbl_entry_size;

                const nb_entries = plt_reloc_tbl_size / entry_size;
                Logger.debug("        => nb plt relocs: {d}", .{nb_entries});
                for (0..nb_entries) |r| {
                    const plt_reloc_addr = plt_reloc_tbl_addr + r * entry_size;

                    // TODO type might be std.elf.Elf64_Rel
                    const plt_reloc: *std.elf.Elf64_Rela = @ptrFromInt(plt_reloc_addr);
                    // logger.debug("           0x{x}: {d}", .{ plt_reloc_addr - file_addr, plt_reloc.r_type() });
                    Logger.debug("          - [{d}] plt reloc: {s}, sym: 0x{x}, offset: 0x{x}, addend: 0x{x}", .{
                        r,
                        @tagName(@as(std.elf.R_X86_64, @enumFromInt(plt_reloc.r_type()))),
                        plt_reloc.r_sym(),
                        plt_reloc.r_offset,
                        plt_reloc.r_addend,
                    });

                    try relocs.append(allocator, .{
                        .type = @as(std.elf.R_X86_64, @enumFromInt(plt_reloc.r_type())),
                        .sym_idx = plt_reloc.r_sym(),
                        .is_relr = false,
                        .offset = plt_reloc.r_offset,
                        .addend = plt_reloc.r_addend,
                    });

                    if (@as(std.elf.R_X86_64, @enumFromInt(plt_reloc.r_type())) == .RELATIVE) {
                        std.debug.assert(plt_reloc.r_addend != 0);
                    }
                }
            }

            if (relr_reloc_tbl_addr > 0) {
                const nb_entries = relr_reloc_tbl_size / relr_reloc_tbl_entry_size;
                Logger.debug("        => nb relr relocs: {d}", .{nb_entries});

                var next: std.elf.Elf64_Addr = undefined;

                for (0..nb_entries) |r| {
                    const relr_reloc_addr = relr_reloc_tbl_addr + r * relr_reloc_tbl_entry_size;
                    const relr_reloc: *std.elf.Elf64_Relr = @ptrFromInt(relr_reloc_addr);

                    if ((relr_reloc.* & 1) == 0) {
                        Logger.debug("          - [{d}] relr reloc: {s}, sym: 0x{x}, offset: 0x{x}, addend: 0x{x}", .{
                            r,
                            "R_X86_64.RELATIVE",
                            0,
                            relr_reloc.*,
                            0,
                        });
                        try relocs.append(allocator, .{
                            .type = .RELATIVE,
                            .is_relr = true,
                            .sym_idx = 0,
                            .offset = relr_reloc.*,
                            .addend = 0,
                        });

                        next = relr_reloc.* + @sizeOf(std.elf.Elf64_Addr);
                    } else {
                        for (0..(8 * @sizeOf(std.elf.Elf64_Addr) - 1)) |sr| {
                            if (((relr_reloc.* >> @as(u6, @intCast(sr + 1))) & 1) != 0) {
                                Logger.debug("          - [{d} - {d}] relr reloc: {s}, sym: 0x{x}, offset: 0x{x}, addend: 0x{x}", .{
                                    r,
                                    sr,
                                    "R_X86_64.RELATIVE",
                                    0,
                                    next + sr * @sizeOf(std.elf.Elf64_Addr),
                                    0,
                                });
                                try relocs.append(allocator, .{
                                    .type = .RELATIVE,
                                    .is_relr = true,
                                    .sym_idx = 0,
                                    .offset = next + sr * @sizeOf(std.elf.Elf64_Addr),
                                    .addend = 0,
                                });
                            }
                        }

                        next += @sizeOf(std.elf.Elf64_Addr) * (8 * @sizeOf(std.elf.Elf64_Addr) - 1);
                    }
                }
            }
        } else {
            Logger.debug("    => TODO: PT type {s}", .{pht_blk: {
                if (@intFromEnum(ph.type) <= 8) {
                    break :pht_blk @tagName(ph.type);
                } else if (ph.type == std.elf.PT.GNU_STACK) {
                    break :pht_blk "GNU_STACK";
                }
                break :pht_blk try std.fmt.bufPrint(&scratch_buf, "0x{x}", .{@intFromEnum(ph.type)});
            }});
        }
    }

    const do_entry = try dyn_objects.getOrPut(allocator, dyn_object_name);
    defer if (do_entry.found_existing) {
        allocator.free(dyn_object_name);
    };

    do_entry.value_ptr.* = .{
        .name_is_key = false,
        .name = try allocator.dupe(u8, dyn_object_name),
        .path = try allocator.dupe(u8, path),
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
        .tls_offset = 0,
        .eh = eh,
        .eh_init_file_offset = eh_init_file_offset,
        .eh_init_file_size = eh_init_file_size,
        .eh_init_mem_offset = eh_init_mem_offset,
        .eh_init_mem_size = eh_init_mem_size,
        .eh_align = eh_align,
        .dyn_section_offset = dyn_addr,
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
        .loaded_at = null,
        .loaded_size = 0,
    };

    const dyn_object = dyn_objects.getEntry(dyn_object_name).?.value_ptr;
    try dyn_objects_sorted_indices.append(allocator, dyn_objects.getIndex(dyn_object_name).?);

    try mapSegments(dyn_object, file_bytes);

    try collectDepsBreadthFirst(dyn_object);

    Logger.info("{s} loaded => {s}", .{ dyn_object_name, dyn_object.path });

    return dyn_objects.getIndex(dyn_object_name).?;
}

fn collectDepsBreadthFirst(dyn_object: *DynObject) !void {
    var queue: std.ArrayList(usize) = .empty;
    defer queue.deinit(allocator);

    try queue.append(allocator, dyn_objects.getIndex(dyn_object.name).?);

    while (queue.items.len > 0) {
        const dep_idx = queue.orderedRemove(0);
        if (std.mem.findScalar(usize, dyn_object.deps_breadth_first.items, dep_idx)) |_| {} else try dyn_object.deps_breadth_first.append(allocator, dep_idx);
        const dep = &dyn_objects.values()[dep_idx];
        for (dep.dependencies.items) |sdep_idx| {
            if (std.mem.findScalar(usize, queue.items, sdep_idx)) |_| continue;
            try queue.append(allocator, sdep_idx);
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

var indent_buf: [64]u8 = @splat(' ');

fn logDepTree(dyn_object: *const DynObject) !void {
    if (Logger.level != .debug) {
        return;
    }

    var already_visited: std.ArrayList(usize) = .empty;
    defer already_visited.deinit(allocator);

    try logDepTreeInner(dyn_object, 0, &already_visited);
}

fn logDepTreeInner(dyn_object: *const DynObject, level: usize, already_visited: *std.ArrayList(usize)) !void {
    std.debug.assert(level < 32);

    Logger.debug("loaded dep tree:{s} - {s} => {s}", .{ indent_buf[0 .. 2 * level], dyn_object.name, dyn_object.path });

    if (std.mem.findScalar(usize, already_visited.items, dyn_objects.getIndex(dyn_object.name).?)) |_| {
        return;
    }

    try already_visited.append(allocator, dyn_objects.getIndex(dyn_object.name).?);

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

    var mem_end: usize = std.math.minInt(usize);

    for (dyn_object.segments.values()) |*segment| {
        std.debug.assert(segment.mem_align >= std.heap.pageSize() and segment.mem_align % std.heap.pageSize() == 0);
        const aligned_mem_end = std.mem.alignForward(usize, segment.mem_offset + segment.mem_size, segment.mem_align);
        mem_end = @max(mem_end, aligned_mem_end);
    }

    const total_mem_size = mem_end;

    Logger.debug("mapping segments: from file, library loaded size: 0x{x} (0x{x} to 0x{x})", .{ total_mem_size, 0, mem_end });

    const mapped_space = std.posix.mmap(
        null,
        total_mem_size,
        std.posix.PROT.NONE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    ) catch |err| {
        Logger.err("failed to allocate library space: {s}", .{@errorName(err)});
        return err;
    };

    const base_addr = @intFromPtr(mapped_space.ptr);

    dyn_object.loaded_at = base_addr;
    dyn_object.loaded_size = total_mem_size;

    Logger.debug("mapping segments: reserved 0x{x} bytes from 0x{x} to 0x{x}", .{ total_mem_size, base_addr, base_addr + total_mem_size });

    for (dyn_object.segments.values(), 0..) |*segment, s| {
        Logger.debug("  segment {d}: foff: 0x{x}, moff: 0x{x}, fsize: 0x{x}, msize: 0x{x}", .{ s, segment.file_offset, segment.mem_offset, segment.file_size, segment.mem_size });

        var prot: u32 = std.posix.PROT.NONE;
        if (segment.flags_first.read) prot |= std.posix.PROT.READ;
        if (segment.flags_first.write) prot |= std.posix.PROT.WRITE;
        if (segment.flags_first.exec) prot |= std.posix.PROT.EXEC;

        const aligned_ptr: [*]align(std.heap.pageSize()) u8 = @ptrFromInt(std.mem.alignBackward(usize, base_addr + segment.mem_offset, segment.mem_align));
        const aligned_end: usize = std.mem.alignForward(usize, base_addr + segment.mem_offset + segment.mem_size, segment.mem_align);
        const aligned_size = aligned_end - @intFromPtr(aligned_ptr);
        const aligned_file_offset = std.mem.alignBackward(usize, segment.file_offset, segment.mem_align);

        segment.loaded_at = base_addr + segment.mem_offset;
        segment.mapped_from_file = true;

        Logger.debug("  segment {d}: mapping: foff: 0x{x}, aligned foff: 0x{x}, from 0x{x} to 0x{x}, size: 0x{x}", .{ s, segment.file_offset, aligned_file_offset, @as(usize, @intFromPtr(aligned_ptr)), aligned_end, aligned_size });
        Logger.debug("  segment {d}: data: from 0x{x} to 0x{x}, size: 0x{x}", .{ s, segment.loaded_at, segment.loaded_at + segment.mem_size, segment.mem_size });

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
            const zero_ptr: [*]align(std.heap.pageSize()) u8 = @ptrFromInt(zero_start);
            const zero_end: usize = std.mem.alignForward(usize, segment.loaded_at + segment.mem_size, std.heap.pageSize());
            const zero_size = zero_end - zero_start;

            std.debug.assert(zero_end <= base_addr + total_mem_size);

            if (zero_start > segment.loaded_at + segment.file_size) {
                const zero_sub_size = zero_start - (segment.loaded_at + segment.file_size);
                Logger.debug("  segment {d}: memory: zeroing from 0x{x} to 0x{x}, size: 0x{x}", .{ s, segment.loaded_at + segment.file_size, zero_start, zero_sub_size });
                @memset(@as([*]u8, @ptrFromInt(segment.loaded_at))[segment.file_size..][0..zero_sub_size], 0);
            }

            if (zero_size > 0) {
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

    Logger.debug("successfully mapped {d} segments for {s} at base 0x{x}", .{ dyn_object.segments.count(), dyn_object.name, base_addr });
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

var initial_tls_init_file_size: usize = undefined;
var initial_tls_init_mem_size: usize = undefined;
var initial_tls_offset: usize = undefined;
var initial_tls_align: ?usize = null;
var initial_tls_init_block: []const u8 = undefined;

fn computeTcbOffset(dyn_object: *DynObject) void {
    Logger.debug("computing tcb offset of library {s}", .{dyn_object.name});

    const current_tls_area_desc = std.os.linux.tls.area_desc;

    var new_area_size: usize = 0;
    new_area_size += dyn_object.tls_init_mem_size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, dyn_object.tls_align) else new_area_size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, current_tls_area_desc.alignment) else new_area_size;
    new_area_size += current_tls_area_desc.block.size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, initial_tls_align orelse current_tls_area_desc.alignment) else new_area_size;
    const new_abi_tcb_offset = new_area_size;

    dyn_object.tls_offset = new_abi_tcb_offset;
}

var current_surplus_size: usize = 0x2000;

fn mapTlsBlock(dyn_object: *DynObject) !void {
    Logger.debug("mapping tls block of library {s}", .{dyn_object.name});

    const current_tls_area_desc = std.os.linux.tls.area_desc;

    var new_area_size: usize = 0;
    const new_block_offset: usize = 0;
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

    var old_tp: usize = undefined;
    const e_get_fs = std.os.linux.syscall2(.arch_prctl, std.os.linux.ARCH.GET_FS, @intFromPtr(&old_tp));
    std.debug.assert(e_get_fs == 0);

    const prev_area_addr = old_tp - (new_abi_tcb_offset - prev_block_offset);

    Logger.debug("tls: old_tp: 0x{x}, prev area: 0x{x}", .{ old_tp, prev_area_addr });

    var new_area: ?[]u8 = null;
    var area_was_extended = false;

    if (current_tls_area_desc.gdt_entry_number == @as(usize, @bitCast(@as(isize, -1)))) {
        Logger.debug("tls: mapping new area (first time): size: 0x{x} (surplus) + 0x{x} (new_area_size) + 0x{x} (size of pthread struct)", .{ current_surplus_size, new_area_size, sizeof_pthread });
        const space = std.posix.mmap(null, current_surplus_size + new_area_size + sizeof_pthread, std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0) catch |err| {
            Logger.err("failed to allocate tls space: {s}", .{@errorName(err)});
            return err;
        };
        Logger.debug("tls: setting new area start at 0x{x} (0x{x})", .{ current_surplus_size, @intFromPtr(space.ptr) + current_surplus_size });
        new_area = space[current_surplus_size..];
    } else if (new_area_size > current_tls_area_desc.size and new_area_size <= current_tls_area_desc.size + current_surplus_size) {
        Logger.debug("tls: extending old area: size: 0x{x} (new_area_size) = 0x{x} (surplus) + 0x{x} (current_area_siz)", .{ new_area_size, new_area_size - current_tls_area_desc.size, current_tls_area_desc.size });
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

        // TODO the goal is to avoid unstable thread pointer
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
            // TODO we should not do that
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

    // TODO this allocation could easily be avoided

    Logger.debug("tls: allocating new init block: size: 0x{x}", .{new_abi_tcb_offset});
    const new_initial_block = try allocator.alloc(u8, new_abi_tcb_offset);

    if (initial_tls_init_file_size != initial_tls_init_mem_size) {
        Logger.debug("tls: copying initial tdata: from 0x{x} to 0x{x} (size: 0x{x})", .{
            new_abi_tcb_offset - initial_tls_offset,
            new_abi_tcb_offset - initial_tls_offset + initial_tls_init_file_size,
            initial_tls_init_file_size,
        });
        @memcpy(new_initial_block[new_abi_tcb_offset - initial_tls_offset ..][0..initial_tls_init_file_size], initial_tls_init_block);
        Logger.debug("tls: zeroing initial tbss: from 0x{x} to 0x{x} (size: 0x{x})", .{
            new_abi_tcb_offset - initial_tls_offset + initial_tls_init_file_size,
            new_abi_tcb_offset - initial_tls_offset + initial_tls_init_mem_size,
            initial_tls_init_mem_size - initial_tls_init_file_size,
        });
        @memset(new_initial_block[new_abi_tcb_offset - initial_tls_offset + initial_tls_init_file_size ..][0 .. initial_tls_init_mem_size - initial_tls_init_file_size], 0);
    }

    for (dyn_objects.values()) |*do| {
        if (do.tls_mapped_at != 0 and do.tls_init_file_size != do.tls_init_mem_size) {
            Logger.debug("tls: copying {s} tdata: from 0x{x} to 0x{x} (size: 0x{x})", .{
                do.name,
                new_abi_tcb_offset - do.tls_offset,
                new_abi_tcb_offset - do.tls_offset + do.tls_init_file_size,
                do.tls_init_file_size,
            });
            @memcpy(new_initial_block[new_abi_tcb_offset - do.tls_offset ..][0..do.tls_init_file_size], @as([*]u8, @ptrFromInt(try vAddressToLoadedAddress(do, do.tls_init_mem_offset, false))));
            Logger.debug("tls: zeroing {s} tbss: from 0x{x} to 0x{x} (size: 0x{x})", .{
                do.name,
                new_abi_tcb_offset - do.tls_offset + do.tls_init_file_size,
                new_abi_tcb_offset - do.tls_offset + do.tls_init_mem_size,
                do.tls_init_mem_size - do.tls_init_file_size,
            });
            @memset(new_initial_block[new_abi_tcb_offset - do.tls_offset + initial_tls_init_file_size ..][0 .. do.tls_init_mem_size - do.tls_init_file_size], 0);
        }
    }

    if (dyn_object.tls_init_file_size != dyn_object.tls_init_mem_size) {
        Logger.debug("tls: copying {s} tdata: from 0x{x} to 0x{x} (size: 0x{x})", .{
            dyn_object.name,
            0,
            dyn_object.tls_init_file_size,
            dyn_object.tls_init_file_size,
        });
        @memcpy(new_initial_block[0..dyn_object.tls_init_file_size], @as([*]u8, @ptrFromInt(try vAddressToLoadedAddress(dyn_object, dyn_object.tls_init_mem_offset, false))));
        Logger.debug("tls: zeroing {s} tbss: from 0x{x} to 0x{x} (size: 0x{x})", .{
            dyn_object.name,
            dyn_object.tls_init_file_size,
            dyn_object.tls_init_mem_size,
            dyn_object.tls_init_mem_size - dyn_object.tls_init_file_size,
        });
        @memset(new_initial_block[dyn_object.tls_init_file_size..dyn_object.tls_init_mem_size], 0);
    }

    const new_block_init = new_initial_block;
    const new_block_size = new_block_init.len;

    const new_align_factor = @max(dyn_object.tls_align, current_tls_area_desc.alignment);

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
    //                       | POTENTIAL PTHREAD STRUCT ====>
    //---------------------------------------------------------
    //| TLS Blocks | Zig TCB | ABI TCB | *DTV | *SELF | SPACE
    //-----------------------^---------------------------------
    //                       `-- The TP register points here.
    //
    // In this case, when main zig executable is relocating, it should take into account
    // the offset created by the Zig TCB struct.
    //
    const new_tls_area_desc: @TypeOf(current_tls_area_desc) = .{
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

    if (current_tls_area_desc.gdt_entry_number != @as(usize, @bitCast(@as(isize, -1)))) {
        allocator.free(current_tls_area_desc.block.init);
    }

    std.os.linux.tls.area_desc = new_tls_area_desc;

    if (new_area != null) {
        if (!area_was_extended) {
            // const new_tp = std.os.linux.tls.prepareArea(new_area);

            const new_tp = @intFromPtr(new_area.?.ptr) + new_abi_tcb_offset;

            // TODO unmap previous area

            const new_tcb: *AbiTcb = @ptrCast(@alignCast(new_area.?.ptr + new_tls_area_desc.abi_tcb.offset));
            new_tcb.self = @ptrFromInt(new_tp);

            // setting dtv.len to self because it happens to coincide with what is expected by pthread
            const new_dtv: *Dtv = @ptrCast(@alignCast(new_area.?.ptr + new_tls_area_desc.dtv.offset));
            new_dtv.tls_block = new_area.?.ptr;
            new_dtv.len = new_tp;

            Logger.debug("tls: tls space mapped, new TP: 0x{x}", .{new_tp});

            const e_set_fs = std.os.linux.syscall2(.arch_prctl, std.os.linux.ARCH.SET_FS, new_tp);
            std.debug.assert(e_set_fs == 0);

            const maybe_rtld_global_ro = resolveSymbolByName("_rtld_global_ro") catch null;

            if (maybe_rtld_global_ro) |rtld_global_ro| {
                Logger.debug("tls: rtld_global_ro: 0x{x}", .{rtld_global_ro.address});

                const seg_infos = try findDynObjectSegmentForLoadedAddr(rtld_global_ro.address);

                // TODO we should find a way to get those field offsets at runtime
                const dl_auxv: *volatile *anyopaque = @ptrFromInt(rtld_global_ro.address + 104);
                const dl_tls_static_size: *volatile usize = @ptrFromInt(rtld_global_ro.address + 704);
                const dl_tls_static_align: *volatile usize = @ptrFromInt(rtld_global_ro.address + 712);

                try unprotectSegment(seg_infos.dyn_object, seg_infos.segment_index);

                if (std.os.linux.elf_aux_maybe) |auxv| {
                    dl_auxv.* = auxv;
                }

                dl_tls_static_size.* = new_tls_area_desc.block.size;
                dl_tls_static_align.* = new_tls_area_desc.alignment;

                try reprotectSegment(seg_infos.dyn_object, seg_infos.segment_index);
            } else {
                Logger.info("tls: no rtld_global_ro symbol found", .{});
            }

            // TODO we should find a way to get this offset at runtime
            const tid = std.Thread.getCurrentId();
            Logger.debug("tls: setting thread id {d} for pthread at 0x{x}", .{ tid, new_tp + 720 });
            const tid_ptr: *volatile usize = @ptrFromInt(new_tp + 720);
            tid_ptr.* = tid;
        }

        dyn_object.tls_offset = new_abi_tcb_offset;
        Logger.debug("tls: tls offset: 0x{x}", .{new_abi_tcb_offset});

        dyn_object.tls_mapped_at = @as(usize, @intFromPtr(new_area.?.ptr)) - dyn_object.tls_offset;
    } else {
        Logger.debug("tls: {s}: no change to TLS area", .{dyn_object.name});
    }
}

// this function has a special callconv
fn tlsDescResolver() callconv(.naked) void {
    asm volatile ("ret");
}

const TlsDesc = extern struct {
    tls_desc_resolver: *const fn () callconv(.naked) void,
    tls_desc_resolver_arg: isize,
};

fn processRelocations(dyn_object: *DynObject) !void {
    Logger.debug("processing relocations for {s}", .{dyn_object.name});

    var reloc_count: usize = 0;

    for (dyn_object.relocs.items) |reloc| {
        const reloc_addr = try vAddressToLoadedAddress(dyn_object, reloc.offset, false);
        const ptr: *usize = @ptrFromInt(reloc_addr);

        std.debug.assert(reloc.addend >= 0);

        switch (reloc.type) {
            .RELATIVE => {
                reloc_count += 1;
                // R_X86_64_RELATIVE: B + A
                const value = try vAddressToLoadedAddress(dyn_object, @as(usize, @intCast(reloc.addend)) + if (reloc.addend == 0) ptr.* else 0, true);
                Logger.debug("  RELATIVE: 0x{x} (0x{x}): 0x{x} -> 0x{x} (addend: 0x{x}, relr: {})", .{ reloc_addr, reloc.offset, ptr.*, value, reloc.addend, reloc.is_relr });
                ptr.* = value;
            },
            .@"64" => {
                reloc_count += 1;
                // R_X86_64_64: S + A
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const value = sym.address + @as(usize, @intCast(reloc.addend));
                Logger.debug("  64: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} + 0x{x})", .{ reloc_addr, reloc.offset, ptr.*, value, sym.value, sym.name, sym.version, reloc.addend });
                ptr.* = value;
            },
            .GLOB_DAT => {
                reloc_count += 1;
                // R_X86_64_GLOB_DAT: S
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const value = sym.address;
                Logger.debug("  GLOB_DAT: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} + 0x{x})", .{ reloc_addr, reloc.offset, ptr.*, value, sym.value, sym.name, sym.version, reloc.addend });
                ptr.* = value;
            },
            .JUMP_SLOT => {
                reloc_count += 1;
                // R_X86_64_JUMP_SLOT: S
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const value = if (getSubstituteAddress(sym, dyn_object)) |a| a else sym.address;
                Logger.debug("  JUMP_SLOT: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} + 0x{x})", .{ reloc_addr, reloc.offset, ptr.*, value, sym.value, sym.name, sym.version, reloc.addend });
                ptr.* = value;
            },
            .TPOFF64 => {
                reloc_count += 1;
                // R_X86_64_TPOFF64: S + A (TLS offset)
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const tls_offset = dyn_objects.values()[sym.dyn_object_idx].tls_offset;
                const value = @as(isize, @intCast(sym.value)) + reloc.addend - @as(isize, @intCast(tls_offset));
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
                const value = @as(isize, @intCast(sym.value)) + reloc.addend;
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
                // TLSDESC
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const tls_offset = dyn_objects.values()[sym.dyn_object_idx].tls_offset;
                const value: TlsDesc = .{ .tls_desc_resolver_arg = @as(isize, @intCast(sym.value)) + reloc.addend - @as(isize, @intCast(tls_offset)), .tls_desc_resolver = &tlsDescResolver };
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
                const casted_ptr: *TlsDesc = @ptrCast(ptr);
                casted_ptr.* = @bitCast(value);
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

    Logger.debug("processed {d} relocations for {s}", .{ reloc_count, dyn_object.name });
}

fn processIRelativeRelocations(dyn_object: *DynObject) !void {
    Logger.debug("processing IRELATIVE relocations for {s}", .{dyn_object.name});

    var reloc_count: usize = 0;

    for (dyn_object.relocs.items) |reloc| {
        const reloc_addr = try vAddressToLoadedAddress(dyn_object, reloc.offset, false);
        const ptr: *usize = @ptrFromInt(reloc_addr);

        std.debug.assert(reloc.addend >= 0);

        switch (reloc.type) {
            .RELATIVE, .@"64", .GLOB_DAT, .JUMP_SLOT, .TPOFF64, .DTPOFF64, .DTPMOD64, .TLSDESC => {},
            .IRELATIVE => {
                reloc_count += 1;
                const resolver_addr = try vAddressToLoadedAddress(dyn_object, @intCast(reloc.addend), false);
                const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                Logger.debug("  IRELATIVE: calling resolver at 0x{x} (0x{x})", .{ resolver_addr, reloc.addend });
                const value = resolver();
                Logger.debug("  IRELATIVE: 0x{x} (0x{x}): 0x{x} -> 0x{x}", .{ reloc_addr, reloc.offset, ptr.*, value });
                ptr.* = value;
                if (ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                    std.debug.assert(res_val == value);
                }
                try ifunc_resolved_addrs.put(allocator, resolver_addr, value);
                try irel_resolved_targets.putNoClobber(allocator, reloc_addr, value);
            },
            else => {
                Logger.err("unhandled relocation type: {s}", .{@tagName(reloc.type)});
                return error.UnhandledReloctationType;
            },
        }
    }

    Logger.debug("processed {d} IRELATIVE relocations for {s}", .{ reloc_count, dyn_object.name });
}

// TODO Should receive a string that must be contained in dso name (like `libc.so`)
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
                        .dyn_object_idx = dyn_objects.getIndex(dep_object.name).?,
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
fn getResolvedSymbolByName(maybe_dyn_object: ?*DynObject, sym_name: []const u8) !ResolvedSymbol {
    if (maybe_dyn_object) |dyn_object| {
        for (dyn_object.deps_breadth_first.items) |dep_idx| {
            const dep_object = &dyn_objects.values()[dep_idx];

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
                            try ifunc_resolved_addrs.put(allocator, resolver_addr, value);
                            try irel_resolved_targets.putNoClobber(allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = dyn_objects.getIndex(dep_object.name).?,
                        };

                        if (getSubstituteAddress(res_sym, dep_object)) |a| {
                            res_sym.address = a;
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
        for (0..dyn_objects.count()) |dep_idx| {
            const dep_object = &dyn_objects.values()[dep_idx];

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
                            try ifunc_resolved_addrs.put(allocator, resolver_addr, value);
                            try irel_resolved_targets.putNoClobber(allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = dyn_objects.getIndex(dep_object.name).?,
                        };

                        if (getSubstituteAddress(res_sym, dep_object)) |a| {
                            res_sym.address = a;
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

    return error.UnresolvedSymbol;
}

// TODO thread safety (called from Symbol)
fn getResolvedSymbolByNameAndVersion(maybe_dyn_object: ?*DynObject, sym_name: []const u8, version: []const u8) !ResolvedSymbol {
    if (maybe_dyn_object) |dyn_object| {
        for (dyn_object.deps_breadth_first.items) |dep_idx| {
            const dep_object = &dyn_objects.values()[dep_idx];

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
                            try ifunc_resolved_addrs.put(allocator, resolver_addr, value);
                            try irel_resolved_targets.putNoClobber(allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = dyn_objects.getIndex(dep_object.name).?,
                        };

                        if (getSubstituteAddress(res_sym, dep_object)) |a| {
                            res_sym.address = a;
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
        for (0..dyn_objects.count()) |dep_idx| {
            const dep_object = &dyn_objects.values()[dep_idx];

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
                            try ifunc_resolved_addrs.put(allocator, resolver_addr, value);
                            try irel_resolved_targets.putNoClobber(allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = dyn_objects.getIndex(dep_object.name).?,
                        };

                        if (getSubstituteAddress(res_sym, dep_object)) |a| {
                            res_sym.address = a;
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

    return error.UnresolvedSymbol;
}

// TODO rules for symbol resolution should be rigorously implemented
fn resolveSymbol(dyn_object: *DynObject, sym_idx: usize) !ResolvedSymbol {
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
            try ifunc_resolved_addrs.put(allocator, resolver_addr, value);
            try irel_resolved_targets.putNoClobber(allocator, resolver_addr, value);
            addr = value;
        }

        return .{
            .value = sym.value,
            .address = addr,
            .name = sym.name,
            .version = sym.version,
            .dyn_object_idx = dyn_objects.getIndex(dyn_object.name).?,
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
                if (dep_sym.shidx != std.elf.SHN_UNDEF and (dep_sym.version.len == 0 or std.mem.eql(u8, dep_sym.version, "GLOBAL") or std.mem.eql(u8, dep_sym.version, sym.version)) and !dep_sym.hidden) {
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
                        try ifunc_resolved_addrs.put(allocator, resolver_addr, value);
                        try irel_resolved_targets.putNoClobber(allocator, resolver_addr, value);
                        dep_addr = value;
                    }

                    return .{
                        .value = dep_sym.value,
                        .address = dep_addr,
                        .name = dep_sym.name,
                        .version = dep_sym.version,
                        .dyn_object_idx = dep_idx,
                    };
                }

                if (dep_sym.shidx == std.elf.SHN_UNDEF) Logger.debug("WARNING: SKIPPING UNDEF SYMBOL from dep: {s} | {s}@{s}", .{ dep_object.name, dep_sym.name, dep_sym.version });
                if (dep_sym.hidden) Logger.debug("WARNING: SKIPPING HIDDEN SYMBOL from dep: {s} | {s}@{s}", .{ dep_object.name, dep_sym.name, dep_sym.version });
                if (dep_sym.version.len != 0 and !std.mem.eql(u8, dep_sym.version, "GLOBAL") and !std.mem.eql(u8, dep_sym.version, sym.version)) Logger.debug("WARNING: SKIPPING MISVERSIONED SYMBOL from dep: {s} | {s} ({s} vs {s})", .{ dep_object.name, dep_sym.name, sym.version, dep_sym.version });
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
        var prot: u32 = std.posix.PROT.NONE;
        if (segment.flags_last.read) prot |= std.posix.PROT.READ;
        if (segment.flags_last.write) prot |= std.posix.PROT.WRITE;
        if (segment.flags_last.exec) prot |= std.posix.PROT.EXEC;

        const aligned_start = std.mem.alignBackward(usize, segment.loaded_at + (segment.flags_last.mem_offset - segment.mem_offset), std.heap.pageSize());
        const aligned_end = std.mem.alignForward(usize, segment.loaded_at + (segment.flags_last.mem_offset - segment.mem_offset) + segment.flags_last.mem_size, std.heap.pageSize());
        Logger.debug("  updating segment {d}: from 0x{x} to 0x{x}, prot: 0x{x}", .{ s, aligned_start, aligned_end, prot });

        const segment_slice = @as([*]align(std.heap.pageSize()) u8, @ptrFromInt(aligned_start))[0 .. aligned_end - aligned_start];
        std.posix.mprotect(segment_slice, prot) catch |err| {
            Logger.err("failed to update segment permissions: {s}", .{@errorName(err)});
            return err;
        };
    }

    Logger.debug("successfully updated {d} segments for {s}", .{ dyn_object.segments.count(), dyn_object.name });
}

fn unprotectSegment(dyn_object: *DynObject, segment_index: usize) !void {
    const segment = dyn_object.segments.values()[segment_index];

    const aligned_start = std.mem.alignBackward(usize, segment.loaded_at, std.heap.pageSize());
    const aligned_end = std.mem.alignForward(usize, segment.loaded_at + segment.mem_size, std.heap.pageSize());
    const prot: u32 = std.posix.PROT.READ | std.posix.PROT.WRITE;

    Logger.debug("{s}: unprotecting segment {d}: from 0x{x} to 0x{x}, prot: 0x{x}", .{ dyn_object.name, segment_index, aligned_start, aligned_end, prot });

    const segment_slice = @as([*]align(std.heap.pageSize()) u8, @ptrFromInt(aligned_start))[0 .. aligned_end - aligned_start];
    std.posix.mprotect(segment_slice, prot) catch |err| {
        Logger.err("failed to update segment permissions: {s}", .{@errorName(err)});
        return err;
    };

    Logger.debug("successfully unprotected segment {d} for {s}", .{ segment_index, dyn_object.name });
}

fn reprotectSegment(dyn_object: *DynObject, segment_index: usize) !void {
    const segment = dyn_object.segments.values()[segment_index];

    var aligned_start = std.mem.alignBackward(usize, segment.loaded_at, std.heap.pageSize());
    var aligned_end = std.mem.alignForward(usize, segment.loaded_at + segment.mem_size, std.heap.pageSize());

    var prot: u32 = std.posix.PROT.NONE;
    if (segment.flags_first.read) prot |= std.posix.PROT.READ;
    if (segment.flags_first.write) prot |= std.posix.PROT.WRITE;
    if (segment.flags_first.exec) prot |= std.posix.PROT.EXEC;

    Logger.debug("{s}: reprotecting segment {d}: from 0x{x} to 0x{x}, prot: 0x{x}", .{ dyn_object.name, segment_index, aligned_start, aligned_end, prot });

    var segment_slice = @as([*]align(std.heap.pageSize()) u8, @ptrFromInt(aligned_start))[0 .. aligned_end - aligned_start];
    std.posix.mprotect(segment_slice, prot) catch |err| {
        Logger.err("failed to update segment permissions: {s}", .{@errorName(err)});
        return err;
    };

    if (dyn_object.loaded) {
        prot = std.posix.PROT.NONE;
        if (segment.flags_last.read) prot |= std.posix.PROT.READ;
        if (segment.flags_last.write) prot |= std.posix.PROT.WRITE;
        if (segment.flags_last.exec) prot |= std.posix.PROT.EXEC;

        aligned_start = std.mem.alignBackward(usize, segment.loaded_at + (segment.flags_last.mem_offset - segment.mem_offset), std.heap.pageSize());
        aligned_end = std.mem.alignForward(usize, segment.loaded_at + (segment.flags_last.mem_offset - segment.mem_offset) + segment.flags_last.mem_size, std.heap.pageSize());

        Logger.debug("{s}: reapplying segment {d} permissions: from 0x{x} to 0x{x}, prot: 0x{x}", .{ dyn_object.name, segment_index, aligned_start, aligned_end, prot });

        segment_slice = @as([*]align(std.heap.pageSize()) u8, @ptrFromInt(aligned_start))[0 .. aligned_end - aligned_start];
        std.posix.mprotect(segment_slice, prot) catch |err| {
            Logger.err("failed to update segment permissions: {s}", .{@errorName(err)});
            return err;
        };
    }

    Logger.debug("successfully reprotected segment {d} for {s}", .{ segment_index, dyn_object.name });
}

const DynObjectSegmentResult = struct {
    dyn_object: *DynObject,
    segment_index: usize,
    sym_index: ?usize,
};

fn findDynObjectSegmentForLoadedAddr(addr: usize) !DynObjectSegmentResult {
    for (dyn_objects.values()) |*dyn_object| {
        for (dyn_object.segments.values(), 0..) |*s, s_idx| {
            const segment_start = s.loaded_at;
            const segment_end = segment_start + s.mem_size;
            if (addr >= segment_start and addr < segment_end) {
                for (dyn_object.syms_array.items, 0..) |*sym, sym_idx| {
                    const sym_addr = try vAddressToLoadedAddress(dyn_object, sym.value, false);
                    if (sym_addr <= addr and sym_addr + sym.size > addr) {
                        return .{
                            .dyn_object = dyn_object,
                            .segment_index = s_idx,
                            .sym_index = sym_idx,
                        };
                    }
                }
                return .{
                    .dyn_object = dyn_object,
                    .segment_index = s_idx,
                    .sym_index = null,
                };
            }
        }
    }

    // TODO also search the main executable, in case it is c++ that wants to unwind an exception

    return error.LoadedAddressNotMapped;
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

        Logger.warn("addr 0x{x} not in any mapped segment", .{addr});
        return dyn_object.loaded_at.? + addr;
    }

    const segment = containing_segment.?;

    return segment.loaded_at + addr - segment.mem_offset;
}

fn vAddressToFileAddress(dyn_object: *DynObject, addr: usize) !usize {
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
        Logger.err("addr 0x{x} not in any mapped segment", .{addr});
        return error.AddressNotInMappedSegments;
    }

    const segment = containing_segment.?;

    return dyn_object.mapped_at + addr - (segment.mem_offset - segment.file_offset);
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
    const is_libc_so = std.mem.startsWith(u8, dyn_obj.name, "libc.so");

    if (is_libc_so) {
        var maybe_sym: ?ResolvedSymbol = undefined;
        maybe_sym = resolveSymbolByName("__libc_early_init") catch null;
        if (maybe_sym) |sym| {
            Logger.debug("libc: found early init: 0x{x}", .{sym.address});
            const early_init: *const fn (bool) callconv(.c) void = @ptrFromInt(sym.address);

            Logger.debug("libc: calling early_init at 0x{x}", .{sym.address});
            early_init(false);
        }

        maybe_sym = resolveSymbolByName("__pre_dls2b") catch null;
        if (maybe_sym) |sym| {
            Logger.debug("libc: found __pre_dls2b: 0x{x}", .{sym.address});
            const early_init: *const fn ([*c]usize) callconv(.c) void = @ptrFromInt(sym.address);

            Logger.debug("libc: calling __pre_dls2b: 0x{x}", .{sym.address});
            early_init(if (std.os.linux.elf_aux_maybe) |auxv| @ptrCast(auxv) else 0);
        }
    }

    if (dyn_obj.init_addr != 0) {
        const initial_addr = dyn_obj.init_addr;
        const actual_addr = try vAddressToLoadedAddress(dyn_obj, dyn_obj.init_addr, false);
        Logger.debug("calling init function for {s} at 0x{x} (initial address: 0x{x})", .{ dyn_obj.name, actual_addr, initial_addr });
        const func = @as(*const fn () callconv(.c) void, @ptrFromInt(actual_addr));
        func();
    }

    if (dyn_obj.init_array_addr != 0 and dyn_obj.init_array_size > 0) {
        const num_funcs = dyn_obj.init_array_size / @sizeOf(usize);
        Logger.debug("calling {d} init_array functions for {s} (0x{x})", .{ num_funcs, dyn_obj.name, dyn_obj.init_array_addr });
        const initial_init_array: [*]const usize = @ptrFromInt(try vAddressToFileAddress(dyn_obj, dyn_obj.init_array_addr));
        const actual_init_array: [*]const usize = @ptrFromInt(try vAddressToLoadedAddress(dyn_obj, dyn_obj.init_array_addr, false));

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

                const argc: c_int = @intCast(std.os.argv.len);
                const argv: [*c]const [*c]const u8 = @ptrCast(std.os.argv);
                const env: [*c]const [*c]const u8 = @ptrCast(std.os.environ);

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

fn getSubstituteAddress(sym: ResolvedSymbol, for_obj: *DynObject) ?usize {
    var addr: ?usize = null;

    if (sym.dyn_object_idx == std.math.maxInt(usize)) {
        return null;
    }

    const dyn_object = &dyn_objects.values()[sym.dyn_object_idx];

    // dl functions
    if (std.mem.eql(u8, sym.name, "dlopen")) {
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
    } else if (std.mem.eql(u8, sym.name, "_dl_find_object")) {
        addr = @intFromPtr(&dlFindObjectSubstitute);
    } else if (std.mem.eql(u8, sym.name, "dl_iterate_phdr")) {
        addr = @intFromPtr(&dlIteratePhdrSubstitute);
    } else if (std.mem.startsWith(u8, sym.name, "dl") or std.mem.startsWith(u8, sym.name, "_dl")) {
        if (!std.mem.startsWith(u8, for_obj.name, "libc.so")) {
            Logger.warn("substitutes: {s}: dangerous unsubstituted dl function [{s}] {s} at 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
        }
        addr = @intFromPtr(&unsubstitutedTrap);
    }

    // pthreads functions
    if (std.mem.eql(u8, sym.name, "pthread_create")) {
        addr = @intFromPtr(&pthreadCreateSubstitute);
    } else if (std.mem.eql(u8, sym.name, "pthread_exit")) {
        if (!std.mem.startsWith(u8, for_obj.name, "libpthread.so") and !std.mem.startsWith(u8, for_obj.name, "libc.so")) {
            Logger.warn("substitutes: {s}: dangerous unsubstituted pthread function [{s}] {s} as 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
        }
        addr = @intFromPtr(&unsubstitutedTrap);
    } else if (std.mem.eql(u8, sym.name, "pthread_cancel")) {
        if (!std.mem.startsWith(u8, for_obj.name, "libpthread.so") and !std.mem.startsWith(u8, for_obj.name, "libc.so")) {
            Logger.warn("substitutes: {s}: dangerous unsubstituted pthread function [{s}] {s} as 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
        }
        addr = @intFromPtr(&unsubstitutedTrap);
    } else if (std.mem.eql(u8, sym.name, "pthread_detach")) {
        if (!std.mem.startsWith(u8, for_obj.name, "libpthread.so") and !std.mem.startsWith(u8, for_obj.name, "libc.so")) {
            Logger.warn("substitutes: {s}: dangerous unsubstituted pthread function [{s}] {s} as 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
        }
        addr = @intFromPtr(&unsubstitutedTrap);
    } else if (std.mem.eql(u8, sym.name, "pthread_join")) {
        if (!std.mem.startsWith(u8, for_obj.name, "libpthread.so") and !std.mem.startsWith(u8, for_obj.name, "libc.so")) {
            Logger.warn("substitutes: {s}: dangerous unsubstituted pthread function [{s}] {s} as 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
        }
        addr = @intFromPtr(&unsubstitutedTrap);
    }
    // TODO checkif those functions really needs to be subsituted, it seems they only acts on the pthread struct
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

var extra_bytes: std.ArrayList([]const u8) = .empty;
var extra_link_maps: std.ArrayList(*DlLinkMap) = .empty;
var last_dl_error: ?[:0]const u8 = null;

fn dlopenSubstitute(path: ?[*:0]const u8, flags: c_int) callconv(.c) ?*anyopaque {
    Logger.info("intercepted call: dlopen(\"{?s}\", 0x{x})", .{ path, flags });

    if (path == null) {
        return @ptrFromInt(std.math.maxInt(usize) - 1);
    }

    const owned_path = allocator.dupe(u8, std.mem.span(path.?)) catch @panic("OOM");
    extra_bytes.append(allocator, owned_path) catch @panic("OOM");

    const lib = load(owned_path) catch |err| {
        if (last_dl_error != null) {
            allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(allocator, "unable to load library {s}: {}", .{ owned_path, err }, 0) catch @panic("OOM");

        Logger.err("dlopen(\"{s}\", 0x{x}) failed: {}", .{ owned_path, flags, err });

        return null;
    };

    Logger.info("intercepted call: success: dlopen(\"{?s}\", 0x{x}) = 0x{x}", .{ path, flags, lib.index + 1 });

    return @ptrFromInt(lib.index + 1);
}

fn dlcloseSubstitute(lib: *anyopaque) callconv(.c) c_int {
    // TODO real implementation
    Logger.warn("unimplemented: dlclose({d})", .{@intFromPtr(lib)});

    return 0;
}

fn dlsymSubstitute(lib_handle: ?*anyopaque, sym_name: [*:0]const u8) callconv(.c) ?*anyopaque {
    Logger.info("intercepted call: dlsym({d}, \"{s}\")", .{ @intFromPtr(lib_handle), sym_name });

    const dyn_object = if (lib_handle != null and @intFromPtr(lib_handle.?) != std.math.maxInt(usize) - 1) &dyn_objects.values()[@intFromPtr(lib_handle.?) - 1] else null;

    const sym = getResolvedSymbolByName(dyn_object, std.mem.span(sym_name)) catch |err| {
        if (last_dl_error != null) {
            allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(allocator, "unable to get symbol {s} for library {s}: {}", .{ sym_name, if (dyn_object) |do| do.name else "NULL", err }, 0) catch @panic("OOM");

        Logger.warn("dlsym({d} [{s}], \"{s}\") failed: {}", .{ @intFromPtr(lib_handle), if (dyn_object) |do| do.name else "NULL", sym_name, err });

        return null;
    };

    Logger.info("intercepted call: success: dlsym({d} [{s}], \"{s}\") = 0x{x}", .{ @intFromPtr(lib_handle), if (dyn_object) |do| do.name else "NULL", sym_name, sym.address });

    return @ptrFromInt(sym.address);
}

fn dlvsymSubstitute(lib_handle: ?*anyopaque, sym_name: [*:0]const u8, version: [*:0]const u8) callconv(.c) ?*anyopaque {
    Logger.info("intercepted call: dlvsym({d}, \"{s}\" \"{s}\")", .{ @intFromPtr(lib_handle), sym_name, version });

    const dyn_object = if (lib_handle != null and @intFromPtr(lib_handle.?) != std.math.maxInt(usize) - 1) &dyn_objects.values()[@intFromPtr(lib_handle.?) - 1] else null;

    const sym = getResolvedSymbolByNameAndVersion(dyn_object, std.mem.span(sym_name), std.mem.span(version)) catch |err| {
        if (last_dl_error != null) {
            allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(allocator, "unable to get symbol {s}@{s} for library {s}: {}", .{ sym_name, version, if (dyn_object) |do| do.name else "NULL", err }, 0) catch @panic("OOM");

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
    _others: [1168]u8, // implementation dependent
};

const DlFindObject = extern struct {
    dlfo_flags: c_ulonglong,
    dlfo_map_start: ?*anyopaque,
    dlfo_map_end: ?*anyopaque,
    dlfo_link_map: ?*DlLinkMap,
    dlfo_eh_frame: ?*anyopaque,
    __dlfo_reserved: [7]c_ulonglong, // implementation dependent
};

fn dladdrSubstitute(addr: *anyopaque, dl_info: *DlInfo) callconv(.c) c_int {
    Logger.info("intercepted call: dladdr(0x{x}, dl_info: *DlInfo [0x{x}])", .{ @intFromPtr(addr), @intFromPtr(dl_info) });

    const infos = findDynObjectSegmentForLoadedAddr(@intFromPtr(addr)) catch |err| {
        if (last_dl_error != null) {
            allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(allocator, "unable to get infos for address 0x{x}: {}", .{ @intFromPtr(addr), err }, 0) catch @panic("OOM");

        Logger.warn("dladdr(0x{x}, {}) failed: {}", .{ @intFromPtr(addr), dl_info.*, err });

        return 0;
    };

    const owned_name = allocator.dupeZ(u8, infos.dyn_object.name) catch @panic("OOM");
    extra_bytes.append(allocator, owned_name) catch @panic("OOM");

    dl_info.dli_fname = owned_name.ptr;
    dl_info.dli_fbase = @ptrFromInt(infos.dyn_object.loaded_at.?);

    if (infos.sym_index) |sidx| {
        const sym = infos.dyn_object.syms_array.items[sidx];
        const sym_addr = vAddressToLoadedAddress(infos.dyn_object, sym.value, false) catch unreachable;

        const owned_sym_name = allocator.dupeZ(u8, sym.name) catch @panic("OOM");
        extra_bytes.append(allocator, owned_sym_name) catch @panic("OOM");

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

fn dlerrorSubstitute() callconv(.c) ?[*:0]const u8 {
    Logger.info("intercepted call: dlerror()", .{});
    Logger.info("intercepted call: success: dlerror() = {?s}", .{last_dl_error});

    return if (last_dl_error) |e| e.ptr else null;
}

fn dladdr1Substitute(addr: *anyopaque, dl_info: *DlInfo, extra_infos: *anyopaque, flags: c_int) callconv(.c) c_int {
    Logger.info("intercepted call: dladdr1(0x{x}, dl_info: *DlInfo [0x{x}], extra_infos: 0x{x}, flags: 0x{x})", .{
        @intFromPtr(addr),
        @intFromPtr(dl_info),
        @intFromPtr(extra_infos),
        if (flags == 1) "RTLD_DL_SYMENT" else if (flags == 2) "RTLD_DL_LINKMAP" else "UNKNOWN_FLAGS",
    });

    const infos = findDynObjectSegmentForLoadedAddr(@intFromPtr(addr)) catch |err| {
        if (last_dl_error != null) {
            allocator.free(last_dl_error.?);
        }
        last_dl_error = std.fmt.allocPrintSentinel(allocator, "unable to get infos for address 0x{x}: {}", .{ @intFromPtr(addr), err }, 0) catch @panic("OOM");

        Logger.warn("dladdr1(0x{x}, dl_info: *DlInfo [0x{x}], extra_infos: 0x{x}, flags: 0x{x}) failed: {}", .{
            @intFromPtr(addr),
            @intFromPtr(dl_info),
            @intFromPtr(extra_infos),
            if (flags == 1) "RTLD_DL_SYMENT" else if (flags == 2) "RTLD_DL_LINKMAP" else "UNKNOWN_FLAGS",
            err,
        });

        return 0;
    };

    const owned_name = allocator.dupeZ(u8, infos.dyn_object.name) catch @panic("OOM");
    extra_bytes.append(allocator, owned_name) catch @panic("OOM");

    dl_info.dli_fname = owned_name.ptr;
    dl_info.dli_fbase = @ptrFromInt(infos.dyn_object.loaded_at.?);

    if (infos.sym_index) |sidx| {
        const sym = infos.dyn_object.syms_array.items[sidx];
        const sym_addr = vAddressToLoadedAddress(infos.dyn_object, sym.value, false) catch unreachable;

        const owned_sym_name = allocator.dupeZ(u8, sym.name) catch @panic("OOM");
        extra_bytes.append(allocator, owned_sym_name) catch @panic("OOM");

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

            const link_map = allocator.create(DlLinkMap) catch @panic("OOM");
            extra_link_maps.append(allocator, link_map) catch @panic("OOM");

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
    Logger.info("intercepted call: _dl_find_object(0x{x}, *DlFindObject [0x{x}])", .{ @intFromPtr(pc), @intFromPtr(result) });

    const infos = findDynObjectSegmentForLoadedAddr(@intFromPtr(pc)) catch |err| {
        Logger.warn("_dl_find_object(0x{x}, *DlFindObject [0x{x}]) failed: {}", .{ @intFromPtr(pc), @intFromPtr(result), err });
        return 1;
    };

    result.dlfo_eh_frame = @ptrFromInt(infos.dyn_object.loaded_at.? + infos.dyn_object.eh_init_mem_offset);

    Logger.warn("_dl_find_object: partial implementation: only `dl_info_result.dlfo_eh_frame` field supported", .{});

    Logger.info("intercepted call: success: _dl_find_object(0x{x}, .{{ .dflo_eh_frame = 0x{x} }})", .{ @intFromPtr(pc), @intFromPtr(result.dlfo_eh_frame) });

    return 0;
}

fn dlIteratePhdrSubstitute(callback: *const fn (*anyopaque, c_uint, *anyopaque) callconv(.c) c_int, data: *anyopaque) callconv(.c) c_int {
    Logger.info("intercepted call: dl_iterate_phdr(callback: 0x{x}, data: 0x{x})", .{ @intFromPtr(callback), @intFromPtr(data) });

    for (dyn_objects.values()) |*dyn_obj| {
        if (!dyn_obj.loaded) {
            continue;
        }

        const dl_phdr_info = allocator.create(std.posix.dl_phdr_info) catch @panic("OOM");

        dl_phdr_info.* = .{
            .addr = dyn_obj.loaded_at.?,
            .name = @ptrCast(dyn_obj.path),
            .phdr = @ptrFromInt(dyn_obj.loaded_at.? + dyn_obj.eh.e_phoff),
            .phnum = dyn_obj.eh.e_phnum,
        };

        const ret = callback(dl_phdr_info, @sizeOf(std.posix.dl_phdr_info), data);
        if (ret != 0) {
            Logger.info("intercepted call: dl_iterate_phdr(callback: 0x{x}, data: 0x{x}) != 0 for {s}", .{ @intFromPtr(callback), @intFromPtr(data), dyn_obj.name });
            return ret;
        }
    }

    Logger.info("intercepted call: success: dl_iterate_phdr(callback: 0x{x}, data: 0x{x})", .{ @intFromPtr(callback), @intFromPtr(data) });

    return 0;
}

fn pthreadCreateSubstitute(newthread: *anyopaque, attr: ?*const anyopaque, start_routine: *const fn (?*anyopaque) callconv(.c) *anyopaque, arg: ?*anyopaque) callconv(.c) c_int {
    // TODO real implementation
    Logger.err("unimplemented: pthread_create(0x{x}, 0x{x}, 0x{x}, 0x{x})", .{ @intFromPtr(newthread), @intFromPtr(attr), @intFromPtr(start_routine), @intFromPtr(arg) });
    @panic("unimplemented pthread_create");
}

const TlsIndex = extern struct {
    ti_module: usize,
    ti_offset: usize,
};

fn tlsGetAddressSubstitute(tls_index: *TlsIndex) callconv(.c) ?*anyopaque {
    Logger.info("intercepted call: __tls_get_addr({})", .{tls_index});

    const dyn_object_idx = tls_index.ti_module - 1;

    var tp: usize = undefined;
    const e_get_fs = std.os.linux.syscall2(.arch_prctl, std.os.linux.ARCH.GET_FS, @intFromPtr(&tp));
    std.debug.assert(e_get_fs == 0);

    const dyn_object = &dyn_objects.values()[dyn_object_idx];
    const addr = tp - dyn_object.tls_offset + tls_index.ti_offset;

    Logger.info("intercepted call: success: __tls_get_addr({{.module = {s}, .offset = 0x{x}}}) = 0x{x}", .{ dyn_object.name, tls_index.ti_offset, addr });

    return @ptrFromInt(addr);
}
