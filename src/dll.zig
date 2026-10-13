//! Process-wide ELF loader for a statically linked x86-64 Linux host.
//!
//! This module owns object discovery, mappings, relocation, TLS, and native API
//! substitution. `DynObject` holds object-local metadata; `libc` owns the native
//! runtime contract. Registry indices identify objects across array reallocations,
//! whereas pointers into the registry are temporary borrows.
//!
//! Loading has separate mapping, relocation, and initialization phases. Native
//! resolvers and constructors can call back into the loader, so iteration orders
//! are copied before invoking them. Lifecycle operations require caller-side
//! serialization; the allocation and worker locks do not protect the whole loader.

const std = @import("std");
const builtin = @import("builtin");

pub const CustomSelfInfo = @import("CustomSelfInfo.zig");

const DynObject = @import("DynObject.zig");
const logger = @import("logger.zig");
const libc = @import("libc.zig");
const CodeView = @import("CodeView.zig");

const LoadSegmentFlags = DynObject.LoadSegmentFlags;
const LoadSegment = DynObject.LoadSegment;
const LoadSegmentList = DynObject.LoadSegmentList;
const DynSym = DynObject.DynSym;
const DynSymList = DynObject.DynSymList;
const ResolvedSymbol = DynObject.ResolvedSymbol;
const Reloc = DynObject.Reloc;
const RelocList = DynObject.RelocList;
const DynObjectId = DynObject.DynObjectId;
const DynObjectSegmentResult = DynObject.DynObjectSegmentResult;

// Public types and initialization options.
// ----------------------------------------

const Symbol = struct {
    addr: usize,
};

/// Registry handle for a loaded root and its dependency scope. Copies refer to
/// the same load; symbol addresses borrow the corresponding native mappings.
/// Handles and symbols must not be used after loader teardown.
pub const DynamicLibrary = struct {
    index: usize,

    /// Searches preload roots before this library's scope and resolves IFUNCs.
    /// The caller supplies the correct native type and calling convention for `addr`.
    pub fn getSymbol(lib: DynamicLibrary, sym_name: []const u8) !Symbol {
        for (state.preload_root_indices.items) |preload_idx| {
            const preload_dyn_obj = &state.dyn_objects.values()[preload_idx];
            const preload_sym = getResolvedSymbolByName(preload_dyn_obj, sym_name, false, false, true) catch |err| switch (err) {
                error.UnresolvedSymbol => continue,
                else => |e| return e,
            };

            return .{
                .addr = preload_sym.address,
            };
        }

        const dyn_obj = &state.dyn_objects.values()[lib.index];
        const sym = try getResolvedSymbolByName(dyn_obj, sym_name, false, false, true);
        return .{
            .addr = sym.address,
        };
    }

    // TODO expose public unloading with an explicit handle lifetime contract.
};

const InitOptions = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    args: std.process.Args,
    environ: std.process.Environ,
    /// Runtime threshold. Debug output also requires the host's `std_options`
    /// to enable `.debug` for the `dynamic_library_loader` log scope.
    log_level: logger.Level = .err,
};

// Loader state.
// -------------

const DynObjectList = std.AutoArrayHashMapUnmanaged(DynObjectId, DynObject);

/// Process-wide loader ownership. This value stays at a stable address: workers
/// borrow `libc_runtime`, and the registries and mutexes must not be copied live.
/// `init`/`deinit` update fields in place; `deinitialized` remains terminal.
const State = struct {
    // Lifecycle and borrowed host context.
    initialized: bool = false,
    deinitializing: bool = false,
    deinitialized: bool = false,
    allocator: std.mem.Allocator = undefined,
    io: std.Io = undefined,
    args: std.process.Args = undefined,
    environ: std.process.Environ = undefined,

    // Object registry, load ordering, handles, and resolution caches.
    dyn_objects: DynObjectList = .empty,
    dyn_objects_sorted_indices: std.ArrayList(usize) = .empty,
    dyn_objects_init_indices: std.ArrayList(usize) = .empty,
    preload_root_indices: std.ArrayList(usize) = .empty,
    preloads_processed: bool = false,
    dl_handles: DlHandleMap = .empty,
    load_request_cache: std.StringArrayHashMapUnmanaged(usize) = .empty,
    ifunc_resolved_addrs: std.AutoArrayHashMapUnmanaged(usize, usize) = .empty,
    irel_resolved_targets: std.AutoArrayHashMapUnmanaged(usize, usize) = .empty,

    // Owns native backend state; worker handles borrow this runtime.
    libc_runtime: ?libc.Runtime = null,

    // Loader TLS bookkeeping; early executable TLS belongs to ElfTlsRuntime.
    initial_tls_init_file_size: usize = undefined,
    initial_tls_init_mem_size: usize = undefined,
    initial_tls_offset: usize = undefined,
    initial_tls_align: ?usize = null,
    initial_tls_init_block: []const u8 = undefined,
    current_surplus_size: usize = 0x100000,
    normal_current_tls_area_desc: ?ElfTlsRuntime.AreaDesc = null,
    loader_thread_pointer: usize = 0,

    // Thread registry, retained thread allocations, and synchronization.
    thread_mutex: std.Io.Mutex = .init,
    thread_infos: ThreadInfosMap = .empty,
    thread_current_idx: usize = 1,
    thread_destructors: std.ArrayList(ThreadDestructor) = .empty,
    extra_threads: std.ArrayList(*std.Thread) = .empty,

    // Intercepted allocations and retained API results.
    alloc_allocator: std.mem.Allocator = undefined,
    alloc_mutex: std.Io.Mutex = .init,
    extra_allocations: std.AutoArrayHashMapUnmanaged(usize, TrackedAllocation) = .empty,
    extra_strs_z: std.ArrayList([:0]const u8) = .empty,
    extra_link_maps: std.ArrayList(*DlLinkMap) = .empty,
};

var state: State = .{};

// Public lifecycle and loading API.
// ---------------------------------

// TODO synchronize loader lifecycle, registry mutation, and lookup while allowing
// constructor and resolver callbacks to reenter the loader.
/// Initializes the singleton using borrowed host arguments, environment, and I/O.
/// Call on the initial thread before loading libraries or starting workers. The
/// allocator and host context must remain valid through `deinit`; reinitializing
/// after teardown is unsupported.
pub fn init(options: InitOptions) !void {
    if (state.deinitialized) return error.ReinitializationUnsupported;
    if (state.initialized) return error.AlreadyInitialized;

    state.allocator = options.allocator;
    state.io = options.io;
    logger.level = options.log_level;

    state.alloc_allocator = state.allocator;

    state.args = options.args;
    state.environ = options.environ;

    // TODO enforce main-thread initialization and the required host linkage mode;
    // the compile-time platform check already rejects hosts linked against libc.

    state.initialized = true;
    logger.info("loader.init: action=ready log_level={t}", .{logger.level});
}

/// Runs finalizers before releasing mappings and runtime state. The caller must
/// have joined all workers and stopped native calls; this does not join workers.
/// Recursive teardown from a finalizer is ignored, and cleanup errors are logged.
pub fn deinit() void {
    if (!state.initialized or state.deinitializing) return;
    logger.info("loader.deinit: action=begin objects={d} workers={d}", .{ state.dyn_objects.count(), state.thread_infos.count() });

    state.deinitializing = true;
    defer state.deinitializing = false;

    runThreadDestructors(libc.currentThreadPointer());
    for (state.dyn_objects.values()) |*dyn_object| {
        dyn_object.finalizing = true;
    }

    var nb_dyn_objects = state.dyn_objects_init_indices.items.len;
    while (nb_dyn_objects > 0) {
        nb_dyn_objects -= 1;

        const dyn_object_idx = state.dyn_objects_init_indices.items[nb_dyn_objects];
        const dyn_object = &state.dyn_objects.values()[dyn_object_idx];

        if (!dyn_object.init_called) {
            dyn_object.ref_count = 0;
            continue;
        }

        dyn_object.init_called = false;

        var finalizing_object = dyn_object.*;
        callFiniFunctions(&finalizing_object) catch |err| {
            logger.warn("deinit: unable to close library {s}: {}", .{ finalizing_object.name, err });
        };

        state.dyn_objects.values()[dyn_object_idx].ref_count = 0;
    }

    CustomSelfInfo.clearExtraElfs(state.allocator);

    for (state.dyn_objects.values()) |*dyn_object| {
        dyn_object.binding_dependencies.deinit(state.allocator);
        if (dyn_object.phdr_name) |name| state.allocator.free(name);

        if (dyn_object.mapped_at != 0) {
            std.posix.munmap(@as([*]align(std.heap.pageSize()) u8, @ptrFromInt(dyn_object.mapped_at))[0..dyn_object.mapped_size]);
        }
        if (dyn_object.reservation) |reservation| std.posix.munmap(reservation);

        dyn_object.syms_array.deinit(state.allocator);

        for (dyn_object.syms.values()) |*v| v.deinit(state.allocator);
        dyn_object.syms.deinit(state.allocator);

        dyn_object.relocs.deinit(state.allocator);
        dyn_object.dependencies.deinit(state.allocator);
        dyn_object.deps_breadth_first.deinit(state.allocator);
        dyn_object.segments.deinit(state.allocator);

        state.allocator.free(dyn_object.name);
        state.allocator.free(dyn_object.path);
        if (dyn_object.runpath) |runpath| state.allocator.free(runpath);

        if (dyn_object.file_handle != -1) {
            _ = std.os.linux.close(dyn_object.file_handle);
        }
    }

    state.dyn_objects.clearAndFree(state.allocator);
    state.dyn_objects_sorted_indices.deinit(state.allocator);
    state.dyn_objects_init_indices.deinit(state.allocator);
    state.preload_root_indices.deinit(state.allocator);
    state.dl_handles.clearAndFree(state.allocator);

    for (state.load_request_cache.keys()) |key| state.allocator.free(key);
    state.load_request_cache.deinit(state.allocator);

    state.ifunc_resolved_addrs.clearAndFree(state.allocator);
    state.irel_resolved_targets.clearAndFree(state.allocator);

    const current_tls_area_desc = ElfTlsRuntime.area_desc;
    ElfTlsRuntime.publish(ElfTlsRuntime.executable_desc);

    state.normal_current_tls_area_desc = null;
    if (current_tls_area_desc.owns_template) state.allocator.free(current_tls_area_desc.block.init);

    for (state.extra_link_maps.items) |e| state.allocator.destroy(e);
    state.extra_link_maps.deinit(state.allocator);

    for (state.extra_threads.items) |e| state.allocator.destroy(e);
    state.extra_threads.deinit(state.allocator);

    last_dl_error = null;

    for (state.thread_infos.values()) |entry| entry.libc_worker.releaseAfterJoin();
    state.thread_infos.clearAndFree(state.allocator);

    state.thread_destructors.deinit(state.allocator);

    if (state.libc_runtime) |*specifics| specifics.deinit();

    if (state.extra_allocations.count() > 0) {
        var not_freed: usize = 0;
        for (state.extra_allocations.keys(), state.extra_allocations.values()) |address, allocation| {
            not_freed += allocation.requested_size;
            const storage = @as([*]u8, @ptrFromInt(address))[0..allocation.storage_size];
            state.alloc_allocator.rawFree(storage, allocation.alignment, @returnAddress());
        }

        logger.warn("loader.deinit: action=reclaim_outstanding_allocations bytes={d} allocations={d}", .{ not_freed, state.extra_allocations.count() });
    }
    state.extra_allocations.clearAndFree(state.allocator);

    for (state.extra_strs_z.items) |e| state.allocator.free(e);
    state.extra_strs_z.deinit(state.allocator);

    state.initialized = false;
    state.deinitialized = true;
    logger.info("loader.deinit: action=complete", .{});
}

/// Searches for a supported ELF library without loading it. A successful path is
/// allocated with the initialization allocator and must be freed by the caller.
/// A missing candidate returns `null`; other errors remain errors.
pub fn resolve(name: []const u8) !?[]const u8 {
    if (!state.initialized) return error.Uninitialized;

    return resolvePath(name, true, null, null, null) catch |err| switch (err) {
        error.LibraryNotFound => null,
        else => |e| return e,
    };
}

/// Loads the first discoverable backend libc candidate. Once a path is found,
/// incompatibility is reported by `load` rather than hidden by trying another ABI.
pub fn loadSystemLibC() !DynamicLibrary {
    if (!state.initialized) return error.Uninitialized;

    logger.debug("libc: searching system libc", .{});

    for (libc.system_libc_names) |candidate| {
        logger.debug("libc: trying {s}", .{candidate});

        const path = resolvePath(candidate, true, null, null, null) catch |err| switch (err) {
            error.LibraryNotFound => continue,
            else => |e| return e,
        };
        defer state.allocator.free(path);

        return load(path);
    }

    return error.SystemLibcNotFound;
}

/// Loads a name or path, its dependencies, and required runtime state; returns
/// after constructors finish. Failure attempts to release unreferenced objects, but native
/// callback side effects and process-wide runtime initialization are not undone.
pub fn load(f_path: []const u8) !DynamicLibrary {
    return loadWithRootResolveContext(f_path, null, null);
}

/// Resolves a name in the loader's global scope. The returned address borrows its
/// defining mapping and may be the result of a native IFUNC resolver call.
pub fn getSymbol(sym_name: []const u8) !Symbol {
    if (!state.initialized) return error.Uninitialized;

    const sym = try getResolvedSymbolByName(null, sym_name, false, false, true);
    return .{
        .addr = sym.address,
    };
}

// Library discovery and dependency loading.
// -----------------------------------------

const ResolvedDynObjectInfos = struct {
    key: DynObjectId,
    path: []const u8,
};

fn appendLdExpansions(list: *std.ArrayList([]const u8), value: []const u8, origin_dir: ?[]const u8) !void {
    var expanded_buf: [std.fs.max_path_bytes]u8 = @splat(0);
    var expanded = try std.fmt.bufPrint(&expanded_buf, "{s}", .{value});

    var expanded_tmp_buf: [std.fs.max_path_bytes]u8 = @splat(0);

    // TODO expand all token occurrences in one pass without re-expanding replacement text.

    var owned_origin: ?[]const u8 = null;
    defer if (owned_origin) |origin| state.allocator.free(origin);

    const origin = origin_dir orelse blk: {
        owned_origin = try std.process.executableDirPathAlloc(state.io, state.allocator);
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
        const platform = if (platform_ptr == 0) try state.allocator.dupe(u8, "x86_64") else try state.allocator.dupe(u8, std.mem.span(@as([*:0]const u8, @ptrFromInt(platform_ptr))));
        defer state.allocator.free(platform);
        @memcpy(expanded_tmp_buf[0..expanded.len], expanded);
        expanded = try std.fmt.bufPrint(&expanded_buf, "{s}{s}{s}", .{ expanded_tmp_buf[0..idx], platform, expanded_tmp_buf[idx + "$PLATFORM".len .. expanded.len] });
    }

    if (std.mem.find(u8, expanded, "${PLATFORM}")) |idx| {
        const platform_ptr = std.os.linux.getauxval(std.elf.AT.PLATFORM);
        const platform = if (platform_ptr == 0) try state.allocator.dupe(u8, "x86_64") else try state.allocator.dupe(u8, std.mem.span(@as([*:0]const u8, @ptrFromInt(platform_ptr))));
        defer state.allocator.free(platform);
        @memcpy(expanded_tmp_buf[0..expanded.len], expanded);
        expanded = try std.fmt.bufPrint(&expanded_buf, "{s}{s}{s}", .{ expanded_tmp_buf[0..idx], platform, expanded_tmp_buf[idx + "${PLATFORM}".len .. expanded.len] });
    }

    if (std.mem.find(u8, expanded, "$LIB") == null and std.mem.find(u8, expanded, "${LIB}") == null) {
        try list.append(state.allocator, try state.allocator.dupe(u8, expanded));
        return;
    }

    const lib_values = [_][]const u8{ "lib/x86_64-linux-gnu", "lib64", "lib" };

    var expanded_candidate_buf: [std.fs.max_path_bytes]u8 = @splat(0);

    if (std.mem.find(u8, expanded, "$LIB")) |idx| {
        for (lib_values) |lv| {
            const expanded_candidate = try std.fmt.bufPrint(&expanded_candidate_buf, "{s}{s}{s}", .{ expanded[0..idx], lv, expanded[idx + "$LIB".len ..] });
            try list.append(state.allocator, try state.allocator.dupe(u8, expanded_candidate));
        }
    }

    if (std.mem.find(u8, expanded, "${LIB}")) |idx| {
        for (lib_values) |lv| {
            const expanded_candidate = try std.fmt.bufPrint(&expanded_candidate_buf, "{s}{s}{s}", .{ expanded[0..idx], lv, expanded[idx + "${LIB}".len ..] });
            try list.append(state.allocator, try state.allocator.dupe(u8, expanded_candidate));
        }
    }
}

/// Processes `LD_PRELOAD` once. Mark it processed before recursive `load` calls;
/// a missing preload is diagnosed but does not abort the requested root load.
fn loadPreloads() void {
    if (state.preloads_processed) return;
    state.preloads_processed = true;

    const preload_list = state.environ.getPosix("LD_PRELOAD") orelse return;

    var candidates: std.ArrayList([]const u8) = .empty;
    defer candidates.deinit(state.allocator);

    var it = std.mem.tokenizeAny(u8, preload_list, ": \t\n\r");
    while (it.next()) |entry| {
        defer {
            for (candidates.items) |candidate| state.allocator.free(candidate);
            candidates.clearRetainingCapacity();
        }

        appendLdExpansions(&candidates, entry, null) catch |err| {
            logger.err("preload: cannot expand {s}: {}", .{ entry, err });
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
                    const cwd_len = std.process.currentPath(state.io, &cwd_buf) catch |err| {
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

            state.preload_root_indices.ensureUnusedCapacity(state.allocator, 1) catch |err| {
                last_err = err;
                continue;
            };

            const preload_lib = load(real_candidate) catch |err| {
                last_err = err;
                continue;
            };

            if (std.mem.findScalar(usize, state.preload_root_indices.items, preload_lib.index) == null) {
                state.preload_root_indices.appendAssumeCapacity(preload_lib.index);
            }

            logger.info("preload: loaded {s} for {s}", .{ candidate, entry });

            loaded = true;
            break;
        }

        if (!loaded) {
            logger.warn("preload: unable to load {s}: {}", .{ entry, last_err orelse error.LibraryNotFound });
        }
    }
}

// Keep this wrapper to log the exact error after the inner function's cleanup,
// including failures from its initial guards.
fn loadWithRootResolveContext(f_path: []const u8, root_runpath: ?[]const u8, root_origin_dir: ?[]const u8) !DynamicLibrary {
    return loadWithRootResolveContextInner(f_path, root_runpath, root_origin_dir) catch |err| {
        logger.err("load: request={s} error={t}", .{ f_path, err });
        return err;
    };
}

fn loadWithRootResolveContextInner(f_path: []const u8, root_runpath: ?[]const u8, root_origin_dir: ?[]const u8) !DynamicLibrary {
    if (!state.initialized) return error.Uninitialized;
    if (state.deinitializing) return error.LoaderDeinitializing;

    var phase: []const u8 = "dependencies";

    logger.debug("load: request={s} action=begin", .{f_path});
    errdefer {
        logger.debug("load: request={s} action=rollback", .{f_path});
        unloadUnreferencedObjects() catch |err| logger.warn("load: request={s} action=rollback error={t}", .{ f_path, err });
    }
    errdefer logger.err("load: request={s} phase={s} action=failed", .{ f_path, phase });

    loadPreloads();

    const lib: DynamicLibrary = blk: {
        if (state.load_request_cache.get(f_path)) |cached_lib_idx| {
            logger.debug("load: request={s} action=cache_hit object_index={d}", .{ f_path, cached_lib_idx });
            break :blk .{ .index = cached_lib_idx };
        }

        const loaded_lib = try loadDepTree(f_path, root_runpath, root_origin_dir);

        const owned_cache_key = try state.allocator.dupe(u8, f_path);
        errdefer state.allocator.free(owned_cache_key);

        try state.load_request_cache.putNoClobber(state.allocator, owned_cache_key, loaded_lib.index);
        break :blk loaded_lib;
    };

    for (state.dyn_objects.values()[lib.index].deps_breadth_first.items) |dep_idx| {
        if (state.dyn_objects.values()[dep_idx].finalizing) return error.LibraryFinalizing;
    }

    const root_dyn_object = &state.dyn_objects.values()[lib.index];
    for (root_dyn_object.deps_breadth_first.items) |dep_idx| {
        const dep_dyn_object = &state.dyn_objects.values()[dep_idx];
        dep_dyn_object.ref_count += 1;
        logger.debug("load.retain: object={s} references={d}", .{ dep_dyn_object.name, dep_dyn_object.ref_count });
    }

    errdefer for (state.dyn_objects.values()[lib.index].deps_breadth_first.items) |dep_idx| {
        state.dyn_objects.values()[dep_idx].ref_count -= 1;
    };

    logSummary("before_preparation", true);

    // Snapshot indices rather than registry pointers: IFUNC resolvers may load
    // another object and move the registry's backing array.
    phase = "relocation_order";
    const relocation_order = try state.allocator.dupe(usize, state.dyn_objects_sorted_indices.items);
    defer state.allocator.free(relocation_order);

    for (relocation_order) |idx| {
        const dyn_obj = &state.dyn_objects.values()[idx];

        if (dyn_obj.relocated or dyn_obj.mapped_at == 0) continue;

        dyn_obj.pinned = libc.requiresLifetimePin(dyn_obj.name);
        phase = "libc_inspection";
        logger.debug("load.prepare: object={s} object_index={d} pinned={}", .{ dyn_obj.name, idx, dyn_obj.pinned });
        errdefer logger.err("load.prepare: object_index={d} phase={s} action=failed", .{ idx, phase });
        if (try libc.inspectObject(&libc_services, state.allocator, dyn_obj)) |specifics| {
            std.debug.assert(state.libc_runtime == null);
            state.libc_runtime = specifics;
        }

        computeTcbOffset(dyn_obj);
        phase = "relocations";
        try processRelocations(dyn_obj);
        phase = "tls";
        try mapTlsBlock(dyn_obj);
        _dl_debug_state();
        phase = "irelative";
        try processIRelativeRelocations(dyn_obj);
        state.dyn_objects.values()[idx].relocated = true;
    }

    // Constructors need final permissions and registered unwind metadata. Mark
    // initialization before calling native code to prevent recursive repetition.
    phase = "initialization_order";
    const initialization_order = try state.allocator.dupe(usize, state.dyn_objects_sorted_indices.items);
    defer state.allocator.free(initialization_order);

    for (initialization_order) |idx| {
        phase = "permissions_and_debug_metadata";
        const dyn_obj = &state.dyn_objects.values()[idx];
        if (dyn_obj.mapped_at == 0) continue;

        if (!dyn_obj.loaded) {
            try dyn_obj.updateSegmentsPermissions();
            _dl_debug_state();

            dyn_obj.loaded = true;

            const dl_phdr_info = try state.allocator.create(std.posix.dl_phdr_info);
            var dl_phdr_info_registered = false;
            errdefer if (!dl_phdr_info_registered) state.allocator.destroy(dl_phdr_info);

            const owned_path_z = try state.allocator.dupeSentinel(u8, dyn_obj.path, 0);
            errdefer state.allocator.free(owned_path_z);

            dl_phdr_info.* = .{
                .addr = dyn_obj.loaded_at.?,
                .name = owned_path_z.ptr,
                .phdr = @ptrFromInt(dyn_obj.mapped_at + dyn_obj.eh.e_phoff),
                .phnum = dyn_obj.eh.e_phnum,
            };

            logger.debug("unwinding: registering {s} at 0x{x}", .{ dyn_obj.name, dyn_obj.loaded_at.? });

            try CustomSelfInfo.addExtraElf(state.allocator, dl_phdr_info);
            dl_phdr_info_registered = true;
            dyn_obj.phdr_info = dl_phdr_info;
            dyn_obj.phdr_name = owned_path_z;
        }

        if (dyn_obj.ref_count == 0 or dyn_obj.init_called) continue;

        if (dyn_obj.current_epoch == std.math.maxInt(u30)) return error.LibraryGenerationExhausted;

        if (state.libc_runtime) |*specifics| {
            phase = "libc_prepare";
            try specifics.prepareObject(dyn_obj);
        }

        phase = "initialization_bookkeeping";
        try state.dyn_objects_init_indices.ensureUnusedCapacity(state.allocator, 1);
        dyn_obj.current_epoch += 1;

        dyn_obj.init_called = true;
        phase = "constructors";
        var initializing_object = dyn_obj.*;
        callInitFunctions(&initializing_object) catch |err| {
            state.dyn_objects.values()[idx].init_called = false;
            return err;
        };

        try state.dyn_objects_init_indices.append(state.allocator, idx);
    }

    logSummary("after_initialization", false);

    logger.info("load: request={s} object_index={d} action=ready", .{ f_path, lib.index });

    return lib;
}

// TODO replace repeated registry scans with a work list of pending dependencies.
fn loadDepTree(o_path: []const u8, root_runpath: ?[]const u8, root_origin_dir: ?[]const u8) !DynamicLibrary {
    logger.debug("dep tree: checking {s}", .{o_path});

    const lib_idx = try loadDso(o_path, root_runpath, root_origin_dir);
    if (state.dyn_objects.values()[lib_idx].mapped_at != 0) {
        return .{
            .index = lib_idx,
        };
    }

    var has_unloaded = true;
    while (has_unloaded) {
        has_unloaded = false;
        var mapped_count: usize = 0;

        const do_count = state.dyn_objects.count();

        for (0..do_count) |dyn_object_idx| {
            {
                const dyn_object = &state.dyn_objects.values()[dyn_object_idx];

                if (!dyn_object.load_requested) continue;

                logger.debug("dep tree: {d}: checking {s}", .{ dyn_object_idx, dyn_object.name });

                if (dyn_object.mapped_at != 0) {
                    logger.debug("dep tree: {s} is mapped", .{dyn_object.name});
                    continue;
                }
            }

            has_unloaded = true;

            const dyn_object_path = state.dyn_objects.values()[dyn_object_idx].path;
            const idx = try loadDso(
                if (dyn_object_idx == lib_idx) o_path else dyn_object_path,
                if (dyn_object_idx == lib_idx) root_runpath else null,
                if (dyn_object_idx == lib_idx) root_origin_dir else null,
            );

            // TODO establish whether alias resolution and retired-slot reuse guarantee
            // idx == dyn_object_idx before merging these progress checks.
            if (state.dyn_objects.values()[idx].mapped_at != 0) {
                logger.debug("dep tree: {s} has been mapped", .{state.dyn_objects.values()[idx].name});
            }
            if (state.dyn_objects.values()[dyn_object_idx].mapped_at != 0) {
                mapped_count += 1;
            }
        }

        if (has_unloaded and mapped_count == 0 and state.dyn_objects.count() == do_count) {
            for (state.dyn_objects.values(), 0..) |dyn_object, dyn_object_idx| {
                if (dyn_object.mapped_at == 0) {
                    logger.err("dep tree stalled at {d}: {s} => {s}", .{ dyn_object_idx, dyn_object.name, dyn_object.path });
                    break;
                }
            }
            return error.DependencyLoadStalled;
        }
    }

    try logDepTree(&state.dyn_objects.values()[lib_idx]);

    return .{
        .index = lib_idx,
    };
}

// TODO implement current-directory semantics for empty/relative search entries
// and define RPATH/RUNPATH inheritance and native search-path configuration.
/// Returns an owned path. `check_mode` only changes missing-library diagnostics;
/// every candidate is checked for the supported ELF class, machine, and type.
fn resolvePath(requested_path: []const u8, check_mode: bool, requester_name: ?[]const u8, runpath: ?[]const u8, origin_dir: ?[]const u8) ![]const u8 {
    logger.debug("path.search: request={s} requester={?s} runpath={?s} origin={?s} probe={}", .{ requested_path, requester_name, runpath, origin_dir, check_mode });
    var buf: [std.fs.max_path_bytes]u8 = @splat(0);

    if (state.environ.getPosix("LD_LIBRARY_PATH")) |dir_list| {
        var dirs_it = std.mem.splitScalar(u8, dir_list, ':');
        while (dirs_it.next()) |dir| {
            if (dir.len == 0) continue;

            const a_path = if (std.mem.startsWith(u8, dir, "/")) try std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir, requested_path }) else try std.fmt.bufPrint(&buf, "/{s}/{s}", .{ dir, requested_path });

            logger.debug("path.candidate: source=LD_LIBRARY_PATH path={s}", .{a_path});
            std.Io.Dir.accessAbsolute(state.io, a_path, .{ .read = true }) catch |err| {
                logger.debug("path.candidate: path={s} result=unreadable error={t}", .{ a_path, err });
                continue;
            };
            if (!isSupportedElfPath(a_path)) {
                logger.debug("skipping unsupported library candidate {s}", .{a_path});
                continue;
            }

            const path = try std.fmt.allocPrint(state.allocator, "{s}", .{a_path});
            logger.debug("found {s} via LD_LIBRARY_PATH: {s}", .{ requested_path, path });
            return path;
        }
    }

    if (requester_name) |name| {
        // Prefer the loader beside its requesting libc to avoid mixing a custom libc with the system loader.
        if (libc.searchBesideRequester(name, requested_path)) {
            if (origin_dir) |dir| {
                const a_path = try std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir, requested_path });

                logger.debug("path.candidate: source=libc_directory path={s}", .{a_path});
                std.Io.Dir.accessAbsolute(state.io, a_path, .{ .read = true }) catch |err| {
                    logger.debug("path.candidate: path={s} result=unreadable error={t}", .{ a_path, err });
                };
                if (isSupportedElfPath(a_path)) {
                    const path = try std.fmt.allocPrint(state.allocator, "{s}", .{a_path});
                    logger.debug("found {s} next to libc: {s}", .{ requested_path, path });
                    return path;
                }
            }
        }
    }

    if (runpath) |dir_list| {
        var dirs_it = std.mem.splitScalar(u8, dir_list, ':');
        while (dirs_it.next()) |dir| {
            if (dir.len == 0) continue;

            var candidates: std.ArrayList([]const u8) = .empty;
            defer {
                for (candidates.items) |candidate| state.allocator.free(candidate);
                candidates.deinit(state.allocator);
            }

            try appendLdExpansions(&candidates, dir, origin_dir);
            for (candidates.items) |candidate| {
                const a_path = if (std.mem.startsWith(u8, candidate, "/")) try std.fmt.bufPrint(&buf, "{s}/{s}", .{ candidate, requested_path }) else try std.fmt.bufPrint(&buf, "{s}/{s}", .{ candidate, requested_path });

                logger.debug("path.candidate: source=RUNPATH path={s}", .{a_path});
                std.Io.Dir.accessAbsolute(state.io, a_path, .{ .read = true }) catch |err| {
                    logger.debug("path.candidate: path={s} result=unreadable error={t}", .{ a_path, err });
                    continue;
                };
                if (!isSupportedElfPath(a_path)) {
                    logger.debug("skipping unsupported library candidate {s}", .{a_path});
                    continue;
                }

                const path = try std.fmt.allocPrint(state.allocator, "{s}", .{a_path});
                logger.debug("found {s} via RUNPATH: {s}", .{ requested_path, path });
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

        logger.debug("path.candidate: source=default_directory path={s}", .{a_path});
        std.Io.Dir.accessAbsolute(state.io, a_path, .{ .read = true }) catch |err| {
            logger.debug("path.candidate: path={s} result=unreadable error={t}", .{ a_path, err });
            continue;
        };
        if (!isSupportedElfPath(a_path)) {
            logger.debug("skipping unsupported library candidate {s}", .{a_path});
            continue;
        }

        path = try std.fmt.allocPrint(state.allocator, "{s}", .{a_path});

        logger.debug("found {s}: {s}", .{ requested_path, path.? });

        break;
    }

    if (path == null) {
        if (check_mode) {
            logger.debug("cannot find library {s}", .{requested_path});
        } else {
            logger.err("cannot find library {s}", .{requested_path});
        }
    }

    return path orelse error.LibraryNotFound;
}

fn resolveDynObjectInfosByNameOrPath(name_or_path: []const u8, requester_name: ?[]const u8, runpath: ?[]const u8, origin_dir: ?[]const u8) !ResolvedDynObjectInfos {
    const path: []const u8 = if (std.mem.findScalar(u8, name_or_path, '/') != null)
        try state.allocator.dupe(u8, name_or_path)
    else
        try resolvePath(name_or_path, false, requester_name, runpath, origin_dir);
    errdefer state.allocator.free(path);

    const f = try std.Io.Dir.openFileAbsolute(state.io, path, .{ .mode = .read_only });
    defer f.close(state.io);

    const stat = try f.stat(state.io);
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;
    if (size < @sizeOf(std.elf.Elf64_Ehdr)) return error.NotAnElfFile;

    var eh: std.elf.Elf64_Ehdr = undefined;
    const read = try f.readPositional(state.io, &.{std.mem.asBytes(&eh)}, 0);
    if (read != @sizeOf(std.elf.Elf64_Ehdr)) return error.NotAnElfFile;
    try validateSupportedElfHeader(path, &eh);

    return .{
        .key = .{ .ino = stat.inode },
        .path = path,
    };
}

fn collectDepsBreadthFirst(dyn_object: *DynObject) !void {
    var queue: std.ArrayList(usize) = .empty;
    defer queue.deinit(state.allocator);

    try queue.append(state.allocator, state.dyn_objects.getIndex(dyn_object.key).?);

    while (queue.items.len > 0) {
        const dep_idx = queue.orderedRemove(0);
        if (std.mem.findScalar(usize, dyn_object.deps_breadth_first.items, dep_idx) == null) {
            try dyn_object.deps_breadth_first.append(state.allocator, dep_idx);
        }

        const dep = &state.dyn_objects.values()[dep_idx];
        for (dep.dependencies.items) |sdep_idx| {
            if (std.mem.findScalar(usize, dyn_object.deps_breadth_first.items, sdep_idx)) |_| continue;
            if (std.mem.findScalar(usize, queue.items, sdep_idx)) |_| continue;
            try queue.append(state.allocator, sdep_idx);
        }
    }

    if (logger.level == .debug and dyn_object.deps_breadth_first.items.len > 0) {
        logger.debug("deps breadth first: {s} => {s}", .{ dyn_object.name, dyn_object.path });
        for (dyn_object.deps_breadth_first.items) |dep_idx| {
            const dep = &state.dyn_objects.values()[dep_idx];
            logger.debug("deps breadth first:   - {s} => {s}", .{ dep.name, dep.path });
        }
    }
}

// ELF inspection, object population, and segment mapping.
// -------------------------------------------------------

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

        return std.mem.bytesAsSlice(T, try DynObject.virtualFileRange(bytes, phdrs, address, size));
    }
};

fn checkSupportedElfHeader(eh: *const std.elf.Elf64_Ehdr) error{
    NotAnElfFile,
    UnsupportedElfClass,
    UnsupportedElfEndian,
    UnsupportedElfMachine,
    UnsupportedElfType,
}!void {
    if (!std.mem.eql(u8, eh.e_ident[0..4], std.elf.MAGIC)) return error.NotAnElfFile;
    if (eh.e_ident[std.elf.EI_CLASS] != std.elf.ELFCLASS64) return error.UnsupportedElfClass;
    if (eh.e_ident[std.elf.EI_DATA] != std.elf.ELFDATA2LSB) return error.UnsupportedElfEndian;
    if (eh.e_machine != std.elf.EM.X86_64) return error.UnsupportedElfMachine;
    if (eh.e_type != .DYN) return error.UnsupportedElfType;
}

fn validateSupportedElfHeader(path: []const u8, eh: *const std.elf.Elf64_Ehdr) !void {
    checkSupportedElfHeader(eh) catch |err| {
        switch (err) {
            error.NotAnElfFile => {},
            error.UnsupportedElfClass => {
                logger.err("unsupported ELF class for {s}: class={d} data={d} version={d} type={} machine=0x{x} expected_machine=0x{x}", .{ path, eh.e_ident[std.elf.EI_CLASS], eh.e_ident[std.elf.EI_DATA], eh.e_ident[std.elf.EI_VERSION], eh.e_type, @backingInt(eh.e_machine), @backingInt(std.elf.EM.X86_64) });
            },
            error.UnsupportedElfEndian => {
                logger.err("unsupported ELF data encoding for {s}: class={d} data={d} version={d} type={} machine=0x{x} expected_machine=0x{x}", .{ path, eh.e_ident[std.elf.EI_CLASS], eh.e_ident[std.elf.EI_DATA], eh.e_ident[std.elf.EI_VERSION], eh.e_type, @backingInt(eh.e_machine), @backingInt(std.elf.EM.X86_64) });
            },
            error.UnsupportedElfMachine => {
                logger.err("unsupported ELF machine for {s}: class={d} data={d} version={d} type={} machine=0x{x} expected_machine=0x{x}", .{ path, eh.e_ident[std.elf.EI_CLASS], eh.e_ident[std.elf.EI_DATA], eh.e_ident[std.elf.EI_VERSION], eh.e_type, @backingInt(eh.e_machine), @backingInt(std.elf.EM.X86_64) });
            },
            error.UnsupportedElfType => {
                logger.err("unsupported ELF type for {s}: class={d} data={d} version={d} type={} machine=0x{x} expected_type={}", .{ path, eh.e_ident[std.elf.EI_CLASS], eh.e_ident[std.elf.EI_DATA], eh.e_ident[std.elf.EI_VERSION], eh.e_type, @backingInt(eh.e_machine), std.elf.ET.DYN });
            },
        }
        return err;
    };
}

fn isSupportedElfPath(path: []const u8) bool {
    const f = std.Io.Dir.openFileAbsolute(state.io, path, .{ .mode = .read_only }) catch return false;
    defer f.close(state.io);

    var eh: std.elf.Elf64_Ehdr = undefined;
    const read = f.readPositional(state.io, &.{std.mem.asBytes(&eh)}, 0) catch return false;
    if (read != @sizeOf(std.elf.Elf64_Ehdr)) return false;

    checkSupportedElfHeader(&eh) catch return false;
    return true;
}

fn validateElfMemoryRangeAccess(phdrs: []align(1) const std.elf.Elf64.Phdr, address: usize, size: usize, access: enum { write, execute }) !void {
    for (phdrs) |ph| {
        if (ph.type != .LOAD or address < ph.vaddr) continue;

        const offset = address - ph.vaddr;
        if (offset <= ph.memsz and size <= ph.memsz - offset) {
            switch (access) {
                .write => if (!ph.flags.W) return error.UnsupportedTextRelocation,
                .execute => if (!ph.flags.X) return error.InvalidRelocationResolver,
            }
            return;
        }
    }

    return error.AddressNotInMappedSegments;
}

fn elfDynamicEntries(bytes: []const u8, phdrs: []align(1) const std.elf.Elf64.Phdr, ph: std.elf.Elf64.Phdr) ![]align(1) const std.elf.Dyn {
    if (ph.filesz % @sizeOf(std.elf.Dyn) != 0) return error.InvalidDynamicSection;

    const table = try DynObject.checkedSliceRange(bytes, ph.offset, ph.filesz);
    if ((try DynObject.virtualFileRange(bytes, phdrs, ph.vaddr, ph.filesz)).ptr != table.ptr) return error.InvalidDynamicSection;

    const entries = std.mem.bytesAsSlice(std.elf.Dyn, table);
    for (entries, 0..) |entry, idx| {
        if (entry.d_tag == std.elf.DT_NULL) return entries[0..idx];
    }

    return error.UnterminatedDynamicSection;
}

fn appendRelaRelocations(relocs: *RelocList, entries: []align(1) const std.elf.Elf64_Rela, phdrs: []align(1) const std.elf.Elf64.Phdr, sym_count: usize) !void {
    // Each table contributes at most one record per entry; NONE entries are
    // skipped. Reserve once, including any records from earlier tables.
    try relocs.ensureUnusedCapacity(state.allocator, entries.len);

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
                logger.err("unsupported relocation type: 0x{x}", .{entry.r_type()});
                return error.UnsupportedRelocationType;
            },
        };

        if (entry.r_sym() >= sym_count) return error.InvalidSymbolIndex;
        if ((kind == .RELATIVE or kind == .IRELATIVE) and entry.r_sym() != 0) return error.InvalidRelocationSymbol;

        try validateElfMemoryRangeAccess(phdrs, entry.r_offset, if (kind == .TLSDESC) @sizeOf(TlsDesc) else @sizeOf(usize), .write);

        if (kind == .IRELATIVE) {
            const resolver = std.math.cast(usize, entry.r_addend) orelse return error.InvalidRelocationAddend;
            try validateElfMemoryRangeAccess(phdrs, resolver, 1, .execute);
        }

        logger.debug("  RELA: {s}, sym: 0x{x}, offset: 0x{x}, addend: 0x{x}", .{ @tagName(kind), entry.r_sym(), entry.r_offset, entry.r_addend });

        relocs.appendAssumeCapacity(.{
            .type = kind,
            .is_relr = false,
            .sym_idx = entry.r_sym(),
            .offset = entry.r_offset,
            .addend = entry.r_addend,
        });
    }
}

/// Expands packed RELR entries into ordinary relative-relocation targets. An even
/// entry is an address; an odd entry uses bits 1..63 for the next 63 pointer slots.
/// Bitmap entries require an earlier address and advance even across unset bits.
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
    try validateElfMemoryRangeAccess(phdrs, address, @sizeOf(usize), .write);

    logger.debug("  RELR: offset: 0x{x}", .{address});

    try relocs.append(state.allocator, .{ .type = .RELATIVE, .is_relr = true, .sym_idx = 0, .offset = address, .addend = 0 });
}

/// Parses and maps one object when its dependencies are ready. A successful
/// return can also denote a registered, deferred object with `mapped_at == 0`;
/// `loadDepTree` repeats the pass until all requested dependencies are mapped.
fn loadDso(o_path: []const u8, root_runpath: ?[]const u8, root_origin_dir: ?[]const u8) !usize {
    const path: []const u8 = if (std.mem.findScalar(u8, o_path, '/') != null)
        try state.allocator.dupe(u8, o_path)
    else
        try resolvePath(o_path, false, null, root_runpath, root_origin_dir);
    defer state.allocator.free(path);

    const dyn_object_name = try state.allocator.dupe(u8, std.fs.path.basename(path));
    defer state.allocator.free(dyn_object_name);

    try libc.checkCompatibleObject(dyn_object_name, path, state.dyn_objects.values());

    const f = try std.Io.Dir.openFileAbsolute(state.io, path, .{ .mode = .read_only });
    var file_open = true;
    errdefer if (file_open) f.close(state.io);

    const stat = try f.stat(state.io);
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;

    const dyn_object_key: DynObjectId = .{ .ino = stat.inode };

    reuseRetiredObjectSlot(dyn_object_key, path);

    if (state.dyn_objects.getPtr(dyn_object_key)) |dyn_object| {
        if (dyn_object.finalizing) return error.LibraryFinalizing;
        dyn_object.load_requested = true;
    }

    if (state.dyn_objects.get(dyn_object_key)) |dyn_object| {
        if (dyn_object.mapped_at != 0) {
            f.close(state.io);
            file_open = false;

            return state.dyn_objects.getIndex(dyn_object_key).?;
        }
    }

    if (size < @sizeOf(std.elf.Elf64_Ehdr)) return error.InvalidElfFileRange;

    logger.debug("loading: {s} [{s}]", .{ o_path, path });

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

    const phdrs = try DynObject.programHeaders(file_bytes, eh);
    if (eh.e_phoff % @alignOf(std.elf.Elf64.Phdr) != 0) return error.InvalidProgramHeaderAlignment;

    for (phdrs) |ph| {
        if (ph.type == .LOAD) {
            if (ph.filesz > ph.memsz) return error.InvalidLoadSegment;
            _ = try DynObject.checkedSliceRange(file_bytes, ph.offset, ph.filesz);
            _ = std.math.add(usize, ph.vaddr, ph.memsz) catch return error.InvalidLoadSegment;
        }
    }

    if (eh.e_shentsize != @sizeOf(std.elf.Elf64.Shdr) or eh.e_shstrndx >= eh.e_shnum) return error.InvalidSectionHeaders;
    if (eh.e_shoff % @alignOf(std.elf.Elf64.Shdr) != 0) return error.InvalidSectionHeaders;
    _ = try DynObject.checkedSliceRange(file_bytes, eh.e_shoff, @as(usize, eh.e_shnum) * @sizeOf(std.elf.Elf64.Shdr));

    if (!state.dyn_objects.contains(dyn_object_key)) {
        const owned_name = try state.allocator.dupe(u8, dyn_object_name);
        errdefer state.allocator.free(owned_name);

        const owned_path = try state.allocator.dupe(u8, path);
        errdefer state.allocator.free(owned_path);

        try state.dyn_objects.putNoClobber(state.allocator, dyn_object_key, .init(dyn_object_key, owned_name, owned_path));
    }

    logger.debug("elf type: {s}", .{@tagName(eh.e_type)});

    logger.debug("sections headers offset: 0x{x}", .{eh.e_shoff});
    logger.debug("sections headers string table index: {d}", .{eh.e_shstrndx});

    const sh_section_strtbl_addr = file_addr + eh.e_shoff + (eh.e_shstrndx * eh.e_shentsize);
    const sh_strtbl: *std.elf.Shdr = @ptrFromInt(sh_section_strtbl_addr);
    _ = try DynObject.checkedSliceRange(file_bytes, sh_strtbl.sh_offset, sh_strtbl.sh_size);
    const sh_strtab_addr: usize = file_addr + sh_strtbl.sh_offset;

    // Section-derived pointers below address the retained read-only file image.
    // Dynamic relocation addresses and program-header addresses are ELF virtual
    // addresses and must be translated separately.
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
        const reusable = state.dyn_objects.getPtr(dyn_object_key).?;
        std.mem.swap(LoadSegmentList, &segments, &reusable.segments);
        std.mem.swap(std.ArrayList(usize), &dependencies, &reusable.dependencies);
        std.mem.swap(RelocList, &relocs, &reusable.relocs);
        dependencies.clearRetainingCapacity();
    }

    errdefer {
        relocs.deinit(state.allocator);
        dependencies.deinit(state.allocator);
        segments.deinit(state.allocator);
    }

    logger.debug("sections headers:", .{});

    var scratch_buf: [1024]u8 = undefined;
    var sh_addr: usize = file_addr + eh.e_shoff;

    var i: usize = 0;
    while (i < eh.e_shnum) : ({
        i += 1;
        sh_addr += eh.e_shentsize;
    }) {
        const sh: *std.elf.Elf64.Shdr = @ptrFromInt(sh_addr);

        if (sh.type != .NOBITS) _ = try DynObject.checkedSliceRange(file_bytes, sh.offset, sh.size);

        const name: [*:0]const u8 = @ptrFromInt(sh_strtab_addr + sh.name);
        logger.debug("  - {d}:", .{i});
        logger.debug("    name: {s}", .{name});
        logger.debug("    link: {d}", .{sh.link});
        logger.debug("    type: 0x{x}", .{sh.type});
        logger.debug("    flags: {b}", .{@as(std.elf.Word, @bitCast(sh.flags.shf))});
        logger.debug("    offset: 0x{x}", .{sh.offset});
        logger.debug("    size: 0x{x}", .{sh.size});

        if (sh.type == .STRTAB) {
            if (logger.level == .debug) {
                logger.debug("    content:", .{});

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
                        if (strs[j] == 0) break;
                    }
                    if (k > 0) {
                        logger.debug("      - {s}", .{scratch_buf[0..k]});
                    }
                }
            }

            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".dynstr")) {
                maybe_dyn_strtab_addr = file_addr + sh.offset;
            } else if (!std.mem.eql(u8, std.mem.sliceTo(name, 0), ".shstrtab")) {
                logger.debug("    == ignored string-table section: {s}", .{name});
            }
        } else if (sh.type == .DYNSYM) {
            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".dynsym")) {
                maybe_dyn_symtab_addr = file_addr + sh.offset;
                maybe_dyn_symtab_size = sh.size;
            } else {
                // TODO locate string, symbol, and version tables through validated dynamic metadata
                // rather than requiring conventional section names.
                logger.debug("    == unrecognized DYNSYM section name: {s}", .{name});
            }
        } else if (sh.type == std.elf.SHT.GNU_VERSYM) {
            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".gnu.version")) {
                versym_tab_addr = file_addr + sh.offset;
            } else {
                logger.debug("    == unrecognized GNU_VERSYM section name: {s}", .{name});
            }
        } else if (sh.type == std.elf.SHT.GNU_VERDEF) {
            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".gnu.version_d")) {
                verdef_tab_addr = file_addr + sh.offset;
            } else {
                logger.debug("    == unrecognized GNU_VERDEF section name: {s}", .{name});
            }
        } else if (sh.type == std.elf.SHT.GNU_VERNEED) {
            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".gnu.version_r")) {
                verneed_tab_addr = file_addr + sh.offset;
            } else {
                logger.debug("    == unrecognized GNU_VERNEED section name: {s}", .{name});
            }
        } else if (sh.type == std.elf.SHT.PROGBITS) {
            if (std.mem.eql(u8, std.mem.sliceTo(name, 0), ".plt.got")) {
                plt_got_addr = sh.addr;
                plt_got_size = sh.size;
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
                std.elf.SHT.GNU_HASH => logger.debug("    == unused GNU_HASH section: {s}", .{name}),
                else => |t| logger.debug("    == ignored section type {s} (0x{x}): {s}", .{ if (@backingInt(t) <= 19) @tagName(t) else "UNKNOWN", @backingInt(t), name }),
            }
        }
    }

    const dyn_strtab_addr = maybe_dyn_strtab_addr orelse {
        logger.err("missing .dynstr for {s} => {s}", .{ dyn_object_name, path });
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

            // Validate the declared stride before dependency loading or symbol iteration.
            for (dyns) |entry| {
                if (entry.d_tag == std.elf.DT_SYMENT and entry.d_val != @sizeOf(std.elf.Elf64.Sym)) {
                    return error.InvalidSymbolEntrySize;
                }
            }

            var runpath_scan_idx: usize = 0;
            while (runpath_scan_idx < dyns.len) : (runpath_scan_idx += 1) {
                if (dyns[runpath_scan_idx].d_tag == std.elf.DT_RUNPATH) {
                    const runpath_z: [*:0]const u8 = @ptrFromInt(dyn_strtab_addr + dyns[runpath_scan_idx].d_val);
                    dyn_runpath = std.mem.span(runpath_z);
                    logger.debug("dep tree: found RUNPATH: {s} => {s}", .{ dyn_object_name, dyn_runpath.? });
                    break;
                }
            }

            var has_unloaded_deps = false;
            var j: usize = 0;
            while (j < dyns.len) : (j += 1) {
                if (dyns[j].d_tag == std.elf.DT_NEEDED) {
                    const dependency_name_z: [*:0]u8 = @ptrFromInt(dyn_strtab_addr + dyns[j].d_val);

                    logger.debug("dep tree: found dependency: {s} => {s}", .{ dyn_object_name, dependency_name_z });

                    const dependency_name_len = std.mem.len(dependency_name_z);
                    const dep_name = dependency_name_z[0..dependency_name_len];

                    if (findDynObjectIndexByName(dep_name)) |dep_idx| {
                        const dep = &state.dyn_objects.values()[dep_idx];
                        if (dep.finalizing) return error.LibraryFinalizing;
                        dep.load_requested = true;
                        if (dep.mapped_at != 0) {
                            logger.debug("dep tree: registering dependency: {s} => {s}", .{ dyn_object_name, dependency_name_z });
                            try dependencies.append(state.allocator, dep_idx);
                        } else {
                            logger.debug("dep tree: {s} loading deferred", .{dyn_object_name});
                            has_unloaded_deps = true;
                        }
                        continue;
                    }

                    const origin_dir = std.fs.path.dirname(path) orelse "/";
                    const resolved_dep = resolveDynObjectInfosByNameOrPath(dep_name, dyn_object_name, dyn_runpath, origin_dir) catch |err| {
                        logger.err("unresolved {s} dependency: {s}: {}", .{ dyn_object_name, dependency_name_z, err });
                        return err;
                    };
                    var resolved_dep_path: ?[]const u8 = resolved_dep.path;
                    errdefer if (resolved_dep_path) |p| state.allocator.free(p);

                    reuseRetiredObjectSlot(resolved_dep.key, resolved_dep.path);

                    const maybe_dep = state.dyn_objects.getPtr(resolved_dep.key);
                    if (maybe_dep == null) {
                        const owned_dep_name = try state.allocator.dupe(u8, dep_name);
                        errdefer state.allocator.free(owned_dep_name);

                        try state.dyn_objects.putNoClobber(state.allocator, resolved_dep.key, .init(resolved_dep.key, owned_dep_name, resolved_dep.path));
                        resolved_dep_path = null;

                        logger.debug("dep tree: {s} loading deferred", .{dyn_object_name});
                        has_unloaded_deps = true;
                    } else {
                        state.allocator.free(resolved_dep_path.?);
                        resolved_dep_path = null;

                        const dep = maybe_dep.?;
                        if (dep.finalizing) return error.LibraryFinalizing;
                        dep.load_requested = true;
                        if (dep.mapped_at != 0) {
                            logger.debug("dep tree: registering dependency: {s} => {s}", .{ dyn_object_name, dependency_name_z });
                            try dependencies.append(state.allocator, state.dyn_objects.getIndex(dep.key).?);
                        } else {
                            logger.debug("dep tree: {s} loading deferred", .{dyn_object_name});
                            has_unloaded_deps = true;
                        }
                    }
                }
            }

            if (has_unloaded_deps) {
                segments.deinit(state.allocator);
                relocs.deinit(state.allocator);
                dependencies.deinit(state.allocator);

                std.posix.munmap(file_bytes);
                f.close(state.io);
                file_open = false;

                return state.dyn_objects.getIndex(dyn_object_key).?;
            }

            break;
        }
    }

    var syms_array: std.ArrayList(DynSym) = .empty;
    var syms: DynSymList = .empty;

    {
        const reusable = state.dyn_objects.getPtr(dyn_object_key).?;
        std.mem.swap(std.ArrayList(DynSym), &syms_array, &reusable.syms_array);
        std.mem.swap(DynSymList, &syms, &reusable.syms);
    }

    errdefer {
        syms_array.deinit(state.allocator);

        for (syms.values()) |*v| v.deinit(state.allocator);
        syms.deinit(state.allocator);
    }

    // Version indices for undefined symbols refer to requirements (`VERNEED`);
    // definitions refer to this object's exported versions (`VERDEF`). Several
    // entries can share a name, so the name map stores symbol-array indices.
    if (versym_tab_addr) |vst_addr| {
        logger.debug("versym table addr: 0x{x}", .{vst_addr});
    }

    const versym_table: ?[*]std.elf.Half = if (versym_tab_addr) |vst| @ptrFromInt(vst) else null;

    if (!found_dynamic) {
        logger.err("no PT_DYNAMIC segment for {s} => {s}", .{ dyn_object_name, path });
        return error.DynamicSectionNotFound;
    }

    const dyn_symtab_addr = maybe_dyn_symtab_addr orelse {
        logger.err("missing .dynsym for {s} => {s} (found_dynamic={})", .{ dyn_object_name, path, found_dynamic });
        return error.DynamicSymbolTableNotFound;
    };
    const dyn_symtab_size = maybe_dyn_symtab_size orelse {
        logger.err("missing .dynsym size for {s} => {s} (found_dynamic={})", .{ dyn_object_name, path, found_dynamic });
        return error.DynamicSymbolTableSizeNotFound;
    };

    logger.debug("dynamic string table addr: 0x{x}", .{dyn_strtab_addr});
    logger.debug("dynamic sym table addr: 0x{x}", .{dyn_symtab_addr});

    logger.debug("{s}: symbols: ", .{dyn_object_name});

    const dyn_sym_count = dyn_symtab_size / @sizeOf(std.elf.Sym);
    logger.debug("{s}: dynamic symbol count: {d}", .{ dyn_object_name, dyn_sym_count });

    try syms_array.ensureTotalCapacity(state.allocator, dyn_sym_count);
    try syms.ensureTotalCapacity(state.allocator, dyn_sym_count);

    for (0..dyn_sym_count) |j| {
        const sym: *std.elf.Elf64.Sym = @ptrFromInt(dyn_symtab_addr + j * @sizeOf(std.elf.Elf64.Sym));

        const strs: [*]u8 = @ptrFromInt(dyn_strtab_addr);
        const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(strs + sym.name)), 0);

        var version: []const u8 = "";
        var ver_sym: ?std.elf.Versym = null;
        var ver_idx: ?u15 = null;

        if (versym_table) |table| {
            ver_sym = @bitCast(table[j]);
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

                            if (aux.next == 0) break;
                            aux = @ptrFromInt(@intFromPtr(aux) + aux.next);
                        }

                        if (curr_def.vn_next == 0) {
                            logger.err("symbol version {d} not found", .{ver_idx.?});
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
                            logger.err("symbol version {d} not found", .{ver_idx.?});
                            return error.SymbolVersionNotFound;
                        }

                        ver_table_cursor += curr_def.next;
                        curr_def = @ptrFromInt(ver_table_cursor);
                    }
                }
            }
        }

        const hidden = sym.other.visibility != .DEFAULT;
        if (logger.level == .debug) {
            logger.debug("{s}  - {d}:", .{ dyn_object_name, j });
            logger.debug("{s}    name: {s}", .{ dyn_object_name, name });
            logger.debug("{s}    ver idx: {?d}", .{ dyn_object_name, if (ver_sym) |vs| vs.VERSION else null });
            logger.debug("{s}    version: {s}", .{ dyn_object_name, version });
            logger.debug("{s}    hidden: {}", .{ dyn_object_name, hidden });
            if (@backingInt(sym.info.type) <= 6) {
                logger.debug("{s}    type: {s}", .{ dyn_object_name, @tagName(sym.info.type) });
            } else {
                logger.debug("{s}    type: {d}", .{ dyn_object_name, @backingInt(sym.info.type) });
            }
            if (@backingInt(sym.info.bind) <= 2) {
                logger.debug("{s}    bind: {s}", .{ dyn_object_name, @tagName(sym.info.bind) });
            } else {
                logger.debug("{s}    bind: {d}", .{ dyn_object_name, @backingInt(sym.info.bind) });
            }
            logger.debug("{s}    value: 0x{x}", .{ dyn_object_name, sym.value });
            logger.debug("{s}    sh idx: 0x{x}", .{ dyn_object_name, sym.shndx });
            logger.debug("{s}    size: 0x{x}", .{ dyn_object_name, sym.size });
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

        const ent = try syms.getOrPut(state.allocator, s.name);
        if (!ent.found_existing) {
            ent.value_ptr.* = .empty;
        }

        try ent.value_ptr.append(state.allocator, syms_array.items.len);
        try syms_array.append(state.allocator, s);
    }

    logger.debug("program headers offset: 0x{x}", .{eh.e_phoff});
    logger.debug("program headers:", .{});

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

        if (logger.level == .debug) {
            logger.debug("  - {d}", .{i});
            logger.debug("    type: 0x{x}", .{ph.type});
            logger.debug("    flags: {b}", .{@as(std.elf.Word, @bitCast(ph.flags))});
            logger.debug("    offset: 0x{x}", .{ph.offset});
            logger.debug("    v_addr: 0x{x}", .{ph.vaddr});
            logger.debug("    fsize: 0x{x}", .{ph.filesz});
            logger.debug("    msize: 0x{x}", .{ph.memsz});
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

            try segments.put(state.allocator, segment.mem_offset, segment);
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

            try segments.put(state.allocator, segment.mem_offset, segment);
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

            var rela_reloc_nb_entry: usize = 0;
            var rela_table: RelocationTable = .{};
            var relr_table: RelocationTable = .{};
            var plt_table: RelocationTable = .{ .entry_size = @sizeOf(std.elf.Elf64_Rela) };
            var plt_reloc_type: usize = 0;
            if (logger.level == .debug) logDynamicEntries(dyn_object_name, dyns);

            for (dyns) |entry| {
                switch (entry.d_tag) {
                    std.elf.DT_RELA => rela_table.address = entry.d_val,
                    std.elf.DT_RELASZ => rela_table.size = entry.d_val,
                    std.elf.DT_RELAENT => rela_table.entry_size = entry.d_val,
                    std.elf.DT_RELACOUNT => rela_reloc_nb_entry = entry.d_val,
                    std.elf.DT_RELR => relr_table.address = entry.d_val,
                    std.elf.DT_RELRSZ => relr_table.size = entry.d_val,
                    std.elf.DT_RELRENT => relr_table.entry_size = entry.d_val,
                    std.elf.DT_REL, std.elf.DT_RELSZ => {
                        if (entry.d_val != 0) return error.UnsupportedRelocationFormat;
                    },
                    std.elf.DT_PLTREL => plt_reloc_type = entry.d_val,
                    std.elf.DT_PLTRELSZ => plt_table.size = entry.d_val,
                    std.elf.DT_JMPREL => plt_table.address = entry.d_val,
                    std.elf.DT_INIT => init_addr = entry.d_val,
                    std.elf.DT_FINI => fini_addr = entry.d_val,
                    std.elf.DT_INIT_ARRAY => init_array_addr = entry.d_val,
                    std.elf.DT_INIT_ARRAYSZ => init_array_size = entry.d_val,
                    std.elf.DT_FINI_ARRAY => fini_array_addr = entry.d_val,
                    std.elf.DT_FINI_ARRAYSZ => fini_array_size = entry.d_val,
                    // TODO handle or reject flags affecting lookup and lifetime.
                    std.elf.DT_FLAGS, std.elf.DT_FLAGS_1 => {},
                    // TODO record SONAME for object alias/reuse semantics.
                    std.elf.DT_SONAME => {},
                    // Consumed earlier, unused by this loader, or diagnostic-only.
                    std.elf.DT_NEEDED,
                    std.elf.DT_RUNPATH,
                    std.elf.DT_STRTAB,
                    std.elf.DT_SYMTAB,
                    std.elf.DT_STRSZ,
                    std.elf.DT_SYMENT,
                    std.elf.DT_VERSYM,
                    std.elf.DT_VERNEED,
                    std.elf.DT_VERNEEDNUM,
                    std.elf.DT_VERDEF,
                    std.elf.DT_VERDEFNUM,
                    std.elf.DT_PLTGOT,
                    std.elf.DT_HASH,
                    std.elf.DT_GNU_HASH,
                    => {},
                    else => {}, // ELF permits additional numeric tags.
                }
            }

            if (logger.level == .debug) {
                logger.debug("dynamic.summary: object={s} runpath={?s} rela_address_elf={?x} rela_bytes={?d} rela_entry_bytes={?d} relative_count={d}", .{ dyn_object_name, dyn_runpath, rela_table.address, rela_table.size, rela_table.entry_size, rela_reloc_nb_entry });
                logger.debug("dynamic.summary: object={s} relr_address_elf={?x} relr_bytes={?d} relr_entry_bytes={?d} plt_address_elf={?x} plt_bytes={?d} plt_entry_bytes={?d} plt_format=0x{x}", .{ dyn_object_name, relr_table.address, relr_table.size, relr_table.entry_size, plt_table.address, plt_table.size, plt_table.entry_size, plt_reloc_type });
                logger.debug("dynamic.summary: object={s} init_elf=0x{x} fini_elf=0x{x} init_array_elf=0x{x} init_array_bytes={d} fini_array_elf=0x{x} fini_array_bytes={d}", .{ dyn_object_name, init_addr, fini_addr, init_array_addr, init_array_size, fini_array_addr, fini_array_size });
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
            // TODO define support or rejection for executable-stack requirements and GNU properties.
            if (logger.level == .debug) {
                const type_name = if (@backingInt(ph.type) <= 8) @tagName(ph.type) else if (ph.type == std.elf.PT.GNU_STACK) "GNU_STACK" else "UNKNOWN";
                logger.debug("    => ignored PT type {s} (0x{x})", .{ type_name, @backingInt(ph.type) });
            }
        }
    }

    if (init_array_size != 0) {
        if (init_array_size % @sizeOf(usize) != 0) return error.InvalidInitArraySize;
        _ = try DynObject.virtualFileRange(file_bytes, phdrs, init_array_addr, init_array_size);
    }
    if (fini_array_size != 0) {
        if (fini_array_size % @sizeOf(usize) != 0) return error.InvalidFiniArraySize;
        _ = try DynObject.virtualFileRange(file_bytes, phdrs, fini_array_addr, fini_array_size);
    }

    const do_entry = try state.dyn_objects.getOrPut(state.allocator, dyn_object_key);
    const previous_dyn_object: ?DynObject = if (do_entry.found_existing) do_entry.value_ptr.* else null;

    {
        const owned_name = try state.allocator.dupe(u8, dyn_object_name);
        errdefer state.allocator.free(owned_name);

        const owned_path = try state.allocator.dupe(u8, path);
        errdefer state.allocator.free(owned_path);

        const owned_runpath = if (dyn_runpath) |runpath| try state.allocator.dupe(u8, runpath) else null;
        errdefer if (owned_runpath) |runpath| state.allocator.free(runpath);

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

    // Ownership has moved into the registry entry. Empty local containers so
    // their error guards cannot release the same allocations a second time.
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

        current_dyn_object.syms_array.deinit(state.allocator);
        for (current_dyn_object.syms.values()) |*v| v.deinit(state.allocator);
        current_dyn_object.syms.deinit(state.allocator);
        current_dyn_object.relocs.deinit(state.allocator);
        current_dyn_object.dependencies.deinit(state.allocator);
        current_dyn_object.deps_breadth_first.deinit(state.allocator);
        current_dyn_object.segments.deinit(state.allocator);

        if (previous_dyn_object) |previous| {
            state.allocator.free(current_name);
            state.allocator.free(current_path);
            if (current_dyn_object.runpath) |runpath| state.allocator.free(runpath);
            current_dyn_object.* = previous;
        } else {
            if (current_dyn_object.runpath) |runpath| state.allocator.free(runpath);
            current_dyn_object.* = .init(dyn_object_key, current_name, current_path);
        }
    };

    const dyn_object = do_entry.value_ptr;

    try collectDepsBreadthFirst(dyn_object);
    try state.dyn_objects_sorted_indices.ensureUnusedCapacity(state.allocator, 1);

    try mapSegments(dyn_object, file_bytes);

    f.close(state.io);
    file_open = false;
    dyn_object.file_handle = -1;

    processRelativeRelocationsFast(dyn_object);

    state.dyn_objects_sorted_indices.appendAssumeCapacity(state.dyn_objects.getIndex(dyn_object_key).?);

    logger.debug("load.map: object={s} path={s} action=mapped_relative_relocated", .{ dyn_object_name, dyn_object.path });

    if (previous_dyn_object) |previous| {
        var previous_to_free = previous;
        previous_to_free.syms_array.deinit(state.allocator);
        for (previous_to_free.syms.values()) |*v| v.deinit(state.allocator);
        previous_to_free.syms.deinit(state.allocator);
        previous_to_free.relocs.deinit(state.allocator);
        previous_to_free.dependencies.deinit(state.allocator);
        previous_to_free.deps_breadth_first.deinit(state.allocator);
        previous_to_free.segments.deinit(state.allocator);
        previous_to_free.binding_dependencies.deinit(state.allocator);
        state.allocator.free(previous_to_free.name);
        state.allocator.free(previous_to_free.path);
        if (previous_to_free.runpath) |runpath| state.allocator.free(runpath);
    }

    dyn_object_installed = false;

    return state.dyn_objects.getIndex(dyn_object_key).?;
}

fn mapSegments(dyn_object: *DynObject, file_bytes: []const u8) !void {
    _ = file_bytes;

    logger.debug("mapping library {s} with {d} segments", .{ dyn_object.name, dyn_object.segments.count() });

    var mem_end: usize = 0;
    var max_align: usize = 0x1000;

    for (dyn_object.segments.values()) |*segment| {
        std.debug.assert(segment.mem_align >= std.heap.pageSize() and segment.mem_align % std.heap.pageSize() == 0);
        const aligned_mem_end = std.mem.alignForward(usize, segment.mem_offset + segment.mem_size, segment.mem_align);
        mem_end = @max(mem_end, aligned_mem_end);
        max_align = @max(max_align, segment.mem_align);
    }

    const original_mem_end = mem_end;

    mem_end += 0x1000; // Reserve a final page for native-call trampolines.

    const total_mem_size = mem_end;

    logger.debug("mapping segments: from file, library loaded size: 0x{x} (0x{x} to 0x{x})", .{ total_mem_size, 0, mem_end });

    const previous_reservation = dyn_object.reservation;
    const reusable_reservation = if (previous_reservation) |reservation| blk: {
        const aligned_base = std.mem.alignForward(usize, @intFromPtr(reservation.ptr), max_align);
        break :blk aligned_base + total_mem_size <= @intFromPtr(reservation.ptr) + reservation.len;
    } else false;

    // Reserve the full address range first. Fixed segment mappings then replace
    // pages inside our own reservation, including anonymous zero-filled tails.
    const mapped_space = if (reusable_reservation) previous_reservation.? else std.posix.mmap(
        null,
        total_mem_size + max_align,
        .{},
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    ) catch |err| {
        logger.err("failed to allocate library space: {s}", .{@errorName(err)});
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

    try dyn_object.segments.put(state.allocator, original_mem_end, extra_segment);

    logger.debug("mapping segments: reserved 0x{x} bytes from 0x{x} to 0x{x}", .{ total_mem_size, base_addr, base_addr + total_mem_size });

    var prev_end: usize = 0;

    for (dyn_object.segments.values(), 0..) |*segment, s| {
        logger.debug("  segment {d}: foff: 0x{x}, moff: 0x{x}, fsize: 0x{x}, msize: 0x{x}", .{ s, segment.file_offset, segment.mem_offset, segment.file_size, segment.mem_size });

        const prot: std.posix.PROT = .{
            .READ = segment.flags_first.read,
            .WRITE = segment.flags_first.write,
            .EXEC = segment.flags_first.exec,
        };

        const aligned_ptr: [*]align(std.heap.pageSize()) u8 = @ptrFromInt(std.mem.alignBackward(usize, base_addr + segment.mem_offset, segment.mem_align));
        const aligned_end: usize = std.mem.alignForward(usize, base_addr + segment.mem_offset + segment.mem_size, segment.mem_align);
        const aligned_size = aligned_end - @intFromPtr(aligned_ptr);
        const aligned_file_offset = std.mem.alignBackward(usize, segment.file_offset, segment.mem_align);

        segment.loaded_at = base_addr + segment.mem_offset;
        segment.mapped_from_file = true;

        logger.debug("  segment {d}: mapping: foff: 0x{x}, aligned foff: 0x{x}, from 0x{x} to 0x{x}, size: 0x{x}", .{ s, segment.file_offset, aligned_file_offset, @as(usize, @intFromPtr(aligned_ptr)), aligned_end, aligned_size });
        logger.debug("  segment {d}: data: from 0x{x} to 0x{x}, size: 0x{x}", .{ s, segment.loaded_at, segment.loaded_at + segment.mem_size, segment.mem_size });

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
            logger.debug("  segment {d}: zeroing from 0x{x} (0x{x}) to 0x{x} (0x{x})", .{
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
                logger.debug("  segment {d}: memory: zeroing from 0x{x} to 0x{x}, size: 0x{x}", .{ s, segment.loaded_at + segment.file_size, zero_start, zero_sub_size });
                @memset(@as([*]u8, @ptrFromInt(segment.loaded_at))[segment.file_size..][0..zero_sub_size], 0);
            }

            if (zero_size > 0) {
                const zero_ptr: [*]align(std.heap.pageSize()) u8 = @ptrFromInt(zero_start);
                logger.debug("  segment {d}: mapping: zeroing from 0x{x} to 0x{x}, size: 0x{x}", .{ s, @intFromPtr(zero_ptr), zero_end, zero_size });
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

    if (!reusable_reservation) {
        if (previous_reservation) |reservation| std.posix.munmap(reservation);
    }
    dyn_object.reservation = mapped_space;
    mapped_space_owned = false;

    logger.debug("successfully mapped {d} segments for {s} at base 0x{x}", .{ dyn_object.segments.count(), dyn_object.name, base_addr });
}

// TLS runtime, allocation, and native entry points.
// -------------------------------------------------

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

const TlsDesc = extern struct {
    tls_desc_resolver: *const fn () callconv(.naked) void,
    tls_desc_resolver_arg: isize,
};

const TlsIndex = extern struct {
    ti_module: usize,
    ti_offset: usize,
};

comptime {
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .linux or @sizeOf(usize) != 8 or builtin.link_libc or builtin.single_threaded) {
        @compileError("DynLoader requires a multithreaded x86_64 Linux no-libc host");
    }

    @export(&ElfTlsRuntime.descriptor, .{ .name = "__zig_elf_static_tls", .linkage = .strong });
    @export(&ElfTlsRuntime.init, .{ .name = "__zig_elf_static_tls_init", .linkage = .strong });
    @export(&ElfTlsRuntime.fill, .{ .name = "__zig_elf_static_tls_fill", .linkage = .strong });
    @export(&ElfTlsRuntime.getAddress, .{ .name = "__tls_get_addr", .linkage = .strong });
}

/// Replaces Zig's executable TLS hooks, including startup before `main`. The
/// published template is used for future Zig threads. Initial executable TLS and
/// library TLS use separate module lookup paths, despite sharing one allocation.
const ElfTlsRuntime = struct {
    // Use `@trap` because panic handling can itself use TLS, allocation, or logging.

    const AreaDesc = struct {
        size: usize,
        alignment: usize,
        dtv: struct { offset: usize },
        abi_tcb: struct { offset: usize },
        block: struct {
            init: []const u8,
            offset: usize,
            size: usize,
        },
        owns_template: bool,
    };

    const Index = extern struct {
        module: usize,
        offset: usize,
    };

    extern var __zig_elf_auxv: [*]std.elf.Auxv;

    var descriptor: extern struct {
        size: usize,
        alignment: usize,
        gdt_entry_number: usize,
    } = undefined;

    var area_desc: AreaDesc = undefined;
    var executable_desc: AreaDesc = undefined;
    var initial_area: [4096]u8 align(4096) = undefined;

    fn publish(desc: AreaDesc) void {
        @setRuntimeSafety(false);
        @disableInstrumentation();

        area_desc = desc;
        descriptor = .{
            .size = desc.size,
            .alignment = desc.alignment,
            .gdt_entry_number = std.math.maxInt(usize),
        };
    }

    fn init(phdrs: [*]std.elf.ElfN.Phdr, phnum: usize) callconv(.c) void {
        @setRuntimeSafety(false);
        @disableInstrumentation();

        var load_base: usize = 0;
        var tls_header: ?std.elf.ElfN.Phdr = null;
        for (phdrs[0..phnum]) |header| {
            switch (header.type) {
                .PHDR => load_base = @intFromPtr(phdrs) - header.vaddr,
                .TLS => tls_header = header,
                else => {},
            }
        }

        const alignment = @max(@alignOf(usize), if (tls_header) |header| header.@"align" else 1);
        if (!std.math.isPowerOfTwo(alignment)) @trap();

        const block_size = if (tls_header) |header| header.memsz else 0;
        const template: []const u8 = if (tls_header) |header|
            @as([*]const u8, @ptrFromInt(load_base + header.vaddr))[0..header.filesz]
        else
            &.{};
        const metadata_size = @sizeOf(AbiTcb) + @sizeOf(ZigTcb) + @sizeOf(Dtv);
        if (template.len > block_size or block_size > std.math.maxInt(usize) - alignment - metadata_size) @trap();

        const tp_offset = std.mem.alignForward(usize, block_size, alignment);
        const dtv_offset = tp_offset + @sizeOf(AbiTcb) + @sizeOf(ZigTcb);

        executable_desc = .{
            .size = dtv_offset + @sizeOf(Dtv),
            .alignment = alignment,
            .dtv = .{ .offset = dtv_offset },
            .abi_tcb = .{ .offset = tp_offset },
            .block = .{
                .init = template,
                .offset = 0,
                .size = block_size,
            },
            .owns_template = false,
        };
        publish(executable_desc);

        const area: [*]u8 = if (descriptor.size <= initial_area.len and alignment <= 4096)
            &initial_area
        else mapping: {
            const mapping_size = @addWithOverflow(descriptor.size, alignment - 1);
            if (mapping_size[1] != 0) @trap();

            const protection: u32 = @bitCast(std.os.linux.PROT{ .READ = true, .WRITE = true });
            const flags: u32 = @bitCast(std.os.linux.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true });
            const address = std.os.linux.syscall6(.mmap, 0, mapping_size[0], protection, flags, std.math.maxInt(usize), 0);
            if (std.os.linux.errno(address) != .SUCCESS) @trap();

            break :mapping @ptrFromInt(std.mem.alignForward(usize, address, alignment));
        };

        const thread_pointer = fill(area);

        if (std.os.linux.syscall2(.arch_prctl, std.os.linux.ARCH.SET_FS, thread_pointer) != 0) @trap();
    }

    fn fill(area: [*]u8) callconv(.c) usize {
        @setRuntimeSafety(false);
        @disableInstrumentation();

        const desc = area_desc;
        @memset(area[0..desc.size], 0);

        const thread_pointer = @intFromPtr(area) + desc.abi_tcb.offset;
        @as(*usize, @ptrFromInt(thread_pointer)).* = thread_pointer;

        const dtv: *[2]usize = @ptrCast(@alignCast(area + desc.dtv.offset));
        dtv.* = .{ 1, @intFromPtr(area) + desc.block.offset };

        @memcpy(area[desc.block.offset..][0..desc.block.init.len], desc.block.init);
        return thread_pointer;
    }

    fn getAddress(index: *const Index) callconv(.c) *anyopaque {
        @setRuntimeSafety(false);
        @disableInstrumentation();

        // This is only used for the main executable.
        // Loaded libraries will use the `__tls_get_addr` substitute we provide
        if (index.module != 1) @trap();

        const thread_pointer = asm ("movq %%fs:0, %[result]"
            : [result] "=r" (-> usize),
        );

        return @ptrFromInt(thread_pointer - executable_desc.abi_tcb.offset + index.offset);
    }
};

/// Assigns a positive distance below TP for x86-64 variant-II TLS. Reuse a retired
/// slot only when both its capacity and alignment satisfy the new object.
fn computeTcbOffset(dyn_object: *DynObject) void {
    logger.debug("computing tcb offset of library {s}", .{dyn_object.name});

    if (dyn_object.tls_capacity >= dyn_object.tls_init_mem_size and
        dyn_object.tls_slot_align >= dyn_object.tls_align and
        dyn_object.tls_capacity != 0)
    {
        logger.debug("tls.slot: object={s} action=reuse offset_below_tp=0x{x} capacity={d} alignment={d}", .{ dyn_object.name, dyn_object.tls_offset, dyn_object.tls_capacity, dyn_object.tls_slot_align });
        return;
    }

    dyn_object.tls_capacity = 0;

    const current_tls_area_desc = state.normal_current_tls_area_desc orelse ElfTlsRuntime.area_desc;

    var new_area_size: usize = 0;
    new_area_size += dyn_object.tls_init_mem_size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, dyn_object.tls_align) else new_area_size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, current_tls_area_desc.alignment) else new_area_size;
    new_area_size += current_tls_area_desc.block.size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, state.initial_tls_align orelse current_tls_area_desc.alignment) else new_area_size;
    const new_abi_tcb_offset = new_area_size;

    dyn_object.tls_offset = new_abi_tcb_offset;
    logger.debug("tls.slot: object={s} action=assign offset_below_tp=0x{x} size={d} alignment={d}", .{ dyn_object.name, dyn_object.tls_offset, dyn_object.tls_init_mem_size, dyn_object.tls_align });
}

/// Adds TLS below the established thread pointer. The first load migrates host
/// TLS; later loads consume reserved surplus so existing TP-relative pointers
/// remain valid. Rebuild the template from original initializers, not live thread
/// values, so new workers start with fresh TLS rather than another thread's state.
fn mapTlsBlock(dyn_object: *DynObject) !void {
    errdefer logger.err("tls.map: object={s} size={d} alignment={d} surplus={d} action=failed", .{ dyn_object.name, dyn_object.tls_init_mem_size, dyn_object.tls_align, state.current_surplus_size });
    logger.debug("mapping tls block of library {s}", .{dyn_object.name});

    if (dyn_object.tls_capacity != 0) {
        try resetTlsSlot(dyn_object);
        return;
    }
    if (dyn_object.tls_init_mem_size == 0 and state.normal_current_tls_area_desc != null) return;

    const current_tls_area_desc = state.normal_current_tls_area_desc orelse ElfTlsRuntime.area_desc;

    var new_area_size: usize = 0;
    new_area_size += dyn_object.tls_init_mem_size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, dyn_object.tls_align) else new_area_size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, current_tls_area_desc.alignment) else new_area_size;
    const prev_block_offset = new_area_size;
    new_area_size += current_tls_area_desc.block.size;
    new_area_size = if (new_area_size > 0) std.mem.alignForward(usize, new_area_size, state.initial_tls_align orelse current_tls_area_desc.alignment) else new_area_size;
    const new_abi_tcb_offset = new_area_size;
    new_area_size += @sizeOf(AbiTcb);
    new_area_size += @sizeOf(ZigTcb);
    new_area_size = std.mem.alignForward(usize, new_area_size, @alignOf(Dtv));
    const new_dtv_offset = new_area_size;
    new_area_size += @sizeOf(Dtv);

    std.debug.assert(new_abi_tcb_offset == dyn_object.tls_offset);
    std.debug.assert(current_tls_area_desc.abi_tcb.offset - current_tls_area_desc.block.offset == new_abi_tcb_offset - prev_block_offset);
    std.debug.assert(prev_block_offset % current_tls_area_desc.alignment == 0);

    logger.debug("tls: ({s}) tdata size: 0x{x}", .{ dyn_object.name, dyn_object.tls_init_file_size });
    logger.debug("tls: ({s}) tbss size: 0x{x}", .{ dyn_object.name, dyn_object.tls_init_mem_size - dyn_object.tls_init_file_size });

    const thread_storage_size = if (state.libc_runtime) |*specifics|
        specifics.threadStorageSize()
    else
        libc.bootstrapThreadStorageSize();
    logger.debug("tls: native thread storage reservation: 0x{x} ({d})", .{ thread_storage_size, thread_storage_size });

    const old_tp = libc.currentThreadPointer();
    const prev_area_addr = old_tp - (new_abi_tcb_offset - prev_block_offset);

    logger.debug("tls: old_tp: 0x{x}, prev area: 0x{x}", .{ old_tp, prev_area_addr });

    var new_area: ?[]u8 = null;
    var owned_tls_mapping: ?[]align(std.heap.pageSize()) u8 = null;
    errdefer if (owned_tls_mapping) |mapping| std.posix.munmap(mapping);

    var area_was_extended = false;
    var remaining_surplus_size = state.current_surplus_size;

    if (!current_tls_area_desc.owns_template) {
        logger.debug("tls: mapping new area (first time): size: 0x{x} (surplus) + 0x{x} (new_area_size) + 0x{x} (native thread storage)", .{ state.current_surplus_size, new_area_size, thread_storage_size });
        const space = std.posix.mmap(null, state.current_surplus_size + new_area_size + thread_storage_size, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0) catch |err| {
            logger.err("failed to allocate tls space: {s}", .{@errorName(err)});
            return err;
        };
        owned_tls_mapping = space;
        logger.debug("tls: setting new area start at 0x{x} (0x{x})", .{ state.current_surplus_size, @intFromPtr(space.ptr) + state.current_surplus_size });
        new_area = space[state.current_surplus_size..];
    } else if (new_area_size > current_tls_area_desc.size and new_area_size <= current_tls_area_desc.size + state.current_surplus_size) {
        logger.debug("tls: extending old area: size: 0x{x} (new_area_size) = 0x{x} (surplus) + 0x{x} (current_area_size)", .{ new_area_size, new_area_size - current_tls_area_desc.size, current_tls_area_desc.size });
        logger.debug("tls: setting new area start at -0x{x} (0x{x})", .{ new_area_size - current_tls_area_desc.size, prev_area_addr - (new_area_size - current_tls_area_desc.size) });
        new_area = @as([*]u8, @ptrFromInt(prev_area_addr - (new_area_size - current_tls_area_desc.size)))[0..new_area_size];
        logger.debug("tls: setting new surplus size: 0x{x}", .{state.current_surplus_size - (new_area_size - current_tls_area_desc.size)});
        remaining_surplus_size -= new_area_size - current_tls_area_desc.size;
        area_was_extended = true;
    } else if (new_area_size > current_tls_area_desc.size) {
        // That would require relocating an established TP.
        logger.err("tls: surplus exhausted: wanted size: 0x{x} (new_area_size) + 0x{x} (native thread storage)", .{ new_area_size, thread_storage_size });

        return error.TlsSurplusExhausted;
    }

    if (new_area != null and dyn_object.tls_init_file_size > 0) {
        logger.debug("tls: copying new block data: from 0x{x} to 0x{x} (size: 0x{x})", .{
            0,
            dyn_object.tls_init_file_size,
            dyn_object.tls_init_file_size,
        });
        @memcpy(new_area.?[0..dyn_object.tls_init_file_size], @as([*]u8, @ptrFromInt(try dyn_object.virtualToLoadedAddress(dyn_object.tls_init_mem_offset, false))));
    }

    if (new_area != null and current_tls_area_desc.block.size > 0 and !area_was_extended) {
        logger.debug("tls: copying previous area block data: from 0x{x} to 0x{x} (size: 0x{x})", .{
            prev_block_offset,
            prev_block_offset + current_tls_area_desc.block.size,
            current_tls_area_desc.block.size,
        });
        @memcpy(new_area.?[prev_block_offset .. prev_block_offset + current_tls_area_desc.block.size], @as([*]u8, @ptrFromInt(old_tp - (new_abi_tcb_offset - prev_block_offset))));
    }

    if (!current_tls_area_desc.owns_template) {
        state.initial_tls_init_file_size = current_tls_area_desc.block.init.len;
        state.initial_tls_init_mem_size = current_tls_area_desc.block.size;
        state.initial_tls_offset = current_tls_area_desc.abi_tcb.offset;
        state.initial_tls_align = current_tls_area_desc.alignment;
        state.initial_tls_init_block = current_tls_area_desc.block.init;

        logger.debug("tls: copying previous area metadata: from 0x{x} to 0x{x} (size: 0x{x})", .{
            new_abi_tcb_offset,
            new_abi_tcb_offset + current_tls_area_desc.size - current_tls_area_desc.abi_tcb.offset,
            current_tls_area_desc.size - current_tls_area_desc.abi_tcb.offset,
        });
        @memcpy(new_area.?[new_abi_tcb_offset..][0 .. current_tls_area_desc.size - current_tls_area_desc.abi_tcb.offset], @as([*]u8, @ptrFromInt(old_tp)));
    }

    logger.debug("tls: allocating new init block: size: 0x{x}", .{new_abi_tcb_offset});
    const new_initial_block = init_blk: {
        const block = try state.allocator.alloc(u8, new_abi_tcb_offset);
        errdefer state.allocator.free(block);

        @memset(block, 0);

        logger.debug("tls: copying initial tdata: from 0x{x} to 0x{x} (size: 0x{x})", .{
            new_abi_tcb_offset - state.initial_tls_offset,
            new_abi_tcb_offset - state.initial_tls_offset + state.initial_tls_init_file_size,
            state.initial_tls_init_file_size,
        });
        if (state.initial_tls_init_file_size > 0) {
            @memcpy(block[new_abi_tcb_offset - state.initial_tls_offset ..][0..state.initial_tls_init_file_size], state.initial_tls_init_block);
        }

        logger.debug("tls: zeroing initial tbss: from 0x{x} to 0x{x} (size: 0x{x})", .{
            new_abi_tcb_offset - state.initial_tls_offset + state.initial_tls_init_file_size,
            new_abi_tcb_offset - state.initial_tls_offset + state.initial_tls_init_mem_size,
            state.initial_tls_init_mem_size - state.initial_tls_init_file_size,
        });
        if (state.initial_tls_init_mem_size > 0) {
            @memset(block[new_abi_tcb_offset - state.initial_tls_offset + state.initial_tls_init_file_size ..][0 .. state.initial_tls_init_mem_size - state.initial_tls_init_file_size], 0);
        }

        for (state.dyn_objects.values()) |*do| {
            if (do.tls_mapped_at != 0) {
                logger.debug("tls: copying {s} tdata: from 0x{x} to 0x{x} (size: 0x{x})", .{
                    do.name,
                    new_abi_tcb_offset - do.tls_offset,
                    new_abi_tcb_offset - do.tls_offset + do.tls_init_file_size,
                    do.tls_init_file_size,
                });
                if (do.tls_init_file_size > 0) {
                    @memcpy(block[new_abi_tcb_offset - do.tls_offset ..][0..do.tls_init_file_size], @as([*]u8, @ptrFromInt(try do.virtualToLoadedAddress(do.tls_init_mem_offset, false))));
                }

                logger.debug("tls: zeroing {s} tbss: from 0x{x} to 0x{x} (size: 0x{x})", .{
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

        logger.debug("tls: copying {s} tdata: from 0x{x} to 0x{x} (size: 0x{x})", .{
            dyn_object.name,
            0,
            dyn_object.tls_init_file_size,
            dyn_object.tls_init_file_size,
        });
        if (dyn_object.tls_init_file_size > 0) {
            @memcpy(block[0..dyn_object.tls_init_file_size], @as([*]u8, @ptrFromInt(try dyn_object.virtualToLoadedAddress(dyn_object.tls_init_mem_offset, false))));
        }

        logger.debug("tls: zeroing {s} tbss: from 0x{x} to 0x{x} (size: 0x{x})", .{
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

    // Initial TLS area:
    //
    //                              --------------------------------------------
    //                              | Executable TLS | ABI TCB | Zig TCB | DTV |
    //                              --------------------------------------------
    //                                               ^
    //                                               TP
    //
    // New TLS area:
    //
    // -------------------------------------------------------------------------
    // | Surplus | Other TLS blocks | Executable TLS | ABI TCB | libc metadata >
    // -------------------------------------------------------------------------
    //                                               ^
    //                                               TP

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

        .owns_template = true,
    };

    owned_tls_mapping = null;

    // Keep logical offsets relative to the active TLS block. The descriptor
    // published to `__zig_elf_static_tls_fill` additionally includes unused
    // surplus before that block and native descriptor storage after TP.
    state.normal_current_tls_area_desc = new_tls_area_desc;
    state.current_surplus_size = remaining_surplus_size;

    new_tls_area_desc.size = state.current_surplus_size + new_area_size + thread_storage_size;
    new_tls_area_desc.dtv.offset += state.current_surplus_size;
    new_tls_area_desc.abi_tcb.offset += state.current_surplus_size;
    new_tls_area_desc.block.offset += state.current_surplus_size;

    ElfTlsRuntime.publish(new_tls_area_desc);
    logger.debug("tls.publish: object={s} template_bytes={d} area_bytes={d} alignment={d} surplus_bytes={d} native_storage_bytes={d}", .{ dyn_object.name, new_block_size, new_tls_area_desc.size, new_align_factor, state.current_surplus_size, thread_storage_size });

    if (current_tls_area_desc.owns_template) state.allocator.free(current_tls_area_desc.block.init);

    if (new_area) |area| {
        const new_tp = @intFromPtr(area.ptr) + new_abi_tcb_offset;

        const new_tcb: *usize = @ptrFromInt(new_tp);
        new_tcb.* = new_tp;

        logger.debug("tls: tls space mapped, new TP: 0x{x}", .{new_tp});

        const e_set_fs = std.os.linux.syscall2(.arch_prctl, std.os.linux.ARCH.SET_FS, new_tp);
        std.debug.assert(e_set_fs == 0);
        logger.debug("tls.activate: object={s} previous_tp_host=0x{x} tp_host=0x{x} migrated={}", .{ dyn_object.name, old_tp, new_tp, old_tp != new_tp });
        if (state.loader_thread_pointer == 0) state.loader_thread_pointer = new_tp;

        if (state.libc_runtime) |*specifics| try specifics.updateRuntimeFields(new_tp);

        dyn_object.tls_offset = new_abi_tcb_offset;
        logger.debug("tls: tls offset: 0x{x}", .{new_abi_tcb_offset});

        dyn_object.tls_mapped_at = @as(usize, @intFromPtr(area.ptr));
    } else {
        logger.debug("tls: {s}: no change to TLS area", .{dyn_object.name});
    }

    dyn_object.tls_capacity = dyn_object.tls_init_mem_size;
    dyn_object.tls_slot_align = dyn_object.tls_align;

    if (dyn_object.tls_capacity != 0) try resetTlsSlot(dyn_object);
}

/// Resets the template and every registered thread's slot when a module is loaded
/// or reloaded. Registry locking protects worker membership during these copies;
/// loader lifecycle serialization remains the caller's responsibility.
fn resetTlsSlot(dyn_object: *DynObject) !void {
    logger.debug("tls.reset: object={s} offset_below_tp=0x{x} capacity={d} initialized_bytes={d}", .{ dyn_object.name, dyn_object.tls_offset, dyn_object.tls_capacity, dyn_object.tls_init_file_size });

    const desc = state.normal_current_tls_area_desc.?;
    const template = @as([*]u8, @constCast(desc.block.init.ptr))[desc.abi_tcb.offset - dyn_object.tls_offset ..][0..dyn_object.tls_capacity];
    @memset(template, 0);

    if (dyn_object.tls_init_file_size != 0) {
        const source: [*]const u8 = @ptrFromInt(try dyn_object.virtualToLoadedAddress(dyn_object.tls_init_mem_offset, false));
        @memcpy(template[0..dyn_object.tls_init_file_size], source[0..dyn_object.tls_init_file_size]);
    }

    const tp = libc.currentThreadPointer();
    @memcpy(@as([*]u8, @ptrFromInt(tp - dyn_object.tls_offset))[0..template.len], template);
    dyn_object.tls_mapped_at = tp - dyn_object.tls_offset;

    state.thread_mutex.lockUncancelable(state.io);
    defer state.thread_mutex.unlock(state.io);

    for (state.thread_infos.values()) |entry| {
        if (entry.handle == tp) continue;
        @memcpy(@as([*]u8, @ptrFromInt(entry.handle - dyn_object.tls_offset))[0..template.len], template);
    }

    if (state.loader_thread_pointer != 0 and state.loader_thread_pointer != tp) {
        @memcpy(@as([*]u8, @ptrFromInt(state.loader_thread_pointer - dyn_object.tls_offset))[0..template.len], template);
    }
}

// The TLSDESC ABI passes the descriptor in `RAX`, not a System V argument
// register. Its second word already contains the signed TP-relative offset;
// return that word without a compiler-generated prologue or other clobbers.
fn tlsDescResolver() callconv(.naked) void {
    asm volatile (
        \\ movq 8(%%rax), %%rax
        \\ ret
    );
}

fn tlsGetAddressSubstitute(tls_index: *TlsIndex) callconv(.c) ?*anyopaque {
    logger.debug("intercepted call: __tls_get_addr({})", .{tls_index});

    const dyn_object_idx = tls_index.ti_module - 1;

    const tp = libc.currentThreadPointer();

    const dyn_object = &state.dyn_objects.values()[dyn_object_idx];
    const addr = tp - dyn_object.tls_offset + tls_index.ti_offset;

    logger.debug("intercepted call: success: __tls_get_addr({{.module = {s}, .offset = 0x{x}}}) = 0x{x}", .{ dyn_object.name, tls_index.ti_offset, addr });

    return @ptrFromInt(addr);
}

fn dlGetTlsStaticInfoSubstitute(size: *usize, alignment: *usize) callconv(.c) void {
    logger.debug("intercepted call: _dl_get_tls_static_info(0x{x}, 0x{x})", .{ @intFromPtr(size), @intFromPtr(alignment) });
    size.* = state.normal_current_tls_area_desc.?.size + state.current_surplus_size;
    alignment.* = state.normal_current_tls_area_desc.?.alignment;
    logger.debug("intercepted call: success: _dl_get_tls_static_info: size={d}, alignment={d}", .{ size.*, alignment.* });
}

// Relocation and symbol resolution.
// ---------------------------------

const DynObjectAddressResult = struct {
    dyn_object_index: usize,
    segment_index: usize,
};

fn processRelativeRelocationsFast(dyn_object: *DynObject) void {
    const base_addr = dyn_object.loaded_at.?;
    for (dyn_object.relocs.items) |reloc| {
        if (reloc.type != .RELATIVE) continue;

        const ptr: *align(1) usize = @ptrFromInt(base_addr + reloc.offset);
        logger.debug("reloc.relative: object={s} target_elf=0x{x} target_host=0x{x} base_host=0x{x} relr={} addend_bits=0x{x}", .{ dyn_object.name, reloc.offset, @intFromPtr(ptr), base_addr, reloc.is_relr, if (reloc.is_relr) ptr.* else @as(usize, @bitCast(reloc.addend)) });
        ptr.* = base_addr +% if (reloc.is_relr) ptr.* else @as(usize, @bitCast(reloc.addend));
    }
}

/// Applies eager symbol bindings after relative relocation. ELF arithmetic uses
/// wrapping pointer-width operations: signed addends are preserved as bit patterns.
/// TLS relocations use symbol offsets, whereas ordinary relocations use host addresses.
fn processRelocations(dyn_object: *DynObject) !void {
    logger.debug("processing relocations for {s}", .{dyn_object.name});

    var reloc_count: usize = 0;

    for (dyn_object.relocs.items) |reloc| {
        if (reloc.type == .RELATIVE) continue; // applied by processRelativeRelocationsFast() after mapping

        logger.debug("reloc: object={s} type={t} target_elf=0x{x} symbol_index={d} addend={d}", .{ dyn_object.name, reloc.type, reloc.offset, reloc.sym_idx, reloc.addend });
        errdefer logger.err("reloc: object={s} type={t} target_elf=0x{x} symbol_index={d} action=failed", .{ dyn_object.name, reloc.type, reloc.offset, reloc.sym_idx });

        const reloc_addr = try dyn_object.virtualToLoadedAddress(reloc.offset, false);
        const ptr: *align(1) usize = @ptrFromInt(reloc_addr);

        switch (reloc.type) {
            .@"64" => {
                reloc_count += 1;
                // R_X86_64_64: S + A
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const value = r64_blk: {
                    if (reloc.addend != 0) break :r64_blk sym.address +% @as(usize, @bitCast(reloc.addend));
                    break :r64_blk if (try getSubstituteAddress(sym, dyn_object, true)) |a| a else sym.address;
                };
                logger.debug("  64: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} + 0x{x})", .{ reloc_addr, reloc.offset, ptr.*, value, sym.value, sym.name, sym.version, reloc.addend });
                ptr.* = value;
            },
            .GLOB_DAT => {
                reloc_count += 1;
                // R_X86_64_GLOB_DAT: S
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const value = if (try getSubstituteAddress(sym, dyn_object, true)) |a| a else sym.address;
                logger.debug("  GLOB_DAT: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} + 0x{x})", .{ reloc_addr, reloc.offset, ptr.*, value, sym.value, sym.name, sym.version, reloc.addend });
                ptr.* = value;
            },
            .JUMP_SLOT => {
                reloc_count += 1;
                // R_X86_64_JUMP_SLOT: S
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const value = if (try getSubstituteAddress(sym, dyn_object, true)) |a| a else sym.address;
                logger.debug("  JUMP_SLOT: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} + 0x{x})", .{ reloc_addr, reloc.offset, ptr.*, value, sym.value, sym.name, sym.version, reloc.addend });
                ptr.* = value;
            },
            .TPOFF64 => {
                reloc_count += 1;
                // R_X86_64_TPOFF64: S + A (TLS offset)
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const tls_offset = state.dyn_objects.values()[sym.dyn_object_idx].tls_offset;
                const value = sym.value +% @as(usize, @bitCast(reloc.addend)) -% tls_offset;
                logger.debug("  TPOFF64: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} - [MODULE_TLS_OFFSET]0x{x} + 0x{x})", .{
                    reloc_addr,
                    reloc.offset,
                    ptr.*,
                    value,
                    sym.value,
                    sym.name,
                    sym.version,
                    tls_offset,
                    reloc.addend,
                });
                ptr.* = @bitCast(value);
            },
            .DTPOFF64 => {
                reloc_count += 1;
                // R_X86_64_DTPOFF64: S + A
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const value = sym.value +% @as(usize, @bitCast(reloc.addend));
                logger.debug("  DTPOFF64: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} + 0x{x})", .{
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
                logger.debug("  DTPMOD64: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} => [MODULE_TLS_ID]0x{x})", .{
                    reloc_addr,
                    reloc.offset,
                    ptr.*,
                    value,
                    sym.value,
                    sym.name,
                    sym.version,
                    tls_module_id,
                });
                ptr.* = @bitCast(value);
            },
            .TLSDESC => {
                reloc_count += 1;
                // R_X86_64_TLSDESC: S + A (TLS offset)
                const sym = try resolveSymbol(dyn_object, reloc.sym_idx);
                const tls_offset = state.dyn_objects.values()[sym.dyn_object_idx].tls_offset;
                const value: TlsDesc = .{
                    .tls_desc_resolver_arg = @bitCast(sym.value +% @as(usize, @bitCast(reloc.addend)) -% tls_offset),
                    .tls_desc_resolver = &tlsDescResolver,
                };
                logger.debug("  TLSDESC: 0x{x} (0x{x}): 0x{x} -> 0x{x} (0x{x}, {s}@{s} - [MODULE_TLS_OFFSET]0x{x} + 0x{x})", .{
                    reloc_addr,
                    reloc.offset,
                    ptr.*,
                    value.tls_desc_resolver_arg,
                    sym.value,
                    sym.name,
                    sym.version,
                    tls_offset,
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
                logger.err("{s}: unhandled relocation type: {s}", .{ dyn_object.name, @tagName(reloc.type) });
                return error.UnhandledReloctationType;
            },
        }
    }

    // TODO prove relocation-time substitution covers every .plt.got entry before
    // removing this mismatch-detection and executable-stub patching fallback.
    if (dyn_object.plt_got_section_size > 0) {
        const PltGotEntry = packed struct {
            inst: u16,
            offset: u32,
            rem: u16,
        };

        std.debug.assert(dyn_object.plt_got_section_size % @sizeOf(PltGotEntry) == 0);

        const nb_entries = dyn_object.plt_got_section_size / @sizeOf(PltGotEntry);

        const entries: []PltGotEntry = @as([*]PltGotEntry, @ptrFromInt(try dyn_object.virtualToLoadedAddress(dyn_object.plt_got_section_offset, false)))[0..nb_entries];

        for (entries, 0..) |*entry, i| {
            const entry_address = dyn_object.plt_got_section_offset + i * @sizeOf(PltGotEntry);
            const target_address = entry_address + @offsetOf(PltGotEntry, "offset") + entry.offset + 4;
            logger.debug(".PLT.GOT entry {d}: faddr: 0x{x}, offset: 0x{x}, target: 0x{x}", .{ i, entry_address, entry.offset, target_address });

            // TODO index relocations by target offset if this fallback remains necessary.
            for (dyn_object.relocs.items) |r| {
                if (r.offset == target_address) {
                    const sym = dyn_object.syms_array.items[r.sym_idx];
                    const r_sym = try resolveSymbol(dyn_object, r.sym_idx);

                    const substitute_addr = try getSubstituteAddress(r_sym, dyn_object, true);
                    if (substitute_addr == null) break;

                    const loaded_target_addr = try dyn_object.virtualToLoadedAddress(target_address, false);
                    const actual_target: *const usize = @ptrFromInt(loaded_target_addr);

                    if (actual_target.* == substitute_addr.?) {
                        @branchHint(.likely);
                        break;
                    }

                    logger.warn(".PLT.GOT target mismatch for {s}: relocation {s}, actual 0x{x}, expected 0x{x}; patching executable stub", .{
                        sym.name,
                        @tagName(r.type),
                        actual_target.*,
                        substitute_addr.?,
                    });

                    // Replace `jmp *{offset}(%rip)`

                    const write_addr = @intFromPtr(entry);
                    const seg_infos = findDynObjectSegmentForLoadedAddr(write_addr) catch null;

                    if (seg_infos) |segment| {
                        try segment.dyn_object.unprotectSegment(segment.segment_index);
                    }

                    const entry_bytes = @as([*]volatile u8, @ptrFromInt(write_addr));
                    entry_bytes[0] = 0xb8; // mov eax
                    entry_bytes[1] = @intCast(substitute_addr.? & 0xff); // imm
                    entry_bytes[2] = @intCast((substitute_addr.? >> 8) & 0xff);
                    entry_bytes[3] = @intCast((substitute_addr.? >> 16) & 0xff);
                    entry_bytes[4] = @intCast((substitute_addr.? >> 24) & 0xff);
                    entry_bytes[5] = 0xff; // jmp rax
                    entry_bytes[6] = 0xe0;

                    if (seg_infos) |segment| {
                        try segment.dyn_object.reprotectSegment(segment.segment_index);
                    }

                    break;
                }
            }
        }
    }

    logger.debug("processed {d} relocations for {s}", .{ reloc_count, dyn_object.name });
}

/// Runs native resolvers only after ordinary relocation and TLS setup. Cache the
/// returned address and retain any managed object containing the implementation,
/// which need not be the object containing the resolver itself.
fn processIRelativeRelocations(dyn_object: *DynObject) !void {
    logger.debug("processing IRELATIVE relocations for {s}", .{dyn_object.name});

    var reloc_count: usize = 0;

    for (dyn_object.relocs.items) |reloc| {
        const reloc_addr = try dyn_object.virtualToLoadedAddress(reloc.offset, false);
        const ptr: *align(1) usize = @ptrFromInt(reloc_addr);

        switch (reloc.type) {
            .RELATIVE, .@"64", .GLOB_DAT, .JUMP_SLOT, .TPOFF64, .DTPOFF64, .DTPMOD64, .TLSDESC => {},
            .IRELATIVE => {
                reloc_count += 1;
                const resolver_addr = try dyn_object.virtualToLoadedAddress(@intCast(reloc.addend), false);
                const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                logger.debug("  IRELATIVE: calling resolver at 0x{x} (0x{x})", .{ resolver_addr, reloc.addend });
                const value = resolver();
                logger.debug("  IRELATIVE: 0x{x} (0x{x}): 0x{x} -> 0x{x}", .{ reloc_addr, reloc.offset, ptr.*, value });
                try recordBindingDependency(dyn_object, value, null);
                ptr.* = value;
                if (state.ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                    std.debug.assert(res_val == value);
                }
                try state.ifunc_resolved_addrs.put(state.allocator, resolver_addr, value);
                try state.irel_resolved_targets.putNoClobber(state.allocator, reloc_addr, value);
            },
            else => {
                logger.err("unhandled relocation type: {s}", .{@tagName(reloc.type)});
                return error.UnhandledReloctationType;
            },
        }
    }

    logger.debug("processed {d} IRELATIVE relocations for {s}", .{ reloc_count, dyn_object.name });
}

// Looks up libc runtime data without invoking IFUNC resolvers or applying
// substitutions; this can run before relocation completes.
// TODO replace registry-order lookup with explicit scopes: private runtime
// metadata should come from its owner, and interposable globals should follow
// relocation lookup precedence.
fn resolveLibcRuntimeSymbol(sym_name: []const u8) !ResolvedSymbol {
    var it = state.dyn_objects.iterator();
    while (it.next()) |entry| {
        const dep_object = entry.value_ptr;

        if (dep_object.syms.get(sym_name)) |dep_sym_list| {
            for (dep_sym_list.items) |dep_sym_idx| {
                const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                if (dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                    if (dep_sym.shidx == std.elf.SHN_ABS) {
                        logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                    }

                    const dep_sym_address = dep_sym.value;

                    var dep_addr = try dep_object.virtualToLoadedAddress(dep_sym_address, false);
                    if (state.ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                        dep_addr = res_addr;
                    }

                    return .{
                        .value = dep_sym.value,
                        .address = dep_addr,
                        .name = dep_sym.name,
                        .version = dep_sym.version,
                        .dyn_object_idx = state.dyn_objects.getIndex(dep_object.key).?,
                        .sym_idx = dep_sym_idx,
                    };
                }

                if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                    logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                }
            }
        }
    }

    return error.UnresolvedSymbol;
}

// TODO share scope traversal and IFUNC resolution between name, versioned-name,
// and relocation lookup while preserving their distinct selection policies.

// TODO synchronize IFUNC cache publication with lookup/load/unload and resolver reentrancy.
/// Selects preload-only, object breadth-first, or global load-order scope. These
/// modes are mutually exclusive where asserted below. `find_next` skips the first
/// object in the supplied dependency scope; it is the current RTLD_NEXT policy.
fn getResolvedSymbolByName(maybe_dyn_object: ?*DynObject, sym_name: []const u8, find_next: bool, only_preload: bool, allow_preload_override: bool) !ResolvedSymbol {
    logger.debug("symbol.lookup: requester={s} symbol={s} next={} preload_only={} preload_override={}", .{ if (maybe_dyn_object) |object| object.name else "<global>", sym_name, find_next, only_preload, allow_preload_override });
    errdefer logger.debug("symbol.lookup: symbol={s} action=failed", .{sym_name});
    std.debug.assert(!(find_next and only_preload));
    std.debug.assert(!(find_next and allow_preload_override));
    std.debug.assert(!(only_preload and allow_preload_override));

    if (only_preload and !find_next) {
        for (state.preload_root_indices.items) |preload_idx| {
            const dep_object = &state.dyn_objects.values()[preload_idx];

            if (dep_object.mapped_at == 0) {
                continue;
            }

            if (dep_object.syms.get(sym_name)) |dep_sym_list| {
                for (dep_sym_list.items) |dep_sym_idx| {
                    const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                    if (dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                        if (dep_sym.shidx == std.elf.SHN_ABS) {
                            logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try dep_object.virtualToLoadedAddress(dep_sym_address, false);

                        if (state.ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (state.ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try state.ifunc_resolved_addrs.put(state.allocator, resolver_addr, value);
                            try state.irel_resolved_targets.putNoClobber(state.allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        return .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = state.dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }

        return error.UnresolvedSymbol;
    }

    if (maybe_dyn_object) |dyn_object| {
        for (dyn_object.deps_breadth_first.items, 0..) |dep_idx, dep_order| {
            const dep_object = &state.dyn_objects.values()[dep_idx];

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
                            logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try dep_object.virtualToLoadedAddress(dep_sym_address, false);

                        if (state.ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (state.ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try state.ifunc_resolved_addrs.put(state.allocator, resolver_addr, value);
                            try state.irel_resolved_targets.putNoClobber(state.allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = state.dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };

                        if (!only_preload) {
                            if (try getSubstituteAddress(res_sym, dep_object, allow_preload_override)) |a| {
                                res_sym.address = a;
                            }
                        }

                        logger.debug("symbol.selected: symbol={s} version={s} provider_index={d} value=0x{x} resolved_host=0x{x}", .{ res_sym.name, res_sym.version, res_sym.dyn_object_idx, res_sym.value, res_sym.address });
                        return res_sym;
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }
    } else {
        for (state.dyn_objects_sorted_indices.items) |dep_idx| {
            const dep_object = &state.dyn_objects.values()[dep_idx];

            if (dep_object.mapped_at == 0) {
                continue;
            }

            if (dep_object.syms.get(sym_name)) |dep_sym_list| {
                for (dep_sym_list.items) |dep_sym_idx| {
                    const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                    if (dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                        if (dep_sym.shidx == std.elf.SHN_ABS) {
                            logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try dep_object.virtualToLoadedAddress(dep_sym_address, false);

                        if (state.ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (state.ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try state.ifunc_resolved_addrs.put(state.allocator, resolver_addr, value);
                            try state.irel_resolved_targets.putNoClobber(state.allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = state.dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };

                        if (!only_preload) {
                            if (try getSubstituteAddress(res_sym, dep_object, allow_preload_override)) |a| {
                                res_sym.address = a;
                            }
                        }

                        logger.debug("symbol.selected: symbol={s} version={s} provider_index={d} value=0x{x} resolved_host=0x{x}", .{ res_sym.name, res_sym.version, res_sym.dyn_object_idx, res_sym.value, res_sym.address });
                        return res_sym;
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }
    }

    return error.UnresolvedSymbol;
}

/// Uses the same scope modes as name lookup but requires an exact version string.
/// Relocation lookup has separate default-version rules in `resolveSymbolInner`.
fn getResolvedSymbolByNameAndVersion(maybe_dyn_object: ?*DynObject, sym_name: []const u8, version: []const u8, find_next: bool, only_preload: bool, allow_preload_override: bool) !ResolvedSymbol {
    logger.debug("symbol.lookup: requester={s} symbol={s} version={s} next={} preload_only={} preload_override={}", .{ if (maybe_dyn_object) |object| object.name else "<global>", sym_name, version, find_next, only_preload, allow_preload_override });
    errdefer logger.debug("symbol.lookup: symbol={s} version={s} action=failed", .{ sym_name, version });
    std.debug.assert(!(find_next and only_preload));
    std.debug.assert(!(find_next and allow_preload_override));
    std.debug.assert(!(only_preload and allow_preload_override));

    if (only_preload and !find_next) {
        for (state.preload_root_indices.items) |preload_idx| {
            const dep_object = &state.dyn_objects.values()[preload_idx];

            if (dep_object.mapped_at == 0) {
                continue;
            }

            if (dep_object.syms.get(sym_name)) |dep_sym_list| {
                for (dep_sym_list.items) |dep_sym_idx| {
                    const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                    if (std.mem.eql(u8, dep_sym.version, version) and dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                        if (dep_sym.shidx == std.elf.SHN_ABS) {
                            logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try dep_object.virtualToLoadedAddress(dep_sym_address, false);

                        if (state.ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (state.ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try state.ifunc_resolved_addrs.put(state.allocator, resolver_addr, value);
                            try state.irel_resolved_targets.putNoClobber(state.allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        return .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = state.dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }

        return error.UnresolvedSymbol;
    }

    if (maybe_dyn_object) |dyn_object| {
        for (dyn_object.deps_breadth_first.items, 0..) |dep_idx, dep_order| {
            const dep_object = &state.dyn_objects.values()[dep_idx];

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
                            logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try dep_object.virtualToLoadedAddress(dep_sym_address, false);

                        if (state.ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (state.ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try state.ifunc_resolved_addrs.put(state.allocator, resolver_addr, value);
                            try state.irel_resolved_targets.putNoClobber(state.allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = state.dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };

                        if (!only_preload) {
                            if (try getSubstituteAddress(res_sym, dep_object, allow_preload_override)) |a| {
                                res_sym.address = a;
                            }
                        }

                        logger.debug("symbol.selected: symbol={s} version={s} provider_index={d} value=0x{x} resolved_host=0x{x}", .{ res_sym.name, res_sym.version, res_sym.dyn_object_idx, res_sym.value, res_sym.address });
                        return res_sym;
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }
    } else {
        for (state.dyn_objects_sorted_indices.items) |dep_idx| {
            const dep_object = &state.dyn_objects.values()[dep_idx];

            if (dep_object.mapped_at == 0) {
                continue;
            }

            if (dep_object.syms.get(sym_name)) |dep_sym_list| {
                for (dep_sym_list.items) |dep_sym_idx| {
                    const dep_sym = dep_object.syms_array.items[dep_sym_idx];
                    if (std.mem.eql(u8, dep_sym.version, version) and dep_sym.shidx != std.elf.SHN_UNDEF and !dep_sym.hidden) {
                        if (dep_sym.shidx == std.elf.SHN_ABS) {
                            logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{dep_sym.name});
                        }

                        const dep_sym_address = dep_sym.value;

                        var dep_addr = try dep_object.virtualToLoadedAddress(dep_sym_address, false);

                        if (state.ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                            logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                            dep_addr = res_addr;
                        } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                            const resolver_addr = dep_addr;
                            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                            logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                            const value = resolver();
                            logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                            if (state.ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                                std.debug.assert(res_val == value);
                            }
                            try state.ifunc_resolved_addrs.put(state.allocator, resolver_addr, value);
                            try state.irel_resolved_targets.putNoClobber(state.allocator, resolver_addr, value);
                            dep_addr = value;
                        }

                        var res_sym: ResolvedSymbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = state.dyn_objects.getIndex(dep_object.key).?,
                            .sym_idx = dep_sym_idx,
                        };

                        if (!only_preload) {
                            if (try getSubstituteAddress(res_sym, dep_object, allow_preload_override)) |a| {
                                res_sym.address = a;
                            }
                        }

                        logger.debug("symbol.selected: symbol={s} version={s} provider_index={d} value=0x{x} resolved_host=0x{x}", .{ res_sym.name, res_sym.version, res_sym.dyn_object_idx, res_sym.value, res_sym.address });
                        return res_sym;
                    }

                    if (dep_sym.shidx != std.elf.SHN_UNDEF and dep_sym.hidden) {
                        logger.debug("WARNING: HIDDEN SYMBOL from dep: {s}", .{dep_sym.name});
                    }
                }
            }
        }
    }

    return error.UnresolvedSymbol;
}

/// Relocation lookup searches self and declared dependencies. Preserve whether
/// the final address came from that scope or from a resolver/cache redirection;
/// only the latter can require retaining a different implementation owner.
const ResolvedBinding = struct {
    symbol: ResolvedSymbol,
    provenance: enum { declared_scope, redirected_address, unresolved_weak },
};

// TODO test and complete scope/preemption, default-version selection, visibility,
// binding, and absolute-symbol semantics across lookup and relocation paths.
fn resolveSymbol(dyn_object: *DynObject, sym_idx: usize) !ResolvedSymbol {
    const binding = try resolveSymbolInner(dyn_object, sym_idx);
    const sym = binding.symbol;
    logger.debug("symbol.bind: requester={s} symbol={s} version={s} provider_index={d} symbol_value=0x{x} resolved_host=0x{x}", .{ dyn_object.name, sym.name, sym.version, sym.dyn_object_idx, sym.value, sym.address });

    // Ordinary definitions come from self or the declared dependency closure,
    // which unloading already follows. Only redirected addresses need an owner.
    switch (binding.provenance) {
        .declared_scope, .unresolved_weak => {},
        .redirected_address => try recordBindingDependency(dyn_object, sym.address, sym.dyn_object_idx),
    }
    return sym;
}

/// Adds a lifetime edge only when the address owner is outside the requester's
/// declared dependency closure. The defining object is merely an ownership hint.
fn recordBindingDependency(dyn_object: *DynObject, address: usize, provider_hint: ?usize) !void {
    const owner_index = owner: {
        // The defining object usually owns the result. Verify the final address:
        // IFUNCs, including cached results, can point into another object.
        if (provider_hint) |index| {
            if (index < state.dyn_objects.count() and state.dyn_objects.values()[index].findSegment(address) != null) {
                break :owner index;
            }
        }

        const target = findDynObjectForLoadedAddr(address) orelse return;
        break :owner target.dyn_object_index;
    };

    if (owner_index != state.dyn_objects.getIndex(dyn_object.key).? and
        std.mem.findScalar(usize, dyn_object.deps_breadth_first.items, owner_index) == null and
        std.mem.findScalar(usize, dyn_object.binding_dependencies.items, owner_index) == null)
    {
        try dyn_object.binding_dependencies.append(state.allocator, owner_index);
        logger.debug("symbol.retain: requester={s} provider_index={d} target_host=0x{x}", .{ dyn_object.name, owner_index, address });
    }
}

fn resolveSymbolInner(dyn_object: *DynObject, sym_idx: usize) !ResolvedBinding {
    if (sym_idx >= dyn_object.syms_array.items.len) return error.InvalidSymbolIndex;

    const sym = dyn_object.syms_array.items[sym_idx];

    if (sym_idx == 0 or sym.shidx != std.elf.SHN_UNDEF) {
        if (sym.bind == .WEAK) {
            logger.debug("WARNING: WEAK SYMBOL: {s}", .{if (sym_idx == 0) "ZERO" else sym.name});
        }

        if (sym.shidx == std.elf.SHN_ABS) {
            logger.debug("WARNING: ABSOLUTE SYMBOL: {s}", .{if (sym_idx == 0) "ZERO" else sym.name});
        }

        const sym_address = sym.value;

        var addr = try dyn_object.virtualToLoadedAddress(sym_address, false);
        var address_redirected = false;

        if (state.ifunc_resolved_addrs.get(addr)) |res_addr| {
            logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ sym.name, addr, res_addr });
            addr = res_addr;
            address_redirected = true;
        } else if (sym.type == std.elf.STT.GNU_IFUNC) {
            const resolver_addr = addr;
            const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
            logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ sym.name, resolver_addr, sym_address });
            const value = resolver();
            logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ sym.name, resolver_addr, sym_address, value });
            if (state.ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                std.debug.assert(res_val == value);
            }
            try state.ifunc_resolved_addrs.put(state.allocator, resolver_addr, value);
            try state.irel_resolved_targets.putNoClobber(state.allocator, resolver_addr, value);
            addr = value;
            address_redirected = true;
        }

        return .{
            .symbol = .{
                .value = sym.value,
                .address = addr,
                .name = sym.name,
                .version = sym.version,
                .dyn_object_idx = state.dyn_objects.getIndex(dyn_object.key).?,
                .sym_idx = sym_idx,
            },
            .provenance = if (address_redirected) .redirected_address else .declared_scope,
        };
    }

    for (dyn_object.deps_breadth_first.items) |dep_idx| {
        const dep_object = &state.dyn_objects.values()[dep_idx];

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
                        logger.debug("WARNING: WEAK SYMBOL from dep: {s}", .{if (sym_idx == 0) "ZERO" else dep_sym.name});
                    }

                    if (dep_sym.shidx == std.elf.SHN_ABS) {
                        logger.debug("WARNING: ABSOLUTE SYMBOL from dep: {s}", .{if (sym_idx == 0) "ZERO" else dep_sym.name});
                    }

                    const dep_sym_address = dep_sym.value;

                    var dep_addr = try dep_object.virtualToLoadedAddress(dep_sym_address, false);
                    var address_redirected = false;

                    if (state.ifunc_resolved_addrs.get(dep_addr)) |res_addr| {
                        logger.debug("ifunc address substitution: {s}: 0x{x} => 0x{x}", .{ dep_sym.name, dep_addr, res_addr });
                        dep_addr = res_addr;
                        address_redirected = true;
                    } else if (dep_sym.type == std.elf.STT.GNU_IFUNC) {
                        const resolver_addr = dep_addr;
                        const resolver: *const fn () callconv(.c) usize = @ptrFromInt(resolver_addr);
                        logger.debug("  IFUNC: calling resolver for {s} at 0x{x} (0x{x})", .{ dep_sym.name, resolver_addr, dep_sym_address });
                        const value = resolver();
                        logger.debug("  IFUNC: {s}: 0x{x} (0x{x}): 0x{x}", .{ dep_sym.name, resolver_addr, dep_sym_address, value });
                        if (state.ifunc_resolved_addrs.get(resolver_addr)) |res_val| {
                            std.debug.assert(res_val == value);
                        }
                        try state.ifunc_resolved_addrs.put(state.allocator, resolver_addr, value);
                        try state.irel_resolved_targets.putNoClobber(state.allocator, resolver_addr, value);
                        dep_addr = value;
                        address_redirected = true;
                    }

                    return .{
                        .symbol = .{
                            .value = dep_sym.value,
                            .address = dep_addr,
                            .name = dep_sym.name,
                            .version = dep_sym.version,
                            .dyn_object_idx = dep_idx,
                            .sym_idx = dep_sym_idx,
                        },
                        .provenance = if (address_redirected) .redirected_address else .declared_scope,
                    };
                }

                if (dep_sym.shidx == std.elf.SHN_UNDEF) logger.debug("WARNING: SKIPPING UNDEF SYMBOL from dep: {s} | {s}@{s}", .{ dep_object.name, dep_sym.name, dep_sym.version });
                if (dep_sym.hidden) logger.debug("WARNING: SKIPPING HIDDEN SYMBOL from dep: {s} | {s}@{s}", .{ dep_object.name, dep_sym.name, dep_sym.version });
                if (!version_matches) logger.debug("WARNING: SKIPPING MISVERSIONED SYMBOL from dep: {s} | {s} ({s} vs {s})", .{ dep_object.name, dep_sym.name, sym.version, dep_sym.version });
            }
        }
    }

    if (sym.bind == .WEAK) {
        logger.debug("symbol.bind: requester={s} symbol={s} version={s} result=unresolved_weak value=0", .{ dyn_object.name, sym.name, sym.version });

        if (sym.shidx == std.elf.SHN_ABS) {
            logger.debug("WARNING: UNRESOLVED WEAK ABSOLUTE SYMBOL: {s}", .{if (sym_idx == 0) "ZERO" else sym.name});
        }

        return .{
            .symbol = .{
                .value = 0,
                .address = 0,
                .name = sym.name,
                .version = sym.version,
                .dyn_object_idx = std.math.maxInt(usize),
                .sym_idx = std.math.maxInt(usize),
            },
            .provenance = .unresolved_weak,
        };
    }

    logger.err("symbol.bind: requester={s} symbol={s} version={s} result=unresolved", .{ dyn_object.name, sym.name, sym.version });
    if (logger.level != .none) {
        logger.err("searched:", .{});
        for (dyn_object.deps_breadth_first.items) |dep_idx| {
            const dep_object = &state.dyn_objects.values()[dep_idx];
            logger.err("  - {s}", .{dep_object.name});
        }
    }
    return error.UnresolvedSymbol;
}

fn findDynObjectIndexByName(name: []const u8) ?usize {
    for (state.dyn_objects.values(), 0..) |dyn_object, dyn_object_idx| {
        if (std.mem.eql(u8, name, dyn_object.name)) return dyn_object_idx;
    }

    return null;
}

fn findDynObjectForLoadedAddr(addr: usize) ?DynObjectAddressResult {
    for (state.dyn_objects.values(), 0..) |*dyn_object, dyn_object_idx| {
        if (dyn_object.findSegment(addr)) |segment_index| {
            return .{
                .dyn_object_index = dyn_object_idx,
                .segment_index = segment_index,
            };
        }
    }

    // TODO represent host executable mappings and unwind metadata as well as managed DSOs.

    return null;
}

fn findDynObjectSegmentForLoadedAddr(addr: usize) !DynObjectSegmentResult {
    const object_result = findDynObjectForLoadedAddr(addr) orelse return error.LoadedAddressNotMapped;
    const dyn_object = &state.dyn_objects.values()[object_result.dyn_object_index];

    for (dyn_object.syms_array.items, 0..) |*sym, sym_idx| {
        const sym_addr = try dyn_object.virtualToLoadedAddress(sym.value, false);
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

// Object initialization and retirement.
// -------------------------------------

fn callInitFunctions(dyn_obj: *DynObject) !void {
    errdefer logger.err("init: object={s} action=failed", .{dyn_obj.name});
    if (state.libc_runtime) |*specifics| try specifics.beforeConstructors(dyn_obj.name);

    if (dyn_obj.init_addr != 0) {
        const initial_addr = dyn_obj.init_addr;
        const actual_addr = try dyn_obj.virtualToLoadedAddress(dyn_obj.init_addr, false);

        logger.debug("init: object={s} function_host=0x{x} function_elf=0x{x} action=call", .{ dyn_obj.name, actual_addr, initial_addr });
        libc.callInitializer(dyn_obj.name, actual_addr, .{ .args = state.args, .environ = state.environ });
        logger.debug("init: object={s} function_host=0x{x} action=returned", .{ dyn_obj.name, actual_addr });
    }

    if (dyn_obj.init_array_addr != 0 and dyn_obj.init_array_size > 0) {
        const num_funcs = dyn_obj.init_array_size / @sizeOf(usize);
        logger.debug("calling {d} init_array functions for {s} (0x{x})", .{ num_funcs, dyn_obj.name, dyn_obj.init_array_addr });

        if (dyn_obj.init_array_size % @sizeOf(usize) != 0) return error.InvalidInitArraySize;

        const initial_init_array: [*]align(1) const usize = @ptrFromInt(try dyn_obj.virtualToFileAddress(dyn_obj.init_array_addr, dyn_obj.init_array_size));
        const actual_init_array: [*]align(1) const usize = @ptrFromInt(try dyn_obj.virtualToLoadedAddress(dyn_obj.init_array_addr, false));

        for (0..num_funcs) |i| {
            const initial_addr = initial_init_array[i];
            const actual_addr = actual_init_array[i];

            if (actual_addr == 0) {
                logger.debug("skipping call to init_array[{d}]: null addr (initial address: 0x{x})", .{ i, initial_addr });
                continue;
            }

            logger.debug("init: object={s} array_index={d} function_host=0x{x} initial_value=0x{x} action=call", .{ dyn_obj.name, i, actual_addr, initial_addr });
            libc.callInitializer(dyn_obj.name, actual_addr, .{ .args = state.args, .environ = state.environ });
            logger.debug("init: object={s} array_index={d} function_host=0x{x} action=returned", .{ dyn_obj.name, i, actual_addr });
        }
    }
}

fn callFiniFunctions(dyn_obj: *DynObject) !void {
    errdefer logger.err("fini: object={s} action=failed", .{dyn_obj.name});
    if (dyn_obj.fini_array_addr != 0 and dyn_obj.fini_array_size > 0) {
        const num_funcs = dyn_obj.fini_array_size / @sizeOf(usize);
        logger.debug("calling {d} fini_array functions for {s} (0x{x})", .{ num_funcs, dyn_obj.name, dyn_obj.fini_array_addr });

        if (dyn_obj.fini_array_size % @sizeOf(usize) != 0) return error.InvalidFiniArraySize;

        const initial_fini_array: [*]align(1) const usize = @ptrFromInt(try dyn_obj.virtualToFileAddress(dyn_obj.fini_array_addr, dyn_obj.fini_array_size));
        const actual_fini_array: [*]align(1) const usize = @ptrFromInt(try dyn_obj.virtualToLoadedAddress(dyn_obj.fini_array_addr, false));

        var i: usize = num_funcs;
        while (i > 0) {
            i -= 1;

            const initial_addr = initial_fini_array[i];
            const actual_addr = actual_fini_array[i];

            if (actual_addr == 0) {
                logger.debug("skipping call to fini_array[{d}]: null addr (initial address: 0x{x})", .{ i, initial_addr });
                continue;
            }

            logger.debug("fini: object={s} array_index={d} function_host=0x{x} initial_value=0x{x} action=call", .{ dyn_obj.name, i, actual_addr, initial_addr });

            const func = @as(*const fn () callconv(.c) void, @ptrFromInt(actual_addr));
            func();
            logger.debug("fini: object={s} array_index={d} function_host=0x{x} action=returned", .{ dyn_obj.name, i, actual_addr });
        }
    }

    if (dyn_obj.fini_addr != 0) {
        const initial_addr = dyn_obj.fini_addr;
        const actual_addr = try dyn_obj.virtualToLoadedAddress(dyn_obj.fini_addr, false);

        logger.debug("fini: object={s} function_host=0x{x} function_elf=0x{x} action=call", .{ dyn_obj.name, actual_addr, initial_addr });

        const func = @as(*const fn () callconv(.c) void, @ptrFromInt(actual_addr));
        func();
        logger.debug("fini: object={s} function_host=0x{x} action=returned", .{ dyn_obj.name, actual_addr });
    }
}

/// Computes reachability from explicit references, pinned runtime objects, active
/// finalization, and pending TLS destructors. Binding edges also retain objects
/// selected by IFUNCs or preloads outside the declared dependency graph.
/// Run all retiring finalizers before removing any of their mappings.
fn unloadUnreferencedObjects() !void {
    const keep = try state.allocator.alloc(bool, state.dyn_objects.count());
    defer state.allocator.free(keep);

    for (state.dyn_objects.values(), keep) |dyn_object, *live| {
        live.* = dyn_object.ref_count != 0 or dyn_object.pinned or dyn_object.finalizing or dyn_object.tls_destructors != 0;
        logger.debug("unload.roots: object={s} retained={} references={d} pinned={} finalizing={} tls_destructors={d}", .{ dyn_object.name, live.*, dyn_object.ref_count, dyn_object.pinned, dyn_object.finalizing, dyn_object.tls_destructors });
    }

    var changed = true;
    while (changed) {
        changed = false;
        for (state.dyn_objects.values(), keep) |dyn_object, live| {
            if (!live) continue;

            for (dyn_object.dependencies.items) |idx| {
                if (!keep[idx]) {
                    logger.debug("unload.retain: object_index={d} owner={s} reason=dependency", .{ idx, dyn_object.name });
                    keep[idx] = true;
                    changed = true;
                }
            }
            for (dyn_object.binding_dependencies.items) |idx| {
                if (!keep[idx]) {
                    logger.debug("unload.retain: object_index={d} owner={s} reason=symbol_binding", .{ idx, dyn_object.name });
                    keep[idx] = true;
                    changed = true;
                }
            }
        }
    }

    var retiring: std.ArrayList(usize) = .empty;
    defer retiring.deinit(state.allocator);

    try retiring.ensureTotalCapacity(state.allocator, state.dyn_objects.count());

    var remaining = state.dyn_objects_init_indices.items.len;
    while (remaining != 0) {
        remaining -= 1;
        const idx = state.dyn_objects_init_indices.items[remaining];
        if (!keep[idx]) {
            retiring.appendAssumeCapacity(idx);
        }
    }

    for (state.dyn_objects_sorted_indices.items) |idx| {
        if (!keep[idx] and std.mem.findScalar(usize, retiring.items, idx) == null) {
            retiring.appendAssumeCapacity(idx);
        }
    }

    for (retiring.items) |idx| {
        state.dyn_objects.values()[idx].finalizing = true;
    }

    var fini_error: ?anyerror = null;
    for (retiring.items) |idx| {
        const dyn_object = &state.dyn_objects.values()[idx];
        if (!dyn_object.init_called) continue;

        dyn_object.init_called = false;
        var finalizing_object = dyn_object.*;
        callFiniFunctions(&finalizing_object) catch |err| {
            logger.err("unload.fini: object={s} error={t}", .{ finalizing_object.name, err });
            fini_error = err;
        };
    }

    for (retiring.items) |idx| try retireObject(idx);

    for (state.dyn_objects.values(), 0..) |*dyn_object, idx| {
        if (dyn_object.mapped_at == 0) {
            dyn_object.load_requested = false;
            dyn_object.key.retired_slot = idx + 1;
            state.dyn_objects.setKey(idx, dyn_object.key);
        }
    }

    if (fini_error) |err| return err;
}

/// Invalidates debug/cache/handle references before discarding mapped contents.
/// Retain the address reservation and TLS capacity for a later compatible load;
/// the epoch distinguishes that load from handles issued for this one.
fn retireObject(idx: usize) !void {
    const dyn_object = &state.dyn_objects.values()[idx];
    logger.debug("unload.retire: object={s} object_index={d} epoch={d} action=begin", .{ dyn_object.name, idx, dyn_object.current_epoch });
    errdefer logger.err("unload.retire: object={s} object_index={d} action=failed", .{ dyn_object.name, idx });

    if (dyn_object.phdr_info) |info| CustomSelfInfo.removeExtraElf(state.allocator, info);
    dyn_object.phdr_info = null;

    if (dyn_object.phdr_name) |name| state.allocator.free(name);
    dyn_object.phdr_name = null;

    const base = dyn_object.loaded_at.?;
    const end = base + dyn_object.loaded_size;
    invalidateAddressCache(&state.ifunc_resolved_addrs, base, end);
    invalidateAddressCache(&state.irel_resolved_targets, base, end);

    var i: usize = 0;
    while (i < state.load_request_cache.count()) {
        if (state.load_request_cache.values()[i] == idx) {
            const key = state.load_request_cache.keys()[i];
            state.load_request_cache.swapRemoveAt(i);
            state.allocator.free(key);
        } else {
            i += 1;
        }
    }

    i = 0;
    while (i < state.dl_handles.count()) {
        if (state.dl_handles.values()[i].dyn_object_idx == idx) {
            state.dl_handles.swapRemoveAt(i);
        } else {
            i += 1;
        }
    }

    if (std.mem.findScalar(usize, state.dyn_objects_init_indices.items, idx)) |pos| {
        _ = state.dyn_objects_init_indices.orderedRemove(pos);
    }
    if (std.mem.findScalar(usize, state.dyn_objects_sorted_indices.items, idx)) |pos| {
        _ = state.dyn_objects_sorted_indices.orderedRemove(pos);
    }

    const reservation = dyn_object.reservation.?;
    _ = try std.posix.mmap(reservation.ptr, reservation.len, .{}, .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = true }, -1, 0);

    std.posix.munmap(@as([*]align(std.heap.pageSize()) u8, @ptrFromInt(dyn_object.mapped_at))[0..dyn_object.mapped_size]);
    dyn_object.mapped_at = 0;
    dyn_object.mapped_size = 0;

    dyn_object.key.retired_slot = idx + 1;
    state.dyn_objects.setKey(idx, dyn_object.key);

    dyn_object.loaded_at = null;
    dyn_object.loaded_size = 0;
    dyn_object.loaded = false;
    dyn_object.relocated = false;
    dyn_object.load_requested = false;
    dyn_object.finalizing = false;
    dyn_object.tls_mapped_at = 0;

    dyn_object.syms_array.clearRetainingCapacity();
    for (dyn_object.syms.values()) |*indices| indices.deinit(state.allocator);
    dyn_object.syms.clearRetainingCapacity();

    dyn_object.relocs.clearRetainingCapacity();
    dyn_object.segments.clearRetainingCapacity();
    dyn_object.binding_dependencies.clearRetainingCapacity();

    if (dyn_object.tls_capacity != 0) {
        const desc = state.normal_current_tls_area_desc.?;
        @memset(@as([*]u8, @constCast(desc.block.init.ptr))[desc.abi_tcb.offset - dyn_object.tls_offset ..][0..dyn_object.tls_capacity], 0);
    }
    logger.info("unload.retire: object={s} object_index={d} action=complete reserved_bytes={d} tls_capacity={d}", .{ dyn_object.name, idx, reservation.len, dyn_object.tls_capacity });
}

fn invalidateAddressCache(cache: *std.AutoArrayHashMapUnmanaged(usize, usize), base: usize, end: usize) void {
    var i: usize = 0;
    while (i < cache.count()) {
        const key = cache.keys()[i];
        const value = cache.values()[i];
        if ((key >= base and key < end) or (value >= base and value < end)) {
            cache.swapRemoveAt(i);
        } else {
            i += 1;
        }
    }
}

fn reuseRetiredObjectSlot(key: DynObjectId, path: []const u8) void {
    if (state.dyn_objects.contains(key)) return;
    for (state.dyn_objects.values(), 0..) |*dyn_object, idx| {
        if (dyn_object.mapped_at == 0 and !dyn_object.finalizing and std.mem.eql(u8, dyn_object.path, path)) {
            logger.debug("load.reuse: path={s} object_index={d} previous_epoch={d}", .{ path, idx, dyn_object.current_epoch });
            state.dyn_objects.setKey(idx, key);
            dyn_object.key = key;
            return;
        }
    }
}

// Native libc integration and symbol substitution.
// ------------------------------------------------

// These callbacks borrow registry entries only for the duration of inspection.
// Native runtime state retains mapped addresses rather than pointers into the map.
const libc_services: libc.Services = .{
    .lookupSymbol = &lookupRuntimeSymbol,
    .lookupRuntimeSymbol = &resolveLibcRuntimeSymbol,
    .definingObject = &runtimeSymbolOwner,
    .inspectSymbol = &inspectRuntimeSymbol,
    .findSegment = &findDynObjectSegmentForLoadedAddr,
    .runtimeValues = &runtimeValues,
    .malloc_substitute = @ptrCast(&mallocSubstitute),
    .calloc_substitute = @ptrCast(&callocSubstitute),
    .mq_notify_substitute = @ptrCast(&mqNotifySubstitute),
    .timer_substitutes = .{
        @ptrCast(&TimerCreateSubstitute(0).call),
        @ptrCast(&TimerCreateSubstitute(1).call),
        @ptrCast(&TimerCreateSubstitute(2).call),
        @ptrCast(&TimerCreateSubstitute(3).call),
    },
};

fn lookupRuntimeSymbol(object: *DynObject, name: []const u8, allow_preload_override: bool) !ResolvedSymbol {
    return getResolvedSymbolByName(object, name, false, false, allow_preload_override);
}

fn runtimeSymbolOwner(symbol: ResolvedSymbol) *DynObject {
    return &state.dyn_objects.values()[symbol.dyn_object_idx];
}

fn inspectRuntimeSymbol(object: *DynObject, name: []const u8) !DynObject.Definition {
    const symbol = try lookupRuntimeSymbol(object, name, true);
    const owner = runtimeSymbolOwner(symbol);
    return .{
        .object = owner,
        .symbol = &owner.syms_array.items[symbol.sym_idx],
    };
}

fn runtimeValues() libc.RuntimeValues {
    const tls = state.normal_current_tls_area_desc orelse ElfTlsRuntime.area_desc;
    return .{
        .args = state.args,
        .environ = state.environ,
        .auxv_address = @intFromPtr(ElfTlsRuntime.__zig_elf_auxv),
        .tls_size = tls.size + state.current_surplus_size,
        .tls_align = tls.alignment,
    };
}

const substitutes = std.StaticStringMap(*const anyopaque).initComptime([_]struct { []const u8, *const anyopaque }{
    // Allocation
    .{ "malloc", @ptrCast(&mallocSubstitute) },
    .{ "free", @ptrCast(&freeSubstitute) },
    .{ "calloc", @ptrCast(&callocSubstitute) },
    .{ "realloc", @ptrCast(&reallocSubstitute) },
    .{ "reallocarray", @ptrCast(&reallocarraySubstitute) },
    .{ "aligned_alloc", @ptrCast(&alignedAllocSubstitute) },
    .{ "posix_memalign", @ptrCast(&posixMemalignSubstitute) },
    .{ "memalign", @ptrCast(&alignedAllocSubstitute) },
    .{ "cfree", @ptrCast(&unsubstitutedTrap) },
    .{ "valloc", @ptrCast(&unsubstitutedTrap) },
    .{ "pvalloc", @ptrCast(&unsubstitutedTrap) },
    .{ "malloc_usable_size", @ptrCast(&mallocUsableSizeSubstitute) },

    // Dynamic loading and TLS
    .{ "dlopen", @ptrCast(&dlopenSubstitute) },
    .{ "dlclose", @ptrCast(&dlcloseSubstitute) },
    .{ "dlsym", @ptrCast(&dlsymSubstitute) },
    .{ "dladdr", @ptrCast(&dladdrSubstitute) },
    .{ "dlerror", @ptrCast(&dlerrorSubstitute) },
    .{ "dlvsym", @ptrCast(&dlvsymSubstitute) },
    .{ "dladdr1", @ptrCast(&dladdr1Substitute) },
    .{ "dlinfo", @ptrCast(&dlinfoSubstitute) },
    .{ "dlmopen", @ptrCast(&dlmopenSubstitute) },
    .{ "_dl_get_tls_static_info", @ptrCast(&dlGetTlsStaticInfoSubstitute) },
    .{ "_dl_find_object", @ptrCast(&dlFindObjectSubstitute) },
    .{ "_dl_find_dso_for_object", @ptrCast(&dlFindDsoForObjectSubstitute) },
    .{ "dl_iterate_phdr", @ptrCast(&dlIteratePhdrSubstitute) },
    .{ "__tls_get_addr", @ptrCast(&tlsGetAddressSubstitute) },
    .{ "__cxa_thread_atexit_impl", @ptrCast(&cxaThreadAtExitSubstitute) },
    .{ "__cxa_thread_atexit", @ptrCast(&cxaThreadAtExitSubstitute) },

    // Threads
    .{ "pthread_create", @ptrCast(&pthreadCreateSubstitute) },
    .{ "pthread_exit", @ptrCast(&pthreadExitSubstitute) },
    .{ "pthread_cancel", @ptrCast(&pthreadCancelSubstitute) },
    .{ "pthread_detach", @ptrCast(&pthreadDetachSubstitute) },
    .{ "pthread_join", @ptrCast(&pthreadJoinSubstitute) },
    .{ "pthread_kill", @ptrCast(&pthreadKillSubstitute) },
    .{ "pthread_tryjoin_np", @ptrCast(&unsubstitutedTrap) },
    .{ "pthread_timedjoin_np", @ptrCast(&unsubstitutedTrap) },

    // C11 threads
    .{ "thrd_create", @ptrCast(&unsubstitutedTrap) },
    .{ "thrd_join", @ptrCast(&unsubstitutedTrap) },
    .{ "thrd_exit", @ptrCast(&unsubstitutedTrap) },
    .{ "thrd_detach", @ptrCast(&unsubstitutedTrap) },

    // Async I/O
    .{ "aio_read", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_write", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_fsync", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_error", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_return", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_suspend", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_cancel", @ptrCast(&unsubstitutedTrap) },
    .{ "lio_listio", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_read64", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_write64", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_fsync64", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_error64", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_return64", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_suspend64", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_cancel64", @ptrCast(&unsubstitutedTrap) },
    .{ "lio_listio64", @ptrCast(&unsubstitutedTrap) },
    .{ "aio_init", @ptrCast(&unsubstitutedTrap) },

    // Others
    .{ "getaddrinfo_a", @ptrCast(&unsubstitutedTrap) },
});

/// Chooses a preload override, backend wrapper, or common host substitute. A
/// preload's own lookup suppresses recursive override so it can reach the next
/// implementation. `null` means to keep the resolved native address.
fn getSubstituteAddress(sym: ResolvedSymbol, for_obj: *DynObject, allow_preload_override: bool) anyerror!?usize {
    if (sym.dyn_object_idx == std.math.maxInt(usize)) return null;

    const dyn_object = &state.dyn_objects.values()[sym.dyn_object_idx];

    var for_obj_is_preload_root = false;
    if (state.dyn_objects.getIndex(for_obj.key)) |for_obj_idx| {
        for_obj_is_preload_root = std.mem.findScalar(usize, state.preload_root_indices.items, for_obj_idx) != null;
    }

    if (allow_preload_override and !for_obj_is_preload_root) {
        const preload_sym = getResolvedSymbolByName(null, sym.name, false, true, false) catch |err| switch (err) {
            error.UnresolvedSymbol => null,
            else => return err,
        };
        if (preload_sym) |psym| {
            if (std.mem.findScalar(usize, for_obj.binding_dependencies.items, psym.dyn_object_idx) == null) {
                try for_obj.binding_dependencies.append(state.allocator, psym.dyn_object_idx);
            }
            logger.debug("substitutes: preload override for {s}: 0x{x} => 0x{x}", .{ sym.name, sym.address, psym.address });
            return psym.address;
        }
    }

    const address = select_substitute: {
        if (state.libc_runtime) |*specifics| {
            if (try specifics.selectSymbolSubstitute(sym)) |replacement| break :select_substitute replacement;
        }

        if (substitutes.get(sym.name)) |replacement| {
            break :select_substitute @intFromPtr(replacement);
        }

        break :select_substitute libc.fallbackSubstitute(sym, dyn_object.name, @intFromPtr(&unsubstitutedTrap)) orelse return null;
    };

    if (address == @intFromPtr(&unsubstitutedTrap)) {
        logger.warn("substitutes: {s}: installing trap for [{s}] {s} at 0x{x}", .{ for_obj.name, dyn_object.name, sym.name, sym.address });
    }

    logger.debug("substitutes: {s}: found for {s}: 0x{x} => 0x{x}", .{ dyn_object.name, sym.name, sym.address, address });
    return address;
}

fn unsubstitutedTrap() callconv(.c) noreturn {
    logger.err("intercepted call: failed: unsupported library function", .{});
    @panic("unsupported library function called");
}

// Allocation interception.
// ------------------------

/// The registry key is both the allocation base and caller-visible address.
/// Storage is nonempty even for a zero-size request. Pass its recorded size and
/// alignment unchanged to the allocator when remapping or freeing it.
const TrackedAllocation = struct {
    storage_size: usize,
    requested_size: usize,
    alignment: std.mem.Alignment,
};

/// Requires `alloc_mutex`. Reserve registry capacity before acquiring payload
/// storage so publication cannot fail after the allocation succeeds.
fn allocateTracked(alignment: usize, requested_size: usize) !*anyopaque {
    if (requested_size > std.math.maxInt(isize)) return error.OutOfMemory;

    const storage_size = @max(requested_size, 1);
    const allocation_alignment = std.mem.Alignment.fromByteUnits(alignment);

    try state.extra_allocations.ensureUnusedCapacity(state.allocator, 1);
    const storage = state.alloc_allocator.rawAlloc(storage_size, allocation_alignment, @returnAddress()) orelse return error.OutOfMemory;

    const address = @intFromPtr(storage);
    state.extra_allocations.putAssumeCapacity(address, .{
        .storage_size = storage_size,
        .requested_size = requested_size,
        .alignment = allocation_alignment,
    });

    return @ptrFromInt(address);
}

fn setErrno(value: std.os.linux.E) void {
    state.libc_runtime.?.getErrnoLocation().* = @intCast(@backingInt(value));
}

fn allocationFailure() ?*anyopaque {
    setErrno(.NOMEM);
    return null;
}

fn mallocSubstitute(size: usize) callconv(.c) ?*anyopaque {
    logger.debug("intercepted call: malloc({d})", .{size});

    state.alloc_mutex.lockUncancelable(state.io);
    defer state.alloc_mutex.unlock(state.io);

    const result = allocateTracked(16, size) catch |err| {
        logger.warn("intercepted call: failed: malloc({d}): ENOMEM ({})", .{ size, err });
        return allocationFailure();
    };

    logger.debug("intercepted call: success: malloc({d}) = 0x{x}", .{ size, @intFromPtr(result) });

    return result;
}

fn alignedAllocSubstitute(alignment: usize, size: usize) callconv(.c) ?*anyopaque {
    logger.debug("intercepted call: aligned_alloc({d}, {d})", .{ alignment, size });

    if (!std.math.isPowerOfTwo(alignment)) {
        logger.warn("intercepted call: failed: aligned_alloc({d}, {d}): EINVAL", .{ alignment, size });
        setErrno(.INVAL);
        return null;
    }

    state.alloc_mutex.lockUncancelable(state.io);
    defer state.alloc_mutex.unlock(state.io);

    const result = allocateTracked(@max(alignment, 16), size) catch |err| {
        logger.warn("intercepted call: failed: aligned_alloc({d}, {d}): ENOMEM ({})", .{ alignment, size, err });
        return allocationFailure();
    };

    logger.debug("intercepted call: success: aligned_alloc({d}, {d}) = 0x{x}", .{ alignment, size, @intFromPtr(result) });

    return result;
}

fn posixMemalignSubstitute(memptr: **anyopaque, alignment: usize, size: usize) callconv(.c) c_int {
    const errno_location = state.libc_runtime.?.getErrnoLocation();
    const entry_errno = errno_location.*;
    defer errno_location.* = entry_errno;

    logger.debug("intercepted call: posix_memalign(0x{x}, {d}, {d})", .{ @intFromPtr(memptr), alignment, size });

    if (alignment == 0 or !std.math.isPowerOfTwo(alignment) or alignment % @sizeOf(*anyopaque) != 0) {
        logger.warn("intercepted call: failed: posix_memalign(0x{x}, {d}, {d}): EINVAL", .{ @intFromPtr(memptr), alignment, size });
        return @backingInt(std.os.linux.E.INVAL);
    }

    state.alloc_mutex.lockUncancelable(state.io);
    defer state.alloc_mutex.unlock(state.io);

    const result = allocateTracked(@max(alignment, 16), size) catch |err| {
        logger.warn("intercepted call: failed: posix_memalign(0x{x}, {d}, {d}): ENOMEM ({})", .{ @intFromPtr(memptr), alignment, size, err });
        return @backingInt(std.os.linux.E.NOMEM);
    };

    memptr.* = result;

    logger.debug("intercepted call: success: posix_memalign(0x{x} [-> 0x{x}], {d}, {d}) = 0", .{ @intFromPtr(memptr), @intFromPtr(result), alignment, size });

    return 0;
}

fn freeSubstitute(p: ?*anyopaque) callconv(.c) void {
    const errno_location = state.libc_runtime.?.getErrnoLocation();
    const entry_errno = errno_location.*;
    defer errno_location.* = entry_errno;

    logger.debug("intercepted call: free(0x{x})", .{@intFromPtr(p)});

    state.alloc_mutex.lockUncancelable(state.io);
    defer state.alloc_mutex.unlock(state.io);

    if (p) |pointer| {
        const address = @intFromPtr(pointer);
        if (state.extra_allocations.get(address)) |allocation| {
            const storage = @as([*]u8, @ptrCast(pointer))[0..allocation.storage_size];
            state.alloc_allocator.rawFree(storage, allocation.alignment, @returnAddress());
            _ = state.extra_allocations.swapRemove(address);
        } else {
            // Panic does not run defers; unlock before logging and panicking.
            state.alloc_mutex.unlock(state.io);
            logger.err("intercepted call: failed: free(0x{x}): externally allocated memory", .{@intFromPtr(p)});
            @panic("free failed: externally allocated memory");
        }
    }

    logger.debug("intercepted call: success: free(0x{x}) [{d} allocs remaining]", .{ @intFromPtr(p), state.extra_allocations.count() });
}

/// Reports only recorded backing storage; allocator-internal spare capacity is
/// unknown. Non-null zero-size allocations have one byte of backing storage.
fn mallocUsableSizeSubstitute(p: ?*anyopaque) callconv(.c) usize {
    const errno_location = state.libc_runtime.?.getErrnoLocation();
    const entry_errno = errno_location.*;
    defer errno_location.* = entry_errno;

    logger.debug("intercepted call: malloc_usable_size(0x{x})", .{@intFromPtr(p)});

    var size: usize = 0;
    if (p) |pointer| {
        const allocation = lookup: {
            state.alloc_mutex.lockUncancelable(state.io);
            defer state.alloc_mutex.unlock(state.io);

            break :lookup state.extra_allocations.get(@intFromPtr(pointer));
        };

        const tracked = allocation orelse {
            logger.err("intercepted call: failed: malloc_usable_size(0x{x}): externally allocated memory", .{@intFromPtr(pointer)});
            @panic("malloc_usable_size failed: externally allocated memory");
        };
        size = tracked.storage_size;
    }

    logger.debug("intercepted call: success: malloc_usable_size(0x{x}) = {d}", .{ @intFromPtr(p), size });

    return size;
}

fn callocSubstitute(n: usize, size: usize) callconv(.c) ?*anyopaque {
    logger.debug("intercepted call: calloc({d}, {d})", .{ n, size });

    state.alloc_mutex.lockUncancelable(state.io);
    defer state.alloc_mutex.unlock(state.io);

    const requested_size = std.math.mul(usize, n, size) catch {
        logger.warn("intercepted call: failed: calloc({d}, {d}): ENOMEM (size overflow)", .{ n, size });
        return allocationFailure();
    };

    const result = allocateTracked(16, requested_size) catch |err| {
        logger.warn("intercepted call: failed: calloc({d}, {d}): ENOMEM ({})", .{ n, size, err });
        return allocationFailure();
    };
    const payload = @as([*]u8, @ptrCast(result))[0..requested_size];
    @memset(payload, 0);

    logger.debug("intercepted call: success: calloc({d}, {d}) = 0x{x}", .{ n, size, @intFromPtr(result) });

    return result;
}

fn reallocSubstitute(p: ?*anyopaque, size: usize) callconv(.c) ?*anyopaque {
    logger.debug("intercepted call: realloc(0x{x}, {d})", .{ @intFromPtr(p), size });

    const result = reallocateTracked(p, size) catch |err| {
        if (err == error.ExternalAllocation) {
            logger.err("intercepted call: failed: realloc(0x{x}, {d}): externally allocated memory", .{ @intFromPtr(p), size });
            @panic("realloc failed: externally allocated memory");
        }
        logger.warn("intercepted call: failed: realloc(0x{x}, {d}): ENOMEM ({})", .{ @intFromPtr(p), size, err });
        return allocationFailure();
    };

    logger.debug("intercepted call: success: realloc(0x{x}, {d}) = 0x{x}", .{ @intFromPtr(p), size, @intFromPtr(result) });
    return result;
}

/// Remap backing storage when supported; otherwise allocate before freeing so
/// failure preserves the original allocation. Only requested payload is copied.
fn reallocateTracked(p: ?*anyopaque, requested_size: usize) !*anyopaque {
    state.alloc_mutex.lockUncancelable(state.io);
    defer state.alloc_mutex.unlock(state.io);

    const previous = if (p) |pointer| state.extra_allocations.get(@intFromPtr(pointer)) orelse return error.ExternalAllocation else null;

    if (requested_size > std.math.maxInt(isize)) return error.OutOfMemory;

    if (previous) |allocation| {
        // Keep zero-size results owned and freeable. Remapping preserves the
        // allocator alignment, so the payload needs no adjustment after a move.
        const old_address = @intFromPtr(p.?);
        const new_storage_size = @max(requested_size, 1);
        const old_storage = @as([*]u8, @ptrCast(p.?))[0..allocation.storage_size];

        if (state.alloc_allocator.rawRemap(old_storage, allocation.alignment, new_storage_size, @returnAddress())) |new_storage| {
            const address = @intFromPtr(new_storage);

            // Replacing one entry needs no capacity growth. Nothing after a
            // successful remap may fail: the old storage may already be gone.
            _ = state.extra_allocations.swapRemove(old_address);
            state.extra_allocations.putAssumeCapacity(address, .{
                .storage_size = new_storage_size,
                .requested_size = requested_size,
                .alignment = allocation.alignment,
            });
            return @ptrFromInt(address);
        }
    }

    const result = try allocateTracked(16, requested_size);
    if (previous) |allocation| {
        const preserved_size = @min(allocation.requested_size, requested_size);
        const source = @as([*]const u8, @ptrCast(p.?))[0..preserved_size];
        const destination = @as([*]u8, @ptrCast(result))[0..preserved_size];
        @memcpy(destination, source);

        const old_storage = @as([*]u8, @ptrCast(p.?))[0..allocation.storage_size];
        state.alloc_allocator.rawFree(old_storage, allocation.alignment, @returnAddress());
        _ = state.extra_allocations.swapRemove(@intFromPtr(p.?));
    }

    return result;
}

fn reallocarraySubstitute(p: ?*anyopaque, n: usize, size: usize) callconv(.c) ?*anyopaque {
    logger.debug("intercepted call: reallocarray(0x{x}, {d}, {d})", .{ @intFromPtr(p), n, size });

    const requested_size = std.math.mul(usize, n, size) catch {
        logger.warn("intercepted call: failed: reallocarray(0x{x}, {d}, {d}): ENOMEM (size overflow)", .{ @intFromPtr(p), n, size });
        return allocationFailure();
    };

    const result = reallocateTracked(p, requested_size) catch |err| {
        if (err == error.ExternalAllocation) {
            logger.err("intercepted call: failed: reallocarray(0x{x}, {d}, {d}): externally allocated memory", .{ @intFromPtr(p), n, size });
            @panic("reallocarray failed: externally allocated memory");
        }
        logger.warn("intercepted call: failed: reallocarray(0x{x}, {d}, {d}): ENOMEM ({})", .{ @intFromPtr(p), n, size, err });
        return allocationFailure();
    };

    logger.debug("intercepted call: success: reallocarray(0x{x}, {d}, {d}) = 0x{x}", .{ @intFromPtr(p), n, size, @intFromPtr(result) });
    return result;
}

// Dynamic-linker API interception.
// --------------------------------

/// Encoded native API handle, never dereferenced as an address. Registry index
/// and load epoch reject stale handles even when a retired slot is reused.
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

const rtld_flags = struct {
    const lazy: c_int = 0x00001;
    const now: c_int = 0x00002;
    const noload: c_int = 0x00004;
    const global: c_int = 0x00100;
    const local: c_int = 0x00000;
};

threadlocal var last_dl_error: ?[:0]const u8 = null;
threadlocal var dl_error_buffer: [2048]u8 = undefined;
threadlocal var dlerror_cleared: bool = true;

// TODO synchronize handle/refcount changes and retained diagnostic allocations
// with object lifetime; dlerror storage itself is already thread-local.

fn dlerrorSubstitute() callconv(.c) ?[*:0]const u8 {
    logger.debug("intercepted call: dlerror()", .{});

    const err = if (!dlerror_cleared and last_dl_error != null) last_dl_error.?.ptr else null;
    dlerror_cleared = true;
    logger.debug("intercepted call: success: dlerror() = {?s}", .{err});

    return err;
}

/// Borrows this thread's diagnostic buffer until the next formatted error. Use
/// scratch storage because formatting arguments can refer to the previous error.
fn formatDlError(comptime format: []const u8, args: anytype) [:0]const u8 {
    dlerror_cleared = false;
    var scratch: [2048]u8 = undefined;
    const message = std.fmt.bufPrintSentinel(&scratch, format, args, 0) catch return "loader operation failed (diagnostic exceeds buffer)";
    @memcpy(dl_error_buffer[0 .. message.len + 1], scratch[0 .. message.len + 1]);
    return dl_error_buffer[0..message.len :0];
}

fn dlopenSubstitute(path: ?[*:0]const u8, flags: c_int) callconv(.c) ?*anyopaque {
    const caller_addr = @returnAddress();
    logger.debug("intercepted call: dlopen(\"{?s}\", 0x{x})", .{ path, flags });

    if (path == null) {
        logger.debug("intercepted call: success: dlopen(NULL, 0x{x}) = 0x{x}", .{ flags, DlHandle.rtld_main.toInt() });
        return @ptrFromInt(@as(usize, @intCast(DlHandle.rtld_main.toInt())));
    }

    const requested_path = std.mem.span(path.?);

    var caller_runpath: ?[]const u8 = null;
    var caller_origin_dir: ?[]const u8 = null;
    if (findDynObjectForLoadedAddr(caller_addr)) |caller_result| {
        const caller = &state.dyn_objects.values()[caller_result.dyn_object_index];
        caller_runpath = caller.runpath;
        caller_origin_dir = std.fs.path.dirname(caller.path) orelse "/";
        logger.debug("dlopen caller: {s} at 0x{x}", .{ caller.name, caller_addr });
    } else {
        logger.debug("dlopen caller at 0x{x} is not a dynamically loaded object", .{caller_addr});
    }

    // TODO implement resident-object lookup for RTLD_NOLOAD before loading or constructors,
    // including successful-handle reference accounting and flag semantics.
    const lib = loadWithRootResolveContext(requested_path, caller_runpath, caller_origin_dir) catch |err| {
        if ((flags & rtld_flags.noload) == 0) {
            last_dl_error = formatDlError("unable to load library {s}: {}", .{ requested_path, err });
            dlerror_cleared = false;
        }

        logger.warn("intercepted call: failed: dlopen(\"{s}\", 0x{x}): {}", .{ requested_path, flags, err });
        return null;
    };

    std.debug.assert(lib.index <= std.math.maxInt(u32));

    const dyn_object = &state.dyn_objects.values()[lib.index];
    const handle: DlHandle = .{
        .tag = 0b10,
        .epoch = dyn_object.current_epoch,
        .index = @intCast(lib.index),
    };
    const handle_raw = handle.toInt();

    const gop = state.dl_handles.getOrPut(state.allocator, handle_raw) catch |err| {
        for (state.dyn_objects.values()[lib.index].deps_breadth_first.items) |dep_idx| {
            state.dyn_objects.values()[dep_idx].ref_count -= 1;
        }

        unloadUnreferencedObjects() catch |unload_err| logger.warn("dlopen rollback: {}", .{unload_err});

        last_dl_error = formatDlError("unable to register library handle: {}", .{err});
        logger.warn("intercepted call: failed: dlopen(\"{s}\", 0x{x}): handle registration: {}", .{ requested_path, flags, err });

        return null;
    };

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

    logger.debug("intercepted call: success: dlopen(\"{?s}\", 0x{x}) = 0x{x}", .{ path, flags, handle_raw });

    return @ptrFromInt(@as(usize, @intCast(handle_raw)));
}

fn dlcloseSubstitute(lib: *anyopaque) callconv(.c) c_int {
    logger.debug("intercepted call: dlclose(0x{x})", .{@intFromPtr(lib)});

    const handle_raw: u64 = @intCast(@intFromPtr(lib));
    const handle = DlHandle.fromInt(handle_raw);

    if (handle == DlHandle.rtld_main) {
        logger.debug("intercepted call: success: dlclose(0x{x} [MAIN]) = 0", .{handle_raw});
        return 0;
    }

    if (handle == DlHandle.rtld_default or handle == DlHandle.rtld_next or handle.tag != 0b10) {
        last_dl_error = formatDlError("invalid library handle 0x{x}", .{handle_raw});
        dlerror_cleared = false;

        logger.warn("intercepted call: failed: dlclose(0x{x}): invalid library handle", .{handle_raw});

        return 1;
    }

    const metadata = state.dl_handles.getPtr(handle_raw) orelse {
        last_dl_error = formatDlError("invalid library handle 0x{x}", .{handle_raw});
        dlerror_cleared = false;

        logger.warn("intercepted call: failed: dlclose(0x{x}): invalid library handle", .{handle_raw});

        return 1;
    };

    if (metadata.open_count == 0) {
        last_dl_error = formatDlError("library handle 0x{x} is already closed", .{handle_raw});
        dlerror_cleared = false;

        logger.warn("intercepted call: failed: dlclose(0x{x}): already closed", .{handle_raw});

        return 1;
    }

    if (metadata.epoch != handle.epoch) {
        last_dl_error = formatDlError("invalid library handle 0x{x}: stale epoch", .{handle_raw});
        dlerror_cleared = false;

        logger.warn("intercepted call: failed: dlclose(0x{x}): stale handle epoch", .{handle_raw});

        return 1;
    }

    const dyn_object_idx = metadata.dyn_object_idx;
    const dyn_object = &state.dyn_objects.values()[dyn_object_idx];

    if (dyn_object.current_epoch != metadata.epoch) {
        last_dl_error = formatDlError("library handle 0x{x} is stale", .{handle_raw});
        dlerror_cleared = false;

        logger.warn("intercepted call: failed: dlclose(0x{x} [{s}]): stale handle", .{ handle_raw, dyn_object.name });

        return 1;
    }

    if (dyn_object.ref_count == 0) {
        metadata.open_count -= 1;
        logger.debug("intercepted call: success: dlclose(0x{x} [{s}]) = 0 (already unloaded)", .{ handle_raw, dyn_object.name });
        return 0;
    }

    for (dyn_object.deps_breadth_first.items) |dep_idx| {
        const dep_dyn_object = &state.dyn_objects.values()[dep_idx];

        std.debug.assert(dep_dyn_object.ref_count > 0);
        dep_dyn_object.ref_count -= 1;
    }

    metadata.open_count -= 1;
    unloadUnreferencedObjects() catch |err| {
        last_dl_error = formatDlError("unable to close library handle 0x{x}: {}", .{ handle_raw, err });
        dlerror_cleared = false;
        logger.warn("intercepted call: failed: dlclose(0x{x}): {}", .{ handle_raw, err });
        return 1;
    };

    logger.debug("intercepted call: success: dlclose(0x{x}) = 0", .{handle_raw});

    return 0;
}

fn dlsymSubstitute(lib_handle: ?*anyopaque, sym_name: [*:0]const u8) callconv(.c) ?*anyopaque {
    return lookupDlSymbol(lib_handle, std.mem.span(sym_name), null, @returnAddress());
}

fn dlvsymSubstitute(lib_handle: ?*anyopaque, sym_name: [*:0]const u8, version: [*:0]const u8) callconv(.c) ?*anyopaque {
    return lookupDlSymbol(lib_handle, std.mem.span(sym_name), std.mem.span(version), @returnAddress());
}

// Capture the caller address in the C entry points: RTLD_NEXT and preload policy
// need the native caller, not the wrapper's call into this helper.
fn lookupDlSymbol(lib_handle: ?*anyopaque, sym_name: []const u8, version: ?[]const u8, caller_addr: usize) ?*anyopaque {
    const operation = if (version != null) "dlvsym" else "dlsym";
    const version_separator = if (version != null) "@" else "";
    const version_name = version orelse "";
    logger.debug("intercepted call: {s}({d}, \"{s}{s}{s}\")", .{ operation, @intFromPtr(lib_handle), sym_name, version_separator, version_name });

    const maybe_caller_infos = findDynObjectSegmentForLoadedAddr(caller_addr) catch null;
    var caller_is_preload_root = false;
    if (maybe_caller_infos) |caller_infos| {
        if (state.dyn_objects.getIndex(caller_infos.dyn_object.key)) |caller_idx| {
            caller_is_preload_root = std.mem.findScalar(usize, state.preload_root_indices.items, caller_idx) != null;
        }
    }

    const handle_raw: u64 = if (lib_handle) |h| @intCast(@intFromPtr(h)) else DlHandle.rtld_default.toInt();
    const handle = DlHandle.fromInt(handle_raw);
    const find_next = lib_handle != null and handle == DlHandle.rtld_next;

    var dyn_object: ?*DynObject = null;

    if (find_next) {
        const infos = maybe_caller_infos orelse {
            last_dl_error = formatDlError("unable to resolve RTLD_NEXT caller for symbol {s}{s}{s} at 0x{x}", .{ sym_name, version_separator, version_name, caller_addr });
            dlerror_cleared = false;

            logger.warn("intercepted call: failed: {s}(RTLD_NEXT, \"{s}{s}{s}\"): unable to resolve caller at 0x{x}", .{ operation, sym_name, version_separator, version_name, caller_addr });

            return null;
        };

        dyn_object = infos.dyn_object;
    } else if (lib_handle != null and handle != DlHandle.rtld_default and handle != DlHandle.rtld_main) {
        if (handle.tag != 0b10) {
            last_dl_error = formatDlError("unable to get symbol {s}{s}{s}: invalid library handle 0x{x}", .{ sym_name, version_separator, version_name, handle_raw });
            dlerror_cleared = false;

            logger.warn("intercepted call: failed: {s}({d}, \"{s}{s}{s}\"): invalid library handle", .{ operation, @intFromPtr(lib_handle), sym_name, version_separator, version_name });

            return null;
        }

        const metadata = state.dl_handles.getPtr(handle_raw) orelse {
            last_dl_error = formatDlError("unable to get symbol {s}{s}{s}: invalid library handle 0x{x}", .{ sym_name, version_separator, version_name, handle_raw });
            dlerror_cleared = false;

            logger.warn("intercepted call: failed: {s}({d}, \"{s}{s}{s}\"): invalid library handle", .{ operation, @intFromPtr(lib_handle), sym_name, version_separator, version_name });

            return null;
        };

        if (metadata.open_count == 0) {
            last_dl_error = formatDlError("unable to get symbol {s}{s}{s}: library handle 0x{x} is closed", .{ sym_name, version_separator, version_name, handle_raw });
            dlerror_cleared = false;

            logger.warn("intercepted call: failed: {s}({d}, \"{s}{s}{s}\"): library handle is closed", .{ operation, @intFromPtr(lib_handle), sym_name, version_separator, version_name });

            return null;
        }

        dyn_object = &state.dyn_objects.values()[metadata.dyn_object_idx];

        if (dyn_object.?.current_epoch != metadata.epoch) {
            last_dl_error = formatDlError("unable to get symbol {s}{s}{s}: library handle 0x{x} is stale", .{ sym_name, version_separator, version_name, handle_raw });
            dlerror_cleared = false;

            logger.warn("intercepted call: failed: {s}({d}, \"{s}{s}{s}\"): library handle is stale", .{ operation, @intFromPtr(lib_handle), sym_name, version_separator, version_name });

            return null;
        }
    }

    if (dyn_object != null and dyn_object.?.ref_count == 0) {
        last_dl_error = formatDlError("unable to get symbol {s}{s}{s} for library {s}: library handle is closed", .{ sym_name, version_separator, version_name, dyn_object.?.name });
        dlerror_cleared = false;

        logger.warn("intercepted call: failed: {s}({d} [{s}], \"{s}{s}{s}\"): library handle is closed", .{ operation, @intFromPtr(lib_handle), dyn_object.?.name, sym_name, version_separator, version_name });

        return null;
    }

    const allow_preload_override = !find_next and !caller_is_preload_root;

    const sym = (if (version) |symbol_version|
        getResolvedSymbolByNameAndVersion(dyn_object, sym_name, symbol_version, find_next, false, allow_preload_override)
    else
        getResolvedSymbolByName(dyn_object, sym_name, find_next, false, allow_preload_override)) catch |err| {
        last_dl_error = formatDlError("unable to get symbol {s}{s}{s} for library {s}: {}", .{ sym_name, version_separator, version_name, if (dyn_object) |do| do.name else "NULL", err });
        dlerror_cleared = false;

        logger.warn("intercepted call: failed: {s}({d} [{s}], \"{s}{s}{s}\"): {}", .{ operation, @intFromPtr(lib_handle), if (dyn_object) |do| do.name else "NULL", sym_name, version_separator, version_name, err });

        return null;
    };

    logger.debug("intercepted call: success: {s}({d} [{s}], \"{s}{s}{s}\") = 0x{x}", .{ operation, @intFromPtr(lib_handle), if (dyn_object) |do| do.name else "NULL", sym_name, version_separator, version_name, sym.address });

    return @ptrFromInt(sym.address);
}

const DlInfo = extern struct {
    dli_fname: [*:0]const u8, // Pathname of shared object that contains address
    dli_fbase: *anyopaque, // Base address at which shared object is loaded
    dli_fsname: ?[*:0]const u8, // Name of symbol whose definition overlaps addr
    dli_fsaddr: ?*anyopaque, // Exact address of symbol named in dli_sname
};

const DlLinkMap = extern struct {
    l_addr: usize,
    l_name: [*:0]const u8,
    l_ld: *std.elf.Dyn,
    l_next: ?*DlLinkMap,
    l_prev: ?*DlLinkMap,
    _others: [1168]u8, // TODO replace unexplained private padding with a documented supported link_map ABI.
};

const DlFindObject = extern struct {
    dlfo_flags: c_ulonglong,
    dlfo_map_start: ?*anyopaque,
    dlfo_map_end: ?*anyopaque,
    dlfo_link_map: ?*DlLinkMap,
    dlfo_eh_frame: ?*anyopaque,
    // TODO validate the x86-64 ABI tail, including newer dlfo_sframe/reserved layouts,
    // and complete _dl_find_object output initialization and its failure return contract.
    __dlfo_reserved: [7]c_ulonglong,
};

/// Copies API result text into loader-owned storage retained until teardown.
/// Failure leaves the retained-results list unchanged.
fn retainDiagnosticString(value: []const u8) ![:0]const u8 {
    try state.extra_strs_z.ensureUnusedCapacity(state.allocator, 1);
    const owned = try state.allocator.dupeSentinel(u8, value, 0);
    state.extra_strs_z.appendAssumeCapacity(owned);
    return owned;
}

fn retainLinkMap() !*DlLinkMap {
    try state.extra_link_maps.ensureUnusedCapacity(state.allocator, 1);
    const link_map = try state.allocator.create(DlLinkMap);
    state.extra_link_maps.appendAssumeCapacity(link_map);
    return link_map;
}

fn discardDiagnosticAllocations(string_count: usize, link_map_count: usize) void {
    for (state.extra_strs_z.items[string_count..]) |text| state.allocator.free(text);
    state.extra_strs_z.shrinkRetainingCapacity(string_count);

    for (state.extra_link_maps.items[link_map_count..]) |link_map| state.allocator.destroy(link_map);
    state.extra_link_maps.shrinkRetainingCapacity(link_map_count);
}

// TODO factor out the shared address lookup and DlInfo construction in dladdrSubstitute
// and dladdr1Substitute, preserving rollback across the complete dladdr1 operation.
fn dladdrSubstitute(addr: *anyopaque, dl_info: *DlInfo) callconv(.c) c_int {
    logger.debug("intercepted call: dladdr(0x{x}, dl_info: *DlInfo [0x{x}])", .{ @intFromPtr(addr), @intFromPtr(dl_info) });

    const string_count = state.extra_strs_z.items.len;
    const link_map_count = state.extra_link_maps.items.len;
    var completed = false;
    defer if (!completed) discardDiagnosticAllocations(string_count, link_map_count);

    const infos = findDynObjectSegmentForLoadedAddr(@intFromPtr(addr)) catch |err| {
        last_dl_error = formatDlError("unable to get infos for address 0x{x}: {}", .{ @intFromPtr(addr), err });

        logger.warn("intercepted call: failed: dladdr(0x{x}): {}", .{ @intFromPtr(addr), err });

        return 0;
    };

    const owned_path = retainDiagnosticString(infos.dyn_object.path) catch {
        last_dl_error = formatDlError("dladdr: out of memory", .{});
        logger.warn("intercepted call: failed: dladdr(0x{x}): out of memory", .{@intFromPtr(addr)});
        return 0;
    };

    dl_info.dli_fname = owned_path.ptr;
    dl_info.dli_fbase = @ptrFromInt(infos.dyn_object.loaded_at.?);

    if (infos.sym_index) |sidx| {
        const sym = infos.dyn_object.syms_array.items[sidx];
        const sym_addr = infos.dyn_object.virtualToLoadedAddress(sym.value, false) catch unreachable;

        const owned_sym_name = retainDiagnosticString(sym.name) catch {
            last_dl_error = formatDlError("dladdr: out of memory", .{});
            logger.warn("intercepted call: failed: dladdr(0x{x}): out of memory", .{@intFromPtr(addr)});
            return 0;
        };

        dl_info.dli_fsname = owned_sym_name.ptr;
        dl_info.dli_fsaddr = @ptrFromInt(sym_addr);
    } else {
        dl_info.dli_fsname = null;
        dl_info.dli_fsaddr = null;
    }

    completed = true;
    logger.debug("intercepted call: success: dladdr(0x{x}, .{{.dli_fname = {s}, .dli_fbase = 0x{x}, .dli_sname = {?s}, .dli_saddr = 0x{x}}}) = 1", .{
        @intFromPtr(addr),
        dl_info.dli_fname,
        @intFromPtr(dl_info.dli_fbase),
        dl_info.dli_fsname,
        if (dl_info.dli_fsaddr) |fsa| @intFromPtr(fsa) else 0,
    });

    return 1;
}

fn dladdr1Substitute(addr: *anyopaque, dl_info: *DlInfo, extra_infos: *anyopaque, flags: c_int) callconv(.c) c_int {
    logger.debug("intercepted call: dladdr1(0x{x}, 0x{x}, 0x{x}, flags={d})", .{ @intFromPtr(addr), @intFromPtr(dl_info), @intFromPtr(extra_infos), flags });

    const string_count = state.extra_strs_z.items.len;
    const link_map_count = state.extra_link_maps.items.len;
    var completed = false;
    defer if (!completed) discardDiagnosticAllocations(string_count, link_map_count);

    const infos = findDynObjectSegmentForLoadedAddr(@intFromPtr(addr)) catch |err| {
        last_dl_error = formatDlError("unable to get infos for address 0x{x}: {}", .{ @intFromPtr(addr), err });
        dlerror_cleared = false;

        logger.warn("intercepted call: failed: dladdr1(0x{x}, dl_info: *DlInfo [0x{x}], extra_infos: 0x{x}, flags: {s}): {}", .{
            @intFromPtr(addr),
            @intFromPtr(dl_info),
            @intFromPtr(extra_infos),
            if (flags == 1) "RTLD_DL_SYMENT" else if (flags == 2) "RTLD_DL_LINKMAP" else "UNKNOWN_FLAGS",
            err,
        });

        return 0;
    };

    const owned_path = retainDiagnosticString(infos.dyn_object.path) catch {
        last_dl_error = formatDlError("dladdr1: out of memory", .{});
        logger.warn("intercepted call: failed: dladdr1(0x{x}): out of memory", .{@intFromPtr(addr)});
        return 0;
    };

    dl_info.dli_fname = owned_path.ptr;
    dl_info.dli_fbase = @ptrFromInt(infos.dyn_object.loaded_at.?);

    if (infos.sym_index) |sidx| {
        const sym = infos.dyn_object.syms_array.items[sidx];
        const sym_addr = infos.dyn_object.virtualToLoadedAddress(sym.value, false) catch unreachable;

        const owned_sym_name = retainDiagnosticString(sym.name) catch {
            last_dl_error = formatDlError("dladdr1: out of memory", .{});
            logger.warn("intercepted call: failed: dladdr1(0x{x}): out of memory", .{@intFromPtr(addr)});
            return 0;
        };

        dl_info.dli_fsname = owned_sym_name.ptr;
        dl_info.dli_fsaddr = @ptrFromInt(sym_addr);
    } else {
        dl_info.dli_fsname = null;
        dl_info.dli_fsaddr = null;
    }

    if (flags == 2) {
        const extra_infos_impl: **DlLinkMap = @ptrCast(@alignCast(extra_infos));

        var curr: ?*DlLinkMap = null;
        for (state.dyn_objects.values()) |*dyn_obj| {
            if (!dyn_obj.loaded) continue;

            // TODO return the queried object's canonical map, with correct names and links,
            // shared across address APIs for the lifetime of that load epoch.
            const link_map = retainLinkMap() catch {
                last_dl_error = formatDlError("dladdr1: out of memory", .{});
                logger.warn("intercepted call: failed: dladdr1(0x{x}): out of memory", .{@intFromPtr(addr)});
                return 0;
            };

            link_map.l_addr = dyn_obj.loaded_at.?;
            link_map.l_name = owned_path;
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
        logger.err("intercepted call: failed: dladdr1(0x{x}, .{{.dli_fname = {s}, .dli_fbase = 0x{x}, .dli_fsname = {?s}, .dli_fs_addr = 0x{x}}}, extra_infos: 0x{x}, flags: {s}): {s}", .{
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

    completed = true;
    logger.debug("intercepted call: success: dladdr1(0x{x}, .{{.dli_fname = {s}, .dli_fbase = 0x{x}, .dli_fsname = {?s}, .dli_fs_addr = 0x{x}}}, extra_infos: 0x{x}, flags: {s}) = 1", .{
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
    logger.debug("intercepted call: dlinfo(0x{x}, 0x{x}, 0x{x})", .{ @intFromPtr(lib), request, @intFromPtr(info) });
    // TODO define supported dlinfo requests and their output/error contracts.
    logger.err("intercepted call: failed: dlinfo(0x{x}, 0x{x}, 0x{x}): unimplemented", .{ @intFromPtr(lib), request, @intFromPtr(info) });
    @panic("unimplemented dlinfo");
}

fn dlmopenSubstitute(lmid: c_long, path: ?[*:0]u8, flags: c_int) callconv(.c) ?*anyopaque {
    logger.debug("intercepted call: dlmopen({d}, \"{?s}\", 0x{x})", .{ lmid, path, flags });
    // TODO implement namespace-aware loading and LM_ID validation.
    logger.err("intercepted call: failed: dlmopen({d}, \"{?s}\", 0x{x}): unimplemented", .{ lmid, path, flags });
    @panic("unimplemented dlmopen");
}

fn dlFindObjectSubstitute(pc: *anyopaque, result: *DlFindObject) callconv(.c) c_int {
    logger.debug("intercepted call: _dl_find_object(0x{x}, *DlFindObject [0x{x}])", .{ @intFromPtr(pc), @intFromPtr(result) });

    const infos = findDynObjectSegmentForLoadedAddr(@intFromPtr(pc)) catch |err| {
        logger.warn("intercepted call: failed: _dl_find_object(0x{x}, *DlFindObject [0x{x}]): {}", .{ @intFromPtr(pc), @intFromPtr(result), err });
        return 1;
    };

    result.dlfo_eh_frame = @ptrFromInt(infos.dyn_object.loaded_at.? + infos.dyn_object.eh_init_mem_offset);

    logger.warn("_dl_find_object: partial implementation: only `dl_info_result.dlfo_eh_frame` field supported", .{});

    logger.debug("intercepted call: success: _dl_find_object(0x{x}, .{{ .dflo_eh_frame = 0x{x} }})", .{ @intFromPtr(pc), @intFromPtr(result.dlfo_eh_frame) });

    return 0;
}

fn dlFindDsoForObjectSubstitute(addr: *anyopaque) callconv(.c) ?*DlLinkMap {
    logger.debug("intercepted call: _dl_find_dso_for_object(0x{x})", .{@intFromPtr(addr)});

    const string_count = state.extra_strs_z.items.len;
    const link_map_count = state.extra_link_maps.items.len;
    var completed = false;
    defer if (!completed) discardDiagnosticAllocations(string_count, link_map_count);

    const infos = findDynObjectSegmentForLoadedAddr(@intFromPtr(addr)) catch |err| {
        logger.warn("intercepted call: failed: _dl_find_dso_for_object(0x{x}): {}", .{ @intFromPtr(addr), err });
        return null;
    };

    const owned_name = retainDiagnosticString(infos.dyn_object.name) catch {
        last_dl_error = formatDlError("_dl_find_dso_for_object: out of memory", .{});
        logger.warn("intercepted call: failed: _dl_find_dso_for_object(0x{x}): out of memory", .{@intFromPtr(addr)});
        return null;
    };

    logger.warn("_dl_find_dso_for_object: partial implementation: link maps should be reused as they can be compared by address", .{});

    // TODO reuse the canonical map shared with dladdr1 for this object's load epoch.
    const link_map = retainLinkMap() catch {
        last_dl_error = formatDlError("_dl_find_dso_for_object: out of memory", .{});
        logger.warn("intercepted call: failed: _dl_find_dso_for_object(0x{x}): out of memory", .{@intFromPtr(addr)});
        return null;
    };

    link_map.l_addr = infos.dyn_object.loaded_at.?;
    link_map.l_name = owned_name;
    link_map.l_ld = @ptrFromInt(infos.dyn_object.loaded_at.? + infos.dyn_object.dyn_section_offset);
    link_map.l_prev = null;
    link_map.l_next = null;
    link_map._others = @splat(0);

    completed = true;
    logger.debug("intercepted call: success: _dl_find_dso_for_object(0x{x}) = 0x{x}", .{ @intFromPtr(addr), @intFromPtr(link_map) });
    return link_map;
}

fn dlIteratePhdrSubstitute(callback: *const fn (*anyopaque, c_uint, *anyopaque) callconv(.c) c_int, data: *anyopaque) callconv(.c) c_int {
    logger.debug("intercepted call: dl_iterate_phdr(callback: 0x{x}, data: 0x{x})", .{ @intFromPtr(callback), @intFromPtr(data) });

    const object_count = state.dyn_objects.count();
    for (0..object_count) |index| {
        const dyn_obj = &state.dyn_objects.values()[index];
        if (!dyn_obj.loaded) continue;
        const registered_info = dyn_obj.phdr_info orelse continue;

        var info = registered_info.*;
        const ret = callback(&info, @sizeOf(std.posix.dl_phdr_info), data);
        if (ret != 0) {
            logger.debug("intercepted call: success: dl_iterate_phdr(callback: 0x{x}, data: 0x{x}) = {d} (callback stopped iteration)", .{ @intFromPtr(callback), @intFromPtr(data), ret });
            return ret;
        }
    }

    logger.debug("intercepted call: success: dl_iterate_phdr(callback: 0x{x}, data: 0x{x}) = 0", .{ @intFromPtr(callback), @intFromPtr(data) });

    return 0;
}

// Thread lifecycle and thread-local destructors.
// ----------------------------------------------

const ThreadInfos = struct {
    idx: usize,
    thread: *std.Thread,
    result: *anyopaque,
    handle: c_ulong,
    joining: bool = false,
    libc_worker: libc.Runtime.Worker,
};
const ThreadInfosMap = std.AutoArrayHashMapUnmanaged(usize, ThreadInfos);

const ThreadRoutineContext = struct {
    idx: usize,
    thread: *std.Thread,
    function: *const fn (?*anyopaque) callconv(.c) *anyopaque,
    argument: ?*anyopaque,
    libc_worker: libc.Runtime.Worker,
};

const ThreadDestructor = struct {
    tp: usize,
    object_idx: usize,
    function: *const fn (?*anyopaque) callconv(.c) void,
    argument: ?*anyopaque,
};

fn cxaThreadAtExitSubstitute(function: *const fn (?*anyopaque) callconv(.c) void, argument: ?*anyopaque, dso: ?*anyopaque) callconv(.c) c_int {
    logger.debug("intercepted call: __cxa_thread_atexit_impl(0x{x}, 0x{x}, 0x{x})", .{ @intFromPtr(function), @intFromPtr(argument), @intFromPtr(dso) });

    const object = findDynObjectForLoadedAddr(@intFromPtr(dso)) orelse findDynObjectForLoadedAddr(@intFromPtr(function)) orelse {
        logger.warn("intercepted call: failed: __cxa_thread_atexit_impl: defining object not found", .{});
        return -1;
    };

    state.thread_mutex.lockUncancelable(state.io);
    defer state.thread_mutex.unlock(state.io);

    state.thread_destructors.append(state.allocator, .{
        .tp = libc.currentThreadPointer(),
        .object_idx = object.dyn_object_index,
        .function = function,
        .argument = argument,
    }) catch |err| {
        logger.warn("intercepted call: failed: __cxa_thread_atexit_impl: {}", .{err});
        return -1;
    };
    state.dyn_objects.values()[object.dyn_object_index].tls_destructors += 1;

    logger.debug("intercepted call: success: __cxa_thread_atexit_impl(0x{x}, 0x{x}, 0x{x}) = 0", .{ @intFromPtr(function), @intFromPtr(argument), @intFromPtr(dso) });
    return 0;
}

/// Removes callbacks in reverse registration order for this TP. Unlock before
/// invoking native code: a destructor can register another destructor or reenter
/// loader services. Keep its defining object retained until the callback returns.
fn runThreadDestructors(tp: usize) void {
    while (true) {
        state.thread_mutex.lockUncancelable(state.io);

        var remaining = state.thread_destructors.items.len;
        const entry = blk: {
            while (remaining != 0) {
                remaining -= 1;
                if (state.thread_destructors.items[remaining].tp == tp) break :blk state.thread_destructors.orderedRemove(remaining);
            }
            state.thread_mutex.unlock(state.io);
            return;
        };
        state.thread_mutex.unlock(state.io);

        logger.debug("tls.destructor: tp_host=0x{x} object_index={d} function_host=0x{x} action=call", .{ tp, entry.object_idx, @intFromPtr(entry.function) });
        entry.function(entry.argument);
        logger.debug("tls.destructor: tp_host=0x{x} object_index={d} function_host=0x{x} action=returned", .{ tp, entry.object_idx, @intFromPtr(entry.function) });
        state.dyn_objects.values()[entry.object_idx].tls_destructors -= 1;
    }
}

/// Child-side lifecycle: establish libc visibility, enter user code, run TLS
/// destructors, retire native visibility, then publish the result for Zig join.
fn threadRoutine(ctx: ThreadRoutineContext) void {
    const new_tp = libc.currentThreadPointer();

    logger.debug("worker.start: worker={d} tp_host=0x{x}", .{ ctx.idx, new_tp });

    ctx.libc_worker.register(new_tp) catch |err| {
        logger.err("worker.start: worker={d} tp_host=0x{x} error={t}", .{ ctx.idx, new_tp, err });
        @panic("error initializing libc worker");
    };

    state.thread_mutex.lockUncancelable(state.io);

    const entry = state.thread_infos.getPtr(ctx.idx).?;
    std.debug.assert(entry.handle == new_tp);
    std.debug.assert(entry.thread == ctx.thread);

    state.thread_mutex.unlock(state.io);

    ctx.libc_worker.enterUserCode();

    logger.debug("worker.user: worker={d} tp_host=0x{x} function_host=0x{x} action=call", .{ ctx.idx, new_tp, @intFromPtr(ctx.function) });
    const ret = ctx.function(ctx.argument);
    logger.debug("worker.user: worker={d} tp_host=0x{x} action=returned result=0x{x}", .{ ctx.idx, new_tp, @intFromPtr(ret) });
    runThreadDestructors(new_tp);

    ctx.libc_worker.unregister(new_tp);

    state.thread_mutex.lockUncancelable(state.io);
    const entry_after = state.thread_infos.getPtr(ctx.idx).?;
    entry_after.result = ret;
    state.thread_mutex.unlock(state.io);

    logger.debug("worker.exit: worker={d} tp_host=0x{x} action=result_published result=0x{x}", .{ ctx.idx, new_tp, @intFromPtr(ret) });
}

fn pthreadCreateSubstitute(newthread: *c_ulong, attr: ?*const anyopaque, start_routine: *const fn (?*anyopaque) callconv(.c) *anyopaque, arg: ?*anyopaque) callconv(.c) c_int {
    const errno_location = state.libc_runtime.?.getErrnoLocation();
    const entry_errno = errno_location.*;
    defer errno_location.* = entry_errno;
    logger.debug("intercepted call: pthread_create(0x{x}, 0x{x}, 0x{x}, 0x{x})", .{ @intFromPtr(newthread), @intFromPtr(attr), @intFromPtr(start_routine), @intFromPtr(arg) });

    const specifics = &state.libc_runtime.?;
    if (!specifics.supportsWorkers()) {
        logger.warn("worker.create: result=ENOSYS reason=native_thread_support_not_loaded", .{});
        return @backingInt(std.os.linux.E.NOSYS);
    }

    // Mirror Zig's default stack/TLS placement to expose TP as native pthread_t.
    // This depends on the current Zig thread implementation, not a libc ABI.
    const page_size = std.heap.pageSize();
    const default_stack_size = std.Thread.SpawnConfig.default_stack_size;

    var bytes: usize = page_size;
    bytes += @max(page_size, default_stack_size);
    bytes = std.mem.alignForward(usize, bytes, page_size);
    bytes = std.mem.alignForward(usize, bytes, ElfTlsRuntime.area_desc.alignment);
    const tls_offset = bytes + ElfTlsRuntime.area_desc.abi_tcb.offset;

    var libc_worker = libc.Runtime.Worker.init(specifics);
    defer libc_worker.restoreCreatorSignals();

    state.thread_mutex.lockUncancelable(state.io);
    var registry_locked = true;
    defer if (registry_locked) state.thread_mutex.unlock(state.io);

    // Reserve everything before spawning.
    state.thread_infos.ensureUnusedCapacity(state.allocator, 1) catch {
        logger.warn("intercepted call: failed: pthread_create: EAGAIN (thread registry allocation)", .{});
        return @backingInt(std.os.linux.E.AGAIN);
    };
    state.extra_threads.ensureUnusedCapacity(state.allocator, 1) catch {
        logger.warn("intercepted call: failed: pthread_create: EAGAIN (thread list allocation)", .{});
        return @backingInt(std.os.linux.E.AGAIN);
    };
    const thread = state.allocator.create(std.Thread) catch {
        logger.warn("intercepted call: failed: pthread_create: EAGAIN (thread allocation)", .{});
        return @backingInt(std.os.linux.E.AGAIN);
    };

    libc_worker.prepare() catch |err| {
        logger.warn("worker.create: phase=prepare result=EAGAIN error={t}", .{err});
        state.allocator.destroy(thread);
        return @backingInt(std.os.linux.E.AGAIN);
    };

    const idx = @atomicRmw(usize, &state.thread_current_idx, .Add, 1, .seq_cst);
    logger.debug("worker.create: worker={d} parent_tp_host=0x{x} action=spawn", .{ idx, libc_worker.parent_tp });

    libc_worker.beginSpawn();
    const context: ThreadRoutineContext = .{
        .idx = idx,
        .thread = thread,
        .function = start_routine,
        .argument = arg,
        .libc_worker = libc_worker,
    };

    thread.* = std.Thread.spawn(.{}, threadRoutine, .{context}) catch |err| {
        libc_worker.spawnFailed();
        state.allocator.destroy(thread);

        logger.warn("intercepted call: failed: pthread_create(0x{x}, 0x{x}, 0x{x}, 0x{x}): EAGAIN ({})", .{ @intFromPtr(newthread), @intFromPtr(attr), @intFromPtr(start_routine), @intFromPtr(arg), err });

        return @backingInt(switch (err) {
            error.OutOfMemory, error.SystemResources, error.ThreadQuotaExceeded, error.LockedMemoryLimitExceeded => std.os.linux.E.AGAIN,
            error.Unexpected => std.os.linux.E.AGAIN,
        });
    };
    libc_worker.endSpawn();

    const newthread_handle: *c_ulong = @ptrCast(@alignCast(newthread));
    newthread_handle.* = @intFromPtr(thread.impl.thread.mapped.ptr) + tls_offset;

    state.extra_threads.appendAssumeCapacity(thread);
    state.thread_infos.putAssumeCapacity(idx, .{
        .idx = idx,
        .handle = newthread_handle.*,
        .thread = thread,
        .result = undefined,
        .libc_worker = libc_worker,
    });

    // The worker needs `thread_mutex` to finish startup. Release it before waiting;
    // the creator reference keeps startup storage alive even if a join races us.
    state.thread_mutex.unlock(state.io);
    registry_locked = false;

    libc_worker.finishStartup();

    logger.debug("intercepted call: success: pthread_create(0x{x}, 0x{x}, 0x{x}, 0x{x}) = 0", .{ @intFromPtr(newthread), @intFromPtr(attr), @intFromPtr(start_routine), @intFromPtr(arg) });

    return 0;
}

fn pthreadExitSubstitute() callconv(.c) void {
    logger.debug("intercepted call: pthread_exit()", .{});
    // TODO implement the native signature and worker-exit cleanup/result handoff.
    logger.err("intercepted call: failed: pthread_exit(): unimplemented", .{});
    @panic("unimplemented pthread_exit");
}

fn pthreadCancelSubstitute() callconv(.c) void {
    logger.debug("intercepted call: pthread_cancel()", .{});
    // TODO implement the native signature, cancellation state, and cancellation-point cleanup.
    logger.err("intercepted call: failed: pthread_cancel(): unimplemented", .{});
    @panic("unimplemented pthread_cancel");
}

fn pthreadDetachSubstitute() callconv(.c) void {
    logger.debug("intercepted call: pthread_detach()", .{});
    // TODO implement the native signature and detached-worker resource reclamation.
    logger.err("intercepted call: failed: pthread_detach(): unimplemented", .{});
    @panic("unimplemented pthread_detach");
}

fn pthreadJoinSubstitute(thread_handle: c_ulong, retval: ?**anyopaque) callconv(.c) c_int {
    const errno_location = state.libc_runtime.?.getErrnoLocation();
    const entry_errno = errno_location.*;
    defer errno_location.* = entry_errno;
    logger.debug("intercepted call: pthread_join(0x{x}, 0x{x})", .{ thread_handle, @intFromPtr(retval) });

    if (thread_handle == libc.currentThreadPointer()) {
        logger.warn("intercepted call: failed: pthread_join(0x{x}, 0x{x}): EDEADLK", .{ thread_handle, @intFromPtr(retval) });
        return @backingInt(std.os.linux.E.DEADLK);
    }

    state.thread_mutex.lockUncancelable(state.io);

    for (state.thread_infos.values()) |*entry| {
        if (entry.handle != thread_handle or entry.joining) continue;

        const thread = entry.thread;
        const idx = entry.idx;
        const libc_worker = entry.libc_worker;

        // Claim the single join while locked, then release the lock while Zig
        // waits for kernel exit. The child needs the same lock to publish `result`.
        entry.joining = true;
        state.thread_mutex.unlock(state.io);

        logger.debug("worker.join: worker={d} tp_host=0x{x} action=wait", .{ idx, thread_handle });
        thread.join();
        logger.debug("worker.join: worker={d} tp_host=0x{x} action=kernel_exit_observed", .{ idx, thread_handle });

        state.thread_mutex.lockUncancelable(state.io);

        if (retval) |result| {
            result.* = state.thread_infos.get(idx).?.result;
        }
        _ = state.thread_infos.swapRemove(idx);
        if (std.mem.findScalar(*std.Thread, state.extra_threads.items, thread)) |pos| {
            _ = state.extra_threads.swapRemove(pos);
        }

        state.thread_mutex.unlock(state.io);

        state.allocator.destroy(thread);
        libc_worker.releaseAfterJoin();

        unloadUnreferencedObjects() catch |err| logger.warn("pthread_join: deferred unload failed: {}", .{err});

        logger.debug("intercepted call: success: pthread_join(0x{x}, 0x{x})", .{ thread_handle, @intFromPtr(retval) });

        return 0;
    }

    state.thread_mutex.unlock(state.io);

    logger.warn("intercepted call: failed: pthread_join(0x{x}, 0x{x}): ESRCH (thread not found)", .{ thread_handle, @intFromPtr(retval) });
    return @backingInt(std.os.linux.E.SRCH);
}

fn pthreadKillSubstitute() callconv(.c) void {
    logger.debug("intercepted call: pthread_kill()", .{});
    // TODO implement the native signature, thread-handle validation, and signal/error semantics.
    logger.err("intercepted call: failed: pthread_kill(): unimplemented", .{});
    @panic("unimplemented pthread_kill");
}

// Timer and queue notifications.
// ------------------------------

const NotificationEvent = libc.NotificationEvent;

// Each index selects a native timer_create symbol-version binding, not a timer.
// Separate C entry points preserve the selected ABI when forwarding the call.
// Slots follow libc/glibc.zig's timerBindingIndex: 0 is the fallback,
// 1 is GLIBC_2.2.5, 2 is GLIBC_2.3.3, and 3 is GLIBC_2.34.
fn TimerCreateSubstitute(comptime binding_index: usize) type {
    return struct {
        fn call(clock: c_int, event: ?*const NotificationEvent, timer_id: *anyopaque) callconv(.c) c_int {
            const errno_location = state.libc_runtime.?.getErrnoLocation();
            const entry_errno = errno_location.*;
            logger.debug("intercepted call: timer_create({d}, 0x{x}, 0x{x})", .{ clock, @intFromPtr(event), @intFromPtr(timer_id) });
            errno_location.* = entry_errno;

            const result = state.libc_runtime.?.createTimer(binding_index, clock, event, timer_id);
            const result_errno = errno_location.*;
            defer errno_location.* = result_errno;

            if (result == 0) {
                logger.debug("intercepted call: success: timer_create({d}, 0x{x}, 0x{x}) = 0", .{ clock, @intFromPtr(event), @intFromPtr(timer_id) });
            } else {
                logger.warn("intercepted call: failed: timer_create({d}, 0x{x}, 0x{x}) = {d}, errno={d}", .{ clock, @intFromPtr(event), @intFromPtr(timer_id), result, result_errno });
            }
            return result;
        }
    };
}

fn mqNotifySubstitute(queue: c_int, event: ?*const NotificationEvent) callconv(.c) c_int {
    const errno_location = state.libc_runtime.?.getErrnoLocation();
    const entry_errno = errno_location.*;
    logger.debug("intercepted call: mq_notify({d}, 0x{x})", .{ queue, @intFromPtr(event) });
    errno_location.* = entry_errno;

    const result = state.libc_runtime.?.notifyQueue(queue, event);
    const result_errno = errno_location.*;
    defer errno_location.* = result_errno;

    if (result == 0) {
        logger.debug("intercepted call: success: mq_notify({d}, 0x{x}) = 0", .{ queue, @intFromPtr(event) });
    } else {
        logger.warn("intercepted call: failed: mq_notify({d}, 0x{x}) = {d}, errno={d}", .{ queue, @intFromPtr(event), result, result_errno });
    }
    return result;
}

// Diagnostics and debugger integration.
// -------------------------------------

const indent_buf: [64]u8 = @splat(' ');

/// Raw values only: callers guard the traversal and supply a bounded table.
/// Dump before interpreting entries so rejected tables retain diagnostic evidence.
fn logDynamicEntries(object_name: []const u8, entries: []align(1) const std.elf.Dyn) void {
    for (entries, 0..) |entry, index| {
        const tag_name = switch (entry.d_tag) {
            std.elf.DT_NULL => "NULL",
            std.elf.DT_NEEDED => "NEEDED",
            std.elf.DT_RUNPATH => "RUNPATH",
            std.elf.DT_RPATH => "RPATH",
            std.elf.DT_RELA => "RELA",
            std.elf.DT_RELASZ => "RELASZ",
            std.elf.DT_RELAENT => "RELAENT",
            std.elf.DT_RELACOUNT => "RELACOUNT",
            std.elf.DT_RELR => "RELR",
            std.elf.DT_RELRSZ => "RELRSZ",
            std.elf.DT_RELRENT => "RELRENT",
            std.elf.DT_REL => "REL",
            std.elf.DT_RELSZ => "RELSZ",
            std.elf.DT_RELENT => "RELENT",
            std.elf.DT_PLTREL => "PLTREL",
            std.elf.DT_PLTRELSZ => "PLTRELSZ",
            std.elf.DT_JMPREL => "JMPREL",
            std.elf.DT_PLTGOT => "PLTGOT",
            std.elf.DT_INIT => "INIT",
            std.elf.DT_FINI => "FINI",
            std.elf.DT_INIT_ARRAY => "INIT_ARRAY",
            std.elf.DT_INIT_ARRAYSZ => "INIT_ARRAYSZ",
            std.elf.DT_FINI_ARRAY => "FINI_ARRAY",
            std.elf.DT_FINI_ARRAYSZ => "FINI_ARRAYSZ",
            std.elf.DT_FLAGS => "FLAGS",
            std.elf.DT_FLAGS_1 => "FLAGS_1",
            std.elf.DT_SONAME => "SONAME",
            std.elf.DT_HASH => "HASH",
            std.elf.DT_GNU_HASH => "GNU_HASH",
            std.elf.DT_STRTAB => "STRTAB",
            std.elf.DT_STRSZ => "STRSZ",
            std.elf.DT_SYMTAB => "SYMTAB",
            std.elf.DT_SYMENT => "SYMENT",
            std.elf.DT_VERSYM => "VERSYM",
            std.elf.DT_VERNEED => "VERNEED",
            std.elf.DT_VERNEEDNUM => "VERNEEDNUM",
            std.elf.DT_VERDEF => "VERDEF",
            std.elf.DT_VERDEFNUM => "VERDEFNUM",
            else => "UNKNOWN",
        };
        logger.debug("dynamic.entry: object={s} index={d} tag={s} tag_raw=0x{x} value=0x{x}", .{ object_name, index, tag_name, entry.d_tag, entry.d_val });
    }
}

/// All registry entries contribute state, including retired reservations. Detailed
/// mapping-backed metadata is inspected only for mapped objects being prepared.
fn logSummary(phase: []const u8, include_pending_details: bool) void {
    if (logger.level != .debug) return;

    var buf: [16]u8 = undefined;

    logger.debug("registry.snapshot: phase={s} objects={d}", .{ phase, state.dyn_objects.count() });
    for (state.dyn_objects.values(), 0..) |*dyn_object, object_index| {
        logger.debug("object.identity: phase={s} index={d} name={s} path={s} inode={d} retired_slot={d} runpath={?s}", .{ phase, object_index, dyn_object.name, dyn_object.path, dyn_object.key.ino, dyn_object.key.retired_slot, dyn_object.runpath });
        logger.debug("object.state: index={d} loaded={} relocated={} init_called={} load_requested={} finalizing={} epoch={d} references={d} pinned={} tls_destructors={d}", .{ object_index, dyn_object.loaded, dyn_object.relocated, dyn_object.init_called, dyn_object.load_requested, dyn_object.finalizing, dyn_object.current_epoch, dyn_object.ref_count, dyn_object.pinned, dyn_object.tls_destructors });
        logger.debug("object.mapping: index={d} file_handle={d} file_mapping_host=0x{x} file_mapping_bytes={d} loaded_base_host={?x} loaded_bytes={d} reservation_host=0x{x} reservation_bytes={d}", .{ object_index, dyn_object.file_handle, dyn_object.mapped_at, dyn_object.mapped_size, dyn_object.loaded_at, dyn_object.loaded_size, if (dyn_object.reservation) |reservation| @intFromPtr(reservation.ptr) else 0, if (dyn_object.reservation) |reservation| reservation.len else 0 });
        logger.debug("object.scope: index={d} dependencies={any} breadth_first={any} binding_dependencies={any} symbol_names={d} symbols={d} relocations={d} segments={d}", .{ object_index, dyn_object.dependencies.items, dyn_object.deps_breadth_first.items, dyn_object.binding_dependencies.items, dyn_object.syms.count(), dyn_object.syms_array.items.len, dyn_object.relocs.items.len, dyn_object.segments.count() });
        logger.debug("object.tls: index={d} alignment={d} offset_below_tp=0x{x} mapped_host=0x{x} capacity_bytes={d} slot_alignment={d}", .{ object_index, dyn_object.tls_align, dyn_object.tls_offset, dyn_object.tls_mapped_at, dyn_object.tls_capacity, dyn_object.tls_slot_align });
        logger.debug("object.debug: index={d} phdr_info_host=0x{x} phdr_name={?s}", .{ object_index, @intFromPtr(dyn_object.phdr_info), dyn_object.phdr_name });

        if (!include_pending_details or dyn_object.loaded or dyn_object.mapped_at == 0) {
            continue;
        }

        logger.debug("object.details: index={d} name={s} phase={s}", .{ object_index, dyn_object.name, phase });
        logger.debug("  elf_header_host=0x{x} type={t} machine=0x{x} entry_elf=0x{x} phdr_file_offset=0x{x} phdr_count={d} shdr_file_offset=0x{x} shdr_count={d}", .{ @intFromPtr(dyn_object.eh), dyn_object.eh.e_type, @backingInt(dyn_object.eh.e_machine), dyn_object.eh.e_entry, dyn_object.eh.e_phoff, dyn_object.eh.e_phnum, dyn_object.eh.e_shoff, dyn_object.eh.e_shnum });
        logger.debug("  dynamic_address_elf=0x{x} plt_got_address_elf=0x{x} plt_got_bytes={d}", .{ dyn_object.dyn_section_offset, dyn_object.plt_got_section_offset, dyn_object.plt_got_section_size });
        logger.debug("  eh_frame_file_offset=0x{x} eh_frame_file_bytes={d} eh_frame_address_elf=0x{x} eh_frame_memory_bytes={d} eh_frame_alignment={d}", .{ dyn_object.eh_init_file_offset, dyn_object.eh_init_file_size, dyn_object.eh_init_mem_offset, dyn_object.eh_init_mem_size, dyn_object.eh_align });
        logger.debug("  segments:  {d} segments loaded", .{dyn_object.segments.count()});
        for (dyn_object.segments.values(), 0..) |segment, s| {
            logger.debug("  - {d}:", .{s});
            logger.debug("    file_offset: 0x{x}", .{segment.file_offset});
            logger.debug("    file_size: 0x{x}", .{segment.file_size});
            logger.debug("    address_elf: 0x{x}", .{segment.mem_offset});
            logger.debug("    mem_size: 0x{x}", .{segment.mem_size});
            logger.debug("    mem_align: 0x{x}", .{segment.mem_align});
            logger.debug("    loaded_host: 0x{x}, mapped_from_file: {}", .{ segment.loaded_at, segment.mapped_from_file });
            logger.debug("    flags_first: {s}, address_elf: 0x{x}, bytes: {d}", .{ segment.flags_first.toStr(&buf) catch unreachable, segment.flags_first.mem_offset, segment.flags_first.mem_size });
            logger.debug("    flags_last: {s}, address_elf: 0x{x}, bytes: {d}", .{ segment.flags_last.toStr(&buf) catch unreachable, segment.flags_last.mem_offset, segment.flags_last.mem_size });
        }
        logger.debug("  tls_init_file_offset: 0x{x}", .{dyn_object.tls_init_file_offset});
        logger.debug("  tls_init_file_size: 0x{x}", .{dyn_object.tls_init_file_size});
        logger.debug("  tls_init_address_elf: 0x{x}", .{dyn_object.tls_init_mem_offset});
        logger.debug("  tls_init_mem_size: 0x{x}", .{dyn_object.tls_init_mem_size});
        logger.debug("  init: {s} init fn, {d} init_array fns", .{ if (dyn_object.init_addr != 0x0) "1" else "no", dyn_object.init_array_size / @sizeOf(usize) });
        logger.debug("    init_address_elf: 0x{x}", .{dyn_object.init_addr});
        logger.debug("    init_array_address_elf: 0x{x}, bytes: {d}", .{ dyn_object.init_array_addr, dyn_object.init_array_size });
        logger.debug("  fini: {s} fini fn, {d} fini_array fns", .{ if (dyn_object.fini_addr != 0x0) "1" else "no", dyn_object.fini_array_size / @sizeOf(usize) });
        logger.debug("    fini_address_elf: 0x{x}", .{dyn_object.fini_addr});
        logger.debug("    fini_array_address_elf: 0x{x}, bytes: {d}", .{ dyn_object.fini_array_addr, dyn_object.fini_array_size });
        logger.debug("  symbols:  {d} symbols", .{dyn_object.syms_array.items.len});
        for (dyn_object.syms_array.items, 0..) |sym, s| {
            logger.debug("  - index: {d}:", .{s});
            logger.debug("    name: {s}", .{sym.name});
            logger.debug("    version: {s}", .{sym.version});
            logger.debug("    hidden: {}", .{sym.hidden});
            logger.debug("    default_version: {}", .{sym.default_version});
            logger.debug("    symbol_table_byte_offset: 0x{x}", .{sym.offset});
            if (@backingInt(sym.type) <= 6) {
                logger.debug("    type: {s}", .{@tagName(sym.type)});
            } else {
                logger.debug("    type: {d}", .{@backingInt(sym.type)});
            }
            if (@backingInt(sym.bind) <= 2) {
                logger.debug("    bind: {s}", .{@tagName(sym.bind)});
            } else {
                logger.debug("    bind: {d}", .{@backingInt(sym.bind)});
            }
            logger.debug("    shidx: {s}", .{sym.sectionNameOrValue(&buf) catch unreachable});
            logger.debug("    value: 0x{x}", .{sym.value});
            logger.debug("    size: 0x{x}", .{sym.size});
        }
        logger.debug("  relocs: {d} relocs", .{dyn_object.relocs.items.len});
        for (dyn_object.relocs.items, 0..) |reloc, s| {
            logger.debug("  - {d}:", .{s});
            logger.debug("    type: {s}", .{@tagName(reloc.type)});
            logger.debug("    sym_idx: 0x{x}", .{reloc.sym_idx});
            logger.debug("    target_elf: 0x{x}, is_relr: {}", .{ reloc.offset, reloc.is_relr });
            if (reloc.is_relr) {
                logger.debug("    addend: implicit original target contents (relative relocation already applied)", .{});
            } else {
                logger.debug("    explicit_addend: {d}, bits: 0x{x}", .{ reloc.addend, @as(usize, @bitCast(reloc.addend)) });
            }
        }
    }
}

fn logDepTree(dyn_object: *const DynObject) !void {
    if (logger.level != .debug) return;

    var already_visited: std.ArrayList(usize) = .empty;
    defer already_visited.deinit(state.allocator);

    try logDepTreeInner(dyn_object, 0, &already_visited);
}

fn logDepTreeInner(dyn_object: *const DynObject, level: usize, already_visited: *std.ArrayList(usize)) !void {
    std.debug.assert(level < 32);

    logger.debug("loaded dep tree:{s} - {s} => {s}", .{ indent_buf[0 .. 2 * level], dyn_object.name, dyn_object.path });

    if (std.mem.findScalar(usize, already_visited.items, state.dyn_objects.getIndex(dyn_object.key).?)) |_| {
        return;
    }

    try already_visited.append(state.allocator, state.dyn_objects.getIndex(dyn_object.key).?);

    if (dyn_object.dependencies.items.len > 0) {
        for (dyn_object.dependencies.items) |dep_idx| {
            const dep = &state.dyn_objects.values()[dep_idx];
            try logDepTreeInner(dep, level + 1, already_visited);
        }
    }

    // Keep completed nodes in the visited set: shared dependencies should be
    // expanded only once, not once for each path from the root.
}

fn dumpSegments(dyn_obj: *DynObject) !void {
    var name_buf: [256]u8 = undefined;

    for (dyn_obj.segments.values()) |*s| {
        const mem_start = s.loaded_at;
        const mem_size = s.mem_size;

        const segment_file_name = try std.fmt.bufPrint(&name_buf, "{s}_0x{x}_0x{x}__0x{x}", .{ dyn_obj.name, mem_start, mem_start + mem_size, s.file_offset });
        const segment_file = try std.fs.cwd().createFile(segment_file_name, .{});
        defer segment_file.close();

        const data: []const u8 = (@as([*]const u8, @ptrFromInt(mem_start)))[0..mem_size];

        var writer = segment_file.writer(&.{});
        try writer.interface.writeAll(data);
    }
}

export fn _dl_debug_state() callconv(.c) void {
    logger.debug("_dl_debug_state called", .{});
}

const ReallocationTestAllocator = struct {
    const Self = @This();
    const Mode = enum { in_place, move, reject };

    buffers: [2][1024]u8 align(256) = undefined,
    lengths: [2]usize = .{ 0, 0 },
    alignments: [2]std.mem.Alignment = undefined,
    mode: Mode,
    allow_alloc: bool = true,
    remaps: usize = 0,

    fn allocator(self: *Self) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = &alloc,
                .resize = &std.mem.Allocator.noResize,
                .remap = &remap,
                .free = &free,
            },
        };
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(context));
        std.debug.assert(alignment.toByteUnits() <= 256 and len > 0);
        if (!self.allow_alloc or len > 1000) return null;

        for (&self.lengths, 0..) |*length, index| {
            if (length.* != 0) continue;

            length.* = len;
            self.alignments[index] = alignment;
            return &self.buffers[index];
        }
        return null;
    }

    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ret_addr: usize) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(context));
        const index: usize = if (memory.ptr == @as([*]u8, &self.buffers[0])) 0 else 1;
        std.debug.assert(memory.ptr == @as([*]u8, &self.buffers[index]) and memory.len == self.lengths[index]);
        std.debug.assert(alignment == self.alignments[index] and len > 0);
        if (len > 1000) return null;

        switch (self.mode) {
            .reject => return null,
            .in_place => {
                self.remaps += 1;
                self.lengths[index] = len;
                return memory.ptr;
            },
            .move => {
                self.remaps += 1;
                const result = alloc(context, len, alignment, ret_addr) orelse return null;
                const preserved_size = @min(memory.len, len);
                @memcpy(result[0..preserved_size], memory[0..preserved_size]);

                free(context, memory, alignment, ret_addr);
                return result;
            },
        }
    }

    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, _: usize) void {
        const self: *Self = @ptrCast(@alignCast(context));
        const index: usize = if (memory.ptr == @as([*]u8, &self.buffers[0])) 0 else 1;
        std.debug.assert(memory.ptr == @as([*]u8, &self.buffers[index]) and memory.len == self.lengths[index]);
        std.debug.assert(alignment == self.alignments[index]);

        @memset(memory, 0xdd);
        self.lengths[index] = 0;
    }
};

test {
    _ = @import("CustomSelfInfo.zig");
    _ = @import("DynObject.zig");
    _ = @import("logger.zig");
    _ = @import("CodeView.zig");
    _ = @import("InstructionFlow.zig");
    _ = @import("libc.zig");
}

test "tracked realloc preserves payload and alignment across remap and fallback" {
    for ([_]ReallocationTestAllocator.Mode{ .in_place, .move, .reject }) |mode| {
        for ([_]usize{ 16, 256 }) |alignment| {
            var allocator: ReallocationTestAllocator = .{ .mode = mode };
            state = .{
                .allocator = std.testing.allocator,
                .alloc_allocator = allocator.allocator(),
                .io = std.testing.io,
            };
            defer {
                for (state.extra_allocations.keys(), state.extra_allocations.values()) |address, allocation| {
                    const storage = @as([*]u8, @ptrFromInt(address))[0..allocation.storage_size];
                    state.alloc_allocator.rawFree(storage, allocation.alignment, @returnAddress());
                }
                state.extra_allocations.deinit(state.allocator);
                state = .{};
            }

            var pointer = try allocateTracked(alignment, 64);
            try std.testing.expectEqual(@as(usize, 0), @intFromPtr(pointer) % alignment);
            try std.testing.expectEqual(@as(usize, 64), state.extra_allocations.get(@intFromPtr(pointer)).?.storage_size);

            for (@as([*]u8, @ptrCast(pointer))[0..64], 0..) |*byte, index| {
                byte.* = @intCast(index);
            }

            var preserved_size: usize = 64;
            for ([_]usize{ 256, 32, 64 }) |size| {
                pointer = try reallocateTracked(pointer, size);
                preserved_size = @min(preserved_size, size);

                const expected_alignment = switch (mode) {
                    .in_place, .move => alignment,
                    .reject => 16,
                };
                const allocation = state.extra_allocations.get(@intFromPtr(pointer)).?;
                try std.testing.expectEqual(@as(usize, 0), @intFromPtr(pointer) % 16);
                try std.testing.expectEqual(@as(usize, 1), state.extra_allocations.count());
                try std.testing.expectEqual(size, allocation.requested_size);
                try std.testing.expectEqual(std.mem.Alignment.fromByteUnits(expected_alignment), allocation.alignment);
                try std.testing.expectEqual(size, allocation.storage_size);

                for (@as([*]u8, @ptrCast(pointer))[0..preserved_size], 0..) |byte, index| {
                    try std.testing.expectEqual(@as(u8, @intCast(index)), byte);
                }
            }

            const expected_remaps: usize = switch (mode) {
                .in_place, .move => 3,
                .reject => 0,
            };
            try std.testing.expectEqual(expected_remaps, allocator.remaps);

            pointer = try reallocateTracked(pointer, 0);
            const allocation = state.extra_allocations.get(@intFromPtr(pointer)).?;
            try std.testing.expectEqual(@as(usize, 0), allocation.requested_size);
            try std.testing.expectEqual(@as(usize, 1), allocation.storage_size);
            try std.testing.expectEqual(@as(usize, 1), state.extra_allocations.count());
        }
    }
}

test "tracked realloc failure preserves payload and registration" {
    for ([_]usize{ 16, 256 }) |alignment| {
        var allocator: ReallocationTestAllocator = .{ .mode = .reject };
        state = .{
            .allocator = std.testing.allocator,
            .alloc_allocator = allocator.allocator(),
            .io = std.testing.io,
        };
        defer {
            for (state.extra_allocations.keys(), state.extra_allocations.values()) |address, allocation| {
                const storage = @as([*]u8, @ptrFromInt(address))[0..allocation.storage_size];
                state.alloc_allocator.rawFree(storage, allocation.alignment, @returnAddress());
            }
            state.extra_allocations.deinit(state.allocator);
            state = .{};
        }

        const pointer = try allocateTracked(alignment, 64);
        const payload = @as([*]u8, @ptrCast(pointer))[0..64];
        for (payload, 0..) |*byte, index| {
            byte.* = @intCast(index);
        }
        const before = state.extra_allocations.get(@intFromPtr(pointer)).?;

        allocator.allow_alloc = false;
        try std.testing.expectError(error.OutOfMemory, allocateTracked(alignment, 32));
        try std.testing.expectError(error.OutOfMemory, reallocateTracked(pointer, 512));
        try std.testing.expectError(error.OutOfMemory, reallocateTracked(pointer, std.math.maxInt(usize)));

        try std.testing.expectEqual(@as(usize, 1), state.extra_allocations.count());
        try std.testing.expectEqualDeep(before, state.extra_allocations.get(@intFromPtr(pointer)).?);
        for (payload, 0..) |byte, index| {
            try std.testing.expectEqual(@as(u8, @intCast(index)), byte);
        }
    }
}

test "tracked realloc accepts null and rejects external pointers" {
    state = .{
        .allocator = std.testing.allocator,
        .alloc_allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer {
        for (state.extra_allocations.keys(), state.extra_allocations.values()) |address, allocation| {
            const storage = @as([*]u8, @ptrFromInt(address))[0..allocation.storage_size];
            state.alloc_allocator.rawFree(storage, allocation.alignment, @returnAddress());
        }
        state.extra_allocations.deinit(state.allocator);
        state = .{};
    }

    const pointer = try reallocateTracked(null, 64);
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(pointer) % 16);

    const zero = try reallocateTracked(null, 0);
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(zero) % 16);
    try std.testing.expectEqual(@as(usize, 1), state.extra_allocations.get(@intFromPtr(zero)).?.storage_size);
    try std.testing.expectError(error.OutOfMemory, allocateTracked(16, std.math.maxInt(usize)));

    var external: u8 = 0;
    try std.testing.expectError(error.ExternalAllocation, reallocateTracked(&external, 64));
}

test "dl symbol lookup preserves versions, caller scopes, and handle validation" {
    state = .{ .allocator = std.testing.allocator };
    defer {
        for (state.dyn_objects.values()) |*object| {
            object.segments.deinit(state.allocator);
            object.deps_breadth_first.deinit(state.allocator);
            object.binding_dependencies.deinit(state.allocator);
            object.syms_array.deinit(state.allocator);
            for (object.syms.values()) |*indices| indices.deinit(state.allocator);
            object.syms.deinit(state.allocator);
        }
        state.dyn_objects.deinit(state.allocator);
        state.dyn_objects_sorted_indices.deinit(state.allocator);
        state.preload_root_indices.deinit(state.allocator);
        state.dl_handles.deinit(state.allocator);
        state = .{};
        last_dl_error = null;
        dlerror_cleared = true;
    }

    // Distinct synthetic ranges make the chosen provider and version observable.
    for ([_][]const u8{ "lookup-root", "lookup-dependency", "lookup-preload" }, 0..) |name, index| {
        const key: DynObjectId = .{ .ino = index + 1 };
        try state.dyn_objects.put(state.allocator, key, DynObject.init(key, name, name));
        const object = &state.dyn_objects.values()[index];
        object.mapped_at = (index + 1) * 0x1000;
        object.ref_count = 1;
        object.current_epoch = 1;

        var segment = std.mem.zeroes(DynObject.LoadSegment);
        segment.loaded_at = object.mapped_at;
        segment.mem_size = 0x100;
        try object.segments.put(state.allocator, 0, segment);
        try object.deps_breadth_first.append(state.allocator, index);
        try state.dyn_objects_sorted_indices.append(state.allocator, index);

        for ([_][]const u8{ "V1", "V2" }, 0..) |version, symbol_index| {
            try object.syms_array.append(state.allocator, .{
                .name = "lookup-test",
                .version = version,
                .hidden = false,
                .default_version = symbol_index == 0,
                .offset = 0,
                .type = .OBJECT,
                .bind = .GLOBAL,
                .shidx = 1,
                .value = 0x20 + symbol_index * 0x10,
                .size = 1,
            });
            const entry = try object.syms.getOrPut(state.allocator, "lookup-test");
            if (!entry.found_existing) entry.value_ptr.* = .empty;
            try entry.value_ptr.append(state.allocator, symbol_index);
        }
    }

    const root = &state.dyn_objects.values()[0];
    try root.deps_breadth_first.append(state.allocator, 1);
    const handle: DlHandle = .{ .tag = 0b10, .epoch = 1, .index = 0 };
    const handle_ptr: *anyopaque = @ptrFromInt(handle.toInt());
    try state.dl_handles.put(state.allocator, handle.toInt(), .{ .dyn_object_idx = 0, .epoch = 1, .open_count = 1 });

    try std.testing.expectEqual(@as(usize, 0x1020), @intFromPtr(dlsymSubstitute(handle_ptr, "lookup-test")));
    try std.testing.expectEqual(@as(usize, 0x1030), @intFromPtr(dlvsymSubstitute(handle_ptr, "lookup-test", "V2")));
    try std.testing.expectEqual(@as(usize, 0x1020), @intFromPtr(dlsymSubstitute(null, "lookup-test")));
    try std.testing.expect(dlvsymSubstitute(handle_ptr, "lookup-test", "") == null);
    try std.testing.expect(std.mem.indexOf(u8, last_dl_error.?, "lookup-test@ for library") != null);
    try std.testing.expect(dlerrorSubstitute() != null);
    try std.testing.expect(dlerrorSubstitute() == null);

    const next: *anyopaque = @ptrFromInt(DlHandle.rtld_next.toInt());
    for ([_]?[]const u8{ null, "V2" }) |version| {
        const offset: usize = if (version == null) 0x20 else 0x30;
        try std.testing.expectEqual(0x2000 + offset, @intFromPtr(lookupDlSymbol(next, "lookup-test", version, 0x1010)));
        try std.testing.expect(lookupDlSymbol(next, "lookup-test", version, 0) == null);
        try std.testing.expect(std.mem.indexOf(u8, last_dl_error.?, "unable to resolve RTLD_NEXT caller") != null);

        try std.testing.expect(lookupDlSymbol(@ptrFromInt(1), "lookup-test", version, 0) == null);
        try std.testing.expect(std.mem.indexOf(u8, last_dl_error.?, "invalid library handle") != null);

        state.dl_handles.getPtr(handle.toInt()).?.open_count = 0;
        try std.testing.expect(lookupDlSymbol(handle_ptr, "lookup-test", version, 0) == null);
        try std.testing.expect(std.mem.indexOf(u8, last_dl_error.?, "is closed") != null);
        state.dl_handles.getPtr(handle.toInt()).?.open_count = 1;

        root.current_epoch = 2;
        try std.testing.expect(lookupDlSymbol(handle_ptr, "lookup-test", version, 0) == null);
        try std.testing.expect(std.mem.indexOf(u8, last_dl_error.?, "is stale") != null);
        root.current_epoch = 1;
    }

    try state.preload_root_indices.append(state.allocator, 2);
    for ([_]?[]const u8{ null, "V1" }) |version| {
        try std.testing.expectEqual(@as(usize, 0x3020), @intFromPtr(lookupDlSymbol(handle_ptr, "lookup-test", version, 0x1010)));
        try std.testing.expectEqual(@as(usize, 0x1020), @intFromPtr(lookupDlSymbol(handle_ptr, "lookup-test", version, 0x3010)));
        try std.testing.expectEqual(@as(usize, 0x2020), @intFromPtr(lookupDlSymbol(next, "lookup-test", version, 0x1010)));
    }
}

test "binding retention follows resolution provenance and declared reachability" {
    state = .{ .allocator = std.testing.allocator };
    defer {
        for (state.dyn_objects.values()) |*object| {
            object.segments.deinit(state.allocator);
            object.binding_dependencies.deinit(state.allocator);
            object.dependencies.deinit(state.allocator);
            object.deps_breadth_first.deinit(state.allocator);
            object.syms_array.deinit(state.allocator);
            for (object.syms.values()) |*indices| indices.deinit(state.allocator);
            object.syms.deinit(state.allocator);
        }
        state.dyn_objects.deinit(state.allocator);
        state.ifunc_resolved_addrs.deinit(state.allocator);
        state.irel_resolved_targets.deinit(state.allocator);
        state = .{};
    }

    // Synthetic, disjoint object ranges; the callable resolver is added below.
    for ([_][]const u8{ "requester", "provider", "implementation" }, 0..) |name, index| {
        const key: DynObjectId = .{ .ino = index + 1 };
        try state.dyn_objects.put(state.allocator, key, DynObject.init(key, name, name));
        var segment = std.mem.zeroes(DynObject.LoadSegment);
        segment.loaded_at = (index + 1) * 0x1000;
        segment.mem_size = 0x100;
        try state.dyn_objects.values()[index].segments.put(state.allocator, 0, segment);
    }

    const Case = struct {
        address: usize,
        hint: ?usize,
        owner: ?usize,
    };
    const cases = [_]Case{
        .{ .address = 0x2020, .hint = 1, .owner = 1 },
        .{ .address = 0x3020, .hint = 1, .owner = 2 }, // IFUNC result outside its provider.
        .{ .address = 0x3020, .hint = null, .owner = 2 }, // IRELATIVE has no provider hint.
        .{ .address = 0x2020, .hint = std.math.maxInt(usize), .owner = 1 },
        .{ .address = 0, .hint = std.math.maxInt(usize), .owner = null }, // Unresolved weak.
        .{ .address = 0x1020, .hint = 0, .owner = null }, // Self-binding adds no dependency.
        .{ .address = 0x5000, .hint = 1, .owner = null },
        .{ .address = 0x2100, .hint = 1, .owner = null }, // Segment end is exclusive.
    };

    const requester = &state.dyn_objects.values()[0];
    for (cases) |case| {
        requester.binding_dependencies.clearRetainingCapacity();
        try recordBindingDependency(requester, case.address, case.hint);
        try recordBindingDependency(requester, case.address, case.hint);

        if (case.owner) |owner_index| {
            try std.testing.expectEqualSlices(usize, &.{owner_index}, requester.binding_dependencies.items);
        } else {
            try std.testing.expectEqual(@as(usize, 0), requester.binding_dependencies.items.len);
        }
    }

    const provider = &state.dyn_objects.values()[1];
    try requester.dependencies.append(state.allocator, 1);
    try collectDepsBreadthFirst(requester);

    const definition: DynSym = .{
        .name = "binding-test",
        .version = "",
        .hidden = false,
        .default_version = true,
        .offset = 0,
        .type = .FUNC,
        .bind = .GLOBAL,
        .shidx = 1,
        .value = 0x20,
        .size = 1,
    };
    var reference = definition;
    reference.shidx = std.elf.SHN_UNDEF;
    try requester.syms_array.append(state.allocator, reference); // ELF symbol zero is reserved.
    try requester.syms_array.append(state.allocator, reference);
    try provider.syms_array.append(state.allocator, definition);
    const indices = try provider.syms.getOrPut(state.allocator, definition.name);
    indices.value_ptr.* = .empty;
    try indices.value_ptr.append(state.allocator, 0);

    requester.binding_dependencies.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 0x2020), (try resolveSymbol(requester, 1)).address);
    try std.testing.expectEqual(@as(usize, 0), requester.binding_dependencies.items.len);

    requester.syms_array.items[1].name = "missing";
    requester.syms_array.items[1].bind = .WEAK;
    try std.testing.expectEqual(@as(usize, 0), (try resolveSymbol(requester, 1)).address);
    try std.testing.expectEqual(@as(usize, 0), requester.binding_dependencies.items.len);

    // Cached redirection must be recognized even for a non-IFUNC definition,
    // both in the requester and in a declared provider.
    requester.syms_array.items[1] = definition;
    try state.ifunc_resolved_addrs.put(state.allocator, 0x1020, 0x3020);
    try std.testing.expectEqual(@as(usize, 0x3020), (try resolveSymbol(requester, 1)).address);
    try std.testing.expectEqualSlices(usize, &.{2}, requester.binding_dependencies.items);

    requester.binding_dependencies.clearRetainingCapacity();
    requester.syms_array.items[1] = reference;
    try state.ifunc_resolved_addrs.put(state.allocator, 0x2020, 0x3020);
    for (0..2) |_| {
        try std.testing.expectEqual(@as(usize, 0x3020), (try resolveSymbol(requester, 1)).address);
    }
    try std.testing.expectEqualSlices(usize, &.{2}, requester.binding_dependencies.items);

    const Resolver = struct {
        fn resolve() callconv(.c) usize {
            return 0x3020;
        }
    };
    var resolver_segment = std.mem.zeroes(DynObject.LoadSegment);
    resolver_segment.mem_offset = 0x400;
    resolver_segment.loaded_at = @intFromPtr(&Resolver.resolve);
    resolver_segment.mem_size = 1;
    try provider.segments.put(state.allocator, 1, resolver_segment);
    provider.syms_array.items[0].type = .GNU_IFUNC;
    provider.syms_array.items[0].value = 0x400;

    requester.binding_dependencies.clearRetainingCapacity();
    for (0..2) |_| {
        try std.testing.expectEqual(@as(usize, 0x3020), (try resolveSymbol(requester, 1)).address);
    }
    try std.testing.expectEqualSlices(usize, &.{2}, requester.binding_dependencies.items);

    // The same redirected target needs no extra edge once a declared path
    // requester -> provider -> implementation already keeps it alive.
    try provider.dependencies.append(state.allocator, 2);
    requester.deps_breadth_first.clearRetainingCapacity();
    try collectDepsBreadthFirst(requester);
    requester.binding_dependencies.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 0x3020), (try resolveSymbol(requester, 1)).address);
    try recordBindingDependency(requester, 0x3020, null);
    try std.testing.expectEqual(@as(usize, 0), requester.binding_dependencies.items.len);
}
