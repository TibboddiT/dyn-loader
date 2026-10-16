//! Native x86-64 glibc integration for the loader.
//! Discovers private layouts through debugger metadata and code inspection.

const std = @import("std");

const common = @import("../libc.zig");
const DynObject = @import("../DynObject.zig");
const CodeView = @import("../CodeView.zig");
const InstructionFlow = @import("../InstructionFlow.zig");
const Register = InstructionFlow.Register;
const logger = @import("../logger.zig");
const Services = common.Services;
const currentThreadPointer = common.currentThreadPointer;
const blockThreadSignals = common.blockThreadSignals;
const restoreThreadSignals = common.restoreThreadSignals;
const findLibcSymbol = common.findLibcSymbol;
const findPltSlot = common.findPltSlot;
const resolveEntryJump = common.resolveEntryJump;

pub const system_libc_names = [_][]const u8{"libc.so.6"};

// Runtime discovery and lifecycle callbacks.
// ------------------------------------------

const Layout = struct {
    // Loaded address of `_rtld_global_ro`, distinct from writable `_rtld_global`.
    rtld_mapped_address: usize,
    // Byte offsets within `_rtld_global_ro`. Older libc lacks `__libc_early_init`.
    tls_offsets: ?GlibcTlsOffsets,
};

/// Borrows native mappings, which must outlive the runtime and all its workers.
const State = struct {
    // `null` denotes the split-libpthread case until that object is prepared.
    // A failed detector returns an error rather than publishing a partial layout.
    threads: ?GlibcThreadLayout,
    earlyInit: ?*const fn (initial: bool) callconv(.c) void,
    initCtype: ?*const fn () callconv(.c) void,
};

const vtable: common.VTable = .{
    .destroyState = &destroyState,
    .initInitialThread = &initInitialThread,
    .prepareThreads = &prepareThreads,
    .supportsWorkers = &supportsWorkers,
    .prepareObject = &prepareObject,
    .threadStorageSize = &threadStorageSize,
    .patchAllocatorCalls = &patchAllocatorCalls,
    .initWorker = &initWorker,
    .prepareWorker = &prepareWorker,
    .beginSpawn = &beginSpawn,
    .spawnFailed = &spawnFailed,
    .registerWorker = &registerWorker,
    .enterUserCode = &enterUserCode,
    .finishStartup = &finishStartup,
    .unregisterWorker = &unregisterWorker,
    .releaseAfterJoin = &releaseAfterJoin,
};

pub fn isLoaderName(name: []const u8) bool {
    return std.mem.eql(u8, name, "ld-linux-x86-64.so.2") or std.mem.eql(u8, name, "ld-linux.so.2");
}

pub fn isThreadSupportName(name: []const u8) bool {
    return std.mem.eql(u8, name, "libpthread.so.0");
}

/// Keeps different symbol versions in separate native `timer_create` slots.
/// Slot zero is the fallback for unversioned or unlisted definitions.
pub fn timerBindingIndex(version: []const u8) usize {
    inline for (.{ "GLIBC_2.2.5", "GLIBC_2.3.3", "GLIBC_2.34" }, 1..) |candidate, index| {
        if (std.mem.eql(u8, version, candidate)) return index;
    }
    return 0;
}

/// Tests for the runtime marker; recognition alone does not validate its layout.
pub fn recognizes(services: *const Services, object: *DynObject) !bool {
    return try findLibcSymbol(services, object, "_rtld_global_ro") != null;
}

/// Creates a runtime after successful recognition.
/// The runtime owns the allocated `State` and write plan, and borrows native
/// mappings and the `Services` interface.
/// Inspects code without executing it. Rejects unproven layouts.
pub fn create(services: *const Services, allocator: std.mem.Allocator, object: *DynObject) !common.Runtime {
    var capability: []const u8 = "symbols";
    errdefer logger.err("glibc.inspect: object={s} capability={s} action=failed", .{ object.name, capability });
    const marker = (try findLibcSymbol(services, object, "_rtld_global_ro")).?;
    const early_init = try findLibcSymbol(services, object, "__libc_early_init");
    const ctype_init = try findLibcSymbol(services, object, "__ctype_init");
    const errno_symbol = try services.lookupSymbol(object, "__errno_location", false);

    capability = "tls_offsets";
    const layout: Layout = .{
        .rtld_mapped_address = try marker.getStaticAddress(),
        .tls_offsets = if (early_init != null)
            try detectGlibcTlsOffsets(allocator, object, try CodeView.fromSymbol(services.inspect(object), "__libc_early_init"))
        else
            null,
    };
    logger.debug("glibc.inspect: object={s} capability=tls_offsets evidence={any}", .{ object.name, layout });

    capability = "threads";
    const threads = detectGlibcThreadLayout(allocator, services, object) catch |err| switch (err) {
        error.CodePatternMismatch => return error.UnrecognizedGlibcThreadLayout,
        else => return err,
    };
    if (threads) |layout_info| try validateThreadStorage(layout_info, services.native_metadata_capacity);

    logger.debug("glibc.inspect: object={s} integrated_threads={} early_init={} ctype_init={} errno_function_host=0x{x}", .{ object.name, threads != null, early_init != null, ctype_init != null, try errno_symbol.getStaticAddress() });
    capability = "runtime_state";
    const state = try allocator.create(State);
    errdefer allocator.destroy(state);
    state.* = .{
        .threads = threads,
        .earlyInit = if (early_init) |symbol| @ptrFromInt(try symbol.getStaticAddress()) else null,
        .initCtype = if (ctype_init) |symbol| @ptrFromInt(try symbol.getStaticAddress()) else null,
    };

    var runtime = common.Runtime.init(allocator, .{
        .services = services,
        .state = state,
        .vtable = &vtable,
        .getErrnoLocation = @ptrFromInt(try errno_symbol.getStaticAddress()),
    });
    errdefer runtime.write_ops.deinit(allocator);
    try appendWritePlan(&runtime, layout);
    return runtime;
}

fn getState(runtime: *const common.Runtime) *State {
    return @ptrCast(@alignCast(runtime.state));
}

fn destroyState(runtime: *common.Runtime) void {
    runtime.allocator.destroy(getState(runtime));
}

fn initInitialThread(runtime: *common.Runtime) !void {
    const state = getState(runtime);
    if (state.threads) |*threads| try initGlibcInitialThread(threads);
    if (state.earlyInit) |initialize| {
        // glibc uses `initial` to mark its outer namespace as single-threaded.
        // This libc is loaded into an existing host, so it cannot make that
        // assumption. Early init also installs ctype data for the current thread
        // and computes default pthread attributes from the runtime TLS values.
        // https://github.com/bminor/glibc/blob/glibc-2.39/elf/libc_early_init.c#L31-L44
        logger.debug("glibc.initial_thread: function=__libc_early_init function_host=0x{x} action=call", .{@intFromPtr(initialize)});
        initialize(false);
        logger.debug("glibc.initial_thread: function=__libc_early_init action=returned", .{});
    }
}

fn supportsWorkers(runtime: *const common.Runtime) bool {
    return getState(runtime).threads != null;
}

fn prepareThreads(runtime: *common.Runtime) !void {
    const threads = &getState(runtime).threads.?;
    try initGlibcInitialThread(threads);

    // Native list/descriptor setup above and these process flags are permanent.
    // Worker counts belong to attempted creations, never to this transition.
    const multiple_threads: *c_int = @ptrFromInt(currentThreadPointer() + 24);
    multiple_threads.* = 1;
    if (threads.single_threaded) |flag| @atomicStore(u8, flag, 0, .release);
}

/// Discovers thread support when an older glibc's libpthread is prepared.
/// Pins that object because the retained list and lock addresses belong to it.
fn prepareObject(runtime: *common.Runtime, object: *DynObject) !void {
    const state = getState(runtime);
    if (state.threads != null or !isThreadSupportName(object.name)) return;

    logger.debug("glibc.threads: object={s} mode=legacy action=inspect", .{object.name});
    const layout = detectLegacyGlibcThreadLayout(runtime.allocator, runtime.services, object) catch |err| switch (err) {
        error.CodePatternMismatch => return error.UnrecognizedGlibcThreadLayout,
        else => return err,
    };
    try validateThreadStorage(layout, runtime.services.native_metadata_capacity);
    state.threads = layout;
    object.runtime_pinned = true;
    logger.debug("glibc.threads: object={s} mode=legacy action=validated pinned=true evidence={any}", .{ object.name, state.threads });
}

fn threadStorageSize(runtime: *const common.Runtime) usize {
    // Use the loaded library's `sizeof(struct pthread)`, not a host-side copy of
    // its private C definition. The extra page is reserved descriptor space;
    // this value is not the worker's stack size or ELF TLS payload size.
    const symbol = runtime.services.lookupRuntimeSymbol("_thread_db_sizeof_pthread") catch return common.bootstrapThreadStorageSize();
    const address = symbol.getStaticAddress() catch return common.bootstrapThreadStorageSize();
    const size: *const u32 = @ptrFromInt(address);
    return size.* + std.heap.pageSize();
}

fn patchAllocatorCalls(_: *common.Runtime, _: *DynObject) !void {
    // glibc allocation calls are covered by symbol substitution.
}

fn initWorker(runtime: *common.Runtime) common.WorkerHandle {
    // The child inherits the blocked mask. It must not run application signal
    // handlers before its descriptor and per-thread libc state are initialized.
    const mask = blockThreadSignals();
    return .{
        .runtime = runtime,
        .state = null,
        .parent_tp = currentThreadPointer(),
        .creator_mask = mask,
        .spawn_mask = null,
    };
}

/// Atomically reserves one native thread count before Zig spawns.
fn prepareWorker(worker: *common.WorkerHandle) !void {
    const threads = &getState(worker.runtime).threads.?;
    _ = @atomicRmw(u32, threads.nthreads, .Add, 1, .seq_cst);
}

fn beginSpawn(_: *common.WorkerHandle) void {
    // `initWorker` already blocked all signals before taking the registry lock.
}

fn spawnFailed(worker: *common.WorkerHandle) void {
    // Undo the reserved thread count. Keeping the single-thread fast paths
    // disabled is conservative even when the attempted spawn fails.
    const threads = &getState(worker.runtime).threads.?;
    _ = @atomicRmw(u32, threads.nthreads, .Sub, 1, .seq_cst);
}

fn registerWorker(worker: *const common.WorkerHandle, tp: usize) !void {
    const state = getState(worker.runtime);
    registerGlibcWorker(&state.threads.?, tp);
    if (state.initCtype) |initialize| {
        // `__ctype_init` must initialize the child's thread-local pointers.
        initialize();
    }
}

fn enterUserCode(worker: *const common.WorkerHandle) void {
    worker.restoreCreatorSignals();
}

fn finishStartup(_: *const common.WorkerHandle) void {
    // There is no separately allocated startup state to await or release.
}

fn unregisterWorker(worker: *const common.WorkerHandle, tp: usize) void {
    _ = blockThreadSignals();
    unregisterGlibcWorker(&getState(worker.runtime).threads.?, tp);
}

fn releaseAfterJoin(_: *const common.WorkerHandle) void {
    // Zig owns the descriptor allocation and has already reclaimed it.
}

// Private TLS and thread-layout inspection.
// -----------------------------------------

const GlibcTlsOffsets = struct {
    tls_size_offset: u32,
    tls_align_offset: u32,
};

/// Finds the static TLS size/alignment loads in `__libc_early_init`.
/// NPTL's inlined early setup rounds storage sizes using values supplied by rtld.
/// Verifies the division's operands: `(size + alignment - 1) / alignment`,
/// with zero in the high half of the dividend. Both fields must originate from
/// the `_rtld_global_ro` relocation, including when SIMD instructions load them.
/// https://github.com/bminor/glibc/blob/glibc-2.39/sysdeps/nptl/pthread_early_init.h#L43-L54
/// The TLS calculation is `roundup(dl_tls_static_size, dl_tls_static_align)`:
/// https://github.com/bminor/glibc/blob/glibc-2.39/nptl/nptl-stack.h#L56-L62
fn detectGlibcTlsOffsets(allocator: std.mem.Allocator, object: *DynObject, code: CodeView) !GlibcTlsOffsets {
    var flow = try analyzeGlibc(allocator, object, code);
    defer flow.deinit();

    const slot = try globalSlot(object, "_rtld_global_ro");
    return tlsOffsets(flow, slot);
}

/// glibc `list_t` stores addresses of embedded list nodes, not thread pointers.
/// Empty heads point to themselves; a zero-filled node is not yet registered.
const GlibcThreadList = extern struct {
    next: usize,
    prev: usize,

    fn init(list: *GlibcThreadList) void {
        list.* = .{ .next = @intFromPtr(list), .prev = @intFromPtr(list) };
    }
};

const GlibcThreadLayout = struct {
    // Caller-owned stacks must not enter glibc's reusable stack cache.
    // Offsets here are relative to the thread pointer (`struct pthread` base).
    const Ownership = union(enum) {
        byte_flag: usize,
        word_mode: struct {
            offset: usize,
            value: u32,
        },
    };

    // Native stack-list heads: active libc allocations, caller-owned stacks,
    // and reusable libc allocations. All are borrowed mapped addresses.
    used: *GlibcThreadList,
    user: *GlibcThreadList,
    cache: *GlibcThreadList,
    list_offset: usize, // Offset of `struct pthread.list` from the thread pointer.
    ownership: Ownership,
    lock: *u32,
    in_flight: *usize, // Journal used by `fork`'s interrupted-list recovery.
    nthreads: *u32, // Includes the initial thread, unlike musl's `threads_minus_1`.
    single_threaded: ?*u8,
    initialized: bool,
};

const GlibcForkLists = struct {
    // `cache` is an offset in `_rtld_global`; `ownership` contains a pthread offset.
    cache: usize,
    ownership: GlibcThreadLayout.Ownership,
};

fn validateThreadStorage(layout: GlibcThreadLayout, capacity: usize) !void {
    if (layout.list_offset > capacity - @sizeOf(GlibcThreadList)) return error.NativeMetadataCapacityExceeded;

    const ownership_end = switch (layout.ownership) {
        .byte_flag => |offset| try std.math.add(usize, offset, 1),
        .word_mode => |mode| try std.math.add(usize, mode.offset, @sizeOf(u32)),
    };
    if (ownership_end > capacity) return error.NativeMetadataCapacityExceeded;
}

/// Reads one scalar debugger descriptor: bit size, element count, byte offset.
/// Validates both its shape and its containing structure before using the offset.
/// Uses debugger exports instead of a compiled-in `struct pthread` layout.
/// https://github.com/bminor/glibc/blob/glibc-2.39/nptl_db/structs.def#L51-L67
/// Field bit size and element count:
/// https://github.com/bminor/glibc/blob/glibc-2.39/nptl_db/db_info.c#L50-L58
/// Structure size and field byte offset:
/// https://github.com/bminor/glibc/blob/glibc-2.39/nptl_db/db_info.c#L72-L76
fn threadDbFieldOffset(services: *const Services, dyn_object: *DynObject, name: []const u8, field_size: usize, container_size: usize) !usize {
    const symbol = try services.lookupSymbol(dyn_object, name, true);
    const owner = services.definingObject(symbol);
    if (owner.syms_array.items[symbol.sym_idx].size != 12) return error.InvalidThreadDbDescriptor;

    const address = try owner.mappedDataAddress(symbol.value, 12);
    const descriptor: *align(1) const [3]u32 = @ptrFromInt(address);
    const offset: usize = descriptor[2];
    logger.debug("glibc.thread_db: object={s} symbol={s} descriptor_host=0x{x} bits={d} count={d} offset={d} expected_bytes={d} container_bytes={d}", .{ dyn_object.name, name, address, descriptor[0], descriptor[1], offset, field_size, container_size });
    if (descriptor[0] != field_size * 8 or descriptor[1] != 1 or
        offset > container_size or field_size > container_size - offset)
    {
        return error.InvalidThreadDbDescriptor;
    }

    return offset;
}

/// Detects the layout with NPTL integrated into libc. A missing debugger marker
/// returns `null` so a later libpthread load can supply the legacy implementation.
/// Once the marker exists, malformed or unrecognized details are errors.
fn detectGlibcThreadLayout(allocator: std.mem.Allocator, services: *const Services, dyn_object: *DynObject) !?GlibcThreadLayout {
    if (try findLibcSymbol(services, dyn_object, "_thread_db_rtld_global__dl_stack_used") == null) {
        logger.debug("glibc.threads: object={s} mode=integrated result=marker_absent awaiting=libpthread", .{dyn_object.name});
        return null;
    }

    const create_code = try CodeView.fromSymbol(services.inspect(dyn_object), "pthread_create");
    var create_flow = try analyzeGlibc(allocator, dyn_object, create_code);
    defer create_flow.deinit();
    if (!hasStore(create_flow, threadAddress(24), constant(1), 32)) return error.GlibcMultipleThreadsStoreNotFound;

    const global = try services.lookupSymbol(dyn_object, "_rtld_global", true);
    const global_object = services.definingObject(global);
    const global_size = global_object.syms_array.items[global.sym_idx].size;
    const size_symbol = try services.lookupSymbol(dyn_object, "_thread_db_sizeof_pthread", true);
    const size_object = services.definingObject(size_symbol);
    if (size_object.syms_array.items[size_symbol.sym_idx].size != 4) return error.InvalidGlibcThreadLayout;

    const size_address = try size_object.mappedDataAddress(size_symbol.value, 4);
    const pthread_size = @as(*align(1) const u32, @ptrFromInt(size_address)).*;

    const list_size = @sizeOf(GlibcThreadList);
    const used_offset = try threadDbFieldOffset(services, dyn_object, "_thread_db_rtld_global__dl_stack_used", list_size, global_size);
    const user_offset = try threadDbFieldOffset(services, dyn_object, "_thread_db_rtld_global__dl_stack_user", list_size, global_size);
    const list_offset = try threadDbFieldOffset(services, dyn_object, "_thread_db_pthread_list", list_size, pthread_size);
    if (try threadDbFieldOffset(services, dyn_object, "_thread_db_list_t_next", @sizeOf(usize), list_size) != 0 or
        try threadDbFieldOffset(services, dyn_object, "_thread_db_list_t_prev", @sizeOf(usize), list_size) != @sizeOf(usize))
    {
        return error.InvalidGlibcThreadLayout;
    }

    // `fork` recovery reveals the cache and ownership fields missing from
    // debugger exports.
    const code = try CodeView.fromSymbol(services.inspect(dyn_object), "fork");
    var flow = try analyzeGlibc(allocator, dyn_object, code);
    defer flow.deinit();

    // Use the GOT slot as the origin: `_rtld_global` belongs to another object.
    const slot = try globalSlot(dyn_object, "_rtld_global");
    const used_head = globalAddress(slot, used_offset);
    const user_head = globalAddress(slot, user_offset);
    const cache_head = try detectStackCache(flow, used_head);
    if (cache_head.kind != .global_address or cache_head.a != slot) return error.InvalidGlibcThreadLayout;
    try requireEmptyHead(flow, used_head);
    try requireEmptyHead(flow, user_head);
    const offsets: GlibcForkLists = .{
        .cache = std.math.cast(usize, cache_head.b) orelse return error.InvalidGlibcThreadLayout,
        .ownership = try detectOwnership(flow, user_head, list_offset),
    };

    const FieldRange = struct {
        offset: usize,
        size_bytes: usize,
    };
    const ownership: FieldRange = switch (offsets.ownership) {
        .byte_flag => |offset| .{ .offset = offset, .size_bytes = 1 },
        .word_mode => |mode| .{ .offset = mode.offset, .size_bytes = 4 },
    };
    if (ownership.offset < list_offset + list_size or ownership.offset > pthread_size or
        ownership.size_bytes > pthread_size - ownership.offset or ownership.offset % ownership.size_bytes != 0)
    {
        return error.InvalidGlibcThreadLayout;
    }

    var heads: [3]*GlibcThreadList = undefined;
    const head_offsets = [_]usize{ used_offset, user_offset, offsets.cache };
    for (head_offsets, 0..) |offset, i| {
        if (offset > global_size or list_size > global_size - offset or offset % @alignOf(GlibcThreadList) != 0) return error.InvalidGlibcThreadLayout;
        for (head_offsets[0..i]) |previous| {
            if (offset < previous + list_size and previous < offset + list_size) return error.InvalidGlibcThreadLayout;
        }

        const virtual_address = std.math.add(usize, global.value, offset) catch return error.InvalidDataAddress;
        const address = try global_object.mappedDataAddress(virtual_address, list_size);
        const location = try services.findSegment(address);
        if (!location.dyn_object.segments.values()[location.segment_index].flags_first.write) return error.InvalidGlibcThreadLayout;
        heads[i] = @ptrFromInt(address);
    }

    if (list_offset % @alignOf(GlibcThreadList) != 0) return error.InvalidGlibcThreadLayout;

    // The supported rtld layouts place cache size after the 16-byte cache head,
    // then the in-flight journal (+24) and lock (+32). These positions are
    // assumed first, then checked against `fork`'s load/reset instructions below.
    const in_flight_offset = offsets.cache + 24;
    const lock_offset = offsets.cache + 32;
    if (!hasRead(flow, globalAddress(slot, in_flight_offset)) or
        !hasStore(flow, globalAddress(slot, in_flight_offset), constant(0), 64) or
        !hasStore(flow, globalAddress(slot, lock_offset), constant(0), 32)) return error.GlibcStackJournalNotFound;

    if (lock_offset > global_size or 4 > global_size - lock_offset) return error.InvalidGlibcThreadLayout;

    const nthreads = try services.lookupSymbol(dyn_object, "__nptl_nthreads", true);
    const single_threaded = try services.lookupSymbol(dyn_object, "__libc_single_threaded", true);

    if (services.definingObject(nthreads) != dyn_object or services.definingObject(single_threaded) != dyn_object) return error.InvalidGlibcThreadLayout;
    if (dyn_object.syms_array.items[nthreads.sym_idx].size != 4 or dyn_object.syms_array.items[single_threaded.sym_idx].size != 1) return error.InvalidGlibcThreadLayout;

    logger.debug("glibc.threads: object={s} mode=integrated pthread_bytes={d} list_offset={d} used_offset={d} user_offset={d} cache_offset={d} ownership={any} lock_offset={d} journal_offset={d}", .{ dyn_object.name, pthread_size, list_offset, used_offset, user_offset, offsets.cache, offsets.ownership, lock_offset, in_flight_offset });
    return .{
        .used = heads[0],
        .user = heads[1],
        .cache = heads[2],
        .list_offset = list_offset,
        .ownership = offsets.ownership,
        .lock = @ptrFromInt(try global_object.mappedWritableDataAddress(global.value + lock_offset, 4, 4)),
        .in_flight = @ptrFromInt(try global_object.mappedWritableDataAddress(global.value + in_flight_offset, 8, 8)),
        .nthreads = @ptrFromInt(try dyn_object.mappedWritableDataAddress(nthreads.value, 4, 4)),
        .single_threaded = @ptrFromInt(try dyn_object.mappedWritableDataAddress(single_threaded.value, 1, 1)),
        .initialized = false,
    };
}

/// Finds legacy libpthread's stack lists through its `__reclaim_stacks` callback.
/// Cross-checks fixed descriptor offsets against native code.
/// https://github.com/bminor/glibc/blob/glibc-2.31/nptl/nptl-init.c#L364-L369
fn detectLegacyGlibcThreadLayout(allocator: std.mem.Allocator, services: *const Services, dyn_object: *DynObject) !GlibcThreadLayout {
    const init_code = try CodeView.fromSymbol(services.inspect(dyn_object), "__pthread_initialize_minimal");
    const create_code = try CodeView.fromSymbol(services.inspect(dyn_object), "pthread_create");
    var initial = try analyzeGlibc(allocator, dyn_object, init_code);
    defer initial.deinit();
    var creation = try analyzeGlibc(allocator, dyn_object, create_code);
    defer creation.deinit();
    if (!hasStore(creation, threadAddress(24), constant(1), 32)) return error.GlibcMultipleThreadsStoreNotFound;

    var callback: ?usize = null;
    for (initial.nodes.items) |node| {
        if (!node.reached or node.instruction.op != .call or node.instruction.target == null) continue;
        if (!try callsSymbol(dyn_object, node.instruction.target.?, "__libc_pthread_init")) continue;

        // `RSI` is the second System V argument, not a compiler-selected
        // temporary. Its defining `lea` may occur earlier or use another register.
        const argument = node.state.registers[Register.rsi];
        if (argument.kind != .address) return error.GlibcReclaimCallbackNotFound;
        try uniqueOffset(&callback, argument.a);
    }

    // The callback has no exported size. The window bounds inspection; reachable
    // decoding and recognized non-returning calls determine which bytes are used.
    const callback_address = callback orelse return error.GlibcReclaimCallbackNotFound;
    const callback_code = try CodeView.fromDynObject(dyn_object, callback_address, 0x300);
    var flow = try analyzeGlibc(allocator, dyn_object, callback_code);
    defer flow.deinit();

    // The supported split libpthread does not export debugger descriptors.
    // Retain its known field positions, but prove their use through the native
    // initialization and recovery operations instead of fixed register bytes.
    const list_offset = 704;

    // Child recovery resets exactly two active heads to self-links. Classify
    // them by the ownership-dependent reinsertion, not by address order.
    var heads: [2]usize = undefined;
    var head_count: usize = 0;
    for (flow.nodes.items) |node| {
        if (!node.reached or node.instruction.op != .mov or node.instruction.width != 64) continue;

        const destination = flow.destination(node);
        if (destination.kind != .address or !std.meta.eql(destination, flow.value(node, node.instruction.src))) continue;
        if (!hasStore(flow, shifted(destination, 8), destination, 64)) continue;
        if (head_count == heads.len) return error.AmbiguousCodePattern;

        heads[head_count] = std.math.cast(usize, destination.a) orelse return error.InvalidDataAddress;
        head_count += 1;
    }
    if (head_count != 2) return error.GlibcStackHeadsNotFound;

    var user: ?usize = null;
    var ownership: ?GlibcThreadLayout.Ownership = null;
    for (heads) |head| {
        const found = detectOwnership(flow, absolute(head), list_offset) catch |err| switch (err) {
            error.GlibcStackOwnershipNotFound => continue,
            else => return err,
        };

        if (ownership != null) return error.AmbiguousCodePattern;
        user = head;
        ownership = found;
    }
    const user_address = user orelse return error.GlibcStackOwnershipNotFound;
    const used = if (heads[0] == user_address) heads[1] else heads[0];
    const cache_value = try detectStackCache(flow, absolute(used));
    if (cache_value.kind != .address) return error.InvalidGlibcThreadLayout;
    const cache = std.math.cast(usize, cache_value.a) orelse return error.InvalidDataAddress;

    const ownership_offset = switch (ownership.?) {
        .byte_flag => |offset| offset,
        .word_mode => return error.InvalidGlibcThreadLayout,
    };
    if (ownership_offset != 1554 or
        !hasStore(initial, threadAddress(ownership_offset), constant(1), 8) or
        !hasStore(initial, absolute(user_address), threadAddress(list_offset), 64)) return error.InvalidGlibcThreadLayout;

    // In a fork child only the calling thread survives. Recovery sets its count
    // to one, repairs any journaled list change, and clears the inherited lock.
    // Exclude list-head writes when identifying the journal's node pointer.
    var journal: ?usize = null;
    var lock_address: ?usize = null;
    var thread_count: ?usize = null;
    for (flow.nodes.items, 0..) |node, index| {
        if (!node.reached or node.instruction.op != .mov) continue;
        const destination = flow.destination(node);
        const source = flow.value(node, node.instruction.src);
        if (destination.kind != .address) continue;

        if (node.instruction.width == 64 and std.meta.eql(source, threadAddress(list_offset)) and
            destination.a != user_address and destination.a != user_address + 8 and destination.a != used and destination.a != used + 8)
        {
            try uniqueOffset(&journal, destination.a);
        }
        if (node.instruction.width == 32 and source.is(.constant, 1)) {
            try uniqueOffset(&thread_count, destination.a);
        }

        if (node.instruction.width == 64 and source.is(.constant, 0) and index + 1 < flow.nodes.items.len) {
            const next = flow.nodes.items[index + 1];
            if (journal != null and destination.a == journal.? and next.instruction.op == .mov and next.instruction.width == 32 and
                flow.value(next, next.instruction.src).is(.constant, 0) and flow.destination(next).kind == .address)
            {
                try uniqueOffset(&lock_address, flow.destination(next).a);
            }
        }
    }

    const in_flight = journal orelse return error.GlibcStackJournalNotFound;
    const lock = lock_address orelse return error.GlibcStackLockNotFound;
    const nthreads = thread_count orelse return error.GlibcThreadCountNotFound;
    if (!hasRead(flow, absolute(in_flight)) or !hasStore(flow, absolute(in_flight), constant(0), 64)) return error.GlibcStackJournalNotFound;

    // The recovery reset alone could identify another zeroed word. Require
    // `pthread_create` to release the same candidate using an atomic exchange.
    var unlock_found = false;
    for (creation.nodes.items) |node| {
        if (node.reached and node.instruction.op == .exchange and std.meta.eql(creation.destination(node), absolute(lock)) and
            creation.value(node, node.instruction.src).is(.constant, 0))
        {
            unlock_found = true;
        }
    }
    if (!unlock_found) return error.GlibcStackLockNotFound;

    return .{
        .used = @ptrFromInt(try dyn_object.mappedWritableDataAddress(used, 16, 8)),
        .user = @ptrFromInt(try dyn_object.mappedWritableDataAddress(user_address, 16, 8)),
        .cache = @ptrFromInt(try dyn_object.mappedWritableDataAddress(cache, 16, 8)),
        .list_offset = @intCast(list_offset),
        .ownership = ownership.?,
        .lock = @ptrFromInt(try dyn_object.mappedWritableDataAddress(lock, 4, 4)),
        .in_flight = @ptrFromInt(try dyn_object.mappedWritableDataAddress(in_flight, 8, 8)),
        .nthreads = @ptrFromInt(try dyn_object.mappedWritableDataAddress(nthreads, 4, 4)),
        .single_threaded = null,
        // Legacy native initialization establishes the initial-thread lists;
        // the manual zero-state setup used for integrated NPTL must not repeat it.
        .initialized = true,
    };
}

/// Finds the stack-cache head from `fork`'s splice of the known `used` list.
/// Native recovery code:
/// https://github.com/bminor/glibc/blob/glibc-2.39/sysdeps/nptl/fork.h#L134-L149
fn detectStackCache(flow: InstructionFlow, used: InstructionFlow.Value) !InstructionFlow.Value {
    var result: ?InstructionFlow.Value = null;
    for (flow.nodes.items) |node| {
        if (!node.reached or node.instruction.op != .mov or node.instruction.width != 64) continue;
        const cache = flow.destination(node);
        if ((cache.kind != .address and cache.kind != .global_address) or std.meta.eql(cache, used) or
            !std.meta.eql(flow.value(node, node.instruction.src), contents(used)))
        {
            continue;
        }

        // Prove all four pointer updates of `list_splice`, including the stores
        // through the old head/tail pointers. A nearby address load is insufficient.
        if (!hasStore(flow, through(contents(used), 8), cache, 64) or
            !hasStore(flow, through(contents(shifted(used, 8)), 0), contents(cache), 64) or
            !hasStore(flow, through(contents(cache), 8), contents(shifted(used, 8)), 64))
        {
            continue;
        }

        if (result) |previous| {
            if (!std.meta.eql(previous, cache)) return error.AmbiguousCodePattern;
        }
        result = cache;
    }
    return result orelse error.GlibcStackSpliceNotFound;
}

/// Associates a descriptor field with the branch that reinserts the surviving
/// thread into the caller-owned list. A byte flag selects that branch when
/// nonzero; a word mode selects it when equal to a particular enum value.
/// Both links of the node and both links of the empty head must be assigned.
fn detectOwnership(flow: InstructionFlow, user: InstructionFlow.Value, list_offset: usize) !GlibcThreadLayout.Ownership {
    var result: ?GlibcThreadLayout.Ownership = null;
    for (flow.nodes.items, 0..) |node, index| {
        if (!node.reached or node.instruction.op != .compare or index + 1 >= flow.nodes.items.len) continue;
        const field = flow.value(node, node.instruction.dst);
        const rhs = flow.value(node, node.instruction.src);
        if (field.kind != .thread_field or field.b < 0) continue;

        // Scheduling may place flag-preserving address calculations between
        // the ownership test and its conditional branch.
        var branch_index = index + 1;
        while (branch_index < flow.nodes.items.len and branch_index - index <= 6) : (branch_index += 1) {
            const op = flow.nodes.items[branch_index].instruction.op;
            if (op != .lea and op != .mov and op != .nop and op != .vector_move) break;
        }
        if (branch_index >= flow.nodes.items.len or branch_index - index > 6) continue;
        const branch = flow.nodes.items[branch_index].instruction;
        if (branch.op != .branch or branch.target == null or branch.target.? < flow.code.address) continue;

        // x86 condition 4 is equal/zero (`JE`); 5 is not-equal/nonzero (`JNE`).
        // A self-test compares the byte with itself in the decoder's operand
        // representation. Its nonzero branch corresponds to a set ownership flag.
        var ownership: GlibcThreadLayout.Ownership = undefined;
        if (node.instruction.width == 32 and rhs.kind == .constant and rhs.a > 0 and rhs.a <= 127 and branch.condition == 4) {
            ownership = .{ .word_mode = .{ .offset = @intCast(field.b), .value = @intCast(rhs.a) } };
        } else if (node.instruction.width == 8 and std.meta.eql(field, rhs) and branch.condition == 5) {
            ownership = .{ .byte_flag = @intCast(field.b) };
        } else {
            continue;
        }

        // Limit the evidence to the target's straight-line block. Taking stores
        // from the opposite branch could reverse the inferred ownership meaning.
        const start = flow.indexAt(branch.target.? - flow.code.address) orelse return error.InvalidInstructionBranch;
        var end = start;
        while (end < flow.nodes.items.len and end - start < 16) : (end += 1) {
            const op = flow.nodes.items[end].instruction.op;
            if (op == .jump or op == .branch or op == .call or op == .ret) break;
        }
        var block = flow;
        // This is a borrowed view of the existing nodes, not a second owner.
        block.nodes.items = flow.nodes.items[start..end];
        const entry = threadAddress(list_offset);
        if (!hasStore(block, entry, user, 64) or !hasStore(block, shifted(entry, 8), user, 64) or
            !hasStore(block, user, entry, 64) or !hasStore(block, shifted(user, 8), entry, 64)) continue;
        if (result) |previous| {
            if (!std.meta.eql(previous, ownership)) return error.AmbiguousCodePattern;
        }
        result = ownership;
    }
    return result orelse error.GlibcStackOwnershipNotFound;
}

/// Builds a glibc-specific analysis. Borrows the object and code.
/// The caller must deinitialize the result.
fn analyzeGlibc(allocator: std.mem.Allocator, object: *DynObject, code: CodeView) !InstructionFlow {
    var options: InstructionFlow.Options = .{
        .thread_self_offsets = &.{ 0, 16 },
        .external_exit_context = object,
        .validateExternalExit = &validateColdExit,
        .borrowStackArgument = &borrowStackArgument,
        .preserve_syscall_arguments = true,
    };

    try setGlibcNoReturnTargets(object, code, &options, false);

    return InstructionFlow.initWithOptions(allocator, code, options) catch |err| {
        logger.err("glibc inspection failed for ELF code 0x{x}, {d} bytes: {s}", .{ code.address, code.bytes.len, @errorName(err) });
        return err;
    };
}

fn setGlibcNoReturnTargets(object: *DynObject, code: CodeView, options: *InstructionFlow.Options, inspect_private_helpers: bool) !void {
    var count: usize = 0;
    var offset: usize = 0;

    // Identify terminal PLT calls before following control flow. In particular,
    // the private legacy callback ends an assertion path with `__assert_fail`,
    // followed in memory by a different function, not a return instruction.
    // Snapshot windows also need private fatal helpers used by newer glibc.
    while (offset < code.bytes.len) {
        const instruction = InstructionFlow.decode(code, offset) catch break;
        if (instruction.op == .call and instruction.target != null) {
            if (try callsSymbol(object, instruction.target.?, "__assert_fail") or try callsSymbol(object, instruction.target.?, "__stack_chk_fail") or
                (inspect_private_helpers and try terminalPath(object, instruction.target.?, 2)))
            {
                if (std.mem.indexOfScalar(?usize, &options.noreturn_targets, instruction.target) == null) {
                    if (count == options.noreturn_targets.len) return error.InstructionAnalysisLimit;
                    options.noreturn_targets[count] = instruction.target;
                    count += 1;
                }
            }
        }
        offset = instruction.end;
    }
}

/// Accepts a direct symbol entry or a PLT stub for that symbol. All addresses
/// remain in this object's ELF coordinate space while checking relocations.
fn callsSymbol(object: *DynObject, target: usize, name: []const u8) !bool {
    for (object.syms_array.items) |symbol| {
        if (symbol.value == target and std.mem.eql(u8, symbol.name, name)) return true;
    }
    return (findPltSlot(object, target, name) catch |err| switch (err) {
        error.UnexpectedPltRelocation => null,
        else => return err,
    }) != null;
}

/// Accepts an external edge only if no explored path returns.
/// GCC may place abort or assertion paths outside the exported symbol size.
/// Inspects those blocks separately.
fn terminalColdPath(object: *DynObject, entry: usize) !bool {
    return terminalPath(object, entry, 0);
}

/// Checks that no path returns, following private fatal helpers to a bounded depth.
/// Tracks visited addresses to stop at closed cycles, which cannot return.
fn terminalPath(object: *DynObject, entry: usize, call_depth: u8) !bool {
    var pending: [32]usize = undefined;
    var count: usize = 1;
    pending[0] = entry;
    var visited: [256]usize = undefined;
    var visited_count: usize = 0;

    while (count != 0) {
        count -= 1;
        var address = pending[count];
        while (true) {
            if (std.mem.indexOfScalar(usize, visited[0..visited_count], address) != null) break;
            if (visited_count == visited.len) return false;

            visited[visited_count] = address;
            visited_count += 1;

            // Fifteen bytes is the architectural maximum instruction length.
            const code = CodeView.fromDynObject(object, address, 15) catch return false;
            const instruction = InstructionFlow.decode(code, 0) catch return false;
            if (instruction.trap) break;
            if (instruction.op == .ret) return false;
            if (instruction.op == .call and instruction.target != null and
                (try callsSymbol(object, instruction.target.?, "__assert_fail") or
                    try callsSymbol(object, instruction.target.?, "__stack_chk_fail") or
                    try callsSymbol(object, instruction.target.?, "abort") or
                    (call_depth != 0 and try terminalPath(object, instruction.target.?, call_depth - 1)))) break;
            if (instruction.op == .jump or instruction.op == .branch) {
                const target = instruction.target orelse return false;
                if (instruction.op == .jump) {
                    address = target;
                    continue;
                }
                if (count == pending.len) return false;
                pending[count] = target;
                count += 1;
            }
            address += instruction.end;
        }
    }
    return true;
}

fn validateColdExit(context: *anyopaque, entry: usize) !bool {
    return terminalColdPath(@ptrCast(@alignCast(context)), entry);
}

/// Bounds writes by snapshot helpers that neither retain nor return the pointer.
/// Unknown uses invalidate private spills. NSS snapshot helpers:
/// https://github.com/bminor/glibc/blob/glibc-2.39/nss/nss_database.c#L505-L538
fn borrowStackArgument(context: *anyopaque, allocator: std.mem.Allocator, entry: usize, argument_register: u4) !?usize {
    if (argument_register != Register.rdi) return null;
    const object: *DynObject = @ptrCast(@alignCast(context));
    const code = CodeView.fromDynObject(object, entry, 512) catch return null;
    var options: InstructionFlow.Options = .{ .log_errors = false };
    try setGlibcNoReturnTargets(object, code, &options, true);

    // A negative origin distinguishes the snapshot from real call-site offsets.
    options.initial_registers[Register.rdi] = .{ .kind = .call, .a = -1, .tainted = true };
    var flow = InstructionFlow.initWithOptions(allocator, code, options) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
    defer flow.deinit();

    const write_size = try firstArgumentWriteSize(flow, object);
    logger.debug("glibc.snapshot: helper_elf=0x{x} write_size={any}", .{ entry, write_size });
    return write_size;
}

/// Returns the exclusive upper bound of writes relative to the first argument.
/// Returns `null` if the helper may retain the snapshot pointer or its writes
/// cannot be bounded. Allows content access, but rejects pointer escape.
/// `object = null` disables symbol lookup and lock-helper exceptions for fixtures.
fn firstArgumentWriteSize(flow: InstructionFlow, object: ?*DynObject) !?usize {
    var argument_used = false;
    var write_size: usize = 0;
    for (flow.nodes.items) |node| {
        if (!node.reached) continue;

        const instruction = node.instruction;
        const source = flow.value(node, instruction.src);
        const destination = flow.destination(node);
        if (node.state.registers[Register.rsp].tainted) return null;
        if (instruction.op == .string_store) return null; // Implicit, potentially repeated writes.
        if (instruction.op == .leave and node.state.registers[Register.rbp].tainted) return null;
        if ((instruction.op == .divide or instruction.op == .multiply) and
            (node.state.registers[Register.rax].tainted or node.state.registers[Register.rdx].tainted)) return null;
        if (instruction.end == flow.code.bytes.len and instruction.op != .ret and instruction.op != .jump) return null;
        if (instruction.op == .ret and node.state.registers[Register.rax].tainted) return null;

        const tail_call = instruction.op == .jump and
            (instruction.target == null or instruction.target.? < flow.code.address or instruction.target.? >= flow.code.address + flow.code.bytes.len);
        if (instruction.op == .call or instruction.op == .syscall or tail_call) {
            // Include function argument registers and Linux's fourth syscall
            // argument (`R10`). Recognized one-argument lock helpers consume only
            // `RDI`; stale values in other volatile registers are not arguments.
            const one_argument_lock = object != null and instruction.target != null and
                (try callsSymbol(object.?, instruction.target.?, "__lll_lock_wait_private") or try callsSymbol(object.?, instruction.target.?, "__lll_lock_wake_private"));
            if (tail_call and !one_argument_lock) return null;
            for ([_]u4{ 7, 6, 2, 1, 8, 9, 10 }) |reg| {
                if (one_argument_lock and reg != 7) continue;
                if (node.state.registers[reg].tainted) return null;
            }
            if (!one_argument_lock) {
                // An unknown callee may consume stack-passed arguments too.
                for (node.state.slots) |slot| {
                    if (slot.used and slot.value.tainted) return null;
                }
            }
        }

        // Reading snapshot contents is distinct from retaining its address.
        // Scalar private spills are allowed; packed pointer stores are rejected
        // conservatively because this proof does not track their escape by lane.
        if (source.is(.call_field, -1)) argument_used = true;
        if (source.tainted and instruction.dst == .memory and destination.kind != .stack) return null;
        if (instruction.dst == .memory and instruction.op != .compare and destination.kind == .unknown) return null;
        if (instruction.op == .vector_move and instruction.dst == .memory) {
            for (flow.sourceLanes(node)) |lane| {
                if (lane.tainted) return null;
            }
        }

        // Replacing a saved pointer does not use its previous value. In
        // particular, epilogue pops restore callee-saved argument registers.
        if (instruction.dst == .reg and instruction.width < 32 and node.state.registers[instruction.dst.reg].tainted) return null;
        const reads_destination = instruction.op != .mov and instruction.op != .lea and instruction.op != .pop and instruction.op != .setcc;
        if (source.tainted or (reads_destination and flow.value(node, instruction.dst).tainted)) {
            if (instruction.op != .mov and instruction.op != .lea and instruction.op != .compare) return null;
            if (instruction.op != .compare and instruction.width != 64) return null;
        }

        // A join can leave a tainted but unknown base. Do not silently lose
        // writes through that base, or through indexed/segment-relative aliases.
        for ([_]InstructionFlow.Operand{ instruction.src, instruction.dst }) |operand| {
            if (operand == .high and node.state.registers[operand.high].tainted) return null;
            if (operand != .memory) continue;

            const memory = operand.memory;
            if (memory.index) |reg| {
                if (node.state.registers[reg].tainted) return null;
            }
            if (memory.base) |reg| {
                const base = node.state.registers[reg];
                if (base.tainted and (memory.index != null or memory.fs or memory.rip or
                    (!base.is(.call, -1) and !base.is(.call_address, -1)))) return null;
            }
        }

        if (destination.is(.call_address, -1)) {
            // Accept only bounded, simple accesses to the snapshot. This limit
            // is a recognition constraint, not a discovered allocation size.
            if (destination.b < 0 or destination.b > 256 or (instruction.op != .mov and instruction.op != .vector_move and instruction.op != .compare)) return null;
            argument_used = true;
            if (instruction.op != .compare) {
                const end = @as(usize, @intCast(destination.b)) + instruction.width / 8;
                write_size = @max(write_size, end);
            }
        }
    }

    return if (argument_used) write_size else null;
}

/// Finds the GOT slot containing a relocated global pointer. Its ELF address
/// identifies the symbolic origin even when the pointee belongs to another object.
fn globalSlot(object: *DynObject, name: []const u8) !usize {
    var slot: ?usize = null;
    for (object.relocs.items) |reloc| {
        if (reloc.type == .GLOB_DAT and std.mem.eql(u8, object.syms_array.items[reloc.sym_idx].name, name)) {
            try uniqueOffset(&slot, @intCast(reloc.offset));
        }
    }
    return slot orelse error.GlibcGlobalRelocationNotFound;
}

fn tlsOffsets(flow: InstructionFlow, slot: usize) !GlibcTlsOffsets {
    var result: ?GlibcTlsOffsets = null;
    for (flow.nodes.items) |node| {
        if (!node.reached or node.instruction.op != .divide or node.instruction.width != 64) continue;
        const divisor = flow.value(node, node.instruction.src);
        // Unsigned 64-bit `div` consumes `RDX:RAX`. A zero high half is needed
        // to interpret `RAX` alone as the rounded-size numerator.
        const numerator = node.state.registers[Register.rax];
        if (!divisor.is(.global_field, @intCast(slot)) or !numerator.is(.sum, @intCast(slot)) or
            numerator.bias != -1 or !node.state.registers[Register.rdx].is(.constant, 0)) continue;

        // Addition is commutative; whichever field equals the divisor supplies
        // alignment. The other field supplies size and must be distinct.
        const size = if (numerator.b == divisor.b) numerator.c else if (numerator.c == divisor.b) numerator.b else continue;
        if (size == divisor.b or size < 0 or divisor.b < 0 or @mod(size, 8) != 0 or @mod(divisor.b, 8) != 0) return error.InvalidGlibcTlsLayout;
        const offsets: GlibcTlsOffsets = .{
            .tls_size_offset = std.math.cast(u32, size) orelse return error.InvalidGlibcTlsLayout,
            .tls_align_offset = std.math.cast(u32, divisor.b) orelse return error.InvalidGlibcTlsLayout,
        };
        if (result) |previous| {
            if (!std.meta.eql(previous, offsets)) return error.AmbiguousCodePattern;
        }
        result = offsets;
    }
    return result orelse error.GlibcTlsRoundingNotFound;
}

const Value = InstructionFlow.Value;

fn constant(number: i64) Value {
    return .{ .kind = .constant, .a = number };
}

fn absolute(address: usize) Value {
    return .{ .kind = .address, .a = @intCast(address) };
}

/// Address of a field relative to the thread pointer, not the field's contents.
fn threadAddress(offset: usize) Value {
    return .{ .kind = .thread_address, .b = @intCast(offset) };
}

/// Address at `offset` from the pointer loaded through the ELF GOT `slot`.
fn globalAddress(slot: usize, offset: usize) Value {
    return .{ .kind = .global_address, .a = @intCast(slot), .b = @intCast(offset) };
}

/// Adds a byte displacement in the coordinate space of the symbolic address.
/// Unsupported origins or overflow return `unknown` and cannot match evidence.
fn shifted(address: Value, offset: i64) Value {
    var result = address;
    switch (result.kind) {
        .address => result.a = std.math.add(i64, result.a, offset) catch return .{},
        .thread_address, .call_address, .global_address => result.b = std.math.add(i64, result.b, offset) catch return .{},
        .indirect_address => result.c = std.math.add(i64, result.c, offset) catch return .{},
        .unknown, .constant, .range, .global, .global_field, .sum, .thread, .stack, .call, .thread_field, .call_field => return .{},
    }
    return result;
}

/// Symbolic load from an absolute or indirect-global address. Callers supply
/// only these two forms; this does not read the native mapping.
fn contents(address: Value) Value {
    return if (address.kind == .address) .{ .kind = .global, .a = address.a } else .{ .kind = .global_field, .a = address.a, .b = address.b };
}

/// Adds an offset through a previously loaded global pointer or global field.
fn through(pointer: Value, offset: i64) Value {
    return if (pointer.kind == .global) .{ .kind = .global_address, .a = pointer.a, .b = offset } else .{ .kind = .indirect_address, .a = pointer.a, .b = pointer.b, .c = offset };
}

/// Treats a packed two-pointer store as two scalar stores.
/// Requires matching lane provenance, not just a matching opcode.
fn hasStore(flow: InstructionFlow, destination: Value, source: Value, width: u8) bool {
    if (destination.kind == .unknown or source.kind == .unknown) return false;

    for (flow.nodes.items) |node| {
        if (!node.reached) continue;
        const instruction = node.instruction;
        const address = flow.destination(node);
        if (instruction.op == .mov and instruction.width == width and std.meta.eql(address, destination) and std.meta.eql(flow.value(node, instruction.src), source)) return true;
        if (instruction.op == .vector_move and (instruction.width == 64 or instruction.width == 128) and width == 64 and instruction.dst == .memory) {
            const lanes = flow.sourceLanes(node);
            if (std.meta.eql(address, destination) and std.meta.eql(lanes[0], source)) return true;
            if (instruction.width == 128 and std.meta.eql(shifted(address, 8), destination) and std.meta.eql(lanes[1], source)) return true;
        }
    }
    return false;
}

fn hasRead(flow: InstructionFlow, address: Value) bool {
    for (flow.nodes.items) |node| {
        if (node.reached and node.instruction.op == .mov and node.instruction.width == 64 and node.instruction.src == .memory and
            std.meta.eql(flow.value(node, node.instruction.src), contents(address)))
        {
            return true;
        }
    }
    return false;
}

fn requireEmptyHead(flow: InstructionFlow, head: Value) !void {
    if (!hasStore(flow, head, head, 64) or !hasStore(flow, shifted(head, 8), head, 64)) return error.GlibcStackHeadResetNotFound;
}

/// Repeated evidence agrees only if it names the same nonnegative byte offset.
fn uniqueOffset(result: *?usize, value: i64) !void {
    const offset = std.math.cast(usize, value) orelse return error.InvalidDataAddress;
    if (result.*) |previous| {
        if (previous != offset) return error.AmbiguousCodePattern;
    } else {
        result.* = offset;
    }
}

// Native list updates and runtime field writes.
// ---------------------------------------------

/// Establishes the initial caller-owned entry for a fresh integrated-NPTL state.
/// Rejects populated lists to preserve native registrations.
fn initGlibcInitialThread(layout: *GlibcThreadLayout) !void {
    if (layout.initialized) return;

    const tp = currentThreadPointer();
    const entry: *GlibcThreadList = @ptrFromInt(tp + layout.list_offset);
    const heads = [_]*GlibcThreadList{ layout.used, layout.user, layout.cache };
    for (heads) |head| {
        if (head.next != 0 or head.prev != 0) return error.GlibcThreadListsAlreadyInitialized;
    }
    if (entry.next != 0 or entry.prev != 0) return error.GlibcThreadAlreadyRegistered;

    for (heads) |head| head.init();

    switch (layout.ownership) {
        .byte_flag => |offset| @as(*u8, @ptrFromInt(tp + offset)).* = 1,
        .word_mode => |mode| @as(*u32, @ptrFromInt(tp + mode.offset)).* = mode.value,
    }

    entry.* = .{ .next = @intFromPtr(layout.user), .prev = @intFromPtr(layout.user) };
    layout.user.* = .{ .next = @intFromPtr(entry), .prev = @intFromPtr(entry) };
    layout.initialized = true;
}

fn lockGlibcThreadList(layout: *const GlibcThreadLayout) void {
    // glibc's `lll_lock` ABI: 0 unlocked, 1 locked, 2 locked with waiters.
    // Contention changes the word to 2 before sleeping. Unlock therefore knows
    // it must wake a waiter. Retry the atomic exchange after every futex return,
    // including interrupts and a value change before the kernel starts waiting.
    if (@cmpxchgStrong(u32, layout.lock, 0, 1, .acquire, .monotonic) == null) return;
    while (@atomicRmw(u32, layout.lock, .Xchg, 2, .acquire) != 0) {
        _ = std.os.linux.futex_4arg(layout.lock, .{ .cmd = .WAIT, .private = true }, 2, null);
    }
}

fn unlockGlibcThreadList(layout: *const GlibcThreadLayout) void {
    if (@atomicRmw(u32, layout.lock, .Xchg, 0, .release) > 1) {
        _ = std.os.linux.futex_3arg(layout.lock, .{ .cmd = .WAKE, .private = true }, 1);
    }
}

/// Registers an initialized Zig descriptor as a caller-owned stack.
/// The caller blocks signals while the native list is updated.
fn registerGlibcWorker(layout: *GlibcThreadLayout, tp: usize) void {
    const entry: *GlibcThreadList = @ptrFromInt(tp + layout.list_offset);
    std.debug.assert(entry.next == 0 and entry.prev == 0);

    @as(*c_int, @ptrFromInt(tp + 24)).* = 1;
    switch (layout.ownership) {
        .byte_flag => |offset| @as(*u8, @ptrFromInt(tp + offset)).* = 1,
        .word_mode => |mode| @as(*u32, @ptrFromInt(tp + mode.offset)).* = mode.value,
    }

    lockGlibcThreadList(layout);
    defer unlockGlibcThreadList(layout);

    const next: *GlibcThreadList = @ptrFromInt(layout.user.next);
    entry.* = .{ .next = @intFromPtr(next), .prev = @intFromPtr(layout.user) };
    @atomicStore(usize, &next.prev, @intFromPtr(entry), .seq_cst);
    @atomicStore(usize, &layout.user.next, @intFromPtr(entry), .seq_cst);
}

fn unregisterGlibcWorker(layout: *GlibcThreadLayout, tp: usize) void {
    const entry: *GlibcThreadList = @ptrFromInt(tp + layout.list_offset);

    lockGlibcThreadList(layout);
    defer unlockGlibcThreadList(layout);

    // glibc journals deletions because `fork` can copy memory between the two
    // link stores. A node address with bit zero clear means deletion; recovery
    // can replay both stores. Clear the journal only after both are visible.
    // This follows `__nptl_stack_list_del`, not native stack deallocation: Zig
    // still owns the descriptor and will reclaim it after kernel thread exit.
    // https://github.com/bminor/glibc/blob/glibc-2.39/nptl/nptl-stack.c#L26-L38
    @atomicStore(usize, layout.in_flight, @intFromPtr(entry), .seq_cst);
    const next: *GlibcThreadList = @ptrFromInt(entry.next);
    const prev: *GlibcThreadList = @ptrFromInt(entry.prev);
    @atomicStore(usize, &next.prev, entry.prev, .seq_cst);
    @atomicStore(usize, &prev.next, entry.next, .seq_cst);
    @atomicStore(usize, layout.in_flight, 0, .seq_cst);
    _ = @atomicRmw(u32, layout.nthreads, .Sub, 1, .seq_cst);
}

/// Describes writes applied by `common.Runtime` after the loader establishes TLS.
/// Absolute entries populate rtld globals; TP-relative entries are also applied
/// in each worker. `auxv` is the host auxiliary vector, and TLS dimensions come
/// from the loader's current allocation, not glibc's native TLS allocator.
fn appendWritePlan(runtime: *common.Runtime, glibc: Layout) !void {
    // Point _rtld_global_ro._dl_auxv at the host process's original auxiliary vector.
    // TODO recover or validate the fixed field offset (104) against the loaded glibc.
    // TODO initialize auxv-derived glibc state, notably _dl_hwcap2, before any
    // native IFUNC/IRELATIVE resolver runs. Setting _dl_auxv alone does not populate
    // those cached fields; this requires preparation before the relocation loop.
    const auxv_field_address = std.math.add(usize, glibc.rtld_mapped_address, 104) catch return error.InvalidDataAddress;
    try runtime.write_ops.append(runtime.allocator, .{
        .addr = auxv_field_address,
        .relative_to = .zero,
        .value = .auxv,
    });

    if (glibc.tls_offsets) |offsets| {
        const size_address = std.math.add(usize, glibc.rtld_mapped_address, offsets.tls_size_offset) catch return error.InvalidDataAddress;
        const align_address = std.math.add(usize, glibc.rtld_mapped_address, offsets.tls_align_offset) catch return error.InvalidDataAddress;

        try runtime.write_ops.appendSlice(runtime.allocator, &.{
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

    // TODO recover or validate the thread-field offsets (0, 16, 720)
    // against the loaded glibc layout.
    // x86-64 LP64 layout references (glibc 2.39):
    // tcbhead_t and TLS_INIT_TP, which initializes both self pointers:
    // https://github.com/bminor/glibc/blob/glibc-2.39/sysdeps/x86_64/nptl/tls.h
    // struct pthread: the 704-byte header is followed by a 16-byte list, then tid:
    // https://github.com/bminor/glibc/blob/glibc-2.39/nptl/descr.h
    // The TID entry writes a `c_int`, not a pointer-sized value.
    try runtime.write_ops.appendSlice(runtime.allocator, &.{
        .{
            .addr = 0, // tcbhead_t.tcb: TCB pointer.
            .relative_to = .tp,
            .value = .tp,
        },
        .{
            .addr = 16, // tcbhead_t.self: thread-descriptor pointer.
            .relative_to = .tp,
            .value = .tp,
        },
        .{
            .addr = 720, // struct pthread.tid: kernel TID (pid_t).
            .relative_to = .tp,
            .value = .tid,
        },
    });
}

// Load alignment at +0x2a8 and size at +0x2a0, then divide size + alignment - 1
// by alignment. At code address 0x1000, the first load reads the GOT at 0x2000.
// mov rax, [rip+0xff9]
// mov r9, [rax+0x2a8]
// mov rbx, [rax+0x2a0]
// add rbx, r9
// sub rbx, 1
// mov rax, rbx
// xor edx, edx
// div r9
// ret
const scalar_tls_fixture = "\x48\x8b\x05\xf9\x0f\x00\x00" ++
    "\x4c\x8b\x88\xa8\x02\x00\x00\x48\x8b\x98\xa0\x02\x00\x00" ++
    "\x4c\x01\xcb\x48\x83\xeb\x01\x48\x89\xd8\x31\xd2\x49\xf7\xf1\xc3";

test "TLS rounding identifies field roles through renamed registers" {
    // glibc's rounding expression identifies which global fields are size and
    // alignment, and must originate at the expected _rtld_global_ro GOT slot.
    var flow = try InstructionFlow.init(std.testing.allocator, CodeView.fromBytes(scalar_tls_fixture, 0x1000));
    defer flow.deinit();
    try std.testing.expectEqual(GlibcTlsOffsets{ .tls_size_offset = 0x2a0, .tls_align_offset = 0x2a8 }, try tlsOffsets(flow, 0x2000));
    try std.testing.expectError(error.GlibcTlsRoundingNotFound, tlsOffsets(flow, 0x3000));
}

test "TLS rounding rejects unrelated divisors and incorrect formulas" {
    // Replace sub rbx, 1 with sub rbx, 2, or div r9 with div r10.
    // Neither is the required rounding calculation.
    for ([_]usize{ 27, 35 }) |offset| {
        var bytes = scalar_tls_fixture.*;
        bytes[offset] = if (offset == 27) 2 else 0xf2;
        var flow = try InstructionFlow.init(std.testing.allocator, CodeView.fromBytes(&bytes, 0x1000));
        defer flow.deinit();
        try std.testing.expectError(error.GlibcTlsRoundingNotFound, tlsOffsets(flow, 0x2000));
    }
    var bytes = scalar_tls_fixture.*;
    // Replace mov r9, [rax+0x2a8] with mov r9, [rax+0x2a0]: both loads use size.
    bytes[10] = 0xa0;
    var flow = try InstructionFlow.init(std.testing.allocator, CodeView.fromBytes(&bytes, 0x1000));
    defer flow.deinit();
    try std.testing.expectError(error.InvalidGlibcTlsLayout, tlsOffsets(flow, 0x2000));
}

test "SIMD TLS rounding retains both field origins" {
    // Vectorized rounding must identify the same size and alignment fields.
    //
    // mov rax, [rip+0xff9] (GOT slot at 0x2000)
    // movdqu xmm0, [rax+0x2a0]
    // movdqa xmm1, xmm0
    // movhlps xmm2, xmm0
    // psrldq xmm1, 8
    // movq r8, xmm2
    // paddq xmm0, xmm1
    // movq rcx, xmm0
    // sub rcx, 1
    // mov rax, rcx
    // xor edx, edx
    // div r8
    // ret
    const bytes = "\x48\x8b\x05\xf9\x0f\x00\x00" ++
        "\xf3\x0f\x6f\x80\xa0\x02\x00\x00\x66\x0f\x6f\xc8\x0f\x12\xd0" ++
        "\x66\x0f\x73\xd9\x08\x66\x49\x0f\x7e\xd0\x66\x0f\xd4\xc1" ++
        "\x66\x48\x0f\x7e\xc1\x48\x83\xe9\x01\x48\x89\xc8\x31\xd2\x49\xf7\xf0\xc3";
    var flow = try InstructionFlow.init(std.testing.allocator, CodeView.fromBytes(bytes, 0x1000));
    defer flow.deinit();
    try std.testing.expectEqual(GlibcTlsOffsets{ .tls_size_offset = 0x2a0, .tls_align_offset = 0x2a8 }, try tlsOffsets(flow, 0x2000));
}

test "packed list-head reset requires both self-links" {
    // An empty glibc list head requires next and prev to point to the head.
    // A packed store with only its low lane holding that address is insufficient.
    //
    // mov rax, [rip+0xff9] (GOT slot at 0x2000)
    // lea r10, [rax+0x800]
    // movq xmm5, r10
    const prefix = "\x48\x8b\x05\xf9\x0f\x00\x00\x4c\x8d\x90\x00\x08\x00\x00" ++
        "\x66\x49\x0f\x6e\xea";
    // movups [rax+0x800], xmm5
    // ret
    const suffix = "\x0f\x11\xa8\x00\x08\x00\x00\xc3";
    // Insert punpcklqdq xmm5, xmm5 to populate both self-links.
    var flow = try InstructionFlow.init(std.testing.allocator, CodeView.fromBytes(prefix ++ "\x66\x0f\x6c\xed" ++ suffix, 0x1000));
    defer flow.deinit();
    try requireEmptyHead(flow, globalAddress(0x2000, 0x800));

    // Without duplication, movq leaves the upper lane zero rather than self-linked.
    var wrong = try InstructionFlow.init(std.testing.allocator, CodeView.fromBytes(prefix ++ suffix, 0x1000));
    defer wrong.deinit();
    try std.testing.expectError(error.GlibcStackHeadResetNotFound, requireEmptyHead(wrong, globalAddress(0x2000, 0x800)));
}

test "ownership detection follows the user-list insertion branch" {
    // The taken equality branch inserts the thread for word mode 2. Replacing
    // it with `JNE` must fail even though the field and four stores still match.
    //
    // mov rax, [rip+0xff9] (GOT slot at 0x2000)
    // mov rbx, fs:[16]
    // lea rdx, [rbx+64]
    // lea rdi, [rax+256]
    const prefix = "\x48\x8b\x05\xf9\x0f\x00\x00\x64\x48\x8b\x1c\x25\x10\x00\x00\x00" ++
        "\x48\x8d\x53\x40\x48\x8d\xb8\x00\x01\x00\x00";
    // insert:
    // mov [rbx+64], rdi
    // mov [rbx+72], rdi
    // mov [rax+256], rdx
    // mov [rax+264], rdx
    // ret
    const insertion = "\x48\x89\x7b\x40\x48\x89\x7b\x48\x48\x89\x90\x00\x01\x00\x00\x48\x89\x90\x08\x01\x00\x00\xc3";
    // Between prefix and insertion:
    // cmp dword ptr fs:[128], 2
    // je insert
    // ret
    const bytes = prefix ++ "\x64\x83\x3c\x25\x80\x00\x00\x00\x02\x74\x01\xc3" ++ insertion;
    const options: InstructionFlow.Options = .{ .thread_self_offsets = &.{ 0, 16 } };
    var flow = try InstructionFlow.initWithOptions(std.testing.allocator, CodeView.fromBytes(bytes, 0x1000), options);
    defer flow.deinit();
    try std.testing.expectEqual(GlibcThreadLayout.Ownership{ .word_mode = .{ .offset = 128, .value = 2 } }, try detectOwnership(flow, globalAddress(0x2000, 256), 64));

    var wrong_bytes = bytes.*;
    wrong_bytes[36] = 0x75; // Replace je insert with jne insert.
    var wrong = try InstructionFlow.initWithOptions(std.testing.allocator, CodeView.fromBytes(&wrong_bytes, 0x1000), options);
    defer wrong.deinit();
    try std.testing.expectError(error.GlibcStackOwnershipNotFound, detectOwnership(wrong, globalAddress(0x2000, 256), 64));

    // Between prefix and insertion:
    // mov cl, fs:[128]
    // test cl, cl
    // lea rdx, [rbx+64]
    // jne insert
    // ret
    const byte_flag = prefix ++ "\x64\x8a\x0c\x25\x80\x00\x00\x00\x84\xc9\x48\x8d\x53\x40\x75\x01\xc3" ++ insertion;
    var older = try InstructionFlow.initWithOptions(std.testing.allocator, CodeView.fromBytes(byte_flag, 0x1000), options);
    defer older.deinit();
    try std.testing.expectEqual(GlibcThreadLayout.Ownership{ .byte_flag = 128 }, try detectOwnership(older, globalAddress(0x2000, 256), 64));
}

test "snapshot borrowing rejects retained, returned, or obscured pointers" {
    // glibc fork inspection permits private spills to survive recognized NSS
    // snapshot helpers only when those helpers borrow, rather than retain, RDI.
    // mov qword ptr [rdi], 0
    const output = "\x48\xc7\x07\x00\x00\x00\x00";
    // xor eax, eax
    // ret
    const finish = "\x31\xc0\xc3";
    const cases = .{
        .{ output ++ finish, true }, // Write snapshot contents only.
        // mov rax, [rdi]
        // mov [rip+32], rax
        // Followed by finish.
        .{ "\x48\x8b\x07\x48\x89\x05\x20\x00\x00\x00" ++ finish, true }, // Publish contents, not the snapshot address.
        // Between output and finish: mov [rip+32], rdi.
        .{ output ++ "\x48\x89\x3d\x20\x00\x00\x00" ++ finish, false }, // Retain the address globally.
        // After output:
        // mov rax, rdi
        // ret
        .{ output ++ "\x48\x89\xf8\xc3", false }, // Return the address in `RAX`.
        // Between output and finish:
        // je publish
        // xor edi, edi
        // publish:
        // mov [rip+32], rdi
        .{ output ++ "\x74\x02\x31\xff\x48\x89\x3d\x20\x00\x00\x00" ++ finish, false }, // One branch still retains it.
        // Between output and finish: mov edi, edi.
        .{ output ++ "\x89\xff" ++ finish, false }, // Truncate the pointer through `EDI`.
        // Between output and finish: lea rax, [rdi*4].
        .{ output ++ "\x48\x8d\x04\xbd\x00\x00\x00\x00" ++ finish, false }, // Use it as a scaled index.
    };

    inline for (cases) |case| {
        var options: InstructionFlow.Options = .{};
        options.initial_registers[7] = .{ .kind = .call, .a = -1, .tainted = true };
        var flow = try InstructionFlow.initWithOptions(std.testing.allocator, CodeView.fromBytes(case[0], 0), options);
        defer flow.deinit();
        try std.testing.expectEqual(case[1], (try firstArgumentWriteSize(flow, null)) != null);
    }
}

test "snapshot borrowing bounds writes through callee-saved pointers" {
    // xor eax, eax
    // ret
    const finish = "\x31\xc0\xc3";
    const Case = struct {
        bytes: []const u8,
        write_size: ?usize,
    };
    const cases = [_]Case{
        // Reading contents does not write the buffer.
        // mov rax, [rdi]
        // ret
        .{ .bytes = "\x48\x8b\x07\xc3", .write_size = 0 },
        // push rbx
        // mov rbx, rdi
        // movups [rbx+16], xmm0
        // pop rbx
        // Followed by finish.
        .{ .bytes = "\x53\x48\x89\xfb\x0f\x11\x43\x10\x5b" ++ finish, .write_size = 32 },
        // je second
        // mov byte ptr [rdi], 0
        // ret
        // second:
        // mov byte ptr [rdi+31], 0
        // ret
        .{ .bytes = "\x74\x04\xc6\x07\x00\xc3\xc6\x47\x1f\x00\xc3", .write_size = 32 },
        // Negative output offsets are not supported.
        // mov byte ptr [rdi-1], 0
        // Followed by finish.
        .{ .bytes = "\xc6\x47\xff\x00" ++ finish, .write_size = null },
        // An unknown index cannot bound the output.
        // mov byte ptr [rdi+rax], 0
        // Followed by finish.
        .{ .bytes = "\xc6\x04\x07\x00" ++ finish, .write_size = null },
        // Implicit output is not a bounded scalar/vector store.
        // mov rax, [rdi]
        // rep stosq
        // Followed by finish.
        .{ .bytes = "\x48\x8b\x07\xf3\x48\xab" ++ finish, .write_size = null },
        // Upper pointer bits survive the partial overwrite.
        // mov rax, [rdi]
        // mov dil, 0
        // Followed by finish.
        .{ .bytes = "\x48\x8b\x07\x40\xc6\xc7\x00" ++ finish, .write_size = null },
        // je store
        // mov rdi, rsi
        // store:
        // mov byte ptr [rdi], 0
        // Followed by finish.
        .{ .bytes = "\x74\x03\x48\x89\xf7\xc6\x07\x00" ++ finish, .write_size = null },
        // Writes through buffer contents cannot establish a bound relative to
        // the buffer itself.
        // mov rax, [rdi]
        // mov byte ptr [rax], 0
        // Followed by finish.
        .{ .bytes = "\x48\x8b\x07\xc6\x00\x00" ++ finish, .write_size = null },
        // mov byte ptr [rdi], 0
        // jmp unknown external helper
        .{ .bytes = "\xc6\x07\x00\xe9\x00\x01\x00\x00", .write_size = null },
        // A truncated body does not prove what the remaining instructions do.
        // mov byte ptr [rdi], 0
        .{ .bytes = "\xc6\x07\x00", .write_size = null },
    };

    for (cases) |case| {
        var options: InstructionFlow.Options = .{};
        options.initial_registers[Register.rdi] = .{ .kind = .call, .a = -1, .tainted = true };
        var flow = try InstructionFlow.initWithOptions(std.testing.allocator, CodeView.fromBytes(case.bytes, 0), options);
        defer flow.deinit();

        try std.testing.expectEqual(case.write_size, try firstArgumentWriteSize(flow, null));
    }
}

test "terminal helper detection checks all paths within the depth bound" {
    var bytes: [64]u8 = @splat(0x90);
    // call 8
    // ret
    @memcpy(bytes[0..6], "\xe8\x03\x00\x00\x00\xc3");
    // call 16
    // ret
    @memcpy(bytes[8..14], "\xe8\x03\x00\x00\x00\xc3");
    // je 20
    // ud2
    // jmp 20
    @memcpy(bytes[16..22], "\x74\x02\x0f\x0b\xeb\xfe");

    var object = DynObject.init(.{ .ino = 0 }, "terminal-fixture", "");
    defer object.segments.deinit(std.testing.allocator);
    const flags: DynObject.LoadSegmentFlags = .{
        .read = true,
        .write = false,
        .exec = true,
        .mem_offset = 0,
        .mem_size = bytes.len,
    };
    try object.segments.put(std.testing.allocator, 0, .{
        .file_offset = 0,
        .file_size = bytes.len,
        .mem_offset = 0,
        .mem_size = bytes.len,
        .mem_align = 1,
        .mapped_from_file = false,
        .flags_first = flags,
        .flags_last = flags,
        .loaded_at = @intFromPtr(&bytes),
    });

    try std.testing.expect(try terminalPath(&object, 0, 2));
    try std.testing.expect(!try terminalPath(&object, 0, 1));

    // A returning conditional arm invalidates the whole proof.
    // ret
    bytes[20] = 0xc3;
    try std.testing.expect(!try terminalPath(&object, 0, 2));

    // Unknown destination.
    // jmp rax
    @memcpy(bytes[16..18], "\xff\xe0");
    try std.testing.expect(!try terminalPath(&object, 0, 2));
}
