//! Native libc policy and lifecycle boundary. Backend state is heap-stable and
//! owned by `Runtime`; worker handles borrow it until their final join/release.
//! Backends inspect mapped objects through `Services`; they do not own loader
//! registries, stack mappings, or Zig's kernel thread-exit notification.

const std = @import("std");

const DynObject = @import("DynObject.zig");
const logger = @import("logger.zig");
const CodeView = @import("CodeView.zig");
const musl = @import("libc/musl.zig");
const glibc = @import("libc/glibc.zig");
const ResolvedSymbol = DynObject.ResolvedSymbol;

/// Loader operations used during native-runtime inspection and preparation.
/// Returned object pointers are borrowed until the next registry mutation.
/// Backends retain mapped addresses, never registry-entry pointers.
pub const Services = struct {
    lookupSymbol: *const fn (object: *DynObject, name: []const u8, allow_preload_override: bool) anyerror!ResolvedSymbol,
    lookupRuntimeSymbol: *const fn (name: []const u8) anyerror!ResolvedSymbol,
    definingObject: *const fn (symbol: ResolvedSymbol) *DynObject,
    inspectSymbol: *const fn (object: *DynObject, name: []const u8) anyerror!DynObject.Definition,
    findSegment: *const fn (address: usize) anyerror!DynObject.DynObjectSegmentResult,
    runtimeValues: *const fn () RuntimeValues,
    malloc_substitute: *const anyopaque,
    calloc_substitute: *const anyopaque,
    mq_notify_substitute: *const anyopaque,
    timer_substitutes: [4]*const anyopaque,

    pub fn inspect(self: *const Services, object: *DynObject) DynObject.Inspection {
        return .{ .object = object, .lookup = self.inspectSymbol };
    }
};

pub const ProcessArguments = struct {
    args: std.process.Args,
    environ: std.process.Environ,
};

pub const RuntimeValues = struct {
    args: std.process.Args,
    environ: std.process.Environ,
    auxv_address: usize,
    tls_size: usize,
    tls_align: usize,
};

/// Deferred native-field assignment. `addr` is a loaded address for `.zero`, or
/// an unsigned byte offset from TP for `.tp`. Values are computed at application
/// time; `.tid` writes a `c_int`, while other values write a pointer-sized word.
pub const WriteOp = struct {
    addr: usize,
    relative_to: enum { zero, tp },
    value: union(enum) {
        auxv,
        tls_size,
        tls_align,
        page_size,
        tp,
        tid,
        self,
        addr: usize,
    },
};

/// Every slot has an explicit implementation, including intentional no-ops.
/// Creator-side preparation/spawn callbacks run under the registry lock. Child
/// callbacks and post-startup/join release use the contracts on `WorkerHandle`.
pub const VTable = struct {
    destroyState: *const fn (runtime: *Runtime) void,
    initInitialThread: *const fn (runtime: *Runtime) anyerror!void,
    supportsWorkers: *const fn (runtime: *const Runtime) bool,
    prepareObject: *const fn (runtime: *Runtime, object: *DynObject) anyerror!void,
    threadStorageSize: *const fn (runtime: *const Runtime) usize,
    patchAllocatorCalls: *const fn (runtime: *Runtime, object: *DynObject) anyerror!void,
    initWorker: *const fn (runtime: *Runtime) WorkerHandle,
    prepareWorker: *const fn (worker: *WorkerHandle) anyerror!void,
    beginSpawn: *const fn (worker: *WorkerHandle) void,
    spawnFailed: *const fn (worker: *WorkerHandle) void,
    registerWorker: *const fn (worker: *const WorkerHandle, tp: usize) anyerror!void,
    enterUserCode: *const fn (worker: *const WorkerHandle) void,
    finishStartup: *const fn (worker: *const WorkerHandle) void,
    unregisterWorker: *const fn (worker: *const WorkerHandle, tp: usize) void,
    releaseAfterJoin: *const fn (worker: *const WorkerHandle) void,
};

const NativeBinding = struct {
    object_index: usize,
    address: usize,
};

/// Owns backend state and its write plan. Copies transfer ownership; they do not
/// duplicate it. Once workers exist, this handle and its services must stay put
/// until every worker has joined and released its backend storage.
pub const Runtime = struct {
    pub const Worker = WorkerHandle;

    pub const InitOptions = struct {
        services: *const Services,
        state: *anyopaque,
        vtable: *const VTable,
        getErrnoLocation: *const fn () callconv(.c) *c_int,
    };

    allocator: std.mem.Allocator,
    services: *const Services,
    state: *anyopaque,
    vtable: *const VTable,
    write_ops: std.ArrayList(WriteOp),
    getErrnoLocation: *const fn () callconv(.c) *c_int,
    native_mq_notify: ?NativeBinding,
    native_timer_create: [4]?NativeBinding,

    /// Takes ownership of backend state; services and native code remain borrowed.
    pub fn init(allocator: std.mem.Allocator, options: InitOptions) Runtime {
        return .{
            .allocator = allocator,
            .services = options.services,
            .state = options.state,
            .vtable = options.vtable,
            .write_ops = .empty,
            .getErrnoLocation = options.getErrnoLocation,
            .native_mq_notify = null,
            .native_timer_create = @splat(null),
        };
    }

    pub fn deinit(self: *Runtime) void {
        self.write_ops.deinit(self.allocator);
        self.vtable.destroyState(self);
    }

    pub fn supportsWorkers(self: *const Runtime) bool {
        return self.vtable.supportsWorkers(self);
    }

    pub fn prepareObject(self: *Runtime, object: *DynObject) !void {
        logger.debug("libc.prepare: object={s} action=begin", .{object.name});
        self.vtable.prepareObject(self, object) catch |err| {
            logger.err("libc.prepare: object={s} error={t}", .{ object.name, err });
            return err;
        };
        logger.debug("libc.prepare: object={s} action=complete workers_supported={}", .{ object.name, self.supportsWorkers() });
    }

    pub fn beforeConstructors(self: *Runtime, name: []const u8) !void {
        if (objectRole(name) == .libc) {
            logger.debug("libc.initial_thread: action=initialize", .{});
            self.vtable.initInitialThread(self) catch |err| {
                logger.err("libc.initial_thread: action=initialize error={t}", .{err});
                return err;
            };
            logger.debug("libc.initial_thread: action=initialized", .{});
        }
    }

    pub fn threadStorageSize(self: *const Runtime) usize {
        return self.vtable.threadStorageSize(self);
    }

    pub fn updateRuntimeFields(self: *const Runtime, tp: usize) !void {
        try self.applyWriteOps(tp, false);
    }

    fn validateWritePlan(self: *const Runtime) !void {
        for (self.write_ops.items) |op| {
            logger.debug("libc.write_plan: base={t} offset_or_host=0x{x} value_kind={s}", .{ op.relative_to, op.addr, @tagName(op.value) });
            errdefer logger.err("libc.write_plan: base={t} offset_or_host=0x{x} action=failed", .{ op.relative_to, op.addr });
            switch (op.relative_to) {
                .tp => {},
                .zero => {
                    const location = try self.services.findSegment(op.addr);
                    const segment = location.dyn_object.segments.values()[location.segment_index];
                    const offset = op.addr - segment.loaded_at;
                    if (!segment.flags_first.read or segment.flags_first.exec or
                        offset > segment.mem_size or @sizeOf(usize) > segment.mem_size - offset)
                    {
                        return error.InvalidDataAddress;
                    }
                },
            }
        }
    }

    /// Global fields are updated for the initial runtime; workers receive only
    /// TP-relative fields. Failure may leave earlier writes applied. Unlike code
    /// patching, this initialization plan does not own rollback byte snapshots.
    fn applyWriteOps(self: *const Runtime, thread_pointer: usize, only_tp_relative: bool) !void {
        const values = self.services.runtimeValues();
        for (self.write_ops.items) |op| {
            if (only_tp_relative and op.relative_to != .tp) continue;

            const address = op.addr + switch (op.relative_to) {
                .zero => @as(usize, 0),
                .tp => thread_pointer,
            };
            const value: usize = switch (op.value) {
                .auxv => values.auxv_address,
                .tls_size => values.tls_size,
                .tls_align => values.tls_align,
                .page_size => std.heap.pageSize(),
                .tp => thread_pointer,
                .tid => std.Thread.getCurrentId(),
                .self => address,
                .addr => |literal| literal,
            };

            const location = self.services.findSegment(address) catch null;
            logger.debug("libc.write: tp_host=0x{x} target_host=0x{x} value_kind={s} value=0x{x} width={d}", .{ thread_pointer, address, @tagName(op.value), value, @as(usize, if (op.value == .tid) @sizeOf(c_int) else @sizeOf(usize)) });
            if (location) |segment| {
                try segment.dyn_object.unprotectSegment(segment.segment_index);
            }

            if (op.value == .tid) {
                const pointer: *volatile c_int = @ptrFromInt(address);
                pointer.* = @intCast(value);
            } else {
                const pointer: *volatile usize = @ptrFromInt(address);
                pointer.* = value;
            }

            if (location) |segment| {
                try segment.dyn_object.reprotectSegment(segment.segment_index);
            }
        }
    }

    /// Saves the original native entry before returning a wrapper. Timer symbol
    /// versions have separate slots because their native argument ABIs may differ.
    pub fn selectSymbolSubstitute(self: *Runtime, symbol: ResolvedSymbol) !?usize {
        if (std.mem.eql(u8, symbol.name, "mq_notify")) {
            self.native_mq_notify = try self.nativeBinding(symbol);
            return @intFromPtr(self.services.mq_notify_substitute);
        }

        if (std.mem.eql(u8, symbol.name, "timer_create")) {
            const index = glibc.timerBindingIndex(symbol.version);
            self.native_timer_create[index] = try self.nativeBinding(symbol);
            return @intFromPtr(self.services.timer_substitutes[index]);
        }

        return null;
    }

    fn nativeBinding(self: *const Runtime, symbol: ResolvedSymbol) !NativeBinding {
        const object = self.services.definingObject(symbol);
        return .{
            .object_index = symbol.dyn_object_idx,
            .address = try object.virtualToLoadedAddress(symbol.value, false),
        };
    }

    pub fn createTimer(self: *const Runtime, binding_index: usize, clock: c_int, event: ?*const NotificationEvent, timer_id: *anyopaque) c_int {
        checkNotification(event);
        const binding = self.native_timer_create[binding_index].?;
        const function: *const fn (clock: c_int, event: ?*const NotificationEvent, timer_id: *anyopaque) callconv(.c) c_int = @ptrFromInt(binding.address);
        return function(clock, event, timer_id);
    }

    pub fn notifyQueue(self: *const Runtime, queue: c_int, event: ?*const NotificationEvent) c_int {
        checkNotification(event);
        const function: *const fn (queue: c_int, event: ?*const NotificationEvent) callconv(.c) c_int = @ptrFromInt(self.native_mq_notify.?.address);
        return function(queue, event);
    }
};

/// Creator, worker context, and registry copy this handle. Backend storage has
/// separate creator/registry ownership; copying the handle adds no reference.
pub const WorkerHandle = struct {
    runtime: *Runtime,
    state: ?*anyopaque,
    parent_tp: usize,
    creator_mask: ?std.os.linux.sigset_t,
    spawn_mask: ?std.os.linux.sigset_t,

    /// Blocks backend-selected signals before the caller acquires its registry lock.
    /// Returns a handle ready for preparation, with no worker state or spawn mask.
    pub fn init(runtime: *Runtime) WorkerHandle {
        return runtime.vtable.initWorker(runtime);
    }

    pub fn restoreCreatorSignals(self: *const WorkerHandle) void {
        if (self.creator_mask) |mask| restoreThreadSignals(&mask);
    }

    /// Requires the registry lock. On failure no worker resources are retained.
    pub fn prepare(self: *WorkerHandle) !void {
        try self.runtime.vtable.prepareWorker(self);
    }

    pub fn beginSpawn(self: *WorkerHandle) void {
        self.runtime.vtable.beginSpawn(self);
    }

    pub fn endSpawn(self: *WorkerHandle) void {
        if (self.spawn_mask) |mask| restoreThreadSignals(&mask);
        self.spawn_mask = null;
    }

    /// Cancels a successful prepare when Zig cannot spawn the worker.
    pub fn spawnFailed(self: *WorkerHandle) void {
        self.endSpawn();
        self.runtime.vtable.spawnFailed(self);
    }

    /// Runs in the child before acquiring the generic registry lock. Native
    /// backends use their own list locks after the TP-relative writes complete.
    pub fn register(self: *const WorkerHandle, tp: usize) !void {
        logger.debug("worker.register: tp_host=0x{x} parent_tp_host=0x{x} action=begin", .{ tp, self.parent_tp });
        errdefer logger.err("worker.register: tp_host=0x{x} action=failed", .{tp});
        try self.runtime.applyWriteOps(tp, true);
        try self.runtime.vtable.registerWorker(self, tp);
        logger.debug("worker.register: tp_host=0x{x} action=complete", .{tp});
    }

    /// Runs in the child after generic registry validation, with no registry lock.
    pub fn enterUserCode(self: *const WorkerHandle) void {
        const tp = currentThreadPointer();
        logger.debug("worker.enter: tp_host=0x{x} action=begin", .{tp});
        self.runtime.vtable.enterUserCode(self);
        logger.debug("worker.enter: tp_host=0x{x} action=complete", .{tp});
    }

    /// Runs in the creator without the registry lock; releases startup ownership.
    pub fn finishStartup(self: *const WorkerHandle) void {
        logger.debug("worker.startup: parent_tp_host=0x{x} backend_state_host=0x{x} action=finish_begin", .{ self.parent_tp, @intFromPtr(self.state) });
        self.runtime.vtable.finishStartup(self);
        logger.debug("worker.startup: parent_tp_host=0x{x} backend_state_host=0x{x} action=finish_complete", .{ self.parent_tp, @intFromPtr(self.state) });
    }

    /// Runs after user cleanup, without the registry lock. Leaves signals blocked
    /// through Zig teardown and preserves Zig's kernel clear-child-TID address.
    pub fn unregister(self: *const WorkerHandle, tp: usize) void {
        logger.debug("worker.unregister: tp_host=0x{x} action=begin", .{tp});
        self.runtime.vtable.unregisterWorker(self, tp);
        logger.debug("worker.unregister: tp_host=0x{x} action=complete", .{tp});
    }

    /// Called only after join or during final loader teardown.
    pub fn releaseAfterJoin(self: *const WorkerHandle) void {
        self.runtime.vtable.releaseAfterJoin(self);
    }
};

pub const ObjectRole = enum { ordinary, libc, loader, thread_support };

/// Prefer the established names before trying architecture-qualified fallbacks.
/// libc.so is a shared alias; backend-specific names belong to the backends.
pub const system_libc_names = glibc.system_libc_names ++ [_][]const u8{"libc.so"} ++ musl.system_libc_names;

pub fn objectRole(name: []const u8) ObjectRole {
    if (std.mem.startsWith(u8, name, "libc.so") or musl.isRuntimeName(name)) return .libc;
    if (glibc.isLoaderName(name)) return .loader;
    if (glibc.isThreadSupportName(name)) return .thread_support;
    return .ordinary;
}

pub fn requiresLifetimePin(name: []const u8) bool {
    return switch (objectRole(name)) {
        .libc, .loader => true,
        .ordinary, .thread_support => false,
    };
}

pub fn searchBesideRequester(requester_name: []const u8, dependency_name: []const u8) bool {
    return objectRole(requester_name) == .libc and objectRole(dependency_name) == .loader;
}

pub fn checkCompatibleObject(name: []const u8, path: []const u8, objects: []const DynObject) !void {
    if (objectRole(name) != .libc) return;

    for (objects) |object| {
        if (object.loaded and objectRole(object.name) == .libc and !std.mem.eql(u8, object.path, path)) {
            return error.MultipleLibcs;
        }
    }
}

/// Returns owned runtime state for a recognized libc and `null` for other roles.
/// Validate all required evidence before publishing it. Recognition ambiguity,
/// failed write-plan validation, or failed allocator patching aborts preparation.
pub fn inspectObject(services: *const Services, allocator: std.mem.Allocator, object: *DynObject) !?Runtime {
    if (objectRole(object.name) != .libc) return null;

    var phase: []const u8 = "recognition";
    logger.debug("libc.inspect: object={s} path={s} phase={s} action=begin", .{ object.name, object.path, phase });
    errdefer logger.err("libc.inspect: object={s} path={s} phase={s} action=failed", .{ object.name, object.path, phase });

    const is_musl = try musl.recognizes(services, object);
    const is_glibc = try glibc.recognizes(services, object);
    logger.debug("libc.inspect: object={s} musl_marker={} glibc_marker={}", .{ object.name, is_musl, is_glibc });
    if (is_musl and is_glibc) return error.AmbiguousLibc;

    phase = "backend_create";
    var runtime = if (is_musl)
        try musl.create(services, allocator, object)
    else if (is_glibc)
        try glibc.create(services, allocator, object)
    else
        return error.UnableToDetectLibc;
    errdefer runtime.deinit();

    phase = "write_plan";
    try runtime.validateWritePlan();

    phase = "allocator_patches";
    try runtime.vtable.patchAllocatorCalls(&runtime, object);

    logger.info("libc.inspect: object={s} backend={s} action=ready write_ops={d} workers_supported={}", .{ object.name, if (is_musl) "musl" else "glibc", runtime.write_ops.items.len, runtime.supportsWorkers() });
    return runtime;
}

pub fn callInitializer(name: []const u8, address: usize, process: ProcessArguments) void {
    switch (objectRole(name)) {
        .ordinary, .loader, .thread_support => {
            const function: *const fn () callconv(.c) void = @ptrFromInt(address);
            function();
        },
        .libc => {
            const function: *const fn (argc: c_int, argv: [*c]const [*c]const u8, envp: [*c]const [*c]const u8) callconv(.c) void = @ptrFromInt(address);
            function(@intCast(process.args.vector.len), @ptrCast(process.args.vector), @ptrCast(process.environ.block.slice));
        },
    }
}

pub fn bootstrapThreadStorageSize() usize {
    return 0x2000 + std.heap.pageSize();
}

pub fn fallbackSubstitute(symbol: ResolvedSymbol, owner_name: []const u8, trap_address: usize) ?usize {
    if (objectRole(owner_name) == .libc and
        (std.mem.eql(u8, symbol.name, "backtrace") or
            std.mem.eql(u8, symbol.name, "backtrace_symbols") or
            std.mem.eql(u8, symbol.name, "backtrace_symbols_fd")))
    {
        return trap_address;
    }

    if (std.mem.startsWith(u8, symbol.name, "dl") or std.mem.startsWith(u8, symbol.name, "_dl")) {
        return trap_address;
    }

    return null;
}

fn checkNotification(event: ?*const NotificationEvent) void {
    // Native `SIGEV_THREAD` would create workers outside the loader's registration
    // protocol. Signal/none notification modes can use the original libc entry.
    const sigev_thread: c_int = 2;
    if (event) |notification| {
        if (notification.sigev_notify == sigev_thread) {
            @panic("unsupported SIGEV_THREAD notification");
        }
    }
}

pub fn currentThreadPointer() usize {
    var tp: usize = undefined;
    const result = std.os.linux.syscall2(.arch_prctl, std.os.linux.ARCH.GET_FS, @intFromPtr(&tp));
    std.debug.assert(result == 0);
    return tp;
}

pub const NotificationEvent = extern struct {
    sigev_value: std.os.linux.sigval,
    sigev_signo: c_int,
    sigev_notify: c_int,
};

/// Checks a PLT jump and its matching relocation. Input and result are ELF virtual
/// addresses; a matching opcode without the named `JUMP_SLOT` is not sufficient.
pub fn findPltSlot(dyn_object: *const DynObject, target_address: usize, symbol_name: []const u8) !?usize {
    const code = try CodeView.fromDynObject(dyn_object, target_address, 6);
    if (!std.mem.eql(u8, code.bytes[0..2], "\xff\x25")) return null; // `jmp [rip + disp32]`

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

/// Follows one recognized direct tail-jump wrapper in ELF coordinates. This is
/// a bounded wrapper recognizer, not general control-flow traversal.
pub fn resolveEntryJump(dyn_object: *const DynObject, entry_address: usize) !usize {
    const entry = try CodeView.fromDynObject(dyn_object, entry_address, 5);
    if (entry.bytes[0] == 0xe9) return entry.relativeTarget(1); // `jmp rel32`

    const frame_pointer_wrapper =
        "\x55" ++ // `push rbp`
        "\x48\x89\xe5" ++ // `mov rbp,rsp`
        "\x5d" ++ // `pop rbp`
        "\xe9"; // `jmp rel32`

    const wrapper = try CodeView.fromDynObject(dyn_object, entry_address, frame_pointer_wrapper.len + 4);
    if (std.mem.startsWith(u8, wrapper.bytes, frame_pointer_wrapper)) {
        return wrapper.relativeTarget(frame_pointer_wrapper.len);
    }

    return error.UnrecognizedEntryJump;
}

pub fn findLibcSymbol(services: *const Services, dyn_object: *DynObject, name: []const u8) !?ResolvedSymbol {
    return services.lookupSymbol(dyn_object, name, true) catch |err| switch (err) {
        error.UnresolvedSymbol => null,
        else => return err,
    };
}

/// Owns copies of the bytes; `address` borrows the object's mapping until application completes.
pub const CodePatch = struct {
    address: usize,
    segment_index: usize,
    size: usize,
    original: [12]u8,
    replacement: [12]u8,
};

/// Prepares patches for one object without changing its mapped bytes.
pub fn appendCodePatch(allocator: std.mem.Allocator, object: *const DynObject, patches: *std.ArrayList(CodePatch), address: usize, replacement: []const u8) !void {
    std.debug.assert(replacement.len > 0 and replacement.len <= 12);
    errdefer logger.err("libc.patch: object={s} action=prepare_failed target_host=0x{x} size={d}", .{ object.name, address, replacement.len });

    const segment_index = object.findSegment(address) orelse return error.InvalidCodeAddress;
    const segment = object.segments.values()[segment_index];
    const offset = address - segment.loaded_at;
    if (!segment.flags_first.read or !segment.flags_first.exec or offset > segment.mem_size or replacement.len > segment.mem_size - offset) {
        return error.InvalidCodeAddress;
    }

    const end_address = std.math.add(usize, address, replacement.len) catch return error.InvalidCodeAddress;
    for (patches.items) |patch| {
        if (address < patch.address + patch.size and patch.address < end_address) return error.OverlappingLibcPatches;
    }

    var patch: CodePatch = .{
        .address = address,
        .segment_index = segment_index,
        .size = replacement.len,
        .original = @splat(0),
        .replacement = @splat(0),
    };
    const original: [*]const u8 = @ptrFromInt(address);
    @memcpy(patch.original[0..patch.size], original[0..patch.size]);
    @memcpy(patch.replacement[0..patch.size], replacement);

    try patches.append(allocator, patch);
    logger.debug("libc.patch: object={s} action=prepared target_host=0x{x} segment={d} size={d} original={x} replacement={x}", .{ object.name, address, segment_index, patch.size, patch.original[0..patch.size], replacement });
}

/// Applies patches prepared for this object. On failure, attempts to restore
/// original bytes and permissions in reverse order; rollback failures are logged.
/// The caller prevents concurrent execution of the segments being modified.
pub fn applyCodePatches(object: *const DynObject, patches: []const CodePatch) !void {
    logger.debug("libc.patch: object={s} action=apply count={d}", .{ object.name, patches.len });
    var applied_count: usize = 0;
    errdefer {
        while (applied_count > 0) {
            applied_count -= 1;
            const patch = patches[applied_count];
            logger.debug("libc.patch: object={s} action=rollback target_host=0x{x} size={d}", .{ object.name, patch.address, patch.size });
            object.unprotectSegment(patch.segment_index) catch |err| {
                logger.err("libc.patch: object={s} action=rollback_unprotect target_host=0x{x} error={t}", .{ object.name, patch.address, err });
                continue;
            };

            const destination: [*]u8 = @ptrFromInt(patch.address);
            @memcpy(destination[0..patch.size], patch.original[0..patch.size]);
            object.reprotectSegment(patch.segment_index) catch |err| {
                logger.err("libc.patch: object={s} action=rollback_reprotect target_host=0x{x} error={t}", .{ object.name, patch.address, err });
            };
        }
    }

    for (patches) |patch| {
        logger.debug("libc.patch: object={s} action=write target_host=0x{x} size={d}", .{ object.name, patch.address, patch.size });
        errdefer logger.err("libc.patch: object={s} action=write_failed target_host=0x{x}", .{ object.name, patch.address });
        try object.unprotectSegment(patch.segment_index);

        const destination: [*]u8 = @ptrFromInt(patch.address);
        @memcpy(destination[0..patch.size], patch.replacement[0..patch.size]);
        applied_count += 1;

        try object.reprotectSegment(patch.segment_index);
    }
    logger.debug("libc.patch: object={s} action=complete count={d}", .{ object.name, applied_count });
}

/// Blocks all blockable signals on the calling thread and returns its previous
/// mask. Direct syscalls include libc-reserved signals in the requested mask.
pub fn blockThreadSignals() std.os.linux.sigset_t {
    var previous: std.os.linux.sigset_t = undefined;
    const all = std.os.linux.sigfillset();
    const result = std.os.linux.sigprocmask(std.os.linux.SIG.BLOCK, &all, &previous);

    std.debug.assert(std.os.linux.errno(result) == .SUCCESS);
    return previous;
}

pub fn restoreThreadSignals(mask: *const std.os.linux.sigset_t) void {
    const result = std.os.linux.sigprocmask(std.os.linux.SIG.SETMASK, mask, null);

    std.debug.assert(std.os.linux.errno(result) == .SUCCESS);
}

test {
    _ = @import("libc/musl.zig");
    _ = @import("libc/glibc.zig");
}
