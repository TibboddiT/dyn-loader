//! Native x86-64 musl integration for the loader.
//! Finds private globals and helpers by inspecting exported functions.

const std = @import("std");

const common = @import("../libc.zig");
const logger = @import("../logger.zig");
const DynObject = @import("../DynObject.zig");
const CodeView = @import("../CodeView.zig");
const InstructionFlow = @import("../InstructionFlow.zig");
const Register = InstructionFlow.Register;
const Services = common.Services;
const currentThreadPointer = common.currentThreadPointer;
const blockThreadSignals = common.blockThreadSignals;
const restoreThreadSignals = common.restoreThreadSignals;
const findLibcSymbol = common.findLibcSymbol;
const findPltSlot = common.findPltSlot;
const resolveEntryJump = common.resolveEntryJump;

// Runtime discovery and lifecycle callbacks.
// ------------------------------------------

const State = struct {
    threads: MuslThreads,
};

const vtable: common.VTable = .{
    .destroyState = &destroyState,
    .initInitialThread = &initInitialThread,
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

pub const system_libc_names = [_][]const u8{
    "libc.musl-x86_64.so.1",
    "ld-musl-x86_64.so.1",
};

pub fn isRuntimeName(name: []const u8) bool {
    for (system_libc_names) |candidate| {
        if (std.mem.eql(u8, name, candidate)) return true;
    }
    return false;
}

/// Checks for `issetugid`. `create` validates the implementation and layout.
pub fn recognizes(services: *const Services, object: *DynObject) !bool {
    return try findLibcSymbol(services, object, "issetugid") != null;
}

/// Detects all required thread facilities before returning backend state.
/// The returned runtime owns `State` and the write plan, but borrows native code,
/// globals, and the `Services` interface.
/// Native mappings must remain valid for the runtime's lifetime. Unknown or
/// conflicting inspection facts return an error.
pub fn create(services: *const Services, allocator: std.mem.Allocator, object: *DynObject) !common.Runtime {
    var capability: []const u8 = "layout";
    errdefer logger.err("musl.inspect: object={s} capability={s} action=failed", .{ object.name, capability });
    const layout = try detectMuslLayout(services, object);
    logger.debug("musl.inspect: object={s} capability=layout evidence={any}", .{ object.name, layout });
    capability = "errno";
    const errno_symbol = try services.lookupSymbol(object, "__errno_location", false);
    capability = "threads";
    const threads = detectMuslThreads(allocator, services, object, layout) catch |err| switch (err) {
        error.CodePatternMismatch => return error.UnrecognizedMuslThreadLayout,
        else => return err,
    };

    capability = "runtime_state";
    const state = try allocator.create(State);
    errdefer allocator.destroy(state);
    state.* = .{ .threads = threads };

    var runtime = common.Runtime.init(allocator, .{
        .services = services,
        .state = state,
        .vtable = &vtable,
        .getErrnoLocation = @ptrFromInt(try errno_symbol.getStaticAddress()),
    });
    errdefer runtime.write_ops.deinit(allocator);
    try appendWritePlan(&runtime, layout);
    logger.debug("musl.inspect: object={s} action=validated tsd_slots={d} errno_function_host=0x{x}", .{ object.name, threads.tsd_slots, try errno_symbol.getStaticAddress() });
    return runtime;
}

fn getState(runtime: *const common.Runtime) *State {
    return @ptrCast(@alignCast(runtime.state));
}

fn getWorker(worker: *const common.WorkerHandle) *MuslWorker {
    return @ptrCast(@alignCast(worker.state.?));
}

fn destroyState(runtime: *common.Runtime) void {
    runtime.allocator.destroy(getState(runtime));
}

fn initInitialThread(runtime: *common.Runtime) !void {
    initMuslInitialThread(&getState(runtime).threads);
}

fn supportsWorkers(_: *const common.Runtime) bool {
    // musl creation already validates all thread support.
    return true;
}

fn prepareObject(_: *common.Runtime, _: *DynObject) !void {
    // All native thread support is part of the original runtime object.
}

fn threadStorageSize(_: *const common.Runtime) usize {
    return common.bootstrapThreadStorageSize();
}

/// Redirects internal allocations that bypass normal symbol substitution.
/// Builds both patch sets before modifying code. `common.applyCodePatches`
/// handles permission changes and rollback. Temporary patch records borrow mappings.
fn patchAllocatorCalls(runtime: *common.Runtime, object: *DynObject) !void {
    var patches: std.ArrayList(common.CodePatch) = .empty;
    defer patches.deinit(runtime.allocator);

    const malloc_call = try detectMuslAllocatorCall(runtime.services, object, "malloc");
    const calloc_call = try detectMuslAllocatorCall(runtime.services, object, "calloc");
    logger.debug("musl.allocator: object={s} malloc_binding={any} calloc_binding={any}", .{ object.name, malloc_call, calloc_call });
    switch (malloc_call) {
        .relocated => {},
        .internal => |binding| try preparePatches(runtime.allocator, object, &patches, binding.target_address, @intFromPtr(runtime.services.malloc_substitute), 0),
    }
    switch (calloc_call) {
        .relocated => {},
        .internal => |binding| try preparePatches(runtime.allocator, object, &patches, binding.target_address, @intFromPtr(runtime.services.calloc_substitute), 16),
    }
    try common.applyCodePatches(object, patches.items);
}

fn initWorker(runtime: *common.Runtime) common.WorkerHandle {
    // Leave internal signals deliverable while waiting for native list locks.
    // `beginSpawn` blocks them only for the interval in which the child can
    // inherit a mask but does not yet have a usable musl descriptor.
    const mask = blockMuslAppSignals();
    return .{
        .runtime = runtime,
        .state = null,
        .parent_tp = currentThreadPointer(),
        .creator_mask = mask,
        .spawn_mask = null,
    };
}

/// Prepares a worker in the creator while holding the loader registry lock.
/// Allocates before the one-time native transition to multithreaded operation,
/// so allocation failure leaves that state unchanged.
fn prepareWorker(worker: *common.WorkerHandle) !void {
    const threads = &getState(worker.runtime).threads;
    worker.state = try MuslWorker.create(worker.runtime.allocator, threads.tsd_slots);

    const was_threaded = threads.threaded;
    prepareMuslThreads(threads);
    if (!was_threaded) {
        // Preserve the reserved signals unblocked by the first-thread transition.
        worker.creator_mask.?[0] &= ~musl_thread_signal_bits;
    }
}

fn beginSpawn(worker: *common.WorkerHandle) void {
    worker.spawn_mask = blockThreadSignals();
}

fn spawnFailed(worker: *common.WorkerHandle) void {
    // Unpublished state has no other owners; destroy it directly.
    getWorker(worker).destroy();
    worker.state = null;
}

fn registerWorker(worker: *const common.WorkerHandle, tp: usize) !void {
    registerMuslWorker(&getState(worker.runtime).threads, tp, worker.parent_tp, getWorker(worker));
}

fn enterUserCode(worker: *const common.WorkerHandle) void {
    // The child has finished native and generic registration. Wake the creator
    // before restoring application signals, whose handlers may run immediately.
    getWorker(worker).publishReady();

    var mask = worker.creator_mask.?;
    // Native `pthread_create` likewise removes `SIGCANCEL` from the child's mask.
    mask[0] &= ~musl_cancel_signal_bit;
    restoreThreadSignals(&mask);
}

/// Waits for worker startup in the creator without the loader registry lock.
/// Holding that lock would prevent the child from completing registration and
/// signalling readiness.
fn finishStartup(worker: *const common.WorkerHandle) void {
    const state = getWorker(worker);
    state.waitUntilReady();
    state.release();
}

fn unregisterWorker(worker: *const common.WorkerHandle, tp: usize) void {
    unregisterMuslWorker(&getState(worker.runtime).threads, tp);
}

fn releaseAfterJoin(worker: *const common.WorkerHandle) void {
    getWorker(worker).release();
}

// Thread-offset checks and allocator-call identification.
// -------------------------------------------------------

/// Cross-checks TID and TSD offsets through `pthread_getcpuclockid` and `getspecific`.
fn validateMuslThreadLayout(services: *const Services, dyn_object: *DynObject, layout: MuslLayout) !void {
    const clock_code = try CodeView.fromSymbol(services.inspect(dyn_object), "pthread_getcpuclockid");
    // mov eax, [rdi+disp8] (the one-byte gap is the TID offset)
    // not eax
    // lea eax, [rax*8+6]
    const load_tid = try clock_code.findUnique("\x8b\x47", 1, "\xf7\xd0\x8d\x04\xc5\x06\x00\x00\x00");
    // xor eax, eax
    // sub eax, [rdi+disp8] (the one-byte gap is the TID offset)
    // jo rel8 (only the opcode is matched; its displacement follows)
    const subtract_tid = try clock_code.findUnique("\x31\xc0\x2b\x47", 1, "\x70");
    if (load_tid != null and subtract_tid != null) return error.AmbiguousCodePattern;

    const tid_operand = if (load_tid) |offset| offset + 2 else if (subtract_tid) |offset| offset + 4 else return error.UnrecognizedMuslThreadLayout;
    if (clock_code.bytes[tid_operand] != layout.tid_offset) return error.InconsistentMuslLayout;

    const tsd_code = try CodeView.fromSymbol(services.inspect(dyn_object), "pthread_getspecific");
    // mov rax, fs:[0]
    // mov rax, [rax+disp32] (disp32 follows this prefix and holds the TSD offset)
    const prefix = "\x64\x48\x8b\x04\x25\x00\x00\x00\x00\x48\x8b\x80";
    const tsd_load = (try tsd_code.findUnique(prefix, 4, &.{})) orelse return error.UnrecognizedMuslThreadLayout;
    if (try tsd_code.readI32(tsd_load + prefix.len) != layout.tsd_offset) return error.InconsistentMuslLayout;
}

/// Both addresses are ELF virtual addresses, not callable host pointers.
/// A relocated call already uses loader symbol substitution through its PLT
/// (procedure linkage table). An internal call needs its `rel32` operand patched.
const CallBinding = union(enum) {
    relocated: struct {
        slot_address: usize,
    },
    internal: struct {
        target_address: usize,
    },
};

const CallProbe = struct {
    // Known allocation arguments in the x86-64 System V integer argument
    // registers. A write to `EDI`/`ESI` also clears the upper half of `RDI`/`RSI`.
    edi_value: i32,
    esi_value: ?i32 = null,
};

/// Recognizes a null check of `RAX`, optionally after saving it in another register.
/// Allows writes of -1 to `EAX` before testing a saved pointer.
fn hasPointerResultCheck(bytes: []const u8) bool {
    if (std.mem.startsWith(u8, bytes, "\x48\x85\xc0")) return true; // `test rax,rax`
    if (bytes.len < 3) return false;

    // `mov saved_register,rax`
    const rex = bytes[0];
    const opcode = bytes[1];
    const modrm = bytes[2];

    if ((rex & 0xfe) != 0x48 or opcode != 0x89) return false;
    if ((modrm & 0xf8) != 0xc0) return false;

    const destination_index = modrm & 0b111;
    const destination_extension = (rex & 0b0001) << 3;
    const saved_register = destination_index | destination_extension;

    if (saved_register == 0 or saved_register == 4) return false; // `rax` or `rsp`

    var following_bytes = bytes[3..];
    if (std.mem.startsWith(u8, following_bytes, "\x83\xc8\xff")) { // `or eax,-1`
        following_bytes = following_bytes[3..];
    }
    if (std.mem.startsWith(u8, following_bytes, "\xb8\xff\xff\xff\xff")) { // `mov eax,-1`
        following_bytes = following_bytes[5..];
    }

    // `test saved_register,saved_register`
    const register_index = saved_register & 0b111;
    const source_field = register_index << 3;
    const destination_field = register_index;
    const test_modrm = 0b11000000 | source_field | destination_field;
    const test_rex: u8 = if (saved_register < 8) 0x48 else 0x4d;
    const test_pointer = [_]u8{ test_rex, 0x85, test_modrm };

    return std.mem.startsWith(u8, following_bytes, &test_pointer);
}

/// Returns the byte offset of a call's signed `rel32` operand, not its opcode.
/// Follows a small allowed set of instructions from known argument loads to a
/// call and pointer-result check. Tracks overwrites of argument registers and
/// stops at unknown instructions.
/// Multiple anchors may describe the same call; different matching calls fail.
fn findCheckedCallOperand(code: CodeView, probe: CallProbe) !usize {
    const instruction_limit = 16;
    const search_span_bytes = 64;
    var call_operand_offset: ?usize = null;

    for (0..code.bytes.len) |anchor_offset| {
        if (code.bytes.len - anchor_offset < 5) break;

        const opcode = code.bytes[anchor_offset];
        // mov edi, imm32 or mov esi, imm32: anchor a known allocation argument.
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

            // call rel32, followed by a check of the returned pointer.
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

            // `mov r32,imm32`
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

            // push rax..rdi or nop.
            const is_push = bytes[0] >= 0x50 and bytes[0] <= 0x57;
            if (is_push or bytes[0] == 0x90) {
                cursor += 1;
                continue;
            }
            if (bytes.len >= 2 and bytes[0] == 0x41 and bytes[1] >= 0x50 and bytes[1] <= 0x57) {
                cursor += 2; // `push r8..r15`
                continue;
            }

            // `mov r64,r64`
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

            // sub rsp, imm8 (the immediate follows the matched prefix).
            if (bytes.len >= 4 and std.mem.startsWith(u8, bytes, "\x48\x83\xec")) {
                cursor += 4;
                continue;
            }
            // sub rsp, imm32 (the immediate follows the matched prefix).
            if (bytes.len >= 7 and std.mem.startsWith(u8, bytes, "\x48\x81\xec")) {
                cursor += 7;
                continue;
            }

            break;
        }
    }

    return call_operand_offset orelse error.UnrecognizedCheckedCall;
}

/// Uses allocation sites with distinctive constant sizes to identify the hidden
/// allocator binding. On x86-64 an atfork record contains five pointers (40
/// bytes); an atexit block contains a link and two arrays of 32 pointers (520
/// bytes). Both callers check allocation failure. These constants describe the
/// supported source layouts, not an allocator ABI.
/// atfork record layout, lines 11-16:
/// https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_atfork.c?h=v1.2.5#n11
/// `malloc` call and failure check, lines 40-43:
/// https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_atfork.c?h=v1.2.5#n40
/// atexit block layout, lines 12-20:
/// https://git.musl-libc.org/cgit/musl/tree/src/exit/atexit.c?h=v1.2.5#n12
/// `calloc` call and failure check, lines 50-56:
/// https://git.musl-libc.org/cgit/musl/tree/src/exit/atexit.c?h=v1.2.5#n50
fn detectMuslAllocatorCall(services: *const Services, dyn_object: *DynObject, name: []const u8) !CallBinding {
    logger.debug("musl.allocator: object={s} symbol={s} action=inspect", .{ dyn_object.name, name });
    errdefer logger.err("musl.allocator: object={s} symbol={s} action=failed", .{ dyn_object.name, name });
    const is_malloc = std.mem.eql(u8, name, "malloc");
    const probe_name = if (is_malloc) "pthread_atfork" else "__cxa_atexit";
    const probe = try CodeView.fromSymbol(services.inspect(dyn_object), probe_name);
    const arguments: CallProbe = if (is_malloc) .{ .edi_value = 40 } else .{ .edi_value = 520, .esi_value = 1 };
    const call_operand_offset = try findCheckedCallOperand(probe, arguments);
    const target_address = try probe.relativeTarget(call_operand_offset);

    if (try findPltSlot(dyn_object, target_address, name)) |slot_address| {
        return .{ .relocated = .{ .slot_address = slot_address } };
    }

    const public_code = try CodeView.fromSymbol(services.inspect(dyn_object), name);
    if (is_malloc) {
        const internal_implementation = try resolveEntryJump(dyn_object, target_address);
        const public_implementation = try resolveEntryJump(dyn_object, public_code.address);

        if (internal_implementation != public_implementation) return error.UnrecognizedAllocatorTarget;

        // Write permission is needed only when applying patches.
        _ = try CodeView.fromDynObject(dyn_object, internal_implementation, 1);

        return .{ .internal = .{ .target_address = target_address } };
    }

    // Chimera's public `calloc` tail-calls its internal allocator after restoring `rsi` and the saved registers.
    const calloc_tail_call =
        "\x4c\x89\xf6" ++ // `mov rsi,r14`
        "\x5b" ++ // `pop rbx`
        "\x41\x5e" ++ // `pop r14`
        "\x5d" ++ // `pop rbp`
        "\xe9"; // `jmp rel32` (the displacement follows this prefix)

    if (try public_code.findUnique(calloc_tail_call, 4, "")) |tail_call_offset| {
        const jump_operand_offset = tail_call_offset + calloc_tail_call.len;
        const tail_call_target = try public_code.relativeTarget(jump_operand_offset);

        if (target_address != tail_call_target) return error.UnrecognizedAllocatorTarget;
    } else {
        // In the recognized GCC shape, public and hidden `calloc` have separate
        // entries. Their overflow check and size multiplication must agree, and
        // their `malloc` calls must lead to the same implementation. Equal entry
        // addresses alone therefore cannot establish this binding.
        const allocation_prefix =
            "\x41\x54" ++ // `push r12`
            "\x49\x89\xf4" ++ // `mov r12,rsi`
            "\x55" ++ // `push rbp`
            "\x53" ++ // `push rbx`
            "\x48\x85\xf6" ++ // `test rsi,rsi`
            "\x74\x08" ++ // `je` past overflow check
            "\x48\x89\xf0" ++ // `mov rax,rsi`
            "\x48\xf7\xe7" ++ // `mul rdi`
            "\x70\x3f" ++ // `jo` allocation failure
            "\x4c\x0f\xaf\xe7" ++ // `imul r12,rdi`
            "\x4c\x89\xe7" ++ // `mov rdi,r12`
            "\xe8"; // `call rel32` (the displacement follows this prefix)
        const result_check =
            "\x48\x89\xc3" ++ // `mov rbx,rax`
            "\x48\x85\xc0"; // `test rax,rax`

        const sequence_size = allocation_prefix.len + 4 + result_check.len;
        const internal_code = try CodeView.fromDynObject(dyn_object, target_address, sequence_size);

        const public_match = try public_code.findUnique(allocation_prefix, 4, result_check);
        if (public_match != 0) return error.UnrecognizedAllocatorTarget;

        const internal_match = try internal_code.findUnique(allocation_prefix, 4, result_check);
        if (internal_match != 0) return error.UnrecognizedAllocatorTarget;

        const public_malloc_target = try public_code.relativeTarget(allocation_prefix.len);
        const malloc_slot = try findPltSlot(dyn_object, public_malloc_target, "malloc");
        if (malloc_slot == null) return error.UnrecognizedAllocatorTarget;

        const malloc_code = try CodeView.fromSymbol(services.inspect(dyn_object), "malloc");
        const internal_malloc_target = try internal_code.relativeTarget(allocation_prefix.len);
        const internal_implementation = try resolveEntryJump(dyn_object, internal_malloc_target);
        const public_implementation = try resolveEntryJump(dyn_object, malloc_code.address);

        if (internal_implementation != public_implementation) return error.UnrecognizedAllocatorTarget;

        _ = try CodeView.fromDynObject(dyn_object, internal_implementation, 1);
    }

    return .{ .internal = .{ .target_address = target_address } };
}

// Private global and pthread-layout inspection.
// ---------------------------------------------

/// Candidate x86-64 layouts selected by the width of `__libc.secure`.
/// Global fields are relative to `mapped_address` (`__libc`); descriptor fields
/// from `tid_offset` onward are relative to the thread pointer. Detection below
/// cross-checks selected fields rather than deriving the entire C structure.
const MuslLayout = struct {
    const Flags = enum { int_flags, byte_flags };

    // Known x86-64 descriptor positions. Worker inspection checks selected
    // accesses; the embedded link position remains a layout assumption.
    const links_offset = 16;
    const sysinfo_offset = 32;
    const canary_offset = 40;
    const allocator_heap_offset = 200;

    mapped_address: usize,
    flags: Flags,
    threaded_offset: usize,
    thread_count_offset: usize, // `libc.threads_minus_1`: excludes the initial thread.
    need_locks_offset: ?usize,
    auxv_offset: usize,
    tls_size_offset: usize,
    tls_align_offset: usize,
    page_size_offset: usize,
    tid_offset: usize,
    tsd_offset: usize,
    robust_head_offset: usize,
    locale_offset: usize,
    detach_state_offset: usize,
    joinable_state: c_int,
};

/// Links point to `struct pthread`, not embedded nodes as in glibc.
const MuslThreadLinks = extern struct {
    prev: usize,
    next: usize,
};

const MuslTsdStorage = struct {
    main_virtual_address: usize,
    main_storage: [*]usize, // Borrowed native array; workers allocate their own.
    slots: usize,
};

const MuslListFunctions = struct {
    lockList: *const fn () callconv(.c) void,
    unlockList: *const fn () callconv(.c) void,
};

const MuslStartup = struct {
    // Byte offset in `pthread_create`, used to bound the earlier stdio setup.
    main_tsd_store_offset: usize,
    initMembarrier: *const fn () callconv(.c) void,
};

const MuslStdio = struct {
    // x86-64 `FILE` fields, checked against the native initialization loop.
    const next_offset = 112;
    const lock_offset = 140;

    lockFiles: *const fn () callconv(.c) *usize,
    unlockFiles: *const fn () callconv(.c) void,
    // Addresses of `__stdin_used`/`__stdout_used`/`__stderr_used` slots, not `FILE`s.
    // Read their contents at initialization time, after relocations are applied.
    standard_files: [3]*const usize,
};

const MuslThreads = struct {
    // Native pointers and callable helpers borrow the loaded libc mapping.
    // `MuslWorker` owns its separately allocated state and per-worker TSD array.
    layout: MuslLayout,
    tsd_slots: usize,
    main_tsd: [*]usize,
    thread_count: *c_int, // Native `threads_minus_1`, updated under the native lock.
    need_locks: ?*i8, // Newer layouts use this to control internal lock elision.

    lockList: *const fn () callconv(.c) void,
    unlockList: *const fn () callconv(.c) void,
    initMembarrier: *const fn () callconv(.c) void,
    stdio: MuslStdio,
    allocator_heap_slot: ?*const usize,

    initial_tp: usize,
    initialized: bool, // Initial descriptor and one-element list exist.
    threaded: bool, // First-worker stdio/signal/TSD transition completed.
};

/// `issetugid` returns `libc.secure`. Its complete short body reveals both the
/// field's address and whether the global flags occupy ints or bytes. Subtract
/// the known `secure` offset to recover `__libc`, then validate the candidate layout.
/// Integer-flag layout in v1.1.22, lines 20-30:
/// https://git.musl-libc.org/cgit/musl/tree/src/internal/libc.h?h=v1.1.22#n20
/// Byte-flag layout in v1.2.5, lines 20-31:
/// https://git.musl-libc.org/cgit/musl/tree/src/internal/libc.h?h=v1.2.5#n20
fn detectMuslLayout(services: *const Services, dyn_object: *DynObject) !MuslLayout {
    const code = try CodeView.fromSymbol(services.inspect(dyn_object), "issetugid");

    const Pattern = struct {
        prefix: []const u8,
        suffix: []const u8,
        layout: MuslLayout.Flags,
    };

    const patterns = [_]Pattern{
        .{
            .prefix = "\x8b\x05", // `mov eax,[rip + disp32]`
            .suffix = "\xc3", // `ret`
            .layout = .int_flags,
        },
        .{
            .prefix = "\x0f\xbe\x05", // `movsx eax,byte [rip + disp32]`
            .suffix = "\xc3", // `ret`
            .layout = .byte_flags,
        },
        .{
            .prefix = "\x55" ++ // `push rbp`
                "\x48\x89\xe5" ++ // `mov rbp,rsp`
                "\x0f\xbe\x05", // `movsx eax,byte [rip + disp32]`
            .suffix = "\x5d" ++ // `pop rbp`
                "\xc3", // `ret`
            .layout = .byte_flags,
        },
    };

    var detected: ?MuslLayout = null;
    for (patterns) |pattern| {
        const match_offset = (try code.findUnique(pattern.prefix, 4, pattern.suffix)) orelse {
            logger.debug("musl.layout: object={s} code_elf=0x{x} flags={t} prefix_bytes={d} result=no_match", .{ dyn_object.name, code.address, pattern.layout, pattern.prefix.len });
            continue;
        };
        if (match_offset != 0 or pattern.prefix.len + 4 + pattern.suffix.len != code.bytes.len) {
            logger.debug("musl.layout: object={s} code_elf=0x{x} flags={t} result=partial_match offset={d}", .{ dyn_object.name, code.address, pattern.layout, match_offset });
            continue;
        }
        logger.debug("musl.layout: object={s} code_elf=0x{x} flags={t} result=matched", .{ dyn_object.name, code.address, pattern.layout });
        if (detected != null) return error.AmbiguousCodePattern;

        const secure_address = try code.relativeTarget(pattern.prefix.len);
        const secure_offset: usize = switch (pattern.layout) {
            .int_flags => 8,
            .byte_flags => 2,
        };

        const virtual_address = std.math.sub(usize, secure_address, secure_offset) catch return error.InvalidDataAddress;

        var layout: MuslLayout = switch (pattern.layout) {
            // These tables include pthread fields as well as `__libc` fields.
            // Their association with int/byte flags is a supported-layout
            // assumption, checked by `validateMuslThreadLayout` and worker probes.
            .int_flags => .{
                .mapped_address = 0,
                .flags = .int_flags,
                .threaded_offset = 4,
                .thread_count_offset = 12,
                .need_locks_offset = null,
                .auxv_offset = 16,
                .tls_size_offset = 32,
                .tls_align_offset = 40,
                .page_size_offset = 56,
                .tid_offset = 56,
                .tsd_offset = 136,
                .robust_head_offset = 144,
                .locale_offset = 176,
                .detach_state_offset = 64,
                .joinable_state = 1,
            },
            .byte_flags => .{
                .mapped_address = 0,
                .flags = .byte_flags,
                .threaded_offset = 1,
                .thread_count_offset = 4,
                .need_locks_offset = 3,
                .auxv_offset = 8,
                .tls_size_offset = 24,
                .tls_align_offset = 32,
                .page_size_offset = 48,
                .tid_offset = 48,
                .tsd_offset = 128,
                .robust_head_offset = 136,
                .locale_offset = 168,
                .detach_state_offset = 56,
                .joinable_state = 2,
            },
        };

        // `global_locale` follows `page_size` and contains six category pointers.
        layout.mapped_address = try dyn_object.mappedDataAddress(virtual_address, layout.page_size_offset + 7 * @sizeOf(usize));
        try validateMuslThreadLayout(services, dyn_object, layout);

        if (try findLibcSymbol(services, dyn_object, "__libc")) |symbol| {
            if (try symbol.getStaticAddress() != layout.mapped_address) return error.InconsistentMuslLayout;
        }

        detected = layout;
    }

    return detected orelse error.UnrecognizedMuslLayout;
}

/// Finds and validates the thread helpers and fields needed by runtime callbacks.
/// Missing helpers or fields fail creation.
fn detectMuslThreads(allocator: std.mem.Allocator, services: *const Services, dyn_object: *DynObject, layout: MuslLayout) !MuslThreads {
    var capability: []const u8 = "pthread_create";
    errdefer logger.err("musl.threads: object={s} capability={s} action=failed", .{ dyn_object.name, capability });
    const create_code = try CodeView.fromSymbol(services.inspect(dyn_object), "pthread_create");
    logger.debug("musl.threads: object={s} symbol=pthread_create code_elf=0x{x} size={d}", .{ dyn_object.name, create_code.address, create_code.bytes.len });

    // RIP-relative targets use ELF coordinates, not loaded addresses.
    const location = try services.findSegment(layout.mapped_address);
    const segment = dyn_object.segments.values()[location.segment_index];
    const global_virtual_address = segment.mem_offset + (layout.mapped_address - segment.loaded_at);

    var create_flow = try InstructionFlow.init(allocator, create_code);
    defer create_flow.deinit();

    capability = "tsd";
    const tsd = try detectMuslTsdStorage(allocator, services, dyn_object, create_flow, layout);
    logger.debug("musl.threads: object={s} capability=tsd slots={d} main_storage_elf=0x{x}", .{ dyn_object.name, tsd.slots, tsd.main_virtual_address });
    capability = "list_helpers";
    const list = try detectMuslListFunctions(allocator, services, dyn_object, layout);
    logger.debug("musl.threads: object={s} capability=list_helpers lock_host=0x{x} unlock_host=0x{x}", .{ dyn_object.name, @intFromPtr(list.lockList), @intFromPtr(list.unlockList) });
    capability = "startup";
    const startup = try detectMuslStartup(dyn_object, create_flow, layout, global_virtual_address, tsd);
    capability = "stdio";
    const stdio = try detectMuslStdio(dyn_object, create_flow, startup.main_tsd_store_offset);
    capability = "worker_fields";
    const heap_slot = try validateMuslWorkerFields(dyn_object, create_flow, layout, global_virtual_address);
    logger.debug("musl.threads: object={s} action=validated startup={any} stdio={any} heap_slot_host=0x{x}", .{ dyn_object.name, startup, stdio, @intFromPtr(heap_slot) });

    return .{
        .layout = layout,
        .tsd_slots = tsd.slots,
        .main_tsd = tsd.main_storage,
        .thread_count = @ptrFromInt(layout.mapped_address + layout.thread_count_offset),
        .need_locks = if (layout.need_locks_offset) |offset| @ptrFromInt(layout.mapped_address + offset) else null,
        .lockList = list.lockList,
        .unlockList = list.unlockList,
        .initMembarrier = startup.initMembarrier,
        .stdio = stdio,
        .allocator_heap_slot = heap_slot,
        .initial_tp = 0,
        .initialized = false,
        .threaded = false,
    };
}

/// Finds the main pthread-key array and per-worker storage size.
/// Cross-checks `key_create`'s index bound against `pthread_create`'s allocation.
/// This TSD storage is separate from ELF TLS.
/// Native TSD size and main array, lines 4-5:
/// https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_key_create.c?h=v1.2.5#n4
/// Lazy main-array setup and key-index wrap, lines 31-50:
/// https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_key_create.c?h=v1.2.5#n31
fn detectMuslTsdStorage(allocator: std.mem.Allocator, services: *const Services, dyn_object: *DynObject, create_flow: InstructionFlow, layout: MuslLayout) !MuslTsdStorage {
    const key_create = try CodeView.fromSymbol(services.inspect(dyn_object), "pthread_key_create");
    var key_flow = try InstructionFlow.init(allocator, key_create);
    defer key_flow.deinit();

    var main_address: ?usize = null;
    var slot_count: ?usize = null;
    for (key_flow.nodes.items, 0..) |node, index| {
        if (!node.reached) continue;

        const instruction = node.instruction;
        const source = key_flow.value(node, instruction.src);
        const destination = key_flow.destination(node);
        if (instruction.op == .mov and instruction.width == 64 and
            destination.kind == .thread_address and destination.b == layout.tsd_offset and source.kind == .address)
        {
            try uniqueAddress(&main_address, source.a);
        }

        // A key-index wrap is followed by a comparison using that same register.
        // Do not infer the bound from an unrelated immediate elsewhere in code.
        if (instruction.op == .bit_and and instruction.dst == .reg and source.kind == .constant and
            source.a > 0 and source.a < 128 and index + 1 < key_flow.nodes.items.len)
        {
            const next = key_flow.nodes.items[index + 1].instruction;
            if (next.op == .compare and (std.meta.eql(next.src, instruction.dst) or std.meta.eql(next.dst, instruction.dst))) {
                try uniqueAddress(&slot_count, source.a + 1);
            }
        }
    }
    const main_tsd_address = main_address orelse return error.MuslMainTsdAssignmentNotFound;
    const slots = slot_count orelse return error.MuslTsdKeyBoundNotFound;
    if (!std.math.isPowerOfTwo(slots)) return error.InconsistentMuslLayout;

    // Match the index bound to the allocation operand, not an unrelated constant.
    const expected_size = slots * @sizeOf(usize);
    var size_address: ?usize = null;
    for (create_flow.nodes.items) |node| {
        if (!node.reached or node.instruction.width != 64) continue;
        if (node.instruction.op != .add and node.instruction.op != .sub) continue;

        for ([_]InstructionFlow.Operand{ node.instruction.src, node.instruction.dst }) |operand| {
            const value = create_flow.value(node, operand);
            if (value.kind != .global or value.a < 0) continue;
            const mapped = dyn_object.mappedDataAddress(@intCast(value.a), 8) catch continue;
            const native_size: *align(1) const usize = @ptrFromInt(mapped);
            if (native_size.* == expected_size) try uniqueAddress(&size_address, value.a);
        }
    }
    if (size_address == null) return error.MuslTsdAllocationSizeNotFound;

    const main_tsd = try dyn_object.mappedWritableDataAddress(main_tsd_address, expected_size, @alignOf(usize));
    return .{
        .main_virtual_address = main_tsd_address,
        .main_storage = @ptrFromInt(main_tsd),
        .slots = slots,
    };
}

/// Finds `__tl_lock`/`__tl_unlock` through `key_delete`.
/// Native readers require musl's lock protocol, not a separate loader mutex.
/// Native thread-list lock and unlock, lines 23-43:
/// https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_create.c?h=v1.2.5#n23
fn detectMuslListFunctions(allocator: std.mem.Allocator, services: *const Services, dyn_object: *DynObject, layout: MuslLayout) !MuslListFunctions {
    const key_delete = try CodeView.fromSymbol(services.inspect(dyn_object), "pthread_key_delete");
    var delete_flow = try InstructionFlow.init(allocator, key_delete);
    defer delete_flow.deinit();

    // `key_delete` takes `key_lock`, then the native thread-list lock. The loop
    // clears each thread's TSD slot before releasing the thread-list lock.
    const wrlock = try services.lookupSymbol(dyn_object, "pthread_rwlock_wrlock", false);
    var lock_entry_index: ?usize = null;
    for (delete_flow.nodes.items, 0..) |node, index| {
        if (node.reached and node.instruction.op == .call and node.instruction.target == wrlock.value) {
            try uniqueAddress(&lock_entry_index, @intCast(index + 1));
        }
    }
    const list_lock_index = lock_entry_index orelse return error.MuslThreadListLockNotFound;
    if (list_lock_index >= delete_flow.nodes.items.len) return error.MuslThreadListLockNotFound;

    const list_lock_call = delete_flow.nodes.items[list_lock_index].instruction;
    if (list_lock_call.op != .call) return error.MuslThreadListLockNotFound;
    const list_lock_address = list_lock_call.target orelse return error.MuslThreadListLockNotFound;

    // The backward edge belongs to the per-thread clearing loop. The call on
    // its fallthrough path releases the list lock after traversal completes.
    var unlock_target: ?usize = null;
    for (delete_flow.nodes.items[list_lock_index + 1 ..], list_lock_index + 1..) |node, index| {
        const branch = node.instruction;
        if (!node.reached or branch.op != .branch or branch.target == null or index + 1 >= delete_flow.nodes.items.len) continue;
        if (branch.target.? < key_delete.address + list_lock_call.end or branch.target.? >= key_delete.address + branch.offset) continue;
        const next = delete_flow.nodes.items[index + 1].instruction;
        if (next.op == .call and next.target != null) try uniqueAddress(&unlock_target, @intCast(next.target.?));
    }
    const list_unlock_address = unlock_target orelse return error.MuslThreadListUnlockNotFound;
    if (list_unlock_address <= list_lock_address or list_unlock_address - list_lock_address > 256) return error.UnrecognizedMuslThreadLayout;

    // The supported build places unlock shortly after lock. That bounded range
    // supplies code bytes without depending on hidden-symbol sizes. Check that
    // lock reads the known TID field and that unlock writes the same lock word.
    const lock_code = try CodeView.fromDynObject(dyn_object, list_lock_address, list_unlock_address - list_lock_address);
    var lock_flow = try InstructionFlow.init(allocator, lock_code);
    defer lock_flow.deinit();

    var lock_global: ?usize = null;
    for (lock_flow.nodes.items, 0..) |node, index| {
        if (!node.reached or node.instruction.op != .mov or node.instruction.width != 32) continue;
        const source = lock_flow.value(node, node.instruction.src);
        if (source.kind != .thread_field or source.b != layout.tid_offset or index + 1 >= lock_flow.nodes.items.len) continue;
        const next = lock_flow.nodes.items[index + 1];
        const global = lock_flow.value(next, next.instruction.src);
        if (next.instruction.op == .mov and next.instruction.width == 32 and global.kind == .global) {
            try uniqueAddress(&lock_global, global.a);
        }
    }
    const lock_address = lock_global orelse return error.MuslThreadListLockNotFound;
    _ = try dyn_object.mappedWritableDataAddress(lock_address, 4, 4);

    const unlock_code = try InstructionFlow.functionPrefix(try CodeView.fromDynObject(dyn_object, list_unlock_address, 0x70));
    var unlock_flow = try InstructionFlow.init(allocator, unlock_code);
    defer unlock_flow.deinit();

    // Decode the store without assuming its source register. The following
    // barrier is musl's inline assembly, not compiler-selected register output.
    var unlock_store_found = false;
    for (unlock_flow.nodes.items) |node| {
        if (!node.reached) continue;
        const instruction = node.instruction;
        if (instruction.op == .mov and instruction.width == 32 and instruction.dst == .memory and instruction.dst.memory.rip and
            @as(i128, unlock_code.address) + instruction.end + instruction.dst.memory.displacement == lock_address and
            std.mem.startsWith(u8, unlock_code.bytes[instruction.end..], "\xf0\x83\x0c\x24\x00"))
        {
            // `lock or dword [rsp],0` provides a memory barrier without changing
            // the stored value. Its position ties the store to musl's unlock.
            unlock_store_found = true;
        }
    }
    if (!unlock_store_found) return error.MuslThreadListUnlockNotFound;

    const lock_entry = try CodeView.fromDynObject(dyn_object, list_lock_address, 1);
    const unlock_entry = try CodeView.fromDynObject(dyn_object, list_unlock_address, 1);
    return .{
        .lockList = @ptrCast(lock_entry.bytes.ptr),
        .unlockList = @ptrCast(unlock_entry.bytes.ptr),
    };
}

/// Validates the native first-thread transition and recovers `__membarrier_init`.
/// Requires the helper call directly between main TSD setup and `libc.threaded`.
fn detectMuslStartup(dyn_object: *DynObject, flow: InstructionFlow, layout: MuslLayout, global_virtual_address: usize, tsd: MuslTsdStorage) !MuslStartup {
    var main_store: ?usize = null;
    var helper: ?usize = null;
    var count_found = false;
    var need_locks_found = layout.need_locks_offset == null;
    const flag_width: u8 = switch (layout.flags) {
        .int_flags => 32,
        .byte_flags => 8,
    };

    for (flow.nodes.items, 0..) |node, index| {
        if (!node.reached or node.instruction.op != .mov) continue;
        const destination = flow.destination(node);
        const source = flow.value(node, node.instruction.src);
        if (destination.is(.address, @intCast(global_virtual_address + layout.thread_count_offset)) and node.instruction.width == 32) {
            count_found = true;
        }
        if (layout.need_locks_offset) |offset| {
            if (destination.is(.address, @intCast(global_virtual_address + offset)) and node.instruction.width == 8 and source.is(.constant, 1)) {
                need_locks_found = true;
            }
        }

        if (node.instruction.width != 64 or destination.kind != .thread_address or destination.b != layout.tsd_offset or
            !source.is(.address, @intCast(tsd.main_virtual_address)))
        {
            continue;
        }

        if (index + 2 >= flow.nodes.items.len) return error.MuslThreadedTransitionNotFound;
        const call = flow.nodes.items[index + 1].instruction;
        const flag = flow.nodes.items[index + 2];
        if (call.op != .call or call.target == null or flag.instruction.op != .mov or
            flag.instruction.width != flag_width or
            !flow.destination(flag).is(.address, @intCast(global_virtual_address + layout.threaded_offset)) or
            !flow.value(flag, flag.instruction.src).is(.constant, 1))
        {
            return error.MuslThreadedTransitionNotFound;
        }

        try uniqueAddress(&main_store, @intCast(node.instruction.offset));
        try uniqueAddress(&helper, @intCast(call.target.?));
    }
    if (!count_found or !need_locks_found) return error.MuslThreadCounterStoreNotFound;
    const membarrier_address = helper orelse return error.MuslThreadedTransitionNotFound;
    const membarrier_entry = try CodeView.fromDynObject(dyn_object, membarrier_address, 1);
    return .{
        .main_tsd_store_offset = main_store.?,
        .initMembarrier = @ptrCast(membarrier_entry.bytes.ptr),
    };
}

/// Recovers the open-file list helpers and three standard-stream pointer slots.
/// Native first-thread setup enables locks on existing `FILE` objects. Standard
/// streams are handled separately because they need not be in the open-file list.
fn detectMuslStdio(dyn_object: *DynObject, flow: InstructionFlow, setup_end_offset: usize) !MuslStdio {
    // The call result is in `RAX` by the System V ABI. The register holding
    // `FILE *` after dereferencing that result is selected by the compiler.
    var lock_index: ?usize = null;
    for (flow.nodes.items, 0..) |node, index| {
        if (!node.reached or node.instruction.offset >= setup_end_offset or node.instruction.op != .call or
            node.instruction.target == null or index + 1 >= flow.nodes.items.len)
        {
            continue;
        }

        const next = flow.nodes.items[index + 1].instruction;
        if (next.op == .mov and next.width == 64 and next.dst == .reg and memoryField(next.src, Register.rax, 0)) {
            try uniqueAddress(&lock_index, @intCast(index));
        }
    }
    const start = lock_index orelse return error.MuslStdioListLockNotFound;
    const file_register = flow.nodes.items[start + 1].instruction.dst.reg;
    var walk_found = false;
    var store_found = false;
    var helper: ?usize = null;
    var unlock_index: ?usize = null;

    // Within the first-thread setup, require traversal via `FILE.next` and an
    // enabling write to `FILE.lock`. The next call after both is the unlock.
    for (flow.nodes.items[start + 2 ..], start + 2..) |node, index| {
        const instruction = node.instruction;
        if (instruction.offset >= setup_end_offset) break;
        if (!node.reached) continue;
        if (instruction.op == .mov and instruction.width == 64 and instruction.dst == .reg and
            instruction.dst.reg == file_register and memoryField(instruction.src, file_register, MuslStdio.next_offset))
        {
            walk_found = true;
        }
        if (instruction.op == .mov and instruction.width == 32 and memoryField(instruction.dst, file_register, MuslStdio.lock_offset) and
            flow.value(node, instruction.src).is(.constant, 0))
        {
            store_found = true;
        }

        if (instruction.op != .call) continue;
        if (walk_found and store_found) {
            unlock_index = index;
            break;
        }
        // Some builds call `init_file_lock` instead of inlining its store.
        // Require the loop's file pointer as the ABI argument and verify the
        // same field store in that helper before accepting its role.
        if (helper != null or instruction.target == null or index == 0) return error.MuslStdioLockStoreNotFound;
        const argument = flow.nodes.items[index - 1].instruction;
        if (argument.op != .mov or argument.dst != .reg or argument.dst.reg != Register.rdi or
            argument.src != .reg or argument.src.reg != file_register) return error.MuslStdioLockStoreNotFound;
        helper = instruction.target.?;
        const code = try CodeView.fromDynObject(dyn_object, helper.?, 26);
        var helper_flow = try InstructionFlow.init(flow.allocator, code);
        defer helper_flow.deinit();
        for (helper_flow.nodes.items) |helper_node| {
            if (!helper_node.reached) continue;
            const operation = helper_node.instruction;
            if (operation.op == .mov and operation.width == 32 and memoryField(operation.dst, Register.rdi, MuslStdio.lock_offset) and
                operation.src == .immediate and operation.src.immediate == 0)
            {
                store_found = true;
            }
        }
        if (!store_found) return error.MuslStdioLockStoreNotFound;
    }
    const end = unlock_index orelse return error.MuslStdioListUnlockNotFound;

    // Retain nullable stream slots; their values are final only after relocation.
    var standard_files: [3]*const usize = undefined;
    var file_count: usize = 0;
    for (flow.nodes.items[end + 1 ..], end + 1..) |node, index| {
        const instruction = node.instruction;
        if (instruction.offset >= setup_end_offset) break;
        if (!node.reached) continue;
        if (instruction.op != .mov or instruction.width != 64 or instruction.dst != .reg or index + 1 >= flow.nodes.items.len) continue;
        const source = flow.value(node, instruction.src);
        if (source.kind != .global) continue;
        const next = flow.nodes.items[index + 1].instruction;
        if (helper) |address| {
            if (instruction.dst.reg != Register.rdi or next.op != .call or next.target != address) continue;
        } else if (next.op != .compare or !std.meta.eql(next.dst, instruction.dst) or !std.meta.eql(next.src, instruction.dst)) {
            continue;
        }

        if (file_count == 3) return error.AmbiguousCodePattern;
        const virtual_address = std.math.cast(usize, source.a) orelse return error.InvalidDataAddress;
        const mapped = try dyn_object.mappedDataAddress(virtual_address, 8);
        for (standard_files[0..file_count]) |previous| {
            if (@intFromPtr(previous) == mapped) return error.InconsistentMuslLayout;
        }

        standard_files[file_count] = @ptrFromInt(mapped);
        file_count += 1;
    }
    if (file_count != 3) return error.MuslStdioStandardStreamsNotFound;

    const lock_address = flow.nodes.items[start].instruction.target.?;
    const unlock_address = flow.nodes.items[end].instruction.target orelse return error.MuslStdioListUnlockNotFound;
    const lock_entry = try CodeView.fromDynObject(dyn_object, lock_address, 1);
    const unlock_entry = try CodeView.fromDynObject(dyn_object, unlock_address, 1);
    return .{
        .lockFiles = @ptrCast(lock_entry.bytes.ptr),
        .unlockFiles = @ptrCast(unlock_entry.bytes.ptr),
        .standard_files = standard_files,
    };
}

/// Tests the encoded `[base + offset]` operand, without resolving the register's
/// symbolic value. Indexed, segment-relative, and RIP-relative operands differ.
fn memoryField(operand: InstructionFlow.Operand, base: u4, offset: usize) bool {
    return switch (operand) {
        .memory => |memory| !memory.rip and !memory.fs and memory.base == base and memory.index == null and memory.displacement == offset,
        .none, .reg, .high, .vector, .immediate => false,
    };
}

/// Validates the descriptor writes reproduced by `initMuslWorkerDescriptor`. Returns
/// the optional allocator initialization slot, borrowed from the loaded object.
/// Requires all descriptor stores to refer to the same native call result.
/// Canary/sysinfo sources must come from the current thread, and the robust
/// head must point back to its own field. Register names are not layout facts.
fn validateMuslWorkerFields(dyn_object: *DynObject, flow: InstructionFlow, layout: MuslLayout, global_virtual_address: usize) !?*const usize {
    const locale_address = global_virtual_address + layout.page_size_offset + @sizeOf(usize);
    // The locale assignment identifies the native descriptor allocation result.
    // Its identity is a call-site offset, not an ELF address or host pointer.
    var worker: ?usize = null;
    for (flow.nodes.items) |node| {
        if (!node.reached or node.instruction.op != .mov or node.instruction.width != 64) continue;
        const destination = flow.destination(node);
        if (destination.kind == .call_address and destination.b == layout.locale_offset and
            flow.value(node, node.instruction.src).is(.address, @intCast(locale_address)))
        {
            try uniqueAddress(&worker, destination.a);
        }
    }
    const worker_id = worker orelse return error.MuslWorkerLocaleStoreNotFound;

    var self_pointer = false;
    var robust = false;
    var canary = false;
    var sysinfo = switch (layout.flags) {
        .int_flags => true, // This layout does not require the newer copy.
        .byte_flags => false,
    };
    var joinable = false;
    var heap_slot: ?*const usize = null;

    for (flow.nodes.items) |node| {
        if (!node.reached or node.instruction.op != .mov) continue;
        const destination = flow.destination(node);
        if (!destination.is(.call_address, @intCast(worker_id))) continue;

        const source = flow.value(node, node.instruction.src);
        if (node.instruction.width == 64) {
            if (destination.b == 0 and source.is(.call, @intCast(worker_id))) {
                self_pointer = true;
            }
            if (destination.b == layout.robust_head_offset and std.meta.eql(source, destination)) {
                robust = true;
            }
            if (destination.b == MuslLayout.canary_offset and source.kind == .thread_field and source.b == MuslLayout.canary_offset) {
                canary = true;
            }
            if (destination.b == MuslLayout.sysinfo_offset and source.kind == .thread_field and source.b == MuslLayout.sysinfo_offset) {
                sysinfo = true;
            }

            // Chimera's extra heap pointer is read from a relocated native slot.
            // Identify it by the store's destination, not by a compiler profile.
            if (destination.b == MuslLayout.allocator_heap_offset) {
                if (source.kind != .global or source.a < 0) return error.MuslWorkerHeapSlotNotFound;
                const address = try dyn_object.mappedDataAddress(@intCast(source.a), 8);
                if (heap_slot != null and @intFromPtr(heap_slot.?) != address) return error.AmbiguousCodePattern;
                heap_slot = @ptrFromInt(address);
            }
        }

        // Native creation selects joinable or detached according to attributes.
        // The merged two-value range is acceptable evidence for this field;
        // our worker initialization always installs the joinable alternative.
        if (node.instruction.width == 32 and destination.b == layout.detach_state_offset and
            (source.is(.constant, layout.joinable_state) or
                (source.is(.range, layout.joinable_state) and source.b == layout.joinable_state + 1)))
        {
            joinable = true;
        }
    }

    if (!self_pointer) return error.MuslWorkerSelfPointerNotFound;
    if (!robust) return error.MuslWorkerRobustHeadNotFound;
    if (!canary) return error.MuslWorkerCanaryCopyNotFound;
    if (!sysinfo) return error.MuslWorkerSysinfoCopyNotFound;
    if (!joinable) return error.MuslWorkerJoinableStoreNotFound;

    return heap_slot;
}

/// Accepts repeated evidence for the same address and rejects conflicting addresses.
fn uniqueAddress(result: *?usize, value: i64) !void {
    const address = std.math.cast(usize, value) orelse return error.InvalidCodeAddress;
    if (result.*) |previous| {
        if (previous != address) return error.AmbiguousCodePattern;
    } else {
        result.* = address;
    }
}

/// Recognizes a pointer-width check or move of the allocator result in `RAX`.
/// Skips known instructions that preserve `RAX`. Stops at unknown instructions
/// or overwrites. This is a bounded call-site check, not full disassembly.
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
            1 => 1, // `disp8`
            2 => 4, // `disp32`
            3 => 0, // register operand
        };

        // A memory operand with `r/m=4` has a SIB (scale/index/base) byte. Its
        // base encoding can add a `disp32` even when the ModR/M mode is zero.
        // Account for both bytes before examining the next instruction.
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

// Direct-call patch preparation.
// ------------------------------

/// Prepares call patches for later application by the caller.
/// A trampoline in the object's extra page reaches host addresses beyond `rel32`
/// range. Its absolute jump preserves the original return address.
fn preparePatches(allocator: std.mem.Allocator, dyn_object: *DynObject, patches: *std.ArrayList(common.CodePatch), target_virtual_address: usize, substitute_address: usize, trampoline_offset: usize) !void {
    const loaded_address = dyn_object.loaded_at orelse return error.InvalidCodeAddress;
    const extra_offset = std.math.sub(usize, dyn_object.loaded_size, 0x1000) catch return error.InvalidCodeAddress;
    const extra_address = std.math.add(usize, loaded_address, extra_offset) catch return error.InvalidCodeAddress;
    const trampoline_address = std.math.add(usize, extra_address, trampoline_offset) catch return error.InvalidCodeAddress;

    const extra_segment_index = dyn_object.findSegment(trampoline_address) orelse return error.InvalidCodeAddress;
    const extra_segment = dyn_object.segments.values()[extra_segment_index];

    // The loader reserves this final page for trampolines. Require an anonymous
    // one-page segment rather than overwriting bytes belonging to the ELF file.
    if (extra_segment.file_size != 0 or extra_segment.mem_size != 0x1000) return error.InvalidCodeAddress;

    var trampoline = ("\x48\xb8" ++ // `mov rax,imm64`
        "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // substitute address
        "\xff\xe0").*; // `jmp rax`
    std.mem.writeInt(usize, trampoline[2..10], substitute_address, .little);
    try common.appendCodePatch(allocator, dyn_object, patches, trampoline_address, &trampoline);

    var call_count: usize = 0;
    for (dyn_object.segments.values()) |segment| {
        if (!segment.flags_first.read or !segment.flags_first.exec or segment.mem_size < 5) continue;

        const code = try CodeView.fromDynObject(dyn_object, segment.mem_offset, segment.mem_size);

        for (0..code.bytes.len - 4) |offset| {
            // Scan for `E8` plus an exact target, then require a recognized use
            // of the returned pointer. This scan does not establish instruction
            // boundaries; reject an unrecognized candidate instead of skipping
            // a potentially real allocator call and producing a partial patch.
            if (code.bytes[offset] != 0xe8) continue;

            const candidate_target = code.relativeTarget(offset + 1) catch continue;
            if (candidate_target != target_virtual_address) continue;
            if (!hasPointerResultUse(code.bytes[offset + 5 ..])) return error.UnrecognizedCallSite;

            // Candidate comparison above used ELF addresses. Replacement bytes
            // are computed from loaded addresses, including the extra page.
            const operand_address = std.math.add(usize, segment.loaded_at, offset + 1) catch return error.InvalidCodeAddress;
            const next_address = std.math.add(usize, operand_address, 4) catch return error.InvalidCodeAddress;
            const distance = @as(i128, trampoline_address) - @as(i128, next_address);
            const displacement = std.math.cast(i32, distance) orelse return error.TrampolineOutOfRange;

            var replacement: [4]u8 = undefined;
            std.mem.writeInt(i32, &replacement, displacement, .little);

            try common.appendCodePatch(allocator, dyn_object, patches, operand_address, &replacement);

            call_count += 1;
        }
    }

    if (call_count == 0) return error.MissingCallSites;
}

// Native thread initialization, publication, and retirement.
// ----------------------------------------------------------

/// Establishes the initial descriptor before libc constructors run. A null TSD
/// pointer preserves musl's lazy main-array setup in `pthread_key_create`; the
/// first-worker transition also installs that array if no key was created yet.
fn initMuslInitialThread(initial_thread: *MuslThreads) void {
    if (initial_thread.initialized) return;

    const layout = initial_thread.layout;
    const tp = currentThreadPointer();

    const links: *MuslThreadLinks = @ptrFromInt(tp + MuslLayout.links_offset);
    links.* = .{ .prev = tp, .next = tp };

    const tsd: *usize = @ptrFromInt(tp + layout.tsd_offset);
    const robust_head: *usize = @ptrFromInt(tp + layout.robust_head_offset);
    const locale: *usize = @ptrFromInt(tp + layout.locale_offset);
    const detach_state: *c_int = @ptrFromInt(tp + layout.detach_state_offset);
    tsd.* = 0;
    robust_head.* = @intFromPtr(robust_head);
    locale.* = layout.mapped_address + layout.page_size_offset + @sizeOf(usize);
    detach_state.* = layout.joinable_state;

    switch (layout.flags) {
        .int_flags => {
            const can_do_threads: *c_int = @ptrFromInt(layout.mapped_address);
            can_do_threads.* = 1;
        },
        .byte_flags => {
            const can_do_threads: *u8 = @ptrFromInt(layout.mapped_address);
            can_do_threads.* = 1;
        },
    }

    initial_thread.initialized = true;
    initial_thread.initial_tp = tp;
}

/// Heap-allocated worker state at a stable address, shared by creator and registry.
/// Owns the worker's pthread-key array. Zig owns the stack and ELF TLS allocation.
const MuslWorker = struct {
    allocator: std.mem.Allocator,
    tsd: []usize,
    ready: u32,

    // Creation may overlap a join initiated by another thread. The creator and
    // registry each own a reference until startup and join respectively finish.
    references: u32,

    /// Returns an unpublished worker owning a zeroed key array. Failed spawn
    /// destroys it directly; successful spawn uses the two-reference protocol.
    fn create(allocator: std.mem.Allocator, slots: usize) !*MuslWorker {
        const worker = try allocator.create(MuslWorker);
        errdefer allocator.destroy(worker);

        const tsd = try allocator.alloc(usize, slots);
        @memset(tsd, 0);

        worker.* = .{
            .allocator = allocator,
            .tsd = tsd,
            .ready = 0,
            .references = 2,
        };
        return worker;
    }

    /// Destroys an unpublished worker, or one whose last reference was released.
    fn destroy(worker: *MuslWorker) void {
        const allocator = worker.allocator;
        allocator.free(worker.tsd);
        allocator.destroy(worker);
    }

    /// Consumes one creator/registry reference; the last release frees storage.
    fn release(worker: *MuslWorker) void {
        if (@atomicRmw(u32, &worker.references, .Sub, 1, .acq_rel) == 1) worker.destroy();
    }

    fn publishReady(worker: *MuslWorker) void {
        // Release/acquire publishes completed registration. The futex only
        // avoids busy waiting; readiness is always decided by the atomic word.
        @atomicStore(u32, &worker.ready, 1, .release);
        _ = std.os.linux.futex_3arg(&worker.ready, .{ .cmd = .WAKE, .private = true }, 1);
    }

    fn waitUntilReady(worker: *MuslWorker) void {
        // A futex wake does not guarantee readiness; recheck the atomic word.
        while (@atomicLoad(u32, &worker.ready, .acquire) == 0) {
            _ = std.os.linux.futex_4arg(&worker.ready, .{ .cmd = .WAIT, .private = true }, 0, null);
        }
    }
};

// Internal signals 32..34 remain deliverable while waiting for the native
// thread-list lock, notably during another thread's `__synccall`.
// `__synccall` holds that lock while signalling registered threads and waiting for
// their handlers. Blocking its signal before taking the lock can deadlock: the
// lock owner waits for our handler while we wait for the owner's lock. Application
// signals are blocked first to prevent reentry from an application handler.
// Native explanation and two-stage signal blocking, lines 52-60:
// https://git.musl-libc.org/cgit/musl/tree/src/thread/synccall.c?h=v1.2.5#n52
const musl_app_signals: std.os.linux.sigset_t = .{0xfffffffc7fffffff};

const musl_cancel_signal_bit: c_ulong = 1 << 32;

const musl_thread_signal_bits: c_ulong = 0x300000000; // `SIGCANCEL` and `SIGSYNCCALL`

fn blockMuslAppSignals() std.os.linux.sigset_t {
    var previous: std.os.linux.sigset_t = undefined;
    const result = std.os.linux.sigprocmask(std.os.linux.SIG.BLOCK, &musl_app_signals, &previous);

    std.debug.assert(std.os.linux.errno(result) == .SUCCESS);
    return previous;
}

/// Negative `FILE.lock` disables locking for single-threaded use. Zero enables
/// the normal unlocked state; preserve a nonnegative value already in use.
fn enableMuslFileLock(file: usize) void {
    if (file == 0) return;

    const lock: *c_int = @ptrFromInt(file + MuslStdio.lock_offset);
    if (lock.* < 0) {
        lock.* = 0;
    }
}

/// Completes the first-thread transition before publishing the worker.
/// Requires the loader's thread registry lock. The caller must preserve changes
/// to the reserved-signal mask.
/// Runs once on the initial thread, replacing `pthread_create`'s `!libc.threaded`
/// setup that Zig spawning bypasses.
/// Native first-thread transition, lines 249-262:
/// https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_create.c?h=v1.2.5#n249
fn prepareMuslThreads(threads: *MuslThreads) void {
    if (threads.threaded) return;
    std.debug.assert(currentThreadPointer() == threads.initial_tp);

    {
        var file = threads.stdio.lockFiles().*;
        defer threads.stdio.unlockFiles();

        while (file != 0) {
            enableMuslFileLock(file);

            const next_file: *const usize = @ptrFromInt(file + MuslStdio.next_offset);
            file = next_file.*;
        }
    }
    for (threads.stdio.standard_files) |slot| enableMuslFileLock(slot.*);

    const internal: std.os.linux.sigset_t = .{musl_thread_signal_bits};
    const result = std.os.linux.sigprocmask(std.os.linux.SIG.UNBLOCK, &internal, null);
    std.debug.assert(std.os.linux.errno(result) == .SUCCESS);

    const tsd: *usize = @ptrFromInt(threads.initial_tp + threads.layout.tsd_offset);
    if (tsd.* == 0) {
        tsd.* = @intFromPtr(threads.main_tsd);
    }
    std.debug.assert(tsd.* == @intFromPtr(threads.main_tsd));

    threads.initMembarrier();

    const threaded_address = threads.layout.mapped_address + threads.layout.threaded_offset;
    switch (threads.layout.flags) {
        .int_flags => @as(*c_int, @ptrFromInt(threaded_address)).* = 1,
        .byte_flags => @as(*u8, @ptrFromInt(threaded_address)).* = 1,
    }
    threads.threaded = true;
}

/// Populates fields that native `pthread_create` normally writes after copying TLS.
/// Requires `self` and kernel TID to be installed by the common write plan.
/// Native worker descriptor initialization, lines 313-329:
/// https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_create.c?h=v1.2.5#n313
/// Upstream descriptor fields, lines 18-60:
/// https://git.musl-libc.org/cgit/musl/tree/src/internal/pthread_impl.h?h=v1.2.5#n18
/// Detach-state values, lines 70-75:
/// https://git.musl-libc.org/cgit/musl/tree/src/internal/pthread_impl.h?h=v1.2.5#n70
fn initMuslWorkerDescriptor(threads: *const MuslThreads, tp: usize, parent_tp: usize, worker: *MuslWorker) void {
    const layout = threads.layout;

    const tsd: *usize = @ptrFromInt(tp + layout.tsd_offset);
    const locale: *usize = @ptrFromInt(tp + layout.locale_offset);
    const robust_head: *usize = @ptrFromInt(tp + layout.robust_head_offset);
    const detach_state: *c_int = @ptrFromInt(tp + layout.detach_state_offset);
    tsd.* = @intFromPtr(worker.tsd.ptr);
    locale.* = layout.mapped_address + layout.page_size_offset + @sizeOf(usize);
    robust_head.* = @intFromPtr(robust_head);
    detach_state.* = layout.joinable_state;

    switch (layout.flags) {
        .int_flags => {},
        .byte_flags => {
            const sysinfo: *usize = @ptrFromInt(tp + MuslLayout.sysinfo_offset);
            const parent_sysinfo: *const usize = @ptrFromInt(parent_tp + MuslLayout.sysinfo_offset);
            sysinfo.* = parent_sysinfo.*;
        },
    }
    const canary: *usize = @ptrFromInt(tp + MuslLayout.canary_offset);
    const parent_canary: *const usize = @ptrFromInt(parent_tp + MuslLayout.canary_offset);
    canary.* = parent_canary.*;

    if (threads.allocator_heap_slot) |slot| {
        // This is native allocator context, not ownership of a new heap. Copy
        // the relocated slot value just as the inspected worker setup does.
        const allocator_heap: *usize = @ptrFromInt(tp + MuslLayout.allocator_heap_offset);
        allocator_heap.* = slot.*;
    }
}

/// Runs in the child, with all signals initially blocked. Publishes a complete
/// descriptor under musl's list lock before allowing application code to run.
fn registerMuslWorker(threads: *MuslThreads, tp: usize, parent_tp: usize, worker: *MuslWorker) void {
    initMuslWorkerDescriptor(threads, tp, parent_tp, worker);

    // The descriptor is now usable by internal signal handlers, but application
    // signals stay blocked until registration and startup publication finish.
    restoreThreadSignals(&musl_app_signals);

    threads.lockList();
    defer threads.unlockList();

    // musl links contain thread pointers, not addresses of the embedded links.
    const links: *MuslThreadLinks = @ptrFromInt(tp + MuslLayout.links_offset);
    const parent_links: *MuslThreadLinks = @ptrFromInt(parent_tp + MuslLayout.links_offset);
    const next_links: *MuslThreadLinks = @ptrFromInt(parent_links.next + MuslLayout.links_offset);
    links.* = .{ .prev = parent_tp, .next = parent_links.next };
    next_links.prev = tp;
    parent_links.next = tp;

    threads.thread_count.* += 1;
    if (threads.need_locks) |flag| {
        flag.* = 1;
    }
}

/// Unlinks the worker after user cleanup, leaving signals blocked for Zig teardown.
/// Does not perform the rest of `pthread_exit`.
/// Native exit-time unlinking and delayed lock release, lines 142-150:
/// https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_create.c?h=v1.2.5#n142
fn unregisterMuslWorker(threads: *MuslThreads, tp: usize) void {
    _ = blockMuslAppSignals();

    threads.lockList();

    // Once we own the lock no concurrent `__synccall` can be waiting for us.
    _ = blockThreadSignals();

    const links: *MuslThreadLinks = @ptrFromInt(tp + MuslLayout.links_offset);
    const prev_links: *MuslThreadLinks = @ptrFromInt(links.prev + MuslLayout.links_offset);
    const next_links: *MuslThreadLinks = @ptrFromInt(links.next + MuslLayout.links_offset);
    next_links.prev = links.prev;
    prev_links.next = links.next;
    links.* = .{ .prev = tp, .next = tp };

    const tid: *c_int = @ptrFromInt(tp + threads.layout.tid_offset);
    tid.* = 0;
    threads.thread_count.* -= 1;

    // Native musl passes `&__thread_list_lock` as `clone`'s clear-child-TID address:
    // the kernel clears it and wakes waiters only when the thread has exited.
    // Zig uses that facility for its own join protocol. Replacing its address
    // with musl's lock would break Zig join, so release the native lock here.
    // Native signal masks and `clone` flags, lines 341-355:
    // https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_create.c?h=v1.2.5#n341
    // From here the worker performs only Zig teardown. Keep `need_locks` enabled
    // even when `threads_minus_1` becomes zero, since kernel exit has not occurred.
    threads.unlockList();
}

/// Supplies process/TLS values normally established by musl's executable startup.
/// The plan borrows host `argv`/`environ` storage. Absolute writes update globals;
/// `self` and TID are TP-relative and are replayed for every worker. The common
/// runtime resolves dynamic values and handles mapping permissions on application.
fn appendWritePlan(runtime: *common.Runtime, musl: MuslLayout) !void {
    const values = runtime.services.runtimeValues();
    const program_name = try runtime.services.lookupRuntimeSymbol("program_invocation_name");
    const environment = try runtime.services.lookupRuntimeSymbol("environ");
    const argv: [*c]const [*c]const u8 = @ptrCast(values.args.vector);

    // Process-global fields use offsets selected by detectMuslLayout for the
    // loaded libc. Field definitions and normal startup assignments (musl 1.2.5):
    // https://git.musl-libc.org/cgit/musl/tree/src/internal/libc.h?h=v1.2.5
    // https://git.musl-libc.org/cgit/musl/tree/src/env/__libc_start_main.c?h=v1.2.5
    // TLS dimensions describe the loader's allocation, not musl's native TLS setup.
    try runtime.write_ops.appendSlice(runtime.allocator, &.{
        // Borrow the host process's original auxiliary vector. musl's getauxval
        // reads HWCAP/HWCAP2 directly from it, but reads AT_SECURE from libc.secure.
        // https://git.musl-libc.org/cgit/musl/tree/src/misc/getauxval.c?h=v1.2.5
        // TODO audit separate auxv-derived startup state, particularly libc.secure
        // and __hwcap; setting libc.auxv alone does not reproduce __init_libc.
        .{
            .addr = musl.mapped_address + musl.auxv_offset, // libc.auxv.
            .relative_to = .zero,
            .value = .auxv,
        },
        .{
            .addr = musl.mapped_address + musl.tls_size_offset, // libc.tls_size.
            .relative_to = .zero,
            .value = .tls_size,
        },
        .{
            .addr = musl.mapped_address + musl.tls_align_offset, // libc.tls_align.
            .relative_to = .zero,
            .value = .tls_align,
        },
        .{
            .addr = musl.mapped_address + musl.page_size_offset, // libc.page_size.
            .relative_to = .zero,
            .value = .page_size,
        },
        .{
            .addr = try program_name.getStaticAddress(), // program_invocation_name / __progname_full.
            .relative_to = .zero,
            .value = .{ .addr = @intFromPtr(argv[0]) },
        },
        .{
            .addr = try environment.getStaticAddress(), // environ / __environ.
            .relative_to = .zero,
            .value = .{ .addr = @intFromPtr(values.environ.block.slice.ptr) },
        },
    });

    // On x86-64, TP points to struct pthread, whose first field is self.
    // The TID offset comes from the selected layout and is cross-checked against
    // pthread_getcpuclockid. The TID write uses c_int, not a pointer-sized value.
    // Descriptor fields and __init_tp's native assignments (musl 1.2.5):
    // https://git.musl-libc.org/cgit/musl/tree/src/internal/pthread_impl.h?h=v1.2.5
    // https://git.musl-libc.org/cgit/musl/tree/src/env/__init_tls.c?h=v1.2.5
    try runtime.write_ops.appendSlice(runtime.allocator, &.{
        .{
            .addr = 0, // struct pthread.self: thread-descriptor pointer.
            .relative_to = .tp,
            .value = .tp,
        },
        .{
            .addr = musl.tid_offset, // struct pthread.tid: kernel TID (int).
            .relative_to = .tp,
            .value = .tid,
        },
    });
}

test "allocator call detection requires matching arguments and a result check" {
    // musl's atfork allocation uses 40 bytes. The call is evidence only when
    // that size reaches EDI and its returned pointer is checked afterward.
    // mov edi, 40
    const argument = "\xbf\x28\x00\x00\x00";
    // call rel32 +0x100 (target is relative to the end of this instruction)
    // test rax, rax
    const checked_call = "\xe8\x00\x01\x00\x00\x48\x85\xc0";
    const probe: CallProbe = .{ .edi_value = 40 };
    try std.testing.expectEqual(@as(usize, 6), try findCheckedCallOperand(CodeView.fromBytes(argument ++ checked_call, 0), probe));

    // Insert mov rdi, rax: it destroys the known size before the call.
    try std.testing.expectError(error.UnrecognizedCheckedCall, findCheckedCallOperand(CodeView.fromBytes(argument ++ "\x48\x89\xc7" ++ checked_call, 0), probe));
    // call rel32 +0x100; ret: no pointer-result check.
    try std.testing.expectError(error.UnrecognizedCheckedCall, findCheckedCallOperand(CodeView.fromBytes(argument ++ "\xe8\x00\x01\x00\x00\xc3", 0), probe));
    try std.testing.expectError(error.UnrecognizedCheckedCall, findCheckedCallOperand(CodeView.fromBytes(argument ++ checked_call, 0), .{ .edi_value = 41 }));
    // Repeating the sequence identifies two different call operands.
    try std.testing.expectError(error.AmbiguousCodePattern, findCheckedCallOperand(CodeView.fromBytes(argument ++ checked_call ++ argument ++ checked_call, 0), probe));
}

test "calloc detection accepts shared anchors and rejects argument clobbers" {
    // musl's atexit allocation uses calloc(520, 1). Both argument-load anchors
    // may identify the same call; this must not be mistaken for ambiguity.
    // mov edi, 520
    // mov esi, 1
    const arguments = "\xbf\x08\x02\x00\x00\xbe\x01\x00\x00\x00";
    // call rel32 +0x100
    // mov rbx, rax
    // mov eax, -1
    // test rbx, rbx
    const checked_call = "\xe8\x00\x01\x00\x00\x48\x89\xc3\xb8\xff\xff\xff\xff\x48\x85\xdb";
    const probe: CallProbe = .{ .edi_value = 520, .esi_value = 1 };
    try std.testing.expectEqual(@as(usize, 11), try findCheckedCallOperand(CodeView.fromBytes(arguments ++ checked_call, 0), probe));

    // Insert mov rsi, rax: the second calloc argument no longer matches.
    try std.testing.expectError(error.UnrecognizedCheckedCall, findCheckedCallOperand(CodeView.fromBytes(arguments ++ "\x48\x89\xc6" ++ checked_call, 0), probe));
    // test rcx, rcx checks the wrong register after saving the result in RBX.
    var wrong = (arguments ++ checked_call).*;
    wrong[wrong.len - 1] = 0xc9;
    try std.testing.expectError(error.UnrecognizedCheckedCall, findCheckedCallOperand(CodeView.fromBytes(&wrong, 0), probe));
}

test "first-thread detection requires TSD, helper, and flag ordering" {
    // This tests musl's transition contract, not generic register propagation:
    // install main TSD, call the membarrier helper, then publish libc.threaded.
    // The counter store and (new layouts only) need_locks = 1 are also required.
    // Initial facts stand for addresses already discovered by the TSD recognizer.
    const allocator = std.testing.allocator;
    var object = DynObject.init(.{ .ino = 1 }, "musl-startup-test", "musl-startup-test");
    defer object.segments.deinit(allocator);

    // ret: a readable executable helper fixture, inspected but never called.
    const helper = "\xc3";
    var segment = std.mem.zeroes(DynObject.LoadSegment);
    segment.mem_offset = 0x2000;
    segment.mem_size = helper.len;
    segment.loaded_at = @intFromPtr(helper.ptr);
    segment.flags_first.read = true;
    segment.flags_first.exec = true;
    try object.segments.put(allocator, 0, segment);

    var main_storage: [1]usize = .{0};
    const tsd: MuslTsdStorage = .{ .main_virtual_address = 0x4000, .main_storage = &main_storage, .slots = 1 };
    inline for (.{ MuslLayout.Flags.int_flags, MuslLayout.Flags.byte_flags }) |flags| {
        const byte_flags = flags == .byte_flags;
        // Only the fields consumed by startup recognition matter in this fixture.
        var layout = std.mem.zeroes(MuslLayout);
        layout.flags = flags;
        layout.threaded_offset = if (byte_flags) 1 else 4;
        layout.thread_count_offset = if (byte_flags) 4 else 12;
        layout.need_locks_offset = if (byte_flags) 3 else null;
        layout.tsd_offset = 128;

        var options: InstructionFlow.Options = .{};
        options.initial_registers[3] = .{ .kind = .thread }; // RBX: current thread.
        options.initial_registers[12] = .{ .kind = .address, .a = 0x3000 }; // R12: __libc.
        options.initial_registers[13] = .{ .kind = .address, .a = @intCast(tsd.main_virtual_address) }; // R13: main TSD.

        // mov [rbx+128], r13
        const store = "\x4c\x89\xab\x80\x00\x00\x00";
        // call 0x2000 (at 0x1007, next instruction at 0x100c)
        const call = "\xe8\xf4\x0f\x00\x00";
        // mov byte ptr [r12+1], 1 or mov dword ptr [r12+4], 1.
        const flag = if (byte_flags) "\x41\xc6\x44\x24\x01\x01" else "\x41\xc7\x44\x24\x04\x01\x00\x00\x00";
        // mov dword ptr [r12+4], 1 or mov dword ptr [r12+12], 1.
        const count = if (byte_flags) "\x41\xc7\x44\x24\x04\x01\x00\x00\x00" else "\x41\xc7\x44\x24\x0c\x01\x00\x00\x00";
        // New layouts: mov byte ptr [r12+3], 1. Old layouts have no need_locks.
        const locks = if (byte_flags) "\x41\xc6\x44\x24\x03\x01" else "";
        // ret terminates the combined transition fixture.
        const bytes = store ++ call ++ flag ++ count ++ locks ++ "\xc3";
        var flow = try InstructionFlow.initWithOptions(allocator, CodeView.fromBytes(bytes, 0x1000), options);
        defer flow.deinit();
        const startup = try detectMuslStartup(&object, flow, layout, 0x3000, tsd);
        try std.testing.expectEqual(@as(usize, 0), startup.main_tsd_store_offset);
        try std.testing.expectEqual(@intFromPtr(helper.ptr), @intFromPtr(startup.initMembarrier));

        // Insert nop between the call and publication: no longer the required
        // immediate helper/flag sequence. The call's target remains unchanged.
        var reordered = try InstructionFlow.initWithOptions(allocator, CodeView.fromBytes(store ++ call ++ "\x90" ++ flag ++ count ++ locks ++ "\xc3", 0x1000), options);
        defer reordered.deinit();
        try std.testing.expectError(error.MuslThreadedTransitionNotFound, detectMuslStartup(&object, reordered, layout, 0x3000, tsd));

        // Change the counter store to mov dword ptr [r12+112], 1.
        var missing_count = bytes.*;
        missing_count[store.len + call.len + flag.len + 4] = 112;
        var wrong_count = try InstructionFlow.initWithOptions(allocator, CodeView.fromBytes(&missing_count, 0x1000), options);
        defer wrong_count.deinit();
        try std.testing.expectError(error.MuslThreadCounterStoreNotFound, detectMuslStartup(&object, wrong_count, layout, 0x3000, tsd));

        // Change libc.threaded's byte/dword immediate from 1 to 0.
        var missing_flag = bytes.*;
        missing_flag[store.len + call.len + 5] = 0;
        var wrong_flag = try InstructionFlow.initWithOptions(allocator, CodeView.fromBytes(&missing_flag, 0x1000), options);
        defer wrong_flag.deinit();
        try std.testing.expectError(error.MuslThreadedTransitionNotFound, detectMuslStartup(&object, wrong_flag, layout, 0x3000, tsd));

        if (byte_flags) {
            // Change mov byte ptr [r12+3], 1 to mov byte ptr [r12+3], 0.
            var missing_locks = bytes.*;
            missing_locks[missing_locks.len - 2] = 0;
            var wrong_locks = try InstructionFlow.initWithOptions(allocator, CodeView.fromBytes(&missing_locks, 0x1000), options);
            defer wrong_locks.deinit();
            try std.testing.expectError(error.MuslThreadCounterStoreNotFound, detectMuslStartup(&object, wrong_locks, layout, 0x3000, tsd));
        }
    }
}
