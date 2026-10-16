//! Mixed host/native workers exercise the public wrapper and publication order.
//! The matrix owns the subprocess deadline; barriers do not rely on sleeps.

const std = @import("std");

const dyn_loader = @import("dyn_loader");
const support = @import("behavior_support");
const LibraryState = @import("regression_abi").LibraryState;

const control = @import("../control.zig");

const ReadState = *const fn (state: *LibraryState) callconv(.c) void;
const SetTls = *const fn (value: u32) callconv(.c) void;
const WorkerCommand = enum(u8) { wait, run, stop };
const WorkerFailure = enum { partial_spawn, before_callbacks };
const SignalFailure = enum { handler_installed, receiver_spawned, receiver_ready };

threadlocal var executable_value: usize = 37;

const Context = struct {
    stop_host: std.atomic.Value(bool) = .init(false),
    host_ready: std.atomic.Value(bool) = .init(false),
    host_cycles: std.atomic.Value(usize) = .init(0),
    managed_ready: std.atomic.Value(usize) = .init(0),
    command: std.atomic.Value(WorkerCommand) = .init(.wait),
    path: []const u8,
    read: ReadState = undefined,
    set: SetTls = undefined,
};

pub fn run(init: std.process.Init, fixtures: support.SpecificContext) !void {
    const signal_mask: std.os.linux.sigset_t = .{1 << (@backingInt(std.os.linux.SIG.USR1) - 1)};
    var previous_mask: std.os.linux.sigset_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.sigprocmask(std.os.linux.SIG.BLOCK, &signal_mask, &previous_mask));
    defer _ = std.os.linux.sigprocmask(std.os.linux.SIG.SETMASK, &previous_mask, null);

    executable_value = 91;
    try std.testing.expectError(error.Overflow, dyn_loader.init(.{
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .tls_surplus_size = std.math.maxInt(usize),
    }));

    try dyn_loader.init(.{
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
    defer dyn_loader.deinit();

    try std.testing.expectEqual(@as(usize, 91), executable_value);
    try std.testing.expectError(error.NativeThreadingUnavailable, dyn_loader.spawn(.{}, emptyWorker, .{}));

    var context: Context = .{ .path = fixtures.target_path };
    const host = try std.Thread.spawn(.{}, hostWorker, .{&context});
    defer {
        context.stop_host.store(true, .release);
        host.join();
    }

    while (!context.host_ready.load(.acquire)) std.atomic.spinLoopHint();

    // In particular, musl performs its first transition while host-only threads
    // already exist and create more threads, without ever entering native code.
    _ = try support.Bridge.init(fixtures.bridge_path, fixtures.bridge_symbols);
    const bridge_library = try dyn_loader.load(fixtures.bridge_path);
    const attributes: *const fn () callconv(.c) c_int = @ptrFromInt((try bridge_library.getSymbol("threadAttributesProbe")).addr);
    try std.testing.expectEqual(@as(c_int, 0), attributes());
    const signal_restored: *const fn () callconv(.c) c_int = @ptrFromInt((try bridge_library.getSymbol("signalProbeRestored")).addr);

    for (std.enums.values(SignalFailure)) |failure| {
        try std.testing.expectError(error.InjectedSignalFailure, exerciseSignal(bridge_library, failure));
        try std.testing.expectEqual(@as(c_int, 1), signal_restored());
    }
    try exerciseSignal(bridge_library, null);
    try std.testing.expectEqual(@as(c_int, 1), signal_restored());

    try std.testing.expectError(error.InjectedFailure, exerciseWorkers(&context, .partial_spawn));
    try std.testing.expectError(error.InjectedWorkerSetup, exerciseWorkers(&context, .before_callbacks));
    try exerciseWorkers(&context, null);
    try std.testing.expectEqual(@as(usize, 91), executable_value);
    try std.testing.expect(context.host_cycles.load(.acquire) != 0);
}

fn exerciseSignal(bridge_library: dyn_loader.DynamicLibrary, fail_after: ?SignalFailure) !void {
    const install_signal: *const fn () callconv(.c) c_int = @ptrFromInt((try bridge_library.getSymbol("installSignalProbe")).addr);
    const signal_worker: *const fn () callconv(.c) void = @ptrFromInt((try bridge_library.getSymbol("signalWorkerProbe")).addr);
    const signal_phase: *const fn () callconv(.c) c_int = @ptrFromInt((try bridge_library.getSymbol("signalPhaseProbe")).addr);
    const deliver_signal: *const fn () callconv(.c) c_int = @ptrFromInt((try bridge_library.getSymbol("deliverSignalProbe")).addr);
    const restore_signal: *const fn () callconv(.c) c_int = @ptrFromInt((try bridge_library.getSymbol("restoreSignalProbe")).addr);
    const stop_signal: *const fn () callconv(.c) void = @ptrFromInt((try bridge_library.getSymbol("stopSignalProbe")).addr);

    var receiver: ?dyn_loader.Thread = null;
    try std.testing.expectEqual(@as(c_int, 0), install_signal());
    defer {
        if (receiver) |thread| {
            stop_signal();
            thread.join();
        }

        // A failed restoration cannot safely release the handler's library.
        if (restore_signal() != 0) @panic("unable to restore the signal probe disposition");
    }

    if (fail_after == .handler_installed) return error.InjectedSignalFailure;
    receiver = try dyn_loader.spawn(.{}, receiveSignal, .{signal_worker});
    if (fail_after == .receiver_spawned) return error.InjectedSignalFailure;

    while (signal_phase() == 0) std.atomic.spinLoopHint();
    try std.testing.expectEqual(@as(c_int, 1), signal_phase());
    if (fail_after == .receiver_ready) return error.InjectedSignalFailure;

    try std.testing.expectEqual(@as(c_int, 0), deliver_signal());
    receiver.?.join();
    receiver = null;
    try std.testing.expectEqual(@as(c_int, 2), signal_phase());
}

fn exerciseWorkers(context: *Context, failure: ?WorkerFailure) !void {
    context.managed_ready.store(0, .monotonic);
    context.command.store(.wait, .release);

    var workers: [4]dyn_loader.Thread = undefined;
    var created_count: usize = 0;
    defer {
        // Stop does not access callbacks, which may not have been installed yet.
        context.command.store(.stop, .release);
        for (workers[0..created_count]) |worker| worker.join();
    }

    for (&workers, 0..) |*worker, index| {
        const previous_failure = control.failure;
        defer control.failure = previous_failure;
        if (failure == .partial_spawn and index == 2) control.failure = .worker_preflight;

        worker.* = try dyn_loader.spawn(.{}, managedWorker, .{context});
        created_count += 1;
    }
    while (context.managed_ready.load(.acquire) != workers.len) std.atomic.spinLoopHint();
    if (failure == .before_callbacks) return error.InjectedWorkerSetup;

    const library = try dyn_loader.load(context.path);
    context.read = @ptrFromInt((try library.getSymbol("readState")).addr);
    context.set = @ptrFromInt((try library.getSymbol("setTls")).addr);
    context.set(55);
    context.command.store(.run, .release);

    for (workers) |worker| worker.join();
    created_count = 0;

    var observed: LibraryState = undefined;
    context.read(&observed);
    try std.testing.expectEqual(@as(u32, 55), observed.tls_value);
}

fn emptyWorker() void {}

fn receiveSignal(function: *const fn () callconv(.c) void) void {
    function();
}

fn freshHostWorker() void {
    if (executable_value != 37) @panic("host worker inherited live TLS");
    executable_value = 123;
}

fn hostWorker(context: *Context) void {
    if (executable_value != 37) @panic("host executable initializer changed");
    if (dyn_loader.getSymbol("readState")) |_| {
        @panic("unregistered symbol lookup succeeded");
    } else |err| {
        if (err != error.UnregisteredThread) @panic("wrong host-only rejection");
    }

    const first = std.Thread.spawn(.{}, freshHostWorker, .{}) catch @panic("host spawn failed");
    first.join();
    _ = context.host_cycles.fetchAdd(1, .release);
    context.host_ready.store(true, .release);

    while (!context.stop_host.load(.acquire)) {
        const child = std.Thread.spawn(.{}, freshHostWorker, .{}) catch @panic("concurrent host spawn failed");
        child.join();
        _ = context.host_cycles.fetchAdd(1, .release);
    }
}

fn managedWorker(context: *Context) void {
    if (executable_value != 37) @panic("managed executable initializer changed");
    _ = context.managed_ready.fetchAdd(1, .release);
    while (true) {
        switch (context.command.load(.acquire)) {
            .wait => std.atomic.spinLoopHint(),
            .run => break,
            .stop => return,
        }
    }

    var observed: LibraryState = undefined;
    context.read(&observed);
    if (observed.tls_value != 11) @panic("live participant missed module publication");
    context.set(77);

    // These calls contend across workers and recursively create a managed child.
    const library = dyn_loader.load(context.path) catch @panic("managed load failed");
    _ = library.getSymbol("readState") catch @panic("managed lookup failed");
    const child = dyn_loader.spawn(.{}, nestedWorker, .{context}) catch @panic("nested managed spawn failed");
    child.join();

    context.read(&observed);
    if (observed.tls_value != 77) @panic("later loading reset live TLS");
}

fn nestedWorker(context: *Context) void {
    var observed: LibraryState = undefined;
    context.read(&observed);
    if (observed.tls_value != 11 or executable_value != 37) @panic("nested worker inherited live values");
}
