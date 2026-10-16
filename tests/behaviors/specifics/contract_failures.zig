const std = @import("std");

const dyn_loader = @import("dyn_loader");
const support = @import("behavior_support");

const control = @import("../control.zig");

const Termination = enum { success, panic, trap };
const Scenario = enum {
    before_init,
    after_deinit,
    wrong_thread,
    native_preflight,
    native_committed,
    worker_preflight,
    child_preflight,
    unjoined_worker,
    sleeping_worker,
    running_worker,
    unsupported_process,
    wrong_teardown,
    double_join,

    fn expectedTermination(self: Scenario) Termination {
        return switch (self) {
            .before_init, .after_deinit => .trap,
            .native_committed, .running_worker, .sleeping_worker, .wrong_teardown, .double_join => .panic,
            .wrong_thread, .native_preflight, .worker_preflight, .child_preflight, .unsupported_process, .unjoined_worker => .success,
        };
    }
};

pub fn run(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try initialize(init);
    defer dyn_loader.deinit();

    for (std.enums.values(Scenario)) |scenario| {
        var child = try std.process.spawn(init.io, .{
            .argv = &.{ "/proc/self/exe", "--threads-child", @tagName(scenario), fixtures.bridge_path },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        defer child.kill(init.io);

        const term = try child.wait(init.io);
        switch (scenario.expectedTermination()) {
            .success => switch (term) {
                .exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
                .signal, .stopped, .unknown => return error.UnexpectedChildTermination,
            },
            .panic => switch (term) {
                .signal => |signal| try std.testing.expectEqual(std.posix.SIG.ABRT, signal),
                .exited, .stopped, .unknown => return error.ExpectedChildPanic,
            },
            .trap => switch (term) {
                // Zig's debugging signal handler may convert SIGILL to SIGABRT.
                .signal => |signal| try std.testing.expect(signal == .ILL or signal == .ABRT),
                .exited, .stopped, .unknown => return error.ExpectedChildTrap,
            },
        }
    }

    // An unknown selector must not fall through to a successful ordinary spawn.
    var unknown = try std.process.spawn(init.io, .{
        .argv = &.{ "/proc/self/exe", "--threads-child", "unknown_scenario", fixtures.bridge_path },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer unknown.kill(init.io);

    switch (try unknown.wait(init.io)) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 1), code),
        .signal, .stopped, .unknown => return error.UnexpectedChildTermination,
    }
}

pub fn runChild(init: std.process.Init, mode: []const u8, bridge_path: []const u8) !void {
    const scenario = std.meta.stringToEnum(Scenario, mode) orelse return error.UnknownThreadScenario;
    try std.posix.setrlimit(.CORE, .{ .cur = 0, .max = 0 });

    switch (scenario) {
        .before_init => {
            const thread = try std.Thread.spawn(.{}, emptyWorker, .{});
            thread.join();
            return;
        },
        .after_deinit,
        .wrong_thread,
        .native_preflight,
        .native_committed,
        .worker_preflight,
        .child_preflight,
        .unjoined_worker,
        .sleeping_worker,
        .running_worker,
        .unsupported_process,
        .wrong_teardown,
        .double_join,
        => {},
    }

    try initialize(init);
    defer dyn_loader.deinit();

    switch (scenario) {
        .before_init => unreachable, // Dispatched before initialization above.
        .after_deinit => {
            dyn_loader.deinit();
            const thread = try std.Thread.spawn(.{}, emptyWorker, .{});
            thread.join();
        },
        .wrong_thread => {
            const thread = try std.Thread.spawn(.{}, wrongThread, .{init});
            thread.join();
        },
        .wrong_teardown => {
            const thread = try std.Thread.spawn(.{}, dyn_loader.deinit, .{});
            thread.join();
        },
        .native_preflight => {
            {
                control.failure = .native_preflight;
                defer control.failure = null;
                try std.testing.expectError(error.InjectedFailure, dyn_loader.load(bridge_path));
            }

            _ = try dyn_loader.load(bridge_path);
            const thread = try dyn_loader.spawn(.{}, emptyWorker, .{});
            thread.join();
        },
        .native_committed => {
            control.failure = .native_committed;
            defer control.failure = null;
            _ = try dyn_loader.load(bridge_path);
        },
        .worker_preflight => try checkCreationRollback(bridge_path, .worker_preflight),
        .child_preflight => try checkCreationRollback(bridge_path, .child_preflight),
        .unjoined_worker => {
            _ = try dyn_loader.load(bridge_path);
            _ = try dyn_loader.spawn(.{}, teardownWorker, .{scenario});
            const tid = waitWorkerTid();
            while (std.os.linux.errno(std.os.linux.syscall3(.tgkill, @intCast(std.os.linux.getpid()), @intCast(tid), 0)) != .SRCH)
                std.atomic.spinLoopHint();
        },
        .sleeping_worker, .running_worker => {
            _ = try dyn_loader.load(bridge_path);
            _ = try dyn_loader.spawn(.{}, teardownWorker, .{scenario});
            const tid = waitWorkerTid();
            if (scenario == .sleeping_worker) try waitSleeping(tid);
            dyn_loader.deinit();
            // Reaching here means teardown incorrectly accepted a live worker.
            std.os.linux.exit_group(0);
        },
        .double_join => {
            _ = try dyn_loader.load(bridge_path);
            const thread = try dyn_loader.spawn(.{}, emptyWorker, .{});
            thread.join();
            thread.join();
        },
        .unsupported_process => {
            _ = try dyn_loader.load(bridge_path);
            const vfork: *const fn () callconv(.c) c_int = @ptrFromInt((try dyn_loader.getSymbol("vfork")).addr);
            const setuid: *const fn (uid: c_uint) callconv(.c) c_int = @ptrFromInt((try dyn_loader.getSymbol("setuid")).addr);
            const errno_location: *const fn () callconv(.c) *c_int = @ptrFromInt((try dyn_loader.getSymbol("__errno_location")).addr);

            try std.testing.expectEqual(@as(c_int, -1), vfork());
            try std.testing.expectEqual(@as(c_int, @backingInt(std.os.linux.E.NOSYS)), errno_location().*);
            try std.testing.expectEqual(@as(c_int, -1), setuid(@intCast(std.os.linux.syscall0(.getuid))));
            try std.testing.expectEqual(@as(c_int, @backingInt(std.os.linux.E.NOSYS)), errno_location().*);
        },
    }
}

fn checkCreationRollback(bridge_path: []const u8, failure: control.Failure) !void {
    _ = try dyn_loader.load(bridge_path);
    {
        control.failure = failure;
        defer control.failure = null;
        for (0..16) |_| {
            try std.testing.expectError(error.InjectedFailure, dyn_loader.spawn(.{}, emptyWorker, .{}));
        }
    }

    const thread = try dyn_loader.spawn(.{}, emptyWorker, .{});
    thread.join();
}

fn initialize(init: std.process.Init) !void {
    try dyn_loader.init(.{
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
}

fn wrongThread(init: std.process.Init) void {
    std.testing.expectError(error.InitialThreadRequired, initialize(init)) catch @panic("wrong-thread init was accepted");
}

fn emptyWorker() void {}

var worker_tid: std.atomic.Value(std.os.linux.pid_t) = .init(0);
var sleep_word: u32 = 0;

fn waitWorkerTid() std.os.linux.pid_t {
    while (true) {
        const tid = worker_tid.load(.acquire);
        if (tid != 0) return tid;
        std.atomic.spinLoopHint();
    }
}

fn teardownWorker(scenario: Scenario) void {
    worker_tid.store(std.os.linux.gettid(), .release);
    if (scenario == .unjoined_worker) return;
    while (true) {
        if (scenario == .sleeping_worker) {
            _ = std.os.linux.syscall6(.futex, @intFromPtr(&sleep_word), 128, 0, 0, 0, 0);
        } else std.atomic.spinLoopHint();
    }
}

fn waitSleeping(tid: std.os.linux.pid_t) !void {
    const linux = std.os.linux;
    var path_buffer: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "/proc/self/task/{d}/stat\x00", .{tid});
    while (true) {
        const fd = linux.openat(linux.AT.FDCWD, @ptrCast(path.ptr), .{ .CLOEXEC = true }, 0);
        if (linux.errno(fd) != .SUCCESS) return error.WorkerObservationFailed;
        var buffer: [4096]u8 = undefined;
        const count = linux.read(@intCast(fd), &buffer, buffer.len);
        _ = linux.close(@intCast(fd));
        if (linux.errno(count) != .SUCCESS) return error.WorkerObservationFailed;
        const end = std.mem.lastIndexOfScalar(u8, buffer[0..count], ')') orelse return error.WorkerObservationFailed;
        if (count > end + 2 and buffer[end + 2] == 'S') return;
        std.atomic.spinLoopHint();
    }
}
