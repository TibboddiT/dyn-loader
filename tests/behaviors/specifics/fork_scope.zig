//! Fork copies a deliberately held lifecycle lock. Child admission must reject
//! unsupported operations without touching that lock or using panic/logging.
//! The matrix's bounded subprocess deadline catches any inherited-lock deadlock.

const std = @import("std");
const linux = std.os.linux;

const dyn_loader = @import("dyn_loader");
const support = @import("behavior_support");

var armed: std.atomic.Value(bool) = .init(false);
var locked: std.atomic.Value(bool) = .init(false);
var released: std.atomic.Value(bool) = .init(false);

const Operation = enum { entry_checks, teardown, zig_spawn, join };
const Fork = *const fn () callconv(.c) c_int;

const ForkReturn = struct {
    fork: Fork,
    child: linux.pid_t = -1,

    fn run(self: *ForkReturn) void {
        const child = self.fork();
        if (child == 0) return;
        self.child = child;
    }
};

const Lookup = struct {
    begin: std.atomic.Value(bool) = .init(false),
    failure: ?anyerror = null,

    fn run(self: *Lookup) void {
        while (!self.begin.load(.acquire)) std.atomic.spinLoopHint();

        _ = dyn_loader.getSymbol("malloc") catch |err| {
            self.failure = err;
            return;
        };
    }
};

pub fn pauseAtMembershipLock() void {
    if (!armed.load(.acquire)) return;

    locked.store(true, .release);
    while (!released.load(.acquire)) std.atomic.spinLoopHint();
}

pub fn run(init: std.process.Init, fixtures: support.SpecificContext) !void {
    const options: dyn_loader.InitOptions = .{
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    };
    try dyn_loader.init(options);
    defer dyn_loader.deinit();

    var stop_host: std.atomic.Value(bool) = .init(false);
    const host = try std.Thread.spawn(.{}, hostWorker, .{&stop_host});
    defer {
        stop_host.store(true, .release);
        host.join();
    }

    const bridge = try dyn_loader.load(fixtures.bridge_path);
    const fork: Fork = @ptrFromInt((try bridge.getSymbol("fork")).addr);
    const dlopen: *const fn (?[*:0]const u8, c_int) callconv(.c) ?*anyopaque = @ptrFromInt((try bridge.getSymbol("dlopen")).addr);
    const dlerror: *const fn () callconv(.c) ?[*:0]const u8 = @ptrFromInt((try bridge.getSymbol("dlerror")).addr);

    for (std.enums.values(Operation)) |operation| {
        var lookup: Lookup = .{};
        const worker = try dyn_loader.spawn(.{}, Lookup.run, .{&lookup});
        locked.store(false, .monotonic);
        released.store(false, .monotonic);
        armed.store(true, .release);
        lookup.begin.store(true, .release);
        while (!locked.load(.acquire)) std.atomic.spinLoopHint();

        const child = fork();
        if (child == 0) {
            switch (operation) {
                .entry_checks => {
                    const rejected = rejects(dyn_loader.init(options)) and
                        rejects(dyn_loader.load(fixtures.target_path)) and
                        rejects(dyn_loader.resolve(init.gpa, "libc.so")) and
                        rejects(dyn_loader.getSymbol("malloc")) and
                        rejects(bridge.getSymbol("malloc")) and
                        rejects(dyn_loader.spawn(.{}, emptyWorker, .{})) and
                        dlopen(null, 2) == null;
                    if (!rejected) linux.exit_group(1);

                    const diagnostic = dlerror() orelse linux.exit_group(2);
                    if (std.mem.indexOf(u8, std.mem.span(diagnostic), "ForkChildUnsupported") == null) linux.exit_group(3);
                    if (dlerror() != null) linux.exit_group(4);
                    linux.exit_group(0);
                },
                .teardown => dyn_loader.deinit(),
                .zig_spawn => {
                    const thread = std.Thread.spawn(.{}, emptyWorker, .{}) catch linux.exit_group(2);
                    thread.join();
                },
                .join => worker.join(),
            }
            linux.exit_group(3);
        }

        // Release and join even if fork failed. The child's lock copy remains
        // locked regardless of these parent-side writes.
        released.store(true, .release);
        worker.join();
        armed.store(false, .release);
        if (lookup.failure) |err| return err;
        try std.testing.expect(child > 0);

        const status = try waitForChild(child);
        switch (operation) {
            .entry_checks => {
                try std.testing.expect(linux.W.IFEXITED(status));
                try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
            },
            .teardown, .zig_spawn, .join => {
                try std.testing.expect(linux.W.IFEXITED(status));
                try std.testing.expectEqual(@as(u8, 127), linux.W.EXITSTATUS(status));
            },
        }

        // Fork must not poison the parent's loader membership or lifecycle.
        const target = try dyn_loader.load(fixtures.target_path);
        _ = try target.getSymbol("readState");
        const next = try dyn_loader.spawn(.{}, emptyWorker, .{});
        next.join();
    }

    // A worker's child must use _exit rather than returning into the parent's
    // managed cleanup protocol. No inherited record may be reaped in the child.
    var returning: ForkReturn = .{ .fork = fork };
    const worker = try dyn_loader.spawn(.{}, ForkReturn.run, .{&returning});
    worker.join();
    try std.testing.expect(returning.child > 0);
    const status = try waitForChild(returning.child);
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 127), linux.W.EXITSTATUS(status));
}

fn rejects(result: anytype) bool {
    if (result) |_| {
        return false;
    } else |err| {
        return err == error.ForkChildUnsupported;
    }
}

fn waitForChild(child: linux.pid_t) !u32 {
    var status: i32 = 0;
    while (true) {
        const result = linux.waitpid(child, &status, 0);
        switch (linux.errno(result)) {
            .SUCCESS => return @bitCast(status),
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
}

fn emptyWorker() void {}

fn hostWorker(stop: *std.atomic.Value(bool)) void {
    while (!stop.load(.acquire)) {
        _ = linux.syscall0(.sched_yield);
    }
}
