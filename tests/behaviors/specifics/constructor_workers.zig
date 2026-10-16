const std = @import("std");

const dyn_loader = @import("dyn_loader");
const support = @import("behavior_support");

const control = @import("../control.zig");

const LoadOutcome = enum { success, failure_after_constructor };

pub fn run(init: std.process.Init, fixtures: support.SpecificContext) !void {
    return exercise(init, fixtures, .success);
}

pub fn runFailedLoad(init: std.process.Init, fixtures: support.SpecificContext) !void {
    return exercise(init, fixtures, .failure_after_constructor);
}

fn exercise(init: std.process.Init, fixtures: support.SpecificContext, outcome: LoadOutcome) !void {
    try dyn_loader.init(.{
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
    defer dyn_loader.deinit();

    switch (outcome) {
        .success => _ = try dyn_loader.load(fixtures.target_path),
        .failure_after_constructor => {
            control.failure = .constructor_completed;
            defer control.failure = null;
            control.object_name = "constructor_workers.so";
            defer control.object_name = "";

            try std.testing.expectError(error.InjectedFailure, dyn_loader.load(fixtures.target_path));
        },
    }

    const count: *const fn () callconv(.c) c_uint = @ptrFromInt((try dyn_loader.getSymbol("constructorCount")).addr);
    const observe: *const fn (*c_uint) callconv(.c) void = @ptrFromInt((try dyn_loader.getSymbol("observeFinalization")).addr);
    try std.testing.expectEqual(@as(c_uint, 1), count());

    var finalized: c_uint = 0;
    observe(&finalized);
    dyn_loader.deinit();
    try std.testing.expectEqual(@as(c_uint, 1), finalized);
}
