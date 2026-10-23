//! Exercises nested native loading and closing before the outer load returns.

const std = @import("std");

const dyn_loader = @import("dyn_loader");
const support = @import("behavior_support");

pub fn run(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try dyn_loader.init(.{
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
    defer dyn_loader.deinit();

    const library = try dyn_loader.load(fixtures.target_path);
    const count: *const c_uint = @ptrFromInt((try library.getSymbol("constructor_count")).addr);
    const status: *const c_int = @ptrFromInt((try library.getSymbol("constructor_status")).addr);
    const value: *const c_uint = @ptrFromInt((try library.getSymbol("nested_value")).addr);

    try std.testing.expectEqual(@as(c_uint, 1), count.*);
    try std.testing.expectEqual(@as(c_int, 0), status.*);
    try std.testing.expectEqual(@as(c_uint, 19), value.*);
}
