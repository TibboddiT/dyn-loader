//! Explicit glibc-only cases distinguish relocation-time and lookup-time
//! resolvers. The catalog declares unavailable coverage on musl SDKs.

const std = @import("std");

const dyn_loader = @import("dyn_loader");
const support = @import("behavior_support");

const Execution = enum { relocation, symbol_lookup };

pub fn runEarly(init: std.process.Init, fixtures: support.SpecificContext) !void {
    return exercise(init, fixtures, .relocation);
}

pub fn runLate(init: std.process.Init, fixtures: support.SpecificContext) !void {
    return exercise(init, fixtures, .symbol_lookup);
}

fn exercise(init: std.process.Init, fixtures: support.SpecificContext, execution: Execution) !void {
    try dyn_loader.init(.{
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
    defer dyn_loader.deinit();

    switch (execution) {
        .relocation => {},
        .symbol_lookup => {
            // The bridge also brings in separate libpthread on older glibc.
            _ = try support.Bridge.init(fixtures.bridge_path, fixtures.bridge_symbols);
        },
    }

    const library = try dyn_loader.load(fixtures.target_path);
    const names: struct {
        value: []const u8,
        rejected: []const u8,
    } = switch (execution) {
        .relocation => .{ .value = "earlyResult", .rejected = "earlyReentryRejected" },
        .symbol_lookup => .{ .value = "lateValue", .rejected = "lateReentryRejected" },
    };
    const value: *const fn () callconv(.c) c_int = @ptrFromInt((try library.getSymbol(names.value)).addr);
    const rejected: *const fn () callconv(.c) c_int = @ptrFromInt((try library.getSymbol(names.rejected)).addr);

    try std.testing.expectEqual(@as(c_int, 41), value());
    try std.testing.expectEqual(@as(c_int, 1), rejected());
}
