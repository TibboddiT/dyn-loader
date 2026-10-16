//! Public TLS lookup must agree with compiler-generated access in each thread.

const std = @import("std");

const dyn_loader = @import("dyn_loader");
const support = @import("behavior_support");

const Lookup = union(enum) {
    unversioned,
    versioned: *const fn (handle: ?*anyopaque, name: [*:0]const u8, version: [*:0]const u8) callconv(.c) ?*anyopaque,
};

const Context = struct {
    library: dyn_loader.DynamicLibrary,
    bridge: support.Bridge,
    handle: *anyopaque,
    lookup: Lookup,
    main_address: ?usize,
};

pub fn run(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try runLookup(init, fixtures, .unversioned);
}

pub fn runVersioned(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try runLookup(init, fixtures, .versioned);
}

fn runLookup(init: std.process.Init, fixtures: support.SpecificContext, mode: std.meta.Tag(Lookup)) !void {
    try dyn_loader.init(.{
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
    defer dyn_loader.deinit();

    const bridge = try support.Bridge.init(fixtures.bridge_path, fixtures.bridge_symbols);
    const library = try dyn_loader.load(fixtures.target_path);
    const handle = try bridge.open(fixtures.target_path);
    defer bridge.close(handle) catch @panic("close failed");

    const lookup: Lookup = switch (mode) {
        .unversioned => .unversioned,
        .versioned => .{ .versioned = @ptrFromInt((try dyn_loader.getSymbol("dlvsym")).addr) },
    };

    var context: Context = .{
        .library = library,
        .bridge = bridge,
        .handle = handle,
        .lookup = lookup,
        .main_address = null,
    };

    try checkThreadLocalLookup(&context, 55);
    context.main_address = (try context.library.getSymbol("tls_value")).addr;

    var thread: usize = undefined;
    try std.testing.expectEqual(@as(c_int, 0), bridge.startThread(&thread, &worker, &context));
    try std.testing.expectEqual(@as(c_int, 0), bridge.joinThread(thread));

    const value: *u32 = @ptrFromInt(context.main_address.?);
    try std.testing.expectEqual(@as(u32, 55), value.*);
    const tail: *u8 = @ptrFromInt((try context.library.getSymbol("tls_tail")).addr);
    try std.testing.expectEqual(@as(u8, 55), tail.*);
}

fn checkThreadLocalLookup(context: *const Context, mutation: u8) !void {
    const getValueAddress: *const fn () callconv(.c) *u32 = @ptrFromInt((try context.library.getSymbol("tlsValueAddress")).addr);
    const getTailAddress: *const fn () callconv(.c) *u8 = @ptrFromInt((try context.library.getSymbol("tlsTailAddress")).addr);
    const getAliasAddress: *const fn () callconv(.c) *u8 = @ptrFromInt((try context.library.getSymbol("tlsTailAliasAddress")).addr);

    const value: *u32 = @ptrFromInt((try context.library.getSymbol("tls_value")).addr);
    const tail: *u8 = @ptrFromInt((try context.library.getSymbol("tls_tail")).addr);
    try std.testing.expectEqual(@intFromPtr(getValueAddress()), @intFromPtr(value));
    try std.testing.expectEqual(@intFromPtr(getTailAddress()), @intFromPtr(tail));
    try std.testing.expectEqual(@intFromPtr(getAliasAddress()), @intFromPtr(tail));

    try std.testing.expectEqual(@intFromPtr(value), (try dyn_loader.getSymbol("tls_value")).addr);
    try std.testing.expectEqual(@intFromPtr(tail), (try dyn_loader.getSymbol("tls_tail")).addr);
    try std.testing.expectEqual(@intFromPtr(value), @intFromPtr(try context.bridge.symbol(*anyopaque, context.handle, "tls_value")));
    try std.testing.expectEqual(@intFromPtr(tail), @intFromPtr(try context.bridge.symbol(*u8, context.handle, "tls_tail")));

    switch (context.lookup) {
        .unversioned => {},
        .versioned => |dlvsym| {
            try std.testing.expectEqual(@intFromPtr(value), @intFromPtr(dlvsym(context.handle, "tls_value", "TLS_TEST_1")));
            try std.testing.expectEqual(@intFromPtr(tail), @intFromPtr(dlvsym(context.handle, "tls_tail", "TLS_TEST_1")));
        },
    }

    if (context.main_address) |main_address| try std.testing.expect(@intFromPtr(value) != main_address);
    try std.testing.expectEqual(@as(u32, 11), value.*);
    try std.testing.expectEqual(@as(u8, 0), tail.*);

    value.* = mutation;
    tail.* = mutation;

    try std.testing.expectEqual(@as(u32, mutation), getValueAddress().*);
    try std.testing.expectEqual(mutation, getTailAddress().*);
}

fn worker(argument: ?*anyopaque) callconv(.c) *anyopaque {
    const context: *const Context = @ptrCast(@alignCast(argument.?));
    checkThreadLocalLookup(context, 77) catch @panic("thread-local symbol lookup failed");

    return argument.?;
}
