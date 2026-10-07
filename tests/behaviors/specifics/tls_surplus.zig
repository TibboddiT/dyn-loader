const std = @import("std");

const dll = @import("dll");
const support = @import("behavior_support");

threadlocal var host_value: usize = 17;

fn callback(argument: ?*anyopaque) callconv(.c) *anyopaque {
    if (host_value != 17) @panic("TLS template changed after rejected load");
    host_value = 99;
    return argument.?;
}

pub fn run(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try dll.init(.{
        .allocator = init.gpa,
        .io = init.io,
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
    defer dll.deinit();

    const bridge = try support.Bridge.init(fixtures.bridge_path, fixtures.bridge_symbols);
    host_value = 42;
    for (0..2) |_| {
        try std.testing.expectError(error.TlsSurplusExhausted, dll.load(fixtures.target_path));
        try std.testing.expectEqual(@as(usize, 42), host_value);

        var handle: usize = undefined;
        try std.testing.expectEqual(@as(c_int, 0), bridge.startThread(&handle, &callback, &handle));
        try std.testing.expectEqual(@as(c_int, 0), bridge.joinThread(handle));
        try std.testing.expectEqual(@as(usize, 42), host_value);
    }

    // A failed load must not prevent a later load that fits in the reserved area.
    const resources = std.fs.path.dirname(fixtures.target_path).?;
    const small_path = try std.fs.path.join(init.gpa, &.{ resources, "target.so" });
    defer init.gpa.free(small_path);
    const library = try dll.load(small_path);
    _ = try library.getSymbol("readState");
}
