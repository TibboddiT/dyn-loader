const std = @import("std");
const loader = @import("dyn_loader");
const support = @import("behavior_support");

const Probe = *const fn () callconv(.c) c_int;
const Address = *const fn () callconv(.c) *c_int;
const Observe = *const fn (*c_int) callconv(.c) void;

pub fn runIdentity(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try loader.init(.{ .args = init.minimal.args, .environ = init.minimal.environ, .log_level = .none });
    defer loader.deinit();
    const bridge = try support.Bridge.init(fixtures.bridge_path, fixtures.bridge_symbols);
    const directory = std.fs.path.dirname(fixtures.target_path).?;
    const broken_path = try std.fmt.allocPrint(init.gpa, "{s}/unique_broken.so", .{directory});
    defer init.gpa.free(broken_path);
    try std.testing.expectError(error.UnresolvedSymbol, loader.load(broken_path));

    const first = try bridge.open(fixtures.target_path);
    const address = try bridge.symbol(Address, first, "uniqueAddress");
    const value = address();
    try std.testing.expectEqual(@as(c_int, 17), value.*);
    value.* = 42;
    try std.testing.expectEqual(value, try bridge.symbol(*c_int, first, "uniqueValue"));
    const observe_first = try bridge.symbol(Observe, first, "uniqueObserve");
    var first_finalizations: c_int = 0;
    observe_first(&first_finalizations);
    try bridge.close(first);
    try std.testing.expectEqual(@as(c_int, 0), first_finalizations);

    const second_path = try std.fmt.allocPrintSentinel(init.gpa, "{s}/unique_b.so", .{directory}, 0);
    defer init.gpa.free(second_path);
    const second = try bridge.open(second_path);
    const second_address = try bridge.symbol(Address, second, "uniqueAddress");
    try std.testing.expectEqual(@intFromPtr(value), @intFromPtr(second_address()));
    try std.testing.expectEqual(value, try bridge.symbol(*c_int, second, "uniqueValue"));
    const observe_second = try bridge.symbol(Observe, second, "uniqueObserve");
    var second_finalizations: c_int = 0;
    observe_second(&second_finalizations);
    try bridge.close(second);
    try std.testing.expectEqual(@as(c_int, 1), second_finalizations);

    const reopened = try bridge.open(fixtures.target_path);
    const constructors = try bridge.symbol(Probe, reopened, "uniqueConstructors");
    try std.testing.expectEqual(@as(c_int, 1), constructors());
    try bridge.close(reopened);
    loader.deinit();
    try std.testing.expectEqual(@as(c_int, 42), value.*);
    try std.testing.expectEqual(@as(c_int, 0), first_finalizations);
}

pub fn runLookup(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try loader.init(.{ .args = init.minimal.args, .environ = init.minimal.environ, .log_level = .none });
    defer loader.deinit();
    const bridge = try support.Bridge.init(fixtures.bridge_path, fixtures.bridge_symbols);
    // Merely mapping a unique definition must not pin its library.
    const unused = try bridge.open(fixtures.target_path);
    const observe = try bridge.symbol(Observe, unused, "uniqueObserve");
    var finalizations: c_int = 0;
    observe(&finalizations);
    try bridge.close(unused);
    try std.testing.expectEqual(@as(c_int, 1), finalizations);

    const selected = try bridge.open(fixtures.target_path);
    const selected_observe = try bridge.symbol(Observe, selected, "uniqueObserve");
    selected_observe(&finalizations);
    const value = try bridge.symbol(*c_int, selected, "uniqueValue");
    value.* = 31;
    try bridge.close(selected);
    loader.deinit();
    try std.testing.expectEqual(@as(c_int, 1), finalizations);
    try std.testing.expectEqual(@as(c_int, 31), value.*);
}

pub fn runRetention(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try loader.init(.{ .args = init.minimal.args, .environ = init.minimal.environ, .log_level = .none });
    defer loader.deinit();
    const bridge = try support.Bridge.init(fixtures.bridge_path, fixtures.bridge_symbols);
    const library = try bridge.open(fixtures.target_path);
    const check = try bridge.symbol(Probe, library, "retentionCheck");
    const start = try bridge.symbol(Probe, library, "retentionStart");
    const stop = try bridge.symbol(Probe, library, "retentionStop");
    const observe = try bridge.symbol(Observe, library, "retentionObserve");
    var finalizations: c_int = 0;
    observe(&finalizations);
    // Weak default-visible definition is preempted; protected definition stays local.
    try std.testing.expectEqual(@as(c_int, 19 + 11 + 5), check());
    try std.testing.expectEqual(@as(c_int, 0), start());
    try bridge.close(library);
    loader.deinit();
    try std.testing.expectEqual(@as(c_int, 0), finalizations);
    try std.testing.expectEqual(@as(c_int, 35), check());
    try std.testing.expectEqual(@as(c_int, 0), stop());
}
