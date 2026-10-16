const std = @import("std");
const dyn_loader = @import("dyn_loader");
const support = @import("behavior_support");
const FinalizationEvents = @import("regression_abi").FinalizationEvents;

const Mode = enum { elf, flag, promotion };
const Probe = *const fn () callconv(.c) c_int;

pub fn runElf(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try run(init, fixtures, .elf);
}
pub fn runFlag(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try run(init, fixtures, .flag);
}
pub fn runPromotion(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try run(init, fixtures, .promotion);
}

fn run(init: std.process.Init, fixtures: support.SpecificContext, mode: Mode) !void {
    const options: dyn_loader.InitOptions = .{
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    };
    try dyn_loader.init(options);
    defer dyn_loader.deinit();
    const bridge = try support.Bridge.init(fixtures.bridge_path, fixtures.bridge_symbols);
    const bridge_library = try dyn_loader.load(fixtures.bridge_path);
    const open_flags: *const fn ([*:0]const u8, c_int) callconv(.c) ?*anyopaque = @ptrFromInt((try bridge_library.getSymbol("openFlagsProbe")).addr);
    const bridge_path = try init.gpa.dupeSentinel(u8, fixtures.bridge_path, 0);
    defer init.gpa.free(bridge_path);
    // This native handle must survive release of the host's bridge references.
    const bridge_handle = try bridge.open(bridge_path);

    const directory = std.fs.path.dirname(fixtures.target_path).?;
    const broken_path = try std.fmt.allocPrintSentinel(init.gpa, "{s}/nodelete_broken.so", .{directory}, 0);
    defer init.gpa.free(broken_path);
    try std.testing.expect(open_flags(broken_path, 2 | 0x1000) == null);
    try std.testing.expect(open_flags(broken_path, 2 | 4) == null);

    try std.testing.expect(open_flags(fixtures.target_path, 2 | 4) == null);
    const handle = open_flags(fixtures.target_path, 2 | @as(c_int, if (mode == .flag) 0x1000 else 0)) orelse return error.OpenFailed;
    const observe = try bridge.symbol(*const fn (*c_int, *c_int) callconv(.c) void, handle, "nodeleteObserve");
    const check = try bridge.symbol(Probe, handle, "nodeleteCheck");
    const start = try bridge.symbol(Probe, handle, "nodeleteStart");
    const finish = try bridge.symbol(Probe, handle, "nodeleteFinish");
    const hold = try bridge.symbol(*const fn ([*:0]const u8) callconv(.c) c_int, handle, "nodeleteHold");
    const release = try bridge.symbol(Probe, handle, "nodeleteRelease");
    const close = try bridge.symbol(*const fn (*anyopaque) callconv(.c) c_int, handle, "nodeleteClose");
    var own_finalizations: c_int = 0;
    var dependency_finalizations: c_int = 0;
    observe(&own_finalizations, &dependency_finalizations);
    if (mode == .promotion) {
        const promoted = open_flags(fixtures.target_path, 2 | 4 | 0x1000) orelse return error.PromotionFailed;
        try bridge.close(promoted);
    }
    try bridge.close(handle);
    try std.testing.expectEqual(@as(c_int, 0), own_finalizations);
    try std.testing.expectEqual(@as(c_int, 0), dependency_finalizations);

    const reopened = open_flags(fixtures.target_path, 2 | 4) orelse return error.RetentionFailed;
    try std.testing.expectEqual(@intFromPtr(check), @intFromPtr(try bridge.symbol(Probe, reopened, "nodeleteCheck")));
    try std.testing.expectEqual(@as(c_int, 1), check());
    try bridge.close(reopened);

    const ordinary_path = try std.fmt.allocPrintSentinel(init.gpa, "{s}/target.so", .{directory}, 0);
    defer init.gpa.free(ordinary_path);
    const ordinary = try dyn_loader.load(ordinary_path);
    const mutate: *const fn (*FinalizationEvents) callconv(.c) void = @ptrFromInt((try ordinary.getSymbol("mutate")).addr);
    var ordinary_events: FinalizationEvents = std.mem.zeroes(FinalizationEvents);
    mutate(&ordinary_events);
    try std.testing.expectEqual(@as(c_int, 0), hold(ordinary_path));

    const independent_path = try std.fmt.allocPrintSentinel(init.gpa, "{s}/target_optimized.so", .{directory}, 0);
    defer init.gpa.free(independent_path);
    const independent = try dyn_loader.load(independent_path);
    const mutate_independent: *const fn (*FinalizationEvents) callconv(.c) void = @ptrFromInt((try independent.getSymbol("mutate")).addr);
    var independent_events: FinalizationEvents = std.mem.zeroes(FinalizationEvents);
    mutate_independent(&independent_events);

    try std.testing.expectEqual(@as(c_int, 0), start());
    dyn_loader.deinit();
    try std.testing.expectEqual(@as(c_int, 0), own_finalizations);
    try std.testing.expectEqual(@as(c_int, 0), dependency_finalizations);
    try std.testing.expectEqual(@as(u32, 1), independent_events.finalizer_count);
    try std.testing.expectEqual(@as(u32, 0), ordinary_events.finalizer_count);
    try std.testing.expectEqual(@as(c_int, 1), check());
    try std.testing.expectEqual(@as(c_int, 0), finish());
    // Native creation and lookup remain usable after the host releases ownership.
    try std.testing.expectEqual(@as(c_int, 0), start());
    try std.testing.expectEqual(@as(c_int, 0), finish());
    try std.testing.expectEqual(@as(c_int, 0), release());
    try std.testing.expectEqual(@as(u32, 1), ordinary_events.finalizer_count);
    try std.testing.expectEqual(@as(c_int, 0), close(bridge_handle));
    dyn_loader.deinit();
    try std.testing.expectError(error.ReinitializationUnsupported, dyn_loader.init(options));
    try std.testing.expectEqual(@as(c_int, 0), own_finalizations);
    try std.testing.expectEqual(@as(c_int, 0), dependency_finalizations);
}
