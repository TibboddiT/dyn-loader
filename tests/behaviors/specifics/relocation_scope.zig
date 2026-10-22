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
    const symbol = try library.getSymbol("scopeRun");
    const probe: *const fn (directory: [*:0]const u8) callconv(.c) c_int = @ptrFromInt(symbol.addr);

    const directory = try init.gpa.dupeSentinel(u8, std.fs.path.dirname(fixtures.target_path).?, 0);
    defer init.gpa.free(directory);

    try std.testing.expectEqual(@as(c_int, 0), probe(directory));
}
