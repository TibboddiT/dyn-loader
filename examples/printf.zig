const std = @import("std");
const builtin = @import("builtin");

const dyn_loader = @import("dyn_loader");

// pub const std_options: std.Options = .{
//     .log_scope_levels = &.{.{
//         .scope = .dyn_loader,
//         .level = .debug,
//     }},
// };

pub const debug = struct {
    pub const SelfInfo = dyn_loader.CustomSelfInfo;
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = init.minimal.args;
    const environ = init.minimal.environ;

    try dyn_loader.init(.{ .allocator = allocator, .io = io, .args = args, .environ = environ });
    defer dyn_loader.deinit();

    std.log.info("loading system libc...", .{});

    const lib_c = try dyn_loader.loadSystemLibC();

    std.log.info("testing libc printf...", .{});

    const printf_sym = try lib_c.getSymbol("printf");
    const printf_addr = printf_sym.addr;
    const printf: *const fn ([*:0]const u8, ...) callconv(.c) c_int = @ptrFromInt(printf_addr);

    var world: [:0]u8 = try allocator.dupeSentinel(u8, "World", 0);
    defer allocator.free(world);

    world.ptr[0] = 'w';

    _ = printf("Hello, %s!\n", world.ptr);
}
