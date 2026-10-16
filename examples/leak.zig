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
    const args = init.minimal.args;
    const environ = init.minimal.environ;

    try dyn_loader.init(.{ .args = args, .environ = environ });
    defer dyn_loader.deinit();

    std.log.info("loading system libc...", .{});
    const lib_c = try dyn_loader.loadSystemLibC();
    _ = lib_c;

    std.log.info("loading 'libX11.so.6'...", .{});
    const lib_x11 = try dyn_loader.load("libX11.so.6");
    _ = lib_x11;

    const arr = try allocator.alloc(u8, 3);
    std.debug.print("addr: 0x{x}\n", .{@intFromPtr(arr.ptr)});
}
