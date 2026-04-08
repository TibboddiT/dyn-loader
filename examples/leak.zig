const std = @import("std");
const builtin = @import("builtin");

const dll = @import("dll");

// pub const std_options: std.Options = .{
//     .log_scope_levels = &.{.{
//         .scope = .dynamic_library_loader,
//         .level = .debug,
//     }},
// };

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = init.minimal.args;
    const environ = init.minimal.environ;

    try dll.init(.{ .allocator = allocator, .io = io, .args = args, .environ = environ });
    defer dll.deinit();

    std.log.info("loading system libc...", .{});
    const lib_c = try dll.loadSystemLibC();
    _ = lib_c;

    std.log.info("loading 'libX11.so.6'...", .{});
    const lib_x11 = try dll.load("libX11.so.6");
    _ = lib_x11;

    const arr = try allocator.alloc(u8, 3);
    std.debug.print("addr: 0x{x}\n", .{@intFromPtr(arr.ptr)});
}
