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

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer if (gpa.deinit() != .ok) @panic("memory check failed");

    try dll.init(.{ .allocator = allocator });
    defer dll.deinit();

    std.log.info("loading 'libc.so.6'...", .{});

    const lib_c = try dll.load("libc.so.6");

    std.log.info("testing libc printf...", .{});

    const printf_sym = try lib_c.getSymbol("printf");
    const printf_addr = printf_sym.addr;
    const printf: *const fn ([*:0]const u8, ...) callconv(.c) c_int = @ptrFromInt(printf_addr);

    var world: [:0]u8 = try allocator.dupeZ(u8, "World");
    defer allocator.free(world);

    world.ptr[0] = 'w';

    _ = printf("Hello, %s!\n", world.ptr);
}
