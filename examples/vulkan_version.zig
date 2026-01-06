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

    std.log.info("loading 'libvulkan.so.1'...", .{});

    const lib_vulkan = try dll.load("libvulkan.so.1");

    std.log.info("testing vulkan...", .{});

    const vkEnumerateInstanceVersion_sym = try lib_vulkan.getSymbol("vkEnumerateInstanceVersion");
    const vkEnumerateInstanceVersion_addr = vkEnumerateInstanceVersion_sym.addr;
    const vkEnumerateInstanceVersion: *const fn (*u32) callconv(.c) c_int = @ptrFromInt(vkEnumerateInstanceVersion_addr);

    var vk_version: u32 = 0;
    switch (vkEnumerateInstanceVersion(&vk_version)) {
        0 => std.log.info("vulkan version: {d}.{d}.{d}", .{ vk_version >> 22, (vk_version >> 12) & 0x3ff, (vk_version & 0xfff) }),
        else => |e| std.log.info("error getting vulkan version = 0x{x}", .{e}),
    }
}
