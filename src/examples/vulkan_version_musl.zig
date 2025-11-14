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

    var cwd_buf: [1024]u8 = undefined;
    const cwd = try std.fs.selfExeDirPath(&cwd_buf);

    var lib_path: [1024]u8 = undefined;

    const lib_c_path = try std.fmt.bufPrint(&lib_path, "{s}/{s}", .{ cwd, "resources/musl/libc.so" });

    std.log.info("loading '{s}'...", .{lib_c_path});

    const lib_c = try dll.load(lib_c_path);

    const lib_vulkan_path = try std.fmt.bufPrint(&lib_path, "{s}/{s}", .{ cwd, "resources/musl/libvulkan.so.1" });

    std.log.info("loading '{s}'...", .{lib_vulkan_path});

    const lib_vulkan = try dll.load(lib_vulkan_path);

    std.log.info("testing libc printf...", .{});

    const printf_sym = try lib_c.getSymbol("printf");
    const printf_addr = printf_sym.addr;
    const printf: *const fn ([*:0]const u8, ...) callconv(.c) c_int = @ptrFromInt(printf_addr);

    var world: [:0]u8 = try allocator.dupeZ(u8, "World");
    defer allocator.free(world);

    world.ptr[0] = 'w';

    _ = printf("Hello, %s!\n", world.ptr);

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
