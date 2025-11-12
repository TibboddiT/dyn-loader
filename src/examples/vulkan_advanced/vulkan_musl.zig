const std = @import("std");
const builtin = @import("builtin");

const dll = @import("dll");
const vk = @import("vk.zig");

// pub const std_options: std.Options = .{
//     .log_scope_levels = &.{.{
//         .scope = .dynamic_library_loader,
//         .level = .debug,
//     }},
// };

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

const VulkanProcResolver = struct {
    var lib_vulkan: dll.DynamicLibrary = undefined;

    fn resolver(instance: vk.Instance, procname: [*:0]const u8) vk.PfnVoidFunction {
        _ = instance;

        std.log.debug("getting vulkan symbol {s}", .{procname});
        const maybe_sym = lib_vulkan.getSymbol(std.mem.span(procname)) catch null;
        if (maybe_sym) |sym| {
            std.log.debug("vulkan symbol {s}: got address 0x{x}", .{ procname, sym.addr });
            return @ptrFromInt(sym.addr);
        }

        std.log.warn("Vulkan symbol not found", .{});
        return null;
    }
};

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{ .stack_trace_frames = 10 }) = .init;
    const allocator = gpa.allocator();
    defer if (gpa.deinit() != .ok) @panic("Memory check failed");

    try dll.init(.{});
    defer dll.deinit(allocator);

    var cwd_buf: [1024]u8 = undefined;
    const cwd = try std.fs.selfExeDirPath(&cwd_buf);

    var lib_path: [1024]u8 = undefined;

    const lib_c_path = try std.fmt.bufPrint(&lib_path, "{s}/{s}", .{ cwd, "resources/musl/libc.so" });

    std.log.info("Loading '{s}'...", .{lib_c_path});

    const lib_c = try dll.load(allocator, lib_c_path);
    _ = lib_c;

    const lib_vulkan_path = try std.fmt.bufPrint(&lib_path, "{s}/{s}", .{ cwd, "resources/musl/libvulkan.so.1" });

    std.log.info("Loading '{s}'...", .{lib_vulkan_path});

    const lib_vulkan = try dll.load(allocator, lib_vulkan_path);

    VulkanProcResolver.lib_vulkan = lib_vulkan;

    const BaseWrapper = vk.BaseWrapper;
    // const InstanceWrapper = vk.InstanceWrapper;
    // const DeviceWrapper = vk.DeviceWrapper;

    // const Instance = vk.InstanceProxy;
    // const Device = vk.DeviceProxy;

    const vkb = BaseWrapper.load(&VulkanProcResolver.resolver);

    std.log.info("Getting vulkan version...", .{});
    const version = try vkb.enumerateInstanceVersion();
    std.log.info("Got vulkan version: {d}.{d}.{d}", .{ version >> 22, (version >> 12) & 0x3ff, (version & 0xfff) });

    std.log.info("Creating vulkan instance (will get error.IncompatibleDriver if dlopen is not yet implemented)...", .{});

    const app_name = "Test";

    const required_layer_names = [_][*:0]const u8{"VK_LAYER_KHRONOS_validation"};

    var extension_names: std.ArrayList([*:0]const u8) = .empty;
    defer extension_names.deinit(allocator);
    try extension_names.append(allocator, vk.extensions.ext_debug_utils.name);

    const instance = try vkb.createInstance(&.{
        .p_application_info = &.{
            .p_application_name = app_name,
            .application_version = @bitCast(vk.makeApiVersion(0, 0, 0, 0)),
            .p_engine_name = app_name,
            .engine_version = @bitCast(vk.makeApiVersion(0, 0, 0, 0)),
            .api_version = @bitCast(vk.API_VERSION_1_2),
        },
        .enabled_layer_count = required_layer_names.len,
        .pp_enabled_layer_names = @ptrCast(&required_layer_names),
        .enabled_extension_count = @intCast(extension_names.items.len),
        .pp_enabled_extension_names = extension_names.items.ptr,
        // enumerate_portability_bit_khr to support vulkan in mac os
        // see https://github.com/glfw/glfw/issues/2335
        .flags = .{ .enumerate_portability_bit_khr = true },
    }, null);

    _ = instance;
}
