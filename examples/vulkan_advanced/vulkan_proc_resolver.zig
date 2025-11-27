const std = @import("std");

const vk = @import("vk.zig");
const dll = @import("dll");

pub const VulkanProcResolver = struct {
    pub var lib_vulkan: dll.DynamicLibrary = undefined;

    pub fn resolver(instance: vk.Instance, procname: [*:0]const u8) vk.PfnVoidFunction {
        _ = instance;

        std.log.debug("getting vulkan symbol {s}", .{procname});
        const maybe_sym = lib_vulkan.getSymbol(std.mem.span(procname)) catch null;
        if (maybe_sym) |sym| {
            std.log.debug("vulkan symbol {s}: got address 0x{x}", .{ procname, sym.addr });
            return @ptrFromInt(sym.addr);
        }

        std.log.warn("vulkan symbol not found", .{});
        return null;
    }
};
