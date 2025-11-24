const std = @import("std");
const builtin = @import("builtin");

const dll = @import("dll");

pub const std_options: std.Options = .{
    // .log_scope_levels = &.{.{
    //     .scope = .dynamic_library_loader,
    //     .level = .debug,
    // }},
    .enable_segfault_handler = true,
};

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer if (gpa.deinit() != .ok) @panic("memory check failed");

    try dll.init(.{ .allocator = allocator });
    defer dll.deinit();

    std.log.info("loading system libc...", .{});

    const lib_c = try dll.loadSystemLibC();

    std.log.info("testing libc printf segfault...", .{});

    const printf_sym = try lib_c.getSymbol("printf");
    const printf_addr = printf_sym.addr;
    const printf: *const fn ([*:0]const u8, ...) callconv(.c) c_int = @ptrFromInt(printf_addr);

    _ = printf("Hello, %s!\n", @as([*:0]const u8, @ptrFromInt(0x8)));
}
