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

    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try dll.init(.{ .allocator = allocator, .io = io });
    defer dll.deinit();

    var cwd_buf: [1024]u8 = undefined;
    const cwd_idx = try std.process.executableDirPath(io, &cwd_buf);

    var lib_path: [1024]u8 = undefined;

    const lib_c_path = try std.fmt.bufPrint(&lib_path, "{s}/{s}", .{ cwd_buf[0..cwd_idx], "resources/musl/libc.so" });

    std.log.info("loading '{s}'...", .{lib_c_path});

    const lib_c = try dll.load(lib_c_path);

    std.log.info("testing libc printf...", .{});

    const printf_sym = try lib_c.getSymbol("printf");
    const printf_addr = printf_sym.addr;
    const printf: *const fn ([*:0]const u8, ...) callconv(.c) c_int = @ptrFromInt(printf_addr);

    var world: [:0]u8 = try allocator.dupeZ(u8, "World");
    defer allocator.free(world);

    world.ptr[0] = 'w';

    _ = printf("Hello, %s!\n", world.ptr);
}
