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

    var threaded: std.Io.Threaded = .init(allocator);
    defer threaded.deinit();
    const io = threaded.io();

    try dll.init(.{ .allocator = allocator });
    defer dll.deinit();

    var cwd_buf: [1024]u8 = undefined;
    const cwd = try std.fs.selfExeDirPath(&cwd_buf);

    var lib_path: [1024]u8 = undefined;

    const lib_raylib_path = try std.fmt.bufPrint(&lib_path, "{s}/{s}", .{ cwd, "resources/raylib/libraylib.so.5.5.0" });

    std.log.info("loading '{s}'...", .{lib_raylib_path});

    const lib_raylib = try dll.load(lib_raylib_path);

    std.log.info("testing raylib InitWindow...", .{});

    const init_window_sym = try lib_raylib.getSymbol("InitWindow");
    const init_window_addr = init_window_sym.addr;
    const init_window: *const fn (width: c_int, height: c_int, title: [*:0]const u8) callconv(.c) void = @ptrFromInt(init_window_addr);

    init_window(800, 600, "Hello from raylib!");

    try std.Io.sleep(io, .fromSeconds(3), .awake);
}
