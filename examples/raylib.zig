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

    const lib_raylib_path = try std.fmt.bufPrint(&lib_path, "{s}/{s}", .{ cwd_buf[0..cwd_idx], "resources/raylib/libraylib.so.5.5.0" });

    std.log.info("loading '{s}'...", .{lib_raylib_path});

    const lib_raylib = try dll.load(lib_raylib_path);

    std.log.info("testing raylib InitWindow...", .{});

    const Color = extern struct {
        r: u8,
        g: u8,
        b: u8,
        a: u8,
    };

    const Vector2 = extern struct {
        x: f32,
        y: f32,
    };

    const initWindow: *const fn (width: c_int, height: c_int, title: [*:0]const u8) callconv(.c) void = @ptrFromInt((try lib_raylib.getSymbol("InitWindow")).addr);
    const windowShouldClose: *const fn () callconv(.c) bool = @ptrFromInt((try lib_raylib.getSymbol("WindowShouldClose")).addr);
    const setTargetFPS: *const fn (fps: c_int) callconv(.c) void = @ptrFromInt((try lib_raylib.getSymbol("SetTargetFPS")).addr);
    const beginDrawing: *const fn () callconv(.c) void = @ptrFromInt((try lib_raylib.getSymbol("BeginDrawing")).addr);
    const clearBackground: *const fn (color: Color) callconv(.c) void = @ptrFromInt((try lib_raylib.getSymbol("ClearBackground")).addr);
    const drawCircleV: *const fn (center: Vector2, radius: f32, color: Color) callconv(.c) void = @ptrFromInt((try lib_raylib.getSymbol("DrawCircleV")).addr);
    const drawText: *const fn (text: [*:0]const u8, pos_x: c_int, pos_y: c_int, font_size: c_int, color: Color) callconv(.c) void = @ptrFromInt((try lib_raylib.getSymbol("DrawText")).addr);
    const endDrawing: *const fn () callconv(.c) void = @ptrFromInt((try lib_raylib.getSymbol("EndDrawing")).addr);
    const closeWindow: *const fn () callconv(.c) void = @ptrFromInt((try lib_raylib.getSymbol("CloseWindow")).addr);

    const screenWidth: f32 = 800;
    const screenHeight: f32 = 450;

    initWindow(screenWidth, screenHeight, "Hello from zig !");

    // Ball properties
    var ballPosition: Vector2 = .{ .x = screenWidth / 2.0, .y = screenHeight / 2.0 };
    var ballSpeed: Vector2 = .{ .x = 4.0, .y = 3.0 };

    const ballRadius: f32 = 20.0;

    setTargetFPS(60);

    while (!windowShouldClose()) {
        ballPosition.x += ballSpeed.x;
        ballPosition.y += ballSpeed.y;

        if ((ballPosition.x > screenWidth - ballRadius) or (ballPosition.x < ballRadius))
            ballSpeed.x *= -1;

        if ((ballPosition.y > screenHeight - ballRadius) or (ballPosition.y < ballRadius))
            ballSpeed.y *= -1;

        // Draw
        beginDrawing();
        clearBackground(.{ .r = 0x18, .g = 0x18, .b = 0x18, .a = 255 });
        drawCircleV(ballPosition, ballRadius, .{ .r = 255, .g = 100, .b = 100, .a = 255 });
        drawText("Yo ! - Raylib", 10, 10, 20, .{ .r = 120, .g = 120, .b = 120, .a = 255 });
        endDrawing();
    }

    closeWindow();
}
