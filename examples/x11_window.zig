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

pub const Xlib = struct {
    pub const XID = c_ulong;

    pub const Display = opaque {};
    pub const Window = XID;

    pub const XOpenDisplay = fn (display_name: [*c]const u8) callconv(.c) ?*Display;
    pub const XDefaultScreen = fn (display: ?*Display) callconv(.c) c_int;
    pub const XRootWindow = fn (display: ?*Display, screen: c_int) callconv(.c) Window;
    pub const XCreateSimpleWindow = fn (display: ?*Display, window: Window, x: c_int, y: c_int, width: c_uint, height: c_uint, border_width: c_uint, border: c_ulong, background: c_ulong) callconv(.c) Window;
    pub const XStoreName = fn (display: ?*Display, window: Window, [*c]const u8) callconv(.c) c_int;
    pub const XMapWindow = fn (display: ?*Display, window: Window) callconv(.c) c_int;
    pub const XFlush = fn (display: ?*Display) callconv(.c) c_int;
    pub const XCloseDisplay = fn (display: ?*Display) callconv(.c) c_int;
    pub const XBlackPixel = fn (display: ?*Display, screen: c_int) callconv(.c) c_ulong;
    pub const XWhitePixel = fn (display: ?*Display, screen: c_int) callconv(.c) c_ulong;
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

    std.log.info("loading 'libX11.so.6'...", .{});

    const lib_x11 = try dll.load("libX11.so.6");

    std.log.info("testing X11...", .{});

    const xOpenDisplay: *Xlib.XOpenDisplay = @ptrFromInt((try lib_x11.getSymbol("XOpenDisplay")).addr);
    const xDefaultScreen: *Xlib.XDefaultScreen = @ptrFromInt((try lib_x11.getSymbol("XDefaultScreen")).addr);
    const xRootWindow: *Xlib.XRootWindow = @ptrFromInt((try lib_x11.getSymbol("XRootWindow")).addr);
    const xCreateSimpleWindow: *Xlib.XCreateSimpleWindow = @ptrFromInt((try lib_x11.getSymbol("XCreateSimpleWindow")).addr);
    const xStoreName: *Xlib.XStoreName = @ptrFromInt((try lib_x11.getSymbol("XStoreName")).addr);
    const xBlackPixel: *Xlib.XBlackPixel = @ptrFromInt((try lib_x11.getSymbol("XBlackPixel")).addr);
    const xWhitePixel: *Xlib.XWhitePixel = @ptrFromInt((try lib_x11.getSymbol("XWhitePixel")).addr);
    const xMapWindow: *Xlib.XMapWindow = @ptrFromInt((try lib_x11.getSymbol("XMapWindow")).addr);
    const xFlush: *Xlib.XFlush = @ptrFromInt((try lib_x11.getSymbol("XFlush")).addr);
    const xCloseDisplay: *Xlib.XCloseDisplay = @ptrFromInt((try lib_x11.getSymbol("XCloseDisplay")).addr);

    const display = xOpenDisplay(null) orelse return error.UnableToCreateDisplay;
    const screen = xDefaultScreen(display);
    const root = xRootWindow(display, screen);
    const window = xCreateSimpleWindow(display, root, 100, 100, 400, 300, 1, xBlackPixel(display, screen), xWhitePixel(display, screen));

    _ = xStoreName(display, window, "x11_window.zig");

    _ = xMapWindow(display, window);
    _ = xFlush(display);

    std.log.info("the window will be closed in 3 seconds", .{});

    try std.Io.sleep(io, .fromSeconds(3), .awake);

    _ = xCloseDisplay(display);
}
