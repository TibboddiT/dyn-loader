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

pub const EGL = struct {
    pub const EGLint = i32;
    pub const EGLBoolean = c_int;

    pub const EGLenum = enum(c_uint) {
        EGL_OPENGL_ES_API = 0x30A0,
    };

    pub const EGL_RENDERABLE_TYPE: EGLint = 0x3040;
    pub const EGL_OPENGL_ES2_BIT: EGLint = 0x0004;
    pub const EGL_SURFACE_TYPE: EGLint = 0x3033;
    pub const EGL_WINDOW_BIT: EGLint = 0x0004;
    pub const EGL_RED_SIZE: EGLint = 0x3024;
    pub const EGL_GREEN_SIZE: EGLint = 0x3023;
    pub const EGL_BLUE_SIZE: EGLint = 0x3022;
    pub const EGL_DEPTH_SIZE: EGLint = 0x3025;
    pub const EGL_CONTEXT_CLIENT_VERSION: EGLint = 0x3098;
    pub const EGL_NONE: EGLint = 0x3038;

    pub const EGL_NO_CONTEXT: EGLContext = @ptrFromInt(0x0);
    pub const EGL_NO_DISPLAY: EGLDisplay = @ptrFromInt(0x0);
    pub const EGL_NO_SURFACE: EGLSurface = @ptrFromInt(0x0);

    pub const EGLDisplay = ?*opaque {};
    pub const EGLConfig = ?*opaque {};
    pub const EGLSurface = ?*opaque {};
    pub const EGLContext = ?*opaque {};

    pub const EGLGetDisplay = fn (native_display: *Xlib.Display) callconv(.c) EGLDisplay;
    pub const EGLInitialize = fn (display: EGLDisplay, major: ?*EGLint, minor: ?*EGLint) callconv(.c) EGLBoolean;
    pub const EGLBindAPI = fn (api: EGLenum) callconv(.c) EGLBoolean;
    pub const EGLTerminate = fn (display: EGLDisplay) callconv(.c) EGLBoolean;
    pub const EGLChooseConfig = fn (display: EGLDisplay, attrib_list: [*c]const EGLint, configs: [*c]EGLConfig, config_size: EGLint, num_config: ?*EGLint) callconv(.c) EGLBoolean;
    pub const EGLCreateWindowSurface = fn (display: EGLDisplay, config: EGLConfig, window: Xlib.Window, attrib_list: [*c]const EGLint) callconv(.c) EGLSurface;
    pub const EGLCreateContext = fn (display: EGLDisplay, config: EGLConfig, share_context: EGLContext, attrib_list: [*c]const EGLint) callconv(.c) EGLContext;
    pub const EGLDestroySurface = fn (display: EGLDisplay, surface: EGLSurface) callconv(.c) EGLBoolean;
    pub const EGLDestroyContext = fn (display: EGLDisplay, context: EGLContext) callconv(.c) EGLBoolean;
    pub const EGLMakeCurrent = fn (display: EGLDisplay, surface: EGLSurface, surface: EGLSurface, context: EGLContext) callconv(.c) EGLBoolean;
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

    std.log.info("loading 'libEGL.so.1'...", .{});
    const lib_egl = try dll.load("libEGL.so.1");

    std.log.info("testing X11 + EGL...", .{});

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

    const eglGetDisplay: *EGL.EGLGetDisplay = @ptrFromInt((try lib_egl.getSymbol("eglGetDisplay")).addr);
    const eglInitialize: *EGL.EGLInitialize = @ptrFromInt((try lib_egl.getSymbol("eglInitialize")).addr);
    const eglBindAPI: *EGL.EGLBindAPI = @ptrFromInt((try lib_egl.getSymbol("eglBindAPI")).addr);
    const eglTerminate: *EGL.EGLTerminate = @ptrFromInt((try lib_egl.getSymbol("eglTerminate")).addr);
    const eglChooseConfig: *EGL.EGLChooseConfig = @ptrFromInt((try lib_egl.getSymbol("eglChooseConfig")).addr);
    const eglCreateWindowSurface: *EGL.EGLCreateWindowSurface = @ptrFromInt((try lib_egl.getSymbol("eglCreateWindowSurface")).addr);
    const eglCreateContext: *EGL.EGLCreateContext = @ptrFromInt((try lib_egl.getSymbol("eglCreateContext")).addr);
    const eglDestroySurface: *EGL.EGLDestroySurface = @ptrFromInt((try lib_egl.getSymbol("eglDestroySurface")).addr);
    const eglDestroyContext: *EGL.EGLDestroyContext = @ptrFromInt((try lib_egl.getSymbol("eglDestroyContext")).addr);
    const eglMakeCurrent: *EGL.EGLMakeCurrent = @ptrFromInt((try lib_egl.getSymbol("eglMakeCurrent")).addr);

    const display = xOpenDisplay(null) orelse return error.X11OpenDisplayError;
    defer _ = xCloseDisplay(display);

    const screen = xDefaultScreen(display);
    const root = xRootWindow(display, screen);
    const window = xCreateSimpleWindow(display, root, 100, 100, 400, 300, 1, xBlackPixel(display, screen), xWhitePixel(display, screen));

    _ = xStoreName(display, window, "x11_window.zig");

    _ = xMapWindow(display, window);

    _ = xFlush(display);

    const egl_display: EGL.EGLDisplay = eglGetDisplay(display);
    if (egl_display == EGL.EGL_NO_DISPLAY) {
        return error.EGLGetDisplayError;
    }

    const init_status = eglInitialize(egl_display, null, null);
    if (init_status == 0) {
        return error.EGLInitializeError;
    }
    defer _ = eglTerminate(egl_display);

    const bind_api_status = eglBindAPI(.EGL_OPENGL_ES_API);
    if (bind_api_status == 0) {
        return error.EGLBindAPIError;
    }

    const config_attribs: []const EGL.EGLint = &.{
        EGL.EGL_RENDERABLE_TYPE, EGL.EGL_OPENGL_ES2_BIT,
        EGL.EGL_SURFACE_TYPE,    EGL.EGL_WINDOW_BIT,
        EGL.EGL_RED_SIZE,        8,
        EGL.EGL_GREEN_SIZE,      8,
        EGL.EGL_BLUE_SIZE,       8,
        EGL.EGL_DEPTH_SIZE,      8,
        EGL.EGL_NONE,
    };

    var configs: [1]EGL.EGLConfig = undefined;
    var num_configs: EGL.EGLint = undefined;
    const choose_config_status = eglChooseConfig(egl_display, config_attribs.ptr, &configs, 1, &num_configs);
    if (choose_config_status == 0 or num_configs != 1) {
        return error.EGLChooseConfigError;
    }

    const surface: EGL.EGLSurface = eglCreateWindowSurface(egl_display, configs[0], @intCast(window), null);
    if (surface == EGL.EGL_NO_SURFACE) {
        return error.EGLCreateWindowError;
    }
    defer _ = eglDestroySurface(egl_display, surface);

    const context_attribs: []const EGL.EGLint = &.{
        EGL.EGL_CONTEXT_CLIENT_VERSION, 2,
        EGL.EGL_NONE,
    };

    const context: EGL.EGLContext = eglCreateContext(egl_display, configs[0], EGL.EGL_NO_CONTEXT, context_attribs.ptr);
    if (context == EGL.EGL_NO_CONTEXT) {
        return error.EGLCreateContextError;
    }
    defer _ = eglDestroyContext(egl_display, context);

    const make_current_status = eglMakeCurrent(egl_display, surface, surface, context);
    if (make_current_status == 0) {
        return error.EGLMakeCurrentError;
    }

    std.log.info("the window will be closed in 3 seconds", .{});

    try std.Io.sleep(io, .fromSeconds(3), .awake);
}
