const dll = @import("dll");

pub const Display = opaque {};
pub const Proxy = opaque {};
pub const Object = opaque {};
pub const Registry = opaque {};
pub const Compositor = opaque {};
pub const Surface = opaque {};
pub const XdgWmBase = opaque {};
pub const XdgSurface = opaque {};
pub const XdgToplevel = opaque {};

pub const Message = extern struct {
    name: [*:0]const u8,
    signature: [*:0]const u8,
    types: ?[*]const ?*const Interface,
};

pub const Interface = extern struct {
    name: [*:0]const u8,
    version: c_int,
    method_count: c_int,
    methods: ?[*]const Message,
    event_count: c_int,
    events: ?[*]const Message,
};

pub const Array = extern struct {
    size: usize,
    alloc: usize,
    data: ?*anyopaque,
};

pub const Argument = extern union {
    i: i32,
    u: u32,
    f: i32,
    s: ?[*:0]const u8,
    o: ?*Object,
    n: u32,
    a: ?*Array,
    h: i32,
};

pub const RegistryListener = extern struct {
    global: *const fn (?*anyopaque, *Registry, u32, [*:0]const u8, u32) callconv(.c) void,
    global_remove: *const fn (?*anyopaque, *Registry, u32) callconv(.c) void,
};

pub const XdgWmBaseListener = extern struct {
    ping: *const fn (?*anyopaque, *XdgWmBase, u32) callconv(.c) void,
};

pub const XdgSurfaceListener = extern struct {
    configure: *const fn (?*anyopaque, *XdgSurface, u32) callconv(.c) void,
};

pub const XdgToplevelListener = extern struct {
    configure: *const fn (?*anyopaque, *XdgToplevel, i32, i32, *Array) callconv(.c) void,
    close: *const fn (?*anyopaque, *XdgToplevel) callconv(.c) void,
};

const marshal_flag_destroy: u32 = 1;

const DisplayConnect = fn (?[*:0]const u8) callconv(.c) ?*Display;
const DisplayDisconnect = fn (*Display) callconv(.c) void;
const DisplayGetFd = fn (*Display) callconv(.c) c_int;
const DisplayDispatchPending = fn (*Display) callconv(.c) c_int;
const DisplayGetError = fn (*Display) callconv(.c) c_int;
const DisplayFlush = fn (*Display) callconv(.c) c_int;
const DisplayRoundtrip = fn (*Display) callconv(.c) c_int;
const DisplayPrepareRead = fn (*Display) callconv(.c) c_int;
const DisplayCancelRead = fn (*Display) callconv(.c) void;
const DisplayReadEvents = fn (*Display) callconv(.c) c_int;
const ProxyMarshalArrayFlags = fn (*Proxy, u32, ?*const Interface, u32, u32, [*c]Argument) callconv(.c) ?*Proxy;
const ProxyAddListener = fn (*Proxy, *const anyopaque, ?*anyopaque) callconv(.c) c_int;
const ProxyGetVersion = fn (*Proxy) callconv(.c) u32;
const ProxyDestroy = fn (*Proxy) callconv(.c) void;

pub const Api = struct {
    display_connect: *const DisplayConnect,
    display_disconnect: *const DisplayDisconnect,
    display_get_fd: *const DisplayGetFd,
    display_dispatch_pending: *const DisplayDispatchPending,
    display_get_error: *const DisplayGetError,
    display_flush: *const DisplayFlush,
    display_roundtrip: *const DisplayRoundtrip,
    display_prepare_read: *const DisplayPrepareRead,
    display_cancel_read: *const DisplayCancelRead,
    display_read_events: *const DisplayReadEvents,
    proxy_marshal_array_flags: *const ProxyMarshalArrayFlags,
    proxy_add_listener: *const ProxyAddListener,
    proxy_get_version: *const ProxyGetVersion,
    proxy_destroy: *const ProxyDestroy,

    registry_interface: *const Interface,
    compositor_interface: *const Interface,
    surface_interface: *const Interface,
    seat_interface: *const Interface,
    output_interface: *const Interface,

    pub fn load(lib: dll.DynamicLibrary) !Api {
        const api = Api{
            .display_connect = try getFunction(DisplayConnect, lib, "wl_display_connect"),
            .display_disconnect = try getFunction(DisplayDisconnect, lib, "wl_display_disconnect"),
            .display_get_fd = try getFunction(DisplayGetFd, lib, "wl_display_get_fd"),
            .display_dispatch_pending = try getFunction(DisplayDispatchPending, lib, "wl_display_dispatch_pending"),
            .display_get_error = try getFunction(DisplayGetError, lib, "wl_display_get_error"),
            .display_flush = try getFunction(DisplayFlush, lib, "wl_display_flush"),
            .display_roundtrip = try getFunction(DisplayRoundtrip, lib, "wl_display_roundtrip"),
            .display_prepare_read = try getFunction(DisplayPrepareRead, lib, "wl_display_prepare_read"),
            .display_cancel_read = try getFunction(DisplayCancelRead, lib, "wl_display_cancel_read"),
            .display_read_events = try getFunction(DisplayReadEvents, lib, "wl_display_read_events"),
            .proxy_marshal_array_flags = try getFunction(ProxyMarshalArrayFlags, lib, "wl_proxy_marshal_array_flags"),
            .proxy_add_listener = try getFunction(ProxyAddListener, lib, "wl_proxy_add_listener"),
            .proxy_get_version = try getFunction(ProxyGetVersion, lib, "wl_proxy_get_version"),
            .proxy_destroy = try getFunction(ProxyDestroy, lib, "wl_proxy_destroy"),
            .registry_interface = try getObject(Interface, lib, "wl_registry_interface"),
            .compositor_interface = try getObject(Interface, lib, "wl_compositor_interface"),
            .surface_interface = try getObject(Interface, lib, "wl_surface_interface"),
            .seat_interface = try getObject(Interface, lib, "wl_seat_interface"),
            .output_interface = try getObject(Interface, lib, "wl_output_interface"),
        };

        initializeXdgInterfaces(api);
        return api;
    }

    pub fn connect(self: Api) !*Display {
        return self.display_connect(null) orelse error.UnableToConnectWaylandDisplay;
    }

    pub fn disconnect(self: Api, display: *Display) void {
        self.display_disconnect(display);
    }

    pub fn getFd(self: Api, display: *Display) c_int {
        return self.display_get_fd(display);
    }

    pub fn dispatchPending(self: Api, display: *Display) !void {
        if (self.display_dispatch_pending(display) < 0) return error.WaylandDispatchFailed;
    }

    pub fn flush(self: Api, display: *Display) !void {
        if (self.display_flush(display) < 0 and self.display_get_error(display) != 0) {
            return error.WaylandFlushFailed;
        }
    }

    pub fn roundtrip(self: Api, display: *Display) !void {
        if (self.display_roundtrip(display) < 0) return error.WaylandRoundtripFailed;
    }

    pub fn prepareRead(self: Api, display: *Display) bool {
        return self.display_prepare_read(display) == 0;
    }

    pub fn cancelRead(self: Api, display: *Display) void {
        self.display_cancel_read(display);
    }

    pub fn readEvents(self: Api, display: *Display) !void {
        if (self.display_read_events(display) < 0) return error.WaylandReadFailed;
    }

    pub fn getRegistry(self: Api, display: *Display) !*Registry {
        var args = [_]Argument{.{ .n = 0 }};
        const proxy = self.proxy_marshal_array_flags(
            @ptrCast(display),
            1,
            self.registry_interface,
            self.proxy_get_version(@ptrCast(display)),
            0,
            &args,
        ) orelse return error.WaylandConstructorFailed;
        return @ptrCast(proxy);
    }

    pub fn bind(self: Api, registry: *Registry, name: u32, interface: *const Interface, version: u32) !*Proxy {
        var args = [_]Argument{
            .{ .u = name },
            .{ .s = interface.name },
            .{ .u = version },
            .{ .n = 0 },
        };
        return self.proxy_marshal_array_flags(@ptrCast(registry), 0, interface, version, 0, &args) orelse error.WaylandConstructorFailed;
    }

    pub fn createSurface(self: Api, compositor: *Compositor) !*Surface {
        var args = [_]Argument{.{ .n = 0 }};
        const proxy = self.proxy_marshal_array_flags(
            @ptrCast(compositor),
            0,
            self.surface_interface,
            self.proxy_get_version(@ptrCast(compositor)),
            0,
            &args,
        ) orelse return error.WaylandConstructorFailed;
        return @ptrCast(proxy);
    }

    pub fn getXdgSurface(self: Api, wm_base: *XdgWmBase, surface: *Surface) !*XdgSurface {
        var args = [_]Argument{
            .{ .n = 0 },
            .{ .o = @ptrCast(surface) },
        };
        const proxy = self.proxy_marshal_array_flags(
            @ptrCast(wm_base),
            2,
            &xdg_surface_interface,
            self.proxy_get_version(@ptrCast(wm_base)),
            0,
            &args,
        ) orelse return error.WaylandConstructorFailed;
        return @ptrCast(proxy);
    }

    pub fn getToplevel(self: Api, xdg_surface: *XdgSurface) !*XdgToplevel {
        var args = [_]Argument{.{ .n = 0 }};
        const proxy = self.proxy_marshal_array_flags(
            @ptrCast(xdg_surface),
            1,
            &xdg_toplevel_interface,
            self.proxy_get_version(@ptrCast(xdg_surface)),
            0,
            &args,
        ) orelse return error.WaylandConstructorFailed;
        return @ptrCast(proxy);
    }

    pub fn addListener(self: Api, proxy: *Proxy, listener: *const anyopaque, data: ?*anyopaque) !void {
        if (self.proxy_add_listener(proxy, listener, data) != 0) return error.WaylandListenerFailed;
    }

    pub fn pong(self: Api, wm_base: *XdgWmBase, serial: u32) void {
        var args = [_]Argument{.{ .u = serial }};
        _ = self.proxy_marshal_array_flags(@ptrCast(wm_base), 3, null, self.proxy_get_version(@ptrCast(wm_base)), 0, &args);
    }

    pub fn setTitle(self: Api, toplevel: *XdgToplevel, title: [*:0]const u8) void {
        var args = [_]Argument{.{ .s = title }};
        _ = self.proxy_marshal_array_flags(@ptrCast(toplevel), 2, null, self.proxy_get_version(@ptrCast(toplevel)), 0, &args);
    }

    pub fn setAppId(self: Api, toplevel: *XdgToplevel, app_id: [*:0]const u8) void {
        var args = [_]Argument{.{ .s = app_id }};
        _ = self.proxy_marshal_array_flags(@ptrCast(toplevel), 3, null, self.proxy_get_version(@ptrCast(toplevel)), 0, &args);
    }

    pub fn commit(self: Api, surface: *Surface) void {
        _ = self.proxy_marshal_array_flags(@ptrCast(surface), 6, null, self.proxy_get_version(@ptrCast(surface)), 0, null);
    }

    pub fn ackConfigure(self: Api, xdg_surface: *XdgSurface, serial: u32) void {
        var args = [_]Argument{.{ .u = serial }};
        _ = self.proxy_marshal_array_flags(@ptrCast(xdg_surface), 4, null, self.proxy_get_version(@ptrCast(xdg_surface)), 0, &args);
    }

    pub fn destroyToplevel(self: Api, toplevel: *XdgToplevel) void {
        self.destroyProtocolObject(@ptrCast(toplevel), 0);
    }

    pub fn destroyXdgSurface(self: Api, xdg_surface: *XdgSurface) void {
        self.destroyProtocolObject(@ptrCast(xdg_surface), 0);
    }

    pub fn destroySurface(self: Api, surface: *Surface) void {
        self.destroyProtocolObject(@ptrCast(surface), 0);
    }

    pub fn destroyWmBase(self: Api, wm_base: *XdgWmBase) void {
        self.destroyProtocolObject(@ptrCast(wm_base), 0);
    }

    pub fn destroyProxy(self: Api, proxy: *Proxy) void {
        self.proxy_destroy(proxy);
    }

    fn destroyProtocolObject(self: Api, proxy: *Proxy, opcode: u32) void {
        _ = self.proxy_marshal_array_flags(proxy, opcode, null, self.proxy_get_version(proxy), marshal_flag_destroy, null);
    }
};

fn getFunction(comptime T: type, lib: dll.DynamicLibrary, name: []const u8) !*const T {
    return @ptrFromInt((try lib.getSymbol(name)).addr);
}

fn getObject(comptime T: type, lib: dll.DynamicLibrary, name: []const u8) !*const T {
    return @ptrFromInt((try lib.getSymbol(name)).addr);
}

// Generated from stable xdg-shell.xml protocol version 7, restricted to the
// requests and events available in protocol version 1.
const null_types = [_]?*const Interface{ null, null, null, null };

var wm_create_positioner_types = [_]?*const Interface{null};
var wm_get_xdg_surface_types = [_]?*const Interface{ null, null };
var surface_get_toplevel_types = [_]?*const Interface{null};
var surface_get_popup_types = [_]?*const Interface{ null, null, null };
var toplevel_set_parent_types = [_]?*const Interface{null};
var toplevel_show_window_menu_types = [_]?*const Interface{ null, null, null, null };
var toplevel_move_types = [_]?*const Interface{ null, null };
var toplevel_resize_types = [_]?*const Interface{ null, null, null };
var toplevel_set_fullscreen_types = [_]?*const Interface{null};
var popup_grab_types = [_]?*const Interface{ null, null };

const xdg_wm_base_requests = [_]Message{
    .{ .name = "destroy", .signature = "", .types = null },
    .{ .name = "create_positioner", .signature = "n", .types = &wm_create_positioner_types },
    .{ .name = "get_xdg_surface", .signature = "no", .types = &wm_get_xdg_surface_types },
    .{ .name = "pong", .signature = "u", .types = &null_types },
};
const xdg_wm_base_events = [_]Message{
    .{ .name = "ping", .signature = "u", .types = &null_types },
};

pub const xdg_wm_base_interface = Interface{
    .name = "xdg_wm_base",
    .version = 1,
    .method_count = xdg_wm_base_requests.len,
    .methods = &xdg_wm_base_requests,
    .event_count = xdg_wm_base_events.len,
    .events = &xdg_wm_base_events,
};

const xdg_positioner_requests = [_]Message{
    .{ .name = "destroy", .signature = "", .types = null },
    .{ .name = "set_size", .signature = "ii", .types = &null_types },
    .{ .name = "set_anchor_rect", .signature = "iiii", .types = &null_types },
    .{ .name = "set_anchor", .signature = "u", .types = &null_types },
    .{ .name = "set_gravity", .signature = "u", .types = &null_types },
    .{ .name = "set_constraint_adjustment", .signature = "u", .types = &null_types },
    .{ .name = "set_offset", .signature = "ii", .types = &null_types },
};

pub const xdg_positioner_interface = Interface{
    .name = "xdg_positioner",
    .version = 1,
    .method_count = xdg_positioner_requests.len,
    .methods = &xdg_positioner_requests,
    .event_count = 0,
    .events = null,
};

const xdg_surface_requests = [_]Message{
    .{ .name = "destroy", .signature = "", .types = null },
    .{ .name = "get_toplevel", .signature = "n", .types = &surface_get_toplevel_types },
    .{ .name = "get_popup", .signature = "n?oo", .types = &surface_get_popup_types },
    .{ .name = "set_window_geometry", .signature = "iiii", .types = &null_types },
    .{ .name = "ack_configure", .signature = "u", .types = &null_types },
};
const xdg_surface_events = [_]Message{
    .{ .name = "configure", .signature = "u", .types = &null_types },
};

pub const xdg_surface_interface = Interface{
    .name = "xdg_surface",
    .version = 1,
    .method_count = xdg_surface_requests.len,
    .methods = &xdg_surface_requests,
    .event_count = xdg_surface_events.len,
    .events = &xdg_surface_events,
};

const xdg_toplevel_requests = [_]Message{
    .{ .name = "destroy", .signature = "", .types = null },
    .{ .name = "set_parent", .signature = "?o", .types = &toplevel_set_parent_types },
    .{ .name = "set_title", .signature = "s", .types = &null_types },
    .{ .name = "set_app_id", .signature = "s", .types = &null_types },
    .{ .name = "show_window_menu", .signature = "ouii", .types = &toplevel_show_window_menu_types },
    .{ .name = "move", .signature = "ou", .types = &toplevel_move_types },
    .{ .name = "resize", .signature = "ouu", .types = &toplevel_resize_types },
    .{ .name = "set_max_size", .signature = "ii", .types = &null_types },
    .{ .name = "set_min_size", .signature = "ii", .types = &null_types },
    .{ .name = "set_maximized", .signature = "", .types = null },
    .{ .name = "unset_maximized", .signature = "", .types = null },
    .{ .name = "set_fullscreen", .signature = "?o", .types = &toplevel_set_fullscreen_types },
    .{ .name = "unset_fullscreen", .signature = "", .types = null },
    .{ .name = "set_minimized", .signature = "", .types = null },
};
const xdg_toplevel_events = [_]Message{
    .{ .name = "configure", .signature = "iia", .types = &null_types },
    .{ .name = "close", .signature = "", .types = null },
};

pub const xdg_toplevel_interface = Interface{
    .name = "xdg_toplevel",
    .version = 1,
    .method_count = xdg_toplevel_requests.len,
    .methods = &xdg_toplevel_requests,
    .event_count = xdg_toplevel_events.len,
    .events = &xdg_toplevel_events,
};

const xdg_popup_requests = [_]Message{
    .{ .name = "destroy", .signature = "", .types = null },
    .{ .name = "grab", .signature = "ou", .types = &popup_grab_types },
};
const xdg_popup_events = [_]Message{
    .{ .name = "configure", .signature = "iiii", .types = &null_types },
    .{ .name = "popup_done", .signature = "", .types = null },
};

pub const xdg_popup_interface = Interface{
    .name = "xdg_popup",
    .version = 1,
    .method_count = xdg_popup_requests.len,
    .methods = &xdg_popup_requests,
    .event_count = xdg_popup_events.len,
    .events = &xdg_popup_events,
};

fn initializeXdgInterfaces(api: Api) void {
    wm_create_positioner_types[0] = &xdg_positioner_interface;
    wm_get_xdg_surface_types[0] = &xdg_surface_interface;
    wm_get_xdg_surface_types[1] = api.surface_interface;
    surface_get_toplevel_types[0] = &xdg_toplevel_interface;
    surface_get_popup_types[0] = &xdg_popup_interface;
    surface_get_popup_types[1] = &xdg_surface_interface;
    surface_get_popup_types[2] = &xdg_positioner_interface;
    toplevel_set_parent_types[0] = &xdg_toplevel_interface;
    toplevel_show_window_menu_types[0] = api.seat_interface;
    toplevel_move_types[0] = api.seat_interface;
    toplevel_resize_types[0] = api.seat_interface;
    toplevel_set_fullscreen_types[0] = api.output_interface;
    popup_grab_types[0] = api.seat_interface;
}
