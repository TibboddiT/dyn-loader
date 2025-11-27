pub const Xlib = struct {
    pub const XID = c_ulong;
    pub const Time = c_ulong;
    pub const Bool = c_int;

    pub const False: c_int = 0;
    pub const True: c_int = 1;

    pub const Display = opaque {};
    pub const Window = XID;
    pub const Status = c_int;
    pub const Visual = opaque {};
    pub const Screen = opaque {};
    pub const Colormap = XID;
    pub const Atom = c_ulong;
    pub const Drawable = XID;

    pub const NoEventMask: c_ulong = 0;
    pub const KeyPressMask: c_ulong = (1 << 0);
    pub const KeyReleaseMask: c_ulong = (1 << 1);
    pub const ButtonPressMask: c_ulong = (1 << 2);
    pub const ButtonReleaseMask: c_ulong = (1 << 3);
    pub const EnterWindowMask: c_ulong = (1 << 4);
    pub const LeaveWindowMask: c_ulong = (1 << 5);
    pub const PointerMotionMask: c_ulong = (1 << 6);
    pub const PointerMotionHintMask: c_ulong = (1 << 7);
    pub const Button1MotionMask: c_ulong = (1 << 8);
    pub const Button2MotionMask: c_ulong = (1 << 9);
    pub const Button3MotionMask: c_ulong = (1 << 10);
    pub const Button4MotionMask: c_ulong = (1 << 11);
    pub const Button5MotionMask: c_ulong = (1 << 12);
    pub const ButtonMotionMask: c_ulong = (1 << 13);
    pub const KeymapStateMask: c_ulong = (1 << 14);
    pub const ExposureMask: c_ulong = (1 << 15);
    pub const VisibilityChangeMask: c_ulong = (1 << 16);
    pub const StructureNotifyMask: c_ulong = (1 << 17);
    pub const ResizeRedirectMask: c_ulong = (1 << 18);
    pub const SubstructureNotifyMask: c_ulong = (1 << 19);
    pub const SubstructureRedirectMask: c_ulong = (1 << 20);
    pub const FocusChangeMask: c_ulong = (1 << 21);
    pub const PropertyChangeMask: c_ulong = (1 << 22);
    pub const ColormapChangeMask: c_ulong = (1 << 23);
    pub const OwnerGrabButtonMask: c_ulong = (1 << 24);

    pub const KeyPress: c_int = 2;
    pub const KeyRelease: c_int = 3;
    pub const ButtonPress: c_int = 4;
    pub const ButtonRelease: c_int = 5;
    pub const MotionNotify: c_int = 6;
    pub const EnterNotify: c_int = 7;
    pub const LeaveNotify: c_int = 8;
    pub const FocusIn: c_int = 9;
    pub const FocusOut: c_int = 10;
    pub const KeymapNotify: c_int = 11;
    pub const Expose: c_int = 12;
    pub const GraphicsExpose: c_int = 13;
    pub const NoExpose: c_int = 14;
    pub const VisibilityNotify: c_int = 15;
    pub const CreateNotify: c_int = 16;
    pub const DestroyNotify: c_int = 17;
    pub const UnmapNotify: c_int = 18;
    pub const MapNotify: c_int = 19;
    pub const MapRequest: c_int = 20;
    pub const ReparentNotify: c_int = 21;
    pub const ConfigureNotify: c_int = 22;
    pub const ConfigureRequest: c_int = 23;
    pub const GravityNotify: c_int = 24;
    pub const ResizeRequest: c_int = 25;
    pub const CirculateNotify: c_int = 26;
    pub const CirculateRequest: c_int = 27;
    pub const PropertyNotify: c_int = 28;
    pub const SelectionClear: c_int = 29;
    pub const SelectionRequest: c_int = 30;
    pub const SelectionNotify: c_int = 31;
    pub const ColormapNotify: c_int = 32;
    pub const ClientMessage: c_int = 33;
    pub const MappingNotify: c_int = 34;
    pub const GenericEvent: c_int = 35;
    pub const LASTEvent: c_int = 36;

    pub const XKeyEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        root: Window = 0,
        subwindow: Window = 0,
        time: Time = 0,
        x: c_int = 0,
        y: c_int = 0,
        x_root: c_int = 0,
        y_root: c_int = 0,
        state: c_uint = 0,
        keycode: c_uint = 0,
        same_screen: c_int = 0,
    };
    pub const XKeyPressedEvent = XKeyEvent;
    pub const XKeyReleasedEvent = XKeyEvent;
    pub const XButtonEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        root: Window = 0,
        subwindow: Window = 0,
        time: Time = 0,
        x: c_int = 0,
        y: c_int = 0,
        x_root: c_int = 0,
        y_root: c_int = 0,
        state: c_uint = 0,
        button: c_uint = 0,
        same_screen: c_int = 0,
    };
    pub const XButtonPressedEvent = XButtonEvent;
    pub const XButtonReleasedEvent = XButtonEvent;
    pub const XMotionEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        root: Window = 0,
        subwindow: Window = 0,
        time: Time = 0,
        x: c_int = 0,
        y: c_int = 0,
        x_root: c_int = 0,
        y_root: c_int = 0,
        state: c_uint = 0,
        is_hint: u8 = 0,
        same_screen: c_int = 0,
    };
    pub const XPointerMovedEvent = XMotionEvent;
    pub const XCrossingEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        root: Window = 0,
        subwindow: Window = 0,
        time: Time = 0,
        x: c_int = 0,
        y: c_int = 0,
        x_root: c_int = 0,
        y_root: c_int = 0,
        mode: c_int = 0,
        detail: c_int = 0,
        same_screen: c_int = 0,
        focus: c_int = 0,
        state: c_uint = 0,
    };
    pub const XEnterWindowEvent = XCrossingEvent;
    pub const XLeaveWindowEvent = XCrossingEvent;
    pub const XFocusChangeEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        mode: c_int = 0,
        detail: c_int = 0,
    };
    pub const XFocusInEvent = XFocusChangeEvent;
    pub const XFocusOutEvent = XFocusChangeEvent;
    pub const XKeymapEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        key_vector: [32]u8 = @import("std").mem.zeroes([32]u8),
    };
    pub const XExposeEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        x: c_int = 0,
        y: c_int = 0,
        width: c_int = 0,
        height: c_int = 0,
        count: c_int = 0,
    };
    pub const XGraphicsExposeEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        drawable: Drawable = 0,
        x: c_int = 0,
        y: c_int = 0,
        width: c_int = 0,
        height: c_int = 0,
        count: c_int = 0,
        major_code: c_int = 0,
        minor_code: c_int = 0,
    };
    pub const XNoExposeEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        drawable: Drawable = 0,
        major_code: c_int = 0,
        minor_code: c_int = 0,
    };
    pub const XVisibilityEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        state: c_int = 0,
    };
    pub const XCreateWindowEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        parent: Window = 0,
        window: Window = 0,
        x: c_int = 0,
        y: c_int = 0,
        width: c_int = 0,
        height: c_int = 0,
        border_width: c_int = 0,
        override_redirect: c_int = 0,
    };
    pub const XDestroyWindowEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        event: Window = 0,
        window: Window = 0,
    };
    pub const XUnmapEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        event: Window = 0,
        window: Window = 0,
        from_configure: c_int = 0,
    };
    pub const XMapEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        event: Window = 0,
        window: Window = 0,
        override_redirect: c_int = 0,
    };
    pub const XMapRequestEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        parent: Window = 0,
        window: Window = 0,
    };
    pub const XReparentEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        event: Window = 0,
        window: Window = 0,
        parent: Window = 0,
        x: c_int = 0,
        y: c_int = 0,
        override_redirect: c_int = 0,
    };
    pub const XConfigureEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        event: Window = 0,
        window: Window = 0,
        x: c_int = 0,
        y: c_int = 0,
        width: c_int = 0,
        height: c_int = 0,
        border_width: c_int = 0,
        above: Window = 0,
        override_redirect: c_int = 0,
    };
    pub const XGravityEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        event: Window = 0,
        window: Window = 0,
        x: c_int = 0,
        y: c_int = 0,
    };
    pub const XResizeRequestEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        width: c_int = 0,
        height: c_int = 0,
    };
    pub const XConfigureRequestEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        parent: Window = 0,
        window: Window = 0,
        x: c_int = 0,
        y: c_int = 0,
        width: c_int = 0,
        height: c_int = 0,
        border_width: c_int = 0,
        above: Window = 0,
        detail: c_int = 0,
        value_mask: c_ulong = 0,
    };
    pub const XCirculateEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        event: Window = 0,
        window: Window = 0,
        place: c_int = 0,
    };
    pub const XCirculateRequestEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        parent: Window = 0,
        window: Window = 0,
        place: c_int = 0,
    };
    pub const XPropertyEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        atom: Atom = 0,
        time: Time = 0,
        state: c_int = 0,
    };
    pub const XSelectionClearEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        selection: Atom = 0,
        time: Time = 0,
    };
    pub const XSelectionRequestEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        owner: Window = 0,
        requestor: Window = 0,
        selection: Atom = 0,
        target: Atom = 0,
        property: Atom = 0,
        time: Time = 0,
    };
    pub const XSelectionEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        requestor: Window = 0,
        selection: Atom = 0,
        target: Atom = 0,
        property: Atom = 0,
        time: Time = 0,
    };
    pub const XColormapEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        colormap: Colormap = 0,
        new: c_int = 0,
        state: c_int = 0,
    };
    const union_unnamed_4 = extern union {
        b: [20]u8,
        s: [10]c_short,
        l: [5]c_long,
    };
    pub const XClientMessageEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        message_type: Atom = 0,
        format: c_int = 0,
        data: union_unnamed_4 = @import("std").mem.zeroes(union_unnamed_4),
    };
    pub const XMappingEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
        request: c_int = 0,
        first_keycode: c_int = 0,
        count: c_int = 0,
    };
    pub const XErrorEvent = extern struct {
        type: c_int = 0,
        display: ?*Display = null,
        resourceid: XID = 0,
        serial: c_ulong = 0,
        error_code: u8 = 0,
        request_code: u8 = 0,
        minor_code: u8 = 0,
    };
    pub const XAnyEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        window: Window = 0,
    };
    pub const XGenericEvent = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        extension: c_int = 0,
        evtype: c_int = 0,
    };
    pub const XGenericEventCookie = extern struct {
        type: c_int = 0,
        serial: c_ulong = 0,
        send_event: c_int = 0,
        display: ?*Display = null,
        extension: c_int = 0,
        evtype: c_int = 0,
        cookie: c_uint = 0,
        data: ?*anyopaque = null,
    };

    pub const XEvent = extern union {
        type: c_int,
        xany: XAnyEvent,
        xkey: XKeyEvent,
        xbutton: XButtonEvent,
        xmotion: XMotionEvent,
        xcrossing: XCrossingEvent,
        xfocus: XFocusChangeEvent,
        xexpose: XExposeEvent,
        xgraphicsexpose: XGraphicsExposeEvent,
        xnoexpose: XNoExposeEvent,
        xvisibility: XVisibilityEvent,
        xcreatewindow: XCreateWindowEvent,
        xdestroywindow: XDestroyWindowEvent,
        xunmap: XUnmapEvent,
        xmap: XMapEvent,
        xmaprequest: XMapRequestEvent,
        xreparent: XReparentEvent,
        xconfigure: XConfigureEvent,
        xgravity: XGravityEvent,
        xresizerequest: XResizeRequestEvent,
        xconfigurerequest: XConfigureRequestEvent,
        xcirculate: XCirculateEvent,
        xcirculaterequest: XCirculateRequestEvent,
        xproperty: XPropertyEvent,
        xselectionclear: XSelectionClearEvent,
        xselectionrequest: XSelectionRequestEvent,
        xselection: XSelectionEvent,
        xcolormap: XColormapEvent,
        xclient: XClientMessageEvent,
        xmapping: XMappingEvent,
        xerror: XErrorEvent,
        xkeymap: XKeymapEvent,
        xgeneric: XGenericEvent,
        xcookie: XGenericEventCookie,
        pad: [24]c_long,
    };

    pub const XWindowAttributes = extern struct {
        x: c_int,
        y: c_int,
        width: c_int,
        height: c_int,
        border_width: c_int,
        depth: c_int,
        visual: *Visual,
        root: Window,
        class: c_int,
        bit_gravity: c_int,
        win_gravity: c_int,
        backing_store: c_int,
        backing_planes: c_ulong,
        backing_pixel: c_ulong,
        save_under: c_int,
        colormap: Colormap,
        map_installed: c_int,
        map_state: c_int,
        all_event_masks: c_long,
        your_event_mask: c_long,
        do_not_propagate_mask: c_long,
        override_redirect: c_int,
        screen: *Screen,
    };

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
    pub const XGetWindowAttributes = fn (display: ?*Display, window: Window, attributes: *XWindowAttributes) callconv(.c) Status;
    pub const XPending = fn (display: ?*Display) callconv(.c) c_int;
    pub const XNextEvent = fn (display: ?*Display, event: *XEvent) callconv(.c) c_int;
    pub const XSelectInput = fn (display: ?*Display, window: Window, event_mask: c_long) callconv(.c) c_int;
    pub const XInternAtom = fn (display: ?*Display, atom_name: [*c]const u8, only_if_exists: Bool) callconv(.c) Atom;
    pub const XSetWMProtocols = fn (display: ?*Display, window: Window, protocols: [*c]const Atom, count: c_int) callconv(.c) c_int;
};
