const std = @import("std");

const dll = @import("dll");

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

const GError = extern struct {
    domain: u32,
    code: c_int,
    message: [*:0]const u8,
};

const Gst = struct {
    const Element = opaque {};
    const Bus = opaque {};

    const State = enum(c_int) { null = 1, playing = 4 };
    const StateChangeReturn = enum(c_int) { failure, success, async, no_preroll };
    const MessageType = enum(c_uint) { eos = 1, err = 2, _ };

    const MiniObject = extern struct {
        type: usize,
        refcount: c_int,
        lockstate: c_int,
        flags: c_uint,
        copy: ?*const fn (object: *const MiniObject) callconv(.c) ?*MiniObject,
        dispose: ?*const fn (object: *MiniObject) callconv(.c) c_int,
        free: ?*const fn (object: *MiniObject) callconv(.c) void,
        priv_uint: c_uint,
        priv_pointer: ?*anyopaque,
    };

    const Message = extern struct {
        mini_object: MiniObject,
        type: MessageType,
    };
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = init.minimal.args;
    const environ = init.minimal.environ;

    try dll.init(.{ .allocator = allocator, .io = io, .args = args, .environ = environ });
    defer dll.deinit();

    std.log.info("loading 'libgstreamer-1.0.so.0'...", .{});

    const lib_gst = try dll.load("libgstreamer-1.0.so.0");
    const lib_glib = try dll.load("libglib-2.0.so.0");

    const gstInitCheck: *const fn (argc: ?*c_int, argv: ?*?[*]?[*:0]u8, err: *?*GError) callconv(.c) c_int = @ptrFromInt((try lib_gst.getSymbol("gst_init_check")).addr);
    const gstDeinit: *const fn () callconv(.c) void = @ptrFromInt((try lib_gst.getSymbol("gst_deinit")).addr);
    const gstParseLaunch: *const fn (description: [*:0]const u8, err: *?*GError) callconv(.c) ?*Gst.Element = @ptrFromInt((try lib_gst.getSymbol("gst_parse_launch")).addr);
    const gstElementSetState: *const fn (element: *Gst.Element, state: Gst.State) callconv(.c) Gst.StateChangeReturn = @ptrFromInt((try lib_gst.getSymbol("gst_element_set_state")).addr);
    const gstElementGetBus: *const fn (element: *Gst.Element) callconv(.c) ?*Gst.Bus = @ptrFromInt((try lib_gst.getSymbol("gst_element_get_bus")).addr);
    const gstBusTimedPopFiltered: *const fn (bus: *Gst.Bus, timeout_ns: u64, types: c_uint) callconv(.c) ?*Gst.Message = @ptrFromInt((try lib_gst.getSymbol("gst_bus_timed_pop_filtered")).addr);
    const gstMessageParseError: *const fn (message: *Gst.Message, err: *?*GError, debug_text: *?[*:0]u8) callconv(.c) void = @ptrFromInt((try lib_gst.getSymbol("gst_message_parse_error")).addr);
    const gstMessageUnref: *const fn (message: *Gst.Message) callconv(.c) void = @ptrFromInt((try lib_gst.getSymbol("gst_message_unref")).addr);
    const gstObjectUnref: *const fn (object: *anyopaque) callconv(.c) void = @ptrFromInt((try lib_gst.getSymbol("gst_object_unref")).addr);
    const gErrorFree: *const fn (err: *GError) callconv(.c) void = @ptrFromInt((try lib_glib.getSymbol("g_error_free")).addr);
    const gFree: *const fn (memory: *anyopaque) callconv(.c) void = @ptrFromInt((try lib_glib.getSymbol("g_free")).addr);

    var gst_error: ?*GError = null;
    defer if (gst_error) |err| gErrorFree(err);

    if (gstInitCheck(null, null, &gst_error) == 0) {
        if (gst_error) |err| std.log.err("GStreamer initialization: {s}", .{err.message});
        return error.GStreamerInitializationFailed;
    }
    defer gstDeinit();

    // 100 buffers of 441 samples at 44.1 kHz produce one second of audio.
    const pipeline = gstParseLaunch(
        "audiotestsrc wave=sine freq=440 num-buffers=100 samplesperbuffer=441 ! " ++
            "audio/x-raw,format=F32LE,rate=44100,channels=1 ! audioconvert ! " ++
            "audio/x-raw,format=S16LE ! wavenc ! fakesink sync=false",
        &gst_error,
    );
    defer if (pipeline) |element| {
        _ = gstElementSetState(element, .null);
        gstObjectUnref(element);
    };

    if (gst_error) |err| {
        std.log.err("GStreamer pipeline: {s}", .{err.message});
        return error.PipelineCreationFailed;
    }

    const element = pipeline orelse return error.PipelineCreationFailed;

    const bus = gstElementGetBus(element) orelse return error.MissingBus;
    defer gstObjectUnref(bus);

    std.log.info("converting a one-second 440 Hz tone from float audio to 16-bit PCM WAV...", .{});

    const state_result = gstElementSetState(element, .playing);
    const timeout_ns: u64 = if (state_result == .failure) 0 else std.math.maxInt(u64);
    const message = gstBusTimedPopFiltered(bus, timeout_ns, @backingInt(Gst.MessageType.eos) | @backingInt(Gst.MessageType.err)) orelse {
        std.log.err("GStreamer pipeline could not start or its bus was shut down", .{});
        return error.PipelineFailed;
    };
    defer gstMessageUnref(message);

    switch (message.type) {
        .eos => std.log.info("conversion complete", .{}),
        .err => {
            var debug_text: ?[*:0]u8 = null;
            gstMessageParseError(message, &gst_error, &debug_text);
            defer if (debug_text) |text| gFree(text);

            if (gst_error) |err| std.log.err("GStreamer: {s}", .{err.message});
            if (debug_text) |text| std.log.err("{s}", .{text});

            return error.PipelineFailed;
        },
        else => return error.UnexpectedMessage,
    }
}
