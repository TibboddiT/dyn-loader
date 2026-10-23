//! Checks character conversion after loading and from a library constructor.

const std = @import("std");

const dyn_loader = @import("dyn_loader");
const support = @import("behavior_support");

pub fn run(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try dyn_loader.init(.{
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
    defer dyn_loader.deinit();

    const library = try dyn_loader.load(fixtures.target_path);
    const open: *const fn ([*:0]const u8, [*:0]const u8) callconv(.c) usize = @ptrFromInt((try library.getSymbol("iconv_open")).addr);
    const convert: *const fn (usize, *[*]const u8, *usize, *[*]u8, *usize) callconv(.c) usize = @ptrFromInt((try library.getSymbol("iconv")).addr);
    const close: *const fn (usize) callconv(.c) c_int = @ptrFromInt((try library.getSymbol("iconv_close")).addr);
    const lookup: *const fn (?*anyopaque, [*:0]const u8) callconv(.c) ?*anyopaque = @ptrFromInt((try library.getSymbol("dlsym")).addr);
    const readError: *const fn () callconv(.c) ?[*:0]const u8 = @ptrFromInt((try library.getSymbol("dlerror")).addr);

    // Conversion must preserve a pending loader error, including when libc
    // internally loads a module and probes optional entry points.
    try std.testing.expect(lookup(null, "dynloader_iconv_missing_symbol") == null);

    const invalid = std.math.maxInt(usize);
    for (0..2) |_| {
        const descriptor = open("UTF-32LE", "UTF-8");
        if (descriptor == invalid) return error.IconvOpenFailed;
        errdefer _ = close(descriptor);

        const input = "A\xc3\xa9\xf0\x9f\x99\x82";
        var input_pointer: [*]const u8 = input;
        var input_left: usize = input.len;
        var output: [32]u8 = undefined;
        var output_pointer: [*]u8 = &output;
        var output_left: usize = output.len;

        try std.testing.expectEqual(@as(usize, 0), convert(descriptor, &input_pointer, &input_left, &output_pointer, &output_left));
        try std.testing.expectEqual(@as(usize, 0), input_left);
        try std.testing.expectEqualSlices(u8, &.{ 0x41, 0, 0, 0, 0xe9, 0, 0, 0, 0x42, 0xf6, 1, 0 }, output[0 .. output.len - output_left]);
        try std.testing.expectEqual(@as(c_int, 0), close(descriptor));
    }

    const message = readError() orelse return error.MissingDlError;
    try std.testing.expect(std.mem.indexOf(u8, std.mem.span(message), "dynloader_iconv_missing_symbol") != null);
    try std.testing.expect(readError() == null);
    try std.testing.expectEqual(invalid, open("DYNLOADER-NONEXISTENT-CHARSET", "UTF-8"));
    try std.testing.expect(readError() == null);
}

pub fn runConstructor(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try dyn_loader.init(.{
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
    defer dyn_loader.deinit();

    const library = try dyn_loader.load(fixtures.target_path);
    const count: *const c_uint = @ptrFromInt((try library.getSymbol("constructor_count")).addr);
    const status: *const c_int = @ptrFromInt((try library.getSymbol("constructor_status")).addr);
    const output: *const [12]u8 = @ptrFromInt((try library.getSymbol("converted")).addr);

    try std.testing.expectEqual(@as(c_uint, 1), count.*);
    try std.testing.expectEqual(@as(c_int, 0), status.*);
    try std.testing.expectEqualSlices(u8, &.{ 0x41, 0, 0, 0, 0xe9, 0, 0, 0, 0x42, 0xf6, 1, 0 }, output);
}
