const std = @import("std");
const builtin = @import("builtin");

const dll = @import("dll");

pub const std_options: std.Options = .{
    .log_scope_levels = &.{.{
        .scope = .dynamic_library_loader,
        .level = .debug,
    }},
};

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = init.minimal.args;
    const environ = init.minimal.environ;

    try dll.init(.{ .allocator = allocator, .io = io, .args = args, .environ = environ, .log_level = .debug });
    defer dll.deinit();

    const args_slice = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args_slice);

    if (args_slice.len <= 1) {
        std.log.err("missing mandatory lib name", .{});
        return error.MissingLibName;
    }

    for (args_slice[1..]) |arg| {
        const lib_name = arg;

        std.log.info("loading '{s}'...", .{lib_name});

        _ = try dll.load(lib_name);
    }

    std.log.info("success", .{});
}
