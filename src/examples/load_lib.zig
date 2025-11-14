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

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer if (gpa.deinit() != .ok) @panic("memory check failed");

    try dll.init(.{ .allocator = allocator, .log_level = .debug });
    defer dll.deinit();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len <= 1) {
        std.log.err("missing mandatory lib name", .{});
        return error.MissingLibName;
    }

    const lib_name = args[1];

    std.log.info("loading '{s}'...", .{lib_name});

    _ = try dll.load(lib_name);

    std.log.info("success", .{});
}
