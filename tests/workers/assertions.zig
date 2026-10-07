const std = @import("std");

const dll = @import("dll");
const elf = @import("elf_runner");
const elf_cases = @import("elf_cases").cases;
const lifecycle = @import("lifecycle_runner");
const lifecycle_cases = @import("lifecycle_cases").cases;

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

fn emit(init: std.process.Init, event: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(init.arena.allocator(), event, .{});
    try std.Io.File.stdout().writeStreamingAll(init.io, bytes);
    try std.Io.File.stdout().writeStreamingAll(init.io, "\n");
}

fn emitCatalog(init: std.process.Init) !void {
    const allocator = init.arena.allocator();

    for (elf_cases, 0..) |case, case_id| {
        const name = try std.fmt.allocPrint(allocator, "elf.{s}", .{case.name});
        try emit(init, .{
            .event = "case",
            .id = case_id,
            .name = name,
        });
    }

    for (lifecycle_cases, elf_cases.len..) |case, case_id| {
        const name = try std.fmt.allocPrint(allocator, "lifecycle.{s}", .{case.name});
        try emit(init, .{
            .event = "case",
            .id = case_id,
            .name = name,
        });
    }

    try emit(init, .{ .event = "ready", .count = elf_cases.len + lifecycle_cases.len });
}

fn validateFixtures(init: std.process.Init, resources_dir: []const u8) !void {
    try elf.validate(init, elf_cases, resources_dir);
    try lifecycle.validate(init, lifecycle_cases, resources_dir);
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const list_only = args.len == 2 and std.mem.eql(u8, args[1], "--list");
    const validate_and_list = args.len == 4 and std.mem.eql(u8, args[2], "--list");

    if (list_only or validate_and_list) {
        if (validate_and_list) {
            validateFixtures(init, args[1]) catch |err| {
                try emit(init, .{
                    .event = "error",
                    .stage = "fixture",
                    .message = @errorName(err),
                });
                std.process.exit(1);
            };
        }
        try emitCatalog(init);

        return;
    }

    if (args.len != 4) return error.InvalidArguments;

    const resources_dir = args[1];
    const case_id = try std.fmt.parseInt(usize, args[2], 10);

    if (case_id >= elf_cases.len + lifecycle_cases.len) return error.UnknownCase;

    try std.posix.setrlimit(.CORE, .{ .cur = 0, .max = 0 });

    if (case_id < elf_cases.len) {
        if (try elf.unavailableReason(init, elf_cases[case_id], resources_dir)) |reason| {
            try emit(init, .{ .event = "result", .id = case_id, .status = 2, .detail = reason });
            return;
        }
    }

    try emit(init, .{ .event = "stage", .stage = "assertion" });

    const result = if (case_id < elf_cases.len)
        elf.runCase(init, elf_cases, elf_cases[case_id].name, resources_dir, "/tmp")
    else
        lifecycle.runCase(init, lifecycle_cases, lifecycle_cases[case_id - elf_cases.len].name, resources_dir);

    result catch |err| {
        if (err == error.RequiredSymbolUnavailable) {
            try emit(init, .{ .event = "result", .id = case_id, .status = 2, .detail = "required runtime symbol is unavailable" });
            return;
        }
        try emit(init, .{
            .event = "error",
            .stage = "assertion",
            .message = @errorName(err),
        });

        std.process.exit(1);
    };

    try emit(init, .{
        .event = "result",
        .id = case_id,
        .status = 0,
    });
}
