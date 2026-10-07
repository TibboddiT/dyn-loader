const std = @import("std");

const dll = @import("dll");

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

const abi_version = 1;
const HostApi = extern struct {
    abi_version: u32 = abi_version,
    struct_size: u32 = @sizeOf(HostApi),
    callback: *const fn (context: ?*anyopaque, value: u32) callconv(.c) u32,
    context: ?*anyopaque,
};

const CaseInfo = extern struct {
    struct_size: u32 = @sizeOf(CaseInfo),
    id: u32 = 0,
    name: [64]u8 = @splat(0),
};

const ProbeResult = extern struct {
    struct_size: u32 = @sizeOf(ProbeResult),
    status: u32 = 0,
    line: u32 = 0,
    saved_errno: i32 = 0,
    expected: i64 = 0,
    observed: i64 = 0,
    detail: [192]u8 = @splat(0),
};

const CallbackContext = struct { calls: u32 = 0 };

const ReadU32 = *const fn () callconv(.c) u32;
const DescribeCase = *const fn (case_id: u32, info: *CaseInfo) callconv(.c) c_int;
const RunCase = *const fn (case_id: u32, host: *const HostApi, result: *ProbeResult) callconv(.c) c_int;

threadlocal var host_tls: u32 = 17;

fn hostCallback(argument: ?*anyopaque, value: u32) callconv(.c) u32 {
    const context: *CallbackContext = @ptrCast(@alignCast(argument.?));
    context.calls += 1;

    if (host_tls != 17) return 0;

    host_tls = 99;

    return value + 1;
}

// Log writes use syscalls so they do not depend on the libc under test.
fn writeAllTo(fd: i32, bytes: []const u8) void {
    var remaining = bytes;
    while (remaining.len != 0) {
        const write_result = std.os.linux.write(fd, remaining.ptr, remaining.len);
        switch (std.os.linux.errno(write_result)) {
            .SUCCESS => {
                if (write_result == 0) {
                    std.process.exit(3);
                }

                remaining = remaining[write_result..];
            },
            .INTR => continue,
            else => std.process.exit(3),
        }
    }
}

fn dumpMappings() void {
    const path: [:0]const u8 = "/proc/self/maps";
    const open_result = std.os.linux.syscall4(.openat, @bitCast(@as(isize, std.os.linux.AT.FDCWD)), @intFromPtr(path.ptr), 0, 0);

    if (std.os.linux.errno(open_result) != .SUCCESS) return;

    const fd: i32 = @intCast(open_result);
    defer _ = std.os.linux.close(fd);

    writeAllTo(2, "Loaded object mappings:\n");

    var buffer: [4096]u8 = undefined;
    while (true) {
        const read_result = std.os.linux.read(fd, &buffer, buffer.len);

        if (std.os.linux.errno(read_result) == .INTR) continue;
        if (std.os.linux.errno(read_result) != .SUCCESS or read_result == 0) break;

        writeAllTo(2, buffer[0..read_result]);
    }
}

fn emit(allocator: std.mem.Allocator, event: anytype) void {
    const bytes = std.json.Stringify.valueAlloc(allocator, event, .{}) catch std.process.exit(3);
    defer allocator.free(bytes);

    writeAllTo(1, bytes);
    writeAllTo(1, "\n");
}

fn fail(allocator: std.mem.Allocator, stage: []const u8, message: []const u8) noreturn {
    emit(allocator, .{
        .event = "error",
        .stage = stage,
        .message = message,
    });

    std.process.exit(2);
}

fn resolveFunction(comptime Function: type, allocator: std.mem.Allocator, library: dll.DynamicLibrary, name: []const u8) Function {
    const symbol = library.getSymbol(name) catch |err| fail(allocator, "abi", @errorName(err));

    return @ptrFromInt(symbol.addr);
}

pub fn main(init: std.process.Init) void {
    const allocator = init.gpa;

    const args = init.minimal.args.toSlice(init.arena.allocator()) catch fail(allocator, "arguments", "argument allocation failed");

    if (args.len != 3) fail(allocator, "arguments", "usage: libc-runner LIBRARY --list|CASE_ID");

    std.posix.setrlimit(.CORE, .{ .cur = 0, .max = 0 }) catch {};

    host_tls = 41;

    emit(allocator, .{ .event = "stage", .stage = "init" });

    dll.init(.{
        .allocator = allocator,
        .io = init.io,
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .err,
    }) catch |err| fail(allocator, "init", @errorName(err));

    emit(allocator, .{ .event = "stage", .stage = "load" });

    const library = dll.load(args[1]) catch |err| fail(allocator, "load", @errorName(err));

    emit(allocator, .{ .event = "stage", .stage = "abi" });

    const read_version = resolveFunction(ReadU32, allocator, library, "probe_abi_version");
    const result_size = resolveFunction(ReadU32, allocator, library, "probe_result_size");
    const case_size = resolveFunction(ReadU32, allocator, library, "probe_case_info_size");
    const host_size = resolveFunction(ReadU32, allocator, library, "probe_host_api_size");

    const abi_matches = read_version() == abi_version and
        result_size() == @sizeOf(ProbeResult) and
        case_size() == @sizeOf(CaseInfo) and
        host_size() == @sizeOf(HostApi);

    if (!abi_matches) fail(allocator, "abi", "ABI layout/version mismatch");

    const case_count = resolveFunction(ReadU32, allocator, library, "probe_case_count")();
    const describe_case = resolveFunction(DescribeCase, allocator, library, "probe_describe");
    const run_case = resolveFunction(RunCase, allocator, library, "probe_run");

    if (std.mem.eql(u8, args[2], "--list")) {
        dumpMappings();

        for (0..case_count) |case_index| {
            var info: CaseInfo = .{};

            if (describe_case(@intCast(case_index), &info) != 0) fail(allocator, "abi", "describe failed");

            emit(allocator, .{
                .event = "case",
                .id = info.id,
                .name = std.mem.sliceTo(&info.name, 0),
            });
        }
        emit(allocator, .{ .event = "ready", .count = case_count });

        std.process.exit(0);
    }

    const case_id = std.fmt.parseInt(u32, args[2], 10) catch fail(allocator, "arguments", "invalid case ID");
    if (case_id >= case_count) {
        fail(allocator, "arguments", "invalid case ID");
    }

    var callback_context: CallbackContext = .{};

    const host: HostApi = .{
        .callback = &hostCallback,
        .context = &callback_context,
    };

    var result: ProbeResult = .{};

    emit(allocator, .{ .event = "stage", .stage = "run" });

    if (run_case(case_id, &host, &result) != 0) {
        fail(allocator, "abi", "probe_run failed");
    }

    const host_callback_case_id = 10;
    const callback_count_valid = case_id != host_callback_case_id or callback_context.calls == 1;

    if (host_tls != 41 or !callback_count_valid) {
        fail(allocator, "run", "host TLS/callback validation failed");
    }

    emit(allocator, .{
        .event = "result",
        .id = case_id,
        .status = result.status,
        .line = result.line,
        .saved_errno = result.saved_errno,
        .expected = result.expected,
        .observed = result.observed,
        .detail = std.mem.sliceTo(&result.detail, 0),
    });

    std.process.exit(if (result.status == 1) 1 else 0);
}
