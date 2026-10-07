const std = @import("std");

const dll = @import("dll");
const support = @import("behavior_support");
const LibraryState = @import("regression_abi").LibraryState;

const ReadState = *const fn (state: *LibraryState) callconv(.c) void;
const SetTls = *const fn (value: u32) callconv(.c) void;

const HostTlsIndex = extern struct {
    module: usize,
    offset: usize,
};
extern fn __tls_get_addr(index: *const HostTlsIndex) callconv(.c) *anyopaque;

const HostTlsContext = struct {
    read: ReadState,
    set: SetTls,
    completed: bool = false,
};

threadlocal var host_initialized: usize = 17;
threadlocal var host_zeroed: usize = 0;
threadlocal var host_buffer: [65536]u8 align(4096) = @splat(0);

pub fn run(init: std.process.Init, fixtures: support.SpecificContext) !void {
    try expectInitialHostTls();
    mutateHostTls();
    {
        const thread = try std.Thread.spawn(.{}, hostTlsThread, .{});
        thread.join();
    }

    try initHostTlsLoader(init);
    defer dll.deinit();

    const bridge = try support.Bridge.init(fixtures.bridge_path, fixtures.bridge_symbols);
    try checkMutatedHostTls();

    const target = try dll.load(fixtures.target_path);
    try checkMutatedHostTls();

    const read: ReadState = @ptrFromInt((try target.getSymbol("readState")).addr);
    const set: SetTls = @ptrFromInt((try target.getSymbol("setTls")).addr);
    var state: LibraryState = undefined;
    read(&state);
    try std.testing.expectEqual(@as(u32, 11), state.tls_value);
    set(55);

    {
        const thread = try std.Thread.spawn(.{}, hostTlsThread, .{});
        thread.join();
    }

    var context: HostTlsContext = .{ .read = read, .set = set };
    var handle: usize = undefined;
    try std.testing.expectEqual(@as(c_int, 0), bridge.startThread(&handle, &hostTlsCallback, &context));
    try std.testing.expectEqual(@as(c_int, 0), bridge.joinThread(handle));
    try std.testing.expect(context.completed);

    read(&state);
    try std.testing.expectEqual(@as(u32, 55), state.tls_value);
    try checkMutatedHostTls();

    dll.deinit();
    try checkMutatedHostTls();
    {
        const thread = try std.Thread.spawn(.{}, hostTlsThread, .{});
        thread.join();
    }
    try checkMutatedHostTls();

    try std.testing.expectError(error.ReinitializationUnsupported, initHostTlsLoader(init));
}

fn checkHostTlsAccessor() !void {
    const phdrs: [*]const std.elf.ElfN.Phdr = @ptrFromInt(std.os.linux.getauxval(std.elf.AT.PHDR));
    var executable_tp_offset: usize = 0;
    for (phdrs[0..std.os.linux.getauxval(std.elf.AT.PHNUM)]) |header| {
        if (header.type == .TLS) {
            executable_tp_offset = std.mem.alignForward(usize, header.memsz, header.@"align");
        }
    }
    try std.testing.expect(executable_tp_offset >= host_buffer.len);

    const thread_pointer = asm ("movq %%fs:0, %[result]"
        : [result] "=r" (-> usize),
    );
    const executable_block_address = thread_pointer - executable_tp_offset;
    for ([_]usize{ @intFromPtr(&host_initialized), @intFromPtr(&host_zeroed), @intFromPtr(&host_buffer) }) |address| {
        const index: HostTlsIndex = .{ .module = 1, .offset = address - executable_block_address };
        try std.testing.expectEqual(address, @intFromPtr(__tls_get_addr(&index)));
    }
}

fn expectInitialHostTls() !void {
    try std.testing.expectEqual(@as(usize, 17), host_initialized);
    try std.testing.expectEqual(@as(usize, 0), host_zeroed);
    try std.testing.expectEqual(@as(u8, 0), host_buffer[0]);
    try std.testing.expectEqual(@as(u8, 0), host_buffer[host_buffer.len - 1]);
    try checkHostTlsAccessor();
}

fn mutateHostTls() void {
    host_initialized = 99;
    host_zeroed = 100;
    host_buffer[0] = 101;
    host_buffer[host_buffer.len - 1] = 102;
}

fn hostTlsThread() void {
    expectInitialHostTls() catch @panic("fresh host TLS regression");
    mutateHostTls();
}

fn checkMutatedHostTls() !void {
    try std.testing.expectEqual(@as(usize, 99), host_initialized);
    try std.testing.expectEqual(@as(usize, 100), host_zeroed);
    try std.testing.expectEqual(@as(u8, 101), host_buffer[0]);
    try std.testing.expectEqual(@as(u8, 102), host_buffer[host_buffer.len - 1]);
    try checkHostTlsAccessor();
}

fn hostTlsCallback(argument: ?*anyopaque) callconv(.c) *anyopaque {
    const context: *HostTlsContext = @ptrCast(@alignCast(argument.?));
    expectInitialHostTls() catch @panic("callback host TLS regression");
    mutateHostTls();

    var state: LibraryState = undefined;
    context.read(&state);
    if (state.tls_value != 11) @panic("fresh library TLS regression");

    context.set(77);
    context.read(&state);
    if (state.tls_value != 77) @panic("library TLS mutation regression");

    checkMutatedHostTls() catch @panic("callback host TLS isolation regression");

    context.completed = true;
    return argument.?;
}

fn initHostTlsLoader(init: std.process.Init) !void {
    try dll.init(.{
        .allocator = init.gpa,
        .io = init.io,
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
}
