const std = @import("std");

const dll = @import("dll");
const support = @import("behavior_support");

const Allocator = std.mem.Allocator;
const FailingAllocator = std.testing.FailingAllocator;
const malloc_alignment: std.mem.Alignment = .@"16";

const DlInfo = extern struct {
    name: [*:0]const u8,
    base: *anyopaque,
    symbol_name: ?[*:0]const u8,
    symbol_address: ?*anyopaque,
};

const OffsetAllocator = struct {
    failing: FailingAllocator,

    fn allocator(self: *OffsetAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = &alloc,
                .resize = &resize,
                .remap = &remap,
                .free = &free,
            },
        };
    }

    fn alloc(context: *anyopaque, length: usize, alignment: std.mem.Alignment, return_address: usize) ?[*]u8 {
        const self: *OffsetAllocator = @ptrCast(@alignCast(context));
        if (alignment != .@"1") return self.failing.allocator().rawAlloc(length, alignment, return_address);
        const total = std.math.add(usize, length, 1) catch return null;
        const memory = self.failing.allocator().rawAlloc(total, malloc_alignment, return_address) orelse return null;
        return memory + 1;
    }

    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, length: usize, return_address: usize) bool {
        const self: *OffsetAllocator = @ptrCast(@alignCast(context));
        if (alignment == .@"1") return false;
        return self.failing.allocator().rawResize(memory, alignment, length, return_address);
    }

    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, length: usize, return_address: usize) ?[*]u8 {
        const self: *OffsetAllocator = @ptrCast(@alignCast(context));
        if (alignment == .@"1") return null;
        return self.failing.allocator().rawRemap(memory, alignment, length, return_address);
    }

    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, return_address: usize) void {
        const self: *OffsetAllocator = @ptrCast(@alignCast(context));
        if (alignment != .@"1") return self.failing.allocator().rawFree(memory, alignment, return_address);
        self.failing.allocator().rawFree((memory.ptr - 1)[0 .. memory.len + 1], malloc_alignment, return_address);
    }

    fn failAfter(self: *OffsetAllocator, count: usize) void {
        self.failing.fail_index = self.failing.alloc_index + count;
        self.failing.resize_fail_index = self.failing.resize_index;
        self.failing.has_induced_failure = false;
    }

    fn recover(self: *OffsetAllocator) void {
        self.failing.fail_index = std.math.maxInt(usize);
        self.failing.resize_fail_index = std.math.maxInt(usize);
    }
};

fn symbol(comptime T: type, name: []const u8) !T {
    const resolved = dll.getSymbol(name) catch |err| {
        std.debug.print("failure-recovery: resolving {s}: {}\n", .{ name, err });
        return err;
    };
    return @ptrFromInt(resolved.addr);
}

fn threadCallback(argument: ?*anyopaque) callconv(.c) *anyopaque {
    return argument.?;
}

fn countObjects(_: *anyopaque, _: c_uint, data: ?*anyopaque) callconv(.c) c_int {
    const count: *usize = @ptrCast(@alignCast(data.?));
    count.* += 1;
    return 0;
}

pub fn run(init: std.process.Init, fixtures: support.SpecificContext) !void {
    var memory: OffsetAllocator = .{ .failing = .init(init.gpa, .{}) };
    try dll.init(.{
        .allocator = memory.allocator(),
        .io = init.io,
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
    defer dll.deinit();
    defer memory.recover();

    const bridge = try support.Bridge.init(fixtures.bridge_path, fixtures.bridge_symbols);
    _ = try dll.load(fixtures.target_path);

    const malloc = try symbol(*const fn (size: usize) callconv(.c) ?*anyopaque, "malloc");
    const calloc = try symbol(*const fn (count: usize, size: usize) callconv(.c) ?*anyopaque, "calloc");
    const aligned_alloc = try symbol(*const fn (alignment: usize, size: usize) callconv(.c) ?*anyopaque, "aligned_alloc");
    const posix_memalign = try symbol(*const fn (output: **anyopaque, alignment: usize, size: usize) callconv(.c) c_int, "posix_memalign");
    const realloc = try symbol(*const fn (pointer: ?*anyopaque, size: usize) callconv(.c) ?*anyopaque, "realloc");
    const free = try symbol(*const fn (pointer: ?*anyopaque) callconv(.c) void, "free");
    const errno_location = try symbol(*const fn () callconv(.c) *c_int, "__errno_location");
    const dlerror = try symbol(*const fn () callconv(.c) ?[*:0]const u8, "dlerror");
    const dlsym = try symbol(*const fn (handle: ?*anyopaque, name: [*:0]const u8) callconv(.c) ?*anyopaque, "dlsym");
    const dladdr = try symbol(*const fn (address: *anyopaque, info: *DlInfo) callconv(.c) c_int, "dladdr");
    const target_address: *anyopaque = @ptrFromInt((try dll.getSymbol("readState")).addr);
    const iterate = try symbol(*const fn (callback: *const fn (*anyopaque, c_uint, ?*anyopaque) callconv(.c) c_int, data: ?*anyopaque) callconv(.c) c_int, "dl_iterate_phdr");

    // Fail both early bookkeeping and later payload allocations, then verify
    // that the allocator remains usable after each attempt.
    for (0..4) |failure_offset| {
        memory.failAfter(failure_offset);
        const pointer = malloc(37);
        memory.recover();
        if (pointer) |allocation| {
            free(allocation);
        } else {
            try std.testing.expect(memory.failing.has_induced_failure);
            try std.testing.expectEqual(@as(c_int, @backingInt(std.os.linux.E.NOMEM)), errno_location().*);
        }
    }

    memory.failAfter(0);
    try std.testing.expect(calloc(7, 9) == null);
    try std.testing.expect(aligned_alloc(64, 128) == null);
    var output: *anyopaque = @ptrFromInt(0x1230);
    errno_location().* = 123;
    try std.testing.expectEqual(@as(c_int, @backingInt(std.os.linux.E.NOMEM)), posix_memalign(&output, 64, 128));
    try std.testing.expectEqual(@as(usize, 0x1230), @intFromPtr(output));
    try std.testing.expectEqual(@as(c_int, 123), errno_location().*);
    memory.recover();

    var pointer = malloc(37) orelse return error.AllocationFailed;
    defer free(pointer);
    @memset(@as([*]u8, @ptrCast(pointer))[0..37], 0xa7);

    memory.failAfter(0);
    try std.testing.expect(realloc(pointer, 1024) == null);
    memory.recover();
    for (@as([*]const u8, @ptrCast(pointer))[0..37]) |byte| try std.testing.expectEqual(@as(u8, 0xa7), byte);

    try std.testing.expect(malloc(std.math.maxInt(usize)) == null);
    pointer = realloc(pointer, 128) orelse return error.AllocationFailed;
    for (@as([*]const u8, @ptrCast(pointer))[0..37]) |byte| try std.testing.expectEqual(@as(u8, 0xa7), byte);

    memory.failAfter(0);
    try std.testing.expect(dlsym(null, "dynloader_missing_symbol_for_failure_test") == null);
    const message = dlerror() orelse return error.MissingDiagnostic;
    try std.testing.expect(std.mem.span(message).len != 0);
    try std.testing.expect(dlerror() == null);
    const long_name: [4096:0]u8 = @splat('x');
    try std.testing.expect(dlsym(null, &long_name) == null);
    const fallback = dlerror() orelse return error.MissingDiagnostic;
    try std.testing.expect(std.mem.indexOf(u8, std.mem.span(fallback), "diagnostic exceeds buffer") != null);

    var object_count: usize = 0;
    try std.testing.expectEqual(@as(c_int, 0), iterate(&countObjects, &object_count));
    try std.testing.expect(object_count != 0);
    memory.recover();

    var open_succeeded = false;
    var open_failed = false;
    for (0..16) |failure_offset| {
        memory.failAfter(failure_offset);
        const opened = bridge.openLibrary(fixtures.target_path.ptr);
        memory.recover();
        if (opened) |library| {
            open_succeeded = true;
            try std.testing.expectEqual(@as(c_int, 0), bridge.closeLibrary(library));
        } else {
            open_failed = true;
            try std.testing.expect(memory.failing.has_induced_failure);
            try std.testing.expect(dlerror() != null);
        }
    }
    try std.testing.expect(open_succeeded and open_failed);

    var address_succeeded = false;
    var address_failed = false;
    for (0..8) |failure_offset| {
        var info: DlInfo = undefined;
        memory.failAfter(failure_offset);
        const result = dladdr(target_address, &info);
        memory.recover();
        if (result == 0) {
            address_failed = true;
            try std.testing.expect(memory.failing.has_induced_failure);
            try std.testing.expect(dlerror() != null);
        } else {
            address_succeeded = true;
            try std.testing.expect(info.symbol_address == target_address);
        }
    }
    try std.testing.expect(address_succeeded and address_failed);

    for (0..4) |failure_offset| {
        var handle: usize = 0x1230;
        memory.failAfter(failure_offset);
        const result = bridge.startThread(&handle, &threadCallback, pointer);
        memory.recover();
        if (result == 0) {
            try std.testing.expectEqual(@as(c_int, 0), bridge.joinThread(handle));
        } else {
            try std.testing.expectEqual(@as(c_int, @backingInt(std.os.linux.E.AGAIN)), result);
            try std.testing.expectEqual(@as(usize, 0x1230), handle);
        }
    }

    // Force std.Thread.spawn's mapping to fail after bookkeeping is prepared.
    const previous_limit = try std.posix.getrlimit(.AS);
    const live_bytes = memory.failing.allocated_bytes - memory.failing.freed_bytes;
    var handle: usize = 0x1230;
    try std.posix.setrlimit(.AS, .{ .cur = 0, .max = previous_limit.max });
    const spawn_result = bridge.startThread(&handle, &threadCallback, pointer);
    try std.posix.setrlimit(.AS, previous_limit);
    try std.testing.expectEqual(@as(c_int, @backingInt(std.os.linux.E.AGAIN)), spawn_result);
    try std.testing.expectEqual(@as(usize, 0x1230), handle);
    try std.testing.expectEqual(live_bytes, memory.failing.allocated_bytes - memory.failing.freed_bytes);

    try std.testing.expectEqual(@as(c_int, 0), bridge.startThread(&handle, &threadCallback, pointer));
    try std.testing.expectEqual(@as(c_int, 0), bridge.joinThread(handle));
    try std.testing.expectEqual(@as(c_int, @backingInt(std.os.linux.E.SRCH)), bridge.joinThread(handle));
}

pub fn runReallocarray(init: std.process.Init, fixtures: support.SpecificContext) !void {
    var memory: OffsetAllocator = .{ .failing = .init(init.gpa, .{}) };
    try dll.init(.{
        .allocator = memory.allocator(),
        .io = init.io,
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
    defer dll.deinit();
    defer memory.recover();
    _ = try dll.load(fixtures.bridge_path);

    const resolved = dll.getSymbol("reallocarray") catch |err| switch (err) {
        error.UnresolvedSymbol => return error.RequiredSymbolUnavailable,
        else => return err,
    };
    const reallocarray: *const fn (pointer: ?*anyopaque, count: usize, size: usize) callconv(.c) ?*anyopaque = @ptrFromInt(resolved.addr);
    const malloc = try symbol(*const fn (size: usize) callconv(.c) ?*anyopaque, "malloc");
    const free = try symbol(*const fn (pointer: ?*anyopaque) callconv(.c) void, "free");
    const errno_location = try symbol(*const fn () callconv(.c) *c_int, "__errno_location");

    const pointer = malloc(37) orelse return error.AllocationFailed;
    defer free(pointer);
    @memset(@as([*]u8, @ptrCast(pointer))[0..37], 0xa7);
    memory.failAfter(0);
    try std.testing.expect(reallocarray(pointer, 16, 64) == null);
    memory.recover();
    try std.testing.expectEqual(@as(c_int, @backingInt(std.os.linux.E.NOMEM)), errno_location().*);
    try std.testing.expect(reallocarray(pointer, std.math.maxInt(usize), 2) == null);
    for (@as([*]const u8, @ptrCast(pointer))[0..37]) |byte| try std.testing.expectEqual(@as(u8, 0xa7), byte);
}
