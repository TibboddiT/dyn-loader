const std = @import("std");
const dll = @import("dll");

const library_out_params = @import("../library_out_params.zig");

const LibraryState = library_out_params.LibraryState;
const FinalizationEvents = library_out_params.FinalizationEvents;
const TlsDestructorEvents = library_out_params.TlsDestructorEvents;

const ReadState = *const fn (*LibraryState) callconv(.c) void;
const Mutate = *const fn (*FinalizationEvents) callconv(.c) void;
const SetTls = *const fn (u32) callconv(.c) void;
const RegisterTls = *const fn (*TlsDestructorEvents) callconv(.c) c_int;
const ThreadRoutine = *const fn (?*anyopaque) callconv(.c) *anyopaque;

pub const Case = struct {
    name: []const u8,
    bridge: []const u8,
    bridge_symbols: BridgeSymbols,
    library: []const u8,
    requires: Prerequisites = .{},
    behavior: Behavior,
};

pub const Prerequisites = struct {
    tls_size_greater_than: ?u64 = null,
};

pub const BridgeSymbols = struct {
    open: []const u8,
    symbol: []const u8,
    close: []const u8,
    start_thread: []const u8,
    join_thread: []const u8,
};

pub const ReloadSymbols = struct {
    read_state: [:0]const u8,
    mutate: [:0]const u8,
    set_tls: [:0]const u8,
};

pub const TlsDestructorSymbols = struct {
    read_state: [:0]const u8,
    mutate: [:0]const u8,
    set_tls: [:0]const u8,
    register_tls_destructor: [:0]const u8,
};

pub const DependencySymbols = struct {
    provider_mutate: [:0]const u8,
    consumer_read_state: [:0]const u8,
    consumer_observe_finalization: [:0]const u8,
};

pub const Behavior = union(enum) {
    reload_cycles: ReloadCycles,
    pending_tls_destructor: PendingTlsDestructor,
    dependency_lifetime: DependencyLifetime,
};

pub const ReloadCycles = struct {
    symbols: ReloadSymbols,
    cycles: u32,
    expected_initial: LibraryState,
    expected_mutated: LibraryState,
    worker_tls_value: u32,
};

pub const PendingTlsDestructor = struct {
    symbols: TlsDestructorSymbols,
    expected_initial: LibraryState,
    expected_mutated: LibraryState,
    worker_tls_value: u32,
    expected_tls_destructor: TlsDestructorEvents,
};

pub const DependencyLifetime = struct {
    consumer: []const u8,
    symbols: DependencySymbols,
    expected_initial: LibraryState,
    expected_mutated: LibraryState,
};

const Bridge = struct {
    open_fn: *const fn ([*:0]const u8) callconv(.c) ?*anyopaque,
    symbol_fn: *const fn (*anyopaque, [*:0]const u8) callconv(.c) ?*anyopaque,
    close_fn: *const fn (*anyopaque) callconv(.c) c_int,
    start_fn: *const fn (*usize, ThreadRoutine, ?*anyopaque) callconv(.c) c_int,
    join_fn: *const fn (usize) callconv(.c) c_int,

    fn init(path: []const u8, symbols: BridgeSymbols) !Bridge {
        const library = try dll.load(path);
        return .{
            .open_fn = @ptrFromInt(try symbolAddress(library, symbols.open)),
            .symbol_fn = @ptrFromInt(try symbolAddress(library, symbols.symbol)),
            .close_fn = @ptrFromInt(try symbolAddress(library, symbols.close)),
            .start_fn = @ptrFromInt(try symbolAddress(library, symbols.start_thread)),
            .join_fn = @ptrFromInt(try symbolAddress(library, symbols.join_thread)),
        };
    }

    fn symbolAddress(library: dll.DynamicLibrary, name: []const u8) !usize {
        const resolved = library.getSymbol(name) catch |err| {
            std.debug.print("unable to resolve bridge symbol '{s}': {s}\n", .{ name, @errorName(err) });
            return err;
        };
        return resolved.addr;
    }

    fn open(bridge: Bridge, path: [:0]const u8) !*anyopaque {
        return bridge.open_fn(path) orelse error.OpenFailed;
    }

    fn symbol(bridge: Bridge, comptime T: type, handle: *anyopaque, name: [:0]const u8) !T {
        const address = bridge.symbol_fn(handle, name) orelse {
            std.debug.print("unable to resolve symbol '{s}'\n", .{name});
            return error.SymbolMissing;
        };
        return @ptrCast(address);
    }

    fn close(bridge: Bridge, handle: *anyopaque) !void {
        try std.testing.expectEqual(@as(c_int, 0), bridge.close_fn(handle));
    }
};

const Worker = struct {
    phase: std.atomic.Value(enum(u32) { idle, work, done, stop }) = .init(.idle),
    read: ReadState = undefined,
    set_tls: SetTls = undefined,
    tls_value: u32,
    register: ?RegisterTls = null,
    values: LibraryState = undefined,
    tls_events: TlsDestructorEvents = .{},
    registration_result: c_int = -1,

    fn exercise(worker: *Worker) void {
        worker.phase.store(.work, .release);
        while (worker.phase.load(.acquire) != .done) std.atomic.spinLoopHint();
        worker.phase.store(.idle, .release);
    }

    fn stop(worker: *Worker, bridge: Bridge, thread: usize) !void {
        worker.phase.store(.stop, .release);
        try std.testing.expectEqual(@as(c_int, 0), bridge.join_fn(thread));
    }
};

fn workerRoutine(argument: ?*anyopaque) callconv(.c) *anyopaque {
    const worker: *Worker = @ptrCast(@alignCast(argument.?));
    while (true) {
        switch (worker.phase.load(.acquire)) {
            .work => {
                worker.read(&worker.values);
                worker.set_tls(worker.tls_value);
                if (worker.register) |register| worker.registration_result = register(&worker.tls_events);
                worker.phase.store(.done, .release);
            },
            .stop => return argument.?,
            else => std.atomic.spinLoopHint(),
        }
    }
}

pub fn run(runner: anytype, cases: []const Case) void {
    for (cases) |case| runner.runCase("lifecycle", case.name);
}

pub fn runCase(init: std.process.Init, cases: []const Case, name: []const u8, resources: []const u8) !void {
    const case = for (cases) |case| {
        if (std.mem.eql(u8, name, case.name)) break case;
    } else return error.UnknownCase;

    const target_path = try std.fmt.allocPrintSentinel(init.gpa, "{s}/{s}", .{ resources, case.library }, 0);
    defer init.gpa.free(target_path);

    if (case.requires.tls_size_greater_than) |size| try expectTlsSizeGreaterThan(init.io, target_path, size);

    const bridge_path = try std.fs.path.join(init.gpa, &.{ resources, case.bridge });
    defer init.gpa.free(bridge_path);

    try dll.init(.{ .allocator = init.gpa, .io = init.io, .args = init.minimal.args, .environ = init.minimal.environ, .log_level = .none });
    defer dll.deinit();

    const bridge = try Bridge.init(bridge_path, case.bridge_symbols);

    switch (case.behavior) {
        .reload_cycles => |options| try reloadCycles(bridge, target_path, options),
        .pending_tls_destructor => |options| try pendingTlsDestructor(bridge, target_path, options),
        .dependency_lifetime => |options| {
            const consumer_path = try std.fmt.allocPrintSentinel(init.gpa, "{s}/{s}", .{ resources, options.consumer }, 0);
            defer init.gpa.free(consumer_path);

            try sharedDependency(bridge, target_path, consumer_path, options);
        },
    }
}

fn expectTlsSizeGreaterThan(io: std.Io, path: []const u8, size: u64) !void {
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);

    var header: std.elf.Elf64_Ehdr = undefined;
    try std.testing.expectEqual(@sizeOf(std.elf.Elf64_Ehdr), try file.readPositional(io, &.{std.mem.asBytes(&header)}, 0));
    try std.testing.expectEqualSlices(u8, std.elf.MAGIC, header.e_ident[0..4]);
    try std.testing.expectEqual(std.elf.ELFCLASS64, header.e_ident[std.elf.EI_CLASS]);
    try std.testing.expectEqual(std.elf.ELFDATA2LSB, header.e_ident[std.elf.EI_DATA]);
    try std.testing.expectEqual(@sizeOf(std.elf.Elf64.Phdr), header.e_phentsize);

    const file_size = (try file.stat(io)).size;
    try std.testing.expect(header.e_phoff <= file_size);
    try std.testing.expect(@as(u64, header.e_phnum) * header.e_phentsize <= file_size - header.e_phoff);

    for (0..header.e_phnum) |idx| {
        var ph: std.elf.Elf64.Phdr = undefined;
        const offset = header.e_phoff + idx * header.e_phentsize;
        try std.testing.expectEqual(@sizeOf(std.elf.Elf64.Phdr), try file.readPositional(io, &.{std.mem.asBytes(&ph)}, offset));
        if (ph.type == .TLS) {
            if (ph.memsz <= size) {
                std.debug.print("expected TLS size greater than {d}, found {d}\n", .{ size, ph.memsz });
                return error.TestUnexpectedResult;
            }
            return;
        }
    }
    return error.MissingTlsSegment;
}

fn expectedFinalization(state: LibraryState, count: u32) FinalizationEvents {
    return .{
        .finalizer_count = count,
        .initialized_global = state.initialized_global,
        .zeroed_global = state.zeroed_global,
        .tls_value = state.tls_value,
    };
}

fn reloadCycles(bridge: Bridge, path: [:0]const u8, options: ReloadCycles) !void {
    try std.testing.expect(options.cycles > 0);

    var events: FinalizationEvents = .{};
    var worker: Worker = .{ .tls_value = options.worker_tls_value };
    var thread: usize = undefined;

    var running = false;
    defer if (running) worker.stop(bridge, thread) catch {};

    var previous_handle: ?*anyopaque = null;
    var previous_address: ?ReadState = null;

    for (0..options.cycles) |cycle| {
        const handle = try bridge.open(path);

        var references: usize = 1;
        defer while (references != 0) {
            references -= 1;
            bridge.close(handle) catch {};
        };

        const second = try bridge.open(path);
        references += 1;

        try std.testing.expectEqual(handle, second);

        if (previous_handle) |old| {
            try std.testing.expect(old != handle);
            try std.testing.expect(bridge.symbol_fn(old, options.symbols.read_state) == null);
            try std.testing.expect(bridge.close_fn(old) != 0);
        }

        const read = try bridge.symbol(ReadState, handle, options.symbols.read_state);

        if (previous_address) |old| try std.testing.expectEqual(old, read);

        worker.read = read;
        worker.set_tls = try bridge.symbol(SetTls, handle, options.symbols.set_tls);

        if (!running) {
            try std.testing.expectEqual(@as(c_int, 0), bridge.start_fn(&thread, &workerRoutine, &worker));
            running = true;
        }

        worker.exercise();
        try std.testing.expectEqualDeep(options.expected_initial, worker.values);

        var values: LibraryState = undefined;
        read(&values);
        try std.testing.expectEqualDeep(options.expected_initial, values);

        const mutate = try bridge.symbol(Mutate, handle, options.symbols.mutate);
        mutate(&events);
        read(&values);
        try std.testing.expectEqualDeep(options.expected_mutated, values);

        try bridge.close(handle);
        references -= 1;

        try std.testing.expectEqual(@as(u32, @intCast(cycle)), events.finalizer_count);

        read(&values);
        try std.testing.expectEqualDeep(options.expected_mutated, values);

        try bridge.close(second);
        references -= 1;

        try std.testing.expectEqualDeep(expectedFinalization(options.expected_mutated, @intCast(cycle + 1)), events);

        previous_handle = handle;
        previous_address = read;
    }

    try worker.stop(bridge, thread);
    running = false;
}

fn pendingTlsDestructor(bridge: Bridge, path: [:0]const u8, options: PendingTlsDestructor) !void {
    const handle = try bridge.open(path);

    var opened = true;
    defer if (opened) bridge.close(handle) catch {};

    var worker: Worker = .{
        .read = try bridge.symbol(ReadState, handle, options.symbols.read_state),
        .set_tls = try bridge.symbol(SetTls, handle, options.symbols.set_tls),
        .tls_value = options.worker_tls_value,
        .register = try bridge.symbol(RegisterTls, handle, options.symbols.register_tls_destructor),
    };
    var thread: usize = undefined;

    try std.testing.expectEqual(@as(c_int, 0), bridge.start_fn(&thread, &workerRoutine, &worker));
    var running = true;
    defer if (running) worker.stop(bridge, thread) catch {};

    worker.exercise();
    try std.testing.expectEqualDeep(options.expected_initial, worker.values);
    try std.testing.expectEqual(@as(c_int, 0), worker.registration_result);

    const mutate = try bridge.symbol(Mutate, handle, options.symbols.mutate);
    var events: FinalizationEvents = .{};
    mutate(&events);
    var state: LibraryState = undefined;
    worker.read(&state);
    try std.testing.expectEqualDeep(options.expected_mutated, state);

    try bridge.close(handle);
    opened = false;

    try std.testing.expectEqual(@as(u32, 0), events.finalizer_count);
    try std.testing.expectEqualDeep(TlsDestructorEvents{}, worker.tls_events);

    try worker.stop(bridge, thread);
    running = false;

    try std.testing.expectEqualDeep(options.expected_tls_destructor, worker.tls_events);
    try std.testing.expectEqualDeep(expectedFinalization(options.expected_mutated, 1), events);
}

fn sharedDependency(bridge: Bridge, target_path: [:0]const u8, consumer_path: [:0]const u8, options: DependencyLifetime) !void {
    const target = try bridge.open(target_path);

    var target_open = true;
    defer if (target_open) bridge.close(target) catch {};

    const consumer = try bridge.open(consumer_path);

    var consumer_open = true;
    defer if (consumer_open) bridge.close(consumer) catch {};

    const observe = try bridge.symbol(*const fn (*u32, *FinalizationEvents) callconv(.c) void, consumer, options.symbols.consumer_observe_finalization);
    var events: FinalizationEvents = .{};
    var observed: u32 = std.math.maxInt(u32);
    observe(&observed, &events);

    const mutate = try bridge.symbol(Mutate, target, options.symbols.provider_mutate);
    mutate(&events);

    const read = try bridge.symbol(ReadState, consumer, options.symbols.consumer_read_state);

    try bridge.close(target);
    target_open = false;

    try std.testing.expectEqual(@as(u32, 0), events.finalizer_count);

    var state: LibraryState = undefined;
    read(&state);
    try std.testing.expectEqualDeep(options.expected_mutated, state);

    try bridge.close(consumer);
    consumer_open = false;

    try std.testing.expectEqual(@as(u32, 0), observed);
    try std.testing.expectEqualDeep(expectedFinalization(options.expected_mutated, 1), events);

    const reopened = try bridge.open(consumer_path);

    var reopened_open = true;
    defer if (reopened_open) bridge.close(reopened) catch {};

    const read_fresh = try bridge.symbol(ReadState, reopened, options.symbols.consumer_read_state);
    read_fresh(&state);
    try std.testing.expectEqualDeep(options.expected_initial, state);

    observed = std.math.maxInt(u32);

    try bridge.close(reopened);
    reopened_open = false;

    try std.testing.expectEqual(std.math.maxInt(u32), observed);
    try std.testing.expectEqual(@as(u32, 1), events.finalizer_count);
}
