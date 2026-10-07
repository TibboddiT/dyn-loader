const std = @import("std");

const dll = @import("dll");
const regression_abi = @import("regression_abi");
const support = @import("behavior_support");

const Bridge = support.Bridge;

pub const SpecificContext = support.SpecificContext;

const LibraryState = regression_abi.LibraryState;
const FinalizationEvents = regression_abi.FinalizationEvents;

const ReadState = *const fn (state: *LibraryState) callconv(.c) void;
const Mutate = *const fn (events: *FinalizationEvents) callconv(.c) void;
const SetTls = *const fn (value: u32) callconv(.c) void;

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

pub const BridgeSymbols = support.BridgeSymbols;

pub const ReloadSymbols = struct {
    read_state: [:0]const u8,
    mutate: [:0]const u8,
    set_tls: [:0]const u8,
};

pub const DependencySymbols = struct {
    provider_mutate: [:0]const u8,
    consumer_read_state: [:0]const u8,
    consumer_observe_finalization: [:0]const u8,
};

pub const Behavior = union(enum) {
    specific: Specific,
    reload_cycles: ReloadCycles,
    dependency_lifetime: DependencyLifetime,
};

/// Runs before loader initialization.
pub const Specific = struct {
    // RequiredSymbolUnavailable reports a missing runtime API, not a failed assertion.
    run: *const fn (init: std.process.Init, context: SpecificContext) anyerror!void,
};

pub const ReloadCycles = struct {
    symbols: ReloadSymbols,
    cycles: u32,
    expected_initial: LibraryState,
    expected_mutated: LibraryState,
    worker_tls_value: u32,
};

pub const DependencyLifetime = struct {
    consumer: []const u8,
    symbols: DependencySymbols,
    expected_initial: LibraryState,
    expected_mutated: LibraryState,
};

const Worker = struct {
    phase: std.atomic.Value(enum(u32) { idle, work, done, stop }) = .init(.idle),
    readState: ReadState = undefined,
    setTls: SetTls = undefined,
    tls_value: u32,
    observed_state: LibraryState = undefined,

    fn exercise(worker: *Worker) void {
        // The worker reads callbacks after .work and writes results before .done.
        worker.phase.store(.work, .release);
        while (worker.phase.load(.acquire) != .done) {
            std.atomic.spinLoopHint();
        }
        worker.phase.store(.idle, .release);
    }

    fn stop(worker: *Worker, bridge: Bridge, thread: usize) !void {
        // Waits for TLS destructors before their results are read.
        worker.phase.store(.stop, .release);
        try std.testing.expectEqual(@as(c_int, 0), bridge.joinThread(thread));
    }
};

fn workerRoutine(argument: ?*anyopaque) callconv(.c) *anyopaque {
    const worker: *Worker = @ptrCast(@alignCast(argument.?));
    while (true) {
        switch (worker.phase.load(.acquire)) {
            .work => {
                worker.readState(&worker.observed_state);
                worker.setTls(worker.tls_value);
                worker.phase.store(.done, .release);
            },
            .stop => return argument.?,
            else => std.atomic.spinLoopHint(),
        }
    }
}

pub fn validate(init: std.process.Init, cases: []const Case, resources_dir: []const u8) !void {
    for (cases) |case| {
        if (case.requires.tls_size_greater_than) |size| {
            const path = try std.fs.path.join(init.gpa, &.{ resources_dir, case.library });
            defer init.gpa.free(path);
            try expectTlsSizeGreaterThan(init.io, path, size);
        }
    }
}

pub fn runCase(init: std.process.Init, cases: []const Case, name: []const u8, resources_dir: []const u8) !void {
    const case = for (cases) |case| {
        if (std.mem.eql(u8, name, case.name)) break case;
    } else return error.UnknownCase;

    const target_path = try std.fmt.allocPrintSentinel(init.gpa, "{s}/{s}", .{ resources_dir, case.library }, 0);
    defer init.gpa.free(target_path);

    if (case.requires.tls_size_greater_than) |size| try expectTlsSizeGreaterThan(init.io, target_path, size);

    const bridge_path = try std.fs.path.join(init.gpa, &.{ resources_dir, case.bridge });
    defer init.gpa.free(bridge_path);

    switch (case.behavior) {
        .specific => |specific| return specific.run(init, .{
            .bridge_path = bridge_path,
            .target_path = target_path,
            .bridge_symbols = case.bridge_symbols,
        }),
        .reload_cycles, .dependency_lifetime => {}, // Runner owns the loader lifecycle.
    }

    try dll.init(.{
        .allocator = init.gpa,
        .io = init.io,
        .args = init.minimal.args,
        .environ = init.minimal.environ,
        .log_level = .none,
    });
    defer dll.deinit();

    const bridge = try Bridge.init(bridge_path, case.bridge_symbols);

    switch (case.behavior) {
        .specific => unreachable,
        .reload_cycles => |options| try reloadCycles(bridge, target_path, options),
        .dependency_lifetime => |options| {
            const consumer_path = try std.fmt.allocPrintSentinel(init.gpa, "{s}/{s}", .{ resources_dir, options.consumer }, 0);
            defer init.gpa.free(consumer_path);

            try sharedDependency(bridge, target_path, consumer_path, options);
        },
    }
}

fn expectTlsSizeGreaterThan(io: std.Io, path: []const u8, minimum_size_bytes: u64) !void {
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);

    var header: std.elf.Elf64_Ehdr = undefined;
    try std.testing.expectEqual(@sizeOf(std.elf.Elf64_Ehdr), try file.readPositional(io, &.{std.mem.asBytes(&header)}, 0));
    try std.testing.expectEqualSlices(u8, std.elf.MAGIC, header.e_ident[0..4]);
    try std.testing.expectEqual(std.elf.ELFCLASS64, header.e_ident[std.elf.EI_CLASS]);
    try std.testing.expectEqual(std.elf.ELFDATA2LSB, header.e_ident[std.elf.EI_DATA]);
    try std.testing.expectEqual(@sizeOf(std.elf.Elf64.Phdr), header.e_phentsize);

    const file_size_bytes = (try file.stat(io)).size;
    const table_size_bytes = @as(u64, header.e_phnum) * header.e_phentsize;

    try std.testing.expect(header.e_phoff <= file_size_bytes);
    try std.testing.expect(table_size_bytes <= file_size_bytes - header.e_phoff);

    for (0..header.e_phnum) |index| {
        var program_header: std.elf.Elf64.Phdr = undefined;
        const file_offset = header.e_phoff + index * header.e_phentsize;
        const bytes_read = try file.readPositional(io, &.{std.mem.asBytes(&program_header)}, file_offset);

        try std.testing.expectEqual(@sizeOf(std.elf.Elf64.Phdr), bytes_read);

        if (program_header.type == .TLS) {
            if (program_header.memsz <= minimum_size_bytes) {
                std.debug.print("expected TLS size greater than {d}, found {d}\n", .{ minimum_size_bytes, program_header.memsz });
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

    for (0..options.cycles) |cycle| {
        const handle = try bridge.open(path);

        var references: usize = 1;
        defer while (references != 0) {
            references -= 1;
            bridge.close(handle) catch {};
        };

        const second = try bridge.open(path);
        references += 1;

        const read = try bridge.symbol(ReadState, handle, options.symbols.read_state);

        worker.readState = read;
        worker.setTls = try bridge.symbol(SetTls, handle, options.symbols.set_tls);

        if (!running) {
            try std.testing.expectEqual(@as(c_int, 0), bridge.startThread(&thread, &workerRoutine, &worker));
            running = true;
        }

        worker.exercise();
        try std.testing.expectEqualDeep(options.expected_initial, worker.observed_state);

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

        const read_remaining = try bridge.symbol(ReadState, second, options.symbols.read_state);
        read_remaining(&values);
        try std.testing.expectEqualDeep(options.expected_mutated, values);

        try bridge.close(second);
        references -= 1;

        try std.testing.expectEqualDeep(expectedFinalization(options.expected_mutated, @intCast(cycle + 1)), events);
    }

    try worker.stop(bridge, thread);
    running = false;
}

fn sharedDependency(bridge: Bridge, target_path: [:0]const u8, consumer_path: [:0]const u8, options: DependencyLifetime) !void {
    const target = try bridge.open(target_path);

    var target_open = true;
    defer if (target_open) bridge.close(target) catch {};

    const consumer = try bridge.open(consumer_path);

    var consumer_open = true;
    defer if (consumer_open) bridge.close(consumer) catch {};

    const observe = try bridge.symbol(*const fn (observed: *u32, events: *FinalizationEvents) callconv(.c) void, consumer, options.symbols.consumer_observe_finalization);
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
