const runner = @import("runner.zig");
const LibraryState = @import("../library_out_params.zig").LibraryState;

const bridge_symbols: runner.BridgeSymbols = .{
    .open = "openProbe",
    .symbol = "symbolProbe",
    .close = "closeProbe",
    .start_thread = "startProbe",
    .join_thread = "joinProbe",
};

const reload_symbols: runner.ReloadSymbols = .{
    .read_state = "readState",
    .mutate = "mutate",
    .set_tls = "setTls",
};

const tls_destructor_symbols: runner.TlsDestructorSymbols = .{
    .read_state = reload_symbols.read_state,
    .mutate = reload_symbols.mutate,
    .set_tls = reload_symbols.set_tls,
    .register_tls_destructor = "registerTlsCallback",
};

const dependency_symbols: runner.DependencySymbols = .{
    .provider_mutate = reload_symbols.mutate,
    .consumer_read_state = "readBoundState",
    .consumer_observe_finalization = "observeFinalization",
};

const initial_state: LibraryState = .{
    .initialized_global = 7,
    .zeroed_global = 0,
    .tls_value = 11,
    .constructor_count = 1,
};

const mutated_state: LibraryState = .{
    .initialized_global = 42,
    .zeroed_global = 99,
    .tls_value = 55,
    .constructor_count = 1,
};

pub const cases: []const runner.Case = &.{
    .{
        .name = "selfhost-reload",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target.so",
        .behavior = .{ .reload_cycles = .{
            .symbols = reload_symbols,
            .cycles = 16,
            .expected_initial = initial_state,
            .expected_mutated = mutated_state,
            .worker_tls_value = 77,
        } },
    },
    .{
        .name = "llvm-reload",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target_llvm.so",
        .behavior = .{ .reload_cycles = .{
            .symbols = reload_symbols,
            .cycles = 16,
            .expected_initial = initial_state,
            .expected_mutated = mutated_state,
            .worker_tls_value = 77,
        } },
    },
    .{
        .name = "pending-tls-destructor",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target.so",
        .behavior = .{ .pending_tls_destructor = .{
            .symbols = tls_destructor_symbols,
            .expected_initial = initial_state,
            .expected_mutated = mutated_state,
            .worker_tls_value = 77,
            .expected_tls_destructor = .{ .destructor_count = 1, .tls_value = 77 },
        } },
    },
    .{
        .name = "shared-dependency",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target.so",
        .behavior = .{ .dependency_lifetime = .{
            .consumer = "dependency.so",
            .symbols = dependency_symbols,
            .expected_initial = initial_state,
            .expected_mutated = mutated_state,
        } },
    },
    .{
        .name = "zig-debug-large-tls",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target_zig_debug.so",
        .requires = .{ .tls_size_greater_than = 32 * 1024 },
        .behavior = .{ .reload_cycles = .{
            .symbols = reload_symbols,
            .cycles = 16,
            .expected_initial = initial_state,
            .expected_mutated = mutated_state,
            .worker_tls_value = 77,
        } },
    },
};
