const runner = @import("lifecycle_runner");
const LibraryState = @import("regression_abi").LibraryState;

const host_tls_migration = @import("specifics/host_tls_migration.zig");
const failure_recovery = @import("specifics/failure_recovery.zig");
const tls_surplus = @import("specifics/tls_surplus.zig");

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
        .name = "reallocarray-failure",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target.so",
        .behavior = .{ .specific = .{ .run = &failure_recovery.runReallocarray } },
    },
    .{
        .name = "tls-surplus-rejection",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target_excess_tls.so",
        .requires = .{ .tls_size_greater_than = 1024 * 1024 },
        .behavior = .{ .specific = .{ .run = &tls_surplus.run } },
    },
    .{
        .name = "failure-recovery",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target.so",
        .behavior = .{ .specific = .{ .run = &failure_recovery.run } },
    },
    .{
        .name = "host-tls-migration",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target.so",
        .behavior = .{
            .specific = .{
                .run = &host_tls_migration.run,
            },
        },
    },
    .{
        .name = "reload",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target.so",
        .behavior = .{
            .reload_cycles = .{
                .symbols = reload_symbols,
                .cycles = 16,
                .expected_initial = initial_state,
                .expected_mutated = mutated_state,
                .worker_tls_value = 77,
            },
        },
    },
    .{
        .name = "reload-optimized",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target_optimized.so",
        .behavior = .{
            .reload_cycles = .{
                .symbols = reload_symbols,
                .cycles = 16,
                .expected_initial = initial_state,
                .expected_mutated = mutated_state,
                .worker_tls_value = 77,
            },
        },
    },
    .{
        .name = "shared-dependency",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target.so",
        .behavior = .{
            .dependency_lifetime = .{
                .consumer = "dependency.so",
                .symbols = dependency_symbols,
                .expected_initial = initial_state,
                .expected_mutated = mutated_state,
            },
        },
    },
    .{
        .name = "large-tls-reload",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target_large_tls.so",
        .requires = .{ .tls_size_greater_than = 32 * 1024 },
        .behavior = .{
            .reload_cycles = .{
                .symbols = reload_symbols,
                .cycles = 16,
                .expected_initial = initial_state,
                .expected_mutated = mutated_state,
                .worker_tls_value = 77,
            },
        },
    },
};
