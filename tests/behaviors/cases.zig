//! Lifecycle scenarios share observable C structs with the regression fixtures.
//! Expected values are independent of loader internals: constructors initialize
//! once per load, mutations survive extra references, and reload starts fresh.

const runner = @import("lifecycle_runner");
const LibraryState = @import("regression_abi").LibraryState;

const host_tls_migration = @import("specifics/host_tls_migration.zig");
const failure_recovery = @import("specifics/failure_recovery.zig");
const tls_surplus = @import("specifics/tls_surplus.zig");
const tls_lookup = @import("specifics/tls_lookup.zig");
const managed_threads = @import("specifics/managed_threads.zig");
const constructor_workers = @import("specifics/constructor_workers.zig");
const contract_failures = @import("specifics/contract_failures.zig");
const fork_scope = @import("specifics/fork_scope.zig");
const control = @import("control.zig");
const resolver_context = @import("specifics/resolver_context.zig");
const nodelete = @import("specifics/nodelete.zig");
const relocation_scope = @import("specifics/relocation_scope.zig");
const iconv = @import("specifics/iconv.zig");
const constructor_nested = @import("specifics/constructor_nested.zig");

pub const runThreadContractChild = contract_failures.runChild;
pub fn onLoaderEvent(event: anytype) error{InjectedFailure}!void {
    switch (event) {
        .managed_membership_locked => fork_scope.pauseAtMembershipLock(),
        .allocator_initialized => |allocator| if (control.allocator) |injected| {
            allocator.* = injected;
        },
        .native_preflight => if (control.shouldFail(.native_preflight, null)) return error.InjectedFailure,
        .native_committed => if (control.shouldFail(.native_committed, null)) return error.InjectedFailure,
        .worker_preflight => if (control.shouldFail(.worker_preflight, null)) return error.InjectedFailure,
        .child_preflight => if (control.shouldFail(.child_preflight, null)) return error.InjectedFailure,
        .constructor_completed => |name| if (control.shouldFail(.constructor_completed, name)) return error.InjectedFailure,
    }
}

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
        .name = "iconv-conversion",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "bridge.so",
        .behavior = .{ .specific = .{ .run = &iconv.run } },
    },
    .{
        .name = "constructor-iconv",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "constructor_iconv.so",
        .behavior = .{ .specific = .{ .run = &iconv.runConstructor } },
    },
    .{
        .name = "constructor-nested-loading",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "constructor_nested.so",
        .behavior = .{ .specific = .{ .run = &constructor_nested.run } },
    },
    .{
        .name = "relocation-load-group",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "scope_driver.so",
        .behavior = .{ .specific = .{ .run = &relocation_scope.run } },
    },
    .{
        .name = "nodelete-elf",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "nodelete.so",
        .behavior = .{ .specific = .{ .run = &nodelete.runElf } },
    },
    .{
        .name = "nodelete-flag",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "nodelete_plain.so",
        .behavior = .{ .specific = .{ .run = &nodelete.runFlag } },
    },
    .{
        .name = "nodelete-promotion",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "nodelete_plain.so",
        .behavior = .{ .specific = .{ .run = &nodelete.runPromotion } },
    },
    .{
        .name = "early-resolver-context-glibc",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "resolver_context.so",
        .requires = .{ .libc_abi = .gnu },
        .behavior = .{ .specific = .{ .run = &resolver_context.runEarly } },
    },
    .{
        .name = "late-resolver-context-glibc",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "resolver_context.so",
        .requires = .{ .libc_abi = .gnu },
        .behavior = .{ .specific = .{ .run = &resolver_context.runLate } },
    },
    .{
        .name = "restricted-fork",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target.so",
        .behavior = .{ .specific = .{ .run = &fork_scope.run } },
    },
    .{
        .name = "escaped-constructor-failure",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "constructor_workers.so",
        .behavior = .{ .specific = .{ .run = &constructor_workers.runFailedLoad } },
    },
    .{
        .name = "thread-contract-failures",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target.so",
        .behavior = .{ .specific = .{ .run = &contract_failures.run } },
    },
    .{
        .name = "constructor-workers",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "constructor_workers.so",
        .behavior = .{ .specific = .{ .run = &constructor_workers.run } },
    },
    .{
        .name = "managed-threads",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target.so",
        .behavior = .{ .specific = .{ .run = &managed_threads.run } },
    },
    .{
        .name = "tls-symbol-lookup",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target_large_tls.so",
        .behavior = .{ .specific = .{ .run = &tls_lookup.run } },
    },
    .{
        .name = "tls-symbol-lookup-versioned-glibc",
        .bridge = "bridge.so",
        .bridge_symbols = bridge_symbols,
        .library = "target_large_tls.so",
        .requires = .{ .libc_abi = .gnu },
        .behavior = .{ .specific = .{ .run = &tls_lookup.runVersioned } },
    },
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
