//! Optional loader events delivered inline to the executable's dynLoaderHook.
//! Callbacks may run under loader locks; absent callbacks are no-ops.

const root = @import("root");
const std = @import("std");

pub const Event = union(enum) {
    /// Before any runtime allocations; permits executable-owned fault injection.
    allocator_initialized: *std.mem.Allocator,
    native_preflight,
    native_committed,
    worker_preflight,
    child_preflight,
    /// Object name borrowed for the duration of the callback.
    constructor_completed: []const u8,
    managed_membership_locked,
};

/// Callback errors are handled by the emitting call site.
pub fn emit(event: Event) anyerror!void {
    if (@hasDecl(root, "dynLoaderHook")) try root.dynLoaderHook(event);
}
