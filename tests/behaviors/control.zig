//! Executable-owned fault selection. The root callbacks adapt the loader's typed
//! probes without exposing a test configuration API from the production module.

const std = @import("std");

pub const Failure = enum {
    native_preflight,
    native_committed,
    worker_preflight,
    child_preflight,
    constructor_completed,
};

pub var failure: ?Failure = null;
pub var allocator: ?std.mem.Allocator = null;
pub var object_name: []const u8 = "";

pub fn shouldFail(requested: Failure, name: ?[]const u8) bool {
    if (failure != requested) return false;
    if (name) |value| return std.mem.eql(u8, object_name, value);
    return true;
}
