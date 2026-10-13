//! Loader diagnostics filtered by a runtime threshold and `std.log`.
//! Configure the runtime threshold before concurrent use.

const std = @import("std");

/// Use `info` for lifecycle events, `warn` for recoverable anomalies,
/// `err` for failures, and `debug` for diagnostic detail.
pub const Level = enum { debug, info, warn, err, none };

// Calls may hold loader locks. Host handlers must preserve native thread error
// state and avoid loader reentry or intercepted allocation.
const inner_logger = std.log.scoped(.dyn_loader);
/// Runtime emission threshold. Check it before expensive diagnostic preparation.
/// `std.log` independently controls host filtering and output.
pub var level: Level = .debug;

pub fn debug(comptime format: []const u8, args: anytype) void {
    switch (level) {
        .debug => inner_logger.debug(format, args),
        .info, .warn, .err, .none => {},
    }
}

pub fn info(comptime format: []const u8, args: anytype) void {
    switch (level) {
        .debug, .info => inner_logger.info(format, args),
        .warn, .err, .none => {},
    }
}

pub fn warn(comptime format: []const u8, args: anytype) void {
    switch (level) {
        .debug, .info, .warn => inner_logger.warn(format, args),
        .err, .none => {},
    }
}

pub fn err(comptime format: []const u8, args: anytype) void {
    switch (level) {
        .debug, .info, .warn, .err => inner_logger.err(format, args),
        .none => {},
    }
}
