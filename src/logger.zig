//! Shared loader diagnostics, controlled by the public loader log-level option.
//! The loader's runtime threshold controls emission and diagnostic preparation.
//! `std.log` independently controls host filtering and output. Set the runtime
//! threshold during loader initialization before concurrent calls.
//! Handlers must not reenter loader services or use intercepted native allocation;
//! some diagnostics run under loader locks. Keep native thread error state intact.
//!
//! Use `info` for lifecycle milestones, `warn` for recoverable anomalies, and
//! `err` for failed operations. `debug` records decisions, expected probe misses,
//! native calls, and detailed evidence; expensive preparation needs a level guard.

const std = @import("std");

pub const Level = enum { debug, info, warn, err, none };

const inner_logger = std.log.scoped(.dyn_loader);
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
