const std = @import("std");
const dll = @import("dll");

const elf_runner = @import("elf/runner.zig");
const elf_cases = @import("elf/cases.zig");
const behaviors_runner = @import("behaviors/runner.zig");
const behaviors_cases = @import("behaviors/cases.zig");

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

const Runner = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    executable: []const u8,
    resources: []const u8,
    temporary: []const u8,
    passed: usize = 0,
    failed: usize = 0,

    pub fn runCase(runner: *Runner, suite: []const u8, name: []const u8) void {
        const timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } };
        const result = std.process.run(runner.allocator, runner.io, .{
            .argv = &.{ runner.executable, "--case", suite, name, runner.resources, runner.temporary },
            .stdout_limit = .limited(128 * 1024),
            .stderr_limit = .limited(128 * 1024),
            .timeout = timeout.toDeadline(runner.io),
        }) catch |err| {
            runner.failed += 1;
            std.debug.print("FAIL {s}/{s}: {s}\n", .{ suite, name, @errorName(err) });
            return;
        };
        defer runner.allocator.free(result.stdout);
        defer runner.allocator.free(result.stderr);

        if (!result.term.success()) {
            runner.failed += 1;
            std.debug.print("FAIL {s}/{s}: {f}\n{s}{s}", .{ suite, name, result.term, result.stdout, result.stderr });
            return;
        }

        runner.passed += 1;
        std.debug.print("PASS {s}/{s}\n", .{ suite, name });
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len == 6 and std.mem.eql(u8, args[1], "--case")) {
        try std.posix.setrlimit(.CORE, .{ .cur = 0, .max = 0 });
        if (std.mem.eql(u8, args[2], "elf")) {
            try elf_runner.runCase(init, elf_cases.cases, args[3], args[4], args[5]);
        } else if (std.mem.eql(u8, args[2], "lifecycle")) {
            try behaviors_runner.runCase(init, behaviors_cases.cases, args[3], args[4]);
        } else return error.UnknownSuite;
        return;
    }

    if (args.len != 1) {
        std.debug.print("Usage: {s}\n", .{args[0]});
        return error.InvalidArguments;
    }

    var random: [16]u8 = undefined;
    init.io.random(&random);

    const temporary = try std.fmt.allocPrint(init.gpa, "/tmp/dynloader-tests-{s}", .{std.fmt.bytesToHex(random, .lower)});
    defer init.gpa.free(temporary);

    try std.Io.Dir.createDirAbsolute(init.io, temporary, .fromMode(0o700));
    defer std.Io.Dir.cwd().deleteTree(init.io, temporary) catch |err| {
        std.log.err("unable to remove {s}: {}", .{ temporary, err });
    };

    const executable = try std.process.executablePathAlloc(init.io, init.gpa);
    defer init.gpa.free(executable);
    const resources = try std.fs.path.join(init.gpa, &.{ std.fs.path.dirname(executable).?, "resources", "test" });
    defer init.gpa.free(resources);

    var runner: Runner = .{
        .allocator = init.gpa,
        .io = init.io,
        .executable = executable,
        .resources = resources,
        .temporary = temporary,
    };
    elf_runner.run(&runner, elf_cases.cases);
    behaviors_runner.run(&runner, behaviors_cases.cases);

    std.debug.print("\n{d} passed, {d} failed\n", .{ runner.passed, runner.failed });

    if (runner.failed != 0) return error.TestsFailed;
}
