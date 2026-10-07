const std = @import("std");
const builtin = @import("builtin");

const json = @import("json.zig");
const protocol = @import("protocol.zig");

pub const Row = struct {
    id: u32,
    suite: []const u8,
    name: []const u8,
    reference: protocol.Outcome,
    dynloader: protocol.Outcome,
    comparison: protocol.Comparison,
};

pub const Bootstrap = struct {
    reference: protocol.Outcome,
    dynloader: protocol.Outcome,
};

pub const RuntimeResult = struct {
    id: []const u8,
    prepared: json.Value = .null,
    assertion_prepared: json.Value = .null,
    assertion_preparation_error: ?[]const u8 = null,
    bootstrap: ?Bootstrap = null,
    preparation_error: ?[]const u8 = null,
    cases: []const Row = &.{},
};

pub const schema_version = 5;

pub const Report = struct {
    schema_version: u32 = schema_version,
    run_id: []const u8,
    zig_version: []const u8 = builtin.zig_version_string,
    compiler_sha256: []const u8 = "",
    git_revision: []const u8,
    git_status: []const u8,
    kernel: []const u8,
    cpu: []const u8,
    source_hashes: json.Value,
    prepare_only: bool = false,
    timeout_ms: u64 = 30_000,
    cache_dir: ?[]const u8 = null,
    runtimes: []const RuntimeResult = &.{},
};

pub fn validate(allocator: std.mem.Allocator, report: json.Value) !void {
    json.requireAllFields(Report, report) catch return error.InvalidReport;

    const parsed = std.json.parseFromValueLeaky(Report, allocator, report, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidReport,
    };

    if (json.asInteger(json.field(report, "schema_version")) != schema_version or parsed.source_hashes != .object) {
        return error.InvalidReport;
    }

    const timeout_ms = json.asInteger(json.field(report, "timeout_ms")) orelse return error.InvalidReport;
    if (timeout_ms < 1 or timeout_ms > 86_400_000) return error.InvalidReport;

    for (json.field(report, "runtimes").array.items) |runtime| {
        json.requireAllFields(RuntimeResult, runtime) catch return error.InvalidReport;

        for ([_][]const u8{ "prepared", "assertion_prepared" }) |key| {
            const prepared = json.field(runtime, key);
            if (prepared != .null and prepared != .object) return error.InvalidReport;
        }

        const bootstrap = json.field(runtime, "bootstrap");
        if (bootstrap != .null) {
            try validateOutcomes(bootstrap);
        }

        for (json.field(runtime, "cases").array.items) |row| {
            json.requireAllFields(Row, row) catch return error.InvalidReport;
            try validateOutcomes(row);

            if (json.asInteger(json.field(row, "id")) == null or
                json.asString(json.field(row, "comparison")) == null)
            {
                return error.InvalidReport;
            }

            const suite = json.stringField(row, "suite");
            if (!std.mem.eql(u8, suite, "libc") and
                !std.mem.eql(u8, suite, "elf") and
                !std.mem.eql(u8, suite, "lifecycle"))
            {
                return error.InvalidReport;
            }
        }
    }
}

fn validateOutcomes(value: json.Value) !void {
    for ([_][]const u8{ "reference", "dynloader" }) |key| {
        protocol.validateOutcome(json.field(value, key)) catch return error.InvalidReport;
    }
}

pub fn summarize(allocator: std.mem.Allocator, report: json.Value) ![]const u8 {
    try validate(allocator, report);

    return summarizeValidated(allocator, report);
}

fn summarizeValidated(allocator: std.mem.Allocator, report: json.Value) ![]const u8 {
    const runtimes = json.field(report, "runtimes");

    const prepare_only = json.field(report, "prepare_only").bool;

    var counts: std.array_hash_map.String(usize) = .empty;
    defer counts.deinit(allocator);

    var total: usize = 0;
    var preparation_failures: usize = 0;

    for (runtimes.array.items) |runtime| {
        const preparation_error = json.asString(json.field(runtime, "preparation_error"));
        const assertion_error = json.asString(json.field(runtime, "assertion_preparation_error"));
        if (preparation_error != null or assertion_error != null) {
            preparation_failures += 1;
        }

        if (prepare_only) continue;

        const cases = json.field(runtime, "cases");

        for (cases.array.items) |row| {
            const comparison = json.stringField(row, "comparison");
            const previous_count = counts.get(comparison) orelse 0;
            try counts.put(allocator, comparison, previous_count + 1);
            total += 1;
        }
    }

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    const writer = &output.writer;
    if (prepare_only) {
        try writer.print("Summary: runtimes={d} prepared={d} preparation_failures={d}", .{
            runtimes.array.items.len,
            runtimes.array.items.len - preparation_failures,
            preparation_failures,
        });
    } else {
        try writer.print("Summary: total={d}", .{total});

        var entries = counts.iterator();
        while (entries.next()) |entry| {
            try writer.print(" {s}={d}", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        if (preparation_failures != 0) {
            try writer.print(" preparation_failures={d}", .{preparation_failures});
        }
    }

    return output.toOwnedSlice();
}

fn writeShellArgument(writer: *std.Io.Writer, argument: []const u8) !void {
    const safe = argument.len != 0 and for (argument) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, "_./:@+-", byte) == null) {
            break false;
        }
    } else true;

    if (safe) {
        try writer.writeAll(argument);
        return;
    }

    try writer.writeByte('\'');
    for (argument) |byte| {
        if (byte == '\'') {
            try writer.writeAll("'\\''");
        } else {
            try writer.writeByte(byte);
        }
    }
    try writer.writeByte('\'');
}

fn reproductionCommand(
    allocator: std.mem.Allocator,
    report: json.Value,
    runtime_id: []const u8,
    row: ?json.Value,
) ![]const u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    const writer = &output.writer;
    try writer.writeAll("zig build run-tests_matrix -- --runtime ");
    try writeShellArgument(writer, runtime_id);

    if (row) |case| {
        try writer.writeAll(" --suite ");
        try writeShellArgument(writer, json.stringField(case, "suite"));
        try writer.writeAll(" --case ");
        try writeShellArgument(writer, json.stringField(case, "name"));
    } else {
        try writer.writeAll(" --prepare-only");
    }

    const timeout_ms: u64 = @intCast(json.field(report, "timeout_ms").integer);
    try writer.print(" --timeout {d}", .{timeout_ms / 1000});
    const remaining_ms = timeout_ms % 1000;
    if (remaining_ms != 0) {
        try writer.print(".{d:0>3}", .{remaining_ms});

        // Float parsing can round a millisecond down.
        const seconds = @as(f64, @floatFromInt(timeout_ms)) / 1000;
        if (@as(u64, @intFromFloat(seconds * 1000)) < timeout_ms) {
            try writer.writeByte('1');
        }
    }

    if (json.asString(json.field(report, "cache_dir"))) |cache_dir| {
        try writer.writeAll(" --cache ");
        try writeShellArgument(writer, cache_dir);
    }

    return output.toOwnedSlice();
}

fn writeCommandCell(writer: *std.Io.Writer, command: []const u8) !void {
    var longest_run: usize = 0;
    var current_run: usize = 0;
    for (command) |byte| {
        current_run = if (byte == '`') current_run + 1 else 0;
        longest_run = @max(longest_run, current_run);
    }

    const delimiter_length = longest_run + 1;
    for (0..delimiter_length) |_| {
        try writer.writeByte('`');
    }
    try writer.writeByte(' ');

    for (command) |byte| {
        if (byte == '|') {
            try writer.writeAll("\\|");
        } else {
            try writer.writeByte(byte);
        }
    }

    try writer.writeByte(' ');
    for (0..delimiter_length) |_| {
        try writer.writeByte('`');
    }
}

pub fn markdown(allocator: std.mem.Allocator, report: json.Value) ![]const u8 {
    try validate(allocator, report);

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    const writer = &output.writer;

    const kernel = std.mem.trim(u8, json.stringField(report, "kernel"), " \r\n\t");
    try writer.print("# Loader matrix results\n\nRun: `{s}`\n\nZig: `{s}`; kernel: `{s}`\n\n", .{
        json.stringField(report, "run_id"),
        json.stringField(report, "zig_version"),
        kernel,
    });

    try writer.writeAll("Reproduction commands run from the project root.\n\n");
    try writer.writeAll("| Runtime | Suite | Case | Reference | dynloader | Result | Reproduce |\n");
    try writer.writeAll("|---|---|---|---|---|---|---|\n");

    const runtimes = json.field(report, "runtimes");

    for (runtimes.array.items) |runtime| {
        const runtime_id = json.stringField(runtime, "id");

        if (json.asString(json.field(runtime, "preparation_error"))) |message| {
            const command = try reproductionCommand(allocator, report, runtime_id, null);
            defer allocator.free(command);

            try writer.print("| {s} | libc | preparation | — | — | {s} | ", .{ runtime_id, message });
            try writeCommandCell(writer, command);
            try writer.writeAll(" |\n");
        }

        if (json.asString(json.field(runtime, "assertion_preparation_error"))) |message| {
            const command = try reproductionCommand(allocator, report, runtime_id, null);
            defer allocator.free(command);

            try writer.print("| {s} | elf/lifecycle | preparation | — | — | {s} | ", .{ runtime_id, message });
            try writeCommandCell(writer, command);
            try writer.writeAll(" |\n");
        }

        const cases = json.field(runtime, "cases");

        for (cases.array.items) |row| {
            const comparison = json.stringField(row, "comparison");

            const suite = json.field(row, "suite").string;
            const reference = json.field(row, "reference");
            const loader = json.field(row, "dynloader");

            const reference_status = json.stringField(reference, "status");
            const loader_status = json.stringField(loader, "status");

            const command = try reproductionCommand(allocator, report, runtime_id, row);
            defer allocator.free(command);

            try writer.print("| {s} | {s} | {s} | {s} | {s} | {s} | ", .{
                runtime_id,
                suite,
                json.stringField(row, "name"),
                reference_status,
                loader_status,
                comparison,
            });

            try writeCommandCell(writer, command);
            try writer.writeAll(" |\n");
        }
    }

    try writer.writeByte('\n');

    for (runtimes.array.items) |runtime| {
        const bootstrap = json.field(runtime, "bootstrap");
        const loader_bootstrap = json.field(bootstrap, "dynloader");
        if (loader_bootstrap == .null) continue;

        const status = json.field(loader_bootstrap, "status");
        if (json.isString(status, "pass")) continue;

        try writer.print("**{s} dynloader bootstrap:** `{s}`, stage `{s}`; see `{s}`.\n\n", .{
            json.stringField(runtime, "id"),
            json.stringField(loader_bootstrap, "status"),
            json.stringField(loader_bootstrap, "stage"),
            json.stringField(loader_bootstrap, "stderr"),
        });
    }

    const summary = try summarizeValidated(allocator, report);
    defer allocator.free(summary);

    try writer.print("{s}\n", .{summary});

    return output.toOwnedSlice();
}

fn testReport(allocator: std.mem.Allocator, runtimes: []const RuntimeResult) !json.Value {
    return json.cloneViaSerialization(allocator, Report{
        .run_id = "test",
        .git_revision = "test",
        .git_status = "",
        .kernel = "test",
        .cpu = "test",
        .source_hashes = json.object(),
        .runtimes = runtimes,
    });
}

const test_row: Row = .{
    .id = 0,
    .suite = "libc",
    .name = "test",
    .reference = .{ .status = .pass },
    .dynloader = .{ .status = .pass },
    .comparison = .pass,
};

test "current reports render explicit suites and result categories" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const report = try testReport(allocator, &.{.{
        .id = "runtime",
        .cases = &.{
            .{
                .id = 0,
                .suite = "libc",
                .name = "test",
                .reference = .{ .status = .pass },
                .dynloader = .{ .status = .crash },
                .comparison = .compatibility_gap,
            },
            .{
                .id = 1,
                .suite = "elf",
                .name = "elf.test",
                .reference = .{ .status = .not_applicable },
                .dynloader = .{ .status = .failure },
                .comparison = .assertion_failure,
            },
        },
    }});

    const text = try markdown(allocator, report);

    try std.testing.expect(std.mem.indexOf(u8, text, "| runtime | libc | test | pass | crash | compatibility_gap |") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "| runtime | elf | elf.test | not_applicable | failure | assertion_failure |") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "| Reproduce |") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zig build run-tests_matrix -- --runtime runtime --suite libc --case test --timeout 30") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zig build run-tests_matrix -- --runtime runtime --suite elf --case elf.test --timeout 30") != null);

    const summary = try summarize(allocator, report);
    try std.testing.expectEqualStrings("Summary: total=2 compatibility_gap=1 assertion_failure=1", summary);
    try std.testing.expect(std.mem.indexOf(u8, text, summary) != null);
}

test "global summaries aggregate runtimes and distinguish preparation from case results" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    var blocked = test_row;
    blocked.dynloader.status = .not_run;
    blocked.comparison = .blocked;

    var unavailable = test_row;
    unavailable.reference.status = .unavailable;
    unavailable.comparison = .unavailable;

    var report = try testReport(allocator, &.{
        .{ .id = "first", .cases = &.{ test_row, blocked } },
        .{ .id = "second", .cases = &.{ test_row, unavailable } },
        .{
            .id = "failed",
            .preparation_error = "SdkFailed",
            .assertion_preparation_error = "FixturesFailed",
        },
    });

    const summary = try summarize(allocator, report);
    try std.testing.expectEqualStrings(
        "Summary: total=4 pass=2 blocked=1 unavailable=1 preparation_failures=1",
        summary,
    );

    try json.putField(allocator, &report, "prepare_only", .{ .bool = true });
    const preparation_summary = try summarize(allocator, report);
    try std.testing.expectEqualStrings(
        "Summary: runtimes=3 prepared=2 preparation_failures=1",
        preparation_summary,
    );

    const empty_report = try testReport(allocator, &.{});
    const empty_summary = try summarize(allocator, empty_report);
    try std.testing.expectEqualStrings("Summary: total=0", empty_summary);
}

test "invalid report versions, missing fields, and wrong types are errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    var report = try testReport(allocator, &.{.{ .id = "runtime", .cases = &.{test_row} }});

    try json.putField(allocator, &report, "schema_version", .{ .integer = 3 });
    try std.testing.expectError(error.InvalidReport, markdown(allocator, report));
    try json.putField(allocator, &report, "schema_version", .{ .integer = schema_version });

    _ = report.object.swapRemove("prepare_only");
    try std.testing.expectError(error.InvalidReport, summarize(allocator, report));
    try json.putField(allocator, &report, "prepare_only", json.string("false"));
    try std.testing.expectError(error.InvalidReport, summarize(allocator, report));
    try json.putField(allocator, &report, "prepare_only", .{ .bool = false });

    const runtime = &report.object.getPtr("runtimes").?.array.items[0];
    const row = &runtime.object.getPtr("cases").?.array.items[0];
    _ = row.object.swapRemove("suite");
    try std.testing.expectError(error.InvalidReport, markdown(allocator, report));
    try json.putField(allocator, row, "suite", json.string("libc"));

    const outcome = row.object.getPtr("dynloader").?;
    _ = outcome.object.swapRemove("exit_code");
    try std.testing.expectError(error.InvalidReport, summarize(allocator, report));
    try json.putField(allocator, outcome, "exit_code", .{ .integer = 0 });
    try json.putField(allocator, outcome, "status", json.string("unknown"));
    try std.testing.expectError(error.InvalidReport, markdown(allocator, report));
}

test "reproduction commands preserve options and quote shell and Markdown characters" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    var report = try testReport(allocator, &.{
        .{ .id = "runtime", .cases = &.{test_row} },
        .{ .id = "failed", .preparation_error = "BuildFailed" },
    });
    try json.putField(allocator, &report, "timeout_ms", .{ .integer = 1250 });
    try json.putField(allocator, &report, "cache_dir", json.string("/tmp/a b's|`cache`"));

    const row = try json.cloneViaSerialization(allocator, test_row);
    const command = try reproductionCommand(allocator, report, "runtime", row);
    try std.testing.expectEqualStrings(
        "zig build run-tests_matrix -- --runtime runtime --suite libc --case test --timeout 1.250 --cache '/tmp/a b'\\''s|`cache`'",
        command,
    );

    const preparation = try reproductionCommand(allocator, report, "failed", null);
    try std.testing.expectEqualStrings(
        "zig build run-tests_matrix -- --runtime failed --prepare-only --timeout 1.250 --cache '/tmp/a b'\\''s|`cache`'",
        preparation,
    );

    const text = try markdown(allocator, report);
    try std.testing.expect(std.mem.indexOf(u8, text, "`` zig build run-tests_matrix") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "--cache '/tmp/a b'\\''s\\|`cache`' ``") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "--runtime failed --prepare-only") != null);

    try json.putField(allocator, &report, "timeout_ms", .{ .integer = 1001 });
    const precise_command = try reproductionCommand(allocator, report, "runtime", row);
    const timeout_start = std.mem.indexOf(u8, precise_command, "--timeout ").? + "--timeout ".len;
    const timeout_length = std.mem.indexOfScalar(u8, precise_command[timeout_start..], ' ').?;
    const seconds = try std.fmt.parseFloat(f64, precise_command[timeout_start..][0..timeout_length]);
    try std.testing.expectEqual(@as(u64, 1001), @as(u64, @intFromFloat(seconds * 1000)));

    try json.putField(allocator, &report, "timeout_ms", .{ .integer = 0 });
    try std.testing.expectError(error.InvalidReport, markdown(allocator, report));
}
