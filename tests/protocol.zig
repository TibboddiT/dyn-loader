const std = @import("std");

const json = @import("json.zig");

pub const Status = enum {
    pass,
    failure,
    unavailable,
    load_failure,
    abi_failure,
    crash,
    timeout,
    resource_limit,
    infrastructure_failure,
    protocol_failure,
    not_run,
    not_applicable,
};

pub const Case = struct {
    id: u32,
    name: []const u8,
};

pub const Outcome = struct {
    status: Status,
    stage: []const u8 = "launch",
    signal: ?i64 = null,
    diagnostic: json.Value = .null,
    cases: []const Case = &.{},
    exit_code: i64 = 0,
    seconds: f64 = 0,
    container_name: []const u8 = "",
    container_state: json.Value = .null,
    command: []const []const u8 = &.{},
    // File paths, not log contents.
    stdout: []const u8 = "",
    stderr: []const u8 = "",
    reason: ?[]const u8 = null,
};

pub const Comparison = enum {
    pass,
    unavailable,
    reference_failure,
    blocked,
    compatibility_gap,
    assertion_failure,
};

pub fn validateOutcome(value: json.Value) !void {
    try json.requireAllFields(Outcome, value);

    if (json.asString(json.field(value, "status")) == null or
        json.asInteger(json.field(value, "exit_code")) == null)
    {
        return error.InvalidData;
    }

    const signal = json.field(value, "signal");
    if (signal != .null and signal != .integer) return error.InvalidData;

    const seconds = json.field(value, "seconds");
    if (seconds != .integer and seconds != .float) return error.InvalidData;

    const cases = json.field(value, "cases");
    if (cases != .array) return error.InvalidData;

    for (cases.array.items) |case| {
        if (json.asInteger(json.field(case, "id")) == null) return error.InvalidData;
    }
}

pub fn assertion(status: Status) Comparison {
    return switch (status) {
        .pass => .pass,
        .unavailable => .unavailable,
        .not_run => .blocked,
        else => .assertion_failure,
    };
}

pub fn compare(reference: Status, loader: Status) Comparison {
    if (reference == .unavailable) return .unavailable;
    if (reference != .pass) return .reference_failure;
    if (loader == .not_run) return .blocked;

    return if (loader == .pass) .pass else .compatibility_gap;
}

pub fn classify(
    allocator: std.mem.Allocator,
    exit_code: i64,
    stdout_text: []const u8,
    timed_out: bool,
    case_id: ?u32,
) !Outcome {
    var outcome: Outcome = .{
        .status = .protocol_failure,
        .exit_code = exit_code,
    };

    var error_count: usize = 0;
    var result_count: usize = 0;
    var ready_count: usize = 0;
    var event_count: usize = 0;
    var declared_case_count: ?i64 = null;
    var result_event: json.Value = .null;
    var cases: std.ArrayList(Case) = .empty;
    var invalid_catalog = false;

    var lines = std.mem.splitScalar(u8, stdout_text, '\n');
    while (lines.next()) |line| {
        const event = json.parse(allocator, line) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => continue, // Worker output can contain non-JSON lines.
        };

        const kind = json.stringField(event, "event");
        if (std.mem.eql(u8, kind, "stage") or std.mem.eql(u8, kind, "error")) {
            event_count += 1;

            if (json.asString(json.field(event, "stage"))) |stage| {
                outcome.stage = stage;
            }

            if (std.mem.eql(u8, kind, "error")) {
                error_count += 1;
                outcome.diagnostic = event;
            }
        } else if (std.mem.eql(u8, kind, "result")) {
            event_count += 1;
            result_count += 1;
            result_event = event;
        } else if (std.mem.eql(u8, kind, "ready")) {
            event_count += 1;
            ready_count += 1;
            declared_case_count = json.asInteger(json.field(event, "count"));
        } else if (std.mem.eql(u8, kind, "case")) {
            event_count += 1;

            const id = json.asInteger(json.field(event, "id")) orelse {
                invalid_catalog = true;
                continue;
            };

            const name = json.stringField(event, "name");
            if (id < 0 or id > std.math.maxInt(u32) or name.len == 0) {
                invalid_catalog = true;
                continue;
            }

            for (cases.items) |previous| {
                if (previous.id == id or std.mem.eql(u8, previous.name, name)) {
                    invalid_catalog = true;
                }
            }

            try cases.append(allocator, .{ .id = @intCast(id), .name = name });
        }
    }

    if (timed_out) {
        outcome.status = .timeout;
        return outcome;
    }

    if (exit_code >= 128 or exit_code < 0) {
        outcome.status = .crash;
        outcome.signal = if (exit_code >= 128) exit_code - 128 else -exit_code;
        return outcome;
    }

    const launch_failed = exit_code == 125 or exit_code == 126 or exit_code == 127;
    if (launch_failed and event_count == 0) {
        outcome.status = .infrastructure_failure;
        return outcome;
    }

    if (error_count != 0) {
        if (std.mem.eql(u8, outcome.stage, "init") or std.mem.eql(u8, outcome.stage, "load")) {
            outcome.status = .load_failure;
        } else if (std.mem.eql(u8, outcome.stage, "abi")) {
            outcome.status = .abi_failure;
        } else {
            outcome.status = .failure;
        }
        return outcome;
    }

    if (case_id) |id| {
        if (result_count != 1) return outcome;

        const reported_id = json.asInteger(json.field(result_event, "id"));
        if (reported_id != id) return outcome;

        const status_code = json.asInteger(json.field(result_event, "status")) orelse return outcome;
        const reported_status: Status = switch (status_code) {
            0 => .pass,
            1 => .failure,
            2 => .unavailable,
            else => return outcome,
        };

        const expected_exit_code: i64 = if (reported_status == .failure) 1 else 0;
        if (exit_code != expected_exit_code) return outcome;
        if (reported_status == .unavailable and json.stringField(result_event, "detail").len == 0) return outcome;

        outcome.status = reported_status;
        outcome.diagnostic = result_event;
    } else {
        const complete_catalog = !invalid_catalog and cases.items.len != 0 and
            declared_case_count == @as(i64, @intCast(cases.items.len));

        if (exit_code == 0 and result_count == 0 and ready_count == 1 and complete_catalog) {
            outcome.status = .pass;
            outcome.cases = try cases.toOwnedSlice(allocator);
        }
    }

    return outcome;
}

fn classifyWithAllocationFailures(allocator: std.mem.Allocator) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const output =
        \\diagnostic noise
        \\{"event":"case","id":0,"name":"example"}
        \\{"event":"ready","count":1}
        \\
    ;
    const outcome = try classify(arena.allocator(), 0, output, false, null);

    try std.testing.expectEqual(Status.pass, outcome.status);
    try std.testing.expectEqualStrings("example", outcome.cases[0].name);
}

test "classification propagates allocation failures while tolerating diagnostic noise" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, classifyWithAllocationFailures, .{});
}

test "worker protocol and exit status are both required" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const pass = "noise\n{\"event\":\"result\",\"id\":3,\"status\":0}\n";

    const success = try classify(allocator, 0, pass, false, 3);
    try std.testing.expectEqual(Status.pass, success.status);

    const failed_exit = try classify(allocator, 1, pass, false, 3);
    try std.testing.expectEqual(Status.protocol_failure, failed_exit.status);

    const missing_result = try classify(allocator, 0, "", false, 3);
    try std.testing.expectEqual(Status.protocol_failure, missing_result.status);

    const wrong_id = try classify(allocator, 0, pass, false, 4);
    try std.testing.expectEqual(Status.protocol_failure, wrong_id.status);

    const unexpected_result = try classify(allocator, 0, pass, false, null);
    try std.testing.expectEqual(Status.protocol_failure, unexpected_result.status);

    const crashed = try classify(allocator, 139, pass, false, 3);
    try std.testing.expectEqual(Status.crash, crashed.status);
}

test "timeout retains stage, missing executable is infrastructure failure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const outcome = try classify(allocator, -9, "{\"event\":\"stage\",\"stage\":\"load\"}", true, 0);
    try std.testing.expectEqual(Status.timeout, outcome.status);
    try std.testing.expectEqualStrings("load", outcome.stage);

    const missing_executable = try classify(allocator, 125, "", false, null);
    try std.testing.expectEqual(Status.infrastructure_failure, missing_executable.status);
}

test "load errors are failures and unavailability needs a reason" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const load_error = "{\"event\":\"error\",\"stage\":\"load\"}";
    const missing_reason = "{\"event\":\"result\",\"id\":0,\"status\":2}";
    const unavailable = "{\"event\":\"result\",\"id\":0,\"status\":2,\"detail\":\"absent\"}";

    const failed_load = try classify(allocator, 2, load_error, false, 0);
    try std.testing.expectEqual(Status.load_failure, failed_load.status);

    const unexplained = try classify(allocator, 0, missing_reason, false, 0);
    try std.testing.expectEqual(Status.protocol_failure, unexplained.status);

    const explained = try classify(allocator, 0, unavailable, false, 0);
    try std.testing.expectEqual(Status.unavailable, explained.status);
}

test "catalogs reject duplicate ids or names" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const item = "{\"event\":\"case\",\"id\":0,\"name\":\"test\"}\n";

    const valid_catalog = item ++
        "{\"event\":\"case\",\"id\":1,\"name\":\"other\"}\n" ++
        "{\"event\":\"ready\",\"count\":2}";
    const valid = try classify(allocator, 0, valid_catalog, false, null);
    try std.testing.expectEqual(Status.pass, valid.status);

    const duplicate_id_catalog = item ++
        "{\"event\":\"case\",\"id\":0,\"name\":\"other\"}\n" ++
        "{\"event\":\"ready\",\"count\":2}";
    const duplicate_id = try classify(allocator, 0, duplicate_id_catalog, false, null);
    try std.testing.expectEqual(Status.protocol_failure, duplicate_id.status);

    const duplicate_name_catalog = item ++
        "{\"event\":\"case\",\"id\":1,\"name\":\"test\"}\n" ++
        "{\"event\":\"ready\",\"count\":2}";
    const duplicate_name = try classify(allocator, 0, duplicate_name_catalog, false, null);
    try std.testing.expectEqual(Status.protocol_failure, duplicate_name.status);
}

test "reference comparisons and assertion statuses map to result categories" {
    try std.testing.expectEqual(Comparison.reference_failure, compare(.crash, .crash));
    try std.testing.expectEqual(Comparison.blocked, compare(.pass, .not_run));
    try std.testing.expectEqual(Comparison.compatibility_gap, compare(.pass, .crash));
    try std.testing.expectEqual(Comparison.pass, compare(.pass, .pass));

    try std.testing.expectEqual(Comparison.pass, assertion(.pass));
    try std.testing.expectEqual(Comparison.unavailable, assertion(.unavailable));
    try std.testing.expectEqual(Comparison.blocked, assertion(.not_run));

    for ([_]Status{ .failure, .crash, .timeout, .protocol_failure, .infrastructure_failure, .resource_limit }) |status| {
        try std.testing.expectEqual(Comparison.assertion_failure, assertion(status));
    }
}
