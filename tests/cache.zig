const std = @import("std");

const json = @import("json.zig");
const protocol = @import("protocol.zig");

pub const prepared_version = 4;
pub const assertions_version = 2;

const StringMap = std.json.ArrayHashMap([]const u8);

const Identity = struct {
    image_id: []const u8,
    libc_package_version: []const u8,
    runtime_sha256: StringMap,
    packages: []const u8,
};

const Prepared = struct {
    schema_version: u32,
    runtime: json.Value,
    base: Identity,
    sdk: Identity,
    sdk_key: struct {
        runtime: json.Value,
        recipe_sha256: []const u8,
    },
    fixture_key: struct {
        sdk_image_id: []const u8,
        flags: []const []const u8,
        source_hashes: StringMap,
    },
    worker_sha256: []const u8,
    zig_version: []const u8,
    compiler: []const u8,
    build_commands: []const []const []const u8,
    source_hashes: StringMap,
    fixture_sha256: StringMap,
    sdk_archive_sha256: []const u8,
    runtime_archive_sha256: ?[]const u8,
    reference_linkage: []const u8,
    prepared_unix_seconds: i64,
};

const AssertionsPrepared = struct {
    schema_version: u32,
    key: struct {
        inputs: StringMap,
        sdk_image: []const u8,
        layout_revision: u32,
    },
    worker_sha256: []const u8,
    fixture_sha256: StringMap,
    build_commands: []const []const []const u8,
    validation: protocol.Outcome,
    toolchain: struct {
        compiler: []const u8,
        linker: []const u8,
        relr_supported: bool,
    },
    fixture_origin: []const u8,
};

pub fn preparedForReuse(allocator: std.mem.Allocator, value: json.Value) !json.Value {
    if (json.asInteger(json.field(value, "schema_version")) != prepared_version) return .null;

    try validatePrepared(allocator, value);
    return value;
}

pub fn validatePrepared(allocator: std.mem.Allocator, value: json.Value) !void {
    const prepared = std.json.parseFromValueLeaky(Prepared, allocator, value, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidCacheMetadata,
    };

    if (json.asInteger(json.field(value, "schema_version")) != prepared_version or
        json.asInteger(json.field(value, "prepared_unix_seconds")) == null or
        prepared.runtime != .object or prepared.sdk_key.runtime != .object or
        prepared.sdk.image_id.len == 0)
    {
        return error.InvalidCacheMetadata;
    }
}

pub fn assertionsForReuse(allocator: std.mem.Allocator, value: json.Value) !json.Value {
    if (json.asInteger(json.field(value, "schema_version")) != assertions_version) return .null;

    try validateAssertions(allocator, value);
    return value;
}

pub fn validateAssertions(allocator: std.mem.Allocator, value: json.Value) !void {
    const prepared = std.json.parseFromValueLeaky(AssertionsPrepared, allocator, value, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidCacheMetadata,
    };

    if (json.asInteger(json.field(value, "schema_version")) != assertions_version or
        prepared.validation.status != .pass)
    {
        return error.InvalidCacheMetadata;
    }

    protocol.validateOutcome(json.field(value, "validation")) catch return error.InvalidCacheMetadata;
}

test "prepared cache records require the current version and complete typed fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const runtime = .{
        .id = "test",
        .image = "image",
        .libc_path = "/lib/libc.so",
        .loader_path = "/lib/loader.so",
        .package_version = "1",
        .sdk_recipe = "alpine",
        .libc_family = "musl",
        .sdk_args = .{},
    };
    const identity = .{
        .image_id = "image",
        .libc_package_version = "1",
        .runtime_sha256 = .{ .libc = "digest" },
        .packages = "musl",
    };
    var record = try json.cloneViaSerialization(allocator, .{
        .schema_version = prepared_version,
        .runtime = runtime,
        .base = identity,
        .sdk = identity,
        .sdk_key = .{ .runtime = runtime, .recipe_sha256 = "digest" },
        .fixture_key = .{
            .sdk_image_id = "image",
            .flags = [_][]const u8{"-O0"},
            .source_hashes = .{ .source = "digest" },
        },
        .worker_sha256 = "digest",
        .zig_version = "test",
        .compiler = "cc",
        .build_commands = [_][]const []const u8{&.{ "cc", "source.c" }},
        .source_hashes = .{ .source = "digest" },
        .fixture_sha256 = .{ .fixture = "digest" },
        .sdk_archive_sha256 = "digest",
        .runtime_archive_sha256 = @as(?[]const u8, null),
        .reference_linkage = "libc",
        .prepared_unix_seconds = 1,
    });

    try validatePrepared(allocator, record);
    try std.testing.expect(json.eql(record, try preparedForReuse(allocator, record)));
    try std.testing.expectError(error.InvalidCacheMetadata, validatePrepared(allocator, .null));

    try json.putField(allocator, &record, "schema_version", .{ .integer = 2 });
    try std.testing.expectError(error.InvalidCacheMetadata, validatePrepared(allocator, record));
    try json.putField(allocator, &record, "schema_version", .{ .integer = prepared_version });

    _ = record.object.swapRemove("sdk_key");
    try std.testing.expectError(error.InvalidCacheMetadata, validatePrepared(allocator, record));
    try std.testing.expectError(error.InvalidCacheMetadata, preparedForReuse(allocator, record));
}

test "cache reuse requires the current schema version" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    inline for (.{ preparedForReuse, assertionsForReuse }, .{ prepared_version, assertions_version }) |reuse, current_version| {
        for ([_]i64{ current_version - 1, current_version + 1 }) |version| {
            const record = try json.cloneViaSerialization(allocator, .{ .schema_version = version });
            try std.testing.expect((try reuse(allocator, record)) == .null);
        }
        for ([_][]const u8{
            "null",
            "{}",
            "{\"schema_version\":\"2\"}",
            "{\"schema_version\":2.0}",
            "{\"schema_version\":0}",
            "{\"schema_version\":-1}",
        }) |text| {
            try std.testing.expect((try reuse(allocator, try json.parse(allocator, text))) == .null);
        }
    }
}

test "assertion cache records require a complete successful validation outcome" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    var record = try json.cloneViaSerialization(allocator, .{
        .schema_version = assertions_version,
        .key = .{
            .inputs = .{ .fixture = "digest" },
            .sdk_image = "image",
            .layout_revision = 1,
        },
        .worker_sha256 = "digest",
        .fixture_sha256 = .{ .fixture = "digest" },
        .build_commands = [_][]const []const u8{&.{ "cc", "source.c" }},
        .validation = protocol.Outcome{ .status = .pass },
        .toolchain = .{ .compiler = "SDK cc", .linker = "SDK ld", .relr_supported = true },
        .fixture_origin = "test",
    });

    try validateAssertions(allocator, record);
    try std.testing.expect(json.eql(record, try assertionsForReuse(allocator, record)));

    const outcome = record.object.getPtr("validation").?;
    _ = outcome.object.swapRemove("exit_code");
    try std.testing.expectError(error.InvalidCacheMetadata, validateAssertions(allocator, record));
    try std.testing.expectError(error.InvalidCacheMetadata, assertionsForReuse(allocator, record));

    try json.putField(allocator, outcome, "exit_code", json.string("0"));
    try std.testing.expectError(error.InvalidCacheMetadata, validateAssertions(allocator, record));

    try json.putField(allocator, outcome, "exit_code", .{ .integer = 0 });
    try json.putField(allocator, outcome, "status", json.string("failure"));
    try std.testing.expectError(error.InvalidCacheMetadata, validateAssertions(allocator, record));
}
