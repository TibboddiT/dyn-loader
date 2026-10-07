const std = @import("std");

pub const Value = std.json.Value;

pub fn requireAllFields(comptime T: type, value: Value) !void {
    if (value != .object) return error.InvalidData;

    inline for (@typeInfo(T).@"struct".field_names) |name| {
        if (!value.object.contains(name)) return error.InvalidData;
    }
}

pub fn field(value: Value, key: []const u8) Value {
    if (value != .object) return .null;

    return value.object.get(key) orelse .null;
}

pub fn asString(value: Value) ?[]const u8 {
    return if (value == .string) value.string else null;
}

pub fn stringField(value: Value, key: []const u8) []const u8 {
    return asString(field(value, key)) orelse "";
}

pub fn requireString(value: Value, key: []const u8) ![]const u8 {
    const text = asString(field(value, key)) orelse return error.InvalidManifest;
    if (text.len == 0) return error.InvalidManifest;

    return text;
}

pub fn asInteger(value: Value) ?i64 {
    return if (value == .integer) value.integer else null;
}

pub fn isString(value: Value, expected: []const u8) bool {
    const text = asString(value) orelse return false;

    return std.mem.eql(u8, text, expected);
}

pub fn string(text: []const u8) Value {
    return .{ .string = text };
}

pub fn object() Value {
    return .{ .object = .empty };
}

pub fn array(allocator: std.mem.Allocator) Value {
    return .{ .array = std.array_list.Managed(Value).init(allocator) };
}

pub fn putField(allocator: std.mem.Allocator, value: *Value, key: []const u8, item: Value) !void {
    try value.object.put(allocator, key, item);
}

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Value {
    return std.json.parseFromSliceLeaky(Value, allocator, bytes, .{ .allocate = .alloc_always });
}

pub fn cloneViaSerialization(allocator: std.mem.Allocator, data: anytype) !Value {
    const bytes = try std.json.Stringify.valueAlloc(allocator, data, .{});
    defer allocator.free(bytes);

    return parse(allocator, bytes);
}

pub fn eql(left: Value, right: Value) bool {
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) return false;

    return switch (left) {
        .null => true,
        .bool => left.bool == right.bool,
        .integer => left.integer == right.integer,
        .float => left.float == right.float,
        .number_string => std.mem.eql(u8, left.number_string, right.number_string),
        .string => std.mem.eql(u8, left.string, right.string),
        .array => arrays_equal: {
            if (left.array.items.len != right.array.items.len) break :arrays_equal false;

            for (left.array.items, right.array.items) |left_item, right_item| {
                if (!eql(left_item, right_item)) break :arrays_equal false;
            }

            break :arrays_equal true;
        },
        .object => objects_equal: {
            if (left.object.count() != right.object.count()) break :objects_equal false;

            var entries = left.object.iterator();
            while (entries.next()) |entry| {
                const right_item = right.object.get(entry.key_ptr.*) orelse break :objects_equal false;
                if (!eql(entry.value_ptr.*, right_item)) break :objects_equal false;
            }

            break :objects_equal true;
        },
    };
}

test "JSON cache identity ignores object order but not values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const ordered = try parse(allocator, "{\"a\":1,\"b\":2}");
    const reordered = try parse(allocator, "{\"b\":2,\"a\":1}");

    try std.testing.expect(eql(ordered, reordered));

    const original = try parse(allocator, "{\"a\":1}");
    const changed = try parse(allocator, "{\"a\":2}");

    try std.testing.expect(!eql(original, changed));
}
