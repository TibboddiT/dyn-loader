//! Borrowed code bytes with an address origin.
//! Object-backed views use ELF virtual addresses.
//! Byte-pattern searches do not establish instruction boundaries.

const std = @import("std");

const DynObject = @import("DynObject.zig");

const CodeView = @This();

bytes: []const u8,
address: usize,

/// Borrows unchecked bytes. Relative targets use `address`.
pub fn fromBytes(bytes: []const u8, address: usize) CodeView {
    return .{ .bytes = bytes, .address = address };
}

/// Borrows a readable, executable range from the supplied mapped object.
/// The object must remain loaded for the lifetime of the view.
pub fn fromDynObject(dyn_object: *const DynObject, virtual_address: usize, size_bytes: usize) !CodeView {
    return fromBytes(try dyn_object.mappedCodeBytes(virtual_address, size_bytes), virtual_address);
}

/// Borrows a symbol's code, rejecting definitions in another object.
/// Does not consume the inspection. The object must outlive the view.
pub fn fromSymbol(object: DynObject.Inspection, name: []const u8) !CodeView {
    const definition = try object.lookup(object.object, name);
    if (definition.object != object.object) return error.InvalidCodeAddress;

    return fromDynObject(object.object, definition.symbol.value, definition.symbol.size);
}

/// Borrows a subrange with its address advanced by `offset`.
pub fn slice(code: CodeView, offset: usize, size: usize) !CodeView {
    if (offset > code.bytes.len or size > code.bytes.len - offset) return error.TruncatedCodePattern;

    const virtual_address = std.math.add(usize, code.address, offset) catch return error.InvalidCodeAddress;
    return .{
        .bytes = code.bytes[offset..][0..size],
        .address = virtual_address,
    };
}

pub fn readI32(code: CodeView, offset: usize) !i32 {
    const operand = try code.slice(offset, 4);
    return std.mem.readInt(i32, operand.bytes[0..4], .little);
}

/// Matches `bytes` at `cursor` and advances it by `bytes.len` on success.
/// Leaves `cursor` unchanged on failure.
/// Use complete known encodings or `InstructionFlow` when decoding is required.
pub fn expectBytes(code: CodeView, cursor: *usize, bytes: []const u8) !void {
    if (!std.mem.eql(u8, (try code.slice(cursor.*, bytes.len)).bytes, bytes)) return error.CodePatternMismatch;
    cursor.* += bytes.len;
}

/// Matches `prefix` followed by a signed 32-bit operand equal to `expected`.
/// If the operand check fails, `cursor` remains after the matched prefix.
pub fn expectI32Operand(code: CodeView, cursor: *usize, prefix: []const u8, expected: i64) !void {
    try code.expectBytes(cursor, prefix);
    if (try code.readI32(cursor.*) != expected) return error.CodePatternMismatch;
    cursor.* += 4;
}

pub fn requireUniqueI32Operand(code: CodeView, prefix: []const u8, expected: i64, suffix: []const u8) !void {
    const suffix_offset = std.math.add(usize, prefix.len, 4) catch return error.TruncatedCodePattern;
    const pattern_size = std.math.add(usize, suffix_offset, suffix.len) catch return error.TruncatedCodePattern;
    if (pattern_size > code.bytes.len) return error.CodePatternMismatch;

    var found = false;
    for (0..code.bytes.len - pattern_size + 1) |offset| {
        const candidate = code.bytes[offset..][0..pattern_size];
        if (!std.mem.eql(u8, candidate[0..prefix.len], prefix)) continue;
        if (std.mem.readInt(i32, candidate[prefix.len..][0..4], .little) != expected) continue;
        if (!std.mem.eql(u8, candidate[suffix_offset..], suffix)) continue;

        if (found) return error.AmbiguousCodePattern;
        found = true;
    }

    if (!found) return error.CodePatternMismatch;
}

/// Finds a RIP-relative reference or `rel32` branch to a virtual address.
/// `trailing_bytes` accounts for operands following the displacement.
pub fn findUniqueRelativeReference(code: CodeView, prefix: []const u8, target: usize, suffix: []const u8, trailing_bytes: usize) !?usize {
    const suffix_offset = std.math.add(usize, prefix.len, 4) catch return error.TruncatedCodePattern;
    const pattern_size = std.math.add(usize, suffix_offset, suffix.len) catch return error.TruncatedCodePattern;
    if (pattern_size > code.bytes.len) return null;

    var found: ?usize = null;
    for (0..code.bytes.len - pattern_size + 1) |offset| {
        const candidate = code.bytes[offset..][0..pattern_size];
        if (!std.mem.eql(u8, candidate[0..prefix.len], prefix) or !std.mem.eql(u8, candidate[suffix_offset..], suffix)) continue;

        const reference = std.math.add(usize, try code.relativeTarget(offset + prefix.len), trailing_bytes) catch return error.InvalidCodeAddress;
        if (reference != target) continue;

        if (found != null) return error.AmbiguousCodePattern;
        found = offset;
    }

    return found;
}

/// Resolves `rel32` from the end of its four-byte operand.
/// The caller must account for any trailing instruction bytes.
pub fn relativeTarget(code: CodeView, operand_offset: usize) !usize {
    const operand = try code.slice(operand_offset, 4);
    const next_instruction_address = std.math.add(usize, operand.address, 4) catch return error.InvalidCodeAddress;
    const displacement = try code.readI32(operand_offset);

    return addDisplacement(next_instruction_address, displacement);
}

pub fn addDisplacement(address: usize, displacement: i32) !usize {
    // Widen before negation: the magnitude of minimum `i32` does not fit in `i32`.
    const safe_displacement: i64 = displacement;
    if (safe_displacement < 0) {
        return std.math.sub(usize, address, @intCast(-safe_displacement)) catch error.InvalidCodeAddress;
    }

    return std.math.add(usize, address, @intCast(safe_displacement)) catch error.InvalidCodeAddress;
}

/// Returns the byte offset of the only match for `prefix` and `suffix`,
/// separated by `gap_bytes` bytes.
/// Returns `null` if no match exists, or `error.AmbiguousCodePattern` if several exist.
pub fn findUnique(code: CodeView, prefix: []const u8, gap_bytes: usize, suffix: []const u8) !?usize {
    const suffix_offset = std.math.add(usize, prefix.len, gap_bytes) catch return error.TruncatedCodePattern;
    const pattern_size = std.math.add(usize, suffix_offset, suffix.len) catch return error.TruncatedCodePattern;
    if (pattern_size == 0 or pattern_size > code.bytes.len) return null;

    var match_offset: ?usize = null;
    for (0..code.bytes.len - pattern_size + 1) |offset| {
        const candidate = code.bytes[offset..][0..pattern_size];
        if (!std.mem.eql(u8, candidate[0..prefix.len], prefix)) continue;
        if (!std.mem.eql(u8, candidate[suffix_offset..], suffix)) continue;

        if (match_offset != null) return error.AmbiguousCodePattern;
        match_offset = offset;
    }

    return match_offset;
}
