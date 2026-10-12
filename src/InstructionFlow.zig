//! Bounded integer dataflow for native code inspection on x86-64 Linux.
//! The project uses a statically linked host and loads 64-bit ELF libraries.
//! Native function calls follow the System V AMD64 ABI; `syscall` instructions
//! use the separate Linux syscall convention. Pointers are 64 bits.
//!
//! Decode from instruction boundaries and merge facts at control-flow joins.
//! Unknown reachable instructions reject inspection; unknown values cannot prove a fact.
//! This is not an emulator. Calls preserve only ABI callee-saved register facts,
//! and memory tracking is restricted to fixed stack slots and symbolic addresses.
//!
//! Construction first decodes reachable instructions, then propagates symbolic
//! states along both sides of conditional branches. At a join, only compatible
//! facts survive. Repeated propagation stops when no incoming state changes.
//! Branch conditions are recorded for backend inspection, not used to select a
//! path. A fact therefore describes the modeled paths, not one execution trace.
//!
//! The result owns its node array and borrows `CodeView` bytes and option context.
//! Copies of the result share that allocation; only its owner calls `deinit`.

const std = @import("std");

const CodeView = @import("CodeView.zig");
const logger = @import("logger.zig");

const Self = @This();

// Symbolic values and incoming instruction states.
// ------------------------------------------------

/// Register indices use the x86 encoding order, including the REX extension bit.
/// These names distinguish ABI-required registers from compiler-selected ones.
pub const Register = struct {
    pub const rax: u4 = 0;
    pub const rcx: u4 = 1;
    pub const rdx: u4 = 2;
    pub const rbx: u4 = 3;
    pub const rsp: u4 = 4;
    pub const rbp: u4 = 5;
    pub const rsi: u4 = 6;
    pub const rdi: u4 = 7;
    // Registers `r8` through `r15` use their numeric suffix as the index.
};

const function_arguments = [_]u4{ Register.rdi, Register.rsi, Register.rdx, Register.rcx, 8, 9 };
const caller_saved_registers = [_]u4{ Register.rax, Register.rcx, Register.rdx, Register.rsi, Register.rdi, 8, 9, 10, 11 };

/// Symbolic values, not values read from the loaded process. `address` names an
/// ELF virtual address; `global` means the contents of that address. `thread`
/// originates at a configured `FS` self-pointer offset. `call` identifies one
/// return value by call-site offset.
/// Field values retain that origin, so two unrelated pointer registers cannot
/// establish a descriptor copy merely because their offsets happen to match.
///
/// Payload convention (`load` below denotes a symbolic read, not a host read):
/// - `unknown`: no usable value; `constant`: integer `a`; `range`: inclusive `[a,b]`.
/// - `address`: ELF address `a`; `global`: `load(a)`.
/// - `global_address`: `load(a) + b`; `global_field`: `load(load(a) + b)`.
/// - `indirect_address`: `load(load(a) + b) + c`.
/// - `sum`: fields at offsets `b` and `c` from `load(a)`, added with `bias`.
/// - `thread`: current thread pointer; `thread_address`: that pointer plus `b`;
///   `thread_field`: contents at that offset.
/// - `stack`: entry stack pointer plus signed byte offset `a`.
/// - `call`: return from call-site byte offset `a`, with ELF target in `b`;
///   `call_address`: that return value plus `b`; `call_field`: contents there.
///
/// For example, loading a GOT slot produces `global`, adding a structure offset
/// produces `global_address`, and loading that field produces `global_field`.
/// Unused payload fields stay zero because equality compares the whole value.
pub const Value = struct {
    kind: enum {
        unknown,
        constant,
        range,
        address,
        global,
        global_address,
        global_field,
        indirect_address,
        sum,
        thread,
        stack,
        call,
        thread_field,
        call_field,
        thread_address,
        call_address,
    } = .unknown,
    a: i64 = 0, // Constant/address, stack offset, call-site identity, or range lower bound.
    b: i64 = 0, // Field offset, call target, or range upper bound; unused for scalar values.
    c: i64 = 0, // Second field in a sum, or displacement through a field's pointer.
    bias: i64 = 0, // Constant term in a sum of two fields.
    bits: u8 = 0, // Nonzero for a narrow field value; it cannot establish a full pointer.
    // Marks a pointer whose escape the caller is checking. Losing its exact
    // origin at a join must not make the pointer appear safe to retain elsewhere.
    tainted: bool = false,

    /// Tests only the kind and primary payload, not full symbolic equality.
    pub fn is(v: Value, kind: @FieldType(Value, "kind"), a: i64) bool {
        return v.kind == kind and v.a == a;
    }

    fn eql(a: Value, b: Value) bool {
        return std.meta.eql(a, b);
    }

    fn merge(a: Value, b: Value) Value {
        if (a.eql(b)) return a;

        // Keep the adjacent alternatives used by native detach-state selection.
        // This is a restricted range model, not general interval arithmetic.
        if (a.kind == .constant and b.kind == .constant and @abs(@as(i128, a.a) - b.a) == 1) {
            return .{ .kind = .range, .a = @min(a.a, b.a), .b = @max(a.a, b.a) };
        }
        if (a.kind == .range and b.kind == .constant and b.a >= a.a and b.a <= a.b) return a;
        if (b.kind == .range and a.kind == .constant and a.a >= b.a and a.a <= b.b) return b;
        return .{ .tainted = a.tainted or b.tainted };
    }
};

pub const Memory = struct {
    // Effective address: base + index * scale + signed displacement. `rip`
    // uses the end of the instruction as the base; `fs` selects the thread base.
    base: ?u4 = null,
    index: ?u4 = null,
    scale: u4 = 1,
    displacement: i64 = 0,
    rip: bool = false,
    fs: bool = false,
};

pub const Operand = union(enum) {
    none,
    reg: u4,
    high: u2, // `AH`, `CH`, `DH`, `BH`: index of the containing GPR.
    vector: u4, // XMM register, represented as two low-to-high 64-bit lanes.
    memory: Memory,
    immediate: i64,
};

// These are analysis operations, not a one-to-one list of machine mnemonics.
// `clobber` means the encoding is understood but no result fact is retained.
pub const Op = enum {
    mov,
    lea,
    add,
    sub,
    sbb,
    bit_and,
    bit_xor,
    compare,
    call,
    jump,
    branch,
    ret,
    push,
    pop,
    leave,
    cmov,
    setcc,
    clobber,
    exchange,
    string_store,
    divide,
    multiply,
    vector_move,
    vector_unpack,
    vector_high,
    vector_shift,
    vector_add,
    vector_xor,
    nop,
    syscall,
};

pub const Instruction = struct {
    // Half-open byte range within `CodeView`, not ELF addresses or node indices.
    offset: usize,
    end: usize,
    op: Op,
    width: u8 = 0, // Operand width in bits; zero where the operation needs none.
    dst: Operand = .none,
    src: Operand = .none,
    target: ?usize = null, // ELF virtual address for a direct call or branch.
    condition: ?u4 = null, // x86 condition code for a conditional branch.
    trap: bool = false, // A terminating trap uses `.ret` but cannot return.
};

const Slot = struct {
    offset: i64 = 0,
    value: Value = .{},
    used: bool = false,
};

/// Register and private-stack facts before an instruction. Stack slots each
/// represent eight bytes relative to the entry stack pointer, even after `RSP`
/// moves. Arbitrary native memory is represented by origin, not simulated writes.
pub const State = struct {
    registers: [16]Value = @splat(.{}),
    vectors: [16][2]Value = @splat(@splat(.{})),
    slots: [32]Slot = @splat(.{}),
    stack_exposed: bool = false, // Sticky once an unproved callee/store can retain a frame pointer.

    /// Merges incoming facts into state. Returns true if any fact or the
    /// stack-exposure flag changes; false if state is unchanged.
    /// Borrows incoming facts for this call. Every fact is merged even after a
    /// change is detected; only further change-detection comparisons are skipped.
    fn merge(state: *State, incoming: *const State) bool {
        var changed = !state.stack_exposed and incoming.stack_exposed;
        state.stack_exposed = state.stack_exposed or incoming.stack_exposed;

        for (&state.registers, &incoming.registers) |*v, other| {
            const merged = v.merge(other);
            changed = changed or !v.eql(merged);
            v.* = merged;
        }
        for (&state.vectors, &incoming.vectors) |*pair, *other| {
            for (pair, other) |*v, lane| {
                const merged = v.merge(lane);
                changed = changed or !v.eql(merged);
                v.* = merged;
            }
        }

        // A spill present on only one incoming path is unknown at the join.
        for (&state.slots) |*slot| {
            if (!slot.used) continue;

            const merged = slot.value.merge(incoming.stackValue(slot.offset));
            changed = changed or !slot.value.eql(merged);
            slot.value = merged;
        }
        return changed;
    }

    fn stackValue(state: *const State, offset: i64) Value {
        for (&state.slots) |*slot| {
            if (slot.used and slot.offset == offset) return slot.value;
        }
        return .{};
    }

    fn putStack(state: *State, offset: i64, stored_value: Value) void {
        for (&state.slots) |*slot| {
            if (slot.used and slot.offset == offset) {
                slot.value = stored_value;
                return;
            }
        }
        for (&state.slots) |*slot| {
            if (!slot.used) {
                slot.* = .{ .used = true, .offset = offset, .value = stored_value };
                return;
            }
        }
        // An untracked spill cannot supply evidence later.
    }

    fn invalidateStack(state: *State, offset: i64, size: u8) void {
        // A partial overwrite destroys the whole eight-byte fact. Widen the
        // interval arithmetic so extreme signed offsets cannot wrap the bounds.
        for (&state.slots) |*slot| {
            if (slot.used and @as(i128, offset) < @as(i128, slot.offset) + 8 and
                @as(i128, slot.offset) < @as(i128, offset) + size)
            {
                slot.value = .{};
            }
        }
    }
};

pub const Node = struct {
    instruction: Instruction,
    state: State = .{}, // Incoming state; executing the instruction uses a copy.
    reached: bool = false,
};

allocator: std.mem.Allocator,
code: CodeView,
nodes: std.ArrayList(Node),
options: Options,

pub const Options = struct {
    /// Native TCB self-pointer positions, relative to `FS`. glibc additionally
    /// exposes `tcbhead_t.self` at offset 16; musl inspection uses only offset 0.
    thread_self_offsets: []const i64 = &.{0},
    /// ELF call targets known not to return. Unused entries are `null`.
    noreturn_targets: [8]?usize = @splat(null),
    /// External conditional edges are rejected unless explicitly authorized.
    /// The validator is called only for reachable edges during construction.
    external_exits: [16]?usize = @splat(null),
    /// Borrowed context shared by both callbacks; required when either is used.
    external_exit_context: ?*anyopaque = null,
    validateExternalExit: ?*const fn (context: *anyopaque, address: usize) anyerror!bool = null,
    /// Known entry values. Unknown entries leave defaults intact, including `RSP`.
    initial_registers: [16]Value = @splat(.{}),
    /// A successful proof excludes retention, not writes through the argument.
    /// Existing spills are still invalidated; later spills remain private.
    /// Mask bits are register indices, not argument positions. For example,
    /// the first System V argument (`RDI`) sets bit 7.
    borrowsStackArguments: ?*const fn (context: *anyopaque, allocator: std.mem.Allocator, address: usize, argument_mask: u16) anyerror!bool = null,
    /// Retain the registers Linux preserves across `syscall`. The default drops
    /// volatile argument facts as well, to avoid attributing stale arguments to
    /// a subsequent call when no callee argument contract is available.
    preserve_syscall_arguments: bool = false,
    log_errors: bool = true,
};

// Reachable decoding and fixed-point propagation.
// -----------------------------------------------

/// Owns decoded instructions and their incoming states. The input bytes remain
/// borrowed. Direct branches must land on decoded boundaries inside the view;
/// a direct tail jump outside the function terminates that path.
pub fn init(allocator: std.mem.Allocator, code: CodeView) !Self {
    return initWithOptions(allocator, code, .{});
}

/// Builds the complete analysis or frees partial allocations on failure. Limits
/// bound code size, external exits, and propagation work; exceeding one rejects
/// inspection rather than returning a partially converged result.
pub fn initWithOptions(allocator: std.mem.Allocator, code: CodeView, options: Options) !Self {
    logger.debug("instruction.analysis: code_elf=0x{x} size={d} action=begin log_errors={}", .{ code.address, code.bytes.len, options.log_errors });
    errdefer logger.debug("instruction.analysis: code_elf=0x{x} size={d} action=rejected", .{ code.address, code.bytes.len });
    if (code.bytes.len == 0 or code.bytes.len > 16384) return error.InstructionAnalysisLimit;

    var self: Self = .{
        .allocator = allocator,
        .code = code,
        .nodes = .empty,
        .options = options,
    };
    errdefer self.deinit();

    // Each byte is unseen (0), an instruction start (1), or an interior byte (2).
    // Reject branches into an interior byte and overlapping alternative decodes.
    const occupied = try allocator.alloc(u8, code.bytes.len);
    defer allocator.free(occupied);
    @memset(occupied, 0);

    var pending: std.ArrayList(usize) = .empty;
    defer pending.deinit(allocator);
    try pending.append(allocator, 0);

    while (pending.pop()) |offset| {
        if (occupied[offset] == 1) continue;
        if (occupied[offset] != 0) return error.InvalidInstructionBranch;

        const instruction = decode(code, offset) catch |err| {
            if (options.log_errors) logger.err("native instruction analysis failed at ELF address 0x{x}: {s}", .{ code.address + offset, @errorName(err) });
            return err;
        };

        for (occupied[offset..instruction.end]) |byte| {
            if (byte != 0) return error.InvalidInstructionBranch;
        }
        @memset(occupied[offset..instruction.end], 2);
        occupied[offset] = 1;
        try self.nodes.append(allocator, .{ .instruction = instruction });

        // Calls are not followed into their callees. Branches add successors;
        // an external conditional edge needs the backend's explicit proof.
        if (instruction.op == .branch or instruction.op == .jump) {
            const target = instruction.target orelse return error.UnsupportedIndirectBranch;
            if (target >= code.address and target < code.address + code.bytes.len) {
                try pending.append(allocator, target - code.address);
            } else if (instruction.op == .branch and std.mem.indexOfScalar(?usize, &self.options.external_exits, target) == null) {
                const validate = self.options.validateExternalExit orelse return error.InvalidInstructionBranch;
                if (!try validate(self.options.external_exit_context.?, target)) return error.InvalidInstructionBranch;
                const slot = std.mem.indexOfScalar(?usize, &self.options.external_exits, null) orelse return error.InstructionAnalysisLimit;
                self.options.external_exits[slot] = target;
            }
        }
        if (instruction.op != .ret and instruction.op != .jump and !self.noReturn(instruction) and instruction.end < code.bytes.len) {
            try pending.append(allocator, instruction.end);
        }
    }

    // Address order makes the next array entry the fallthrough successor.
    // Entry `RSP` supplies an origin for prologue adjustments and stack spills.
    std.mem.sort(Node, self.nodes.items, {}, struct {
        fn less(_: void, a: Node, b: Node) bool {
            return a.instruction.offset < b.instruction.offset;
        }
    }.less);

    self.nodes.items[0].reached = true;
    self.nodes.items[0].state.registers[Register.rsp] = .{ .kind = .stack };
    for (options.initial_registers, 0..) |initial, reg| {
        if (initial.kind != .unknown) {
            self.nodes.items[0].state.registers[reg] = initial;
        }
    }

    // A first visit copies the predecessor state. Subsequent visits merge it;
    // loops require another pass whenever any successor loses or gains a fact.
    var changed = true;
    var iterations: usize = 0;
    while (changed) {
        iterations += 1;
        if (iterations > 128) {
            if (options.log_errors) logger.err("native dataflow did not converge at ELF address 0x{x}", .{code.address});
            return error.InstructionAnalysisLimit;
        }
        changed = false;

        for (self.nodes.items, 0..) |node, index| {
            if (!node.reached) continue;

            var state = node.state;
            try self.execute(&state, node.instruction);

            const instruction = node.instruction;
            if (instruction.op == .branch or instruction.op == .jump) {
                const target = instruction.target orelse return error.UnsupportedIndirectBranch;
                if (target >= code.address and target < code.address + code.bytes.len) {
                    const destination_index = self.indexAt(target - code.address) orelse return error.InvalidInstructionBranch;
                    changed = self.propagate(destination_index, &state) or changed;
                } else if (instruction.op == .branch and std.mem.indexOfScalar(?usize, &self.options.external_exits, target) == null) {
                    return error.InvalidInstructionBranch;
                }
            }
            if (instruction.op != .ret and instruction.op != .jump and !self.noReturn(instruction) and index + 1 < self.nodes.items.len) {
                changed = self.propagate(index + 1, &state) or changed;
            }
        }
    }

    logger.debug("instruction.analysis: code_elf=0x{x} action=converged instructions={d} iterations={d}", .{ code.address, self.nodes.items.len, iterations });
    if (logger.level == .debug) {
        for (self.nodes.items) |node| {
            if (!node.reached) continue;
            logger.debug("instruction.evidence: code_elf=0x{x} instruction_elf=0x{x} reached={} instruction={any} source={any} destination={any}", .{ code.address, code.address + node.instruction.offset, node.reached, node.instruction, self.value(node, node.instruction.src), self.destination(node) });
        }
    }
    return self;
}

fn noReturn(self: Self, instruction: Instruction) bool {
    if (instruction.op != .call or instruction.target == null) return false;
    for (self.options.noreturn_targets) |target| {
        if (target == instruction.target) return true;
    }
    return false;
}

pub fn deinit(self: *Self) void {
    self.nodes.deinit(self.allocator);
}

/// Bounds a private helper without a symbol size. A return before a known
/// forward branch target does not end the helper. The caller supplies a maximum
/// readable window; an incomplete body is rejected rather than guessed.
pub fn functionPrefix(code: CodeView) !CodeView {
    var offset: usize = 0;
    var last_target: usize = 0;
    while (offset < code.bytes.len) {
        const instruction = try decode(code, offset);
        if (instruction.op == .branch or instruction.op == .jump) {
            const target = instruction.target orelse return error.UnsupportedIndirectBranch;
            if (target < code.address or target >= code.address + code.bytes.len) return error.InvalidInstructionBranch;
            last_target = @max(last_target, target - code.address);
        }
        if (instruction.op == .ret and instruction.offset >= last_target) return code.slice(0, instruction.end);
        offset = instruction.end;
    }
    return error.TruncatedInstruction;
}

fn propagate(self: *Self, index: usize, state: *const State) bool {
    const node = &self.nodes.items[index];
    if (!node.reached) {
        node.state = state.*;
        node.reached = true;
        return true;
    }
    return node.state.merge(state);
}

/// Looks up a byte offset relative to the input view. Interior bytes do not match.
pub fn indexAt(self: Self, offset: usize) ?usize {
    for (self.nodes.items, 0..) |node, i| {
        if (node.instruction.offset == offset) return i;
    }
    return null;
}

/// Evaluates an operand at the fixed point, before its instruction executes.
pub fn value(self: Self, node: Node, operand: Operand) Value {
    return self.read(&node.state, node.instruction, operand);
}

/// Returns a memory destination's address, not its contents. Other destinations
/// return `unknown`; callers inspect the operand for register destinations.
pub fn destination(self: Self, node: Node) Value {
    return switch (node.instruction.dst) {
        .memory => |memory| self.address(&node.state, node.instruction, memory),
        .none, .reg, .high, .vector, .immediate => .{},
    };
}

/// Returns low and high 64-bit source lanes using the instruction's incoming state.
pub fn sourceLanes(self: Self, node: Node) [2]Value {
    return self.vectorValue(&node.state, node.instruction, node.instruction.src);
}

// Operand evaluation and instruction effects.
// -------------------------------------------

/// Computes a symbolic effective address without reading its contents. Only a
/// constant index, or the restricted two-field sum used by TLS rounding, survives.
fn address(self: Self, state: *const State, instruction: Instruction, memory: Memory) Value {
    if (memory.fs) {
        return if (!memory.rip and memory.base == null and memory.index == null)
            .{ .kind = .thread_address, .b = memory.displacement }
        else
            .{};
    }

    var displacement = memory.displacement;
    if (memory.index) |index| {
        const v = state.registers[index];
        if (v.kind != .constant) {
            if (memory.base != null and memory.scale == 1 and !memory.rip) {
                return addValues(state.registers[memory.base.?], v, memory.displacement);
            }
            return .{};
        }
        displacement = std.math.cast(i64, @as(i128, displacement) + @as(i128, v.a) * memory.scale) orelse return .{};
    }
    if (memory.rip) return .{ .kind = .address, .a = std.math.cast(i64, @as(i128, self.code.address) + instruction.end + displacement) orelse return .{} };
    if (memory.base) |base| {
        var v = state.registers[base];
        if (v.bits != 0) return .{};
        switch (v.kind) {
            .thread => return .{ .kind = .thread_address, .b = displacement },
            .call => return .{ .kind = .call_address, .a = v.a, .b = displacement, .tainted = v.tainted },
            .global => return .{ .kind = .global_address, .a = v.a, .b = displacement },
            .global_field => return .{ .kind = .indirect_address, .a = v.a, .b = v.b, .c = displacement },
            .address, .stack => v.a = std.math.add(i64, v.a, displacement) catch return .{},
            .thread_address, .call_address, .global_address => v.b = std.math.add(i64, v.b, displacement) catch return .{},
            .sum => v.bias = std.math.add(i64, v.bias, displacement) catch return .{},
            .unknown, .constant, .range, .indirect_address, .thread_field, .call_field => return .{},
        }
        return v;
    }
    return .{ .kind = .address, .a = displacement };
}

fn read(self: Self, state: *const State, instruction: Instruction, operand: Operand) Value {
    // Native memory reads retain a location's identity. Only private stack reads
    // recover previously stored values; this analyzer does not dereference ELF
    // addresses in the host process.
    return switch (operand) {
        .none => .{},
        .reg => |reg| if (state.registers[reg].bits == 0 or state.registers[reg].bits == instruction.width) state.registers[reg] else .{},
        .high => .{},
        .vector => |reg| state.vectors[reg][0],
        .immediate => |value_| .{ .kind = .constant, .a = value_ },
        .memory => |memory| blk: {
            if (memory.fs and !memory.rip and memory.base == null and memory.index == null and instruction.width == 64) {
                for (self.options.thread_self_offsets) |offset| {
                    if (memory.displacement == offset) break :blk .{ .kind = .thread };
                }
            }

            const location = self.address(state, instruction, memory);
            break :blk switch (location.kind) {
                .address => .{ .kind = .global, .a = location.a },
                .stack => if (instruction.width == 64) state.stackValue(location.a) else .{},
                .thread_address => .{ .kind = .thread_field, .b = location.b, .bits = if (instruction.width == 64) 0 else instruction.width },
                .global_address => .{ .kind = .global_field, .a = location.a, .b = location.b, .bits = if (instruction.width == 64) 0 else instruction.width },
                .call_address => .{ .kind = .call_field, .a = location.a, .b = location.b },
                .unknown, .constant, .range, .global, .global_field, .indirect_address, .sum, .thread, .call, .thread_field, .call_field => .{},
            };
        },
    };
}

fn write(self: Self, state: *State, instruction: Instruction, value_: Value) void {
    var result = value_;
    // A narrow write cannot preserve an arbitrary pointer. A 32-bit GPR write
    // zero-extends, while an 8/16-bit write leaves unmodeled upper bits intact.
    if (instruction.width < 64 and result.kind != .constant and result.kind != .range and result.bits != instruction.width) result = .{};
    switch (instruction.dst) {
        .reg => |reg| {
            if (instruction.width < 32 and result.bits != instruction.width) result = .{};
            if (instruction.width == 32 and result.kind == .constant) result.a = @as(u32, @truncate(@as(u64, @bitCast(result.a))));
            if (instruction.width == 32 and result.kind == .range and (result.a < 0 or result.b > std.math.maxInt(u32))) result = .{};
            state.registers[reg] = result;
        },
        .memory => |memory| {
            const location = self.address(state, instruction, memory);
            if (location.kind == .stack) {
                state.invalidateStack(location.a, instruction.width / 8);
                if (instruction.width == 64) state.putStack(location.a, result);
            } else {
                // Before a frame address escapes, a store through a native
                // object pointer cannot alias our private spill slots.
                if (result.kind == .stack) state.stack_exposed = true;
                if (location.kind == .unknown and state.stack_exposed) state.slots = @splat(.{});
            }
        },
        .vector => |reg| state.vectors[reg] = .{ result, .{} },
        .high => |reg| state.registers[reg] = .{},
        .none, .immediate => {},
    }
}

fn execute(self: Self, state: *State, instruction: Instruction) anyerror!void {
    const src = self.read(state, instruction, instruction.src);
    const dst = self.read(state, instruction, instruction.dst);

    switch (instruction.op) {
        .mov => self.write(state, instruction, src),
        .lea => self.write(state, instruction, self.address(state, instruction, instruction.src.memory)),
        .add, .sub => {
            var value_ = dst;
            if (src.kind == .constant and (dst.kind == .constant or dst.kind == .stack or dst.kind == .address)) {
                const result = @as(i128, value_.a) + (if (instruction.op == .add) @as(i128, src.a) else -@as(i128, src.a));
                value_ = if (std.math.cast(i64, result)) |number| .{ .kind = value_.kind, .a = number } else .{};
            } else if (instruction.op == .add) {
                value_ = addValues(dst, src, 0);
            } else if (dst.kind == .sum and src.kind == .constant) {
                value_.bias = std.math.sub(i64, dst.bias, src.a) catch {
                    self.write(state, instruction, .{});
                    return;
                };
            } else {
                value_ = .{};
            }

            self.write(state, instruction, value_);
        },
        .sbb => {
            // Carry is not tracked. Subtract-with-borrow therefore has two
            // possible results, differing by one, when both inputs are known.
            const fits_range = dst.kind == .constant and src.kind == .constant and
                @as(i128, dst.a) - src.a - 1 >= std.math.minInt(i64) and
                @as(i128, dst.a) - src.a <= std.math.maxInt(i64);
            const result: Value = if (fits_range)
                .{ .kind = .range, .a = dst.a - src.a - 1, .b = dst.a - src.a }
            else
                .{};
            self.write(state, instruction, result);
        },
        .bit_and => self.write(state, instruction, if (dst.kind == .constant and src.kind == .constant)
            .{ .kind = .constant, .a = dst.a & src.a }
        else
            .{}),
        .bit_xor => self.write(state, instruction, if (std.meta.eql(instruction.dst, instruction.src))
            .{ .kind = .constant, .a = 0 }
        else
            .{}),
        // Without flag tracking, either operand can survive a conditional move.
        .cmov => self.write(state, instruction, dst.merge(src)),
        .setcc, .clobber => self.write(state, instruction, .{}),
        .exchange => {
            self.write(state, instruction, .{});
            var other = instruction;
            other.dst = instruction.src;
            self.write(state, other, .{});
        },
        .call => {
            // A callee may write through a stack pointer passed as an argument.
            // Without a pointee extent, retain no spill facts across that call.
            var stack_arguments: u16 = 0;
            for (function_arguments) |reg| {
                if (state.registers[reg].kind == .stack) {
                    stack_arguments |= @as(u16, 1) << reg;
                }
            }

            var borrowed = false;
            if (stack_arguments != 0 and instruction.target != null) {
                if (self.options.borrowsStackArguments) |prove| {
                    borrowed = try prove(self.options.external_exit_context.?, self.allocator, instruction.target.?, stack_arguments);
                }
            }
            if (stack_arguments != 0 and !borrowed) state.stack_exposed = true;

            // Even a non-retaining callee can modify its output buffer.
            if (stack_arguments != 0) state.slots = @splat(.{});
            if (state.stack_exposed) state.slots = @splat(.{});
            for (caller_saved_registers) |reg| {
                state.registers[reg] = .{};
            }
            state.vectors = @splat(@splat(.{}));
            if (instruction.target) |target| {
                if (std.math.cast(i64, target)) |native_target| {
                    state.registers[Register.rax] = .{ .kind = .call, .a = @intCast(instruction.offset), .b = native_target };
                }
            }
        },
        .syscall => {
            // Model selected kernel output buffers before discarding register
            // facts. `rt_sigprocmask` writes its third argument; basic futex
            // wait/wake and `sched_setscheduler` do not write frame buffers.
            // Other syscalls discard all spills because their writes are unknown.
            const number = state.registers[Register.rax];
            if (number.is(.constant, @backingInt(std.os.linux.SYS.rt_sigprocmask))) {
                const output = state.registers[Register.rdx];
                if (output.kind == .stack) {
                    state.invalidateStack(output.a, 8);
                } else if (!output.is(.constant, 0) and state.stack_exposed) {
                    state.slots = @splat(.{});
                }
            } else if (number.is(.constant, @backingInt(std.os.linux.SYS.futex))) {
                const operation = state.registers[Register.rsi];
                // Low seven bits select the futex command; 0/1 are wait/wake.
                if (operation.kind != .constant or (operation.a & 0x7f) > 1) {
                    state.slots = @splat(.{});
                }
            } else if (!number.is(.constant, @backingInt(std.os.linux.SYS.sched_setscheduler))) {
                state.slots = @splat(.{});
            }

            if (self.options.preserve_syscall_arguments) {
                // Hardware overwrites `RCX`/`R11`; `RAX` holds the result.
                for ([_]u4{ Register.rax, Register.rcx, 11 }) |reg| {
                    state.registers[reg] = .{};
                }
            } else {
                for (caller_saved_registers) |reg| {
                    state.registers[reg] = .{};
                }
            }
        },
        .string_store => {
            // A native object being cleared does not alias private frame spills.
            // Lose spill facts when the destination is our stack, or when frame
            // addresses have escaped and the alias cannot be excluded.
            if (state.registers[7].kind == .stack or state.stack_exposed) state.slots = @splat(.{});
            state.registers[7] = .{};
            state.registers[1] = .{};
            if (instruction.src == .reg) state.registers[instruction.src.reg] = .{};
        },
        .push => {
            if (state.registers[Register.rsp].kind == .stack) {
                state.registers[Register.rsp].a = std.math.sub(i64, state.registers[Register.rsp].a, 8) catch {
                    state.registers[Register.rsp] = .{};
                    return;
                };
                state.invalidateStack(state.registers[Register.rsp].a, 8);
                state.putStack(state.registers[Register.rsp].a, src);
            }
        },
        .pop => {
            const sp = state.registers[Register.rsp];
            self.write(state, instruction, if (sp.kind == .stack) state.stackValue(sp.a) else .{});
            if (state.registers[Register.rsp].kind == .stack) {
                state.registers[Register.rsp] = if (std.math.add(i64, state.registers[Register.rsp].a, 8)) |stack_offset|
                    .{ .kind = .stack, .a = stack_offset }
                else |_|
                    .{};
            }
        },
        .leave => {
            // `leave` restores the stack from `RBP`, then pops the saved `RBP`.
            // An unknown frame pointer makes both restored values unknown.
            const frame = state.registers[Register.rbp];
            state.registers[Register.rbp] = if (frame.kind == .stack) state.stackValue(frame.a) else .{};
            if (frame.kind != .stack) {
                state.registers[Register.rsp] = .{};
                return;
            }

            const stack_offset = std.math.add(i64, frame.a, 8) catch {
                state.registers[Register.rsp] = .{};
                return;
            };
            state.registers[Register.rsp] = .{ .kind = .stack, .a = stack_offset };
        },
        .divide, .multiply => {
            // Backends inspect incoming operands. The quotient/product is not
            // needed as evidence, so both implicit result registers are forgotten.
            state.registers[Register.rax] = .{};
            state.registers[Register.rdx] = .{};
        },
        .vector_move => {
            // Preserve pointer-sized lanes across packed loads, copies, and
            // spills. A 32-bit transfer can only preserve a truncated constant.
            var pair = self.vectorValue(state, instruction, instruction.src);
            if (instruction.width == 32) {
                pair[0] = if (pair[0].kind == .constant) .{ .kind = .constant, .a = @as(u32, @truncate(@as(u64, @bitCast(pair[0].a)))) } else .{};
                pair[1] = .{ .kind = .constant, .a = 0 };
            }
            if (instruction.dst == .vector) {
                state.vectors[instruction.dst.vector] = pair;
            } else {
                var lane = instruction;
                lane.width = if (instruction.width == 128) 64 else instruction.width;
                self.write(state, lane, pair[0]);
                if (instruction.width == 128 and lane.dst == .memory) {
                    lane.dst.memory.displacement += 8;
                    self.write(state, lane, pair[1]);
                }
            }
        },
        .vector_unpack => {
            // `punpcklqdq` interleaves the low quadword of each operand.
            const reg = instruction.dst.vector;
            const low = state.vectors[reg][0];
            const source = self.vectorValue(state, instruction, instruction.src);
            state.vectors[reg] = .{ low, source[0] };
        },
        .vector_high => {
            // Register-form `movhlps` replaces only the destination's low half.
            const reg = instruction.dst.vector;
            const high = state.vectors[reg][1];
            const source = self.vectorValue(state, instruction, instruction.src);
            state.vectors[reg] = .{ source[1], high };
        },
        .vector_shift => {
            // Only the eight-byte `psrldq` shift preserves a whole known lane.
            const reg = instruction.dst.vector;
            const high = state.vectors[reg][1];
            state.vectors[reg] = if (instruction.src.immediate == 8) .{ high, .{ .kind = .constant, .a = 0 } } else @splat(.{});
        },
        .vector_add => {
            const reg = instruction.dst.vector;
            const left = state.vectors[reg];
            const right = self.vectorValue(state, instruction, instruction.src);
            state.vectors[reg] = .{ addValues(left[0], right[0], 0), addValues(left[1], right[1], 0) };
        },
        .vector_xor => {
            state.vectors[instruction.dst.vector] = if (std.meta.eql(instruction.dst, instruction.src)) @splat(.{ .kind = .constant, .a = 0 }) else @splat(.{});
        },
        .compare, .jump, .branch, .ret, .nop => {},
    }
}

fn vectorValue(self: Self, state: *const State, instruction: Instruction, operand: Operand) [2]Value {
    if (operand == .vector) return state.vectors[operand.vector];

    var lane = instruction;
    lane.width = 64;
    const low = self.read(state, lane, operand);
    if (instruction.width != 128 or operand != .memory) return .{ low, .{ .kind = .constant, .a = 0 } };

    var high_operand = operand;
    high_operand.memory.displacement += 8;
    return .{ low, self.read(state, lane, high_operand) };
}

fn addValues(left: Value, right: Value, bias: i64) Value {
    // Canonicalize the field order so scalar and packed addition produce the
    // same TLS numerator. Both fields must come from the same indirect global.
    if (left.kind == .global_field and right.kind == .global_field and left.a == right.a and left.bits == 0 and right.bits == 0) {
        return .{ .kind = .sum, .a = left.a, .b = @min(left.b, right.b), .c = @max(left.b, right.b), .bias = bias };
    }

    if (left.kind == .sum and right.kind == .constant) {
        var result = left;
        result.bias = std.math.cast(i64, @as(i128, left.bias) + right.a + bias) orelse return .{};
        return result;
    }
    if (right.kind == .constant and right.a == 0 and bias == 0) return left;
    return .{};
}

// Bounded x86-64 instruction decoding.
// ------------------------------------

const Reader = struct {
    bytes: []const u8,
    cursor: usize,

    fn byte(self: *Reader) !u8 {
        if (self.cursor >= self.bytes.len) return error.TruncatedInstruction;
        defer self.cursor += 1;
        return self.bytes[self.cursor];
    }

    /// Reads a signed little-endian operand. The decoder supplies widths from
    /// the encoding (1, 2, 4, or 8 bytes); no other size is an internal valid call.
    fn integer(self: *Reader, size: usize) !i64 {
        if (size > self.bytes.len - self.cursor) return error.TruncatedInstruction;
        defer self.cursor += size;
        return switch (size) {
            1 => @as(i8, @bitCast(self.bytes[self.cursor])),
            2 => std.mem.readInt(i16, self.bytes[self.cursor..][0..2], .little),
            4 => std.mem.readInt(i32, self.bytes[self.cursor..][0..4], .little),
            8 => std.mem.readInt(i64, self.bytes[self.cursor..][0..8], .little),
            else => unreachable,
        };
    }
};

/// Decodes the integer and legacy SIMD forms used by the inspected functions.
/// Selected packed integer operations retain two 64-bit lane facts; other known
/// operations may only invalidate their destinations. Unsupported encodings fail
/// instead of resynchronizing at an arbitrary byte that resembles an opcode.
pub fn decode(code: CodeView, offset: usize) !Instruction {
    var r: Reader = .{ .bytes = code.bytes, .cursor = offset };
    var rex: u8 = 0;
    var short = false;
    var fs = false;
    var address_override = false;
    var locked = false;
    var repeat: u8 = 0;
    var opcode = try r.byte();

    // Prefixes affect operand width, register extension, address interpretation,
    // and SIMD opcode selection. Here `short` records `0x66`; for SIMD that byte
    // can select an instruction rather than request a 16-bit operand.
    while (true) {
        switch (opcode) {
            0x40...0x4f => rex = opcode,
            0x66 => short = true,
            0x64 => fs = true,
            0x67 => address_override = true,
            0xf0 => locked = true,
            0xf2, 0xf3 => repeat = opcode,
            0x2e => {},
            else => break,
        }
        if (r.cursor - offset >= 14) return error.UnsupportedInstruction;
        opcode = try r.byte();
    }
    var instruction: Instruction = .{
        .offset = offset,
        .end = 0,
        .op = .nop,
        .width = if (rex & 8 != 0) 64 else if (short) 16 else 32,
    };
    var second: ?u8 = null;
    if (opcode == 0x0f) second = try r.byte();

    // Clang emits address-size-prefixed `ud1` traps. No address calculation is
    // executed for that instruction; other address-size overrides are rejected.
    if (address_override and second != 0xb9 and opcode != 0xe8 and opcode != 0xe9) return error.UnsupportedInstruction;
    var relative: ?i64 = null;
    const immediate_size: usize = if (short) 2 else 4;

    // Handle instructions without a ModR/M byte first. Relative destinations
    // are resolved only after all bytes have been consumed.
    if (opcode == 0xe8 or opcode == 0xe9 or opcode == 0xeb or (opcode >= 0x70 and opcode <= 0x7f) or (second != null and second.? >= 0x80 and second.? <= 0x8f)) {
        instruction.op = if (opcode == 0xe8) .call else if (opcode == 0xe9 or opcode == 0xeb) .jump else .branch;
        if (instruction.op == .branch) instruction.condition = @intCast((second orelse opcode) & 15);
        relative = try r.integer(if (opcode == 0xeb or (opcode >= 0x70 and opcode <= 0x7f)) 1 else 4);
    } else if (opcode >= 0x50 and opcode <= 0x5f) {
        instruction.op = if (opcode < 0x58) .push else .pop;
        instruction.width = 64;
        const reg: u4 = @intCast((opcode & 7) | ((rex & 1) << 3));
        if (instruction.op == .push) {
            instruction.src = .{ .reg = reg };
        } else {
            instruction.dst = .{ .reg = reg };
        }
    } else if (opcode >= 0xb8 and opcode <= 0xbf) {
        instruction.op = .mov;
        instruction.dst = .{ .reg = @intCast((opcode & 7) | ((rex & 1) << 3)) };
        instruction.src = .{ .immediate = try r.integer(if (instruction.width == 64) 8 else immediate_size) };
    } else if (opcode == 0x68 or opcode == 0x6a) {
        instruction.op = .push;
        instruction.src = .{ .immediate = try r.integer(if (opcode == 0x6a) 1 else 4) };
    } else if (opcode == 0xc9) {
        instruction.op = .leave;
    } else if (opcode == 0xc3 or opcode == 0xc2) {
        instruction.op = .ret;
        if (opcode == 0xc2) _ = try r.integer(2);
    } else if (opcode == 0x90 or opcode == 0xcc or (second != null and second.? == 0x1e)) {
        if (opcode == 0xcc) {
            instruction.op = .ret;
            instruction.trap = true;
        }
        if (second != null) {
            if (try r.byte() != 0xfa) return error.UnsupportedInstruction;
        }
    } else if (second == 0x0b) {
        instruction.op = .ret;
        instruction.trap = true;
    } else if (second != null and second.? == 0x05) {
        instruction.op = .syscall;
    } else if (opcode == 0xaa or opcode == 0xab or opcode == 0xa4 or opcode == 0xa5) {
        instruction.op = .string_store;
        if (opcode == 0xa4 or opcode == 0xa5) instruction.src = .{ .reg = 6 };
    } else if (opcode == 0x98 or opcode == 0x99) {
        instruction.op = .clobber;
        instruction.dst = .{ .reg = if (opcode == 0x98) 0 else 2 };
    } else if (opcode == 0xa8) {
        instruction.op = .compare;
        instruction.width = 8;
        instruction.dst = .{ .reg = 0 };
        instruction.src = .{ .immediate = try r.integer(1) };
    } else if (opcode == 0x25 or opcode == 0x05 or opcode == 0x2d or opcode == 0x3d or opcode == 0xa9) {
        instruction.op = switch (opcode) {
            0x25 => .bit_and,
            0x05 => .add,
            0x2d => .sub,
            0x3d, 0xa9 => .compare,
            else => unreachable,
        };
        instruction.dst = .{ .reg = 0 };
        instruction.src = .{ .immediate = try r.integer(immediate_size) };
    } else {
        // ModR/M contains an addressing mode, a register/opcode-extension field,
        // and a register-or-memory field. REX.R extends the register field;
        // REX.B extends the other register or memory base.
        const modrm = try r.byte();
        const mode = modrm >> 6;
        const group = (modrm >> 3) & 7;
        const reg: Operand = .{ .reg = @intCast(group | ((rex & 4) << 1)) };
        const low = modrm & 7;
        var rm: Operand = undefined;
        if (mode == 3) {
            rm = .{ .reg = @intCast(low | ((rex & 1) << 3)) };
        } else {
            var memory: Memory = .{ .fs = fs };
            if (low == 4) {
                // SIB encodes scale/index/base. Index 4 means no index unless
                // REX.X extends it; mode 0/base 5 means a displacement-only base.
                const sib = try r.byte();
                memory.scale = @as(u4, 1) << @as(u2, @intCast(sib >> 6));
                if ((sib >> 3) & 7 != 4 or rex & 2 != 0) memory.index = @intCast(((sib >> 3) & 7) | ((rex & 2) << 2));
                if (mode == 0 and sib & 7 == 5) {
                    memory.displacement = try r.integer(4);
                } else {
                    memory.base = @intCast((sib & 7) | ((rex & 1) << 3));
                }
            } else if (mode == 0 and low == 5) {
                memory.rip = true;
                memory.displacement = try r.integer(4);
            } else {
                memory.base = @intCast(low | ((rex & 1) << 3));
            }

            if (mode == 1) memory.displacement = try r.integer(1);
            if (mode == 2) memory.displacement = try r.integer(4);
            rm = .{ .memory = memory };
        }
        instruction.dst = rm;
        instruction.src = reg;
        // Most two-operand encodings default to `r/m <- reg`. Load forms swap
        // them below. SIMD uses the same encoded indices in the XMM register bank.
        const vector_reg: Operand = .{ .vector = reg.reg };
        const vector_rm: Operand = if (rm == .reg) .{ .vector = rm.reg } else rm;
        if (second) |op| {
            switch (op) {
                0xb9 => {
                    instruction.op = .ret;
                    instruction.trap = true;
                },
                0x1f => {},
                0x40...0x4f => {
                    instruction.op = .cmov;
                    instruction.dst = reg;
                    instruction.src = rm;
                },
                0x90...0x9f => {
                    instruction.op = .setcc;
                    instruction.width = 8;
                    instruction.src = .none;
                },
                0xb6, 0xb7, 0xbe, 0xbf, 0xaf, 0xbc, 0xbd => {
                    // Extension, multiplication, and bit-scan forms have known
                    // destinations but no modeled result for layout inspection.
                    instruction.op = .clobber;
                    instruction.dst = reg;
                    instruction.src = rm;
                },
                0xb1 => {
                    instruction.op = .exchange;
                    instruction.src = .{ .reg = 0 };
                },
                0xba => {
                    _ = try r.integer(1);
                    instruction.op = .clobber;
                },
                0x10, 0x28, 0x6f => {
                    // Packed moves preserve both lanes. Reject scalar `F2`/`F3`
                    // variants and unprefixed MMX forms with different semantics.
                    if (repeat != 0 and !(op == 0x6f and repeat == 0xf3)) return error.UnsupportedInstruction;
                    if (op == 0x6f and !short and repeat != 0xf3) return error.UnsupportedInstruction;
                    instruction.op = .vector_move;
                    instruction.width = 128;
                    instruction.dst = vector_reg;
                    instruction.src = vector_rm;
                },
                0x6e => {
                    if (!short or repeat != 0) return error.UnsupportedInstruction;
                    instruction.op = .vector_move;
                    instruction.width = if (rex & 8 != 0) 64 else 32;
                    instruction.dst = vector_reg;
                    instruction.src = rm;
                },
                0x6c, 0x12, 0xd4, 0x57, 0xef, 0x62 => {
                    if (repeat != 0) return error.UnsupportedInstruction;
                    if (op == 0x12 and short) return error.UnsupportedInstruction;
                    if (op != 0x12 and op != 0x57 and !short) return error.UnsupportedInstruction;
                    instruction.op = switch (op) {
                        0x6c => .vector_unpack,
                        0x12 => .vector_high,
                        0xd4 => .vector_add,
                        0x57, 0xef => .vector_xor,
                        0x62 => .clobber,
                        else => unreachable,
                    };
                    instruction.width = 128;
                    instruction.dst = vector_reg;
                    instruction.src = vector_rm;
                    if (op == 0x12 and rm != .reg) return error.UnsupportedInstruction;
                },
                0x73 => {
                    if (group != 3 or rm != .reg or !short or repeat != 0) return error.UnsupportedInstruction;
                    instruction.op = .vector_shift;
                    instruction.dst = vector_rm;
                    instruction.src = .{ .immediate = try r.integer(1) };
                },
                0x11, 0x29, 0x7f, 0xd6 => {
                    if (repeat != 0 and !(op == 0x7f and repeat == 0xf3)) return error.UnsupportedInstruction;
                    if ((op == 0x7f or op == 0xd6) and !short and repeat != 0xf3) return error.UnsupportedInstruction;
                    instruction.op = .vector_move;
                    instruction.width = if (op == 0xd6) 64 else 128;
                    instruction.dst = vector_rm;
                    instruction.src = vector_reg;
                },
                0x7e => {
                    if (!short and repeat != 0xf3) return error.UnsupportedInstruction;
                    instruction.op = .vector_move;
                    instruction.width = if (rex & 8 != 0 or repeat == 0xf3) 64 else 32;
                    instruction.dst = if (repeat == 0xf3) vector_reg else rm;
                    instruction.src = if (repeat == 0xf3) vector_rm else vector_reg;
                },
                else => return error.UnsupportedInstruction,
            }
        } else switch (opcode) {
            0x88, 0x89 => {
                instruction.op = .mov;
                if (opcode == 0x88) instruction.width = 8;
            },
            0x8a, 0x8b => {
                instruction.op = .mov;
                instruction.dst = reg;
                instruction.src = rm;
                if (opcode == 0x8a) instruction.width = 8;
            },
            0x8d => {
                if (rm != .memory) return error.UnsupportedInstruction;
                instruction.op = .lea;
                instruction.dst = reg;
                instruction.src = rm;
            },
            0xc6, 0xc7 => {
                if (group != 0) return error.UnsupportedInstruction;
                instruction.op = .mov;
                if (opcode == 0xc6) instruction.width = 8;
                instruction.src = .{ .immediate = try r.integer(if (opcode == 0xc6) 1 else immediate_size) };
            },
            0x80, 0x81, 0x83 => {
                // The ModR/M register field selects the arithmetic operation;
                // it is not a source register for these immediate forms.
                instruction.op = switch (group) {
                    0 => .add,
                    3 => .sbb,
                    4 => .bit_and,
                    5 => .sub,
                    6 => .bit_xor,
                    7 => .compare,
                    1, 2 => .clobber,
                    else => unreachable,
                };
                instruction.src = .{ .immediate = try r.integer(if (opcode == 0x81) immediate_size else 1) };
                if (opcode == 0x80) instruction.width = 8;
            },
            0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0b, 0x19, 0x1b, 0x21, 0x23, 0x29, 0x2b, 0x31, 0x33, 0x38, 0x39, 0x3a, 0x3b, 0x84, 0x85 => {
                instruction.op = switch (opcode & 0xf8) {
                    0 => .add,
                    0x18 => .sbb,
                    0x20 => .bit_and,
                    0x28 => .sub,
                    0x30 => .bit_xor,
                    0x38, 0x80 => .compare,
                    else => .clobber,
                };
                if (opcode & 2 != 0 and opcode < 0x80) {
                    instruction.dst = reg;
                    instruction.src = rm;
                }
                if (opcode & 1 == 0) instruction.width = 8;
            },
            0xff => {
                // Indirect calls can invalidate state without a known target.
                // Indirect jumps decode here but control-flow construction
                // rejects them because their successors cannot be enumerated.
                instruction.op = switch (group) {
                    0 => .add,
                    1 => .sub,
                    2 => .call,
                    4 => .jump,
                    6 => .push,
                    else => return error.UnsupportedInstruction,
                };
                instruction.src = if (group <= 1) .{ .immediate = 1 } else rm;
                if (group >= 2) instruction.width = 64;
            },
            0xf6, 0xf7 => {
                // Only unsigned division supplies a recognizable divisor.
                // The other multiply/divide forms discard the implicit results.
                if (opcode == 0xf6) instruction.width = 8;
                instruction.op = .clobber;
                if (group <= 1) {
                    instruction.op = .compare;
                    instruction.src = .{ .immediate = try r.integer(if (opcode == 0xf6) 1 else immediate_size) };
                }
                if (group >= 4) {
                    instruction.op = if (group == 6) .divide else .multiply;
                    instruction.src = rm;
                    instruction.dst = .none;
                }
            },
            0xc0, 0xc1 => {
                instruction.op = .clobber;
                _ = try r.integer(1);
            },
            0xd1, 0xd3, 0x63 => {
                instruction.op = .clobber;
                if (opcode == 0x63) instruction.dst = reg;
            },
            0x87 => instruction.op = .exchange,
            0x69, 0x6b => {
                instruction.op = .clobber;
                instruction.dst = reg;
                _ = try r.integer(if (opcode == 0x6b) 1 else immediate_size);
            },
            else => return error.UnsupportedInstruction,
        }
    }
    instruction.end = r.cursor;

    // Validate prefix/operand combinations after opcode selection. A recognized
    // byte sequence is insufficient if its prefixes describe a different effect.
    if (locked and (instruction.dst != .memory or switch (instruction.op) {
        .add, .sub, .sbb, .bit_and, .bit_xor, .exchange, .clobber => false,
        .mov, .lea, .compare, .call, .jump, .branch, .ret, .push, .pop, .leave, .cmov, .setcc, .string_store, .divide, .multiply, .vector_move, .vector_unpack, .vector_high, .vector_shift, .vector_add, .vector_xor, .nop, .syscall => true,
    })) return error.UnsupportedInstruction;

    if (instruction.width == 8 and rex == 0) {
        // Legacy `AH`..`BH` do not name the low bytes of registers 4..7.
        // Reads establish no layout fact; writes invalidate the actual parent.
        for ([_]*Operand{ &instruction.dst, &instruction.src }) |operand| {
            if (operand.* == .reg and operand.reg >= 4 and operand.reg <= 7) {
                const high: u2 = @intCast(operand.reg - 4);
                operand.* = .{ .high = high };
            }
        }
    }

    if (r.cursor - offset > 15) return error.UnsupportedInstruction;

    if (relative) |displacement| {
        // x86 relative branches use the address after the entire instruction.
        const target = @as(i128, code.address) + r.cursor + displacement;
        instruction.target = std.math.cast(usize, target) orelse return error.InvalidInstructionBranch;
    }

    return instruction;
}

// Inspection regressions.
// -----------------------

fn allocationFailureProbe(allocator: std.mem.Allocator) !void {
    // 32 nop instructions followed by ret.
    var bytes: [33]u8 = @splat(0x90);
    bytes[32] = 0xc3;

    var flow = try Self.init(allocator, CodeView.fromBytes(&bytes, 0));
    defer flow.deinit();
}

test "state merge detects unchanged facts and contained ranges" {
    var state: State = .{};
    state.registers[0] = .{ .kind = .range, .a = 2, .b = 3 };
    state.vectors[15][1] = .{ .kind = .address, .a = 0x1000 };
    state.putStack(-8, .{ .kind = .constant, .a = 7 });
    const before = state;
    try std.testing.expect(!state.merge(&state));

    var incoming = state;
    incoming.registers[0] = .{ .kind = .constant, .a = 2 };
    try std.testing.expect(!state.merge(&incoming));
    try std.testing.expectEqualDeep(before, state);
}

test "state merge updates every fact after detecting an early change" {
    var state: State = .{};
    state.registers[0] = .{ .kind = .constant, .a = 2 };
    state.registers[15] = .{ .kind = .address, .a = 0x1000 };
    state.vectors[0][0] = .{ .kind = .constant, .a = 10 };
    state.vectors[15][1] = .{ .kind = .address, .a = 0x2000 };
    state.putStack(-8, .{ .kind = .address, .a = 0x3000, .tainted = true });
    state.putStack(-16, .{ .kind = .constant, .a = 20 });

    var incoming: State = .{ .stack_exposed = true };
    incoming.registers[0] = .{ .kind = .constant, .a = 3 };
    incoming.registers[15] = .{ .kind = .address, .a = 0x4000, .tainted = true };
    incoming.vectors[0][0] = .{ .kind = .constant, .a = 11 };
    incoming.putStack(-16, .{ .kind = .constant, .a = 21 });
    incoming.putStack(-24, .{ .kind = .address, .a = 0x5000 });

    var expected: State = .{ .stack_exposed = true };
    expected.registers[0] = .{ .kind = .range, .a = 2, .b = 3 };
    expected.registers[15] = .{ .tainted = true };
    expected.vectors[0][0] = .{ .kind = .range, .a = 10, .b = 11 };
    expected.putStack(-8, .{ .tainted = true });
    expected.putStack(-16, .{ .kind = .range, .a = 20, .b = 21 });

    try std.testing.expect(state.merge(&incoming));
    try std.testing.expectEqualDeep(expected, state);
    try std.testing.expect(!state.merge(&incoming));
    try std.testing.expectEqualDeep(expected, state);
}

test "state merge stack exposure is a sticky change" {
    var state: State = .{};
    try std.testing.expect(state.merge(&.{ .stack_exposed = true }));
    try std.testing.expect(state.stack_exposed);
    try std.testing.expect(!state.merge(&.{}));
    try std.testing.expect(state.stack_exposed);
}

test "state merge detects changes confined to one fact category" {
    const Field = enum { register, vector, spill };
    for ([_]Field{ .register, .vector, .spill }) |field| {
        var state: State = .{};
        const fact: Value = .{ .kind = .address, .a = 0x1000 };
        switch (field) {
            .register => state.registers[15] = fact,
            .vector => state.vectors[15][1] = fact,
            .spill => state.putStack(-8, fact),
        }

        try std.testing.expect(state.merge(&.{}));
        try std.testing.expect(!state.merge(&.{}));
        try std.testing.expectEqual(Value{}, state.registers[15]);
        try std.testing.expectEqual(Value{}, state.vectors[15][1]);
        try std.testing.expectEqual(Value{}, state.stackValue(-8));
    }
}

test "main TSD assignment follows renamed registers, copies, and a lazy branch" {
    // mov rax, fs:[0]
    // test rax, rax
    // je assign
    // nop
    // assign:
    // lea rbx, [rip]
    // mov rdx, rbx
    // mov [rax+128], rdx
    // ret
    const bytes = "\x64\x48\x8b\x04\x25\x00\x00\x00\x00" ++
        "\x48\x85\xc0\x74\x01\x90\x48\x8d\x1d\x00\x00\x00\x00" ++
        "\x48\x89\xda\x48\x89\x90\x80\x00\x00\x00\xc3";
    var flow = try Self.init(std.testing.allocator, CodeView.fromBytes(bytes, 0x1000));
    defer flow.deinit();
    const store = flow.nodes.items[flow.nodes.items.len - 2];
    try std.testing.expectEqual(Value{ .kind = .thread_address, .b = 128 }, flow.destination(store));
    try std.testing.expect(flow.value(store, store.instruction.src).is(.address, 0x1016));
}

test "an overwritten pointer cannot establish an assignment" {
    // lea rbx, [rip]
    // xor ebx, ebx
    // mov [rax+128], rbx
    // ret
    const bytes = "\x48\x8d\x1d\x00\x00\x00\x00\x31\xdb\x48\x89\x98\x80\x00\x00\x00\xc3";
    var flow = try Self.init(std.testing.allocator, CodeView.fromBytes(bytes, 0));
    defer flow.deinit();
    const store = flow.nodes.items[2];
    try std.testing.expect(!flow.value(store, store.instruction.src).is(.address, 7));
}

test "conflicting branch definitions do not become an address fact" {
    // je alternate
    // lea rbx, [rip]
    // jmp assign
    // alternate:
    // lea rbx, [rip]
    // assign:
    // mov [rax+128], rbx
    // ret
    const bytes = "\x74\x09\x48\x8d\x1d\x00\x00\x00\x00\xeb\x07" ++
        "\x48\x8d\x1d\x00\x00\x00\x00\x48\x89\x98\x80\x00\x00\x00\xc3";
    var flow = try Self.init(std.testing.allocator, CodeView.fromBytes(bytes, 0));
    defer flow.deinit();
    const store = flow.nodes.items[4];
    try std.testing.expectEqual(Value{}, flow.value(store, store.instruction.src));
}

test "calls invalidate caller-saved facts but preserve callee-saved facts" {
    // lea rbx, [rip]
    // mov rcx, rbx
    // call 0x10f
    // ret
    const bytes = "\x48\x8d\x1d\x00\x00\x00\x00\x48\x89\xd9\xe8\x00\x01\x00\x00\xc3";
    var flow = try Self.init(std.testing.allocator, CodeView.fromBytes(bytes, 0));
    defer flow.deinit();
    const state = flow.nodes.items[3].state;
    try std.testing.expect(state.registers[3].is(.address, 7));
    try std.testing.expectEqual(Value{}, state.registers[1]);
}

test "stack spills preserve pointer provenance until an overlapping write" {
    // mov rax, fs:[0]
    // mov [rsp], rax
    const prefix = "\x64\x48\x8b\x04\x25\x00\x00\x00\x00\x48\x89\x04\x24";
    // mov rbx, [rsp]
    // ret
    const suffix = "\x48\x8b\x1c\x24\xc3";
    var intact = try Self.init(std.testing.allocator, CodeView.fromBytes(prefix ++ suffix, 0));
    defer intact.deinit();
    try std.testing.expect(intact.nodes.items[3].state.registers[3].kind == .thread);
    // Insert mov byte ptr [rsp+1], 0 between the spill and reload.
    var overwritten = try Self.init(std.testing.allocator, CodeView.fromBytes(prefix ++ "\xc6\x44\x24\x01\x00" ++ suffix, 0));
    defer overwritten.deinit();
    try std.testing.expectEqual(Value{}, overwritten.nodes.items[4].state.registers[3]);
}

test "instruction bytes embedded in an immediate are not decoded as instructions" {
    // mov rax, 0x1d8d48 (the immediate contains bytes resembling lea rbx, [rip])
    // ret
    const bytes = "\x48\xb8\x48\x8d\x1d\x00\x00\x00\x00\x00\xc3";
    var flow = try Self.init(std.testing.allocator, CodeView.fromBytes(bytes, 0));
    defer flow.deinit();
    try std.testing.expectEqual(@as(usize, 2), flow.nodes.items.len);
    // je 0x3 (into the mov instruction, after its REX prefix)
    // mov rax, rbx
    // ret
    try std.testing.expectError(error.InvalidInstructionBranch, Self.init(std.testing.allocator, CodeView.fromBytes("\x74\x01\x48\x89\xd8\xc3", 0)));
    // Truncated lea: REX.W and opcode, without the ModR/M byte.
    try std.testing.expectError(error.TruncatedInstruction, decode(CodeView.fromBytes("\x48\x8d", 0), 0));
    // vzeroupper (unsupported VEX encoding).
    try std.testing.expectError(error.UnsupportedInstruction, decode(CodeView.fromBytes("\xc5\xf8\x77", 0), 0));
}

test "inspection allocation failures release partial state" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailureProbe, .{});
}

test "a private helper includes forward branches beyond an early return" {
    // je alternate
    // ret
    // alternate:
    // xor eax, eax
    // ret
    // Trailing 0xff is an incomplete opcode outside the function prefix.
    const code = CodeView.fromBytes("\x74\x01\xc3\x31\xc0\xc3\xff", 0x1000);
    const prefix = try functionPrefix(code);
    try std.testing.expectEqual(@as(usize, 6), prefix.bytes.len);
    // je 0x81 (outside the supplied bytes)
    // ret
    try std.testing.expectError(error.InvalidInstructionBranch, functionPrefix(CodeView.fromBytes("\x74\x7f\xc3", 0)));
}

test "syscall argument registers do not expose a private spill to a later call" {
    // Clang spills the parent thread pointer before the first-thread transition.
    // The signal-mask syscall reads another stack slot. Its stale `RSI` must
    // not be interpreted as an argument to the later no-argument native helper.
    //
    // mov rax, fs:[0]
    // mov [rsp], rax
    // lea rsi, [rsp+8]
    // mov eax, 14
    // xor edx, edx
    // syscall
    // call 0x120
    // mov rbx, [rsp]
    // ret
    const bytes = "\x64\x48\x8b\x04\x25\x00\x00\x00\x00\x48\x89\x04\x24" ++
        "\x48\x8d\x74\x24\x08\xb8\x0e\x00\x00\x00\x31\xd2\x0f\x05" ++
        "\xe8\x00\x01\x00\x00\x48\x8b\x1c\x24\xc3";
    var flow = try Self.init(std.testing.allocator, CodeView.fromBytes(bytes, 0));
    defer flow.deinit();
    try std.testing.expect(flow.nodes.items[flow.nodes.items.len - 1].state.registers[3].kind == .thread);
}

test "address assignment accepts every non-stack temporary register" {
    for (1..16) |register| {
        if (register == 4) continue; // Preserve `RSP`; `RAX` holds the thread pointer.
        const rex: u8 = 0x48 | @as(u8, if (register >= 8) 4 else 0);
        const register_bits: u8 = @intCast((register & 7) << 3);
        const bytes = [_]u8{
            0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // `mov rax,fs:0`
            rex, 0x8d, register_bits | 5, 0, 0, 0, 0, // `lea temporary,[rip]`
            rex, 0x89, register_bits | 0x80, 128, 0, 0, 0, // `mov [rax+128],temporary`
            0xc3, // `ret`
        };
        var flow = try Self.init(std.testing.allocator, CodeView.fromBytes(&bytes, 0x1000));
        defer flow.deinit();
        const store = flow.nodes.items[2];
        try std.testing.expectEqual(Value{ .kind = .thread_address, .b = 128 }, flow.destination(store));
        try std.testing.expect(flow.value(store, store.instruction.src).is(.address, 0x1010));
    }
}

test "narrow register writes invalidate pointer provenance" {
    // lea rbx, [rip]
    // mov ebx, ebx
    // mov [rax+128], rbx
    // ret
    const bytes = "\x48\x8d\x1d\x00\x00\x00\x00\x89\xdb\x48\x89\x98\x80\x00\x00\x00\xc3";
    var flow = try Self.init(std.testing.allocator, CodeView.fromBytes(bytes, 0));
    defer flow.deinit();
    const store = flow.nodes.items[2];
    try std.testing.expectEqual(Value{}, flow.value(store, store.instruction.src));
}

test "FS-relative RIP access is not the thread-pointer load" {
    // mov rax, fs:[rip]
    // ret
    const bytes = "\x64\x48\x8b\x05\x00\x00\x00\x00\xc3";
    var flow = try Self.init(std.testing.allocator, CodeView.fromBytes(bytes, 0));
    defer flow.deinit();
    try std.testing.expectEqual(Value{}, flow.nodes.items[1].state.registers[0]);
}

test "legacy high-byte operands invalidate their actual parent register" {
    // test ah, 8
    const instruction = try decode(CodeView.fromBytes("\xf6\xc4\x08", 0), 0);
    try std.testing.expectEqual(Operand{ .high = 0 }, instruction.dst);
    // lea rax, [rip]
    // mov ah, cl
    // ret
    const bytes = "\x48\x8d\x05\x00\x00\x00\x00\x88\xcc\xc3";
    var flow = try Self.init(std.testing.allocator, CodeView.fromBytes(bytes, 0));
    defer flow.deinit();
    try std.testing.expectEqual(Value{}, flow.nodes.items[2].state.registers[0]);
}

test "glibc self pointer and hardware-preserved syscall registers are explicit" {
    // mov rdx, fs:[16]
    // mov eax, 186
    // syscall
    // mov [rdx+704], rdx
    // ret
    const bytes = "\x64\x48\x8b\x14\x25\x10\x00\x00\x00\xb8\xba\x00\x00\x00\x0f\x05" ++
        "\x48\x89\x92\xc0\x02\x00\x00\xc3";
    var flow = try Self.initWithOptions(std.testing.allocator, CodeView.fromBytes(bytes, 0), .{
        .thread_self_offsets = &.{ 0, 16 },
        .preserve_syscall_arguments = true,
    });
    defer flow.deinit();
    try std.testing.expectEqual(Value{ .kind = .thread_address, .b = 704 }, flow.destination(flow.nodes.items[3]));
    var ordinary = try Self.init(std.testing.allocator, CodeView.fromBytes(bytes, 0));
    defer ordinary.deinit();
    try std.testing.expectEqual(Value{}, ordinary.destination(ordinary.nodes.items[3]));
}

test "non-returning calls exclude following bytes and unknown external edges fail" {
    // call 0x2000
    // Trailing 0x62, 0x00 begins an unsupported EVEX encoding; it is unreachable
    // only when the call target is known not to return.
    const bytes = "\xe8\xfb\x0f\x00\x00\x62\x00";
    var options: Options = .{ .log_errors = false };
    options.noreturn_targets[0] = 0x2000;
    var flow = try Self.initWithOptions(std.testing.allocator, CodeView.fromBytes(bytes, 0x1000), options);
    defer flow.deinit();
    try std.testing.expectEqual(@as(usize, 1), flow.nodes.items.len);
    try std.testing.expectError(error.UnsupportedInstruction, Self.initWithOptions(std.testing.allocator, CodeView.fromBytes(bytes, 0x1000), .{ .log_errors = false }));
    // je 0x81 (outside the supplied bytes)
    // ret
    try std.testing.expectError(error.InvalidInstructionBranch, Self.init(std.testing.allocator, CodeView.fromBytes("\x74\x7f\xc3", 0)));
}

test "SIMD lane operations retain field origins and arithmetic bias" {
    // RAX initially holds a pointer loaded through a synthetic GOT slot.
    // movdqu xmm0, [rax+32]
    // movdqa xmm1, xmm0
    // movhlps xmm2, xmm0
    // psrldq xmm1, 8
    // movq r8, xmm2
    // paddq xmm0, xmm1
    // movq rcx, xmm0
    const prefix = "\xf3\x0f\x6f\x40\x20\x66\x0f\x6f\xc8\x0f\x12\xd0" ++
        "\x66\x0f\x73\xd9\x08\x66\x49\x0f\x7e\xd0\x66\x0f\xd4\xc1\x66\x48\x0f\x7e\xc1";
    // sub rcx, 1 or add rcx, -1; followed by ret.
    inline for (.{ "\x48\x83\xe9\x01", "\x48\x83\xc1\xff" }) |bias| {
        var options: Options = .{};
        options.initial_registers[Register.rax] = .{ .kind = .global, .a = 0x2000 };
        var flow = try Self.initWithOptions(std.testing.allocator, CodeView.fromBytes(prefix ++ bias ++ "\xc3", 0), options);
        defer flow.deinit();

        const state = flow.nodes.items[flow.nodes.items.len - 1].state;
        try std.testing.expectEqual(Value{ .kind = .global_field, .a = 0x2000, .b = 40 }, state.registers[8]);
        try std.testing.expectEqual(Value{ .kind = .sum, .a = 0x2000, .b = 32, .c = 40, .bias = -1 }, state.registers[Register.rcx]);
    }
}

test "packed pointer lanes survive spills and are replaced by zeroing" {
    // movq xmm5, r10
    // punpcklqdq xmm5, xmm5
    // movdqu [rsp], xmm5
    // pxor xmm5, xmm5
    // movdqu xmm6, [rsp]
    const prefix = "\x66\x49\x0f\x6e\xea\x66\x0f\x6c\xed\xf3\x0f\x7f\x2c\x24" ++
        "\x66\x0f\xef\xed\xf3\x0f\x6f\x34\x24";
    // movups [rax], xmm6
    // ret
    const suffix = "\x0f\x11\x30\xc3";
    // Optionally insert pxor xmm6, xmm6 after the reload.
    inline for (.{ "", "\x66\x0f\xef\xf6" }) |overwrite| {
        const pointer: Value = .{ .kind = .global_address, .a = 0x2000, .b = 128 };
        var options: Options = .{};
        options.initial_registers[10] = pointer;
        var flow = try Self.initWithOptions(std.testing.allocator, CodeView.fromBytes(prefix ++ overwrite ++ suffix, 0), options);
        defer flow.deinit();

        const store = flow.nodes.items[flow.nodes.items.len - 2];
        const expected: Value = if (overwrite.len == 0) pointer else .{ .kind = .constant, .a = 0 };
        try std.testing.expectEqualDeep([2]Value{ expected, expected }, flow.sourceLanes(store));
    }
}

test "scalar SIMD moves cannot preserve a 64-bit pointer fact" {
    // lea rax, [rip]
    // movq xmm0, rax
    // movd ebx, xmm0
    // ret
    const bytes = "\x48\x8d\x05\x00\x00\x00\x00\x66\x48\x0f\x6e\xc0\x66\x0f\x7e\xc3\xc3";
    var flow = try Self.init(std.testing.allocator, CodeView.fromBytes(bytes, 0));
    defer flow.deinit();
    try std.testing.expectEqual(Value{}, flow.nodes.items[3].state.registers[3]);
    // movss xmm0, dword ptr [rax] (unsupported scalar floating-point load).
    try std.testing.expectError(error.UnsupportedInstruction, decode(CodeView.fromBytes("\xf3\x0f\x10\x00", 0), 0));
    // Invalid punpcklqdq encoding: 0x0f, 0x6c lacks the required 0x66 prefix.
    try std.testing.expectError(error.UnsupportedInstruction, decode(CodeView.fromBytes("\x0f\x6c\xc0", 0), 0));
    // movddup xmm0, xmm0 (unsupported lane duplication).
    try std.testing.expectError(error.UnsupportedInstruction, decode(CodeView.fromBytes("\xf2\x0f\x12\xc0", 0), 0));
}
