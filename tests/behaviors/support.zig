const std = @import("std");

const dll = @import("dll");

pub const BridgeSymbols = struct {
    open: []const u8,
    symbol: []const u8,
    close: []const u8,
    start_thread: []const u8,
    join_thread: []const u8,
};

pub const SpecificContext = struct {
    bridge_path: []const u8,
    target_path: [:0]const u8,
    bridge_symbols: BridgeSymbols,
};

const ThreadRoutine = *const fn (argument: ?*anyopaque) callconv(.c) *anyopaque;

pub const Bridge = struct {
    openLibrary: *const fn (path: [*:0]const u8) callconv(.c) ?*anyopaque,
    resolveSymbol: *const fn (handle: *anyopaque, name: [*:0]const u8) callconv(.c) ?*anyopaque,
    closeLibrary: *const fn (handle: *anyopaque) callconv(.c) c_int,
    startThread: *const fn (thread: *usize, routine: ThreadRoutine, argument: ?*anyopaque) callconv(.c) c_int,
    joinThread: *const fn (thread: usize) callconv(.c) c_int,

    pub fn init(path: []const u8, symbols: BridgeSymbols) !Bridge {
        const library = try dll.load(path);
        return .{
            .openLibrary = @ptrFromInt(try symbolAddress(library, symbols.open)),
            .resolveSymbol = @ptrFromInt(try symbolAddress(library, symbols.symbol)),
            .closeLibrary = @ptrFromInt(try symbolAddress(library, symbols.close)),
            .startThread = @ptrFromInt(try symbolAddress(library, symbols.start_thread)),
            .joinThread = @ptrFromInt(try symbolAddress(library, symbols.join_thread)),
        };
    }

    pub fn open(bridge: Bridge, path: [:0]const u8) !*anyopaque {
        return bridge.openLibrary(path) orelse error.OpenFailed;
    }

    pub fn symbol(bridge: Bridge, comptime T: type, handle: *anyopaque, name: [:0]const u8) !T {
        const address = bridge.resolveSymbol(handle, name) orelse {
            std.debug.print("unable to resolve symbol '{s}'\n", .{name});
            return error.SymbolMissing;
        };
        return @ptrCast(address);
    }

    pub fn close(bridge: Bridge, handle: *anyopaque) !void {
        try std.testing.expectEqual(@as(c_int, 0), bridge.closeLibrary(handle));
    }

    fn symbolAddress(library: dll.DynamicLibrary, name: []const u8) !usize {
        const resolved = library.getSymbol(name) catch |err| {
            std.debug.print("unable to resolve bridge symbol '{s}': {s}\n", .{ name, @errorName(err) });
            return err;
        };
        return resolved.addr;
    }
};
