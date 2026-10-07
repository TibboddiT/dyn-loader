const std = @import("std");

const json = @import("json.zig");

pub const CommandResult = struct {
    exit_code: i64,
    timed_out: bool = false,
    truncated: bool = false,
    stdout_text: []const u8,
    stderr_text: []const u8,
    stdout_path: []const u8,
    stderr_path: []const u8,
};

pub const CommandOptions = struct {
    timeout_ms: u64 = 900_000,
    check_exit: bool = true,
    log_prefix: ?[]const u8 = null,
    capture: bool = true,
};

pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    project_dir: []const u8,
    cache_dir: []const u8,
    run_dir: []const u8,
    command_index: usize = 0,

    pub fn makeDir(context: *Context, path: []const u8) !void {
        try std.Io.Dir.cwd().createDirPath(context.io, path);
    }

    pub fn readFile(context: *Context, path: []const u8) ![]const u8 {
        const file = try std.Io.Dir.cwd().openFile(context.io, path, .{});
        defer file.close(context.io);

        // procfs files can contain data even when their reported size is zero.
        var buffer: [8192]u8 = undefined;
        var reader = file.readerStreaming(context.io, &buffer);

        return reader.interface.allocRemaining(context.allocator, .limited(16 * 1024 * 1024));
    }

    pub fn loadJson(context: *Context, path: []const u8) !json.Value {
        const bytes = try context.readFile(path);

        return json.parse(context.allocator, bytes);
    }

    pub fn loadOptionalJson(context: *Context, path: []const u8) !?json.Value {
        const bytes = context.readFile(path) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };

        return try json.parse(context.allocator, bytes);
    }

    pub fn writeFile(context: *Context, path: []const u8, bytes: []const u8) !void {
        if (std.fs.path.dirname(path)) |parent| {
            try context.makeDir(parent);
        }

        try std.Io.Dir.cwd().writeFile(context.io, .{
            .sub_path = path,
            .data = bytes,
        });
    }

    pub fn saveJson(context: *Context, path: []const u8, data: anytype) !void {
        const temporary_path = try std.fmt.allocPrint(context.allocator, "{s}.partial", .{path});

        const bytes = try std.json.Stringify.valueAlloc(context.allocator, data, .{ .whitespace = .indent_2 });
        defer context.allocator.free(bytes);

        try context.writeFile(temporary_path, bytes);
        try std.Io.Dir.renameAbsolute(temporary_path, path, context.io);
    }

    pub fn removeFile(context: *Context, path: []const u8) void {
        std.Io.Dir.cwd().deleteFile(context.io, path) catch {};
    }

    pub fn copyFile(context: *Context, source_path: []const u8, destination_path: []const u8) !void {
        try std.Io.Dir.copyFileAbsolute(source_path, destination_path, context.io, .{ .make_path = true });
    }

    pub fn hashFile(context: *Context, path: []const u8) ![]const u8 {
        const file = try std.Io.Dir.cwd().openFile(context.io, path, .{});
        defer file.close(context.io);

        var buffer: [65536]u8 = undefined;
        var reader = file.reader(context.io, &.{});
        var hash = std.crypto.hash.sha2.Sha256.init(.{});

        while (true) {
            const bytes_read = try reader.interface.readSliceShort(&buffer);
            if (bytes_read == 0) break;

            hash.update(buffer[0..bytes_read]);
        }

        const hex_digest = std.fmt.bytesToHex(hash.finalResult(), .lower);

        return context.allocator.dupe(u8, &hex_digest);
    }

    pub fn hashOptionalFile(context: *Context, path: []const u8) !?[]const u8 {
        return context.hashFile(path) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
    }

    pub fn randomSuffix(context: *Context) ![]const u8 {
        var bytes: [12]u8 = undefined;
        context.io.random(&bytes);

        const hex = std.fmt.bytesToHex(bytes, .lower);

        return context.allocator.dupe(u8, &hex);
    }

    pub fn formatCommand(context: *Context, argv: []const []const u8) ![]const u8 {
        var output: std.Io.Writer.Allocating = .init(context.allocator);
        defer output.deinit();

        for (argv, 0..) |arg, index| {
            if (index != 0) {
                try output.writer.writeByte(' ');
            }

            try output.writer.writeByte('\'');
            for (arg) |byte| {
                if (byte == '\'') {
                    try output.writer.writeAll("'\\''");
                } else {
                    try output.writer.writeByte(byte);
                }
            }
            try output.writer.writeByte('\'');
        }

        return output.toOwnedSlice();
    }

    fn readLogPrefix(context: *Context, path: []const u8, truncated: *bool) ![]const u8 {
        const file = try std.Io.Dir.cwd().openFile(context.io, path, .{});
        defer file.close(context.io);

        const file_size_bytes = (try file.stat(context.io)).size;
        const capture_limit_bytes = 2 * 1024 * 1024;

        if (file_size_bytes > capture_limit_bytes) {
            truncated.* = true;
        }

        const capture_size: usize = @intCast(@min(file_size_bytes, capture_limit_bytes));
        const buffer = try context.allocator.alloc(u8, capture_size);

        var reader = file.reader(context.io, &.{});
        const bytes_read = try reader.interface.readSliceShort(buffer);

        return buffer[0..bytes_read];
    }

    pub fn runCommand(context: *Context, argv: []const []const u8, options: CommandOptions) !CommandResult {
        context.command_index += 1;

        const log_prefix = options.log_prefix orelse try std.fmt.allocPrint(context.allocator, "{s}/commands/{d:0>6}", .{
            context.run_dir,
            context.command_index,
        });

        if (std.fs.path.dirname(log_prefix)) |parent| {
            try context.makeDir(parent);
        }

        const stdout_path = try std.fmt.allocPrint(context.allocator, "{s}.stdout", .{log_prefix});
        const stderr_path = try std.fmt.allocPrint(context.allocator, "{s}.stderr", .{log_prefix});

        const stdout_file = try std.Io.Dir.cwd().createFile(context.io, stdout_path, .{});
        defer stdout_file.close(context.io);

        const stderr_file = try std.Io.Dir.cwd().createFile(context.io, stderr_path, .{});
        defer stderr_file.close(context.io);

        const command_path = try std.fmt.allocPrint(context.allocator, "{s}.command.json", .{log_prefix});
        try context.saveJson(command_path, argv);

        var child = std.process.spawn(context.io, .{
            .argv = argv,
            .cwd = .{ .path = context.project_dir },
            .stdin = .ignore,
            .stdout = .{ .file = stdout_file },
            .stderr = .{ .file = stderr_file },
        }) catch |err| {
            try stderr_file.writeStreamingAll(context.io, @errorName(err));
            std.debug.print("Unable to execute {s}: {s}\n", .{ argv[0], @errorName(err) });

            if (options.check_exit) return error.CommandFailed;

            return .{
                .exit_code = 125,
                .stdout_text = "",
                .stderr_text = @errorName(err),
                .stdout_path = stdout_path,
                .stderr_path = stderr_path,
            };
        };
        defer child.kill(context.io);

        const WaitEvent = union(enum) {
            process: std.process.Child.WaitError!std.process.Child.Term,
            timer: std.Io.Cancelable!void,
        };

        var events: [2]WaitEvent = undefined;
        var wait = std.Io.Select(WaitEvent).init(context.io, &events);
        defer wait.cancelDiscard();

        try wait.concurrent(.process, std.process.Child.wait, .{ &child, context.io });

        const timeout = std.Io.Duration.fromMilliseconds(@intCast(options.timeout_ms));
        try wait.concurrent(.timer, std.Io.sleep, .{ context.io, timeout, .awake });

        var result: CommandResult = .{
            .exit_code = -9,
            .stdout_text = "",
            .stderr_text = "",
            .stdout_path = stdout_path,
            .stderr_path = stderr_path,
        };

        switch (try wait.await()) {
            .process => |termination| result.exit_code = terminationCode(try termination),
            .timer => |slept| {
                try slept;

                result.timed_out = true;
            },
        }

        wait.cancelDiscard();
        if (result.timed_out) {
            child.kill(context.io);
        }

        if (options.capture or result.exit_code != 0) {
            result.stdout_text = try context.readLogPrefix(stdout_path, &result.truncated);
            result.stderr_text = try context.readLogPrefix(stderr_path, &result.truncated);
        }

        const exit_path = try std.fmt.allocPrint(context.allocator, "{s}.exit.json", .{log_prefix});
        try context.saveJson(exit_path, .{
            .exit_code = result.exit_code,
            .timed_out = result.timed_out,
        });

        if (options.check_exit and (result.exit_code != 0 or result.timed_out)) {
            const command_text = try context.formatCommand(argv);
            std.debug.print("Command failed: {s}\nLogs: {s}.stdout / .stderr\n{s}\n", .{
                command_text,
                log_prefix,
                result.stderr_text,
            });

            return error.CommandFailed;
        }

        return result;
    }

    /// Saves the docker image to disk and compresses it in chunks.
    pub fn exportImage(context: *Context, image: []const u8, destination_path: []const u8) !void {
        const tar_path = try std.fmt.allocPrint(context.allocator, "{s}.tar.partial", .{destination_path});
        const compressed_path = try std.fmt.allocPrint(context.allocator, "{s}.partial", .{destination_path});
        defer context.removeFile(tar_path);
        errdefer context.removeFile(compressed_path);

        _ = try context.runCommand(&.{ "docker", "image", "save", "--output", tar_path, image }, .{
            .timeout_ms = 1200_000,
            .capture = false,
        });

        try context.compressGzip(tar_path, compressed_path);
        try std.Io.Dir.renameAbsolute(compressed_path, destination_path, context.io);
    }

    pub fn compressGzip(context: *Context, source_path: []const u8, destination_path: []const u8) !void {
        const input_file = try std.Io.Dir.cwd().openFile(context.io, source_path, .{});
        defer input_file.close(context.io);

        const output_file = try std.Io.Dir.cwd().createFile(context.io, destination_path, .{});
        defer output_file.close(context.io);

        var read_buffer: [65536]u8 = undefined;
        var write_buffer: [65536]u8 = undefined;
        var window: [std.compress.flate.max_window_len]u8 = undefined;

        var reader = input_file.reader(context.io, &read_buffer);
        var writer = output_file.writer(context.io, &write_buffer);

        const compressor = try context.allocator.create(std.compress.flate.Compress);
        defer context.allocator.destroy(compressor);

        compressor.* = try .init(&writer.interface, &window, .gzip, .fastest);

        _ = try reader.interface.streamRemaining(&compressor.writer);
        try compressor.finish();
        try writer.interface.flush();
    }
};

pub fn terminationCode(termination: std.process.Child.Term) i64 {
    return switch (termination) {
        .exited => |code| code,
        .signal, .stopped => |signal| 128 + @as(i64, @intCast(@backingInt(signal))),
        .unknown => 125,
    };
}

test "procfs metadata is read despite zero stat size" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var context: Context = .{
        .allocator = arena.allocator(),
        .io = std.testing.io,
        .project_dir = ".",
        .cache_dir = ".",
        .run_dir = ".",
    };

    const kernel_release = try context.readFile("/proc/sys/kernel/osrelease");
    try std.testing.expect(kernel_release.len != 0);
}

test "optional file hashing distinguishes missing files from allocation failure" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();

    const directory = try temporary.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(directory);

    const path = try std.fs.path.join(std.testing.allocator, &.{ directory, "artifact" });
    defer std.testing.allocator.free(path);

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var context: Context = .{
        .allocator = failing.allocator(),
        .io = std.testing.io,
        .project_dir = directory,
        .cache_dir = directory,
        .run_dir = directory,
    };

    try std.testing.expectEqual(@as(?[]const u8, null), try context.hashOptionalFile(path));

    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "artifact", .data = "data" });
    try std.testing.expectError(error.OutOfMemory, context.hashOptionalFile(path));
}
