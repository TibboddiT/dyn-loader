const std = @import("std");
const builtin = @import("builtin");

const json = @import("json.zig");
const support = @import("support.zig");
const protocol = @import("protocol.zig");
const layout = @import("fixture_layout.zig");
const reporting = @import("report.zig");
const cache = @import("cache.zig");

const Context = support.Context;

const libc_sources = [_][]const u8{
    "tests/main.zig",
    "tests/resources/libc/probe.c",
    "tests/resources/libc/probe_api.h",
    "tests/resources/libc/reference.c",
    "tests/resources/libc/tls_object.cpp",
    "tests/resources/libc/tls_object.h",
    "tests/resources/libc/dependencies/provider.c",
    "tests/resources/libc/dependencies/consumer.c",
    "tests/resources/libc/runpath/build.sh",
    "tests/resources/libc/runpath/leaf.c",
    "tests/resources/libc/runpath/middle.c",
    "tests/resources/libc/runpath/top.c",
};

const libc_filenames = [_][]const u8{
    "libprobe.so",
    "libprobe_provider.so",
    "libprobe_consumer.so",
    "reference",
    "libtls_object.so",
    "runpath/chain/top.so",
    "runpath/chain/middle/libmatrix_middle.so",
    "runpath/chain/leaf/libmatrix_leaf.so",
    "runpath/scope/top.so",
    "runpath/scope/middle/libmatrix_middle.so",
    "runpath/scope/leaf/libmatrix_leaf.so",
};

const regression_filenames = [_][]const u8{
    "target.so",
    "target_optimized.so",
    "target_large_tls.so",
    "target_excess_tls.so",
    "bridge.so",
    "dependency.so",
    "plt_only.so",
    "relr.so",
    "relative_addends.so",
    "layout.so",
    "capabilities.json",
};

const Options = struct {
    project_dir: []const u8 = "",
    libc_worker_path: []const u8 = "",
    assertion_worker_path: []const u8 = "",
    zig_exe_path: []const u8 = "",
    suites: std.ArrayList([]const u8) = .empty,
    cache_dir: ?[]const u8 = null,
    runtimes: std.ArrayList([]const u8) = .empty,
    case_name: ?[]const u8 = null,
    case_prefix: ?[]const u8 = null,
    timeout_ms: u64 = 30_000,
    prepare_only: bool = false,
    report_only: bool = false,
    self_test: bool = false,
    results_path: ?[]const u8 = null,
    help: bool = false,

    fn selectsSuite(options: Options, suite: []const u8) bool {
        if (options.suites.items.len == 0) return true;

        for (options.suites.items) |selected| {
            if (std.mem.eql(u8, selected, suite)) return true;
        }

        return false;
    }

    fn selectsCase(options: Options, suite: []const u8, name: []const u8) bool {
        if (!options.selectsSuite(suite)) return false;
        if (options.case_name) |selected| return std.mem.eql(u8, name, selected);
        if (options.case_prefix) |prefix| return std.mem.startsWith(u8, name, prefix);

        return true;
    }
};

fn printUsage(allocator: std.mem.Allocator) !void {
    std.debug.print(
        \\Usage: zig build run-tests_matrix -- [options]
        \\  --runtime ID          Select a runtime (default: all)
        \\  --suite NAME          Select elf, lifecycle, or libc (default: all)
        \\  --case NAME           Select one exact case name
        \\  --case-prefix PREFIX  Select cases by prefix
        \\  --timeout SECONDS     Per-case deadline (default: 30)
        \\  --cache PATH          Artifact cache (default: PROJECT/.tests-matrix)
        \\  --prepare-only        Validate/prepare artifacts without running cases
        \\  --report              Print the latest report
        \\  --results PATH        Select results.json with --report
        \\  --self-test           Check runner handling of success, crashes, timeouts, and cleanup
        \\                        Requires exactly one --runtime
        \\  --help                Show this help
        \\
        \\Available runtime IDs:
        \\
    , .{});

    const manifest = try json.parse(allocator, @embedFile("environments/runtimes.json"));
    const runtimes = json.field(manifest, "runtimes");
    if (runtimes != .array) return error.InvalidManifest;

    for (runtimes.array.items) |runtime| {
        const id = try json.requireString(runtime, "id");
        std.debug.print("  {s}\n", .{id});
    }
}

fn parseOptions(allocator: std.mem.Allocator, argv: []const []const u8) !Options {
    var options: Options = .{};
    var arg_index: usize = 1;

    while (arg_index < argv.len) : (arg_index += 1) {
        const arg = argv[arg_index];

        if (std.mem.eql(u8, arg, "--help")) {
            options.help = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--prepare-only")) {
            options.prepare_only = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--report")) {
            options.report_only = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--self-test")) {
            options.self_test = true;
            continue;
        }

        if (arg_index + 1 == argv.len) return error.MissingArgument;

        arg_index += 1;
        const argument_value = argv[arg_index];

        if (std.mem.eql(u8, arg, "--cases-worker")) {
            options.assertion_worker_path = argument_value;
        } else if (std.mem.eql(u8, arg, "--zig-exe")) {
            options.zig_exe_path = argument_value;
        } else if (std.mem.eql(u8, arg, "--suite")) {
            const valid_suite = std.mem.eql(u8, argument_value, "elf") or
                std.mem.eql(u8, argument_value, "lifecycle") or
                std.mem.eql(u8, argument_value, "libc");

            if (!valid_suite) return error.UnknownSuite;

            try options.suites.append(allocator, argument_value);
        } else if (std.mem.eql(u8, arg, "--project")) {
            options.project_dir = argument_value;
        } else if (std.mem.eql(u8, arg, "--worker")) {
            options.libc_worker_path = argument_value;
        } else if (std.mem.eql(u8, arg, "--cache")) {
            options.cache_dir = argument_value;
        } else if (std.mem.eql(u8, arg, "--runtime")) {
            try options.runtimes.append(allocator, argument_value);
        } else if (std.mem.eql(u8, arg, "--case")) {
            options.case_name = argument_value;
        } else if (std.mem.eql(u8, arg, "--case-prefix")) {
            options.case_prefix = argument_value;
        } else if (std.mem.eql(u8, arg, "--results")) {
            options.results_path = argument_value;
        } else if (std.mem.eql(u8, arg, "--timeout")) {
            const timeout_seconds = try std.fmt.parseFloat(f64, argument_value);

            if (!std.math.isFinite(timeout_seconds) or timeout_seconds < 0.001 or timeout_seconds > 86400) {
                return error.InvalidTimeout;
            }

            options.timeout_ms = @intFromFloat(timeout_seconds * 1000);
        } else {
            std.debug.print("Unknown option: {s}\n", .{arg});
            return error.InvalidArguments;
        }
    }

    if (!options.help and (options.project_dir.len == 0 or options.libc_worker_path.len == 0)) {
        return error.MissingBuildArguments;
    }

    const exclusive_modes: u8 = @as(u8, @intFromBool(options.prepare_only)) +
        @intFromBool(options.report_only) +
        @intFromBool(options.self_test);

    if (exclusive_modes > 1) return error.ConflictingModes;
    if (options.case_name != null and options.case_prefix != null) return error.ConflictingFilters;

    return options;
}

fn trimOutput(text: []const u8) []const u8 {
    return std.mem.trim(u8, text, " \r\n\t");
}

const WorkerKind = enum { assertion, reference, dynloader };

const Runtime = struct {
    const SdkRecipe = enum { debian, arch, alpine, chimera, nixos };
    const LibcFamily = enum { glibc, musl };

    id: []const u8,
    image: []const u8,
    libc_path: []const u8,
    loader_path: []const u8,
    package_version: []const u8,
    sdk_recipe: SdkRecipe,
    libc_family: LibcFamily,
    sdk_args: json.Value,
    metadata: json.Value,
    cpp_libraries: []const []const u8,

    fn buildsRuntime(runtime: Runtime) bool {
        return runtime.sdk_recipe == .chimera or runtime.sdk_recipe == .nixos;
    }

    fn initFromJson(value: json.Value) !Runtime {
        const sdk_args = json.field(value, "sdk_args");
        if (sdk_args != .object) return error.InvalidManifest;

        var arguments = sdk_args.object.iterator();
        while (arguments.next()) |argument| {
            if (json.asString(argument.value_ptr.*) == null) return error.InvalidManifest;
        }

        const id = try json.requireString(value, "id");
        const image = try json.requireString(value, "image");
        const libc_path = try json.requireString(value, "libc_path");
        const loader_path = try json.requireString(value, "loader_path");
        const package_version = try json.requireString(value, "package_version");

        const recipe_name = try json.requireString(value, "sdk_recipe");
        const sdk_recipe = std.meta.stringToEnum(SdkRecipe, recipe_name) orelse return error.UnknownSdkRecipe;

        const family_name = try json.requireString(value, "libc_family");
        const libc_family = std.meta.stringToEnum(LibcFamily, family_name) orelse return error.UnknownLibcFamily;

        return .{
            .id = id,
            .image = image,
            .libc_path = libc_path,
            .loader_path = loader_path,
            .package_version = package_version,
            .sdk_recipe = sdk_recipe,
            .libc_family = libc_family,
            .sdk_args = sdk_args,
            .metadata = value,
            .cpp_libraries = switch (sdk_recipe) {
                .chimera => &.{ "libc++.so.1", "libc++abi.so.1", "libunwind.so.1" },
                .nixos => &.{},
                else => &.{ "libstdc++.so.6", "libgcc_s.so.1" },
            },
        };
    }
};

const Matrix = struct {
    const ExecuteOptions = struct {
        fixtures_dir: []const u8,
        worker: WorkerKind,
        case_id: ?u32 = null,
        timeout_ms: u64 = 30_000,
        log_prefix: []const u8,
    };

    context: *Context,
    manifest: json.Value,
    libc_worker_path: []const u8,
    assertion_worker_path: []const u8 = "",
    compiler_sha256: []const u8 = "",
    platform: []const u8,

    fn ensureImage(matrix: *Matrix, image: []const u8) !void {
        const inspected = try matrix.context.runCommand(&.{ "docker", "image", "inspect", image }, .{ .check_exit = false });

        if (inspected.exit_code != 0) {
            _ = try matrix.context.runCommand(&.{ "docker", "pull", "--platform", matrix.platform, image }, .{ .capture = false });
        }
    }

    fn queryImage(matrix: *Matrix, image: []const u8, args: []const []const u8) ![]const u8 {
        const context = matrix.context;

        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(context.allocator, &.{ "docker", "run", "--rm", "--pull=never" });
        try argv.appendSlice(context.allocator, &.{ "--network", "none" });
        try argv.appendSlice(context.allocator, &.{ "--platform", matrix.platform });
        try argv.append(context.allocator, image);
        try argv.appendSlice(context.allocator, args);

        const result = try context.runCommand(argv.items, .{});
        if (result.truncated) return error.QueryTooLarge;

        return result.stdout_text;
    }

    fn imageId(matrix: *Matrix, image: []const u8) ![]const u8 {
        const result = try matrix.context.runCommand(&.{ "docker", "image", "inspect", image, "--format", "{{.Id}}" }, .{});

        return trimOutput(result.stdout_text);
    }

    fn restoreImage(matrix: *Matrix, image: []const u8, archive_path: []const u8) !void {
        const context = matrix.context;
        const inspected = try context.runCommand(&.{ "docker", "image", "inspect", image }, .{ .check_exit = false });
        if (inspected.exit_code != 0) {
            _ = try context.runCommand(&.{ "docker", "image", "load", "--input", archive_path }, .{ .capture = false });
        }
    }

    fn inspectRuntime(matrix: *Matrix, runtime: Runtime, image: []const u8) !json.Value {
        const context = matrix.context;
        const allocator = context.allocator;

        const libc_path = runtime.libc_path;
        const loader_path = runtime.loader_path;
        const digest_output = try matrix.queryImage(image, &.{ "sha256sum", libc_path, loader_path });

        var digests = json.object();
        var lines = std.mem.splitScalar(u8, digest_output, '\n');
        while (lines.next()) |line| {
            var fields = std.mem.tokenizeAny(u8, line, " \t\r");
            const digest = fields.next() orelse continue;
            const path = fields.next() orelse return error.InvalidDigestOutput;

            if (digest.len != 64) return error.InvalidDigestOutput;

            try json.putField(allocator, &digests, path, json.string(digest));
        }

        if (json.field(digests, libc_path) == .null or json.field(digests, loader_path) == .null) {
            return error.MissingRuntimeDigest;
        }

        const packages = switch (runtime.sdk_recipe) {
            .debian => try matrix.queryImage(image, &.{ "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n" }),
            .arch => try matrix.queryImage(image, &.{ "pacman", "-Q" }),
            .alpine, .chimera => try matrix.queryImage(image, &.{ "apk", "list", "--installed" }),
            .nixos => try matrix.queryImage(image, &.{ "sh", "-ec", "getconf GNU_LIBC_VERSION; nix-store -qR /opt/runtime" }),
        };

        var package_lines = std.mem.splitScalar(u8, packages, '\n');
        var actual_version: ?[]const u8 = null;
        while (package_lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "libc6:amd64\t")) {
                actual_version = trimOutput(line[12..]);
            } else if (std.mem.startsWith(u8, line, "glibc ")) {
                actual_version = trimOutput(line[6..]);
            } else if (std.mem.startsWith(u8, line, "musl-") and line.len > 5 and std.ascii.isDigit(line[5])) {
                const version_end = std.mem.indexOfScalar(u8, line, ' ') orelse line.len;
                actual_version = line[5..version_end];
            }
        }

        const expected_version = runtime.package_version;
        if (!std.mem.eql(u8, actual_version orelse "", expected_version)) {
            std.debug.print("[{s}] expected libc {s}, got {s}\n", .{
                runtime.id, expected_version, actual_version orelse "unknown",
            });
            return error.LibcVersionMismatch;
        }

        const image_id = try matrix.imageId(image);

        return json.cloneViaSerialization(allocator, .{
            .image_id = image_id,
            .libc_package_version = actual_version.?,
            .runtime_sha256 = digests,
            .packages = packages,
        });
    }

    fn hashFiles(matrix: *Matrix, directory: []const u8, paths: []const []const u8) !json.Value {
        const context = matrix.context;

        var hashes = json.object();
        for (paths) |path| {
            const absolute_path = try std.fs.path.join(context.allocator, &.{ directory, path });
            const digest = try context.hashFile(absolute_path);

            try json.putField(context.allocator, &hashes, path, json.string(digest));
        }

        return hashes;
    }

    fn libcFixturesValid(matrix: *Matrix, fixtures_dir: []const u8, filenames: []const []const u8, recorded_hashes: json.Value) !bool {
        const context = matrix.context;

        for (filenames) |name| {
            const path = try std.fs.path.join(context.allocator, &.{ fixtures_dir, name });
            const actual_hash = context.hashFile(path) catch |err| switch (err) {
                error.FileNotFound => return false,
                else => return err,
            };

            if (!json.isString(json.field(recorded_hashes, name), actual_hash)) return false;
        }

        return true;
    }

    fn runSdkCommand(
        matrix: *Matrix,
        sdk_image: []const u8,
        fixtures_dir: []const u8,
        args: []const []const u8,
        log_prefix: []const u8,
    ) !void {
        const context = matrix.context;
        const allocator = context.allocator;

        const user = try std.fmt.allocPrint(allocator, "{d}:{d}", .{ std.os.linux.getuid(), std.os.linux.getgid() });
        const source_mount = try std.fmt.allocPrint(allocator, "type=bind,src={s}/tests/resources,dst=/src,readonly", .{context.project_dir});
        const fixtures_mount = try std.fmt.allocPrint(allocator, "type=bind,src={s},dst=/fixtures", .{fixtures_dir});

        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(allocator, &.{ "docker", "run", "--rm", "--pull=never" });
        try argv.appendSlice(allocator, &.{ "--network", "none" });
        try argv.appendSlice(allocator, &.{ "--user", user });
        try argv.appendSlice(allocator, &.{ "--mount", source_mount });
        try argv.appendSlice(allocator, &.{ "--mount", fixtures_mount });
        try argv.appendSlice(allocator, &.{ "-w", "/fixtures" });
        try argv.append(allocator, sdk_image);
        try argv.appendSlice(allocator, args);

        _ = try context.runCommand(argv.items, .{
            .log_prefix = log_prefix,
            .capture = false,
        });
    }

    fn compileLibcFixtures(matrix: *Matrix, runtime: Runtime, sdk_image: []const u8, fixtures_dir: []const u8, runtime_dir: []const u8) !json.Value {
        const context = matrix.context;

        const flags = json.field(matrix.manifest, "fixture_cflags");

        if (flags != .array) return error.InvalidManifest;

        const recipes = [_][]const []const u8{
            &.{
                "-shared",
                "/src/libc/dependencies/provider.c",
                "-Wl,-soname,libprobe_provider.so",
                "-o",
                "libprobe_provider.so",
            },
            &.{
                "-shared",
                "/src/libc/dependencies/consumer.c",
                "-L.",
                "-Wl,--no-as-needed",
                "-lprobe_provider",
                "-Wl,-rpath,$ORIGIN",
                "-Wl,-soname,libprobe_consumer.so",
                "-o",
                "libprobe_consumer.so",
            },
            &.{
                "-shared",
                "/src/libc/probe.c",
                "-L.",
                "-Wl,--no-as-needed",
                "-lprobe_consumer",
                "-Wl,-rpath,$ORIGIN",
                "-pthread",
                "-ldl",
                "-lm",
                "-lrt",
                "-Wl,-soname,libprobe.so",
                "-o",
                "libprobe.so",
            },
            &.{ "/src/libc/reference.c", "-ldl", "-pthread", "-o", "reference" },
        };

        var commands = json.array(context.allocator);
        for (recipes, 0..) |recipe, index| {
            var argv: std.ArrayList([]const u8) = .empty;
            try argv.append(context.allocator, "cc");

            for (flags.array.items) |flag| {
                const argument = json.asString(flag) orelse return error.InvalidManifest;
                try argv.append(context.allocator, argument);
            }

            try argv.appendSlice(context.allocator, recipe);

            const recorded_command = try json.cloneViaSerialization(context.allocator, argv.items);
            try commands.array.append(recorded_command);

            const log_prefix = try std.fmt.allocPrint(context.allocator, "{s}/build-{d}", .{ runtime_dir, index });
            try matrix.runSdkCommand(sdk_image, fixtures_dir, argv.items, log_prefix);
        }

        const additional_commands = [_][]const []const u8{
            &.{ "c++", "-std=c++11", "-O0", "-g", "-fPIC", "-shared", "-Wall", "-Wextra", "-Werror", "/src/libc/tls_object.cpp", "-pthread", "-Wl,-rpath,$ORIGIN", "-Wl,-soname,libtls_object.so", "-o", "libtls_object.so" },
            &.{ "sh", "/src/libc/runpath/build.sh" },
        };
        for (additional_commands, recipes.len..) |command, index| {
            try commands.array.append(try json.cloneViaSerialization(context.allocator, command));
            const log_prefix = try std.fmt.allocPrint(context.allocator, "{s}/build-{d}", .{ runtime_dir, index });
            try matrix.runSdkCommand(sdk_image, fixtures_dir, command, log_prefix);
        }

        for (runtime.cpp_libraries) |name| {
            const command = &[_][]const u8{ "sh", "-ec", "source=$(c++ -print-file-name=\"$1\"); test \"$source\" != \"$1\"; cp -L \"$source\" \"/fixtures/$1\"", "copy-cpp-library", name };
            try commands.array.append(try json.cloneViaSerialization(context.allocator, command));
            const log_prefix = try std.fmt.allocPrint(context.allocator, "{s}/build-{s}", .{ runtime_dir, name });
            try matrix.runSdkCommand(sdk_image, fixtures_dir, command, log_prefix);
        }

        return commands;
    }

    fn buildEnvironment(matrix: *Matrix, runtime: Runtime, recipe_path: []const u8, runtime_dir: []const u8, target: []const u8) ![]const u8 {
        const context = matrix.context;
        const allocator = context.allocator;

        const image_tag = try std.fmt.allocPrint(allocator, "dynloader-libc-{s}:{s}", .{ target, runtime.id });
        const base_argument = try std.fmt.allocPrint(allocator, "BASE={s}", .{try json.requireString(runtime.metadata, "image")});
        const version_argument = try std.fmt.allocPrint(allocator, "LIBC_PACKAGE_VERSION={s}", .{runtime.package_version});

        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(allocator, &.{ "docker", "build" });
        try argv.appendSlice(allocator, &.{ "--platform", matrix.platform });
        try argv.appendSlice(allocator, &.{ "-f", recipe_path });
        try argv.appendSlice(allocator, &.{ "-t", image_tag });
        try argv.appendSlice(allocator, &.{ "--build-arg", base_argument });
        try argv.appendSlice(allocator, &.{ "--build-arg", version_argument });
        if (runtime.buildsRuntime()) try argv.appendSlice(allocator, &.{ "--target", target });

        var entries = runtime.sdk_args.object.iterator();
        while (entries.next()) |entry| {
            const argument_value = entry.value_ptr.string;
            const argument = try std.fmt.allocPrint(allocator, "{s}={s}", .{ entry.key_ptr.*, argument_value });

            try argv.appendSlice(allocator, &.{ "--build-arg", argument });
        }

        const sdk_dir = try std.fs.path.join(allocator, &.{ context.project_dir, "tests/environments/sdk" });
        try argv.append(allocator, sdk_dir);

        std.debug.print("[{s}] building {s} environment\n", .{ runtime.id, target });

        const log_prefix = try std.fmt.allocPrint(allocator, "{s}/{s}-build", .{ runtime_dir, target });
        _ = try context.runCommand(argv.items, .{
            .capture = false,
            .timeout_ms = 1200_000,
            .log_prefix = log_prefix,
        });

        return matrix.imageId(image_tag);
    }

    fn prepareRuntime(matrix: *Matrix, runtime: *Runtime) !json.Value {
        const context = matrix.context;
        const allocator = context.allocator;
        const runtime_id = runtime.id;

        const runtime_dir = try std.fs.path.join(allocator, &.{ context.cache_dir, runtime_id });
        try context.makeDir(runtime_dir);

        const state_path = try std.fs.path.join(allocator, &.{ runtime_dir, "prepared.json" });
        const previous: json.Value = if (try context.loadOptionalJson(state_path)) |record| validated: {
            const reusable = try cache.preparedForReuse(allocator, record);
            if (reusable == .null) {
                std.debug.print("[{s}] obsolete preparation cache; regenerating metadata and artifacts\n", .{runtime_id});
                break :validated .null;
            }
            _ = Runtime.initFromJson(json.field(record, "runtime")) catch return error.InvalidCacheMetadata;

            const recorded_sdk_key = json.field(record, "sdk_key");
            _ = Runtime.initFromJson(json.field(recorded_sdk_key, "runtime")) catch return error.InvalidCacheMetadata;

            break :validated record;
        } else .null;

        const recipe_name = @tagName(runtime.sdk_recipe);
        const recipe_relative_path = try std.fmt.allocPrint(allocator, "tests/environments/sdk/{s}.Dockerfile", .{recipe_name});
        const recipe_path = try std.fs.path.join(allocator, &.{ context.project_dir, recipe_relative_path });
        const recipe_hash = try context.hashFile(recipe_path);

        const sdk_key = try json.cloneViaSerialization(allocator, .{
            .runtime = runtime.metadata,
            .recipe_sha256 = recipe_hash,
        });

        const sdk_archive_path = try std.fs.path.join(allocator, &.{ runtime_dir, "sdk.tar.gz" });
        const reuse_sdk = json.eql(json.field(previous, "sdk_key"), sdk_key);

        var runtime_archive_hash: ?[]const u8 = null;
        if (runtime.buildsRuntime()) {
            const runtime_archive_path = try std.fs.path.join(allocator, &.{ runtime_dir, "runtime.tar.gz" });
            if (reuse_sdk) {
                runtime.image = try json.requireString(json.field(previous, "base"), "image_id");
                runtime_archive_hash = try context.hashFile(runtime_archive_path);
                if (!json.isString(json.field(previous, "runtime_archive_sha256"), runtime_archive_hash.?)) return error.RuntimeArchiveCorrupt;
                try matrix.restoreImage(runtime.image, runtime_archive_path);
            } else {
                try matrix.ensureImage(runtime.image);
                runtime.image = try matrix.buildEnvironment(runtime.*, recipe_path, runtime_dir, "runtime");
                try context.exportImage(runtime.image, runtime_archive_path);
                runtime_archive_hash = try context.hashFile(runtime_archive_path);
            }
        } else {
            try matrix.ensureImage(runtime.image);
        }
        const image = runtime.image;
        const runtime_identity = try matrix.inspectRuntime(runtime.*, image);

        var sdk_image: []const u8 = undefined;
        var archive_hash: []const u8 = undefined;
        if (reuse_sdk) {
            const previous_sdk = json.field(previous, "sdk");
            sdk_image = try json.requireString(previous_sdk, "image_id");

            archive_hash = try context.hashFile(sdk_archive_path);
            if (!json.isString(json.field(previous, "sdk_archive_sha256"), archive_hash)) return error.SdkArchiveCorrupt;

            try matrix.restoreImage(sdk_image, sdk_archive_path);

            std.debug.print("[{s}] reusing recorded SDK\n", .{runtime_id});
        } else {
            sdk_image = try matrix.buildEnvironment(runtime.*, recipe_path, runtime_dir, "sdk");
            try context.exportImage(sdk_image, sdk_archive_path);
            archive_hash = try context.hashFile(sdk_archive_path);
        }

        const sdk_identity = try matrix.inspectRuntime(runtime.*, sdk_image);
        const runtime_hashes = json.field(runtime_identity, "runtime_sha256");
        const sdk_runtime_hashes = json.field(sdk_identity, "runtime_sha256");

        if (!json.eql(runtime_hashes, sdk_runtime_hashes)) {
            return error.SdkChangedRuntime;
        }

        const source_hashes = try matrix.hashFiles(context.project_dir, &libc_sources);
        const fixture_key = try json.cloneViaSerialization(allocator, .{
            .sdk_image_id = sdk_image,
            .flags = json.field(matrix.manifest, "fixture_cflags"),
            .source_hashes = source_hashes,
        });

        const fixtures_dir = try std.fs.path.join(allocator, &.{ runtime_dir, "fixtures" });
        try context.makeDir(fixtures_dir);

        const fixture_key_matches = json.eql(json.field(previous, "fixture_key"), fixture_key);
        const filenames = try std.mem.concat(allocator, []const u8, &.{ &libc_filenames, runtime.cpp_libraries });
        const fixtures_current = fixture_key_matches and
            try matrix.libcFixturesValid(fixtures_dir, filenames, json.field(previous, "fixture_sha256"));

        var build_commands = json.field(previous, "build_commands");
        if (!fixtures_current) {
            std.debug.print("[{s}] compiling C fixtures\n", .{runtime_id});
            try std.Io.Dir.cwd().deleteTree(context.io, fixtures_dir);
            try context.makeDir(fixtures_dir);
            build_commands = try matrix.compileLibcFixtures(runtime.*, sdk_image, fixtures_dir, runtime_dir);
        } else {
            std.debug.print("[{s}] C fixtures are current\n", .{runtime_id});
        }

        const worker_destination = try std.fs.path.join(allocator, &.{ fixtures_dir, "libc-runner" });
        const worker_hash = try context.hashFile(matrix.libc_worker_path);
        const previous_worker_hash = try context.hashOptionalFile(worker_destination) orelse "";
        const worker_changed = !std.mem.eql(u8, previous_worker_hash, worker_hash);

        if (worker_changed) {
            try context.copyFile(matrix.libc_worker_path, worker_destination);
        }

        if (!fixtures_current or worker_changed) {
            for (filenames) |name| {
                const log_prefix = try std.fmt.allocPrint(allocator, "{s}/{s}.elf", .{ runtime_dir, name });
                try matrix.runSdkCommand(sdk_image, fixtures_dir, &.{ "readelf", "-aW", name }, log_prefix);
            }
        }

        const fixtures_mount = try std.fmt.allocPrint(allocator, "type=bind,src={s},dst=/fixtures,readonly", .{fixtures_dir});
        const linkage_log_prefix = try std.fs.path.join(allocator, &.{ runtime_dir, "reference-linkage" });
        const linkage = try context.runCommand(&.{
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--mount",
            fixtures_mount,
            image,
            "ldd",
            "/fixtures/libprobe.so",
        }, .{ .log_prefix = linkage_log_prefix });

        const compiler = try matrix.queryImage(sdk_image, &.{ "cc", "--version" });

        var sources = try json.cloneViaSerialization(allocator, source_hashes);
        try json.putField(allocator, &sources, recipe_relative_path, json.string(recipe_hash));

        var fixture_hashes = try matrix.hashFiles(fixtures_dir, filenames);
        try json.putField(allocator, &fixture_hashes, "libc-runner", json.string(worker_hash));
        const prepared_unix_seconds = std.Io.Clock.real.now(context.io).toSeconds();

        const prepared = try json.cloneViaSerialization(allocator, .{
            .schema_version = cache.prepared_version,
            .runtime = runtime.metadata,
            .base = runtime_identity,
            .sdk = sdk_identity,
            .sdk_key = sdk_key,
            .fixture_key = fixture_key,
            .worker_sha256 = worker_hash,
            .zig_version = builtin.zig_version_string,
            .compiler = compiler,
            .build_commands = build_commands,
            .source_hashes = sources,
            .fixture_sha256 = fixture_hashes,
            .sdk_archive_sha256 = archive_hash,
            .runtime_archive_sha256 = runtime_archive_hash,
            .reference_linkage = linkage.stdout_text,
            .prepared_unix_seconds = prepared_unix_seconds,
        });

        try context.saveJson(state_path, prepared);

        return prepared;
    }

    fn compileRegressionFixtures(matrix: *Matrix, sdk_image: []const u8, fixtures_dir: []const u8, runtime_dir: []const u8, relr_supported: bool) !json.Value {
        const context = matrix.context;

        const recipes = [_][]const []const u8{
            &.{ "/src/regression/target.c", "-Wl,-soname,target.so", "-o", "target.so" },
            &.{ "/src/regression/target.c", "-O2", "-Wl,-soname,target_optimized.so", "-o", "target_optimized.so" },
            &.{ "/src/regression/target.c", "-DTLS_BYTES=65536", "-Wl,-soname,target_large_tls.so", "-o", "target_large_tls.so" },
            &.{ "/src/regression/target.c", "-DTLS_BYTES=2097152", "-Wl,-soname,target_excess_tls.so", "-o", "target_excess_tls.so" },
            &.{
                "/src/regression/bridge.c",
                "-ldl",
                "-pthread",
                "-Wl,-soname,bridge.so",
                "-o",
                "bridge.so",
            },
            &.{
                "-nostdlib",
                "/src/regression/dependency.c",
                "target.so",
                "-Wl,-rpath,$ORIGIN",
                "-Wl,-soname,dependency.so",
                "-o",
                "dependency.so",
            },
            &.{
                "-nostdlib",
                "/src/regression/plt_only.c",
                "-lc",
                "-Wl,-soname,plt_only.so",
                "-o",
                "plt_only.so",
            },
            &.{ "-nostdlib", "/src/regression/relative_addends.c", "-Wl,-z,defs", "-Wl,-soname,relative_addends.so", "-o", "relative_addends.so" },
            &.{ "-nostdlib", "/src/regression/relr.c", "-Wl,-z,defs", "-Wl,--fatal-warnings", "-Wl,-z,pack-relative-relocs", "-Wl,-soname,relr.so", "-o", "relr.so" },
        };

        var commands = json.array(context.allocator);
        for (recipes, 0..) |recipe, index| {
            if (!relr_supported and std.mem.eql(u8, recipe[recipe.len - 1], "relr.so")) continue;

            var argv: std.ArrayList([]const u8) = .empty;
            try argv.appendSlice(context.allocator, &.{ "cc", "-std=c11", "-shared", "-fPIC", "-O0", "-g", "-Wall", "-Wextra", "-Werror", "-Wl,-z,max-page-size=4096" });
            try argv.appendSlice(context.allocator, recipe);

            const log_prefix = try std.fmt.allocPrint(context.allocator, "{s}/assertion-build-{d}", .{ runtime_dir, index });
            try matrix.runSdkCommand(sdk_image, fixtures_dir, argv.items, log_prefix);

            const recorded_command = try json.cloneViaSerialization(context.allocator, argv.items);
            try commands.array.append(recorded_command);
        }

        return commands;
    }

    fn prepareAssertions(matrix: *Matrix, runtime: Runtime, prepared: json.Value) !json.Value {
        const context = matrix.context;
        const allocator = context.allocator;
        const runtime_id = runtime.id;

        const runtime_dir = try std.fs.path.join(allocator, &.{ context.cache_dir, runtime_id });
        const fixtures_dir = try std.fs.path.join(allocator, &.{ runtime_dir, "fixtures" });
        const regression_dir = try std.fs.path.join(allocator, &.{ fixtures_dir, "regression" });
        try context.makeDir(regression_dir);

        const sdk = json.field(prepared, "sdk");
        const sdk_image = try json.requireString(sdk, "image_id");

        const input_hashes = try matrix.hashFiles(context.project_dir, &.{
            "tests/main.zig",
            "tests/fixture_layout.zig",
            "tests/resources/regression/target.c",
            "tests/resources/regression/abi.h",
            "tests/resources/regression/bridge.c",
            "tests/resources/regression/dependency.c",
            "tests/resources/regression/abi.zig",
            "tests/resources/regression/plt_only.c",
            "tests/resources/regression/relr.c",
            "tests/resources/regression/relative_addends.c",
        });

        const relr_probe = try matrix.queryImage(sdk_image, &.{
            "sh", "-ec",
            "printf '%s\\n' 'static int value; int *pointer = &value;' | " ++
                "if cc -x c -shared -fPIC -nostdlib -Wl,--fatal-warnings -Wl,-z,pack-relative-relocs -o /tmp/relr-probe.so -; then " ++
                "readelf -d /tmp/relr-probe.so; fi",
        });
        const relr_supported = std.mem.indexOf(u8, relr_probe, "(RELR)") != null;

        const toolchain = .{
            .compiler = try matrix.queryImage(sdk_image, &.{ "cc", "--version" }),
            .linker = try matrix.queryImage(sdk_image, &.{ "sh", "-ec", "\"$(cc -print-prog-name=ld)\" --version" }),
            .relr_supported = relr_supported,
        };

        const cache_key = try json.cloneViaSerialization(allocator, .{
            .inputs = input_hashes,
            .sdk_image = sdk_image,
            .layout_revision = layout.revision,
        });

        const state_path = try std.fs.path.join(allocator, &.{ runtime_dir, "assertions-prepared.json" });
        const previous: json.Value = if (try context.loadOptionalJson(state_path)) |record| validated: {
            const reusable = try cache.assertionsForReuse(allocator, record);
            if (reusable == .null) {
                std.debug.print("[{s}] obsolete assertion cache; regenerating metadata and artifacts\n", .{runtime_id});
            }
            break :validated reusable;
        } else .null;

        var fixtures_current = json.eql(json.field(previous, "key"), cache_key);
        const previous_hashes = json.field(previous, "fixture_sha256");
        for (regression_filenames) |name| {
            if (!relr_supported and std.mem.eql(u8, name, "relr.so")) continue;

            const path = try std.fs.path.join(allocator, &.{ regression_dir, name });
            const digest = try context.hashOptionalFile(path) orelse "";

            if (!json.isString(json.field(previous_hashes, name), digest)) {
                fixtures_current = false;
            }
        }

        var build_commands = json.field(previous, "build_commands");
        if (!relr_supported) {
            std.debug.print("[{s}] SDK linker cannot generate RELR fixtures\n", .{runtime_id});
        }
        if (!fixtures_current) {
            std.debug.print("[{s}] preparing ELF/lifecycle fixtures\n", .{runtime_id});

            try std.Io.Dir.cwd().deleteTree(context.io, regression_dir);
            try context.makeDir(regression_dir);

            build_commands = try matrix.compileRegressionFixtures(sdk_image, regression_dir, runtime_dir, relr_supported);
            const capabilities_path = try std.fs.path.join(allocator, &.{ regression_dir, "capabilities.json" });
            try context.saveJson(capabilities_path, try json.cloneViaSerialization(allocator, .{ .relr = relr_supported }));

            const target_path = try std.fs.path.join(allocator, &.{ regression_dir, "target.so" });
            const layout_path = try std.fs.path.join(allocator, &.{ regression_dir, "layout.so" });

            const target_bytes = try context.readFile(target_path);
            const layout_bytes = try layout.createNonIdentityLayout(allocator, target_bytes);
            try context.writeFile(layout_path, layout_bytes);

            for (regression_filenames) |name| {
                if (std.mem.eql(u8, name, "capabilities.json")) continue;
                if (!relr_supported and std.mem.eql(u8, name, "relr.so")) continue;

                const log_prefix = try std.fmt.allocPrint(allocator, "{s}/assertion-{s}.elf", .{ runtime_dir, name });
                try matrix.runSdkCommand(sdk_image, regression_dir, &.{ "readelf", "-aW", name }, log_prefix);
            }
        } else {
            std.debug.print("[{s}] ELF/lifecycle fixtures are current\n", .{runtime_id});
        }

        const worker_destination = try std.fs.path.join(allocator, &.{ fixtures_dir, "loader-cases" });
        const worker_hash = try context.hashFile(matrix.assertion_worker_path);
        const previous_worker_hash = try context.hashOptionalFile(worker_destination) orelse "";

        if (!std.mem.eql(u8, previous_worker_hash, worker_hash)) {
            try context.copyFile(matrix.assertion_worker_path, worker_destination);
        }

        var output_hashes = json.object();
        for (regression_filenames) |name| {
            if (!relr_supported and std.mem.eql(u8, name, "relr.so")) continue;

            const path = try std.fs.path.join(allocator, &.{ regression_dir, name });
            try json.putField(allocator, &output_hashes, name, json.string(try context.hashFile(path)));
        }

        const validation_log_prefix = try std.fs.path.join(allocator, &.{ context.run_dir, runtime_id, "assertion-validation" });
        const validation = try matrix.execute(runtime, .{
            .fixtures_dir = fixtures_dir,
            .worker = .assertion,
            .log_prefix = validation_log_prefix,
        });

        if (validation.status != .pass) return error.InvalidAssertionFixtures;

        const state = try json.cloneViaSerialization(allocator, .{
            .schema_version = cache.assertions_version,
            .key = cache_key,
            .worker_sha256 = worker_hash,
            .fixture_sha256 = output_hashes,
            .build_commands = build_commands,
            .validation = validation,
            .toolchain = toolchain,
            .fixture_origin = "matching SDK compiler and linker; deterministic ELF layout transform of SDK output",
        });

        try context.saveJson(state_path, state);

        return state;
    }

    fn removeContainer(matrix: *Matrix, container_name: []const u8) void {
        const result = matrix.context.runCommand(&.{ "docker", "rm", "-f", container_name }, .{
            .check_exit = false,
            .timeout_ms = 30_000,
        }) catch |err| {
            std.debug.print("Could not remove container {s}: {s}\n", .{ container_name, @errorName(err) });
            return;
        };

        if (result.timed_out) {
            std.debug.print("Container cleanup timed out: {s}\n", .{container_name});
        }
    }

    fn createContainerArgs(matrix: *Matrix, runtime: Runtime, options: ExecuteOptions, container_name: []const u8) ![]const []const u8 {
        const context = matrix.context;
        const allocator = context.allocator;

        const is_assertion = options.worker == .assertion;
        const executable = switch (options.worker) {
            .assertion => "loader-cases",
            .reference => "reference",
            .dynloader => "libc-runner",
        };

        const executable_path = try std.fmt.allocPrint(allocator, "/fixtures/{s}", .{executable});
        const input_path = if (is_assertion) "/fixtures/regression" else "/fixtures/libprobe.so";
        const case_argument = if (options.case_id) |id|
            try std.fmt.allocPrint(allocator, "{d}", .{id})
        else
            "--list";

        const temporary_mount = if (is_assertion) "/tmp:rw,exec,nosuid,size=64m" else "/tmp:rw,nosuid,size=64m";
        const fixtures_mount = try std.fmt.allocPrint(allocator, "type=bind,src={s},dst=/fixtures,readonly", .{options.fixtures_dir});

        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(allocator, &.{ "docker", "create", "--pull=never" });
        try argv.appendSlice(allocator, &.{ "--name", container_name });
        try argv.append(allocator, "--init");
        try argv.appendSlice(allocator, &.{ "--network", "none" });
        try argv.append(allocator, "--read-only");
        try argv.appendSlice(allocator, &.{ "--tmpfs", temporary_mount });
        try argv.appendSlice(allocator, &.{ "--pids-limit", "128" });
        try argv.appendSlice(allocator, &.{ "--memory", "512m" });
        try argv.appendSlice(allocator, &.{ "--ulimit", "core=0" });
        try argv.appendSlice(allocator, &.{ "--platform", matrix.platform });
        try argv.appendSlice(allocator, &.{ "--mount", fixtures_mount });
        try argv.appendSlice(allocator, &.{ "-w", "/fixtures" });

        if (is_assertion) {
            try argv.appendSlice(allocator, &.{ "--env", "LD_LIBRARY_PATH=/fixtures/regression" });
        } else {
            try argv.appendSlice(allocator, &.{ "--env", "LD_LIBRARY_PATH=/fixtures" });
        }

        try argv.appendSlice(allocator, &.{
            runtime.image, executable_path, input_path, case_argument,
        });

        if (is_assertion) {
            const abi = if (runtime.libc_family == .musl) "musl" else "gnu";
            try argv.append(allocator, abi);
        }

        return argv.toOwnedSlice(allocator);
    }

    fn execute(matrix: *Matrix, runtime: Runtime, options: ExecuteOptions) !protocol.Outcome {
        const context = matrix.context;

        const suffix = try context.randomSuffix();
        const container_name = try std.fmt.allocPrint(context.allocator, "dynloader-probe-{s}", .{suffix});
        defer matrix.removeContainer(container_name);

        const create_argv = try matrix.createContainerArgs(runtime, options, container_name);
        const started = std.Io.Clock.awake.now(context.io);
        const create_log_prefix = try std.fmt.allocPrint(context.allocator, "{s}-create", .{options.log_prefix});

        const created = try context.runCommand(create_argv, .{
            .check_exit = false,
            .timeout_ms = 60_000,
            .log_prefix = create_log_prefix,
        });

        var result = created;
        var container_state: json.Value = .null;
        if (created.exit_code == 0 and !created.timed_out) {
            result = try context.runCommand(&.{ "docker", "start", "--attach", container_name }, .{
                .check_exit = false,
                .timeout_ms = options.timeout_ms,
                .log_prefix = options.log_prefix,
            });

            if (result.timed_out) {
                _ = try context.runCommand(&.{ "docker", "kill", container_name }, .{
                    .check_exit = false,
                    .timeout_ms = 30_000,
                });
            }

            const inspected = try context.runCommand(&.{ "docker", "inspect", container_name, "--format", "{{json .State}}" }, .{
                .check_exit = false,
                .timeout_ms = 30_000,
            });

            if (inspected.exit_code == 0 and !inspected.truncated) {
                container_state = try json.parse(context.allocator, inspected.stdout_text);
                if (!result.timed_out) {
                    const exit_code = json.field(container_state, "ExitCode");
                    result.exit_code = json.asInteger(exit_code) orelse return error.InvalidContainerState;
                }
            }
        } else {
            result.exit_code = 125;
        }

        var outcome = try protocol.classify(
            context.allocator,
            result.exit_code,
            result.stdout_text,
            result.timed_out,
            options.case_id,
        );

        if (result.truncated and outcome.status == .pass) {
            outcome.status = .protocol_failure;
        }

        const oom_killed = json.field(container_state, "OOMKilled");
        if (oom_killed == .bool and oom_killed.bool) {
            outcome.status = .resource_limit;
        }

        const elapsed_ns = started.durationTo(std.Io.Clock.awake.now(context.io)).nanoseconds;

        outcome.exit_code = result.exit_code;
        outcome.seconds = @as(f64, @floatFromInt(elapsed_ns)) / 1e9;
        outcome.container_name = container_name;
        outcome.container_state = container_state;
        outcome.command = create_argv;
        outcome.stdout = result.stdout_path;
        outcome.stderr = result.stderr_path;

        const outcome_path = try std.fmt.allocPrint(context.allocator, "{s}.json", .{options.log_prefix});
        try context.saveJson(outcome_path, outcome);

        return outcome;
    }
};

fn verifyWorker(context: *Context, path: []const u8) !void {
    const file = try std.Io.Dir.cwd().openFile(context.io, path, .{});
    defer file.close(context.io);

    var header: [64]u8 = undefined;
    const header_bytes_read = try file.readPositional(context.io, &.{&header}, 0);
    if (header_bytes_read != header.len) return error.InvalidWorkerElf;

    const valid_format = std.mem.eql(u8, header[0..4], std.elf.MAGIC) and
        header[std.elf.EI_CLASS] == std.elf.ELFCLASS64 and
        header[std.elf.EI_DATA] == std.elf.ELFDATA2LSB and
        std.mem.readInt(u16, header[18..20], .little) == @backingInt(std.elf.EM.X86_64);

    if (!valid_format) return error.InvalidWorkerElf;

    const table_offset_bytes = std.mem.readInt(u64, header[32..40], .little);
    const entry_size_bytes = std.mem.readInt(u16, header[54..56], .little);
    const entry_count = std.mem.readInt(u16, header[56..58], .little);

    if (entry_size_bytes != @sizeOf(std.elf.Elf64.Phdr)) return error.InvalidWorkerElf;

    for (0..entry_count) |index| {
        var program_header: [@sizeOf(std.elf.Elf64.Phdr)]u8 = undefined;
        const entry_offset_bytes = table_offset_bytes + index * entry_size_bytes;
        const bytes_read = try file.readPositional(context.io, &.{&program_header}, entry_offset_bytes);
        if (bytes_read != program_header.len) return error.InvalidWorkerElf;

        const segment_type = std.mem.readInt(u32, program_header[0..4], .little);
        if (segment_type == @backingInt(std.elf.PT.INTERP)) return error.WorkerHasDynamicInterpreter;
    }
}

fn discoverAssertions(matrix: *Matrix) ![]const protocol.Case {
    const context = matrix.context;

    if (matrix.assertion_worker_path.len == 0 or
        matrix.compiler_sha256.len == 0)
    {
        return error.MissingBuildArguments;
    }

    try verifyWorker(context, matrix.assertion_worker_path);

    const listed = try context.runCommand(&.{ matrix.assertion_worker_path, "--list" }, .{});
    const outcome = try protocol.classify(context.allocator, listed.exit_code, listed.stdout_text, listed.timed_out, null);

    if (listed.truncated or outcome.status != .pass) return error.InvalidAssertionCatalog;

    return outcome.cases;
}

fn runRuntimeCases(
    matrix: *Matrix,
    runtime: Runtime,
    entry: *reporting.RuntimeResult,
    catalog: []const protocol.Case,
    options: Options,
) !bool {
    const context = matrix.context;
    const allocator = context.allocator;

    const fixtures_dir = try std.fs.path.join(allocator, &.{ context.cache_dir, entry.id, "fixtures" });
    const logs_dir = try std.fs.path.join(allocator, &.{ context.run_dir, entry.id });

    var rows: std.ArrayList(reporting.Row) = .empty;
    var failed = false;

    for (catalog) |case| {
        const separator = std.mem.indexOfScalar(u8, case.name, '.') orelse return error.InvalidAssertionCatalog;

        const suite = case.name[0..separator];
        if (!options.selectsCase(suite, case.name)) continue;

        const log_prefix = try std.fs.path.join(allocator, &.{ logs_dir, case.name, "dynloader" });
        const outcome: protocol.Outcome = if (entry.assertion_preparation_error) |reason|
            .{ .status = .not_run, .reason = reason }
        else
            try matrix.execute(runtime, .{
                .fixtures_dir = fixtures_dir,
                .worker = .assertion,
                .case_id = case.id,
                .timeout_ms = options.timeout_ms,
                .log_prefix = log_prefix,
            });

        const comparison = protocol.assertion(outcome.status);
        try rows.append(allocator, .{
            .id = case.id,
            .suite = suite,
            .name = case.name,
            .reference = .{ .status = .not_applicable },
            .dynloader = outcome,
            .comparison = comparison,
        });

        failed = failed or (comparison != .pass and comparison != .unavailable);

        std.debug.print("[{s}] {s}: {t}\n", .{ entry.id, case.name, outcome.status });
    }

    if (options.selectsSuite("libc")) {
        const reference_log = try std.fs.path.join(allocator, &.{ logs_dir, "reference-bootstrap" });
        const loader_log = try std.fs.path.join(allocator, &.{ logs_dir, "dynloader-bootstrap" });

        const reference = try matrix.execute(runtime, .{
            .fixtures_dir = fixtures_dir,
            .worker = .reference,
            .timeout_ms = options.timeout_ms,
            .log_prefix = reference_log,
        });

        var loader = try matrix.execute(runtime, .{
            .fixtures_dir = fixtures_dir,
            .worker = .dynloader,
            .timeout_ms = options.timeout_ms,
            .log_prefix = loader_log,
        });

        if (reference.status == .pass and loader.status == .pass) {
            const reference_catalog = try json.cloneViaSerialization(allocator, reference.cases);
            const loader_catalog = try json.cloneViaSerialization(allocator, loader.cases);

            if (!json.eql(reference_catalog, loader_catalog)) {
                loader.status = .abi_failure;
                loader.reason = "test catalogs differ";
            }
        }

        entry.bootstrap = .{ .reference = reference, .dynloader = loader };

        if (reference.status != .pass) {
            entry.preparation_error = "reference bootstrap failed; see bootstrap logs";
            failed = true;
        } else {
            for (reference.cases) |case| {
                if (!options.selectsCase("libc", case.name)) continue;

                const case_dir = try std.fs.path.join(allocator, &.{ logs_dir, case.name });
                const reference_case_log = try std.fs.path.join(allocator, &.{ case_dir, "reference" });
                const loader_case_log = try std.fs.path.join(allocator, &.{ case_dir, "dynloader" });

                const reference_result = try matrix.execute(runtime, .{
                    .fixtures_dir = fixtures_dir,
                    .worker = .reference,
                    .case_id = case.id,
                    .timeout_ms = options.timeout_ms,
                    .log_prefix = reference_case_log,
                });

                const loader_result: protocol.Outcome = if (loader.status == .pass)
                    try matrix.execute(runtime, .{
                        .fixtures_dir = fixtures_dir,
                        .worker = .dynloader,
                        .case_id = case.id,
                        .timeout_ms = options.timeout_ms,
                        .log_prefix = loader_case_log,
                    })
                else
                    .{ .status = .not_run, .reason = "dynloader bootstrap failed" };

                const comparison = protocol.compare(reference_result.status, loader_result.status);
                try rows.append(allocator, .{
                    .id = case.id,
                    .suite = "libc",
                    .name = case.name,
                    .reference = reference_result,
                    .dynloader = loader_result,
                    .comparison = comparison,
                });

                failed = failed or (comparison != .pass and comparison != .unavailable);

                std.debug.print("[{s}] {s}: reference={t} dynloader={t}\n", .{
                    entry.id,
                    case.name,
                    reference_result.status,
                    loader_result.status,
                });
            }
        }
    }

    entry.cases = try rows.toOwnedSlice(allocator);

    return failed;
}

fn runMatrix(matrix: *Matrix, selected_runtimes: []const Runtime, options: Options) !u8 {
    const context = matrix.context;

    const assertions_selected = options.selectsSuite("elf") or options.selectsSuite("lifecycle");
    const catalog = if (assertions_selected) try discoverAssertions(matrix) else &.{};

    const source_paths = libc_sources ++ .{
        "build.zig",
        "build.zig.zon",
        "src/dynamic_library_loader.zig",
        "src/CustomSelfInfo.zig",
        "tests/environments/runtimes.json",
        "tests/workers/libc.zig",
        "tests/workers/assertions.zig",
        "tests/support.zig",
        "tests/json.zig",
        "tests/cache.zig",
        "tests/protocol.zig",
        "tests/report.zig",
        "tests/environments/sdk/debian.Dockerfile",
        "tests/environments/sdk/arch.Dockerfile",
        "tests/environments/sdk/alpine.Dockerfile",
        "tests/main.zig",
        "tests/elf/cases.zig",
        "tests/elf/runner.zig",
        "tests/behaviors/cases.zig",
        "tests/behaviors/runner.zig",
        "tests/resources/regression/abi.zig",
    };

    const git_revision = try context.runCommand(&.{ "git", "rev-parse", "HEAD" }, .{});
    const git_status = try context.runCommand(&.{ "git", "status", "--short" }, .{});

    const kernel_release = try context.readFile("/proc/sys/kernel/osrelease");
    const cpu_info = try context.readFile("/proc/cpuinfo");
    const source_hashes = try matrix.hashFiles(context.project_dir, &source_paths);

    var report: reporting.Report = .{
        .compiler_sha256 = matrix.compiler_sha256,
        .run_id = std.fs.path.basename(context.run_dir),
        .git_revision = trimOutput(git_revision.stdout_text),
        .git_status = git_status.stdout_text,
        .kernel = trimOutput(kernel_release),
        .cpu = cpu_info,
        .source_hashes = source_hashes,
        .prepare_only = options.prepare_only,
        .timeout_ms = options.timeout_ms,
        .cache_dir = options.cache_dir,
    };

    const results_path = try std.fs.path.join(context.allocator, &.{ context.run_dir, "results.json" });
    var entries: std.ArrayList(reporting.RuntimeResult) = .empty;
    var failed = false;
    var case_count: usize = 0;

    for (selected_runtimes) |selected_runtime| {
        var runtime = selected_runtime;
        var entry: reporting.RuntimeResult = .{ .id = runtime.id };

        const prepared = matrix.prepareRuntime(&runtime) catch |err| {
            std.debug.print("[{s}] preparation failed: {s}\n", .{ entry.id, @errorName(err) });
            entry.preparation_error = @errorName(err);

            try entries.append(context.allocator, entry);
            report.runtimes = entries.items;
            try context.saveJson(results_path, report);

            failed = true;
            continue;
        };

        entry.prepared = prepared;

        if (assertions_selected) {
            entry.assertion_prepared = matrix.prepareAssertions(runtime, prepared) catch |err| preparation_failed: {
                entry.assertion_preparation_error = @errorName(err);
                std.debug.print("[{s}] assertion preparation failed: {s}\n", .{ entry.id, @errorName(err) });
                failed = true;
                break :preparation_failed .null;
            };
        }

        if (!options.prepare_only) {
            const runtime_failed = try runRuntimeCases(matrix, runtime, &entry, catalog, options);
            failed = failed or runtime_failed;
            case_count += entry.cases.len;
        }

        try entries.append(context.allocator, entry);
        report.runtimes = entries.items;
        try context.saveJson(results_path, report);
    }

    try context.saveJson(results_path, report);

    const report_path = try std.fs.path.join(context.allocator, &.{ context.run_dir, "report.md" });
    const report_json = try json.cloneViaSerialization(context.allocator, report);
    const markdown = try reporting.markdown(context.allocator, report_json);
    try context.writeFile(report_path, markdown);

    if (!options.prepare_only) {
        const latest_path = try std.fs.path.join(context.allocator, &.{ context.cache_dir, "latest.json" });
        try context.saveJson(latest_path, .{ .results = results_path });
    }

    const summary = try reporting.summarize(context.allocator, report_json);
    defer context.allocator.free(summary);

    std.debug.print("Report: {s}\n{s}\n", .{ report_path, summary });

    if (!options.prepare_only and case_count == 0) {
        std.debug.print("No cases were executed. Check filters and preparation diagnostics.\n", .{});
        failed = true;
    }

    return if (failed) 1 else 0;
}

fn runIsolationChecks(matrix: *Matrix, runtime: Runtime) !u8 {
    const context = matrix.context;

    try matrix.ensureImage(runtime.image);

    const fixtures_dir = try std.fs.path.join(context.allocator, &.{ context.run_dir, "self-test" });
    try context.makeDir(fixtures_dir);

    const IsolationCase = struct {
        name: []const u8,
        script: []const u8,
        timeout_ms: u64,
        status: protocol.Status,
    };

    const cases = [_]IsolationCase{
        .{
            .name = "success",
            .script = "printf '{\"event\":\"result\",\"id\":0,\"status\":0}\\n'\n",
            .timeout_ms = 10_000,
            .status = .pass,
        },
        .{
            .name = "signal",
            .script = "printf '{\"event\":\"stage\",\"stage\":\"run\"}\\n'\nkill -SEGV $$\n",
            .timeout_ms = 10_000,
            .status = .crash,
        },
        .{
            .name = "descendant-timeout",
            .script = "printf '{\"event\":\"stage\",\"stage\":\"run\"}\\n'\nsleep 600 &\nwait\n",
            .timeout_ms = 1000,
            .status = .timeout,
        },
    };

    for (cases) |case| {
        const script_path = try std.fs.path.join(context.allocator, &.{ fixtures_dir, "reference" });
        const script = try std.fmt.allocPrint(context.allocator, "#!/bin/sh\n{s}", .{case.script});

        try std.Io.Dir.cwd().writeFile(context.io, .{
            .sub_path = script_path,
            .data = script,
            .flags = .{ .permissions = .fromMode(0o755) },
        });

        const log_prefix = try std.fs.path.join(context.allocator, &.{ fixtures_dir, case.name });
        const outcome = try matrix.execute(runtime, .{
            .fixtures_dir = fixtures_dir,
            .worker = .reference,
            .case_id = 0,
            .timeout_ms = case.timeout_ms,
            .log_prefix = log_prefix,
        });

        if (outcome.status != case.status) return error.IsolationTestFailed;
        if (outcome.status == .crash and outcome.signal != 11) return error.IsolationTestFailed;
        if (outcome.status == .timeout and !std.mem.eql(u8, outcome.stage, "run")) return error.IsolationTestFailed;

        const inspected = try context.runCommand(&.{ "docker", "inspect", outcome.container_name }, .{ .check_exit = false });
        if (inspected.exit_code == 0) return error.ContainerLeaked;

        std.debug.print("PASS isolation/{s}\n", .{case.name});
    }

    return 0;
}

fn selectRuntimes(allocator: std.mem.Allocator, manifest: json.Value, requested_ids: []const []const u8) ![]const Runtime {
    const records = json.field(manifest, "runtimes");
    if (records != .array) return error.InvalidManifest;

    var runtimes: std.ArrayList(Runtime) = .empty;
    defer runtimes.deinit(allocator);

    try runtimes.ensureTotalCapacity(allocator, records.array.items.len);
    for (records.array.items) |record| {
        runtimes.appendAssumeCapacity(try Runtime.initFromJson(record));
    }

    for (requested_ids) |requested_id| {
        var found = false;
        for (runtimes.items) |runtime| {
            if (std.mem.eql(u8, runtime.id, requested_id)) {
                found = true;
                break;
            }
        }

        if (!found) {
            std.debug.print("Unknown runtime: {s}\n", .{requested_id});
            return error.UnknownRuntime;
        }
    }

    var selected: std.ArrayList(Runtime) = .empty;
    errdefer selected.deinit(allocator);

    for (runtimes.items) |runtime| {
        const runtime_id = runtime.id;
        var include = requested_ids.len == 0;
        for (requested_ids) |requested_id| {
            if (std.mem.eql(u8, requested_id, runtime_id)) {
                include = true;
                break;
            }
        }

        if (include) {
            try selected.append(allocator, runtime);
        }
    }

    if (selected.items.len == 0) return error.NoRuntimes;

    return selected.toOwnedSlice(allocator);
}

fn executeMain(init: std.process.Init) !u8 {
    const allocator = init.arena.allocator();

    const argv = try init.minimal.args.toSlice(allocator);
    const options = parseOptions(allocator, argv) catch |err| {
        try printUsage(allocator);
        return err;
    };

    if (options.help) {
        try printUsage(allocator);
        return 0;
    }

    const project_dir = try std.Io.Dir.cwd().realPathFileAlloc(init.io, options.project_dir, allocator);
    const worker_path = try std.Io.Dir.cwd().realPathFileAlloc(init.io, options.libc_worker_path, allocator);
    const cache_dir = try std.fs.path.resolve(allocator, &.{ project_dir, options.cache_dir orelse ".tests-matrix" });

    var context: Context = .{
        .allocator = allocator,
        .io = init.io,
        .project_dir = project_dir,
        .cache_dir = cache_dir,
        .run_dir = "",
    };

    const timestamp_seconds = std.Io.Clock.real.now(init.io).toSeconds();
    const suffix = try context.randomSuffix();
    context.run_dir = try std.fmt.allocPrint(allocator, "{s}/runs/{d}-{s}", .{ cache_dir, timestamp_seconds, suffix });

    if (options.report_only) {
        const results_path = options.results_path orelse results_from_cache: {
            const latest_path = try std.fs.path.join(allocator, &.{ cache_dir, "latest.json" });
            const latest = try context.loadJson(latest_path);

            break :results_from_cache try json.requireString(latest, "results");
        };

        const results = try context.loadJson(results_path);
        const markdown = try reporting.markdown(allocator, results);
        try std.Io.File.stdout().writeStreamingAll(init.io, markdown);

        return 0;
    }

    const manifest_path = try std.fs.path.join(allocator, &.{ project_dir, "tests/environments/runtimes.json" });
    const manifest = try context.loadJson(manifest_path);
    const schema_version = json.asInteger(json.field(manifest, "schema_version"));

    if (schema_version != 1) return error.UnsupportedManifestVersion;

    const selected_runtimes = try selectRuntimes(allocator, manifest, options.runtimes.items);

    try context.makeDir(context.run_dir);
    _ = context.runCommand(&.{ "docker", "info", "--format", "{{.OSType}}/{{.Architecture}}" }, .{ .timeout_ms = 20_000 }) catch {
        std.debug.print("run-tests_matrix requires the Docker CLI and an accessible Docker daemon.\n", .{});
        return error.DockerUnavailable;
    };

    try verifyWorker(&context, worker_path);

    var matrix: Matrix = .{
        .context = &context,
        .manifest = manifest,
        .libc_worker_path = worker_path,
        .platform = try json.requireString(manifest, "platform"),
    };

    if (options.assertion_worker_path.len != 0) {
        matrix.assertion_worker_path = try std.Io.Dir.cwd().realPathFileAlloc(init.io, options.assertion_worker_path, allocator);
    }

    if (options.zig_exe_path.len != 0) {
        matrix.compiler_sha256 = try context.hashFile(options.zig_exe_path);
    }

    if (options.self_test) {
        if (selected_runtimes.len != 1) return error.SelfTestRequiresOneRuntime;

        return runIsolationChecks(&matrix, selected_runtimes[0]);
    }

    return runMatrix(&matrix, selected_runtimes, options);
}

pub fn main(init: std.process.Init) void {
    const exit_code = executeMain(init) catch |err| {
        std.debug.print("matrix: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };

    if (exit_code != 0) {
        std.process.exit(exit_code);
    }
}

test {
    _ = protocol;
    _ = support;
    _ = json;
    _ = layout;
    _ = reporting;
    _ = cache;
}

test "argument filters and invalid deadlines" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const base_args = [_][]const u8{ "matrix", "--project", ".", "--worker", "worker" };

    const parsed = try parseOptions(allocator, &(base_args ++ .{ "--runtime", "test", "--case-prefix", "synchronization." }));
    try std.testing.expectEqualStrings("synchronization.", parsed.case_prefix.?);

    try std.testing.expectError(error.InvalidTimeout, parseOptions(allocator, &(base_args ++ .{ "--timeout", "0" })));
    try std.testing.expectError(error.InvalidTimeout, parseOptions(allocator, &(base_args ++ .{ "--timeout", "nan" })));
    try std.testing.expectError(error.ConflictingFilters, parseOptions(allocator, &(base_args ++ .{ "--case", "a", "--case-prefix", "b" })));
}

test "suite selection composes with case filters and rejects unknown suites" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const base_args = [_][]const u8{ "matrix", "--project", ".", "--worker", "worker" };

    const options = try parseOptions(allocator, &(base_args ++ .{ "--suite", "elf", "--suite", "lifecycle", "--case-prefix", "elf.relr-" }));

    try std.testing.expect(options.selectsSuite("lifecycle"));
    try std.testing.expect(!options.selectsSuite("libc"));
    try std.testing.expect(options.selectsCase("elf", "elf.relr-valid"));
    try std.testing.expect(!options.selectsCase("elf", "elf.plt-only"));
    try std.testing.expect(!options.selectsCase("lifecycle", "lifecycle.reload"));

    try std.testing.expectError(error.UnknownSuite, parseOptions(allocator, &(base_args ++ .{ "--suite", "unknown" })));
}

test "runtime boundary validates configuration and retains original metadata" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    var record = try json.parse(allocator,
        \\{
        \\  "id": "test",
        \\  "image": "image",
        \\  "libc_path": "/lib/libc.so",
        \\  "loader_path": "/lib/loader.so",
        \\  "package_version": "1",
        \\  "sdk_recipe": "alpine",
        \\  "libc_family": "musl",
        \\  "sdk_args": {"VERSION": "1"},
        \\  "extra": "retained"
        \\}
    );

    const runtime = try Runtime.initFromJson(record);
    try std.testing.expectEqual(Runtime.SdkRecipe.alpine, runtime.sdk_recipe);
    try std.testing.expectEqual(Runtime.LibcFamily.musl, runtime.libc_family);
    try std.testing.expectEqualStrings("retained", json.stringField(runtime.metadata, "extra"));

    var manifest = json.object();
    const records = try json.cloneViaSerialization(allocator, .{record});
    try json.putField(allocator, &manifest, "runtimes", records);

    const selected = try selectRuntimes(allocator, manifest, &.{ "test", "test" });
    try std.testing.expectEqual(@as(usize, 1), selected.len);
    try std.testing.expectError(error.UnknownRuntime, selectRuntimes(allocator, manifest, &.{"missing"}));

    try json.putField(allocator, &record, "sdk_recipe", json.string("unknown"));
    try std.testing.expectError(error.UnknownSdkRecipe, Runtime.initFromJson(record));

    try json.putField(allocator, &record, "sdk_recipe", json.string("alpine"));
    try json.putField(allocator, &record, "libc_family", json.string("unknown"));
    try std.testing.expectError(error.UnknownLibcFamily, Runtime.initFromJson(record));

    try json.putField(allocator, &record, "libc_family", json.string("musl"));
    const invalid_sdk_args = try json.parse(allocator, "{\"VERSION\":1}");
    try json.putField(allocator, &record, "sdk_args", invalid_sdk_args);
    try std.testing.expectError(error.InvalidManifest, Runtime.initFromJson(record));

    try json.putField(allocator, &record, "sdk_args", json.object());
    try json.putField(allocator, &record, "image", json.string(""));
    try std.testing.expectError(error.InvalidManifest, Runtime.initFromJson(record));
}
