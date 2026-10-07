const std = @import("std");

const Example = struct {
    source_path: []const u8,
    force_unstripped: bool = false,
    optimize: ?std.builtin.OptimizeMode = null,
};

pub fn build(b: *std.Build) void {
    const target: std.Build.ResolvedTarget = b.resolveTargetQuery(.{
        .cpu_model = .baseline,
        .os_tag = .linux,
        .cpu_arch = .x86_64,
    });

    const optimize = b.standardOptimizeOption(.{});

    const dll_mod = b.addModule("dll", .{
        .root_source_file = b.path("src/dynamic_library_loader.zig"),
        .target = target,
        .optimize = optimize,
    });

    const resources_dir = b.addInstallDirectory(.{
        .source_dir = b.path("resources"),
        .install_dir = .bin,
        .install_subdir = "resources",
    });

    const check_step = b.step("check", "Check");

    addTestMatrix(b, check_step, dll_mod, target, optimize);

    const examples = [_]Example{
        .{ .source_path = "examples/load_lib.zig" },
        .{ .source_path = "examples/printf.zig" },
        .{ .source_path = "examples/printf_musl.zig" },
        .{ .source_path = "examples/segfault.zig", .force_unstripped = true },
        .{ .source_path = "examples/leak.zig", .force_unstripped = true, .optimize = .Debug },
        .{ .source_path = "examples/vulkan_version.zig" },
        .{ .source_path = "examples/vulkan_version_musl.zig" },
        .{ .source_path = "examples/x11_window.zig" },
        .{ .source_path = "examples/raylib.zig" },
        .{ .source_path = "examples/x11_egl.zig" },
        .{ .source_path = "examples/vulkan_advanced/vulkan_instance.zig" },
        .{ .source_path = "examples/vulkan_advanced/x11_vulkan_triangle.zig" },
        .{ .source_path = "examples/vulkan_advanced/wayland_vulkan_triangle.zig" },
    };

    for (examples) |example| {
        addExample(b, &resources_dir.step, check_step, dll_mod, target, example.optimize orelse optimize, example);
    }
}

fn addExample(
    b: *std.Build,
    resources_step: *std.Build.Step,
    check_step: *std.Build.Step,
    dll_module: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    example: Example,
) void {
    const name = std.fs.path.stem(example.source_path);
    const exe = b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(example.source_path),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dll", .module = dll_module },
            },
            .strip = if (example.force_unstripped) false else null,
        }),
    });
    const install = b.addInstallArtifact(exe, .{});

    install.step.dependOn(resources_step);

    b.getInstallStep().dependOn(&install.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(&install.step);
    run_cmd.addPassthruArgs();

    const run_step = b.step(b.fmt("run-{s}", .{name}), b.fmt("Run {s}", .{name}));
    run_step.dependOn(&run_cmd.step);

    const check_name = b.fmt("check-{s}", .{name});
    const check = b.addExecutable(.{
        .name = check_name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(example.source_path),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dll", .module = dll_module },
            },
        }),
    });

    check_step.dependOn(&check.step);
}

fn addTestMatrix(b: *std.Build, check_step: *std.Build.Step, dll_mod: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) void {
    const regression_abi = b.createModule(.{
        .root_source_file = b.path("tests/resources/regression/abi.zig"),
        .target = target,
        .optimize = optimize,
    });

    const elf_runner = b.createModule(.{
        .root_source_file = b.path("tests/elf/runner.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dll", .module = dll_mod }},
    });

    const lifecycle_runner = b.createModule(.{
        .root_source_file = b.path("tests/behaviors/runner.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "dll", .module = dll_mod },
            .{ .name = "regression_abi", .module = regression_abi },
        },
    });

    const elf_cases = b.createModule(.{
        .root_source_file = b.path("tests/elf/cases.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "elf_runner", .module = elf_runner },
            .{ .name = "regression_abi", .module = regression_abi },
        },
    });

    const lifecycle_cases = b.createModule(.{
        .root_source_file = b.path("tests/behaviors/cases.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "lifecycle_runner", .module = lifecycle_runner },
            .{ .name = "regression_abi", .module = regression_abi },
        },
    });

    const cases_worker = b.addExecutable(.{
        .name = "loader-cases",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/workers/assertions.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dll", .module = dll_mod },
                .{ .name = "elf_runner", .module = elf_runner },
                .{ .name = "elf_cases", .module = elf_cases },
                .{ .name = "lifecycle_runner", .module = lifecycle_runner },
                .{ .name = "lifecycle_cases", .module = lifecycle_cases },
            },
        }),
    });

    const libc_runner = b.addExecutable(.{
        .name = "libc-runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/workers/libc.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "dll", .module = dll_mod }},
        }),
    });

    const matrix_module = b.createModule(.{
        .root_source_file = b.path("tests/main.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
    });

    const matrix = b.addExecutable(.{
        .name = "libc-matrix",
        .root_module = matrix_module,
    });

    const run_matrix = b.addRunArtifact(matrix);
    run_matrix.addArg("--project");
    run_matrix.addDirectoryArg2(b.path("."), .{});
    run_matrix.addArg("--worker");
    run_matrix.addArtifactArg2(libc_runner, .{});
    run_matrix.addArg("--cases-worker");
    run_matrix.addArtifactArg2(cases_worker, .{});
    run_matrix.addArg("--zig-exe");
    run_matrix.addFileArg(.{ .cwd_relative = b.graph.zig_exe });
    run_matrix.addPassthruArgs();
    run_matrix.has_side_effects = true;

    const unit_tests = b.addTest(.{ .root_module = matrix_module });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    run_matrix.step.dependOn(&run_unit_tests.step);

    const run_matrix_step = b.step("run-tests_matrix", "Run ELF, lifecycle, and libc tests (uses docker)");
    run_matrix_step.dependOn(&run_matrix.step);

    check_step.dependOn(&matrix.step);
    check_step.dependOn(&libc_runner.step);
    check_step.dependOn(&cases_worker.step);
}
