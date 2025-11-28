const std = @import("std");

pub fn build(b: *std.Build) void {
    // const target = b.standardTargetOptions(.{});

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

    b.getInstallStep().dependOn(&resources_dir.step);

    const check_step = b.step("check", "Check");

    addExecutable(b, check_step, dll_mod, target, optimize, false, "load_lib", "examples/load_lib.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, false, "printf", "examples/printf.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, false, "printf_musl", "examples/printf_musl.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, true, "segfault", "examples/segfault.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, false, "vulkan_version", "examples/vulkan_version.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, false, "vulkan_version_musl", "examples/vulkan_version_musl.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, false, "x11_window", "examples/x11_window.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, false, "raylib", "examples/raylib.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, false, "x11_egl", "examples/x11_egl.zig");

    addExecutable(b, check_step, dll_mod, target, optimize, false, "vulkan_instance", "examples/vulkan_advanced/vulkan_instance.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, false, "x11_vulkan_triangle", "examples/vulkan_advanced/x11_vulkan_triangle.zig");
}

fn addExecutable(b: *std.Build, check_step: *std.Build.Step, mod: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, force_unstripped: bool, name: []const u8, root_source_file: []const u8) void {
    const exe = b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(root_source_file),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dll", .module = mod },
            },
            .strip = if (force_unstripped) false else null,
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step(std.fmt.allocPrint(b.allocator, "run-{s}", .{name}) catch unreachable, "Run");
    run_step.dependOn(&run_cmd.step);

    const check_name = std.fmt.allocPrint(b.allocator, "check-{s}", .{name}) catch unreachable;
    const check = b.addExecutable(.{
        .name = check_name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(root_source_file),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dll", .module = mod },
            },
        }),
    });

    check_step.dependOn(&check.step);
}
