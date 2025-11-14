const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const dll_mod = b.addModule("dll", .{
        .root_source_file = b.path("src/lib/dynamic_library_loader.zig"),
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

    addExecutable(b, check_step, dll_mod, target, optimize, "load_lib", "src/examples/load_lib.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, "printf", "src/examples/printf.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, "printf_musl", "src/examples/printf_musl.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, "vulkan_version", "src/examples/vulkan_version.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, "vulkan_advanced", "src/examples/vulkan_advanced/vulkan.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, "vulkan_version_musl", "src/examples/vulkan_version_musl.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, "vulkan_advanced_musl", "src/examples/vulkan_advanced/vulkan_musl.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, "x11_window", "src/examples/x11_window.zig");
    addExecutable(b, check_step, dll_mod, target, optimize, "x11_egl", "src/examples/x11_egl.zig");
}

fn addExecutable(b: *std.Build, check_step: *std.Build.Step, mod: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, name: []const u8, root_source_file: []const u8) void {
    const exe = b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(root_source_file),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dll", .module = mod },
            },
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
