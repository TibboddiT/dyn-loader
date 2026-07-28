const std = @import("std");
const dll = @import("dll");
const vk = @import("vk.zig");
const wl = @import("wayland.zig");
const VulkanProcResolver = @import("vulkan_proc_resolver.zig").VulkanProcResolver;
const GraphicsContext = @import("graphics_context.zig").GraphicsContext;
const Swapchain = @import("swapchain.zig").Swapchain;
const Allocator = std.mem.Allocator;

// pub const std_options: std.Options = .{
//     .log_scope_levels = &.{.{
//         .scope = .dynamic_library_loader,
//         .level = .debug,
//     }},
// };

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

const vert_spv align(@alignOf(u32)) = @embedFile("vert.spv").*;
const frag_spv align(@alignOf(u32)) = @embedFile("frag.spv").*;

const app_name = "vulkan-zig triangle example";

const Vertex = struct {
    const binding_description = vk.VertexInputBindingDescription{
        .binding = 0,
        .stride = @sizeOf(Vertex),
        .input_rate = .vertex,
    };

    const attribute_description = [_]vk.VertexInputAttributeDescription{
        .{
            .binding = 0,
            .location = 0,
            .format = .r32g32_sfloat,
            .offset = @offsetOf(Vertex, "pos"),
        },
        .{
            .binding = 0,
            .location = 1,
            .format = .r32g32b32_sfloat,
            .offset = @offsetOf(Vertex, "color"),
        },
    };

    pos: [2]f32,
    color: [3]f32,
};

const vertices = [_]Vertex{
    .{ .pos = .{ 0, -0.5 }, .color = .{ 1, 0, 0 } },
    .{ .pos = .{ 0.5, 0.5 }, .color = .{ 0, 1, 0 } },
    .{ .pos = .{ -0.5, 0.5 }, .color = .{ 0, 0, 1 } },
};

const WaylandState = struct {
    api: *const wl.Api,
    compositor: ?*wl.Compositor = null,
    wm_base: ?*wl.XdgWmBase = null,
    extent: vk.Extent2D = .{ .width = 800, .height = 600 },
    pending_extent: ?vk.Extent2D = null,
    resize_pending: bool = false,
    configured: bool = false,
    running: bool = true,
    bind_failed: bool = false,

    fn registryGlobal(data: ?*anyopaque, registry: *wl.Registry, name: u32, interface: [*:0]const u8, version: u32) callconv(.c) void {
        const self: *WaylandState = @ptrCast(@alignCast(data.?));
        const interface_name = std.mem.span(interface);

        if (self.compositor == null and std.mem.eql(u8, interface_name, "wl_compositor")) {
            const proxy = self.api.bind(registry, name, self.api.compositor_interface, @min(version, 1)) catch {
                self.bind_failed = true;
                return;
            };
            self.compositor = @ptrCast(proxy);
        } else if (self.wm_base == null and std.mem.eql(u8, interface_name, "xdg_wm_base")) {
            const proxy = self.api.bind(registry, name, &wl.xdg_wm_base_interface, @min(version, 1)) catch {
                self.bind_failed = true;
                return;
            };
            self.wm_base = @ptrCast(proxy);
        }
    }

    fn registryGlobalRemove(_: ?*anyopaque, _: *wl.Registry, _: u32) callconv(.c) void {}

    fn wmBasePing(data: ?*anyopaque, wm_base: *wl.XdgWmBase, serial: u32) callconv(.c) void {
        const self: *WaylandState = @ptrCast(@alignCast(data.?));
        self.api.pong(wm_base, serial);
    }

    fn surfaceConfigure(data: ?*anyopaque, xdg_surface: *wl.XdgSurface, serial: u32) callconv(.c) void {
        const self: *WaylandState = @ptrCast(@alignCast(data.?));
        self.api.ackConfigure(xdg_surface, serial);

        if (self.pending_extent) |extent| {
            if (self.configured and !std.meta.eql(self.extent, extent)) self.resize_pending = true;
            self.extent = extent;
            self.pending_extent = null;
        }
        self.configured = true;
    }

    fn toplevelConfigure(data: ?*anyopaque, _: *wl.XdgToplevel, width: i32, height: i32, _: *wl.Array) callconv(.c) void {
        const self: *WaylandState = @ptrCast(@alignCast(data.?));
        var extent = self.extent;
        var changed = false;

        if (width > 0) {
            extent.width = @intCast(width);
            changed = true;
        }
        if (height > 0) {
            extent.height = @intCast(height);
            changed = true;
        }
        if (changed) self.pending_extent = extent;
    }

    fn toplevelClose(data: ?*anyopaque, _: *wl.XdgToplevel) callconv(.c) void {
        const self: *WaylandState = @ptrCast(@alignCast(data.?));
        self.running = false;
    }
};

const registry_listener = wl.RegistryListener{
    .global = &WaylandState.registryGlobal,
    .global_remove = &WaylandState.registryGlobalRemove,
};
const wm_base_listener = wl.XdgWmBaseListener{ .ping = &WaylandState.wmBasePing };
const surface_listener = wl.XdgSurfaceListener{ .configure = &WaylandState.surfaceConfigure };
const toplevel_listener = wl.XdgToplevelListener{
    .configure = &WaylandState.toplevelConfigure,
    .close = &WaylandState.toplevelClose,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = init.minimal.args;
    const environ = init.minimal.environ;

    try dll.init(.{ .allocator = allocator, .io = io, .args = args, .environ = environ });
    defer dll.deinit();

    std.log.info("loading 'libwayland-client.so.0'...", .{});

    const lib_wayland = try dll.load("libwayland-client.so.0");
    const wayland = try wl.Api.load(lib_wayland);

    std.log.info("loading 'libvulkan.so.1'...", .{});

    const lib_vulkan = try dll.load("libvulkan.so.1");
    VulkanProcResolver.lib_vulkan = lib_vulkan;

    const display = try wayland.connect();
    defer wayland.disconnect(display);

    var window = WaylandState{ .api = &wayland };

    const registry = try wayland.getRegistry(display);
    defer wayland.destroyProxy(@ptrCast(registry));
    try wayland.addListener(@ptrCast(registry), @ptrCast(&registry_listener), &window);
    try wayland.roundtrip(display);

    if (window.bind_failed) return error.WaylandGlobalBindFailed;
    const compositor = window.compositor orelse return error.MissingWaylandCompositor;
    defer wayland.destroyProxy(@ptrCast(compositor));
    const wm_base = window.wm_base orelse return error.MissingXdgWmBase;
    defer wayland.destroyWmBase(wm_base);
    try wayland.addListener(@ptrCast(wm_base), @ptrCast(&wm_base_listener), &window);

    const surface = try wayland.createSurface(compositor);
    defer wayland.destroySurface(surface);
    const xdg_surface = try wayland.getXdgSurface(wm_base, surface);
    defer wayland.destroyXdgSurface(xdg_surface);
    try wayland.addListener(@ptrCast(xdg_surface), @ptrCast(&surface_listener), &window);

    const toplevel = try wayland.getToplevel(xdg_surface);
    defer wayland.destroyToplevel(toplevel);
    try wayland.addListener(@ptrCast(toplevel), @ptrCast(&toplevel_listener), &window);
    wayland.setTitle(toplevel, "wayland_vulkan_triangle.zig");
    wayland.setAppId(toplevel, "wayland_vulkan_triangle");

    wayland.commit(surface);
    while (!window.configured and window.running) try wayland.roundtrip(display);
    if (!window.running) return;

    const gc = try GraphicsContext.init(allocator, app_name, .{ .wayland = .{
        .display = @ptrCast(display),
        .surface = @ptrCast(surface),
    } });
    defer gc.deinit();

    std.log.info("Using device: {s}", .{gc.deviceName()});

    var swapchain = try Swapchain.init(&gc, allocator, window.extent);
    defer swapchain.deinit();

    const pipeline_layout = try gc.dev.createPipelineLayout(&.{
        .flags = .{},
        .set_layout_count = 0,
        .p_set_layouts = undefined,
        .push_constant_range_count = 0,
        .p_push_constant_ranges = undefined,
    }, null);
    defer gc.dev.destroyPipelineLayout(pipeline_layout, null);

    const render_pass = try createRenderPass(&gc, swapchain);
    defer gc.dev.destroyRenderPass(render_pass, null);

    const pipeline = try createPipeline(&gc, pipeline_layout, render_pass);
    defer gc.dev.destroyPipeline(pipeline, null);

    var framebuffers = try createFramebuffers(&gc, allocator, render_pass, swapchain);
    defer destroyFramebuffers(&gc, allocator, framebuffers);

    const pool = try gc.dev.createCommandPool(&.{
        .queue_family_index = gc.graphics_queue.family,
    }, null);
    defer gc.dev.destroyCommandPool(pool, null);

    const buffer = try gc.dev.createBuffer(&.{
        .size = @sizeOf(@TypeOf(vertices)),
        .usage = .{ .transfer_dst_bit = true, .vertex_buffer_bit = true },
        .sharing_mode = .exclusive,
    }, null);
    defer gc.dev.destroyBuffer(buffer, null);
    const mem_reqs = gc.dev.getBufferMemoryRequirements(buffer);
    const memory = try gc.allocate(mem_reqs, .{ .device_local_bit = true });
    defer gc.dev.freeMemory(memory, null);
    try gc.dev.bindBufferMemory(buffer, memory, 0);

    try uploadVertices(&gc, pool, buffer);

    var cmdbufs = try createCommandBuffers(
        &gc,
        pool,
        allocator,
        buffer,
        swapchain.extent,
        render_pass,
        pipeline,
        framebuffers,
    );
    defer destroyCommandBuffers(&gc, pool, allocator, cmdbufs);

    var state: Swapchain.PresentState = .optimal;
    main_loop: while (window.running) {
        try dispatchWayland(&wayland, display);
        if (!window.running) break :main_loop;

        if (state == .suboptimal or window.resize_pending) {
            window.resize_pending = false;
            var do_recycle = true;
            while (true) {
                swapchain.recreate(window.extent, do_recycle) catch |err| switch (err) {
                    error.OutOfDateKHR => {
                        try dispatchWayland(&wayland, display);
                        if (!window.running) break :main_loop;
                        do_recycle = false;
                        continue;
                    },
                    else => |e| return e,
                };
                break;
            }

            destroyFramebuffers(&gc, allocator, framebuffers);
            framebuffers = try createFramebuffers(&gc, allocator, render_pass, swapchain);

            destroyCommandBuffers(&gc, pool, allocator, cmdbufs);
            cmdbufs = try createCommandBuffers(
                &gc,
                pool,
                allocator,
                buffer,
                swapchain.extent,
                render_pass,
                pipeline,
                framebuffers,
            );
        }

        const cmdbuf = cmdbufs[swapchain.image_index];
        state = swapchain.present(cmdbuf) catch |err| switch (err) {
            error.OutOfDateKHR => Swapchain.PresentState.suboptimal,
            else => |narrow| return narrow,
        };
    }

    try swapchain.waitForAllFences();
    try gc.dev.deviceWaitIdle();
}

fn dispatchWayland(api: *const wl.Api, display: *wl.Display) !void {
    while (!api.prepareRead(display)) try api.dispatchPending(display);

    var read_prepared = true;
    defer if (read_prepared) api.cancelRead(display);

    try api.flush(display);

    var poll_fds = [_]std.posix.pollfd{.{
        .fd = api.getFd(display),
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = try std.posix.poll(&poll_fds, 0);
    if (ready > 0 and poll_fds[0].revents & std.posix.POLL.IN != 0) {
        try api.readEvents(display);
    } else {
        api.cancelRead(display);
    }
    read_prepared = false;

    try api.dispatchPending(display);
    try api.flush(display);
}

fn uploadVertices(gc: *const GraphicsContext, pool: vk.CommandPool, buffer: vk.Buffer) !void {
    const staging_buffer = try gc.dev.createBuffer(&.{
        .size = @sizeOf(@TypeOf(vertices)),
        .usage = .{ .transfer_src_bit = true },
        .sharing_mode = .exclusive,
    }, null);
    defer gc.dev.destroyBuffer(staging_buffer, null);
    const mem_reqs = gc.dev.getBufferMemoryRequirements(staging_buffer);
    const staging_memory = try gc.allocate(mem_reqs, .{ .host_visible_bit = true, .host_coherent_bit = true });
    defer gc.dev.freeMemory(staging_memory, null);
    try gc.dev.bindBufferMemory(staging_buffer, staging_memory, 0);

    {
        const data = try gc.dev.mapMemory(staging_memory, 0, vk.WHOLE_SIZE, .{});
        defer gc.dev.unmapMemory(staging_memory);

        const gpu_vertices: [*]Vertex = @ptrCast(@alignCast(data));
        @memcpy(gpu_vertices, vertices[0..]);
    }

    try copyBuffer(gc, pool, buffer, staging_buffer, @sizeOf(@TypeOf(vertices)));
}

fn copyBuffer(gc: *const GraphicsContext, pool: vk.CommandPool, dst: vk.Buffer, src: vk.Buffer, size: vk.DeviceSize) !void {
    var cmdbuf_handle: vk.CommandBuffer = undefined;
    try gc.dev.allocateCommandBuffers(&.{
        .command_pool = pool,
        .level = .primary,
        .command_buffer_count = 1,
    }, @ptrCast(&cmdbuf_handle));
    defer gc.dev.freeCommandBuffers(pool, 1, @ptrCast(&cmdbuf_handle));

    const cmdbuf = GraphicsContext.CommandBuffer.init(cmdbuf_handle, gc.dev.wrapper);

    try cmdbuf.beginCommandBuffer(&.{
        .flags = .{ .one_time_submit_bit = true },
    });

    const region = vk.BufferCopy{
        .src_offset = 0,
        .dst_offset = 0,
        .size = size,
    };
    cmdbuf.copyBuffer(src, dst, 1, @ptrCast(&region));
    try cmdbuf.endCommandBuffer();

    const si = vk.SubmitInfo{
        .command_buffer_count = 1,
        .p_command_buffers = (&cmdbuf.handle)[0..1],
        .p_wait_dst_stage_mask = undefined,
    };
    try gc.dev.queueSubmit(gc.graphics_queue.handle, 1, @ptrCast(&si), .null_handle);
    try gc.dev.queueWaitIdle(gc.graphics_queue.handle);
}

fn createCommandBuffers(
    gc: *const GraphicsContext,
    pool: vk.CommandPool,
    allocator: Allocator,
    buffer: vk.Buffer,
    extent: vk.Extent2D,
    render_pass: vk.RenderPass,
    pipeline: vk.Pipeline,
    framebuffers: []vk.Framebuffer,
) ![]vk.CommandBuffer {
    const cmdbufs = try allocator.alloc(vk.CommandBuffer, framebuffers.len);
    errdefer allocator.free(cmdbufs);

    try gc.dev.allocateCommandBuffers(&.{
        .command_pool = pool,
        .level = .primary,
        .command_buffer_count = @intCast(cmdbufs.len),
    }, cmdbufs.ptr);
    errdefer gc.dev.freeCommandBuffers(pool, @intCast(cmdbufs.len), cmdbufs.ptr);

    const clear = vk.ClearValue{
        .color = .{ .float_32 = .{ 0, 0, 0, 1 } },
    };

    const viewport = vk.Viewport{
        .x = 0,
        .y = 0,
        .width = @floatFromInt(extent.width),
        .height = @floatFromInt(extent.height),
        .min_depth = 0,
        .max_depth = 1,
    };

    const scissor = vk.Rect2D{
        .offset = .{ .x = 0, .y = 0 },
        .extent = extent,
    };

    for (cmdbufs, framebuffers) |cmdbuf, framebuffer| {
        try gc.dev.beginCommandBuffer(cmdbuf, &.{});

        gc.dev.cmdSetViewport(cmdbuf, 0, 1, @ptrCast(&viewport));
        gc.dev.cmdSetScissor(cmdbuf, 0, 1, @ptrCast(&scissor));

        // This needs to be a separate definition - see https://github.com/ziglang/zig/issues/7627.
        const render_area = vk.Rect2D{
            .offset = .{ .x = 0, .y = 0 },
            .extent = extent,
        };

        gc.dev.cmdBeginRenderPass(cmdbuf, &.{
            .render_pass = render_pass,
            .framebuffer = framebuffer,
            .render_area = render_area,
            .clear_value_count = 1,
            .p_clear_values = @ptrCast(&clear),
        }, .@"inline");

        gc.dev.cmdBindPipeline(cmdbuf, .graphics, pipeline);
        const offset = [_]vk.DeviceSize{0};
        gc.dev.cmdBindVertexBuffers(cmdbuf, 0, 1, @ptrCast(&buffer), &offset);
        gc.dev.cmdDraw(cmdbuf, vertices.len, 1, 0, 0);

        gc.dev.cmdEndRenderPass(cmdbuf);
        try gc.dev.endCommandBuffer(cmdbuf);
    }

    return cmdbufs;
}

fn destroyCommandBuffers(gc: *const GraphicsContext, pool: vk.CommandPool, allocator: Allocator, cmdbufs: []vk.CommandBuffer) void {
    gc.dev.freeCommandBuffers(pool, @truncate(cmdbufs.len), cmdbufs.ptr);
    allocator.free(cmdbufs);
}

fn createFramebuffers(gc: *const GraphicsContext, allocator: Allocator, render_pass: vk.RenderPass, swapchain: Swapchain) ![]vk.Framebuffer {
    const framebuffers = try allocator.alloc(vk.Framebuffer, swapchain.swap_images.len);
    errdefer allocator.free(framebuffers);

    var i: usize = 0;
    errdefer for (framebuffers[0..i]) |fb| gc.dev.destroyFramebuffer(fb, null);

    for (framebuffers) |*fb| {
        fb.* = try gc.dev.createFramebuffer(&.{
            .render_pass = render_pass,
            .attachment_count = 1,
            .p_attachments = @ptrCast(&swapchain.swap_images[i].view),
            .width = swapchain.extent.width,
            .height = swapchain.extent.height,
            .layers = 1,
        }, null);
        i += 1;
    }

    return framebuffers;
}

fn destroyFramebuffers(gc: *const GraphicsContext, allocator: Allocator, framebuffers: []const vk.Framebuffer) void {
    for (framebuffers) |fb| gc.dev.destroyFramebuffer(fb, null);
    allocator.free(framebuffers);
}

fn createRenderPass(gc: *const GraphicsContext, swapchain: Swapchain) !vk.RenderPass {
    const color_attachment = vk.AttachmentDescription{
        .format = swapchain.surface_format.format,
        .samples = .{ .@"1_bit" = true },
        .load_op = .clear,
        .store_op = .store,
        .stencil_load_op = .dont_care,
        .stencil_store_op = .dont_care,
        .initial_layout = .undefined,
        .final_layout = .present_src_khr,
    };

    const color_attachment_ref = vk.AttachmentReference{
        .attachment = 0,
        .layout = .color_attachment_optimal,
    };

    const subpass = vk.SubpassDescription{
        .pipeline_bind_point = .graphics,
        .color_attachment_count = 1,
        .p_color_attachments = @ptrCast(&color_attachment_ref),
    };

    return try gc.dev.createRenderPass(&.{
        .attachment_count = 1,
        .p_attachments = @ptrCast(&color_attachment),
        .subpass_count = 1,
        .p_subpasses = @ptrCast(&subpass),
    }, null);
}

fn createPipeline(
    gc: *const GraphicsContext,
    layout: vk.PipelineLayout,
    render_pass: vk.RenderPass,
) !vk.Pipeline {
    const vert = try gc.dev.createShaderModule(&.{
        .code_size = vert_spv.len,
        .p_code = @ptrCast(&vert_spv),
    }, null);
    defer gc.dev.destroyShaderModule(vert, null);

    const frag = try gc.dev.createShaderModule(&.{
        .code_size = frag_spv.len,
        .p_code = @ptrCast(&frag_spv),
    }, null);
    defer gc.dev.destroyShaderModule(frag, null);

    const pssci = [_]vk.PipelineShaderStageCreateInfo{
        .{
            .stage = .{ .vertex_bit = true },
            .module = vert,
            .p_name = "main",
        },
        .{
            .stage = .{ .fragment_bit = true },
            .module = frag,
            .p_name = "main",
        },
    };

    const pvisci = vk.PipelineVertexInputStateCreateInfo{
        .vertex_binding_description_count = 1,
        .p_vertex_binding_descriptions = @ptrCast(&Vertex.binding_description),
        .vertex_attribute_description_count = Vertex.attribute_description.len,
        .p_vertex_attribute_descriptions = &Vertex.attribute_description,
    };

    const piasci = vk.PipelineInputAssemblyStateCreateInfo{
        .topology = .triangle_list,
        .primitive_restart_enable = .false,
    };

    const pvsci = vk.PipelineViewportStateCreateInfo{
        .viewport_count = 1,
        .p_viewports = undefined,
        .scissor_count = 1,
        .p_scissors = undefined,
    };

    const prsci = vk.PipelineRasterizationStateCreateInfo{
        .depth_clamp_enable = .false,
        .rasterizer_discard_enable = .false,
        .polygon_mode = .fill,
        .cull_mode = .{ .back_bit = true },
        .front_face = .clockwise,
        .depth_bias_enable = .false,
        .depth_bias_constant_factor = 0,
        .depth_bias_clamp = 0,
        .depth_bias_slope_factor = 0,
        .line_width = 1,
    };

    const pmsci = vk.PipelineMultisampleStateCreateInfo{
        .rasterization_samples = .{ .@"1_bit" = true },
        .sample_shading_enable = .false,
        .min_sample_shading = 1,
        .alpha_to_coverage_enable = .false,
        .alpha_to_one_enable = .false,
    };

    const pcbas = vk.PipelineColorBlendAttachmentState{
        .blend_enable = .false,
        .src_color_blend_factor = .one,
        .dst_color_blend_factor = .zero,
        .color_blend_op = .add,
        .src_alpha_blend_factor = .one,
        .dst_alpha_blend_factor = .zero,
        .alpha_blend_op = .add,
        .color_write_mask = .{ .r_bit = true, .g_bit = true, .b_bit = true, .a_bit = true },
    };

    const pcbsci = vk.PipelineColorBlendStateCreateInfo{
        .logic_op_enable = .false,
        .logic_op = .copy,
        .attachment_count = 1,
        .p_attachments = @ptrCast(&pcbas),
        .blend_constants = [_]f32{ 0, 0, 0, 0 },
    };

    const dynstate = [_]vk.DynamicState{ .viewport, .scissor };
    const pdsci = vk.PipelineDynamicStateCreateInfo{
        .flags = .{},
        .dynamic_state_count = dynstate.len,
        .p_dynamic_states = &dynstate,
    };

    const gpci = vk.GraphicsPipelineCreateInfo{
        .flags = .{},
        .stage_count = 2,
        .p_stages = &pssci,
        .p_vertex_input_state = &pvisci,
        .p_input_assembly_state = &piasci,
        .p_tessellation_state = null,
        .p_viewport_state = &pvsci,
        .p_rasterization_state = &prsci,
        .p_multisample_state = &pmsci,
        .p_depth_stencil_state = null,
        .p_color_blend_state = &pcbsci,
        .p_dynamic_state = &pdsci,
        .layout = layout,
        .render_pass = render_pass,
        .subpass = 0,
        .base_pipeline_handle = .null_handle,
        .base_pipeline_index = -1,
    };

    var pipeline: vk.Pipeline = undefined;
    _ = try gc.dev.createGraphicsPipelines(
        .null_handle,
        1,
        @ptrCast(&gpci),
        null,
        @ptrCast(&pipeline),
    );
    return pipeline;
}
