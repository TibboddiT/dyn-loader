## Loading dynamic libraries from non libc static executable

### Proof of concept

*Warning: prototype quality: lots of bugs, lots of TODOs remaining.*

Tested on `x86_64-linux-gnu`, with libraries compiled agasint glibc 2.41 and musl 1.2.5.

See [this thread](https://ziggit.dev/t/dynamic-linking-without-libc-adventures) for further information.

### Usage

```zig
const std = @import("std");
const dll = @import("dll");

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer if (gpa.deinit() != .ok) @panic("memory check failed");

    // `dll` is a singleton, it should be initialized early and only once, on the main thread
    try dll.init(.{ .allocator = allocator, .log_level = .warn });
    defer dll.deinit();

    const lib_c = try dll.loadSystemLibC();

    const printf_sym = try lib_c.getSymbol("printf");
    const printf_addr = printf_sym.addr;
    const printf: *const fn ([*:0]const u8, ...) callconv(.c) c_int = @ptrFromInt(printf_addr);

    _ = printf("Hello, %s!\n", "World");
}
```

### Current limitations

- Loading libraries should be done before having started any thread.
- Some (rare) relocation types are still missing.
- Dirty tricks are used to accomodate with patched libc.

### Notes

A musl's `libc.so` is included, compiled from sources without any modification.
You should load it first before loading libraries compiled against musl on a non musl based system (see [the musl printf example](src/examples/printf_musl.zig)).
The library is stripped (`strip --strip-unneeded lib/libc.so`) as it is often the case when it is packaged for linux distros.

An original copy of `libvulkan.so.1.4.326` from the `vulkan-loader` package of [Chimera Linux](https://repo.chimera-linux.org/current/main/x86_64/)
is also included (renamed `libvulkan.so.1`), to make the `vulkan_version_musl` example work.

---

An original copy of `libraylib.so.5.5.0` from [the raylib repository release assets](https://github.com/raysan5/raylib/releases/download/5.5/raylib-5.5_linux_amd64.tar.gz)
is included, to make the `raylib` example work. Since this library is compiled against glibc, it will not work on musl based systems.

It is in the `resources/raylib` directory.

---

It is recommended that you produce these binary artifacts by yourself.

### Run examples

```
zig build run-printf
zig build run-printf_musl
zig build run-vulkan_version
zig build run-vulkan_version_musl
zig build run-x11_window
zig build run-x11_egl
```

The following examples will only work on glibc based systems:

```
zig build run-raylib
```
