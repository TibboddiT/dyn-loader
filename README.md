## Loading dynamic libraries from non libc static executable - Proof of concept

*Warning: prototype quality: lots of bugs, lots of TODOs remaining.*

Tested on `x86_64-linux-gnu`, with libraries compiled agasint glibc 2.41.
Seems to also work on libraries compiled agasint musl, with a lightly patched `libc.so` version for now (cf. [Notes](#Notes)).

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

    const lib_c = try dll.load("libc.so.6");

    const printf_sym = try lib_c.getSymbol("printf");
    const printf_addr = printf_sym.addr;
    const printf: *const fn ([*:0]const u8, ...) callconv(.c) c_int = @ptrFromInt(printf_addr);

    _ = printf("Hello, %s!\n", "World");
}
```

### Current limitations

- Libraries that `dlopen` other libraries might not behave correctly until:
  - all `dl` public API functions (like `dladdr`) are implemented
- Even some `dl` not so private functions need an implementation, mainly because C++ exception handling (*sad*) might call them... (for instance `_dl_find_object`)
- Loading libraries should be done before having started any thread.
- Starting threads in zig land and in library land needs to be tested.
- Some (rare) relocation types are still missing.
- You should not link any `libc` (it is part of the goal anyway).

### Notes

A custom musl's `libc.so` is included, which is a patched version of musl 1.25.
You should load it first before loading libraries compiled against musl (see [the musl printf example](src/examples/printf_musl.zig)).
The library is stripped (`strip --strip-unneeded lib/libc.so`) as it is often the case when it is packaged for linux distros.

The patch is:

```patch
--- a/./original/musl-1.2.5/src/internal/libc.h
+++ b/./musl-1.2.5/src/internal/libc.h
@@ -34,7 +34,7 @@ struct __libc {
 #define PAGE_SIZE libc.page_size
 #endif
 
-extern hidden struct __libc __libc;
+extern struct __libc __libc;
 #define libc __libc
 
 hidden void __init_libc(char **, char *);
```

An unpatched copy of `libvulkan.so.1.4.326` from [the Alpine repository](https://repo.chimera-linux.org/current/main/x86_64/vulkan-loader-1.4.326-r0.apk) is also included (renamed `libvulkan.so.1`).

Both are in the `resources/musl` directory. It is recommended that you produce those binary artifacts by yourself.

### Run examples

```
zig build run-printf
zig build run-vulkan_version
zig build run-vulkan_version_musl
zig build run-x11_window
```
