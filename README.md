## Loading dynamic libraries from non libc static executable - Proof of concept

Prototype quality: lots of bugs, lots of TODOs remaining.

Tested on `x86_64-linux-gnu` with glibc 2.41.
Works with a lightly patched musl for now.

See [this thread](https://ziggit.dev/t/dynamic-linking-without-libc-adventures) for further information.

### Usage

```zig
const std = @import("std");
const dll = @import("dll");

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{ .stack_trace_frames = 10 }) = .init;
    const allocator = gpa.allocator();
    defer if (gpa.deinit() != .ok) @panic("Memory check failed");

    try dll.init(.{ .allocator = allocator });
    defer dll.deinit();

    const lib_c = try dll.load("libc.so.6");

    const printf_sym = try lib_c.getSymbol("printf");
    const printf_addr = printf_sym.addr;
    const printf: *const fn ([*:0]const u8, ...) callconv(.c) c_int = @ptrFromInt(printf_addr);

    _ = printf("Hello, %s!\n", "World");
}
```

### Notes

A custom musl's `libc.so` is included, which is a patched version of musl 1.25. The library is stripped (`strip --strip-unneeded lib/libc.so`) as it is often the case when it is packaged for linux distros.

The patch is:

```patch
diff --git a/original/musl-1.2.5/ldso/dynlink.c b/musl-1.2.5/ldso/dynlink.c
index 324aa85..bfc5140 100644
--- a/original/musl-1.2.5/ldso/dynlink.c
+++ b/musl-1.2.5/ldso/dynlink.c
@@ -1767,6 +1767,14 @@ hidden void __dls2(unsigned char *base, size_t *sp)
        else ((stage3_func)laddr(&ldso, dls2b_def.sym->st_value))(sp, auxv);
 }
 
+extern void __pre_dls2b(size_t *auxv)
+{
+       search_vec(auxv, &__hwcap, AT_HWCAP);
+       libc.auxv = auxv;
+       libc.tls_size = sizeof builtin_tls;
+       libc.tls_align = tls_align;
+}
+
 /* Stage 2b sets up a valid thread pointer, which requires relocations
  * completed in stage 2, and on which stage 3 is permitted to depend.
  * This is done as a separate stage, with symbolic lookup as a barrier,
@@ -1775,13 +1783,11 @@ hidden void __dls2(unsigned char *base, size_t *sp)
 
 void __dls2b(size_t *sp, size_t *auxv)
 {
+       __pre_dls2b(auxv);
+
        /* Setup early thread pointer in builtin_tls for ldso/libc itself to
         * use during dynamic linking. If possible it will also serve as the
         * thread pointer at runtime. */
-       search_vec(auxv, &__hwcap, AT_HWCAP);
-       libc.auxv = auxv;
-       libc.tls_size = sizeof builtin_tls;
-       libc.tls_align = tls_align;
        if (__init_tp(__copy_tls((void *)builtin_tls)) < 0) {
                a_crash();
        }
```

An unpatched copy of `libvulkan.so.1.4.326` from [the Alpine repository](https://repo.chimera-linux.org/current/main/x86_64/vulkan-loader-1.4.326-r0.apk) is also included (renamed `libvulkan.so.1`).

Both are in the `resources/musl` directory. It is recommended that you produce those binary artifacts by yourself.

### Build examples

```
zig build run-printf
zig build run-vulkan
zig build run-vulkan_advanced
zig build run-vulkan_musl
zig build run-vulkan_advanced_musl
zig build run-x11_window
```

- Non musl versions expect a glibc based system.
- Both `vulkan_advanced` versions will currently result in an error, until libc's `dl` function replacements are implemented.
