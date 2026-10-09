# DynLoader

Loading system dynamic libraries from non libc static executables.

## Proof of concept

All executable artifacts produced by the included examples are static executables that load dynamic libraries without using libc's `dlopen`.

*Warning: prototype quality: can contain bugs, lots of TODOs remaining.*

See [this thread](https://ziggit.dev/t/dynamic-linking-without-libc-adventures) for further information.

## Usage

For now, the library always follows the latest "master" x86_64 tarball available on [ziglang.org](https://ziglang.org/download/).

```sh
zig fetch --save=dll https://github.com/TibboddiT/dyn-loader/archive/refs/heads/main.tar.gz
```

```zig
// build.zig

// ...

    const dll_dep = b.dependency("dll", .{
        .optimize = optimize,
        // no `target`, because it is always x86_64 linux baseline
    });
    const dll_mod = dll_dep.module("dll");

// then add the module to your executable as usual
```

```zig
const std = @import("std");
const dll = @import("dll");

pub const debug = struct {
    pub const SelfInfo = dll.CustomSelfInfo;
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = init.minimal.args;
    const environ = init.minimal.environ;

    // `dll` is a singleton, it should be initialized early and only once, on the main thread
    try dll.init(.{ .allocator = allocator, .io = io, .args = args, .environ = environ, .log_level = .err });
    defer dll.deinit();

    const lib_c = try dll.loadSystemLibC();

    // or load any other dynamic library:
    // const lib_x11 = try dll.load("libX11.so.6");

    const printf_sym = try lib_c.getSymbol("printf");
    const printf_addr = printf_sym.addr;
    const printf: *const fn ([*:0]const u8, ...) callconv(.c) c_int = @ptrFromInt(printf_addr);

    _ = printf("Hello, %s!\n", "World");
}
```

## Current known limitations

- Initializing the loader and loading libraries should be done before starting any thread.
- Dirty tricks are used to accommodate patched libc versions from various distros.
- Some libc functions that need to be implemented in zig are not yet implemented.

## How it works

Before `main`, the loader takes ownership of TLS through strong definitions of
`__zig_elf_static_tls`, `__zig_elf_static_tls_init`, `__zig_elf_static_tls_fill`, and
`__tls_get_addr`.

Here is a simplified overview of what is done when loading a dynamic library:

- libraries from `LD_PRELOAD` are loaded first
- dependencies are resolved, and for each library to load:
  - segments are mmapped
  - relative relocations are processed
- for each newly mapped library:
  - libc-specific patches are applied if needed
  - TLS offsets are computed
  - "normal" relocations are processed
    - dl, malloc, and thread functions are "redirected" to zig code
  - TLS is set up
  - `IRELATIVE` relocations are processed
- then for each newly loaded library:
  - segment permissions are applied
  - information about the extra ELF files is added to `CustomSelfInfo` to get nice stack traces
  - init functions are called
    - with specific handling in the case of libc

## Notes

A copy of musl's `libc.so` is included, compiled from sources without any modification.
You should load it before loading libraries compiled against musl on a non musl based system (see [the musl printf example](examples/printf_musl.zig)).
The library is stripped (`strip --strip-unneeded lib/libc.so`) as is often the case when it is packaged for linux distros.

To demonstrate loading musl based libraries, an original copy of `libvulkan.so.1.4.326` from the `vulkan-loader` package of [Chimera Linux](https://repo.chimera-linux.org/current/main/x86_64/)
is also included (renamed `libvulkan.so.1`) to make the `vulkan_version_musl` example work.

A copy of `libraylib.so.5.5.0` from [the raylib repository release assets](https://github.com/raysan5/raylib/releases/download/5.5/raylib-5.5_linux_amd64.tar.gz)
is included to make the `raylib` example work. Since this library is compiled against glibc, it will not work on musl based systems. It is in the `resources/raylib` directory.

It is recommended that you build these binary artifacts yourself.

## Run examples

```sh
zig build run-printf
zig build run-printf_musl
zig build run-vulkan_version
zig build run-vulkan_version_musl
zig build run-vulkan_instance
zig build run-x11_window
zig build run-x11_egl
zig build run-x11_vulkan_triangle
zig build run-wayland_vulkan_triangle
```

The following example will intentionally trigger a segfault to demonstrate stack traces across loaded libraries:

```sh
zig build run-segfault
```

The following example will only work on glibc-based systems (because it uses libraries compiled against glibc):

```sh
zig build run-raylib
```

## Test matrix

Note: *Not all tests pass yet*

Tested environments:

| OS                                 | libc                       | Toolchain         |
| ---                                | ---                        | ---               |
| Debian 11 (bullseye)               | glibc 2.31                 | GCC 10.2.1        |
| Debian 12 (bookworm)               | glibc 2.36                 | GCC 12.2.0        |
| Debian testing (forky), 2026-10-07 | glibc 2.43                 | GCC 16.2.0        |
| Arch Linux, 2026-10-07             | glibc 2.44                 | GCC 16.2.1        |
| Alpine 3.10.9                      | musl 1.1.22                | GCC 8.3.0         |
| Chimera Linux, 2025-12-20          | musl 1.2.6 (with mimalloc) | Clang/LLVM 22.1.8 |
| NixOS/nixpkgs, Nix 2.24.11         | glibc 2.39                 | GCC 13.2.0        |
| Alpine 3.22.6                      | musl 1.2.5                 | GCC 14.2.0        |

```sh
zig build run-tests_matrix -- --help
```
