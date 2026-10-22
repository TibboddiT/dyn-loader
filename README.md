# DynLoader

Loading system dynamic libraries from non libc static executables.

## Proof of concept

All executable artifacts produced by the included examples are static executables that load dynamic libraries without using libc's `dlopen`.

*Warning: can contain bugs, lots of TODOs remaining.*

See [this thread](https://ziggit.dev/t/dynamic-linking-without-libc-adventures) for further information.

## Usage

For now, the library always follows the latest "master" x86_64 tarball available on [ziglang.org](https://ziglang.org/download/).

```sh
zig fetch --save=dyn_loader https://github.com/TibboddiT/dyn-loader/archive/refs/heads/main.tar.gz
```

```zig
// build.zig

// ...

    const dyn_loader_dep = b.dependency("dyn_loader", .{
        .optimize = optimize,
        // no `target`, because it is always x86_64 linux baseline
    });
    const dyn_loader_mod = dyn_loader_dep.module("dyn_loader");

// then add the module to your executable as usual
```

```zig
const std = @import("std");
const dyn_loader = @import("dyn_loader");

pub const debug = struct {
    pub const SelfInfo = dyn_loader.CustomSelfInfo;
};

pub fn main(init: std.process.Init) !void {
    const args = init.minimal.args;
    const environ = init.minimal.environ;

    // Initialize once, on the initial thread, before any additional threads.
    try dyn_loader.init(.{ .args = args, .environ = environ, .log_level = .err });
    defer dyn_loader.deinit();

    const lib_c = try dyn_loader.loadSystemLibC();

    // or load any other dynamic library:
    // const lib_x11 = try dyn_loader.load("libX11.so.6");

    const printf_sym = try lib_c.getSymbol("printf");
    const printf_addr = printf_sym.addr;
    const printf: *const fn ([*:0]const u8, ...) callconv(.c) c_int = @ptrFromInt(printf_addr);

    _ = printf("Hello, %s!\n", "World");
}
```

## Public API

The loader is process-wide. Its internal allocations use `std.heap.smp_allocator`,
and it owns its `Io.Threaded` I/O backend. Functions returning caller-owned memory take an allocator explicitly.

### Initialization and teardown

```zig
pub fn init(options: InitOptions) !void;
pub fn deinit() void;
```

`init` must run on the initial thread, before creating additional threads or loading libraries.
It establishes the fixed TLS layout. Pointers into executable thread-local variables obtained
before successful initialization become stale.

```zig
pub const InitOptions = struct {
    // Required startup data.
    // Normally init.minimal.args and init.minimal.environ, respectively.
    args: std.process.Args,
    environ: std.process.Environ,

    // Runtime logging level: .debug, .info, .warn, .err, or .none.
    // Host std.log filtering also applies: debug output requires the host's
    // std_options to enable .debug for the dyn_loader log scope.
    log_level: logger.Level = .err,

    // Reserved library TLS bytes, including alignment padding.
    // Fixed at initialization. Defaults to 1 MiB.
    tls_surplus_size: usize = 0x100000,
};
```

Before calling `deinit`, join application-owned managed workers and stop external calls into
loaded libraries. Teardown runs eligible finalizers and frees resources. Libraries marked
NODELETE retain their dependencies and supporting runtime, including the I/O backend.
Repeated `deinit` calls are no-op. Reinitialization after teardown is unsupported.

### Finding and loading libraries

```zig
pub fn resolve(allocator: std.mem.Allocator, name: []const u8) !?[]const u8;
pub fn load(name_or_path: []const u8) !DynamicLibrary;
pub fn loadSystemLibC() !DynamicLibrary;
```

- **`resolve`** searches for a supported ELF library without loading it. It returns `null`
  when no candidate is found. The caller owns the returned path memory.
- **`load`** accepts a library name or path and loads it with its dependencies. Constructors finish
  before it returns. A failed load attempts cleanup.
- **`loadSystemLibC`** loads the first system-libc candidate found. It does not retry another
  ABI if that load fails.

For example, within an initialized loader:

```zig
const libvulkan = try dyn_loader.load("libvulkan.so.1");
```

Or:

```zig
const path = try dyn_loader.resolve(init.gpa, "libvulkan.so.1") orelse return error.VulkanNotFound;
defer init.gpa.free(path);
const libvulkan = try dyn_loader.load(path);
```

`DynamicLibrary` is a handle to a loaded library and its dependency scope. Copies refer to
the same load; copying does not acquire a separate reference. Its `index` field is an internal
registry identifier. There is currently no public per-library unload function.

### Looking up symbols

```zig
// Global scope lookup:
pub fn getSymbol(sym_name: []const u8) !Symbol;

// Local scope lookup:
pub fn getSymbol(lib: DynamicLibrary, sym_name: []const u8) !Symbol;
```

`dyn_loader.getSymbol` searches the global loader scope. `library.getSymbol` searches preload
roots first, then that library and its dependencies.

The result has an `addr: usize` field. To convert the address to the correct native pointer type:

```zig
const lib_c = try dyn_loader.loadSystemLibC();
const symbol = try lib_c.getSymbol("puts");
const puts: *const fn ([*:0]const u8) callconv(.c) c_int = @ptrFromInt(symbol.addr);
_ = puts("Hello from a loaded library");
```

Symbol addresses are not allocations to free. They remain valid only while their
defining mappings remain loaded. TLS symbols identify the calling thread's instance: look
them up separately in each thread and do not retain them past that thread's lifetime.
Library handles become invalid when their objects retire. NODELETE retention can keep
objects and their symbols valid beyond `deinit`.

### Managed threads

```zig
pub fn spawn(
    config: std.Thread.SpawnConfig,
    comptime function: anytype,
    args: anytype,
) !Thread;

// Thread method:
pub fn join(self: Thread) void;
```

Use `dyn_loader.spawn` for Zig workers that call loaded libraries. It establishes both
executable and native-library TLS. A native libc with ready threading support must already
be loaded, and the caller must be the initial thread or another managed worker.

The function must return `void`. Arguments are passed as a tuple and copied by value.

```zig
fn worker(value: usize) void {
    std.debug.print("worker value: {d}\n", .{value});
}

fn runWorker() !void {
    const thread = try dyn_loader.spawn(.{}, worker, .{@as(usize, 42)});
    thread.join();
}
```

`Thread` represents one join obligation. Copies share that obligation: join exactly once.
Its `index` and `native_handle` fields are internal identifiers. Invalid, duplicate, stale,
or self-joins panic. Detachment is unsupported. Failed startup reclaims the failed child
and its resources before returning an error.

### Debug information

`CustomSelfInfo` integrates loaded-library symbols and unwind information with Zig's debug
facilities. Enable it in the executable's root source file:

```zig
pub const debug = struct {
    pub const SelfInfo = dyn_loader.CustomSelfInfo;
};
```


## Current known limitations

- Initialization requires the initial thread to be the only thread. `/proc/self/task` must be accessible.
- Ordinary `std.Thread.spawn` workers must not interact with the loader. Use `dyn_loader.spawn` for workers that call loaded libraries.
- Dirty tricks are used to manually initialize the supported libc (glibc and musl).
- Some libc functions that need to be implemented in Zig are not yet implemented.

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
    - dl, malloc, and thread functions are "redirected" to Zig code
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

The following example will only work on glibc-based systems (because it uses provided libraries compiled against glibc):

```sh
zig build run-raylib
```

## Test matrix

Note: *Not all tests pass yet*

Tested environments:

| OS                                 | libc                       | Toolchain         |
| ---                                | ---                        | ---               |
| Debian 11 (bullseye)               | glibc 2.31                 | GCC 10.2.1        |
| Ubuntu 22.04 (jammy)               | glibc 2.35                 | GCC 11.4.0        |
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
