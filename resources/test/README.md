# Test libraries

## Reproduction

Tested with:

- zig `0.17.0-dev.2338+b46a7f3a2`.
- gcc `16.2.0` (debian `16.2.0-3`).
- GNU binutils `2.47`.
- A glibc host.

### Build commands

```sh
work="$(mktemp -d)"
# save target.zig, bridge.zig, dependency.c, relr.c, plt_only.c, relative_addends.c into "$work".

zig build-lib "$work/target.zig" -dynamic -lc -target x86_64-linux-gnu -mcpu baseline -O ReleaseFast -fno-llvm -fno-lld -fsoname=target.so -femit-bin="$work/target.so"
zig build-lib "$work/target.zig" -dynamic -lc -target x86_64-linux-gnu -mcpu baseline -O ReleaseFast -fllvm -flld -fsoname=target_llvm.so -femit-bin="$work/target_llvm.so"
zig build-lib "$work/target.zig" -dynamic -lc -target x86_64-linux-gnu -mcpu baseline -O Debug -fno-llvm -fno-lld -fsoname=target_zig_debug.so -femit-bin="$work/target_zig_debug.so"
zig build-lib "$work/bridge.zig" -dynamic -lc -target x86_64-linux-gnu -mcpu baseline -O ReleaseFast -fno-llvm -fno-lld -fsoname=bridge.so -femit-bin="$work/bridge.so"

cc -shared -fPIC -O0 "$work/relr.c" -Wl,-z,pack-relative-relocs -Wl,-soname,relr.so -o "$work/relr.so"
cc -nostdlib -shared -fPIC -O0 "$work/plt_only.c" -lc -Wl,-soname,plt_only.so -o "$work/plt_only.so"
cc -shared -fPIC -O0 "$work/relative_addends.c" -Wl,-soname,relative_addends.so -o "$work/relative_addends.so"
cc -nostdlib -shared -fPIC -O0 "$work/dependency.c" "$work/target.so" -Wl,-soname,dependency.so '-Wl,-rpath,$ORIGIN' -o "$work/dependency.so"
```

## Sources

### target.zig

```zig
var initialized: u32 = 7;
var zeroed: u32 = 0;
threadlocal var tls_value: u32 = 11;
var constructor_count: u32 = 0;
var events: ?*[4]u32 = null;

extern "c" fn __cxa_thread_atexit_impl(function: *const fn (?*anyopaque) callconv(.c) void, argument: ?*anyopaque, dso: ?*anyopaque) c_int;
extern var __dso_handle: u8;

fn initialize() callconv(.c) void {
    constructor_count += 1;
}

fn finalize() callconv(.c) void {
    if (events) |out| {
        out[0] += 1;
        out[1] = initialized;
        out[2] = zeroed;
        out[3] = tls_value;
    }
}

export const constructors: [1]*const fn () callconv(.c) void linksection(".init_array") = .{&initialize};
export const finalizers: [1]*const fn () callconv(.c) void linksection(".fini_array") = .{&finalize};

export fn readState(out: *[4]u32) void {
    out.* = .{ initialized, zeroed, tls_value, constructor_count };
}

export fn mutate(out: *[4]u32) void {
    events = out;
    initialized = 42;
    zeroed = 99;
    tls_value = 55;
}

export fn setTls(value: u32) void {
    tls_value = value;
}

fn tlsDestructor(argument: ?*anyopaque) callconv(.c) void {
    const out: *[2]u32 = @ptrCast(@alignCast(argument.?));
    out[0] += 1;
    out[1] = tls_value;
}

export fn registerTlsCallback(out: *[2]u32) c_int {
    return __cxa_thread_atexit_impl(&tlsDestructor, out, &__dso_handle);
}
```

### bridge.zig

```zig
extern "c" fn dlopen(path: [*:0]const u8, flags: c_int) ?*anyopaque;
extern "c" fn dlsym(handle: *anyopaque, name: [*:0]const u8) ?*anyopaque;
extern "c" fn dlclose(handle: *anyopaque) c_int;
extern "c" fn pthread_create(thread: *usize, attributes: ?*anyopaque, routine: *const fn (?*anyopaque) callconv(.c) *anyopaque, argument: ?*anyopaque) c_int;
extern "c" fn pthread_join(thread: usize, result: ?**anyopaque) c_int;

export fn openProbe(path: [*:0]const u8) ?*anyopaque {
    return dlopen(path, 2); // RTLD_NOW
}

export fn openGlobalProbe(path: [*:0]const u8) ?*anyopaque {
    return dlopen(path, 0x102); // RTLD_NOW | RTLD_GLOBAL
}

export fn symbolProbe(handle: *anyopaque, name: [*:0]const u8) ?*anyopaque {
    return dlsym(handle, name);
}

export fn closeProbe(handle: *anyopaque) c_int {
    return dlclose(handle);
}

export fn startProbe(thread: *usize, routine: *const fn (?*anyopaque) callconv(.c) *anyopaque, argument: ?*anyopaque) c_int {
    return pthread_create(thread, null, routine, argument);
}

export fn joinProbe(thread: usize) c_int {
    return pthread_join(thread, null);
}
```

### dependency.c

```c
#include <stdint.h>

extern void readState(uint32_t *);
static uint32_t *observed;
static uint32_t *provider_events;

void readBoundState(uint32_t *out) {
    readState(out);
}

void observeFinalization(uint32_t *out, uint32_t *events) {
    observed = out;
    provider_events = events;
}

__attribute__((destructor)) static void finalize(void) {
    if (observed) *observed = provider_events[0];
}
```

### relr.c

```c
static int state = 21;
static int *pointers[] = { &state, &state, &state, &state };

int answer(void) {
    return *pointers[0] + *pointers[3];
}
```

### plt_only.c

```c
extern int puts(const char *);

int answer(void) {
    return puts("") >= 0 ? 42 : 0;
}
```

### relative_addends.c

```c
#include <stdint.h>

static int state = 21;
void *relative_slot = &state;
extern const char __ehdr_start[];

int check_zero(void) {
    return (uintptr_t)relative_slot == (uintptr_t)__ehdr_start ? 42 : 0;
}

int check_negative(void) {
    return (uintptr_t)relative_slot == (uintptr_t)__ehdr_start - 8 ? 42 : 0;
}
```
