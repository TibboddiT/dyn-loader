#include "probe_api.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Thread_local uint32_t host_tls = 17;
struct CallbackContext { unsigned calls; };

static uint32_t hostCallback(void *argument, uint32_t value) {
    struct CallbackContext *context = argument;
    ++context->calls;
    if (host_tls != 17) return 0;
    host_tls = 99;
    return value + 1;
}

static void printJsonString(const char *value) {
    putchar('"');
    for (const unsigned char *byte = (const unsigned char *)value; *byte; ++byte) {
        if (*byte == '"' || *byte == '\\') {
            putchar('\\');
            putchar(*byte);
        } else if (*byte < 32) {
            printf("\\u%04x", *byte);
        } else {
            putchar(*byte);
        }
    }
    putchar('"');
}
static void emitStage(const char *name) {
    printf("{\"event\":\"stage\",\"stage\":\"%s\"}\n", name);
    fflush(stdout);
}
static void fail(const char *name, const char *message) {
    printf("{\"event\":\"error\",\"stage\":\"%s\",\"message\":", name);
    printJsonString(message);
    puts("}");
    fflush(stdout);
    _exit(2);
}

#define RESOLVE(type, name) \
    type name = (type)dlsym(library, #name); \
    if (!(name)) fail("abi", "missing " #name)

int main(int argc, char **argv) {
    if (argc != 3) fail("arguments", "usage: reference LIBRARY --list|CASE_ID");
    host_tls = 41;
    emitStage("load");
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) fail("load", dlerror());
    emitStage("abi");
    typedef uint32_t (*ReadU32)(void);
    typedef int (*DescribeCase)(uint32_t, struct probe_case_info *);
    typedef int (*RunCase)(uint32_t, const struct probe_host_api *, struct probe_result *);
    RESOLVE(ReadU32, probe_abi_version);
    RESOLVE(ReadU32, probe_case_count);
    RESOLVE(ReadU32, probe_result_size);
    RESOLVE(ReadU32, probe_case_info_size);
    RESOLVE(ReadU32, probe_host_api_size);
    RESOLVE(DescribeCase, probe_describe);
    RESOLVE(RunCase, probe_run);
    if (probe_abi_version() != PROBE_ABI_VERSION || probe_result_size() != sizeof(struct probe_result) ||
        probe_case_info_size() != sizeof(struct probe_case_info) || probe_host_api_size() != sizeof(struct probe_host_api)) {
        fail("abi", "ABI layout/version mismatch");
    }
    uint32_t case_count = probe_case_count();
    if (strcmp(argv[2], "--list") == 0) {
        FILE *maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char buffer[4096];
            size_t bytes_read;
            fputs("Loaded object mappings:\n", stderr);
            while ((bytes_read = fread(buffer, 1, sizeof buffer, maps)) != 0) {
                fwrite(buffer, 1, bytes_read, stderr);
            }
            fclose(maps);
            fflush(stderr);
        }
        for (uint32_t case_index = 0; case_index < case_count; ++case_index) {
            struct probe_case_info info = {.struct_size = sizeof info};
            if (probe_describe(case_index, &info) != 0) fail("abi", "describe failed");
            printf("{\"event\":\"case\",\"id\":%u,\"name\":", info.id);
            printJsonString(info.name);
            puts("}");
        }
        printf("{\"event\":\"ready\",\"count\":%u}\n", case_count);
        fflush(stdout);
        _exit(0);
    }
    char *parse_end;
    unsigned long case_id = strtoul(argv[2], &parse_end, 10);
    if (!argv[2][0] || *parse_end || case_id >= case_count) fail("arguments", "invalid case ID");
    struct CallbackContext context = {0};
    struct probe_host_api host = {
        .abi_version = PROBE_ABI_VERSION,
        .struct_size = sizeof host,
        .callback = hostCallback,
        .context = &context,
    };
    struct probe_result result = {.struct_size = sizeof result};
    emitStage("run");
    if (probe_run((uint32_t)case_id, &host, &result) != 0) fail("abi", "probe_run failed");
    const unsigned long host_callback_case_id = 10;
    if (host_tls != 41 || (case_id == host_callback_case_id && context.calls != 1)) {
        fail("run", "host TLS/callback validation failed");
    }
    printf("{\"event\":\"result\",\"id\":%lu,\"status\":%u,\"line\":%u,\"saved_errno\":%d,"
           "\"expected\":%lld,\"observed\":%lld,\"detail\":", case_id, result.status, result.line, result.saved_errno,
           (long long)result.expected, (long long)result.observed);
    printJsonString(result.detail);
    puts("}");
    fflush(stdout);
    /* A failed test may leave worker threads running.
       The process exits without unloading the library. */
    _exit(result.status == PROBE_FAIL ? 1 : 0);
}
