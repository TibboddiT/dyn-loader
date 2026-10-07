#ifndef DYNLOADER_PROBE_API_H
#define DYNLOADER_PROBE_API_H
#include <stdint.h>

#define PROBE_ABI_VERSION 1u
enum { PROBE_PASS = 0, PROBE_FAIL = 1, PROBE_UNAVAILABLE = 2 };

struct probe_host_api {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t (*callback)(void *context, uint32_t value);
    void *context;
};

struct probe_case_info {
    uint32_t struct_size;
    uint32_t id;
    char name[64];
};

struct probe_result {
    uint32_t struct_size;
    uint32_t status;
    uint32_t line;
    int32_t saved_errno;
    int64_t expected;
    int64_t observed;
    char detail[192];
};

uint32_t probe_abi_version(void);
uint32_t probe_case_count(void);
uint32_t probe_result_size(void);
uint32_t probe_case_info_size(void);
uint32_t probe_host_api_size(void);
int probe_describe(uint32_t index, struct probe_case_info *out);
int probe_run(uint32_t id, const struct probe_host_api *host, struct probe_result *out);
#endif
