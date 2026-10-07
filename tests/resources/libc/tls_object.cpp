#include "tls_object.h"
#include <cstdio>
#include <cstdlib>

namespace {
class Tracked {
    tls_object_events *events;
    unsigned value;
    unsigned ordinal;
public:
    Tracked(tls_object_events *events, unsigned value, unsigned ordinal)
        : events(events), value(value), ordinal(ordinal) {
        ++events->constructed;
    }
    ~Tracked() {
        ++events->destroyed;
        events->destruction_order = events->destruction_order * 10 + ordinal;
        events->value_sum += value;
    }
};

tls_object_events process_events = {};
unsigned process_case;

void checkProcessExit() {
    const bool passed = process_events.constructed == 2 &&
        process_events.destroyed == 2 && process_events.destruction_order == 21 &&
        process_events.value_sum == 46;
    std::printf("{\"event\":\"result\",\"id\":%u,\"status\":%u,"
                "\"expected\":2,\"observed\":%u,"
                "\"detail\":\"main-thread C++ TLS destruction at normal exit\"}\n",
                process_case, passed ? 0u : 1u, process_events.destroyed);
    std::fflush(stdout);
    if (!passed) std::_Exit(1);
}
}

extern "C" void touchTlsObjects(tls_object_events *events, unsigned value) {
    static thread_local Tracked first(events, value, 1);
    static thread_local Tracked second(events, value, 2);
}

extern "C" void prepareTlsProcessExit(unsigned case_id) {
    process_case = case_id;
    if (std::atexit(checkProcessExit) != 0) std::abort();
    touchTlsObjects(&process_events, 23);
}
