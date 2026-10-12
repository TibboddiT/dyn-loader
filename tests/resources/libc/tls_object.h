#ifndef DYNLOADER_TLS_OBJECT_H
#define DYNLOADER_TLS_OBJECT_H

/* Caller-owned observation storage must outlive the thread's TLS destructors.
 * `destruction_order` appends each object's ordinal as a decimal digit. */
struct tls_object_events {
    unsigned constructed;
    unsigned destroyed;
    unsigned destruction_order;
    unsigned value_sum;
};

#ifdef __cplusplus
extern "C" {
#endif
void touchTlsObjects(struct tls_object_events *events, unsigned value);
/* This case emits its result at normal process exit, after main-thread TLS cleanup. */
void prepareTlsProcessExit(unsigned case_id);
#ifdef __cplusplus
}
#endif
#endif
