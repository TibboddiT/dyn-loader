#ifndef DYNLOADER_TLS_OBJECT_H
#define DYNLOADER_TLS_OBJECT_H

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
void prepareTlsProcessExit(unsigned case_id);
#ifdef __cplusplus
}
#endif
#endif
