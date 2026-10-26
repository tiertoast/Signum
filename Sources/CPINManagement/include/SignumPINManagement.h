#pragma once
#include <stddef.h>
#include <stdint.h>
#include "SignumSecurePIN.h"
#ifdef __cplusplus
extern "C" {
#endif
enum { SG_PIN_CHANGE = 1, SG_PIN_UNBLOCK = 2 };
enum { SG_PIN_PREPARED, SG_PIN_APPROVED, SG_PIN_READY, SG_PIN_DISPATCHED,
       SG_PIN_SUCCEEDED, SG_PIN_REJECTED, SG_PIN_UNCERTAIN, SG_PIN_NOT_EXECUTED };
enum { SG_PIN_SOURCE = 0, SG_PIN_NEW = 1, SG_PIN_CONFIRMATION = 2 };
typedef struct SGPINAttempt SGPINAttempt;
typedef struct SGPINSecrets SGPINSecrets;
/* Single owner, no concurrent calls. Binding includes provider identity, token,
 * domain, profile and discovery generation; never a signing certificate route.
 * These transitions grant no hardware capability. Real dispatch always refuses. */
SGPINAttempt *sg_pin_attempt_create(const uint8_t request[16], const uint8_t binding[32], int action);
void sg_pin_attempt_destroy(SGPINAttempt *);
int sg_pin_attempt_approve(SGPINAttempt *, const uint8_t request[16], const uint8_t binding[32], int action);
int sg_pin_attempt_ready(SGPINAttempt *, int context_verified, int complete, int unique, int workflow_locked);
int sg_pin_attempt_mark_dispatched(SGPINAttempt *);
void sg_pin_attempt_finish(SGPINAttempt *, int command_succeeded, int cleanup_succeeded);
void sg_pin_attempt_abort(SGPINAttempt *);
int sg_pin_attempt_state(const SGPINAttempt *);
int sg_pin_attempt_cleanup_failed(const SGPINAttempt *);
int sg_pin_attempt_may_have_dispatched(const SGPINAttempt *);
SGPINSecrets *sg_pin_secrets_create(void);
void sg_pin_secrets_clear(SGPINSecrets *);
void sg_pin_secrets_destroy(SGPINSecrets *);
int sg_pin_secrets_set(SGPINSecrets *, int field, const uint8_t *, size_t);
int sg_pin_secrets_validate_local(SGPINSecrets *, size_t minimum, size_t maximum);
/* Version 1: 56 public bytes: SPIN, version, action, two zero bytes,
 * request UUID (16), context digest (32). Then two network-order length-prefixed
 * secret frames (1..64 bytes each). Entire receive <=5 seconds. No Data/JSON.
 * Used only by the test harness in 12A. Real worker never requests/reads secrets. */
int sg_pin_secrets_receive(SGPINSecrets *, int fd, const uint8_t request[16], const uint8_t binding[32], int action);
/* No module path, function table or callback accepted. No real backend linked. */
int sg_pin_real_dispatch(SGPINAttempt *, SGPINSecrets *);
#ifdef SIGNUM_PIN_ADMIN_TESTING
/* Test binary only, never emitted by SwiftPM/product target. */
const uint8_t *sg_pin_test_secret_bytes(const SGPINSecrets *, int field);
size_t sg_pin_test_secret_length(const SGPINSecrets *, int field);
#endif
#ifdef __cplusplus
}
#endif
