#ifndef SIGNUM_SECURE_PIN_H
#define SIGNUM_SECURE_PIN_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct SGSecurePIN SGSecurePIN;
/* Single owner in the worker. Creation fails closed if locking fails.
 * Borrowed bytes remain valid only until clear/destroy; never log or serialize. */
SGSecurePIN *sg_secure_pin_create(void);
int sg_secure_pin_set(SGSecurePIN *, const uint8_t *, size_t);
int sg_secure_pin_receive(SGSecurePIN *, int fd, double timeout_seconds);
const uint8_t *sg_secure_pin_bytes(const SGSecurePIN *);
size_t sg_secure_pin_length(const SGSecurePIN *);
/* Terminal-only: explicit final LF (Ctrl-J), 1..64 strict UTF-8 bytes.
 * No CR mapping, trimming, NUL truncation or UTF-8 repair. Ctrl-C/D cancel.
 * Restores terminal state on every controlled return; clears storage on failure. */
int sg_secure_pin_read_terminal(SGSecurePIN *, double timeout_seconds);
void sg_secure_pin_clear(SGSecurePIN *);
void sg_secure_pin_destroy(SGSecurePIN *);
#ifdef __cplusplus
}
#endif
#endif
