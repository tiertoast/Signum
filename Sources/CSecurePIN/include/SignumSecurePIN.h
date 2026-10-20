#ifndef SIGNUM_SECURE_PIN_H
#define SIGNUM_SECURE_PIN_H
#include <stddef.h>
#include <stdint.h>
typedef struct SGSecurePIN SGSecurePIN;
/* Single owner in the worker. Creation fails closed if locking fails.
 * Borrowed bytes remain valid only until clear/destroy; never log or serialize. */
SGSecurePIN *sg_secure_pin_create(void);
int sg_secure_pin_set(SGSecurePIN *, const uint8_t *, size_t);
int sg_secure_pin_receive(SGSecurePIN *, int fd, double timeout_seconds);
const uint8_t *sg_secure_pin_bytes(const SGSecurePIN *);
size_t sg_secure_pin_length(const SGSecurePIN *);
void sg_secure_pin_clear(SGSecurePIN *);
void sg_secure_pin_destroy(SGSecurePIN *);
#endif
