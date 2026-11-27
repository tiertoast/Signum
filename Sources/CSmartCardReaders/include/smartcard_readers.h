#ifndef SIGNUM_SMARTCARD_READERS_H
#define SIGNUM_SMARTCARD_READERS_H
#include <stddef.h>

/* Public PC/SC observation only: reader names and card presence. No card is
 * connected to, no APDU is sent and no vendor code is loaded. */
enum {
    SG_READER_EMPTY = 0,     /* reader present, no card */
    SG_READER_PRESENT = 1,   /* card present and answering */
    SG_READER_MUTE = 2,      /* card present but not answering */
    SG_READER_UNKNOWN = 3
};
enum {
    SG_READERS_OK = 0,
    SG_READERS_NO_SERVICE = 1, /* the smart card service is not available */
    SG_READERS_ERROR = 2
};
typedef struct { char name[128]; int state; } SGReader;

/* Fills up to `capacity` readers; `*count` is how many were written. */
int sg_readers(SGReader *out, size_t capacity, size_t *count);
#endif
