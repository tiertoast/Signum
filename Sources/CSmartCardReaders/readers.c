#include "smartcard_readers.h"
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <stdlib.h>
#include <string.h>

#define SG_MAX_READERS 16

int sg_readers(SGReader *out, size_t capacity, size_t *count) {
    if (!count) return SG_READERS_ERROR;
    *count = 0;
    if (!out && capacity) return SG_READERS_ERROR;
    SCARDCONTEXT context = 0;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &context);
    if (rv == SCARD_E_NO_SERVICE) return SG_READERS_NO_SERVICE;
    if (rv != SCARD_S_SUCCESS) return SG_READERS_ERROR;

    uint32_t length = 0;
    rv = SCardListReaders(context, NULL, NULL, &length);
    if (rv == SCARD_E_NO_READERS_AVAILABLE) { SCardReleaseContext(context); return SG_READERS_OK; }
    if (rv != SCARD_S_SUCCESS || length == 0 || length > 64 * 1024) { SCardReleaseContext(context); return SG_READERS_ERROR; }
    char *names = calloc(length + 1, 1);
    if (!names) { SCardReleaseContext(context); return SG_READERS_ERROR; }
    rv = SCardListReaders(context, NULL, names, &length);
    if (rv == SCARD_E_NO_READERS_AVAILABLE) { free(names); SCardReleaseContext(context); return SG_READERS_OK; }
    if (rv != SCARD_S_SUCCESS) { free(names); SCardReleaseContext(context); return SG_READERS_ERROR; }
    names[length] = '\0';

    SCARD_READERSTATE states[SG_MAX_READERS];
    memset(states, 0, sizeof states);
    size_t found = 0;
    for (char *name = names; *name && name < names + length && found < SG_MAX_READERS; name += strlen(name) + 1) {
        states[found].szReader = name;
        states[found].dwCurrentState = SCARD_STATE_UNAWARE;
        ++found;
    }
    /* Timeout 0: report the current state without waiting for a change. */
    rv = found ? SCardGetStatusChange(context, 0, states, (uint32_t)found) : SCARD_S_SUCCESS;
    int known = rv == SCARD_S_SUCCESS || rv == SCARD_E_TIMEOUT;
    size_t written = 0;
    for (size_t i = 0; i < found && written < capacity; ++i) {
        SGReader *reader = &out[written++];
        memset(reader, 0, sizeof *reader);
        strncpy(reader->name, states[i].szReader, sizeof reader->name - 1);
        uint32_t event = states[i].dwEventState;
        if (!known || (event & (SCARD_STATE_UNAVAILABLE | SCARD_STATE_UNKNOWN))) reader->state = SG_READER_UNKNOWN;
        else if (event & SCARD_STATE_MUTE) reader->state = SG_READER_MUTE;
        else if (event & SCARD_STATE_PRESENT) reader->state = SG_READER_PRESENT;
        else if (event & SCARD_STATE_EMPTY) reader->state = SG_READER_EMPTY;
        else reader->state = SG_READER_UNKNOWN;
    }
    *count = written;
    free(names);
    SCardReleaseContext(context);
    return SG_READERS_OK;
}
