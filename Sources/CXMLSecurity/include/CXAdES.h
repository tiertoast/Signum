#ifndef SIGNUM_XADES_H
#define SIGNUM_XADES_H
#include <stddef.h>
/* Fixed, bounded enveloped XAdES-B profile. No private keys, network or trust decisions. */
typedef struct {
    unsigned char *document, *signed_info, *certificate, *signature;
    size_t document_size, signed_info_size, certificate_size, signature_size;
    char signing_time[32], error[256];
} signum_xades_result;
int signum_xml_initialize(void);
int signum_xades_input(const unsigned char *, size_t, signum_xades_result *);
int signum_xades_prepare(const unsigned char *, size_t, const unsigned char *, size_t, const char *, signum_xades_result *);
int signum_xades_finish(const unsigned char *, size_t, const unsigned char *, size_t, signum_xades_result *);
/* Verify: 1 valid; -1 cryptographic/binding failure; 0 unsupported/unsafe structure. */
int signum_xades_verify(const unsigned char *, size_t, signum_xades_result *);
void signum_xades_dispose(signum_xades_result *);
#endif
