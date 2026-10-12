#ifndef SIGNUM_PKCS11_H
#define SIGNUM_PKCS11_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct SGContext SGContext;
typedef struct { unsigned long slot; char label[33]; char manufacturer[33]; char model[17]; char reader[65]; } SGToken;
typedef struct { char label[129]; uint8_t id[64]; size_t id_length; } SGCertificate;
int sg_open(const char *path, SGContext **out, char *error, size_t error_size);
void sg_close(SGContext *context);
// A token may be temporarily unrecognized during card/reader initialization.
// Ignore known transient slot failures and report the number skipped.
int sg_tokens(SGContext *context, SGToken *out, size_t capacity,
              size_t *count, size_t *unavailable, char *error, size_t error_size);
int sg_certificates(SGContext *context, unsigned long slot, SGCertificate *out,
                    size_t capacity, size_t *count, char *error, size_t error_size);
// To read a DER certificate, call once with out=NULL and capacity=0, then again with a buffer.
int sg_certificate_der(SGContext *context, unsigned long slot, const uint8_t *id,
                       size_t id_length, uint8_t *out, size_t capacity,
                       size_t *length, char *error, size_t error_size);
// Signs full message using CKM_SHA256_RSA_PKCS; output buffer >=8192 bytes.
// This is a cryptographic test, NOT a PAdES/CAdES signing API.
int sg_sign_test(SGContext *context, unsigned long slot, const uint8_t *id,
                 size_t id_length, const uint8_t *pin, size_t pin_length,
                 const uint8_t *message, size_t message_length,
                 uint8_t *signature, size_t signature_capacity,
                 size_t *signature_length, char *error, size_t error_size);
#ifdef __cplusplus
}
#endif
#endif
