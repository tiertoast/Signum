#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* One offline policy implementation, linked by SignumCore and the PAdES helper.
 * No trust evaluation, keychain access, network, PIN or private-key operation. */
enum { SG_CERT_ELIGIBLE, SG_CERT_INELIGIBLE, SG_CERT_INDETERMINATE };
enum {
    SG_CERT_MALFORMED = 1u << 0, SG_CERT_EXPIRED = 1u << 1,
    SG_CERT_FUTURE = 1u << 2, SG_CERT_KEY_USAGE = 1u << 3,
    SG_CERT_MISSING_KEY_USAGE = 1u << 4, SG_CERT_EKU = 1u << 5,
    SG_CERT_UNKNOWN_EKU = 1u << 6, SG_CERT_KEY_ALGORITHM = 1u << 7,
    SG_CERT_KEY_SIZE = 1u << 8, SG_CERT_CRITICAL_EXTENSION = 1u << 9,
    SG_CERT_CA = 1u << 10, SG_CERT_CLOCK = 1u << 11
};
typedef struct {
    int status;
    uint32_t reasons;
    double not_before, not_after; /* Unix seconds; zero on malformed input. */
    int key_usage_present, digital_signature, content_commitment;
    int eku_present, document_signing, any_extended_key_usage;
    int client_authentication; /* Informational only; does not change eligibility. */
    int public_key_bits;
} SGCertificateAssessment;
SGCertificateAssessment sg_certificate_assess(const uint8_t *der, size_t length, double unix_time);
const char *sg_certificate_reason_message(uint32_t reason);
/* Current system clock. Inject an explicit date into assess() for deterministic tests. */
double sg_certificate_now(void);
#ifdef __cplusplus
}
#endif
