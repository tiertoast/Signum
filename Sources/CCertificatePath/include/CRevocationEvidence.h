#ifndef SIGNUM_REVOCATION_EVIDENCE_H
#define SIGNUM_REVOCATION_EVIDENCE_H
#include <stdint.h>
#include <stddef.h>
// Pair-level evidence checks only: the caller must authenticate the certificate
// path separately. No default trust store, filesystem or network access.
// kind: 1 OCSP DER, 2 full direct CRL DER.
// result: 1 good, 2 revoked, 0 unknown/unsupported, -1 invalid, -2 stale.
// Dates are Unix seconds, zero if unavailable. Evaluation is at current time;
// this API does not establish historical proof of existence.
int signum_revocation_evidence(int kind,
    const uint8_t *certificate, size_t certificate_size,
    const uint8_t *issuer, size_t issuer_size,
    const uint8_t *evidence, size_t evidence_size, int64_t now,
    int64_t *this_update, int64_t *next_update, int64_t *revocation_time,
    char *reason, size_t reason_size);
// RFC 3161 token (ContentInfo, not TimeStampResp) and exact signature bytes.
// The explicit anchor is a caller-selected TSA identity, not a system root.
// 1 = signature, ESS binding, imprint and TSA path verified at genTime;
// does not establish TSA revocation, TL authorization, historical POE, or QES.
int signum_timestamp_token(const uint8_t *token, size_t token_size,
    const uint8_t *data, size_t data_size,
    const uint8_t *anchor, size_t anchor_size, int64_t observed_at,
    int64_t *generated_at, char *reason, size_t reason_size);
// Untrusted token metadata and imprint match, not TSA authorization.
int signum_timestamp_inspect(const uint8_t *token, size_t token_size,
    const uint8_t *value, size_t value_size, int64_t *time, int64_t *accuracy_microseconds,
    uint8_t *certificates, size_t capacity, size_t *used);
int signum_certificate_issued_by(const uint8_t *cert, size_t size, const uint8_t *issuer, size_t issuer_size);
int signum_revocation_locations(const uint8_t *cert, size_t size, char *locations, size_t capacity);
int signum_ocsp_request(const uint8_t *cert, size_t size, const uint8_t *issuer, size_t issuer_size,
    uint8_t *out, size_t capacity, size_t *used);
int signum_revocation_targets(int kind, const uint8_t *evidence, size_t evidence_size,
    const uint8_t *cert, size_t cert_size, const uint8_t *issuer, size_t issuer_size);
#endif
