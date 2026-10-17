#include "SignumCertificatePolicy.h"
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <math.h>
#include <string.h>
#include <time.h>

/* Bounded DER field reader. Security.framework imports the certificate/key;
 * DER is used for non-localized usage OIDs and strict RFC 5280 time semantics.
 * This is not a chain/path validator or a general ASN.1 implementation. */
typedef struct { const uint8_t *p; size_t n; } Slice;
typedef struct { unsigned tag; Slice value; } Node;
static int take(Slice *s, Node *out) {
    if (s->n < 2) return 0;
    unsigned tag = s->p[0], first = s->p[1]; size_t head = 2, n = first;
    if ((tag & 31) == 31) return 0;
    if (first & 128) {
        unsigned count = first & 127;
        if (!count || count > 4 || count > s->n - head || !s->p[head]) return 0;
        n = 0;
        for (unsigned i = 0; i < count; ++i) n = (n << 8) | s->p[head++];
        if (n < 128) return 0;
    }
    if (n > s->n - head) return 0;
    *out = (Node){tag, {s->p + head, n}};
    s->p += head + n; s->n -= head + n; return 1;
}
static int field(Slice *s, unsigned tag, Slice *out) {
    Node node; if (!take(s, &node) || node.tag != tag) return 0;
    *out = node.value; return 1;
}
static int same(Slice a, const uint8_t *p, size_t n) { return a.n == n && !memcmp(a.p, p, n); }
#define OID(s, ...) same((s), (const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))
static int oid_valid(Slice s) {
    if (!s.n || s.n > 128) return 0;
    for (size_t i = 0; i < s.n; ++i) {
        if (s.p[i] == 128) return 0; /* non-minimal component */
        while (s.p[i] & 128) if (++i == s.n) return 0;
    }
    return 1;
}
static int number(const uint8_t *p, size_t n) {
    int value = 0;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] < '0' || p[i] > '9') return -1;
        value = value * 10 + p[i] - '0';
    }
    return value;
}
static int date(Node node, double *out) {
    size_t year_digits = node.tag == 0x17 ? 2 : node.tag == 0x18 ? 4 : 0;
    if (!year_digits || node.value.n != year_digits + 11 || node.value.p[node.value.n - 1] != 'Z') return 0;
    const uint8_t *p = node.value.p;
    int y = number(p, year_digits); if (y < 0) return 0;
    if (year_digits == 2) y += y >= 50 ? 1900 : 2000;
    else if (y < 2050) return 0; /* RFC 5280 uses UTCTime through 2049. */
    int m = number(p + year_digits, 2), d = number(p + year_digits + 2, 2);
    int h = number(p + year_digits + 4, 2), min = number(p + year_digits + 6, 2);
    int sec = number(p + year_digits + 8, 2);
    if (m < 1 || m > 12 || d < 1 || d > 31 || h < 0 || h > 23 || min < 0 || min > 59 || sec < 0 || sec > 59) return 0;
    struct tm tm = {0}; tm.tm_year = y - 1900; tm.tm_mon = m - 1; tm.tm_mday = d;
    tm.tm_hour = h; tm.tm_min = min; tm.tm_sec = sec;
    time_t result = timegm(&tm); struct tm check;
    if (!gmtime_r(&result, &check) || check.tm_year != y - 1900 || check.tm_mon != m - 1 || check.tm_mday != d) return 0;
    *out = (double)result; return 1;
}
static int bits(Slice s) {
    if (s.n < 2 || s.p[0] > 7) return 0;
    unsigned unused = s.p[0];
    return !(s.p[s.n - 1] & ((1u << unused) - 1));
}
static int extensions(Slice list, SGCertificateAssessment *r) {
    Slice seen[128]; size_t count = 0;
    while (list.n) {
        Slice ext, oid, value; Node node;
        if (count == 128 || !field(&list, 0x30, &ext) || !field(&ext, 6, &oid) || !oid_valid(oid)) return 0;
        for (size_t i = 0; i < count; ++i) if (same(oid, seen[i].p, seen[i].n)) return 0;
        seen[count++] = oid;
        int critical = 0;
        if (ext.n && ext.p[0] == 1) {
            Slice boolean;
            if (!field(&ext, 1, &boolean) || boolean.n != 1 || boolean.p[0] != 255) return 0;
            critical = 1; /* DEFAULT FALSE must be omitted in DER. */
        }
        if (!field(&ext, 4, &value) || ext.n) return 0;
        /* extnValue is opaque for unknown OIDs. Validate its outer OCTET STRING,
         * OID and uniqueness, without requiring the private syntax to fit take().
         * Unsupported critical semantics still block signing as indeterminate. */
        if (!OID(oid, 0x55,0x1d,0x0f) && !OID(oid, 0x55,0x1d,0x25) && !OID(oid, 0x55,0x1d,0x13)) {
            if (critical) r->reasons |= SG_CERT_CRITICAL_EXTENSION;
            continue;
        }
        if (!take(&value, &node) || value.n) return 0;
        Slice inner = node.value;
        if (OID(oid, 0x55,0x1d,0x0f)) {
            if (node.tag != 3 || !bits(inner) || inner.n > 3 || !inner.p[inner.n - 1]) return 0;
            /* KeyUsage is a named bit string: no unknown bits or trailing zero bits. */
            unsigned trailing = 0, last = inner.p[inner.n - 1];
            while (!(last & 1)) { ++trailing; last >>= 1; }
            if (inner.p[0] != trailing || (inner.n == 3 && (inner.p[2] != 128 || inner.p[0] != 7))) return 0;
            r->key_usage_present = 1;
            r->digital_signature = !!(inner.p[1] & 128); r->content_commitment = !!(inner.p[1] & 64);
            if (!r->digital_signature && !r->content_commitment) r->reasons |= SG_CERT_KEY_USAGE;
        } else if (OID(oid, 0x55,0x1d,0x25)) {
            if (node.tag != 0x30 || !inner.n) return 0;
            r->eku_present = 1; int unknown = 0;
            while (inner.n) {
                Slice purpose;
                if (!field(&inner, 6, &purpose) || !oid_valid(purpose)) return 0;
                if (OID(purpose, 0x2b,6,1,5,5,7,3,36)) r->document_signing = 1;
                else if (OID(purpose, 0x55,0x1d,0x25,0)) r->any_extended_key_usage = 1;
                else if (!(purpose.n == 8 && !memcmp(purpose.p, (const uint8_t[]){0x2b,6,1,5,5,7,3}, 7)
                           && (purpose.p[7] >= 1 && purpose.p[7] <= 9))) unknown = 1;
            }
            if (!r->document_signing && !r->any_extended_key_usage)
                r->reasons |= unknown ? SG_CERT_UNKNOWN_EKU : SG_CERT_EKU;
        } else if (OID(oid, 0x55,0x1d,0x13)) {
            if (node.tag != 0x30) return 0;
            int ca = 0;
            if (inner.n && inner.p[0] == 1) {
                Slice boolean;
                if (!field(&inner, 1, &boolean) || boolean.n != 1 || boolean.p[0] != 255) return 0;
                ca = 1;
            }
            if (inner.n) {
                Slice path;
                if (!ca || !field(&inner, 2, &path) || !path.n || (path.p[0] & 128) ||
                    (path.n > 1 && !path.p[0] && !(path.p[1] & 128))) return 0;
            }
            if (inner.n) return 0;
            if (ca) r->reasons |= SG_CERT_CA;
        }
    }
    return count > 0;
}
static int parse(Slice input, SGCertificateAssessment *r) {
    Slice cert, tbs, ignored, validity, spki, alg, oid; Node node;
    if (!field(&input, 0x30, &cert) || input.n || !field(&cert, 0x30, &tbs) ||
        !field(&cert, 0x30, &ignored) || !field(&cert, 3, &ignored) || !bits(ignored) || cert.n) return 0;
    int version = 0;
    if (tbs.n && tbs.p[0] == 0xa0) {
        Slice v, integer;
        if (!field(&tbs, 0xa0, &v) || !field(&v, 2, &integer) || v.n || integer.n != 1 || integer.p[0] < 1 || integer.p[0] > 2) return 0;
        version = integer.p[0];
    }
    if (!field(&tbs, 2, &ignored) || !ignored.n || !field(&tbs, 0x30, &ignored) ||
        !field(&tbs, 0x30, &ignored) || !field(&tbs, 0x30, &validity) ||
        !take(&validity, &node) || !date(node, &r->not_before) ||
        !take(&validity, &node) || !date(node, &r->not_after) || validity.n || r->not_before > r->not_after ||
        !field(&tbs, 0x30, &ignored) || !field(&tbs, 0x30, &spki) ||
        !field(&spki, 0x30, &alg) || !field(&alg, 6, &oid) || !oid_valid(oid) ||
        !field(&spki, 3, &ignored) || !bits(ignored) || spki.n) return 0;
    if (!OID(oid, 0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1)) r->reasons |= SG_CERT_KEY_ALGORITHM;
    else if (alg.n) { /* rsaEncryption accepts NULL or absent parameters only. */
        if (!field(&alg, 5, &ignored) || ignored.n || alg.n) return 0;
    }
    unsigned previous = 0;
    while (tbs.n) {
        if (!take(&tbs, &node)) return 0;
        unsigned order = node.tag == 0x81 ? 1 : node.tag == 0x82 ? 2 : node.tag == 0xa3 ? 3 : 0;
        if (!order || order <= previous || version == 0) return 0;
        previous = order;
        if (order == 3) {
            Slice list;
            if (version != 2 || !field(&node.value, 0x30, &list) || node.value.n || !extensions(list, r)) return 0;
        } else if (!bits(node.value)) return 0;
    }
    return 1;
}

double sg_certificate_now(void) { return CFAbsoluteTimeGetCurrent() + 978307200.0; }
SGCertificateAssessment sg_certificate_assess(const uint8_t *der, size_t length, double now) {
    SGCertificateAssessment r = {0};
    r.status = SG_CERT_INELIGIBLE;
    if (!der || !length || length > 65536 || !parse((Slice){der, length}, &r)) {
        r.reasons = SG_CERT_MALFORMED; return r;
    }
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, der, (CFIndex)length);
    SecCertificateRef cert = data ? SecCertificateCreateWithData(NULL, data) : NULL;
    if (data) CFRelease(data);
    if (!cert) { r.reasons |= SG_CERT_MALFORMED; return r; }
    SecKeyRef key = SecCertificateCopyKey(cert);
    if (!key || !SecKeyIsAlgorithmSupported(key, kSecKeyOperationTypeVerify, kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256))
        r.reasons |= SG_CERT_KEY_ALGORITHM;
    if (key) {
        CFDictionaryRef attrs = SecKeyCopyAttributes(key);
        if (attrs) {
            CFTypeRef type = CFDictionaryGetValue(attrs, kSecAttrKeyType);
            if (!type || !CFEqual(type, kSecAttrKeyTypeRSA)) r.reasons |= SG_CERT_KEY_ALGORITHM;
            CFTypeRef size = CFDictionaryGetValue(attrs, kSecAttrKeySizeInBits);
            if (size && CFGetTypeID(size) == CFNumberGetTypeID())
                CFNumberGetValue((CFNumberRef)size, kCFNumberIntType, &r.public_key_bits);
            CFRelease(attrs);
        }
        CFRelease(key);
    }
    CFRelease(cert);
    if (!(r.reasons & SG_CERT_KEY_ALGORITHM) && (r.public_key_bits < 2048 || r.public_key_bits > 8192)) r.reasons |= SG_CERT_KEY_SIZE;
    if (!isfinite(now)) r.reasons |= SG_CERT_CLOCK;
    else {
        if (now < r.not_before) r.reasons |= SG_CERT_FUTURE;
        if (now > r.not_after) r.reasons |= SG_CERT_EXPIRED;
    }
    if (!r.key_usage_present) r.reasons |= SG_CERT_MISSING_KEY_USAGE;
    const uint32_t uncertain = SG_CERT_MISSING_KEY_USAGE | SG_CERT_UNKNOWN_EKU | SG_CERT_CRITICAL_EXTENSION | SG_CERT_CLOCK;
    r.status = (r.reasons & ~uncertain) ? SG_CERT_INELIGIBLE : r.reasons ? SG_CERT_INDETERMINATE : SG_CERT_ELIGIBLE;
    return r;
}
const char *sg_certificate_reason_message(uint32_t reason) {
    switch (reason) {
    case SG_CERT_MALFORMED: return "Certificato X.509 malformato o non interpretabile.";
    case SG_CERT_EXPIRED: return "Il certificato è scaduto.";
    case SG_CERT_FUTURE: return "Il certificato non è ancora valido.";
    case SG_CERT_KEY_USAGE: return "KeyUsage non consente digitalSignature né contentCommitment.";
    case SG_CERT_MISSING_KEY_USAGE: return "KeyUsage assente: uso di firma non determinabile con questa policy.";
    case SG_CERT_EKU: return "ExtendedKeyUsage limita il certificato a usi diversi dalla firma di documenti.";
    case SG_CERT_UNKNOWN_EKU: return "ExtendedKeyUsage contiene finalità non riconosciute: idoneità indeterminata.";
    case SG_CERT_KEY_ALGORITHM: return "Chiave incompatibile con RSA PKCS#1 v1.5 / SHA-256 supportato da Signum.";
    case SG_CERT_KEY_SIZE: return "La policy richiede una chiave RSA da 2048 a 8192 bit.";
    case SG_CERT_CRITICAL_EXTENSION: return "Estensione critica con semantica non valutata: idoneità indeterminata.";
    case SG_CERT_CA: return "Certificato CA: non ammesso come certificato personale di firma.";
    case SG_CERT_CLOCK: return "Data di valutazione non disponibile.";
    default: return "Controllo locale non determinabile.";
    }
}
