/* S16: exercise the actual shim helpers with a scalar-only provider.
 * The provider never writes beyond the ONE supplied handle. No token/PIN,
 * dlopen, login or signing call is used. This tests returned-count validation,
 * not protection against a provider that actually overwrites memory. */
#include <limits.h>
#include <stdint.h>
#include "../../Sources/CPKCS11/pkcs11_shim.c"

static CK_ULONG reported;
static CK_RV find_rv, final_rv, close_rv;
static unsigned finds, finals, closes, attributes, bad_capacity;
static unsigned cases, failures;
static const char *failed_names[32];
static CK_RV open_fake(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR app,
                       CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session) {
    (void)slot; (void)flags; (void)app; (void)notify; *session = 7; return CKR_OK;
}
static CK_RV init_fake(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR a, CK_ULONG n) {
    (void)session; (void)a; (void)n; return CKR_OK;
}
static CK_RV find_fake(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR object,
                       CK_ULONG capacity, CK_ULONG_PTR count) {
    (void)session; if (capacity != 1) ++bad_capacity;
    *count = finds++ == 0 ? reported : 0;
    if (*count && capacity) object[0] = 73;
    return find_rv;
}
static CK_RV final_fake(CK_SESSION_HANDLE session) {
    (void)session; ++finals; return final_rv;
}
static CK_RV close_fake(CK_SESSION_HANDLE session) {
    (void)session; ++closes; return close_rv;
}
static CK_RV attribute_fake(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                            CK_ATTRIBUTE_PTR attrs, CK_ULONG n) {
    (void)session; (void)object; ++attributes;
    for (CK_ULONG i = 0; i < n; ++i) {
        if (attrs[i].pValue && attrs[i].ulValueLen) memset(attrs[i].pValue, 'A', 1);
        attrs[i].ulValueLen = 1;
    }
    return CKR_OK;
}
static void one_case(int route, CK_ULONG count, CK_RV fr, CK_RV er, CK_RV cr,
                     const char *name) {
    reported = count; find_rv = fr; final_rv = er; close_rv = cr;
    finds = finals = closes = attributes = bad_capacity = 0;
    CK_FUNCTION_LIST api = {0};
    api.C_OpenSession = open_fake; api.C_CloseSession = close_fake;
    api.C_FindObjectsInit = init_fake; api.C_FindObjects = find_fake;
    api.C_FindObjectsFinal = final_fake; api.C_GetAttributeValue = attribute_fake;
    SGProvider provider = {0}; SGContext ctx = {.provider = &provider, .api = &api};
    char error[512] = {0}; uint8_t id = 1; int status;
    struct { uint64_t before; CK_OBJECT_HANDLE value; uint64_t after; } handle = {11, 0, 22};
    struct { uint64_t before; SGCertificate value; uint64_t after; } cert;
    memset(&cert, 0, sizeof cert); cert.before = 11; cert.after = 22;
    struct { uint64_t before; uint8_t value[4]; uint64_t after; } der = {11, {0}, 22};
    size_t length = 99;
    if (route == 0) status = find_one(&ctx, 7, CKO_PRIVATE_KEY, &id, 1, &handle.value, error, sizeof error);
    else if (route == 1) status = sg_certificates_impl(&ctx, 7, &cert.value, 1, &length, error, sizeof error);
    else status = sg_certificate_der_impl(&ctx, 7, &id, 1, der.value, sizeof der.value, &length, error, sizeof error);
    int success_expected = count <= 1 && (route == 1 || count == 1) && fr == CKR_OK && er == CKR_OK && cr == CKR_OK;
    int ok = (status == 0) == success_expected;
    ok &= finals == 1 && closes == (route == 0 ? 0u : 1u) && !bad_capacity;
    ok &= handle.before == 11 && handle.after == 22 && cert.before == 11 && cert.after == 22 && der.before == 11 && der.after == 22;
    if (count > 1 || fr != CKR_OK) ok &= attributes == 0;
    if (count > 1 && fr == CKR_OK && er == CKR_OK) ok &= strstr(error, "count exceeds") != NULL;
    if (route == 1 && count > 1) ok &= length == 0;
    if (route == 2 && status) ok &= length == 0 && !der.value[0] && !der.value[1] && !der.value[2] && !der.value[3];
    if (fr != CKR_OK) ok &= strstr(error, "C_FindObjects failed") != NULL;
    if (er != CKR_OK) ok &= strstr(error, "C_FindObjectsFinal") != NULL;
    if (cr != CKR_OK) ok &= provider.quarantined && strstr(error, "C_CloseSession") != NULL;
    ++cases; if (!ok) failed_names[failures++] = name;
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
}
int main(void) {
    const CK_ULONG values[] = {0, 1, 2, ULONG_MAX};
    static const char *names[3][4] = {{"one-0","one-1","one-2","one-max"}, {"list-0","list-1","list-2","list-max"}, {"der-0","der-1","der-2","der-max"}};
    for (int route = 0; route < 3; ++route)
        for (unsigned i = 0; i < 4; ++i) one_case(route, values[i], CKR_OK, CKR_OK, CKR_OK, names[route][i]);
    one_case(1, 2, CKR_GENERAL_ERROR, CKR_OK, CKR_OK, "list-primary-error");
    one_case(2, 2, CKR_GENERAL_ERROR, CKR_OK, CKR_OK, "der-primary-error");
    one_case(1, 0, CKR_OK, CKR_GENERAL_ERROR, CKR_OK, "list-final-error");
    one_case(2, 0, CKR_OK, CKR_GENERAL_ERROR, CKR_OK, "der-final-error");
    one_case(1, 2, CKR_OK, CKR_OK, CKR_GENERAL_ERROR, "list-close-error");
    one_case(2, 2, CKR_OK, CKR_OK, CKR_GENERAL_ERROR, "der-close-error");
    printf("{\"cases\":%u,\"passed\":%u,\"failed\":[", cases, cases-failures);
    for (unsigned i = 0; i < failures; ++i) printf("%s\"%s\"", i ? "," : "", failed_names[i]);
    puts("]}"); return failures ? 1 : 0;
}
