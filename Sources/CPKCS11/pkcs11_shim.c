#include "SignumPKCS11.h"
#include "pkcs11.h" // p11-kit: upstream copyright and permission notice retained.
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct SGContext {
    void *library;
    CK_FUNCTION_LIST_PTR api;
    int owns_initialization;
};

static int failed(char *error, size_t size, const char *operation, CK_RV rv) {
    if (error && size) snprintf(error, size, "%s failed (PKCS#11 RV=0x%lX)", operation, (unsigned long)rv);
    return -1;
}
static int invalid(char *error, size_t size, const char *reason) {
    if (error && size) snprintf(error, size, "%s", reason);
    return -1;
}
static void copy_padded(char *target, size_t capacity, const unsigned char *source, size_t length) {
    if (!capacity) return;
    size_t n = length < capacity - 1 ? length : capacity - 1;
    while (n && (source[n - 1] == ' ' || source[n - 1] == '\0')) --n;
    memcpy(target, source, n);
    target[n] = '\0';
}

int sg_open(const char *path, SGContext **out, char *error, size_t error_size) {
    if (!out || !path || path[0] != '/') return invalid(error, error_size, "Use an absolute module path");
    *out = NULL;
    SGContext *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return invalid(error, error_size, "Out of memory");
    ctx->library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!ctx->library) {
        const char *reason = dlerror();
        if (error && error_size) snprintf(error, error_size, "Cannot load module: %s", reason ? reason : "unknown error");
        free(ctx);
        return -1;
    }
    CK_C_GetFunctionList get_list = (CK_C_GetFunctionList)dlsym(ctx->library, "C_GetFunctionList");
    if (!get_list) { sg_close(ctx); return invalid(error, error_size, "Module lacks C_GetFunctionList"); }
    CK_RV rv = get_list(&ctx->api);
    if (rv != CKR_OK || !ctx->api) { sg_close(ctx); return failed(error, error_size, "C_GetFunctionList", rv); }
    rv = ctx->api->C_Initialize(NULL);
    if (rv == CKR_OK) ctx->owns_initialization = 1;
    else if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) { sg_close(ctx); return failed(error, error_size, "C_Initialize", rv); }
    *out = ctx;
    return 0;
}

void sg_close(SGContext *ctx) {
    if (!ctx) return;
    if (ctx->owns_initialization && ctx->api) ctx->api->C_Finalize(NULL);
    if (ctx->library) dlclose(ctx->library);
    free(ctx);
}

int sg_tokens(SGContext *ctx, SGToken *out, size_t capacity,
              size_t *count, char *error, size_t error_size) {
    if (!ctx || !out || !count) return invalid(error, error_size, "Invalid token arguments");
    *count = 0;
    CK_ULONG n = 0;
    CK_RV rv = ctx->api->C_GetSlotList(CK_TRUE, NULL, &n);
    if (rv != CKR_OK) return failed(error, error_size, "C_GetSlotList", rv);
    if (n > 256) return invalid(error, error_size, "Too many token slots");
    CK_SLOT_ID *slots = calloc(n ? n : 1, sizeof(CK_SLOT_ID));
    if (!slots) return invalid(error, error_size, "Out of memory");
    rv = ctx->api->C_GetSlotList(CK_TRUE, slots, &n);
    if (rv != CKR_OK) { free(slots); return failed(error, error_size, "C_GetSlotList", rv); }
    if (n > capacity) { free(slots); return invalid(error, error_size, "Too many slots for output buffer"); }
    for (CK_ULONG i = 0; i < n; ++i) {
        CK_TOKEN_INFO info;
        rv = ctx->api->C_GetTokenInfo(slots[i], &info);
        if (rv != CKR_OK) { free(slots); return failed(error, error_size, "C_GetTokenInfo", rv); }
        SGToken *t = &out[i];
        memset(t, 0, sizeof(*t));
        t->slot = slots[i];
        copy_padded(t->label, sizeof(t->label), info.label, sizeof(info.label));
        copy_padded(t->manufacturer, sizeof(t->manufacturer), info.manufacturerID, sizeof(info.manufacturerID));
        copy_padded(t->model, sizeof(t->model), (const unsigned char *)info.model, sizeof(info.model));
    }
    *count = n;
    free(slots);
    return 0;
}

static int open_session(SGContext *ctx, unsigned long slot, CK_SESSION_HANDLE *session,
                        char *error, size_t size) {
    CK_RV rv = ctx->api->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, session);
    return rv == CKR_OK ? 0 : failed(error, size, "C_OpenSession", rv);
}
static int find_one(SGContext *ctx, CK_SESSION_HANDLE session, CK_OBJECT_CLASS kind,
                    const uint8_t *id, size_t id_length, CK_OBJECT_HANDLE *object,
                    char *error, size_t size) {
    CK_ATTRIBUTE attrs[] = { {CKA_CLASS, &kind, sizeof(kind)}, {CKA_ID, (void *)id, id_length} };
    CK_RV rv = ctx->api->C_FindObjectsInit(session, attrs, 2);
    if (rv != CKR_OK) return failed(error, size, "C_FindObjectsInit", rv);
    CK_ULONG found = 0;
    rv = ctx->api->C_FindObjects(session, object, 1, &found);
    CK_RV end = ctx->api->C_FindObjectsFinal(session);
    if (rv != CKR_OK) return failed(error, size, "C_FindObjects", rv);
    if (end != CKR_OK) return failed(error, size, "C_FindObjectsFinal", end);
    if (!found) return invalid(error, size, "Matching object not found");
    return 0;
}

int sg_certificates(SGContext *ctx, unsigned long slot, SGCertificate *out,
                    size_t capacity, size_t *count, char *error, size_t error_size) {
    if (!ctx || !out || !count) return invalid(error, error_size, "Invalid certificate arguments");
    *count = 0;
    CK_SESSION_HANDLE session;
    if (open_session(ctx, slot, &session, error, error_size)) return -1;
    CK_OBJECT_CLASS kind = CKO_CERTIFICATE;
    CK_ATTRIBUTE filter = {CKA_CLASS, &kind, sizeof(kind)};
    CK_RV rv = ctx->api->C_FindObjectsInit(session, &filter, 1);
    if (rv != CKR_OK) { ctx->api->C_CloseSession(session); return failed(error, error_size, "C_FindObjectsInit", rv); }
    int status = 0;
    for (;;) {
        CK_OBJECT_HANDLE object;
        CK_ULONG found = 0;
        rv = ctx->api->C_FindObjects(session, &object, 1, &found);
        if (rv != CKR_OK) { status = failed(error, error_size, "C_FindObjects", rv); break; }
        if (!found) break;
        if (*count >= capacity) { status = invalid(error, error_size, "Too many certificates for output buffer"); break; }
        SGCertificate *cert = &out[*count];
        memset(cert, 0, sizeof(*cert));
        CK_ATTRIBUTE attrs[] = {
            {CKA_LABEL, cert->label, sizeof(cert->label) - 1},
            {CKA_ID, cert->id, sizeof(cert->id)}
        };
        rv = ctx->api->C_GetAttributeValue(session, object, attrs, 2);
        if (rv != CKR_OK || attrs[1].ulValueLen > sizeof(cert->id) || attrs[0].ulValueLen > sizeof(cert->label) - 1) {
            status = invalid(error, error_size, "Cannot read certificate label/ID"); break;
        }
        cert->id_length = attrs[1].ulValueLen;
        cert->label[attrs[0].ulValueLen] = '\0';
        (*count)++;
    }
    CK_RV end = ctx->api->C_FindObjectsFinal(session);
    if (!status && end != CKR_OK) status = failed(error, error_size, "C_FindObjectsFinal", end);
    ctx->api->C_CloseSession(session);
    return status;
}

int sg_certificate_der(SGContext *ctx, unsigned long slot, const uint8_t *id,
                       size_t id_length, uint8_t *out, size_t capacity,
                       size_t *length, char *error, size_t error_size) {
    if (!ctx || !id || !id_length || !length) return invalid(error, error_size, "Invalid DER arguments");
    *length = 0;
    CK_SESSION_HANDLE session;
    if (open_session(ctx, slot, &session, error, error_size)) return -1;
    CK_OBJECT_HANDLE object;
    int status = find_one(ctx, session, CKO_CERTIFICATE, id, id_length, &object, error, error_size);
    if (!status) {
        CK_ATTRIBUTE attr = {CKA_VALUE, NULL, 0};
        CK_RV rv = ctx->api->C_GetAttributeValue(session, object, &attr, 1);
        if (rv != CKR_OK || attr.ulValueLen == CK_UNAVAILABLE_INFORMATION || attr.ulValueLen > 65536) {
            status = invalid(error, error_size, "Cannot obtain X.509 DER size");
        } else {
            *length = attr.ulValueLen;
            if (out) {
                if (capacity < attr.ulValueLen) status = invalid(error, error_size, "DER buffer too small");
                else {
                    attr.pValue = out;
                    attr.ulValueLen = capacity;
                    rv = ctx->api->C_GetAttributeValue(session, object, &attr, 1);
                    if (rv != CKR_OK) status = failed(error, error_size, "C_GetAttributeValue DER", rv);
                    else *length = attr.ulValueLen;
                }
            }
        }
    }
    ctx->api->C_CloseSession(session);
    return status;
}

int sg_sign_test(SGContext *ctx, unsigned long slot, const uint8_t *id,
                 size_t id_length, const uint8_t *pin, size_t pin_length,
                 const uint8_t *message, size_t message_length,
                 uint8_t *signature, size_t signature_capacity,
                 size_t *signature_length, char *error, size_t error_size) {
    if (!ctx || !id || !id_length || !pin || !pin_length || !message || !signature ||
        !signature_length || message_length > 1024 * 1024 || signature_capacity < 8192)
        return invalid(error, error_size, "Invalid signing arguments");
    *signature_length = 0;
    CK_SESSION_HANDLE session;
    if (open_session(ctx, slot, &session, error, error_size)) return -1;
    CK_RV rv = ctx->api->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin, pin_length);
    int status = 0;
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        status = failed(error, error_size, "C_Login USER", rv);
    } else {
        CK_OBJECT_HANDLE key;
        status = find_one(ctx, session, CKO_PRIVATE_KEY, id, id_length, &key, error, error_size);
        if (!status) {
            CK_MECHANISM mechanism = {CKM_SHA256_RSA_PKCS, NULL, 0};
            rv = ctx->api->C_SignInit(session, &mechanism, key);
            if (rv != CKR_OK) status = failed(error, error_size, "C_SignInit", rv);
            else {
                CK_BBOOL always_auth = CK_FALSE;
                CK_ATTRIBUTE auth = {CKA_ALWAYS_AUTHENTICATE, &always_auth, sizeof(always_auth)};
                CK_RV arv = ctx->api->C_GetAttributeValue(session, key, &auth, 1);
                if (arv == CKR_OK && always_auth == CK_TRUE) {
                    rv = ctx->api->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)pin, pin_length);
                    if (rv != CKR_OK) status = failed(error, error_size, "C_Login CONTEXT_SPECIFIC", rv);
                } else if (arv != CKR_OK && arv != CKR_ATTRIBUTE_TYPE_INVALID && arv != CKR_ATTRIBUTE_SENSITIVE) {
                    status = failed(error, error_size, "C_GetAttributeValue authentication", arv);
                }
                if (!status) {
                    CK_ULONG n = signature_capacity;
                    rv = ctx->api->C_Sign(session, (CK_BYTE_PTR)message, message_length, signature, &n);
                    if (rv == CKR_OK) *signature_length = n;
                    else status = failed(error, error_size, "C_Sign", rv);
                }
            }
        }
    }
    // Closing the session also ends authenticated use and releases the key handle.
    ctx->api->C_CloseSession(session);
    return status;
}
