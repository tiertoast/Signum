#include "SignumCertificatePolicy.h"
#include "SignumPKCS11.h"
#include "pkcs11.h" // p11-kit: upstream copyright and permission notice retained.
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <math.h>

typedef struct SGProvider {
    char *canonical_path;
    dev_t device;
    ino_t inode;
    void *library;
    CK_FUNCTION_LIST_PTR api;
    size_t references;
    int owns_initialization;
    int quarantined;
    enum { SG_LOADING, SG_READY, SG_FINALIZING, SG_RETAINED_FAILURE } state;
    pthread_mutex_t operations;
    struct SGProvider *next;
} SGProvider;

struct SGContext {
    SGProvider *provider;
    CK_FUNCTION_LIST_PTR api;
};

// The registry mutex never spans vendor code or waiting for an operation mutex.
// Loading/finalizing records are waited on using a global condition (waiters
// re-lookup by identity and never retain a pointer that could be freed).
// Operations never acquire the registry. This is in-process coordination only.
static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t registry_changed = PTHREAD_COND_INITIALIZER;
static SGProvider *providers;
static size_t provider_count;
#define SG_MAX_PROVIDERS 64

static int failed(char *error, size_t size, const char *operation, CK_RV rv) {
    if (error && size) snprintf(error, size, "%s failed (PKCS#11 RV=0x%lX)", operation, (unsigned long)rv);
    return rv == CKR_USER_NOT_LOGGED_IN ? -2 : -1;
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

static int complete_api(CK_FUNCTION_LIST_PTR a) {
    return a && a->C_Initialize && a->C_Finalize && a->C_GetSlotList &&
        a->C_GetTokenInfo && a->C_GetSlotInfo && a->C_OpenSession &&
        a->C_CloseSession && a->C_GetSessionInfo && a->C_Login &&
        a->C_FindObjectsInit && a->C_FindObjects && a->C_FindObjectsFinal &&
        a->C_GetAttributeValue && a->C_SignInit && a->C_Sign;
}

static void unlink_provider(SGProvider *provider) { // registry lock held
    SGProvider **entry = &providers;
    while (*entry != provider) entry = &(*entry)->next;
    *entry = provider->next;
    --provider_count;
}

static void free_provider(SGProvider *provider) { // no registry lock
    pthread_mutex_destroy(&provider->operations);
    if (provider->library) dlclose(provider->library);
    free(provider->canonical_path);
    free(provider);
}

static int finish_attach(SGProvider *provider, SGContext *context, SGContext **out,
                         char *error, size_t error_size) {
    // A provisional reference, already taken under the registry mutex, keeps
    // the record alive while we wait for the current transaction to finish.
    context->provider = provider;
    context->api = provider->api;
    pthread_mutex_lock(&provider->operations);
    const int quarantined = provider->quarantined;
    pthread_mutex_unlock(&provider->operations);
    if (quarantined) {
        (void)sg_close_checked(context, NULL, 0);
        return invalid(error, error_size,
            "Provider quarantined after uncertain cleanup; release all contexts or restart the process");
    }
    *out = context;
    return 0;
}

int sg_open(const char *path, SGContext **out, char *error, size_t error_size) {
    if (out) *out = NULL;
    if (!out || !path || path[0] != '/') return invalid(error, error_size, "Use an absolute module path");
    SGContext *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return invalid(error, error_size, "Out of memory");
retry:;
    char *canonical = realpath(path, NULL);
    struct stat identity;
    if (!canonical || stat(canonical, &identity) || !S_ISREG(identity.st_mode)) {
        free(canonical); free(ctx);
        return invalid(error, error_size, "Cannot resolve a regular provider file");
    }
    pthread_mutex_lock(&registry_lock);
    for (SGProvider *p = providers; p; p = p->next) {
        if (!strcmp(p->canonical_path, canonical) && (p->device != identity.st_dev || p->inode != identity.st_ino)) {
            pthread_mutex_unlock(&registry_lock); free(canonical); free(ctx);
            return invalid(error, error_size, "Provider file changed while loaded; release contexts or restart");
        }
        if (p->device == identity.st_dev && p->inode == identity.st_ino) {
            if (p->state == SG_LOADING || p->state == SG_FINALIZING) {
                pthread_cond_wait(&registry_changed, &registry_lock);
                pthread_mutex_unlock(&registry_lock); free(canonical);
                goto retry; // refresh identity; record may have disappeared
            }
            if (p->state == SG_RETAINED_FAILURE) {
                pthread_mutex_unlock(&registry_lock); free(canonical); free(ctx);
                return invalid(error, error_size, "Provider retained after failed finalization; restart the process");
            }
            ++p->references;
            pthread_mutex_unlock(&registry_lock); free(canonical);
            return finish_attach(p, ctx, out, error, error_size);
        }
    }
    if (provider_count >= SG_MAX_PROVIDERS) {
        pthread_mutex_unlock(&registry_lock); free(canonical); free(ctx);
        return invalid(error, error_size, "Too many retained providers");
    }
    SGProvider *p = calloc(1, sizeof(*p));
    if (!p || pthread_mutex_init(&p->operations, NULL)) {
        pthread_mutex_unlock(&registry_lock); free(p); free(canonical); free(ctx);
        return invalid(error, error_size, "Cannot allocate provider owner/mutex");
    }
    p->canonical_path = canonical;
    p->device = identity.st_dev; p->inode = identity.st_ino;
    p->state = SG_LOADING;
    p->next = providers; providers = p; ++provider_count;
    pthread_mutex_unlock(&registry_lock);

    int status = -1;
    p->library = dlopen(canonical, RTLD_NOW | RTLD_LOCAL);
    if (!p->library) {
        const char *reason = dlerror();
        if (error && error_size) snprintf(error, error_size, "Cannot load module: %s", reason ? reason : "unknown error");
        goto load_failed;
    }
    CK_C_GetFunctionList get_list = (CK_C_GetFunctionList)dlsym(p->library, "C_GetFunctionList");
    CK_FUNCTION_LIST_PTR api = NULL;
    CK_RV rv = get_list ? get_list(&api) : CKR_FUNCTION_NOT_SUPPORTED;
    if (rv != CKR_OK) { failed(error, error_size, "C_GetFunctionList", rv); goto load_failed; }
    if (!complete_api(api)) { invalid(error, error_size, "Provider exposes an incomplete function table"); goto load_failed; }

    // Handle additional aliases deduplicated by the dynamic loader itself.
    pthread_mutex_lock(&registry_lock);
    for (SGProvider *existing = providers; existing; existing = existing->next) {
        if (existing != p && existing->api == api) {
            const int state = existing->state;
            const int ready = state == SG_READY;
            if (ready) ++existing->references;
            unlink_provider(p);
            pthread_cond_broadcast(&registry_changed);
            if (state == SG_LOADING || state == SG_FINALIZING)
                pthread_cond_wait(&registry_changed, &registry_lock);
            pthread_mutex_unlock(&registry_lock);
            free_provider(p);
            if (ready) return finish_attach(existing, ctx, out, error, error_size);
            // No reference to the old record survives a wait/unlock: another
            // thread may have removed it. Only the captured state is used here.
            if (state == SG_RETAINED_FAILURE) {
                free(ctx);
                return invalid(error, error_size, "Provider alias retained after failed finalization; restart");
            }
            goto retry;
        }
    }
    p->api = api;
    pthread_mutex_unlock(&registry_lock);
    CK_C_INITIALIZE_ARGS arguments = {0};
    arguments.flags = CKF_OS_LOCKING_OK;
    rv = p->api->C_Initialize(&arguments);
    if (rv == CKR_OK) p->owns_initialization = 1;
    else if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        status = failed(error, error_size, "C_Initialize", rv);
        goto load_failed;
    }
    pthread_mutex_lock(&registry_lock);
    p->references = 1;
    p->state = SG_READY;
    pthread_cond_broadcast(&registry_changed);
    pthread_mutex_unlock(&registry_lock);
    ctx->provider = p; ctx->api = p->api; *out = ctx;
    return 0;
load_failed:
    pthread_mutex_lock(&registry_lock);
    unlink_provider(p);
    pthread_cond_broadcast(&registry_changed);
    pthread_mutex_unlock(&registry_lock);
    free_provider(p); free(ctx);
    return status;
}

const char *sg_canonical_path(SGContext *ctx) { return ctx ? ctx->provider->canonical_path : NULL; }

int sg_close_checked(SGContext *ctx, char *error, size_t error_size) {
    if (!ctx) return 0;
    SGProvider *p = ctx->provider;
    pthread_mutex_lock(&registry_lock);
    --p->references;
    if (p->references || !p->owns_initialization) {
        // An externally initialized provider is never finalized/unloaded by
        // Signum, even at ref=0. Its owner must maintain its lifetime.
        pthread_mutex_unlock(&registry_lock); free(ctx); return 0;
    }
    p->state = SG_FINALIZING;
    pthread_mutex_unlock(&registry_lock);
    pthread_mutex_lock(&p->operations);
    CK_RV rv = p->api->C_Finalize(NULL);
    if (rv != CKR_OK) p->quarantined = 1;
    pthread_mutex_unlock(&p->operations);
    pthread_mutex_lock(&registry_lock);
    if (rv == CKR_OK) unlink_provider(p);
    else p->state = SG_RETAINED_FAILURE;
    pthread_cond_broadcast(&registry_changed);
    pthread_mutex_unlock(&registry_lock);
    if (rv == CKR_OK) free_provider(p);
    free(ctx);
    return rv == CKR_OK ? 0 : failed(error, error_size, "C_Finalize (provider retained)", rv);
}

void sg_close(SGContext *ctx) { (void)sg_close_checked(ctx, NULL, 0); }

static int enter(SGContext *ctx, char *error, size_t size) {
    if (!ctx) return invalid(error, size, "Invalid provider context");
    pthread_mutex_lock(&ctx->provider->operations);
    if (ctx->provider->quarantined) {
        pthread_mutex_unlock(&ctx->provider->operations);
        return invalid(error, size, "Provider quarantined after uncertain session cleanup; release contexts or restart");
    }
    return 0;
}

static int close_session(SGContext *ctx, CK_SESSION_HANDLE session, int status, char *error, size_t size) {
    CK_RV rv = ctx->api->C_CloseSession(session);
    if (rv == CKR_OK) return status;
    // No CloseAllSessions/Logout: these could invalidate another owner's state.
    ctx->provider->quarantined = 1;
    if (!status) return failed(error, size, "C_CloseSession (provider quarantined)", rv);
    if (error && size) {
        const size_t used = strnlen(error, size);
        if (used < size) snprintf(error + used, size - used, "; cleanup C_CloseSession RV=0x%lX (quarantined)", (unsigned long)rv);
    }
    return -1;
}

int sg_module_version(SGContext *ctx, unsigned *major, unsigned *minor) {
    if (!major || !minor || enter(ctx, NULL, 0)) return -1;
    CK_INFO info;
    CK_RV rv = ctx->api->C_GetInfo ? ctx->api->C_GetInfo(&info) : CKR_FUNCTION_NOT_SUPPORTED;
    if (rv == CKR_OK) { *major = info.libraryVersion.major; *minor = info.libraryVersion.minor; }
    pthread_mutex_unlock(&ctx->provider->operations);
    return rv == CKR_OK ? 0 : -1;
}

static int login_user(SGContext *ctx, CK_SESSION_HANDLE session, const uint8_t *pin, size_t pin_length,
                       char *error, size_t size) {
    CK_SESSION_INFO info;
    CK_RV rv = ctx->api->C_GetSessionInfo(session, &info);
    if (rv != CKR_OK) return failed(error, size, "C_GetSessionInfo", rv);
    if (info.state != CKS_RO_PUBLIC_SESSION && info.state != CKS_RW_PUBLIC_SESSION)
        return invalid(error, size, "Provider already authenticated elsewhere; supplied PIN not verified; no logout performed");
    rv = ctx->api->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin, pin_length);
    if (rv != CKR_OK) return failed(error, size, "C_Login USER (no retry)", rv);
    return 0;
}

static int transient_slot_error(CK_RV rv) {
    return rv == CKR_TOKEN_NOT_RECOGNIZED || rv == CKR_TOKEN_NOT_PRESENT ||
           rv == CKR_SLOT_ID_INVALID || rv == CKR_DEVICE_REMOVED;
}

static int sg_tokens_impl(SGContext *ctx, SGToken *out, size_t capacity,
              size_t *count, size_t *unavailable, char *error, size_t error_size) {
    if (!ctx || !out || !count || !unavailable)
        return invalid(error, error_size, "Invalid token arguments");
    *count = 0;
    *unavailable = 0;

    CK_ULONG initial_count = 0;
    CK_RV rv = ctx->api->C_GetSlotList(CK_TRUE, NULL, &initial_count);
    if (rv != CKR_OK) return failed(error, error_size, "C_GetSlotList", rv);
    if (initial_count > 256) return invalid(error, error_size, "Too many token slots");

    // Allocate for the maximum accepted capacity: slots can appear between
    // the count query and the data query, so allocating only initial_count
    // would spuriously fail when a second token is inserted.
    CK_SLOT_ID slots[256] = {0};
    CK_ULONG n = 256;
    rv = ctx->api->C_GetSlotList(CK_TRUE, slots, &n);
    if (rv != CKR_OK) return failed(error, error_size, "C_GetSlotList", rv);
    if (n > 256) return invalid(error, error_size, "Token slot list changed unexpectedly");

    for (CK_ULONG i = 0; i < n; ++i) {
        CK_TOKEN_INFO info;
        rv = ctx->api->C_GetTokenInfo(slots[i], &info);
        if (transient_slot_error(rv)) {
            ++(*unavailable);
            continue;
        }
        if (rv != CKR_OK) return failed(error, error_size, "C_GetTokenInfo", rv);

        if (*count >= capacity)
            return invalid(error, error_size, "Too many tokens for output buffer");
        SGToken *t = &out[*count];
        memset(t, 0, sizeof(*t));
        t->slot = slots[i];
        copy_padded(t->label, sizeof(t->label), info.label, sizeof(info.label));
        copy_padded(t->manufacturer, sizeof(t->manufacturer), info.manufacturerID, sizeof(info.manufacturerID));
        copy_padded(t->model, sizeof(t->model), (const unsigned char *)info.model, sizeof(info.model));
        copy_padded(t->serial, sizeof(t->serial), info.serialNumber, sizeof(info.serialNumber));
        CK_SLOT_INFO slot_info;
        if (ctx->api->C_GetSlotInfo(slots[i], &slot_info) == CKR_OK) {
            copy_padded(t->reader, sizeof(t->reader), slot_info.slotDescription,
                        sizeof(slot_info.slotDescription));
        }
        ++(*count);
    }
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
    if (found > 1) return invalid(error, size, "C_FindObjects count exceeds requested capacity");
    if (!found) return invalid(error, size, "Matching object not found");
    return 0;
}

static int sg_certificates_impl(SGContext *ctx, unsigned long slot, SGCertificate *out,
                    size_t capacity, size_t *count, char *error, size_t error_size) {
    if (!ctx || !out || !count) return invalid(error, error_size, "Invalid certificate arguments");
    *count = 0;
    CK_SESSION_HANDLE session;
    if (open_session(ctx, slot, &session, error, error_size)) return -1;
    CK_OBJECT_CLASS kind = CKO_CERTIFICATE;
    CK_ATTRIBUTE filter = {CKA_CLASS, &kind, sizeof(kind)};
    CK_RV rv = ctx->api->C_FindObjectsInit(session, &filter, 1);
    if (rv != CKR_OK) {
        int status = failed(error, error_size, "C_FindObjectsInit", rv);
        return close_session(ctx, session, status, error, error_size);
    }
    int status = 0;
    for (;;) {
        CK_OBJECT_HANDLE object;
        CK_ULONG found = 0;
        rv = ctx->api->C_FindObjects(session, &object, 1, &found);
        if (rv != CKR_OK) { status = failed(error, error_size, "C_FindObjects", rv); break; }
        if (found > 1) { status = invalid(error, error_size, "C_FindObjects count exceeds requested capacity"); break; }
        if (!found) break;
        if (*count >= capacity) { status = invalid(error, error_size, "Too many certificates for output buffer"); break; }
        SGCertificate *cert = &out[*count];
        memset(cert, 0, sizeof(*cert));
        CK_ATTRIBUTE attrs[] = {
            {CKA_LABEL, cert->label, sizeof(cert->label) - 1},
            {CKA_ID, cert->id, sizeof(cert->id)}
        };
        rv = ctx->api->C_GetAttributeValue(session, object, attrs, 2);
        if (rv == CKR_USER_NOT_LOGGED_IN) { status = failed(error, error_size, "C_GetAttributeValue", rv); break; }
        if (rv != CKR_OK || attrs[1].ulValueLen > sizeof(cert->id) || attrs[0].ulValueLen > sizeof(cert->label) - 1) {
            status = invalid(error, error_size, "Cannot read certificate label/ID"); break;
        }
        cert->id_length = attrs[1].ulValueLen;
        cert->label[attrs[0].ulValueLen] = '\0';
        (*count)++;
    }
    CK_RV end = ctx->api->C_FindObjectsFinal(session);
    if (!status && end != CKR_OK) status = failed(error, error_size, "C_FindObjectsFinal", end);
    return close_session(ctx, session, status, error, error_size);
}

static int sg_certificate_der_impl(SGContext *ctx, unsigned long slot, const uint8_t *id,
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
        if (rv == CKR_USER_NOT_LOGGED_IN) return close_session(ctx, session, failed(error, error_size, "C_GetAttributeValue DER", rv), error, error_size);
        if (rv != CKR_OK || !attr.ulValueLen || attr.ulValueLen == CK_UNAVAILABLE_INFORMATION || attr.ulValueLen > 65536) {
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
                    else if (!attr.ulValueLen || attr.ulValueLen > capacity || attr.ulValueLen > 65536)
                        status = invalid(error, error_size, "Invalid returned DER length");
                    else *length = attr.ulValueLen;
                }
            }
        }
    }
    status = close_session(ctx, session, status, error, error_size);
    if (status) { *length = 0; if (out && capacity) memset(out, 0, capacity); }
    return status;
}

/* No active sign operation exists here. Find/DER/policy are evaluated in
 * the same authenticated session, before key selection and SignInit. Never
 * insert object searches after the CONTEXT_SPECIFIC authorization. */
static int check_authenticated_certificate(SGContext *ctx, CK_SESSION_HANDLE session,
    const uint8_t *id, size_t id_length, const uint8_t *expected, size_t expected_length,
    char *error, size_t size) {
    CK_OBJECT_HANDLE certificate;
    int status = find_one(ctx, session, CKO_CERTIFICATE, id, id_length, &certificate, error, size);
    if (status) return status;
    uint8_t actual[65536];
    CK_ATTRIBUTE attr = { CKA_VALUE, actual, sizeof(actual) };
    CK_RV rv = ctx->api->C_GetAttributeValue(session, certificate, &attr, 1);
    if (rv != CKR_OK) return failed(error, size, "Authenticated certificate DER", rv);
    if (!attr.ulValueLen || attr.ulValueLen > sizeof(actual) || attr.ulValueLen != expected_length ||
        memcmp(actual, expected, expected_length))
        return invalid(error, size, "Certificate changed after USER login");
    SGCertificateAssessment assessment = sg_certificate_assess(actual, attr.ulValueLen, sg_certificate_now());
    return assessment.status == SG_CERT_ELIGIBLE ? 0 : invalid(error, size, "Certificate no longer locally eligible");
}

static int sg_sign_test_impl(SGContext *ctx, unsigned long slot, const uint8_t *id,
                 size_t id_length, const uint8_t *pin, size_t pin_length,
                 const uint8_t *message, size_t message_length,
                 uint8_t *signature, size_t signature_capacity,
                 size_t *signature_length, const uint8_t *expected, size_t expected_length, char *error, size_t error_size) {
    if (!ctx || !id || !id_length || !pin || !pin_length || !message || !signature ||
        !signature_length || message_length > 1024 * 1024 || signature_capacity < 8192)
        return invalid(error, error_size, "Invalid signing arguments");
    *signature_length = 0;
    CK_SESSION_HANDLE session;
    if (open_session(ctx, slot, &session, error, error_size)) return -1;
    CK_RV rv;
    int status = login_user(ctx, session, pin, pin_length, error, error_size);
    if (!status && expected) status = check_authenticated_certificate(ctx, session, id, id_length, expected, expected_length, error, error_size);
    if (!status) {
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
                if (arv == CKR_OK && (auth.ulValueLen != sizeof(always_auth) || (always_auth != CK_TRUE && always_auth != CK_FALSE))) {
                    status = invalid(error, error_size, "Invalid authentication attribute");
                } else if (arv == CKR_OK && always_auth == CK_TRUE) {
                    rv = ctx->api->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)pin, pin_length);
                    if (rv != CKR_OK) status = failed(error, error_size, "C_Login CONTEXT_SPECIFIC", rv);
                } else if (arv != CKR_OK && arv != CKR_ATTRIBUTE_TYPE_INVALID && arv != CKR_ATTRIBUTE_SENSITIVE) {
                    status = failed(error, error_size, "C_GetAttributeValue authentication", arv);
                }
                if (!status) {
                    CK_ULONG n = signature_capacity;
                    rv = ctx->api->C_Sign(session, (CK_BYTE_PTR)message, message_length, signature, &n);
                    if (rv == CKR_OK && n > 0 && n <= signature_capacity) *signature_length = n;
                    else if (rv == CKR_OK) status = invalid(error, error_size, "Invalid returned signature length");
                    else status = failed(error, error_size, "C_Sign", rv);
                }
            }
        }
    }
    // Close only our session. Other owners' sessions may keep a shared login.
    status = close_session(ctx, session, status, error, error_size);
    if (status) { memset(signature, 0, signature_capacity); *signature_length = 0; }
    return status;
}

// Raw PKCS#1 v1.5 signature of *already ASN.1 wrapped* SHA-256 digest.
// Never supply arbitrary data here. Higher-level code must have calculated
// a matching signed digest; this entry point does not hash.
static int sg_sign_encoded_digest_impl(SGContext *ctx, unsigned long slot,
                           const uint8_t *id, size_t id_length,
                           const uint8_t *pin, size_t pin_length,
                           const uint8_t *digestinfo, size_t digestinfo_length,
                           uint8_t *signature, size_t signature_capacity,
                           size_t *signature_length, const uint8_t *expected, size_t expected_length, char *error, size_t error_size) {
    // SHA-256 DigestInfo is exactly 51 bytes:
    // SEQUENCE AlgorithmIdentifier SHA256 + OCTET STRING 32.
    static const uint8_t prefix[] = {
        0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
        0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
    };
    if (!ctx || !id || !id_length || !pin || !pin_length ||
        !digestinfo || digestinfo_length != 51 ||
        memcmp(digestinfo, prefix, sizeof(prefix)) != 0 ||
        !signature || signature_capacity < 8192 || !signature_length)
        return invalid(error, error_size, "Expected DER SHA-256 DigestInfo and valid signing buffers");
    *signature_length = 0;
    CK_SESSION_HANDLE session;
    if (open_session(ctx, slot, &session, error, error_size)) return -1;
    CK_RV rv;
    int status = login_user(ctx, session, pin, pin_length, error, error_size);
    if (!status && expected) status = check_authenticated_certificate(ctx, session, id, id_length, expected, expected_length, error, error_size);
    if (!status) {
        CK_OBJECT_HANDLE key;
        status = find_one(ctx, session, CKO_PRIVATE_KEY, id, id_length,
                          &key, error, error_size);
        if (!status) {
            CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};
            rv = ctx->api->C_SignInit(session, &mechanism, key);
            if (rv != CKR_OK) status = failed(error, error_size, "C_SignInit", rv);
            else {
                CK_BBOOL always_auth = CK_FALSE;
                CK_ATTRIBUTE auth = {CKA_ALWAYS_AUTHENTICATE, &always_auth, sizeof(always_auth)};
                CK_RV arv = ctx->api->C_GetAttributeValue(session, key, &auth, 1);
                if (arv == CKR_OK && (auth.ulValueLen != sizeof(always_auth) || (always_auth != CK_TRUE && always_auth != CK_FALSE))) {
                    status = invalid(error, error_size, "Invalid authentication attribute");
                } else if (arv == CKR_OK && always_auth == CK_TRUE) {
                    rv = ctx->api->C_Login(session, CKU_CONTEXT_SPECIFIC,
                                           (CK_UTF8CHAR_PTR)pin, pin_length);
                    if (rv != CKR_OK) status = failed(error, error_size, "C_Login CONTEXT_SPECIFIC", rv);
                } else if (arv != CKR_OK && arv != CKR_ATTRIBUTE_TYPE_INVALID &&
                           arv != CKR_ATTRIBUTE_SENSITIVE) {
                    status = failed(error, error_size, "C_GetAttributeValue authentication", arv);
                }
                if (!status) {
                    CK_ULONG n = signature_capacity;
                    rv = ctx->api->C_Sign(session, (CK_BYTE_PTR)digestinfo,
                                          digestinfo_length, signature, &n);
                    if (rv == CKR_OK && n > 0 && n <= signature_capacity) *signature_length = n;
                    else if (rv == CKR_OK) status = invalid(error, error_size, "Invalid returned signature length");
                    else status = failed(error, error_size, "C_Sign", rv);
                }
            }
        }
    }
    status = close_session(ctx, session, status, error, error_size);
    if (status) { memset(signature, 0, signature_capacity); *signature_length = 0; }
    return status;
}

int sg_tokens(SGContext *ctx, SGToken *out, size_t capacity, size_t *count, size_t *unavailable, char *error, size_t error_size) {
    if (count) *count = 0;
    if (unavailable) *unavailable = 0;
    if (enter(ctx, error, error_size)) return -1;
    int status = sg_tokens_impl(ctx, out, capacity, count, unavailable, error, error_size);
    pthread_mutex_unlock(&ctx->provider->operations);
    return status;
}

int sg_pin_public_info(SGContext *ctx, unsigned long slot, SGPINPublicInfo *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (enter(ctx, NULL, 0)) return -1;
    CK_TOKEN_INFO info = {0};
    CK_SLOT_INFO reader = {0};
    CK_RV rv = ctx->api->C_GetTokenInfo(slot, &info);
    if (rv == CKR_OK) rv = ctx->api->C_GetSlotInfo(slot, &reader);
    if (rv == CKR_OK) {
        out->version = 1; out->token.slot = slot;
        copy_padded(out->token.label, sizeof(out->token.label), info.label, sizeof(info.label));
        copy_padded(out->token.manufacturer, sizeof(out->token.manufacturer), info.manufacturerID, sizeof(info.manufacturerID));
        copy_padded(out->token.model, sizeof(out->token.model), info.model, sizeof(info.model));
        copy_padded(out->token.serial, sizeof(out->token.serial), info.serialNumber, sizeof(info.serialNumber));
        copy_padded(out->token.reader, sizeof(out->token.reader), reader.slotDescription, sizeof(reader.slotDescription));
        out->flags = (uint64_t)info.flags;
        out->minimum_known = info.ulMinPinLen != CK_UNAVAILABLE_INFORMATION;
        out->maximum_known = info.ulMaxPinLen != CK_UNAVAILABLE_INFORMATION;
        if (out->minimum_known) out->minimum_bytes = (uint64_t)info.ulMinPinLen;
        if (out->maximum_known) out->maximum_bytes = (uint64_t)info.ulMaxPinLen;
    }
    pthread_mutex_unlock(&ctx->provider->operations);
    return rv == CKR_OK ? 0 : -1;
}

int sg_certificates(SGContext *ctx, unsigned long slot, SGCertificate *out, size_t capacity, size_t *count, char *error, size_t error_size) {
    if (count) *count = 0;
    if (enter(ctx, error, error_size)) return -1;
    int status = sg_certificates_impl(ctx, slot, out, capacity, count, error, error_size);
    pthread_mutex_unlock(&ctx->provider->operations);
    return status;
}

int sg_certificate_der(SGContext *ctx, unsigned long slot, const uint8_t *id, size_t id_length, uint8_t *out, size_t capacity, size_t *length, char *error, size_t error_size) {
    if (length) *length = 0;
    if (enter(ctx, error, error_size)) return -1;
    int status = sg_certificate_der_impl(ctx, slot, id, id_length, out, capacity, length, error, error_size);
    pthread_mutex_unlock(&ctx->provider->operations);
    return status;
}

int sg_sign_test(SGContext *ctx, unsigned long slot, const uint8_t *id, size_t id_length, const uint8_t *pin, size_t pin_length, const uint8_t *message, size_t message_length, uint8_t *signature, size_t signature_capacity, size_t *signature_length, char *error, size_t error_size) {
    if (signature_length) *signature_length = 0;
    if (enter(ctx, error, error_size)) return -1;
    int status = sg_sign_test_impl(ctx, slot, id, id_length, pin, pin_length, message, message_length, signature, signature_capacity, signature_length, NULL, 0, error, error_size);
    pthread_mutex_unlock(&ctx->provider->operations);
    return status;
}

int sg_sign_encoded_digest(SGContext *ctx, unsigned long slot, const uint8_t *id, size_t id_length, const uint8_t *pin, size_t pin_length, const uint8_t *digestinfo, size_t digestinfo_length, uint8_t *signature, size_t signature_capacity, size_t *signature_length, char *error, size_t error_size) {
    if (signature_length) *signature_length = 0;
    if (enter(ctx, error, error_size)) return -1;
    int status = sg_sign_encoded_digest_impl(ctx, slot, id, id_length, pin, pin_length, digestinfo, digestinfo_length, signature, signature_capacity, signature_length, NULL, 0, error, error_size);
    pthread_mutex_unlock(&ctx->provider->operations);
    return status;
}

/* Caller holds provider->operations. No extra lock or recursive public call. */
static int check_signing_certificate(SGContext *ctx, unsigned long slot, const uint8_t *id,
    size_t id_length, const uint8_t *expected, size_t expected_length, char *error, size_t error_size) {
    if (!expected || !expected_length || expected_length > 65536)
        return invalid(error, error_size, "Missing approved certificate DER");
    uint8_t *der = malloc(65536);
    if (!der) return invalid(error, error_size, "Cannot allocate certificate buffer");
    size_t length = 0;
    int status = sg_certificate_der_impl(ctx, slot, id, id_length, der, 65536, &length, error, error_size);
    if (!status && (length != expected_length || memcmp(der, expected, length)))
        status = invalid(error, error_size, "Il certificato è cambiato. Ricarica i certificati prima di firmare.");
    if (!status) {
        SGCertificateAssessment assessment = sg_certificate_assess(der, length, sg_certificate_now());
        if (assessment.status != SG_CERT_ELIGIBLE) {
            uint32_t first = assessment.reasons & (0u - assessment.reasons);
            status = invalid(error, error_size, sg_certificate_reason_message(first));
        }
    }
    free(der); return status;
}
#define CHECKED_SIGN(name, implementation) \
int name(SGContext *ctx, unsigned long slot, const uint8_t *id, size_t id_length, \
    const uint8_t *expected, size_t expected_length, const uint8_t *pin, size_t pin_length, \
    const uint8_t *message, size_t message_length, uint8_t *signature, size_t capacity, \
    size_t *length, char *error, size_t error_size) { \
    if (length) *length = 0; \
    if (enter(ctx, error, error_size)) return -1; \
    int status = check_signing_certificate(ctx, slot, id, id_length, expected, expected_length, error, error_size); \
    if (!status) status = implementation(ctx, slot, id, id_length, pin, pin_length, message, message_length, signature, capacity, length, expected, expected_length, error, error_size); \
    if (status && signature && capacity) memset(signature, 0, capacity); \
    pthread_mutex_unlock(&ctx->provider->operations); \
    return status; \
}
CHECKED_SIGN(sg_sign_test_checked, sg_sign_test_impl)
CHECKED_SIGN(sg_sign_encoded_digest_checked, sg_sign_encoded_digest_impl)

/* Dedicated worker owns this context and its lease for the entire batch. */
struct SGBatchSession {
    SGContext *ctx;
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot;
    CK_TOKEN_INFO token;
    uint8_t id[64], der[65536];
    size_t id_length, der_length;
    int reusable, failed, temporary_pin, auth_known;
    CK_BBOOL auth; CK_OBJECT_HANDLE key;
    double pin_deadline;
};
static int batch_token(SGBatchSession *s, int initial, const char *serial, char *error, size_t size) {
    CK_TOKEN_INFO token;
    CK_RV rv = s->ctx->api->C_GetTokenInfo(s->slot, &token);
    if (rv != CKR_OK) return failed(error, size, "C_GetTokenInfo batch", rv);
    if (initial) {
        char value[17]; copy_padded(value, sizeof(value), (const unsigned char *)token.serialNumber, sizeof(token.serialNumber));
        if (!serial || !*serial || strcmp(value, serial)) return invalid(error, size, "Selected token identity changed or unavailable");
        s->token = token;
    } else if (memcmp(token.serialNumber, s->token.serialNumber, sizeof(token.serialNumber)) ||
               memcmp(token.label, s->token.label, sizeof(token.label)) ||
               memcmp(token.manufacturerID, s->token.manufacturerID, sizeof(token.manufacturerID)) ||
               memcmp(token.model, s->token.model, sizeof(token.model))) return invalid(error, size, "Batch token replaced");
    return 0;
}
static int batch_certificate(SGBatchSession *s, char *error, size_t size) {
    CK_OBJECT_HANDLE certificate;
    int status = find_one(s->ctx, s->handle, CKO_CERTIFICATE, s->id, s->id_length, &certificate, error, size);
    if (status) return status;
    uint8_t actual[65536];
    CK_ATTRIBUTE attr = { CKA_VALUE, actual, sizeof(actual) };
    CK_RV rv = s->ctx->api->C_GetAttributeValue(s->handle, certificate, &attr, 1);
    if (rv != CKR_OK) return failed(error, size, "Batch certificate DER", rv);
    if (attr.ulValueLen != s->der_length || memcmp(actual, s->der, s->der_length)) return invalid(error, size, "Batch certificate replaced");
    SGCertificateAssessment assessment = sg_certificate_assess(actual, attr.ulValueLen, sg_certificate_now());
    return assessment.status == SG_CERT_ELIGIBLE ? 0 : invalid(error, size, "Batch certificate no longer locally eligible");
}
double sg_batch_monotonic_now(void) {
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) ? -1 : now.tv_sec + now.tv_nsec / 1e9;
}
static int batch_pin_current(SGBatchSession *s) {
    if (!s->temporary_pin) return 1;
    double now = sg_batch_monotonic_now();
    return now >= 0 && now < s->pin_deadline;
}
static int batch_sign(SGBatchSession *s, int first, const uint8_t *pin, size_t pin_length,
    const uint8_t *message, size_t message_length, uint8_t *signature, size_t capacity, size_t *length, char *error, size_t size) {
    if (!message || !message_length || message_length > 4096 || !signature || capacity < 8192 || !length || s->failed)
        return invalid(error, size, "Invalid/retired batch signature request");
    *length = 0;
    int status = batch_token(s, 0, NULL, error, size);
    CK_SESSION_INFO info;
    CK_RV rv;
    if (!status) {
        rv = s->ctx->api->C_GetSessionInfo(s->handle, &info);
        if (rv != CKR_OK) status = failed(error, size, "Batch session info", rv);
        else if (info.slotID != s->slot || (info.state != CKS_RO_USER_FUNCTIONS && info.state != CKS_RW_USER_FUNCTIONS))
            status = invalid(error, size, "Batch USER session lost; no automatic reauthentication");
    }
    if (!status) status = batch_certificate(s, error, size);
    CK_OBJECT_HANDLE key;
    if (!status) status = find_one(s->ctx, s->handle, CKO_PRIVATE_KEY, s->id, s->id_length, &key, error, size);
    CK_BBOOL auth = CK_FALSE; int known = 0;
    if (!status) {
        CK_ATTRIBUTE attribute = { CKA_ALWAYS_AUTHENTICATE, &auth, sizeof(auth) };
        rv = s->ctx->api->C_GetAttributeValue(s->handle, key, &attribute, 1);
        known = rv == CKR_OK && attribute.ulValueLen == sizeof(auth) && (auth == CK_FALSE || auth == CK_TRUE);
        if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID && rv != CKR_ATTRIBUTE_SENSITIVE)
            status = failed(error, size, "Batch authentication attribute", rv);
        if (!first && (!known || !s->auth_known || auth != s->auth || key != s->key || !s->reusable))
            status = invalid(error, size, "Batch key or authentication policy changed");
        if (!first && known && auth == CK_TRUE && (!s->temporary_pin || !pin || !pin_length))
            status = invalid(error, size, "Missing authorized batch authentication");
        if (!status && !batch_pin_current(s)) status = invalid(error, size, "Batch PIN expired");
        if (first) { s->auth_known = known; s->auth = auth; s->key = key; }
    }
    if (!status) {
        CK_MECHANISM mechanism = { CKM_SHA256_RSA_PKCS, NULL, 0 };
        rv = s->ctx->api->C_SignInit(s->handle, &mechanism, key);
        if (rv != CKR_OK) status = failed(error, size, "Batch C_SignInit", rv);
        if (!status && known && auth == CK_TRUE) {
            if (!batch_pin_current(s)) status = invalid(error, size, "Batch PIN expired before authentication");
            rv = status ? CKR_GENERAL_ERROR : s->ctx->api->C_Login(s->handle, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)pin, pin_length);
            if (rv != CKR_OK) status = failed(error, size, "Batch C_Login CONTEXT_SPECIFIC (no retry)", rv);
        }
        if (!status && !batch_pin_current(s)) status = invalid(error, size, "Batch PIN expired before Sign");
        if (!status) {
            CK_ULONG count = capacity;
            rv = s->ctx->api->C_Sign(s->handle, (CK_BYTE_PTR)message, message_length, signature, &count);
            if (rv != CKR_OK || !count || count > capacity) status = failed(error, size, "Batch C_Sign (no retry)", rv == CKR_OK ? CKR_GENERAL_ERROR : rv);
            else *length = count;
        }
        if (first) s->reusable = known && (auth == CK_FALSE || s->temporary_pin) && s->ctx->provider->owns_initialization;
    }
    if (status) { s->failed = 1; memset(signature, 0, capacity); *length = 0; }
    return status;
}
static int batch_first(SGContext *ctx, unsigned long slot, const char *serial, const uint8_t *id, size_t id_length,
    const uint8_t *der, size_t der_length, const uint8_t *pin, size_t pin_length, const uint8_t *message, size_t message_length,
    SGBatchSession **out, int *reusable, uint8_t *signature, size_t capacity, size_t *length, char *error, size_t size, int temporary_pin, double pin_deadline) {
    if (length) *length = 0;
    if (!out || !reusable || !signature || capacity < 8192 || !length || !message || !message_length || message_length > 4096 || !id || !id_length || id_length > 64 || !der || !der_length || der_length > 65536 || !pin || !pin_length || pin_length > 64)
        return invalid(error, size, "Invalid first batch request");
    *out = NULL; *reusable = 0;
    if (enter(ctx, error, size)) return -1;
    SGBatchSession *s = calloc(1, sizeof(*s));
    int status = s ? 0 : invalid(error, size, "Cannot allocate batch session");
    if (s) {
        s->ctx = ctx; s->slot = slot; s->temporary_pin = temporary_pin; s->pin_deadline = pin_deadline; s->id_length = id_length; s->der_length = der_length;
        memcpy(s->id, id, id_length); memcpy(s->der, der, der_length);
        status = batch_token(s, 1, serial, error, size);
        if (!status) status = open_session(ctx, slot, &s->handle, error, size);
        if (!status) {
            status = batch_certificate(s, error, size);
            if (!status && !batch_pin_current(s)) status = invalid(error, size, "Batch PIN expired before USER login");
            if (!status) status = login_user(ctx, s->handle, pin, pin_length, error, size);
            if (!status) status = batch_sign(s, 1, pin, pin_length, message, message_length, signature, capacity, length, error, size);
            if (temporary_pin) {
                /* Return cleanup ownership even on error: worker must erase
                 * the PIN BEFORE potentially blocking CloseSession/Finalize. */
                if (status) s->failed = 1;
                *out = s; *reusable = !status && s->reusable;
            } else if (!status && s->reusable) { *out = s; *reusable = 1; }
            else { status = close_session(ctx, s->handle, status, error, size); free(s); }
        } else free(s);
    }
    pthread_mutex_unlock(&ctx->provider->operations);
    return status;
}
int sg_batch_first(SGContext *ctx, unsigned long slot, const char *serial, const uint8_t *id, size_t id_length,
    const uint8_t *der, size_t der_length, const uint8_t *pin, size_t pin_length, const uint8_t *message, size_t message_length,
    SGBatchSession **out, int *reusable, uint8_t *signature, size_t capacity, size_t *length, char *error, size_t size) {
    return batch_first(ctx, slot, serial, id, id_length, der, der_length, pin, pin_length, message, message_length,
        out, reusable, signature, capacity, length, error, size, 0, 0);
}
int sg_batch_first_temporary(SGContext *ctx, unsigned long slot, const char *serial, const uint8_t *id, size_t id_length,
    const uint8_t *der, size_t der_length, const uint8_t *pin, size_t pin_length, double deadline,
    const uint8_t *message, size_t message_length, SGBatchSession **out, int *reusable,
    uint8_t *signature, size_t capacity, size_t *length, char *error, size_t size) {
    if (!isfinite(deadline) || deadline <= 0) return invalid(error, size, "Invalid PIN deadline");
    return batch_first(ctx, slot, serial, id, id_length, der, der_length, pin, pin_length, message, message_length,
        out, reusable, signature, capacity, length, error, size, 1, deadline);
}
int sg_batch_requires_pin(SGBatchSession *s) {
    return s && !s->failed && s->reusable && s->temporary_pin && s->auth_known && s->auth == CK_TRUE;
}
int sg_batch_next_temporary(SGBatchSession *s, const uint8_t *pin, size_t pin_length,
    const uint8_t *message, size_t message_length, uint8_t *signature,
    size_t capacity, size_t *length, char *error, size_t size) {
    if (!s || !s->temporary_pin || pin_length > 64 || enter(s->ctx, error, size)) return -1;
    int status = batch_sign(s, 0, pin, pin_length, message, message_length, signature, capacity, length, error, size);
    pthread_mutex_unlock(&s->ctx->provider->operations); return status;
}
int sg_batch_next(SGBatchSession *s, const uint8_t *message, size_t message_length, uint8_t *signature,
    size_t capacity, size_t *length, char *error, size_t size) {
    if (!s || enter(s->ctx, error, size)) return -1;
    int status = batch_sign(s, 0, NULL, 0, message, message_length, signature, capacity, length, error, size);
    pthread_mutex_unlock(&s->ctx->provider->operations); return status;
}
int sg_batch_close(SGBatchSession *s, char *error, size_t size) {
    if (!s) return 0;
    SGContext *ctx = s->ctx;
    if (enter(ctx, error, size)) { free(s); return -1; }
    int status = close_session(ctx, s->handle, 0, error, size);
    pthread_mutex_unlock(&ctx->provider->operations); free(s); return status;
}
