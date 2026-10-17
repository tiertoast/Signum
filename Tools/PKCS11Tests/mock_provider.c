// Test-only PKCS#11 provider. No device, PIN validation or real cryptography.
#include "mock_provider.h"
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static MockStats stats;
static CK_RV faults[M_COUNT];
static unsigned delay_us;
static unsigned char certificate_bytes[65536], replacement_bytes[65536];
static size_t certificate_length, replacement_length;
static unsigned certificate_reads, replace_after;
void mock_certificate_der(const unsigned char *bytes, size_t length) {
    pthread_mutex_lock(&mutex);
    if (bytes && length && length <= sizeof(certificate_bytes)) {
        memcpy(certificate_bytes, bytes, length); certificate_length = length;
        certificate_reads = 0; replacement_length = 0;
    }
    pthread_mutex_unlock(&mutex);
}
void mock_replace_certificate(const unsigned char *bytes, size_t length, unsigned after_reads) {
    pthread_mutex_lock(&mutex);
    if (bytes && length && length <= sizeof(replacement_bytes)) {
        memcpy(replacement_bytes, bytes, length); replacement_length = length; replace_after = after_reads;
    }
    pthread_mutex_unlock(&mutex);
}
static int blocked_operation = -1, blocked, released, always_auth, external_session;
typedef struct { int active, delivered; CK_OBJECT_CLASS kind; } Session;
static Session sessions[512];
static CK_ULONG next_session = 1;
void mock_stats(MockStats *out) { pthread_mutex_lock(&mutex); *out = stats; pthread_mutex_unlock(&mutex); }
unsigned mock_call_count(int op) { pthread_mutex_lock(&mutex); unsigned count = stats.calls[op]; pthread_mutex_unlock(&mutex); return count; }
unsigned mock_finalize_on_main(void) { pthread_mutex_lock(&mutex); unsigned value = stats.finalize_on_main; pthread_mutex_unlock(&mutex); return value; }
void mock_fail(int op, CK_RV rv) { pthread_mutex_lock(&mutex); faults[op] = rv; pthread_mutex_unlock(&mutex); }
void mock_preinitialized(int value) { pthread_mutex_lock(&mutex); stats.initialized = value; pthread_mutex_unlock(&mutex); }
void mock_shared_login(int value) { pthread_mutex_lock(&mutex); stats.logged_in = value; external_session = value; pthread_mutex_unlock(&mutex); }
void mock_always_authenticate(int value) { pthread_mutex_lock(&mutex); always_auth = value; pthread_mutex_unlock(&mutex); }
void mock_delay(unsigned value) { pthread_mutex_lock(&mutex); delay_us = value; pthread_mutex_unlock(&mutex); }
void mock_block(int op) { pthread_mutex_lock(&mutex); blocked_operation = op; blocked = released = 0; pthread_mutex_unlock(&mutex); }
int mock_wait_blocked(void) {
    struct timespec deadline; clock_gettime(CLOCK_REALTIME, &deadline); deadline.tv_sec += 3;
    pthread_mutex_lock(&mutex);
    int rv = 0; while (!blocked && !rv) rv = pthread_cond_timedwait(&condition, &mutex, &deadline);
    int result = blocked; pthread_mutex_unlock(&mutex); return result;
}
void mock_release(void) { pthread_mutex_lock(&mutex); released = 1; blocked_operation = -1; pthread_cond_broadcast(&condition); pthread_mutex_unlock(&mutex); }
static CK_RV begin(int op) {
    pthread_mutex_lock(&mutex);
    ++stats.calls[op]; ++stats.active_calls;
    if (op == M_FINALIZE) stats.finalize_on_main = pthread_main_np() ? 1 : 0;
    if (stats.active_calls > stats.maximum_calls) stats.maximum_calls = stats.active_calls;
    while (blocked_operation == op && !released) { blocked = 1; pthread_cond_broadcast(&condition); pthread_cond_wait(&condition, &mutex); }
    unsigned delay = delay_us;
    pthread_mutex_unlock(&mutex);
    if (delay) usleep(delay);
    pthread_mutex_lock(&mutex); // caller keeps this lock until end()
    if (op == M_SIGN && faults[op] == CKR_DEVICE_REMOVED) {
        memset(sessions, 0, sizeof(sessions)); stats.sessions = 0; stats.logged_in = 0;
    }
    return faults[op];
}
static CK_RV end(CK_RV rv) { --stats.active_calls; pthread_mutex_unlock(&mutex); return rv; }
#define BEGIN(op) CK_RV injected = begin(op); if (injected != CKR_OK) return end(injected)
#define VALID(h) if ((h) >= 512 || !sessions[h].active) return end(CKR_SESSION_HANDLE_INVALID)
static CK_RV initialize(void *args) {
    BEGIN(M_INIT);
    stats.initialize_flags = args ? ((CK_C_INITIALIZE_ARGS_PTR)args)->flags : 0;
    if (stats.initialized) return end(CKR_CRYPTOKI_ALREADY_INITIALIZED);
    stats.initialized = 1; return end(CKR_OK);
}
static CK_RV finalize(void *unused) {
    (void)unused; BEGIN(M_FINALIZE);
    if (!stats.initialized) return end(CKR_CRYPTOKI_NOT_INITIALIZED);
    stats.initialized = stats.logged_in = 0; stats.sessions = 0;
    memset(sessions, 0, sizeof(sessions)); return end(CKR_OK);
}
static CK_RV slots(CK_BBOOL present, CK_SLOT_ID_PTR out, CK_ULONG_PTR n) {
    (void)present; BEGIN(M_SLOT_LIST);
    if (!stats.initialized) return end(CKR_CRYPTOKI_NOT_INITIALIZED);
    if (out && *n < 1) { *n = 1; return end(CKR_BUFFER_TOO_SMALL); }
    if (out) out[0] = 7; *n = 1; return end(CKR_OK);
}
static CK_RV token(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR out) {
    (void)slot; BEGIN(M_TOKEN_INFO); memset(out, ' ', sizeof(*out));
    memcpy(out->label, "Signum Mock", 11); memcpy(out->model, "Synthetic", 9);
    memcpy(out->manufacturerID, "Offline fixture", 15); return end(CKR_OK);
}
static CK_RV slot_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR out) {
    (void)slot; BEGIN(M_SLOT_INFO); memset(out, ' ', sizeof(*out));
    memcpy(out->slotDescription, "Synthetic reader", 16); return end(CKR_OK);
}
static CK_RV open_session(CK_SLOT_ID slot, CK_FLAGS flags, void *app, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR out) {
    (void)slot; (void)flags; (void)app; (void)notify; BEGIN(M_OPEN);
    if (!stats.initialized) return end(CKR_CRYPTOKI_NOT_INITIALIZED);
    if (next_session >= 512) return end(CKR_SESSION_COUNT);
    *out = next_session++; sessions[*out].active = 1;
    ++stats.sessions; if (stats.sessions > stats.maximum_sessions) stats.maximum_sessions = stats.sessions;
    return end(CKR_OK);
}
static CK_RV close_session(CK_SESSION_HANDLE h) {
    BEGIN(M_CLOSE); VALID(h); sessions[h].active = 0; --stats.sessions;
    if (!stats.sessions && !external_session) stats.logged_in = 0;
    return end(CKR_OK);
}
static CK_RV session_info(CK_SESSION_HANDLE h, CK_SESSION_INFO_PTR out) {
    BEGIN(M_SESSION_INFO); VALID(h); memset(out, 0, sizeof(*out));
    out->slotID = 7; out->state = stats.logged_in ? CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;
    out->flags = CKF_SERIAL_SESSION; return end(CKR_OK);
}
static CK_RV login(CK_SESSION_HANDLE h, CK_USER_TYPE user, CK_UTF8CHAR_PTR value, CK_ULONG length) {
    (void)value; (void)length; // deliberately never inspect, store or log credentials
    BEGIN(user == CKU_CONTEXT_SPECIFIC ? M_LOGIN_CONTEXT : M_LOGIN_USER); VALID(h);
    if (user == CKU_USER) {
        if (stats.logged_in) return end(CKR_USER_ALREADY_LOGGED_IN);
        stats.logged_in = 1;
    }
    return end(CKR_OK);
}
static CK_RV logout(CK_SESSION_HANDLE h) { BEGIN(M_LOGOUT); VALID(h); stats.logged_in = 0; return end(CKR_OK); }
static CK_RV find_init(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG n) {
    BEGIN(M_FIND_INIT); VALID(h); sessions[h].delivered = 0;
    for (CK_ULONG i = 0; i < n; ++i) if (attrs[i].type == CKA_CLASS) sessions[h].kind = *(CK_OBJECT_CLASS*)attrs[i].pValue;
    return end(CKR_OK);
}
static CK_RV find_objects(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE_PTR out, CK_ULONG max, CK_ULONG_PTR count) {
    (void)max; BEGIN(M_FIND); VALID(h); *count = sessions[h].delivered ? 0 : 1;
    if (*count) *out = sessions[h].kind == CKO_CERTIFICATE ? 1 : 2;
    sessions[h].delivered = 1; return end(CKR_OK);
}
static CK_RV find_final(CK_SESSION_HANDLE h) { BEGIN(M_FIND_FINAL); VALID(h); return end(CKR_OK); }
static CK_RV attribute(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    (void)obj; BEGIN(M_ATTRIBUTE); VALID(h);
    static const unsigned char der[] = {0x30,0x03,0x02,0x01,0x01}, id[] = {0x53};
    CK_BBOOL auth = always_auth ? CK_TRUE : CK_FALSE;
    for (CK_ULONG i = 0; i < count; ++i) {
        const void *value = NULL; size_t n = 0;
        switch (attrs[i].type) {
        case CKA_LABEL: value = "Synthetic certificate"; n = 21; break;
        case CKA_ID: value = id; n = sizeof(id); break;
        case CKA_VALUE:
            if (replacement_length && certificate_reads >= replace_after) {
                memcpy(certificate_bytes, replacement_bytes, replacement_length);
                certificate_length = replacement_length; replacement_length = 0;
            }
            value = certificate_length ? certificate_bytes : der;
            n = certificate_length ? certificate_length : sizeof(der);
            if (attrs[i].pValue) ++certificate_reads;
            break;
        case CKA_ALWAYS_AUTHENTICATE: value = &auth; n = sizeof(auth); break;
        default: return end(CKR_ATTRIBUTE_TYPE_INVALID);
        }
        if (attrs[i].pValue) {
            if (attrs[i].ulValueLen < n) { attrs[i].ulValueLen = n; return end(CKR_BUFFER_TOO_SMALL); }
            memcpy(attrs[i].pValue, value, n);
        }
        attrs[i].ulValueLen = n;
    }
    return end(CKR_OK);
}
static CK_RV sign_init(CK_SESSION_HANDLE h, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
    (void)key; BEGIN(M_SIGN_INIT); VALID(h); stats.last_mechanism = mechanism->mechanism; return end(CKR_OK);
}
static CK_RV sign(CK_SESSION_HANDLE h, CK_BYTE_PTR bytes, CK_ULONG n, CK_BYTE_PTR signature, CK_ULONG_PTR length) {
    (void)bytes; (void)n; BEGIN(M_SIGN); VALID(h);
    if (*length < 32) return end(CKR_BUFFER_TOO_SMALL);
    memset(signature, 0x53, 32); *length = 32; return end(CKR_OK);
}
static CK_FUNCTION_LIST functions = {
    .version = {2,40}, .C_Initialize = initialize, .C_Finalize = finalize,
    .C_GetSlotList = slots, .C_GetTokenInfo = token, .C_GetSlotInfo = slot_info,
    .C_OpenSession = open_session, .C_CloseSession = close_session, .C_GetSessionInfo = session_info,
    .C_Login = login, .C_Logout = logout, .C_FindObjectsInit = find_init,
    .C_FindObjects = find_objects, .C_FindObjectsFinal = find_final,
    .C_GetAttributeValue = attribute, .C_SignInit = sign_init, .C_Sign = sign
};
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) { *out = &functions; return CKR_OK; }
