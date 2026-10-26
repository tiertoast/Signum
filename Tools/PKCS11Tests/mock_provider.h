#pragma once
#include "pkcs11.h"
#ifdef __cplusplus
extern "C" {
#endif
enum { M_INIT, M_FINALIZE, M_SLOT_LIST, M_TOKEN_INFO, M_SLOT_INFO, M_OPEN, M_CLOSE,
       M_SESSION_INFO, M_LOGIN_USER, M_LOGIN_CONTEXT, M_LOGOUT, M_FIND_INIT,
       M_FIND, M_FIND_FINAL, M_ATTRIBUTE, M_SIGN_INIT, M_SIGN,
#ifdef SIGNUM_MOCK_PIN_ADMIN
       M_SET_PIN, M_UNBLOCK_PIN,
#endif
       M_COUNT };
#ifdef SIGNUM_MOCK_PIN_ADMIN
void mock_pin_status(CK_FLAGS flags, CK_ULONG minimum, CK_ULONG maximum);
/* Explicit synthetic PUK backend. Does not claim PKCS#11 SO/PUK equivalence. */
CK_RV mock_unblock_pin(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG);
#endif
typedef struct {
    unsigned calls[M_COUNT];
    unsigned active_calls, maximum_calls, sessions, maximum_sessions;
    int initialized, logged_in;
    unsigned finalize_on_main;
    CK_FLAGS initialize_flags;
    CK_MECHANISM_TYPE last_mechanism;
} MockStats;
void mock_certificate_der(const unsigned char *bytes, size_t length);
void mock_replace_certificate(const unsigned char *bytes, size_t length, unsigned after_reads);
void mock_after_user_login(int action);
void mock_return_length(int operation, unsigned long length);
void mock_stats(MockStats *stats);
unsigned mock_call_count(int operation);
unsigned mock_finalize_on_main(void);
void mock_fail(int operation, CK_RV result);
void mock_preinitialized(int value);
void mock_shared_login(int value);
void mock_always_authenticate(int value);
void mock_delay(unsigned microseconds);
void mock_block(int operation);
int mock_wait_blocked(void);
void mock_release(void);
#ifdef __cplusplus
}
#endif
