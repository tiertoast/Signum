#pragma once
#include "pkcs11.h"
#ifdef __cplusplus
extern "C" {
#endif
enum { M_INIT, M_FINALIZE, M_SLOT_LIST, M_TOKEN_INFO, M_SLOT_INFO, M_OPEN, M_CLOSE,
       M_SESSION_INFO, M_LOGIN_USER, M_LOGIN_CONTEXT, M_LOGOUT, M_FIND_INIT,
       M_FIND, M_FIND_FINAL, M_ATTRIBUTE, M_SIGN_INIT, M_SIGN, M_COUNT };
typedef struct {
    unsigned calls[M_COUNT];
    unsigned active_calls, maximum_calls, sessions, maximum_sessions;
    int initialized, logged_in;
    unsigned finalize_on_main;
    CK_FLAGS initialize_flags;
    CK_MECHANISM_TYPE last_mechanism;
} MockStats;
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
