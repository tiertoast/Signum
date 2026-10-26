/* Linked solely to the existing synthetic provider, never dlopen a middleware.
 * Every case runs in a fresh child; test credentials are non-secret fixtures. */
#include "SignumPINManagement.h"
#include "mock_provider.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <poll.h>
#include <signal.h>

static int allocation_fail_after = -1;
static int dispatch_notice_fd = -1;
/* Only the test object for secure_pin.c redirects mlock to this function. */
int sg_pin_test_mlock(const void *p, size_t n) {
    if (allocation_fail_after == 0) return -1;
    if (allocation_fail_after > 0) --allocation_fail_after;
    return mlock(p, n);
}
#ifndef __APPLE__
int pthread_main_np(void) { return 0; } /* Test instrumentation compatibility. */
#endif
typedef struct {
    SGPINAttempt *attempt;
    SGPINSecrets *secrets;
    CK_FUNCTION_LIST_PTR api;
    uint8_t request[16], binding[32];
    int action;
} Fixture;
static Fixture fixture(int action) {
    Fixture f = {0}; f.action = action; f.request[0] = 0x12; f.binding[0] = 0x34;
    f.attempt = sg_pin_attempt_create(f.request, f.binding, action); assert(f.attempt);
    f.secrets = sg_pin_secrets_create(); assert(f.secrets);
    const uint8_t old[] = "SYNTH-OLD", next[] = "SYNTH-NEW";
    assert(!sg_pin_secrets_set(f.secrets, SG_PIN_SOURCE, old, sizeof(old)-1));
    assert(!sg_pin_secrets_set(f.secrets, SG_PIN_NEW, next, sizeof(next)-1));
    assert(!sg_pin_secrets_set(f.secrets, SG_PIN_CONFIRMATION, next, sizeof(next)-1));
    assert(!sg_pin_secrets_validate_local(f.secrets, 4, 64));
    assert(C_GetFunctionList(&f.api) == CKR_OK);
    assert(f.api->C_Initialize(NULL) == CKR_OK);
    return f;
}
static void clear_and_assert(Fixture *f) {
    const uint8_t *previous[3];
    for (int i=0; i<3; ++i) previous[i] = sg_pin_test_secret_bytes(f->secrets, i);
    sg_pin_secrets_clear(f->secrets);
    for (int i=0; i<3; ++i) {
        assert(sg_pin_test_secret_length(f->secrets,i) == 0);
        if (previous[i]) for (int j=0; j<64; ++j) assert(previous[i][j] == 0);
    }
}
static void dispose(Fixture *f) {
    clear_and_assert(f); sg_pin_secrets_destroy(f->secrets); sg_pin_attempt_destroy(f->attempt);
}
static unsigned mutations(void) { return mock_call_count(M_SET_PIN) + mock_call_count(M_UNBLOCK_PIN); }
static void ready(Fixture *f) {
    assert(!sg_pin_attempt_approve(f->attempt, f->request, f->binding, f->action));
    assert(!sg_pin_attempt_ready(f->attempt, 1, 1, 1, 0));
}
/* Sole mutating harness: direct static synthetic function table, no path or
 * backend selector. Neither compiled nor copied into the product target. */
static void synthetic_dispatch(Fixture *f, int lose_response) {
    if (sg_pin_attempt_state(f->attempt) != SG_PIN_READY) { clear_and_assert(f); return; }
    CK_SESSION_HANDLE h;
    CK_RV opened = f->api->C_OpenSession(7, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &h);
    if (opened != CKR_OK) { sg_pin_attempt_abort(f->attempt); clear_and_assert(f); return; }
    assert(!sg_pin_attempt_mark_dispatched(f->attempt));
    if (dispatch_notice_fd >= 0) assert(write(dispatch_notice_fd,"D",1)==1);
    CK_UTF8CHAR_PTR source = (CK_UTF8CHAR_PTR)sg_pin_test_secret_bytes(f->secrets, SG_PIN_SOURCE);
    CK_UTF8CHAR_PTR next = (CK_UTF8CHAR_PTR)sg_pin_test_secret_bytes(f->secrets, SG_PIN_NEW);
    CK_ULONG source_n = sg_pin_test_secret_length(f->secrets, SG_PIN_SOURCE);
    CK_ULONG next_n = sg_pin_test_secret_length(f->secrets, SG_PIN_NEW);
    CK_RV rv = f->action == SG_PIN_CHANGE ? f->api->C_SetPIN(h, source, source_n, next, next_n) :
        mock_unblock_pin(h, source, source_n, next, next_n);
    clear_and_assert(f); /* Before any provider cleanup, even when it fails. */
    CK_RV cleanup = f->api->C_CloseSession(h);
    if (lose_response || rv == CKR_DEVICE_REMOVED || rv == CKR_DEVICE_ERROR || rv == CKR_GENERAL_ERROR) sg_pin_attempt_abort(f->attempt);
    else sg_pin_attempt_finish(f->attempt, rv == CKR_OK, cleanup == CKR_OK);
}
static void send_frame(int fd, Fixture *f, int malformed) {
    uint8_t header[56] = {'S','P','I','N',1,0,0,0}; header[5] = f->action;
    memcpy(header+8, f->request,16); memcpy(header+24, f->binding,32);
    if (malformed == 1) header[8] ^= 1;
    if (malformed == 4) header[4] = 2;
    assert(write(fd,header,sizeof(header)) == sizeof(header));
    uint8_t bytes[] = {0,0,0,4,'T','E','S','T'};
    if (malformed == 3) bytes[3] = 65;
    assert(write(fd, bytes, sizeof(bytes)) == sizeof(bytes));
    if (malformed != 2) assert(write(fd,bytes,sizeof(bytes)) == sizeof(bytes));
}
static void subprocess_failure(Fixture *f, int kind) {
    int p[2];assert(!pipe(p));ready(f);
    pid_t child=fork();assert(child>=0);
    if(!child){
        close(p[0]);
        if(kind==0) for(;;) pause();
        dispatch_notice_fd=p[1];
        if(kind==1) mock_block(M_SET_PIN);
        synthetic_dispatch(f,0);
        assert(mutations()==1); /* One real call into the synthetic provider. */
        _exit(0); /* Deliberately lose the result after synthetic success. */
    }
    close(p[1]);clear_and_assert(f);
    struct pollfd descriptor={p[0],POLLIN,0};
    int readable=poll(&descriptor,1,1000);
    if(kind==0) assert(readable==0);
    else {
        char marker=0;assert(readable>0&&read(p[0],&marker,1)==1&&marker=='D');
        assert(!sg_pin_attempt_mark_dispatched(f->attempt));
        if(kind==1) assert(poll(&descriptor,1,50)==0);
    }
    if(kind!=2) assert(!kill(child,SIGKILL));
    int status;assert(waitpid(child,&status,0)==child);close(p[0]);
    if(kind==2) assert(WIFEXITED(status)&&!WEXITSTATUS(status));
    else assert(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
    sg_pin_attempt_abort(f->attempt);
    assert(sg_pin_attempt_state(f->attempt)==(kind==0?SG_PIN_NOT_EXECUTED:SG_PIN_UNCERTAIN));
    assert(sg_pin_attempt_approve(f->attempt,f->request,f->binding,f->action));
    assert(!sg_pin_attempt_create(f->request,f->binding,f->action));
    assert(!mutations()); /* Parent never retries a child command. */
}
static void run_case(int n) {
    if (n == 28 || n == 29) {
        allocation_fail_after = n == 28 ? 0 : 1;
        assert(sg_pin_secrets_create() == NULL); return;
    }
    Fixture f = fixture(n == 2 || n == 3 ? SG_PIN_UNBLOCK : SG_PIN_CHANGE);
    switch (n) {
    case 0: ready(&f); synthetic_dispatch(&f,0); assert(sg_pin_attempt_state(f.attempt) == SG_PIN_SUCCEEDED); break;
    case 1: ready(&f); mock_fail(M_SET_PIN,CKR_PIN_INCORRECT); synthetic_dispatch(&f,0); assert(sg_pin_attempt_state(f.attempt) == SG_PIN_REJECTED); break;
    case 2: ready(&f); mock_fail(M_UNBLOCK_PIN,CKR_PIN_INCORRECT); synthetic_dispatch(&f,0); assert(sg_pin_attempt_state(f.attempt) == SG_PIN_REJECTED); break;
    case 3: ready(&f); mock_fail(M_UNBLOCK_PIN,CKR_PIN_LOCKED); synthetic_dispatch(&f,0); assert(sg_pin_attempt_state(f.attempt) == SG_PIN_REJECTED); break;
    case 4: ready(&f); mock_fail(M_OPEN,CKR_SESSION_READ_ONLY); synthetic_dispatch(&f,0); assert(!mutations()); assert(sg_pin_attempt_state(f.attempt) == SG_PIN_NOT_EXECUTED); break;
    case 5: /* Removed device during independent revalidation. */
        assert(!sg_pin_attempt_approve(f.attempt,f.request,f.binding,f.action));
        assert(sg_pin_attempt_ready(f.attempt,0,1,1,0)); assert(!mutations()); break;
    case 6: f.binding[0] ^= 1; assert(sg_pin_attempt_approve(f.attempt,f.request,f.binding,f.action)); assert(!mutations()); break;
    case 7:
        assert(!sg_pin_attempt_approve(f.attempt,f.request,f.binding,f.action));
        assert(sg_pin_attempt_ready(f.attempt,1,1,0,0)); assert(!mutations()); break;
    case 8: ready(&f); sg_pin_attempt_abort(f.attempt); assert(sg_pin_attempt_state(f.attempt) == SG_PIN_NOT_EXECUTED); synthetic_dispatch(&f,0); assert(!mutations()); break;
    case 9: ready(&f); assert(!sg_pin_attempt_mark_dispatched(f.attempt)); sg_pin_attempt_abort(f.attempt); assert(sg_pin_attempt_state(f.attempt) == SG_PIN_UNCERTAIN); assert(sg_pin_attempt_mark_dispatched(f.attempt)); break;
    case 10: ready(&f); synthetic_dispatch(&f,1); assert(sg_pin_attempt_state(f.attempt) == SG_PIN_UNCERTAIN); synthetic_dispatch(&f,0); assert(mutations()==1); break;
    case 11: ready(&f); synthetic_dispatch(&f,0); synthetic_dispatch(&f,0); assert(mutations()==1); assert(sg_pin_attempt_mark_dispatched(f.attempt)); break;
    case 12:
        assert(!sg_pin_attempt_approve(f.attempt,f.request,f.binding,f.action));
        assert(sg_pin_attempt_ready(f.attempt,1,1,1,1)); synthetic_dispatch(&f,0); assert(!mutations()); break;
    case 13: ready(&f); mock_fail(M_CLOSE,CKR_GENERAL_ERROR); synthetic_dispatch(&f,0); assert(sg_pin_attempt_state(f.attempt)==SG_PIN_SUCCEEDED); assert(sg_pin_attempt_cleanup_failed(f.attempt)); break;
    case 14: assert(!sg_pin_secrets_set(f.secrets,SG_PIN_CONFIRMATION,(const uint8_t *)"DIFFERENT",9)); assert(sg_pin_secrets_validate_local(f.secrets,4,64)); assert(!mutations()); break;
    case 15: { uint8_t bytes[65]; memset(bytes,'X',65); assert(sg_pin_secrets_set(f.secrets,SG_PIN_SOURCE,bytes,65)); break; }
    case 16: { uint8_t bytes[3]={'X',0,'Y'}; assert(sg_pin_secrets_set(f.secrets,SG_PIN_NEW,bytes,3)); break; }
    case 17: case 18: case 19: case 20: case 24: {
        int p[2]; assert(!pipe(p)); int kind = n==24 ? 4 : n-17;
        send_frame(p[1],&f,kind); close(p[1]);
        int result = sg_pin_secrets_receive(f.secrets,p[0],f.request,f.binding,f.action); close(p[0]);
        if (!kind) { assert(!result); assert(sg_pin_test_secret_length(f.secrets,SG_PIN_SOURCE)==4); assert(sg_pin_test_secret_length(f.secrets,SG_PIN_NEW)==4); }
        else { assert(result); for(int i=0;i<3;++i) assert(!sg_pin_test_secret_length(f.secrets,i)); }
        assert(!mutations()); break;
    }
    case 21: ready(&f); assert(sg_pin_real_dispatch(f.attempt,f.secrets)); assert(!mutations()); assert(!mock_call_count(M_OPEN)); assert(!sg_pin_attempt_may_have_dispatched(f.attempt)); for(int i=0;i<3;++i) assert(!sg_pin_test_secret_length(f.secrets,i)); break;
    case 22: assert(!sg_pin_attempt_create(f.request,f.binding,99)); assert(sg_pin_attempt_approve(f.attempt,f.request,f.binding,SG_PIN_UNBLOCK)); break;
    case 23: {
        mock_pin_status(CKF_USER_PIN_LOCKED|CKF_USER_PIN_FINAL_TRY,CK_UNAVAILABLE_INFORMATION,12);
        CK_TOKEN_INFO info; assert(f.api->C_GetTokenInfo(7,&info)==CKR_OK);
        assert(info.flags & CKF_USER_PIN_LOCKED); assert(info.flags & CKF_USER_PIN_FINAL_TRY);
        assert(info.ulMinPinLen==CK_UNAVAILABLE_INFORMATION); assert(info.ulMaxPinLen==12); assert(!mutations()); break;
    }
    case 25: ready(&f); assert(!sg_pin_attempt_mark_dispatched(f.attempt)); sg_pin_attempt_abort(f.attempt); sg_pin_attempt_finish(f.attempt,1,1); assert(sg_pin_attempt_state(f.attempt)==SG_PIN_UNCERTAIN); break;
    case 26: ready(&f); synthetic_dispatch(&f,0); assert(sg_pin_attempt_approve(f.attempt,f.request,f.binding,f.action)); assert(sg_pin_attempt_ready(f.attempt,1,1,1,0)); assert(mutations()==1); break;
    case 27: ready(&f); mock_fail(M_SET_PIN,CKR_DEVICE_REMOVED); synthetic_dispatch(&f,0); assert(sg_pin_attempt_state(f.attempt)==SG_PIN_UNCERTAIN); assert(mutations()==1); break;
    case 30:
        assert(!sg_pin_attempt_approve(f.attempt,f.request,f.binding,f.action));
        assert(sg_pin_attempt_ready(f.attempt,1,0,1,0)); assert(!mutations()); break;
    case 31: clear_and_assert(&f); assert(sg_pin_secrets_validate_local(f.secrets,4,64)); assert(!mutations()); break;
    case 32: ready(&f); assert(sg_pin_real_dispatch(f.attempt,f.secrets)); assert(sg_pin_real_dispatch(f.attempt,f.secrets)); assert(!mutations()); break;
    case 33: ready(&f); synthetic_dispatch(&f,0); assert(!sg_pin_attempt_create(f.request,f.binding,f.action)); assert(mutations()==1); break;
    case 34: f.request[1] ^= 1; assert(sg_pin_attempt_approve(f.attempt,f.request,f.binding,f.action)); assert(!mutations()); break;
    case 35: case 36: case 37: subprocess_failure(&f,n-35); break;
    default: assert(0);
    }
    assert(!mock_call_count(M_LOGIN_USER)); assert(!mock_call_count(M_LOGIN_CONTEXT));
    if (n==0 || n==1 || n==2 || n==3 || n==10 || n==11 || n==13 || n==26 || n==27) assert(mutations()==1);
    dispose(&f);
}
int main(void) {
    for (int n=0;n<38;++n) {
        pid_t child=fork(); assert(child>=0);
        if (!child) { run_case(n); _exit(0); }
        int status; assert(waitpid(child,&status,0)==child);
        if (!WIFEXITED(status) || WEXITSTATUS(status)) { fprintf(stderr,"FAIL admin case %d\n",n); return 1; }
    }
    puts("PASS 38 administrative foundation cases (synthetic provider only, including subprocess timeout/lost response)"); return 0;
}
