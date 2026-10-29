#include "SignumPINManagement.h"
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>

struct SGPINAttempt {
    uint8_t request[16], binding[32];
    int action, state, may_have_dispatched, cleanup_failed;
};
struct SGPINSecrets { SGSecurePIN *fields[3]; };
/* Bounded, non-evicting request ledger for this process. No secrets. A future
 * hardware backend also requires a durable pre-dispatch journal; 12A has none
 * because it cannot dispatch to real hardware under any circumstance. */
static pthread_mutex_t ledger_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t seen_requests[128][16];
static size_t seen_count;
static void wipe(void *p, size_t n) { volatile uint8_t *b = p; while (n--) *b++ = 0; }
static int equal(const uint8_t *a, const uint8_t *b, size_t n) {
    unsigned difference = 0;
    for (size_t i = 0; i < n; ++i) difference |= a[i] ^ b[i];
    return difference == 0;
}
static int valid_action(int action) { return action == SG_PIN_CHANGE || action == SG_PIN_UNBLOCK; }
SGPINAttempt *sg_pin_attempt_create(const uint8_t request[16], const uint8_t binding[32], int action) {
    if (!request || !binding || !valid_action(action)) return NULL;
    SGPINAttempt *a = calloc(1, sizeof(*a)); if (!a) return NULL;
    pthread_mutex_lock(&ledger_lock);
    int duplicate = 0;
    for (size_t i = 0; i < seen_count; ++i) if (equal(request, seen_requests[i], 16)) duplicate = 1;
    if (duplicate || seen_count == 128) { pthread_mutex_unlock(&ledger_lock); free(a); return NULL; }
    memcpy(seen_requests[seen_count++], request, 16);
    pthread_mutex_unlock(&ledger_lock);
    memcpy(a->request, request, 16); memcpy(a->binding, binding, 32);
    a->action = action; a->state = SG_PIN_PREPARED; return a;
}
void sg_pin_attempt_destroy(SGPINAttempt *a) { if (a) { wipe(a, sizeof(*a)); free(a); } }
int sg_pin_attempt_approve(SGPINAttempt *a, const uint8_t request[16], const uint8_t binding[32], int action) {
    if (!a || a->state != SG_PIN_PREPARED) return -1;
    if (!request || !binding || action != a->action || !equal(request, a->request, 16) || !equal(binding, a->binding, 32)) {
        a->state = SG_PIN_NOT_EXECUTED; return -1;
    }
    a->state = SG_PIN_APPROVED; return 0;
}
int sg_pin_attempt_ready(SGPINAttempt *a, int verified, int complete, int unique, int locked) {
    if (!a || a->state != SG_PIN_APPROVED) return -1;
    if (!verified || !complete || !unique || locked) { a->state = SG_PIN_NOT_EXECUTED; return -1; }
    a->state = SG_PIN_READY; return 0;
}
int sg_pin_attempt_mark_dispatched(SGPINAttempt *a) {
    if (!a || a->state != SG_PIN_READY || a->may_have_dispatched) return -1;
    /* Set before any test callback. No transition can clear/rearm this flag. */
    a->may_have_dispatched = 1; a->state = SG_PIN_DISPATCHED; return 0;
}
void sg_pin_attempt_finish(SGPINAttempt *a, int succeeded, int cleanup) {
    if (!a || a->state != SG_PIN_DISPATCHED) return;
    a->state = succeeded ? SG_PIN_SUCCEEDED : SG_PIN_REJECTED;
    a->cleanup_failed = !cleanup;
}
void sg_pin_attempt_abort(SGPINAttempt *a) {
    if (!a || a->state >= SG_PIN_SUCCEEDED) return;
    a->state = a->may_have_dispatched ? SG_PIN_UNCERTAIN : SG_PIN_NOT_EXECUTED;
}
int sg_pin_attempt_state(const SGPINAttempt *a) { return a ? a->state : SG_PIN_NOT_EXECUTED; }
int sg_pin_attempt_cleanup_failed(const SGPINAttempt *a) { return a ? a->cleanup_failed : 0; }
int sg_pin_attempt_may_have_dispatched(const SGPINAttempt *a) { return a ? a->may_have_dispatched : 0; }
SGPINSecrets *sg_pin_secrets_create(void) {
    SGPINSecrets *s = calloc(1, sizeof(*s)); if (!s) return NULL;
    for (int i = 0; i < 3; ++i) {
        s->fields[i] = sg_secure_pin_create();
        if (!s->fields[i]) { sg_pin_secrets_destroy(s); return NULL; }
    }
    return s;
}
void sg_pin_secrets_clear(SGPINSecrets *s) {
    if (s) for (int i = 0; i < 3; ++i) sg_secure_pin_clear(s->fields[i]);
}
void sg_pin_secrets_destroy(SGPINSecrets *s) {
    if (!s) return;
    for (int i = 0; i < 3; ++i) sg_secure_pin_destroy(s->fields[i]);
    wipe(s, sizeof(*s)); free(s);
}
int sg_pin_secrets_set(SGPINSecrets *s, int field, const uint8_t *bytes, size_t n) {
    if (!s) return -1;
    if (field < 0 || field > 2 || sg_secure_pin_set(s->fields[field], bytes, n)) {
        sg_pin_secrets_clear(s); return -1;
    }
    return 0;
}
int sg_pin_secrets_validate_local(SGPINSecrets *s, size_t minimum, size_t maximum) {
    if (!s) return -1;
    if (!minimum || maximum > 64 || maximum < minimum) { sg_pin_secrets_clear(s); return -1; }
    size_t source = sg_secure_pin_length(s->fields[0]);
    size_t next = sg_secure_pin_length(s->fields[1]);
    size_t confirm = sg_secure_pin_length(s->fields[2]);
    /* Source policy may differ (PUK); only implementation bounds apply here.
     * A future qualified profile must validate its own source alphabet/length. */
    if (!source || source > 64 || next < minimum || next > maximum || next != confirm ||
        !equal(sg_secure_pin_bytes(s->fields[1]), sg_secure_pin_bytes(s->fields[2]), next)) {
        sg_pin_secrets_clear(s); return -1;
    }
    return 0;
}
static double now(void) {
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return t.tv_sec + t.tv_nsec / 1e9;
}
int sg_pin_secrets_receive(SGPINSecrets *s, int fd, const uint8_t request[16], const uint8_t binding[32], int action) {
    if (!s) return -1;
    sg_pin_secrets_clear(s);
    if (fd < 0 || !request || !binding || !valid_action(action)) return -1;
    uint8_t header[56]; size_t offset = 0; double start = now();
    if (start < 0) return -1;
    double deadline = start + 5;
    while (offset < sizeof(header)) {
        double current = now(); if (current < 0 || current >= deadline) goto failed;
        struct pollfd p = { fd, POLLIN, 0 };
        int ready = poll(&p, 1, 10);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) goto failed;
        if (!ready) continue;
        ssize_t n = read(fd, header + offset, sizeof(header) - offset);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) goto failed;
        offset += (size_t)n;
    }
    if (memcmp(header, "SPIN", 4) || header[4] != 1 || header[5] != action || header[6] || header[7] ||
        !equal(header + 8, request, 16) || !equal(header + 24, binding, 32)) goto failed;
    for (int i = 0; i < 2; ++i) {
        double current = now();
        if (current < 0 || current >= deadline || sg_secure_pin_receive(s->fields[i], fd, deadline - current)) goto failed;
    }
    wipe(header, sizeof(header)); return 0;
failed:
    wipe(header, sizeof(header)); sg_pin_secrets_clear(s); return -1;
}
int sg_pin_real_dispatch(SGPINAttempt *a, SGPINSecrets *s) {
    sg_pin_secrets_clear(s);
    sg_pin_attempt_abort(a);
    /* Intentionally no dlopen, C_SetPIN, C_InitPIN, login, reset or unblock. */
    return -1;
}
#ifdef SIGNUM_PIN_ADMIN_TESTING
const uint8_t *sg_pin_test_secret_bytes(const SGPINSecrets *s, int field) {
    return s && field >= 0 && field < 3 ? sg_secure_pin_bytes(s->fields[field]) : NULL;
}
size_t sg_pin_test_secret_length(const SGPINSecrets *s, int field) {
    return s && field >= 0 && field < 3 ? sg_secure_pin_length(s->fields[field]) : 0;
}
#endif

/* These primitives do not grant a hardware capability. Only a future separately
 * qualified coordinator may connect them to a real backend. */
struct SGPINConsent { uint8_t request[16], binding[32]; double deadline; int consumed; };
SGPINConsent *sg_pin_consent_create(const uint8_t request[16],const uint8_t binding[32],double lifetime) {
    double t=now();
    if(!request||!binding||!(lifetime>0&&lifetime<=90)||t<0)return NULL;
    SGPINConsent *c=calloc(1,sizeof(*c));if(!c)return NULL;
    memcpy(c->request,request,16);memcpy(c->binding,binding,32);c->deadline=t+lifetime;return c;
}
int sg_pin_consent_consume(SGPINConsent *c,const uint8_t request[16],const uint8_t binding[32],int action) {
    if(!c||c->consumed)return -1;c->consumed=1;double t=now();
    return request&&binding&&action==SG_PIN_CHANGE&&t>=0&&t<c->deadline&&
        equal(c->request,request,16)&&equal(c->binding,binding,32)?0:-1;
}
void sg_pin_consent_destroy(SGPINConsent *c){if(c){wipe(c,sizeof(*c));free(c);}}
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
static int private_pipe(int fd,int write_side) {
    struct stat s;int flags=fcntl(fd,F_GETFL);
    if(fstat(fd,&s)||!S_ISFIFO(s.st_mode)||s.st_nlink!=0||s.st_uid!=getuid()||flags<0||
       (flags&O_ACCMODE)!=(write_side?O_WRONLY:O_RDONLY)||fcntl(fd,F_SETFD,FD_CLOEXEC))return -1;
    return fcntl(fd,F_SETFL,flags|O_NONBLOCK);
}
static int send_bytes(int fd,const uint8_t *bytes,size_t length,double deadline) {
    size_t offset=0;
    while(offset<length) {
        double t=now();if(t<0||t>=deadline)return -1;
        struct pollfd p={fd,POLLOUT,0};int ready=poll(&p,1,10);
        if(ready<0&&errno==EINTR)continue;if(ready<0)return -1;if(!ready)continue;
        ssize_t n=write(fd,bytes+offset,length-offset);
        if(n<0&&(errno==EINTR||errno==EAGAIN))continue;if(n<=0)return -1;offset+=(size_t)n;
    }
    return 0;
}
int sg_pin_secrets_send_change(SGPINSecrets *s,int fd,const uint8_t request[16],const uint8_t binding[32],size_t minimum,size_t maximum) {
    int result=-1;sigset_t block,previous,pending;int masked=0,was_pending=0;
    if(!s)return -1;
    if(!request||!binding||private_pipe(fd,1)||sg_pin_secrets_validate_local(s,minimum,maximum))goto done;
    sigemptyset(&block);sigaddset(&block,SIGPIPE);
    if(pthread_sigmask(SIG_BLOCK,&block,&previous))goto done;masked=1;
    if(sigpending(&pending))goto done;was_pending=sigismember(&pending,SIGPIPE);
    double t=now();if(t<0)goto done;
    uint8_t header[56]={'S','P','I','N',1,SG_PIN_CHANGE,0,0};
    memcpy(header+8,request,16);memcpy(header+24,binding,32);
    if(send_bytes(fd,header,56,t+5))goto done;
    for(int i=0;i<2;i++) {
        size_t n=sg_secure_pin_length(s->fields[i]);uint8_t length[4]={0,0,0,(uint8_t)n};
        if(send_bytes(fd,length,4,t+5)||send_bytes(fd,sg_secure_pin_bytes(s->fields[i]),n,t+5))goto done;
    }
    result=0;
done:
    sg_pin_secrets_clear(s);
    if(masked) {
        if(!was_pending&&!sigpending(&pending)&&sigismember(&pending,SIGPIPE)) {
            int signal_number=0;sigwait(&block,&signal_number);
        }
        pthread_sigmask(SIG_SETMASK,&previous,NULL);
    }
    return result;
}
int sg_pin_secrets_receive_change(SGPINSecrets *s,int fd,const uint8_t request[16],const uint8_t binding[32],size_t minimum,size_t maximum) {
    if(!s)return -1;
    if(private_pipe(fd,0)||sg_pin_secrets_receive(s,fd,request,binding,SG_PIN_CHANGE))goto failed;
    /* EOF is part of the bounded contract: no second frame or hidden retry.
     * Trailing input is detected inside the locked confirmation buffer. */
    double t=now();if(t<0)goto failed;double deadline=t+1;
    const uint8_t marker=1;
    if(sg_pin_secrets_set(s,SG_PIN_CONFIRMATION,&marker,1))goto failed;
    uint8_t *extra=(uint8_t *)sg_secure_pin_bytes(s->fields[SG_PIN_CONFIRMATION]);
    for(;;) {
        t=now();if(t<0||t>=deadline)goto failed;
        struct pollfd p={fd,POLLIN,0};int ready=poll(&p,1,10);
        if(ready<0&&errno==EINTR)continue;if(ready<0)goto failed;if(!ready)continue;
        ssize_t n=read(fd,extra,1);
        if(n<0&&(errno==EINTR||errno==EAGAIN))continue;if(n!=0)goto failed;
        sg_secure_pin_clear(s->fields[SG_PIN_CONFIRMATION]);break;
    }
    if(sg_pin_secrets_set(s,SG_PIN_CONFIRMATION,sg_secure_pin_bytes(s->fields[SG_PIN_NEW]),sg_secure_pin_length(s->fields[SG_PIN_NEW]))||
       sg_pin_secrets_validate_local(s,minimum,maximum))goto failed;
    return 0;
failed:sg_pin_secrets_clear(s);return -1;
}
