/* Synthetic-only complete change path. No loader, real module path, vendor
 * environment or credential argument. Statically linked to mock_provider.c. */
#include "SignumPINManagement.h"
#include "SignumPINJournal.h"
#include "process_coordination.h"
#include "mock_provider.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <poll.h>
static uint8_t request[16]={0x12},binding[32]={0x34},domain[32]={0x56};
static const uint8_t old[]="SYNTH-OLD",next[]="SYNTH-NEW";
static SGPINSecrets *secrets(void) {
    SGPINSecrets *s=sg_pin_secrets_create();assert(s);
    assert(!sg_pin_secrets_set(s,0,old,sizeof(old)-1));
    assert(!sg_pin_secrets_set(s,1,next,sizeof(next)-1));
    assert(!sg_pin_secrets_set(s,2,next,sizeof(next)-1));return s;
}
static unsigned mutations(void){return mock_call_count(M_SET_PIN)+mock_call_count(M_UNBLOCK_PIN);}
static void assert_clear(SGPINSecrets *s){for(int i=0;i<3;i++)assert(!sg_pin_test_secret_length(s,i));}
static void worker(const char *root,const char *provider,int input,int events,int kind) {
    struct rlimit zero={0,0};assert(!setrlimit(RLIMIT_CORE,&zero));assert(!sg_worker_watch_parent());
    SGTokenLease *lease=sg_admin_lease_acquire(provider,7,0);assert(lease);
    SGPINConsent *consent=sg_pin_consent_create(request,binding,30);assert(consent);
    assert(!sg_pin_consent_consume(consent,request,binding,SG_PIN_CHANGE));
    assert(sg_pin_consent_consume(consent,request,binding,SG_PIN_CHANGE));
    sg_pin_consent_destroy(consent);
    SGPINJournal *journal=sg_pin_journal_reserve(root,request,binding,domain);assert(journal);
    SGPINAttempt *attempt=sg_pin_attempt_create(request,binding,SG_PIN_CHANGE);assert(attempt);
    assert(!sg_pin_attempt_approve(attempt,request,binding,SG_PIN_CHANGE));
    assert(!sg_pin_attempt_ready(attempt,1,1,1,0));
    assert(write(events,"R",1)==1); /* Barrier, one-shot consent and journal ready. */
    char go=0;assert(read(input,&go,1)==1&&go=='G');
    if(kind==5)_exit(0); /* Durable intent only; never infer safe retry. */
    SGPINSecrets *s=sg_pin_secrets_create();assert(s);
    if(sg_pin_secrets_receive_change(s,input,request,binding,4,64)||kind==9||kind==10) {
        sg_pin_secrets_clear(s);assert_clear(s);assert(!sg_pin_journal_finish(journal,SG_PIN_JOURNAL_NOT_EXECUTED));
        sg_pin_secrets_destroy(s);sg_pin_attempt_abort(attempt);sg_pin_journal_close(journal);sg_token_lease_release(lease);_exit(0);
    }
    close(input);
    CK_FUNCTION_LIST_PTR api;assert(C_GetFunctionList(&api)==CKR_OK);
    assert(api->C_Initialize(NULL)==CKR_OK);
    CK_SESSION_HANDLE session=0;mock_pin_model(old,sizeof(old)-1);
    if(kind==39)mock_fail(M_OPEN,CKR_SESSION_READ_ONLY);
    CK_RV opened=api->C_OpenSession(7,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&session);
    if(kind==38)mock_shared_login(1); /* Existing login must not redirect a PIN change. */
    CK_SESSION_INFO info;CK_RV inspected=opened==CKR_OK?api->C_GetSessionInfo(session,&info):CKR_SESSION_HANDLE_INVALID;
    if(opened!=CKR_OK||inspected!=CKR_OK||info.state!=CKS_RW_PUBLIC_SESSION||!(info.flags&CKF_RW_SESSION)){
        sg_pin_secrets_clear(s);assert_clear(s);assert(!mutations());
        if(opened==CKR_OK)assert(api->C_CloseSession(session)==CKR_OK);
        assert(api->C_Finalize(NULL)==CKR_OK);assert(!sg_pin_journal_finish(journal,4));
        sg_pin_secrets_destroy(s);sg_pin_journal_close(journal);sg_token_lease_release(lease);_exit(0);
    }
    if(kind==1)mock_fail(M_SET_PIN,CKR_PIN_INCORRECT);
    if(kind==2)mock_fail(M_SET_PIN,CKR_DEVICE_ERROR);
    if(kind==3)mock_fail(M_CLOSE,CKR_GENERAL_ERROR);
    if(kind==4)mock_fail(M_FINALIZE,CKR_GENERAL_ERROR);
    if(kind==8)sg_pin_journal_test_fail_sync(1);
    if(sg_pin_journal_arm(journal)) {
        sg_pin_secrets_clear(s);assert_clear(s);assert(!mutations());
        sg_pin_secrets_destroy(s);assert(api->C_CloseSession(session)==CKR_OK);assert(api->C_Finalize(NULL)==CKR_OK);
        sg_pin_attempt_destroy(attempt);sg_pin_journal_close(journal);sg_token_lease_release(lease);_exit(0);
    }
    assert(!sg_pin_attempt_mark_dispatched(attempt));
    if(kind==6)_exit(0); /* Durable arm, zero backend calls; still uncertain. */
    assert(write(events,"D",1)==1);
    if(kind==16){mock_block(M_SET_PIN);}
    CK_RV rv=api->C_SetPIN(session,(CK_UTF8CHAR_PTR)sg_pin_test_secret_bytes(s,0),sg_pin_test_secret_length(s,0),
                          (CK_UTF8CHAR_PTR)sg_pin_test_secret_bytes(s,1),sg_pin_test_secret_length(s,1));
    sg_pin_secrets_clear(s);assert_clear(s);assert(mutations()==1);
    if(rv==CKR_OK){assert(mock_pin_matches(next,sizeof(next)-1));assert(!mock_pin_matches(old,sizeof(old)-1));}
    else assert(mock_pin_matches(old,sizeof(old)-1));
    if(kind==7)_exit(0); /* Result lost after actual synthetic call. */
    CK_RV closed=api->C_CloseSession(session),final=api->C_Finalize(NULL);
    assert(!mock_call_count(M_LOGIN_USER)&&!mock_call_count(M_LOGIN_CONTEXT)&&!mock_call_count(M_UNBLOCK_PIN));
    int state=rv==CKR_DEVICE_ERROR?SG_PIN_JOURNAL_UNCERTAIN:rv==CKR_PIN_INCORRECT?SG_PIN_JOURNAL_REJECTED:
        closed!=CKR_OK||final!=CKR_OK?SG_PIN_JOURNAL_SUCCEEDED_CLEANUP_FAILED:SG_PIN_JOURNAL_SUCCEEDED;
    if(kind==17){
        char path[4096];assert(snprintf(path,sizeof(path),"%s/12000000000000000000000000000000.result",root)<(int)sizeof(path));
        int fd=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);assert(fd>=0);close(fd);
        assert(sg_pin_journal_finish(journal,state));
    }else assert(!sg_pin_journal_finish(journal,state));
    assert(sg_pin_journal_finish(journal,state));
    sg_pin_secrets_destroy(s);sg_pin_attempt_destroy(attempt);sg_pin_journal_close(journal);sg_token_lease_release(lease);
    _exit(0);
}
static void pipeline(const char *root,const char *provider,int kind) {
    int pipefd[2],events[2];assert(!pipe(pipefd)&&!pipe(events));pid_t pid=fork();assert(pid>=0);
    if(!pid){close(pipefd[1]);close(events[0]);worker(root,provider,pipefd[0],events[1],kind);_exit(99);}
    close(pipefd[0]);close(events[1]);char ready=0;assert(read(events[0],&ready,1)==1&&ready=='R');
    /* The actual administrative worker excludes ordinary helpers across providers. */
    assert(!sg_token_lease_acquire(provider,8,0,0));
    assert(write(pipefd[1],"G",1)==1);
    if(kind==13){assert(write(pipefd[1],"SPIN",4)==4);}
    else if(kind!=5){
        SGPINSecrets *s=secrets();
        if(kind==40)assert(!sg_pin_secrets_set(s,0,(const uint8_t *)"SYNTH-BAD",9));
        if(kind==14)assert(!sg_pin_secrets_set(s,2,(const uint8_t *)"DIFFERENT",9));
        if(kind==11)binding[0]^=1;
        int sent=sg_pin_secrets_send_change(s,pipefd[1],request,binding,4,64);
        assert_clear(s);sg_pin_secrets_destroy(s);
        if(kind==14)assert(sent);else assert(!sent);
        if(kind==11)binding[0]^=1;
        if(kind==12)assert(write(pipefd[1],"X",1)==1);
        if(kind==13){ /* Parent cancels/terminates transport; test receiver separately below. */ }
        if(kind==15) {struct pollfd p={events[0],POLLIN,0};assert(poll(&p,1,1300)>=0);}
    }
    close(pipefd[1]);
    if(kind==16){char dispatch=0;assert(read(events[0],&dispatch,1)==1&&dispatch=='D');assert(!kill(pid,SIGKILL));}
    int status;assert(waitpid(pid,&status,0)==pid);close(events[0]);
    if(kind==16)assert(WIFSIGNALED(status));else assert(WIFEXITED(status)&&!WEXITSTATUS(status));
    int expected=(kind==1||kind==40)?SG_PIN_JOURNAL_REJECTED:(kind==3||kind==4)?SG_PIN_JOURNAL_SUCCEEDED_CLEANUP_FAILED:
        (kind==2||kind==5||kind==6||kind==7||kind==8||kind==16||kind==17)?SG_PIN_JOURNAL_UNCERTAIN:
        (kind==9||kind==10||kind==11||kind==12||kind==13||kind==14||kind==15||kind==38||kind==39)?SG_PIN_JOURNAL_NOT_EXECUTED:SG_PIN_JOURNAL_SUCCEEDED;
    assert(sg_pin_journal_recover(root,request)==expected);
    assert(!sg_pin_journal_reserve(root,request,binding,domain)); /* Same ID never replayed after restart. */
    uint8_t fresh[16]={0x99},new_binding[32]={0xaa};
    SGPINJournal *j=sg_pin_journal_reserve(root,fresh,new_binding,domain);
    if(expected==SG_PIN_JOURNAL_UNCERTAIN)assert(!j); /* New session/generation cannot bypass unknown. */
    else {assert(j);assert(!sg_pin_journal_finish(j,SG_PIN_JOURNAL_NOT_EXECUTED));sg_pin_journal_close(j);}
    SGTokenLease *lease=sg_token_lease_acquire(provider,7,0,0);assert(lease);sg_token_lease_release(lease);
}
static void journal_cases(const char *base,int kind) {
    char root[4096];snprintf(root,sizeof(root),"%s/store",base);assert(!mkdir(root,0700));
    if(kind==20){chmod(root,0755);assert(!sg_pin_journal_reserve(root,request,binding,domain));return;}
    if(kind==21){char alias[4096];snprintf(alias,sizeof(alias),"%s/alias",base);assert(!symlink(root,alias));assert(!sg_pin_journal_reserve(alias,request,binding,domain));return;}
    if(kind==22){sg_pin_journal_test_fail_sync(1);assert(!sg_pin_journal_reserve(root,request,binding,domain));sg_pin_journal_test_fail_sync(0);assert(sg_pin_journal_recover(root,request)==1);return;}
    SGPINJournal *j=sg_pin_journal_reserve(root,request,binding,domain);assert(j);
    assert(!sg_pin_journal_reserve(root,(uint8_t[16]){4},binding,domain)); /* Lock exclusion. */
    if(kind==23){assert(!sg_pin_journal_arm(j));assert(sg_pin_journal_arm(j));assert(sg_pin_journal_finish(j,4));}
    if(kind==24){assert(sg_pin_journal_finish(j,2));assert(!sg_pin_journal_finish(j,4));assert(sg_pin_journal_arm(j));}
    sg_pin_journal_close(j);
    char path[4096];assert(snprintf(path,sizeof(path),"%s/12000000000000000000000000000000.intent",root)<(int)sizeof(path));
    if(kind==25){int fd=open(path,O_WRONLY);assert(fd>=0);assert(write(fd,"X",1)==1);close(fd);}
    if(kind==26){char alias[4096];snprintf(alias,sizeof(alias),"%s/hardlink",base);assert(!link(path,alias));}
    if(kind==27){chmod(path,0644);}
    if(kind==28){char alias[4096];snprintf(alias,sizeof(alias),"%s/saved",base);assert(!rename(path,alias));assert(!symlink(alias,path));}
    if(kind==18)assert(sg_pin_journal_recover(root,(uint8_t[16]){8})==0);
    if(kind==19){int fd=open(path,O_WRONLY);assert(fd>=0);assert(lseek(fd,40,SEEK_SET)==40);assert(write(fd,"X",1)==1);close(fd);
        assert(!sg_pin_journal_reserve(root,(uint8_t[16]){4},binding,(uint8_t[32]){5}));}
    if(kind==23)assert(sg_pin_journal_recover(root,request)==1);
    if(kind==24)assert(sg_pin_journal_recover(root,request)==4);
    if(kind>=25){assert(sg_pin_journal_recover(root,request)==1);assert(!sg_pin_journal_reserve(root,(uint8_t[16]){4},binding,(uint8_t[32]){5}));}
}
int main(int argc,char **argv) {
    assert(argc==3);int kind=atoi(argv[2]);
    if(kind==34||kind==35){
        char root[4096];snprintf(root,sizeof(root),"%s/store",argv[1]);
        assert(sg_pin_journal_recover(root,request)==(kind==34?1:2));
        assert(!sg_pin_journal_reserve(root,request,binding,domain));
        if(kind==34)assert(!sg_pin_journal_reserve(root,(uint8_t[16]){9},(uint8_t[32]){8},domain));
        assert(!mutations());printf("PASS qualification restart contract %d (fresh process)\n",kind);return 0;
    }
    if(kind==36){
        char root[4096];snprintf(root,sizeof(root),"%s/store",argv[1]);assert(!mkdir(root,0700));
        for(unsigned i=0;i<256;i++){
            uint8_t id[16]={0x80,(uint8_t)i};SGPINJournal *j=sg_pin_journal_reserve(root,id,binding,domain);assert(j);
            assert(!sg_pin_journal_finish(j,4));sg_pin_journal_close(j);
        }
        assert(!sg_pin_journal_reserve(root,request,binding,domain));
        puts("PASS qualification capacity contract 36 (no eviction)");return 0;
    }
    if(kind<18||kind==38||kind==39||kind==40){char root[4096],provider[4096];snprintf(root,sizeof(root),"%s/store",argv[1]);assert(!mkdir(root,0700));snprintf(provider,sizeof(provider),"%s/provider-fixture",argv[1]);int fd=open(provider,O_CREAT|O_EXCL|O_WRONLY,0600);assert(fd>=0);close(fd);pipeline(root,provider,kind);}
    else if(kind<29)journal_cases(argv[1],kind);
    else {
        SGPINConsent *c=sg_pin_consent_create(request,binding,90);assert(c);
        if(kind==29){assert(sg_pin_consent_consume(c,request,binding,SG_PIN_UNBLOCK));assert(sg_pin_consent_consume(c,request,binding,SG_PIN_CHANGE));}
        if(kind==30){uint8_t wrong[32]={0xff};assert(sg_pin_consent_consume(c,request,wrong,SG_PIN_CHANGE));assert(sg_pin_consent_consume(c,request,binding,SG_PIN_CHANGE));}
        if(kind==31){sg_pin_consent_destroy(c);c=sg_pin_consent_create(request,binding,0.000001);assert(c);usleep(2000);assert(sg_pin_consent_consume(c,request,binding,SG_PIN_CHANGE));}
        if(kind==32){SGPINSecrets *s=secrets();int p[2];assert(!pipe(p));close(p[0]);assert(sg_pin_secrets_send_change(s,p[1],request,binding,4,64));assert_clear(s);close(p[1]);sg_pin_secrets_destroy(s);}
        if(kind==33){SGPINSecrets *s=secrets();int p[2];assert(!pipe(p));assert(write(p[1],"SPIN",4)==4);close(p[1]);assert(sg_pin_secrets_receive_change(s,p[0],request,binding,4,64));assert_clear(s);close(p[0]);sg_pin_secrets_destroy(s);}
        if(kind==37){
            char path[4096];snprintf(path,sizeof(path),"%s/named-pipe",argv[1]);assert(!mkfifo(path,0600));
            int reader=open(path,O_RDONLY|O_NONBLOCK);assert(reader>=0);int writer=open(path,O_WRONLY|O_NONBLOCK);assert(writer>=0);
            SGPINSecrets *s=secrets();assert(sg_pin_secrets_send_change(s,writer,request,binding,4,64));assert_clear(s);
            sg_pin_secrets_destroy(s);close(writer);close(reader);
        }
        sg_pin_consent_destroy(c);
    }
    printf("PASS qualification contract %d (synthetic only)\n",kind);return 0;
}
