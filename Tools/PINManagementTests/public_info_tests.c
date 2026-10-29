#include "SignumPKCS11.h"
#include "SignumCertificatePolicy.h"
#include "mock_provider.h"
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#ifndef __APPLE__
int pthread_main_np(void) { return 0; }
#endif
/* Signing policy is never exercised by public reads. Rejecting stubs let this
 * portable test link; macOS regressions must use the original policy target. */
SGCertificateAssessment sg_certificate_assess(const uint8_t *b,size_t n,double t) {
    (void)b;(void)n;(void)t;SGCertificateAssessment a={0};a.status=SG_CERT_INDETERMINATE;return a;
}
const char *sg_certificate_reason_message(uint32_t r) { (void)r;return "test policy unavailable"; }
double sg_certificate_now(void) { return 0; }
int main(int argc,char **argv) {
    assert(argc==2);
    void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);assert(lib);
    void (*status)(CK_FLAGS,CK_ULONG,CK_ULONG)=dlsym(lib,"mock_pin_status");
    unsigned (*count)(int)=dlsym(lib,"mock_call_count");
    void (*fail)(int,CK_RV)=dlsym(lib,"mock_fail");
    assert(status&&count&&fail);
    SGContext *ctx=NULL;assert(!sg_open(argv[1],&ctx,NULL,0));
    SGPINPublicInfo info;
    status(CKF_USER_PIN_LOCKED|CKF_USER_PIN_FINAL_TRY,4,12);
    assert(!sg_pin_public_info(ctx,7,&info));assert(info.version==1);
    assert(info.flags==(CKF_USER_PIN_LOCKED|CKF_USER_PIN_FINAL_TRY));
    assert(info.minimum_known&&info.minimum_bytes==4&&info.maximum_known&&info.maximum_bytes==12);
    assert(!strcmp(info.token.label,"Signum Mock"));assert(!strcmp(info.token.reader,"Synthetic reader"));
    status(0,CK_UNAVAILABLE_INFORMATION,CK_UNAVAILABLE_INFORMATION);
    assert(!sg_pin_public_info(ctx,7,&info));assert(!info.minimum_known&&!info.maximum_known);assert(!info.flags);
    status(CKF_USER_PIN_TO_BE_CHANGED,12,4);assert(!sg_pin_public_info(ctx,7,&info));
    assert(info.minimum_bytes==12&&info.maximum_bytes==4); /* Preserve contradictions, never repair policy. */
    fail(M_TOKEN_INFO,CKR_DEVICE_REMOVED);assert(sg_pin_public_info(ctx,7,&info));assert(info.version==0);
    assert(!count(M_OPEN)&&!count(M_LOGIN_USER)&&!count(M_LOGIN_CONTEXT)&&!count(M_SET_PIN)&&!count(M_UNBLOCK_PIN));
    fail(M_TOKEN_INFO,CKR_OK);fail(M_SLOT_INFO,CKR_GENERAL_ERROR);assert(sg_pin_public_info(ctx,7,&info));assert(info.version==0);
    assert(!sg_close_checked(ctx,NULL,0));dlclose(lib);
    puts("PASS 5 public status cases on actual shim: flags, unknown/contradictory limits, removal, reader error; zero sessions/auth/mutations");
    return 0;
}
