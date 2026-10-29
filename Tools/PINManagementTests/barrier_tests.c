#include "process_coordination.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef __APPLE__
static char private_directory[4096];
/* Private-directory and ACL glue only. flock/openat/lease code is unmodified.
 * The Darwin confstr/ACL policy and RSS API still require native macOS tests. */
size_t sg_test_confstr(int ignored, char *out, size_t n) {
    (void)ignored; size_t count=strlen(private_directory)+1;
    if(n>=count) memcpy(out,private_directory,count); return count;
}
int sg_output_make_private(int fd, mode_t mode) { return fchmod(fd,mode); }
int proc_pidinfo(int a,int b,unsigned long long c,void *d,int e) {
    (void)a;(void)b;(void)c;(void)d;(void)e;errno=ESRCH;return 0;
}
#endif
static void check_wait(pid_t child) {
    int status;assert(waitpid(child,&status,0)==child);assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    char stage[2048]; assert(snprintf(stage,sizeof(stage),"%s/barrier-XXXXXX",argv[1]) < (int)sizeof(stage)); assert(mkdtemp(stage));
#ifndef __APPLE__
    snprintf(private_directory,sizeof(private_directory),"%s",stage);
#endif
    char provider_a[4096],provider_b[4096];
    snprintf(provider_a,sizeof(provider_a),"%s/synthetic-A",stage);
    snprintf(provider_b,sizeof(provider_b),"%s/synthetic-B",stage);
    int a=open(provider_a,O_RDWR|O_CREAT|O_EXCL,0600),b=open(provider_b,O_RDWR|O_CREAT|O_EXCL,0600);
    assert(a>=0&&b>=0);close(a);close(b);
    SGTokenLease *first=sg_token_lease_acquire(provider_a,1,0,0);assert(first);
    pid_t child=fork();assert(child>=0);
    if(!child){
        /* Do not keep an inherited copy of the parent's shared lease. */
        sg_token_lease_release(first);
        assert(!sg_admin_lease_acquire(provider_b,99,0));assert(errno==ETIMEDOUT);
        SGTokenLease *other=sg_token_lease_acquire(provider_b,99,0,0);assert(other);sg_token_lease_release(other);_exit(0);
    }
    check_wait(child);sg_token_lease_release(first);
    first=sg_admin_lease_acquire(provider_a,1,0);assert(first);
    child=fork();assert(child>=0);
    if(!child){
        sg_token_lease_release(first);
        assert(!sg_token_lease_acquire(provider_b,99,0,0));assert(errno==ETIMEDOUT);
        assert(!sg_token_lease_acquire(provider_b,0,1,0));assert(errno==ETIMEDOUT);
        assert(!sg_admin_lease_acquire(provider_b,99,0));assert(errno==ETIMEDOUT);_exit(0);
    }
    check_wait(child);sg_token_lease_release(first);
    first=sg_token_lease_acquire(provider_b,99,0,0);assert(first);sg_token_lease_release(first);
    first=sg_admin_lease_acquire(provider_b,99,0);assert(first);sg_token_lease_release(first);
    assert(!sg_admin_lease_acquire(provider_b,99,30001));
    puts("PASS 8 cross-process/cross-provider administrative barrier assertions");
    /* Isolated temporary lock inodes are intentionally retained until this
     * test's temporary directory is removed by the parent test runner. */
    unlink(provider_a);unlink(provider_b);
    return 0;
}
