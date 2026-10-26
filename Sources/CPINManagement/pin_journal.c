#include "SignumPINJournal.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef __APPLE__
#include "output_permissions.h"
#include <CommonCrypto/CommonDigest.h>
#else
#define O_NOFOLLOW_ANY O_NOFOLLOW
#endif
struct SGPINJournal { int root, lock, armed, finished; char name[33]; uint8_t record[88]; };
#ifdef SIGNUM_PIN_ADMIN_TESTING
static int fail_sync;
void sg_pin_journal_test_fail_sync(int enabled) { fail_sync=enabled; }
#endif
static int durable(int fd, int directory) {
#ifdef SIGNUM_PIN_ADMIN_TESTING
    if(fail_sync) { errno=EIO; return -1; }
#endif
#ifdef __APPLE__
    if(!directory && fcntl(fd,F_FULLFSYNC)) return -1;
#else
    (void)directory;
#endif
    return fsync(fd);
}
static int private_fd(int fd, int directory) {
#ifdef __APPLE__
    return sg_output_is_private(fd,directory?0700:0600);
#else
    struct stat s;
    return fstat(fd,&s)||s.st_uid!=getuid()||(s.st_mode&07777)!=(directory?0700:0600)||
        (directory?!S_ISDIR(s.st_mode):(!S_ISREG(s.st_mode)||s.st_nlink!=1)) ? -1:0;
#endif
}
static void identifier(const uint8_t id[16], char out[33]) {
    static const char hex[]="0123456789abcdef";
    for(int i=0;i<16;i++){out[i*2]=hex[id[i]>>4];out[i*2+1]=hex[id[i]&15];}out[32]=0;
}
static int valid_name(const char *name) {
    if(strlen(name)!=32)return 0;
    for(int i=0;i<32;i++)if(!((name[i]>='0'&&name[i]<='9')||(name[i]>='a'&&name[i]<='f')))return 0;
    return 1;
}
/* Detect accidental corruption; private-file policy is the access boundary.
 * This checksum is not an authenticity proof against the same user/root. */
static int checksum(const uint8_t *bytes,size_t length,uint8_t out[32]) {
#ifdef __APPLE__
    return CC_SHA256(bytes,(CC_LONG)length,out)?0:-1;
#else
    (void)bytes;(void)length;(void)out;return -1; /* Native durability not qualified. */
#endif
}
static int read_record(int root,const char *base,const char *suffix,uint8_t *bytes,size_t length) {
    char name[48];snprintf(name,sizeof(name),"%s.%s",base,suffix);
    int fd=openat(root,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if(fd<0)return errno==ENOENT?1:-1;
    struct stat s;int result=-1;
    if(!private_fd(fd,0)&&!fstat(fd,&s)&&s.st_size==(off_t)(length+32)) {
        size_t n=0;while(n<length){ssize_t got=read(fd,bytes+n,length-n);if(got<0&&errno==EINTR)continue;if(got<=0)break;n+=(size_t)got;}
        if(n==length){
            uint8_t digest[32],expected[32];size_t k=0;
            while(k<32){ssize_t got=read(fd,digest+k,32-k);if(got<0&&errno==EINTR)continue;if(got<=0)break;k+=(size_t)got;}
            if(k==32&&!checksum(bytes,length,expected)&&!memcmp(digest,expected,32))result=0;
        }
    }
    close(fd);return result;
}
static int outcome(int root,const char *base,uint8_t record[88]) {
    char name[33];identifier(record+8,name);
    if(memcmp(record,"SPJ12B1\0",8)||strcmp(base,name))return SG_PIN_JOURNAL_UNCERTAIN;
    uint8_t dispatch[88],result[90];int armed=read_record(root,base,"dispatch",dispatch,88);
    if(armed<0||(!armed&&memcmp(dispatch,record,88)))return SG_PIN_JOURNAL_UNCERTAIN;
    if(read_record(root,base,"result",result,90)||memcmp(result,record,88)||
       (unsigned)result[88]+result[89]!=255)return SG_PIN_JOURNAL_UNCERTAIN;
    int code=result[88];
    if(code<SG_PIN_JOURNAL_SUCCEEDED||code>SG_PIN_JOURNAL_SUCCEEDED_CLEANUP_FAILED)return SG_PIN_JOURNAL_UNCERTAIN;
    if((code==SG_PIN_JOURNAL_NOT_EXECUTED)!=(armed==1))return SG_PIN_JOURNAL_UNCERTAIN;
    return code;
}
static SGPINJournal *open_root(const char *path,int create) {
    if(!path||path[0]!='/')return NULL;
    int root=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW_ANY|O_CLOEXEC);
    if(root<0)return NULL;
    if(private_fd(root,1)){close(root);return NULL;}
    int lock=openat(root,"ledger.lock",(create?(O_RDWR|O_CREAT):O_RDONLY)|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK,0600);
    struct stat s;
    if(lock<0||private_fd(lock,0)||fstat(lock,&s)||s.st_size||flock(lock,LOCK_EX|LOCK_NB)) {
        if(lock>=0)close(lock);close(root);return NULL;
    }
    SGPINJournal *j=calloc(1,sizeof(*j));if(!j){close(lock);close(root);return NULL;}
    j->root=root;j->lock=lock;return j;
}
/* No replace, rename, truncate, chmod of existing entries, or unlink. A partial
 * write remains a tombstone and blocks future operations conservatively. */
static int store(SGPINJournal *j,const char *suffix,const uint8_t *data,size_t length) {
    char name[48];snprintf(name,sizeof(name),"%s.%s",j->name,suffix);
    int fd=openat(j->root,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return -1;
    int result=-1;
    if(!private_fd(fd,0)) {
        size_t n=0;while(n<length){ssize_t sent=write(fd,data+n,length-n);if(sent<0&&errno==EINTR)continue;if(sent<=0)break;n+=(size_t)sent;}
        uint8_t digest[32];size_t k=0;
        if(n==length&&!checksum(data,length,digest)) {
            while(k<32){ssize_t sent=write(fd,digest+k,32-k);if(sent<0&&errno==EINTR)continue;if(sent<=0)break;k+=(size_t)sent;}
            if(k==32&&!durable(fd,0)&&!durable(j->root,1))result=0;
        }
    }
    close(fd);return result;
}
SGPINJournal *sg_pin_journal_reserve(const char *path,const uint8_t request[16],const uint8_t binding[32],const uint8_t domain[32]) {
    if(!request||!binding||!domain)return NULL;
    SGPINJournal *j=open_root(path,1);if(!j)return NULL;
    identifier(request,j->name);memcpy(j->record,"SPJ12B1\0",8);memcpy(j->record+8,request,16);
    memcpy(j->record+24,binding,32);memcpy(j->record+56,domain,32);
    int scan=openat(j->root,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);DIR *dir=scan<0?NULL:fdopendir(scan);
    if(!dir){if(scan>=0)close(scan);goto failed;}
    struct dirent *entry;unsigned records=0,entries=0;int bad=0;
    errno=0;
    while((entry=readdir(dir))) {
        const char *name=entry->d_name;
        if(!strcmp(name,".")||!strcmp(name,"..")||!strcmp(name,"ledger.lock"))continue;
        if(++entries>768){bad=1;break;}
        const char *dot=strchr(name,'.');char base[33];
        if(!dot||dot-name!=32){bad=1;break;}memcpy(base,name,32);base[32]=0;
        if(!valid_name(base)||(!strcmp(base,j->name))){bad=1;break;}
        if(strcmp(dot,".intent")&&strcmp(dot,".dispatch")&&strcmp(dot,".result")){bad=1;break;}
        uint8_t prior[88];
        if(read_record(j->root,base,"intent",prior,88)){bad=1;break;}
        int state=outcome(j->root,base,prior);
        /* Any structurally invalid record poisons the store, even another domain. */
        char expected[33];identifier(prior+8,expected);
        if(memcmp(prior,"SPJ12B1\0",8)||strcmp(expected,base)){bad=1;break;}
        if(!strcmp(dot,".intent"))records++;
        if(state==SG_PIN_JOURNAL_UNCERTAIN&&!memcmp(prior+56,domain,32)){bad=1;break;}
        uint8_t extra[90];
        if(!strcmp(dot,".dispatch")&&(read_record(j->root,base,"dispatch",extra,88)||memcmp(extra,prior,88))){bad=1;break;}
        if(!strcmp(dot,".result")&&state==SG_PIN_JOURNAL_UNCERTAIN){bad=1;break;}
        errno=0;
    }
    if(errno)bad=1;
    closedir(dir);
    if(bad||records>=256||store(j,"intent",j->record,88))goto failed;
    return j;
failed:sg_pin_journal_close(j);return NULL;
}
int sg_pin_journal_arm(SGPINJournal *j) {
    if(!j||j->armed||j->finished)return -1;
    j->armed=1; /* Failure cannot be relabelled not-executed or rearmed. */
    int result=store(j,"dispatch",j->record,88);
    if(!result)j->armed=2;
    return result;
}
int sg_pin_journal_finish(SGPINJournal *j,int code) {
    if(!j||j->finished)return -1;
    if(code==SG_PIN_JOURNAL_UNCERTAIN){j->finished=1;return 0;}
    if(code<2||code>5||(code==SG_PIN_JOURNAL_NOT_EXECUTED ? j->armed!=0 : j->armed!=2))return -1;
    j->finished=1;
    uint8_t data[90];memcpy(data,j->record,88);data[88]=(uint8_t)code;data[89]=(uint8_t)(255-code);
    return store(j,"result",data,90);
}
void sg_pin_journal_close(SGPINJournal *j){if(j){close(j->lock);close(j->root);free(j);}}
int sg_pin_journal_recover(const char *path,const uint8_t request[16]) {
    if(!request)return SG_PIN_JOURNAL_UNCERTAIN;
    SGPINJournal *j=open_root(path,0);if(!j)return SG_PIN_JOURNAL_UNCERTAIN;
    identifier(request,j->name);uint8_t record[88];int read=read_record(j->root,j->name,"intent",record,88);
    int state=read==1?SG_PIN_JOURNAL_ABSENT:read?SG_PIN_JOURNAL_UNCERTAIN:outcome(j->root,j->name,record);
    sg_pin_journal_close(j);return state;
}
int sg_pin_evidence_descriptor_is_safe(int fd) {
#ifdef __APPLE__
    struct stat s;
    if(fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_nlink!=1||(s.st_mode&0022)||
       (s.st_uid!=0&&s.st_uid!=getuid()))return -1;
    acl_t acl=acl_get_fd(fd);
    if(!acl)return errno==ENOENT?0:-1;
    acl_entry_t entry;errno=0;int status=acl_get_entry(acl,ACL_FIRST_ENTRY,&entry);
    int empty=status!=0&&errno==EINVAL;acl_free(acl);return empty?0:-1;
#else
    (void)fd;return -1;
#endif
}
int sg_pin_journal_prepare_directory(const char *path) {
#ifdef __APPLE__
    if(!path||path[0]!='/'||strlen(path)>4095)return -1;
    const char *leaf=strrchr(path,'/');if(!leaf||leaf==path||!leaf[1]||strlen(leaf+1)>64||!strcmp(leaf+1,".")||!strcmp(leaf+1,".."))return -1;
    char parent_path[4096];size_t n=(size_t)(leaf-path);memcpy(parent_path,path,n);parent_path[n]=0;
    int parent=open(parent_path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW_ANY|O_CLOEXEC);if(parent<0)return -1;
    struct stat info;
    if(fstat(parent,&info)||info.st_uid!=getuid()||(info.st_mode&0022)||sg_discovery_acl_safe(parent_path)!=1){close(parent);return -1;}
    int created=mkdirat(parent,leaf+1,0700)==0;
    if(!created&&errno!=EEXIST){close(parent);return -1;}
    int fd=openat(parent,leaf+1,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    int result=-1;
    if(fd>=0){
        if((created?sg_output_make_private(fd,0700):private_fd(fd,1))==0&&!durable(fd,1)&&!durable(parent,1))result=0;
        close(fd);
    }
    close(parent);
    if(!result){SGPINJournal *j=open_root(path,1);if(!j)return -1;sg_pin_journal_close(j);}
    return result;
#else
    (void)path;return -1;
#endif
}
