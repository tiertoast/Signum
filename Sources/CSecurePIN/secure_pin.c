#include "SignumSecurePIN.h"
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <math.h>

/* Volatile stores are observable and cannot be optimized away (macOS 13). */
static void wipe(void *p, size_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }

struct SGSecurePIN { void *mapping; uint8_t *bytes; size_t page, length; };
SGSecurePIN *sg_secure_pin_create(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page < 64 || page > 1048576) return NULL;
    SGSecurePIN *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->page = (size_t)page;
    s->mapping = mmap(NULL, s->page * 3, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (s->mapping == MAP_FAILED) { free(s); return NULL; }
    s->bytes = (uint8_t *)s->mapping + s->page;
    if (mprotect(s->bytes, s->page, PROT_READ | PROT_WRITE) || mlock(s->bytes, s->page)) {
        munmap(s->mapping, s->page * 3); free(s); return NULL;
    }
    return s;
}
void sg_secure_pin_clear(SGSecurePIN *s) {
    if (s) { wipe(s->bytes, s->page); s->length = 0; }
}
void sg_secure_pin_destroy(SGSecurePIN *s) {
    if (!s) return;
    sg_secure_pin_clear(s);
    munlock(s->bytes, s->page); munmap(s->mapping, s->page * 3);
    wipe(s, sizeof(*s)); free(s);
}
const uint8_t *sg_secure_pin_bytes(const SGSecurePIN *s) { return s && s->length ? s->bytes : NULL; }
size_t sg_secure_pin_length(const SGSecurePIN *s) { return s ? s->length : 0; }
int sg_secure_pin_set(SGSecurePIN *s, const uint8_t *value, size_t n) {
    if (!s) return -1;
    sg_secure_pin_clear(s);
    if (!value || !n || n > 64 || memchr(value, 0, n)) return -1;
    memcpy(s->bytes, value, n); s->length = n; return 0;
}
static double monotonic(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return now.tv_sec + now.tv_nsec / 1e9;
}
static int read_exact(int fd, uint8_t *bytes, size_t n, double deadline) {
    size_t offset = 0;
    while (offset < n) {
        double now = monotonic();
        if (now < 0 || now >= deadline) return -1;
        struct pollfd p = { fd, POLLIN, 0 };
        int ready = poll(&p, 1, 10);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -1;
        if (!ready) continue;
        ssize_t count = read(fd, bytes + offset, n - offset);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) return -1;
        offset += (size_t)count;
    }
    return 0;
}
int sg_secure_pin_receive(SGSecurePIN *s, int fd, double timeout) {
    if (!s) return -1;
    sg_secure_pin_clear(s);
    double now = monotonic();
    if (fd < 0 || now < 0 || !isfinite(timeout) || timeout <= 0 || timeout > 60) return -1;
    double deadline = now + timeout;
    uint8_t header[4];
    if (read_exact(fd, header, 4, deadline)) return -1;
    uint32_t n = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) | ((uint32_t)header[2] << 8) | header[3];
    if (!n || n > 64) return -1;
    if (read_exact(fd, s->bytes, n, deadline) || memchr(s->bytes, 0, n)) {
        sg_secure_pin_clear(s); return -1;
    }
    s->length = n; return 0;
}

/* A terminal has submission keys, unlike the length-delimited worker channel.
 * Explicit LF is the sole terminator; CR and pasted multi-line input are refused.
 * The prompt states Ctrl-J so no implicit CR->LF conversion can alter a PIN. */
#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
static int strict_utf8(const uint8_t *p, size_t n) {
    size_t i=0;
    while(i<n) {
        uint32_t value=p[i++], minimum=0; unsigned rest=0;
        if(value<0x80) continue;
        if(value>=0xc2 && value<=0xdf){value&=0x1f;rest=1;minimum=0x80;}
        else if(value>=0xe0 && value<=0xef){value&=0x0f;rest=2;minimum=0x800;}
        else if(value>=0xf0 && value<=0xf4){value&=7;rest=3;minimum=0x10000;}
        else return 0;
        if(rest>n-i) return 0;
        while(rest--){uint8_t b=p[i++];if((b&0xc0)!=0x80)return 0;value=(value<<6)|(b&0x3f);}
        if(value<minimum || value>0x10ffff || (value>=0xd800 && value<=0xdfff))return 0;
    }
    return 1;
}
int sg_secure_pin_read_terminal(SGSecurePIN *s, double timeout) {
    if(!s)return -1;
    sg_secure_pin_clear(s);
    if(!isfinite(timeout) || timeout<=0 || timeout>600)return -1;
    int fd=open("/dev/tty",O_RDWR|O_CLOEXEC|O_NOCTTY);
    if(fd<0)return -1;
    struct termios original, raw;
    int changed=0, result=-1; uint8_t value=0;
    if(tcgetattr(fd,&original))goto done;
    raw=original;cfmakeraw(&raw);
    if(tcsetattr(fd,TCSAFLUSH,&raw))goto done;
    changed=1;
    const char prompt[]="Token PIN (1-64 byte UTF-8, no NUL/CR/LF; conferma Ctrl-J, annulla Ctrl-C): ";
    size_t offset=0;
    while(offset<sizeof(prompt)-1){ssize_t n=write(fd,prompt+offset,sizeof(prompt)-1-offset);if(n<0&&errno==EINTR)continue;if(n<=0)goto done;offset+=(size_t)n;}
    double now=monotonic();if(now<0)goto done;
    const double deadline=now+timeout;
    for(;;) {
        now=monotonic();if(now<0 || now>=deadline)goto done;
        struct pollfd p={fd,POLLIN,0};int ready=poll(&p,1,10);
        if(ready<0&&errno==EINTR)continue;
        if(ready<0)goto done;if(!ready)continue;
        ssize_t n=read(fd,&value,1);if(n<0&&errno==EINTR)continue;if(n!=1)goto done;
        if(value=='\n') {
            int pending=0;
            if(ioctl(fd,FIONREAD,&pending) || pending || !s->length || !strict_utf8(s->bytes,s->length))goto done;
            result=0;break;
        }
        if(value==0 || value=='\r' || value==3 || value==4 || s->length>=64)goto done;
        s->bytes[s->length++]=value;wipe(&value,1);
    }
 done:
    wipe(&value,1);
    if(changed) {
        /* Discard refused input before re-enabling echo. Never print it. */
        if(tcflush(fd,TCIFLUSH))result=-1;
        if(tcsetattr(fd,TCSANOW,&original))result=-1;
        (void)write(fd,"\n",1);
    }
    close(fd);
    if(result)sg_secure_pin_clear(s);
    return result;
}
