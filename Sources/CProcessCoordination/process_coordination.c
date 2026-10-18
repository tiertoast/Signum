#include "process_coordination.h"
#include "output_permissions.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <libproc.h>
#include <sys/proc.h>

int sg_process_resident_bytes(int pid, uint64_t *bytes) {
    struct proc_taskinfo info;
    if (!bytes) return -1;
    if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &info, sizeof(info)) != sizeof(info)) {
        struct proc_bsdinfo state;
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &state, sizeof(state)) == sizeof(state))
            return state.pbi_status == SZOMB ? 1 : -1;
        return errno == ESRCH ? 1 : -1;
    }
    *bytes = info.pti_resident_size;
    return 0;
}

struct SGTokenLease { int provider, token; };
static uint64_t milliseconds(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
static int lock_until(int fd, int mode, uint64_t deadline) {
    for (;;) {
        if (flock(fd, mode | LOCK_NB) == 0) return 0;
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) return -1;
        if (milliseconds() >= deadline) { errno = ETIMEDOUT; return -1; }
        struct timespec pause = {0, 10000000}; nanosleep(&pause, NULL);
    }
}
static int private_root(void) {
    char path[PATH_MAX], canonical[PATH_MAX];
    size_t size = confstr(_CS_DARWIN_USER_TEMP_DIR, path, sizeof(path));
    if (!size || size > sizeof(path) || !realpath(path, canonical)) return -1;
    int parent = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC);
    if (parent < 0) return -1;
    struct stat info;
    if (fstat(parent, &info) || info.st_uid != getuid() || (info.st_mode & 0077)) {
        close(parent); errno = EPERM; return -1;
    }
    const char *name = ".signum-coordination-v1";
    if (mkdirat(parent, name, 0700) && errno != EEXIST) { int saved = errno; close(parent); errno = saved; return -1; }
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int saved = errno; close(parent); errno = saved;
    if (fd < 0) return -1;
    if (sg_output_make_private(fd, 0700)) { saved = errno; close(fd); errno = saved; return -1; }
    return fd;
}
static int lock_file(int root, const char *name) {
    int fd = openat(root, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0) return -1;
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != getuid() || info.st_nlink != 1 || info.st_size != 0) {
        close(fd); errno = EPERM; return -1;
    }
    if (sg_output_make_private(fd, 0600)) { int saved = errno; close(fd); errno = saved; return -1; }
    // Never unlink lock files: replacing a live lock inode would split owners.
    return fd;
}
SGTokenLease *sg_token_lease_acquire(const char *provider, uint64_t slot, int discovery, unsigned wait_ms) {
    struct stat identity; char canonical[PATH_MAX], name[160];
    if (!provider || provider[0] != '/' || wait_ms > 30000 || (discovery != 0 && discovery != 1)) { errno = EINVAL; return NULL; }
    if (!realpath(provider, canonical) || stat(canonical, &identity)) return NULL;
    if (!S_ISREG(identity.st_mode)) { errno = EINVAL; return NULL; }
    int root = private_root(); if (root < 0) return NULL;
    SGTokenLease *lease = calloc(1, sizeof(*lease));
    if (!lease) { close(root); return NULL; }
    lease->provider = lease->token = -1;
    uint64_t deadline = milliseconds() + wait_ms;
    snprintf(name, sizeof(name), "provider-%llx-%llx", (unsigned long long)identity.st_dev, (unsigned long long)identity.st_ino);
    lease->provider = lock_file(root, name);
    if (lease->provider < 0 || lock_until(lease->provider, discovery ? LOCK_EX : LOCK_SH, deadline)) goto failed;
    if (!discovery) {
        snprintf(name, sizeof(name), "token-%llx-%llx-%llx", (unsigned long long)identity.st_dev,
                 (unsigned long long)identity.st_ino, (unsigned long long)slot);
        lease->token = lock_file(root, name);
        if (lease->token < 0 || lock_until(lease->token, LOCK_EX, deadline)) goto failed;
    }
    close(root); return lease;
failed:;
    int saved = errno; close(root); sg_token_lease_release(lease); errno = saved; return NULL;
}
void sg_token_lease_release(SGTokenLease *lease) {
    if (!lease) return;
    if (lease->token >= 0) close(lease->token);
    if (lease->provider >= 0) close(lease->provider);
    free(lease);
}
static _Atomic int watching = 0;
static void *watch_parent(void *argument) {
    const pid_t parent = (pid_t)(intptr_t)argument;
    for (;;) { usleep(250000); if (getppid() != parent) _exit(74); }
    return NULL;
}
int sg_worker_watch_parent(void) {
    if (atomic_exchange(&watching, 1)) return 0;
    const pid_t parent = getppid();
    if (parent <= 1) { errno = ECHILD; return -1; }
    struct rlimit core = {0, 0}; if (setrlimit(RLIMIT_CORE, &core)) return -1;
    pthread_t thread;
    int status = pthread_create(&thread, NULL, watch_parent, (void *)(intptr_t)parent);
    if (status) { errno = status; return -1; }
    pthread_detach(thread); return 0;
}
