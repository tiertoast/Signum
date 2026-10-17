#include "output_permissions.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *chamber = ".permissions", *probe = "empty";
/* Darwin reports an absent extended ACL as ENOENT, not an empty object. */
static acl_t get_acl(int fd) {
    acl_t acl = acl_get_fd(fd);
    return !acl && errno == ENOENT ? acl_init(0) : acl;
}
static int same(int dir, const char *name, const struct stat *expected) {
    struct stat now;
    if (fstatat(dir, name, &now, AT_SYMLINK_NOFOLLOW)) return 0;
    if (now.st_dev != expected->st_dev || now.st_ino != expected->st_ino) {
        errno = ESTALE; return 0;
    }
    return 1;
}
int sg_output_is_private(int fd, mode_t mode) {
    struct stat info;
    if (fstat(fd, &info) || info.st_uid != getuid() || (info.st_mode & 07777) != mode ||
        (mode == 0700 ? !S_ISDIR(info.st_mode) : (!S_ISREG(info.st_mode) || info.st_nlink != 1))) {
        errno = EPERM; return -1;
    }
    acl_t acl = get_acl(fd);
    if (!acl) return -1;
    acl_entry_t entry;
    /* Darwin returns -1/EINVAL at end of list, rather than POSIX's zero. */
    errno = 0;
    int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    int empty = result != 0 && errno == EINVAL;
    acl_free(acl);
    if (!empty) { errno = EPERM; return -1; }
    return 0;
}
int sg_output_make_private(int fd, mode_t mode) {
    struct stat info;
    if (mode != 0700 && mode != 0600) { errno = EINVAL; return -1; }
    if (fstat(fd, &info)) return -1;
    if (info.st_uid != getuid() || (mode == 0700 ? !S_ISDIR(info.st_mode) :
        (!S_ISREG(info.st_mode) || info.st_nlink != 1))) { errno = EPERM; return -1; }
    acl_t empty = acl_init(0);
    if (!empty) return -1;
    int result = acl_set_fd(fd, empty), saved = errno;
    acl_free(empty);
    if (result) { errno = saved; return -1; }
    if (fchmod(fd, mode)) return -1;
    return sg_output_is_private(fd, mode);
}
int sg_output_cleanup_permissions(int stage) {
    struct stat dir, file;
    int fd = openat(stage, chamber, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    int result = -1;
    int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *entries = scan >= 0 ? fdopendir(scan) : NULL;
    if (!entries) { if (scan >= 0) close(scan); close(fd); return -1; }
    int known = 1;
    for (;;) {
        errno = 0; struct dirent *entry = readdir(entries);
        if (!entry) { if (errno) known = 0; break; }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..") && strcmp(entry->d_name, probe)) { known = 0; break; }
    }
    closedir(entries);
    int data = -1;
    if (!known || fstat(fd, &dir) || dir.st_uid != getuid()) { errno = EPERM; goto done; }
    if (fstatat(fd, probe, &file, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(file.st_mode) || file.st_uid != getuid() || file.st_nlink != 1 || file.st_size != 0) {
            errno = EPERM; goto done;
        }
        data = openat(fd, probe, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        struct stat pinned;
        if (data < 0 || fstat(data, &pinned)) goto done;
        if (pinned.st_dev != file.st_dev || pinned.st_ino != file.st_ino || !S_ISREG(pinned.st_mode) ||
            pinned.st_uid != getuid() || pinned.st_nlink != 1 || pinned.st_size != 0) { errno = ESTALE; goto done; }
    } else if (errno != ENOENT) goto done;
    /* A crash can leave the destination's deny-delete ACE on either empty
     * fixture. Neutralize it only after layout, ownership and identity checks. */
    if (sg_output_make_private(fd, 0700)) goto done;
    if (data >= 0 && (sg_output_make_private(data, 0600) || !same(fd, probe, &file) || unlinkat(fd, probe, 0))) goto done;
    if (same(stage, chamber, &dir)) result = unlinkat(stage, chamber, AT_REMOVEDIR);
done:;
    int saved = errno;
    if (data >= 0) close(data);
    close(fd); errno = saved;
    return result;
}
acl_t sg_output_inherited_acl(int parent, int stage) {
    if (sg_output_is_private(stage, 0700)) return NULL;
    acl_t parent_acl = get_acl(parent), result = NULL;
    if (!parent_acl) return NULL;
    int directory = -1, file = -1, have_dir = 0, have_file = 0;
    struct stat dir_info, file_info;
    /* The outer private stage prevents access even while the inner directory
     * has the destination ACL. No document bytes ever enter these objects. */
    if (mkdirat(stage, chamber, 0700)) goto done;
    directory = openat(stage, chamber, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0 || fstat(directory, &dir_info)) goto done;
    have_dir = 1;
    if (acl_set_fd(directory, parent_acl)) goto done;
    file = openat(directory, probe, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (file < 0 || fstat(file, &file_info)) goto done;
    have_file = 1;
    result = get_acl(file);
done:;
    int capture_error = result ? 0 : errno, cleanup_error = 0;
    /* The destination ACL may deny deletion of this directory or its children.
     * These are empty, owned fixtures behind a private ancestor, not the final
     * payload. Capture first, then harden the directory before removing entries;
     * also clear an inherited deny-delete ACE on the empty file itself. */
    if (have_dir && sg_output_make_private(directory, 0700)) cleanup_error = errno;
    if (have_file) {
        if (sg_output_make_private(file, 0600) && !cleanup_error) cleanup_error = errno;
        if ((!same(directory, probe, &file_info) || unlinkat(directory, probe, 0)) && !cleanup_error) cleanup_error = errno;
    }
    if (file >= 0 && close(file) && !cleanup_error) cleanup_error = errno;
    if (have_dir && (!same(stage, chamber, &dir_info) || unlinkat(stage, chamber, AT_REMOVEDIR)) && !cleanup_error) cleanup_error = errno;
    if (directory >= 0 && close(directory) && !cleanup_error) cleanup_error = errno;
    acl_free(parent_acl);
    if (cleanup_error && result) { acl_free(result); result = NULL; }
    /* Keep the first real error; never disguise EACCES/EPERM/etc. as EIO. */
    errno = capture_error ? capture_error : cleanup_error;
    return result;
}
int sg_output_apply_acl(int fd, acl_t acl) {
    if (acl_set_fd(fd, acl)) return -1;
    acl_t actual = get_acl(fd);
    if (!actual) return -1;
    /* Canonical external representations also include flags and ACE order. */
    ssize_t size = acl_size(acl), actual_size = acl_size(actual);
    void *expected = NULL, *observed = NULL;
    int equal = 0;
    if (size > 0 && size == actual_size) {
        expected = calloc(1, (size_t)size); observed = calloc(1, (size_t)size);
        if (expected && observed && acl_copy_ext(expected, acl, size) == size &&
            acl_copy_ext(observed, actual, size) == size) equal = memcmp(expected, observed, (size_t)size) == 0;
    }
    free(expected); free(observed); acl_free(actual);
    if (!equal) { errno = EPERM; return -1; }
    return 0;
}
