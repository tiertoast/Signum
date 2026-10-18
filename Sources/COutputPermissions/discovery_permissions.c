#include <sys/acl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "output_permissions.h"

/* Read-only, conservative automatic-code policy. Deny ACEs do not cancel an
 * allow ACE here. Even root-targeted write grants are rejected, conservatively.
 * Root ownership/POSIX/path provenance are checked separately by the caller. */
int sg_discovery_acl_safe(const char *path) {
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    int saved = errno;
    close(fd);
    if (!acl) { errno = saved; return saved == ENOENT ? 1 : -1; }
    acl_entry_t entry;
    int selector = ACL_FIRST_ENTRY, safe = 1;
    for (;;) {
        errno = 0;
        int result = acl_get_entry(acl, selector, &entry);
        selector = ACL_NEXT_ENTRY;
        if (result != 0) {
            if (!(result == -1 && errno == EINVAL)) safe = -1;
            break;
        }
        acl_tag_t tag;
        acl_permset_t permissions;
        if (acl_get_tag_type(entry, &tag) || acl_get_permset(entry, &permissions)) { safe = -1; break; }
        if (tag != ACL_EXTENDED_ALLOW) continue;
        const acl_perm_t writes[] = {ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE,
            ACL_DELETE_CHILD, ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES,
            ACL_WRITE_SECURITY, ACL_CHANGE_OWNER};
        for (unsigned i = 0; i < sizeof(writes) / sizeof(writes[0]); ++i) {
            int bit = acl_get_perm_np(permissions, writes[i]);
            if (bit < 0) { safe = -1; break; }
            if (bit) { safe = 0; break; }
        }
        if (safe != 1) break;
    }
    acl_free(acl);
    return safe;
}
