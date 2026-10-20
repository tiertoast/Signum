#pragma once
#include <sys/acl.h>
#include <sys/types.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Descriptor-only macOS policy shared by the Swift and native writers. */
int sg_output_is_private(int fd, mode_t mode);
int sg_output_make_private(int fd, mode_t mode);
/* Requires a hardened stage. Uses only empty objects inside it to let the
 * kernel derive file inheritance from the pinned destination's current ACL. */
acl_t sg_output_inherited_acl(int parent, int stage);
int sg_output_apply_acl(int fd, acl_t acl);
/* Conservative recovery of the empty inheritance fixture after a crash. */
int sg_output_cleanup_permissions(int stage);
/* Read-only check: 1 = no extended ACL write grants, 0 = unsafe, -1 = error. */
int sg_discovery_acl_safe(const char *path);
#ifdef __cplusplus
}
#endif
