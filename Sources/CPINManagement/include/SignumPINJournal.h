#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct SGPINJournal SGPINJournal;
enum { SG_PIN_JOURNAL_ABSENT=0, SG_PIN_JOURNAL_UNCERTAIN=1,
       SG_PIN_JOURNAL_SUCCEEDED=2, SG_PIN_JOURNAL_REJECTED=3,
       SG_PIN_JOURNAL_NOT_EXECUTED=4, SG_PIN_JOURNAL_SUCCEEDED_CLEANUP_FAILED=5 };
/* Existing, persistent, private directory (0700/no ACL). Never a temporary root.
 * No secrets, paths, token serials or credentials are written. Request IDs are
 * tombstoned permanently. domain is stable across scans/provider upgrades;
 * binding also includes configuration/module hashes and the scan generation.
 * One owner; exclusive lock held until close. Unknown/corrupt state fails closed.
 * 256 records maximum; no eviction, automatic recovery/retry or resolution API. */
SGPINJournal *sg_pin_journal_reserve(const char *directory, const uint8_t request[16],
                                    const uint8_t binding[32], const uint8_t domain[32]);
/* Durable before ANY vendor dispatch, including on macOS F_FULLFSYNC failure. */
int sg_pin_journal_arm(SGPINJournal *);
int sg_pin_journal_finish(SGPINJournal *, int result);
void sg_pin_journal_close(SGPINJournal *);
/* Read only: missing outcome (even before arm), malformed data or unsafe path
 * return UNCERTAIN. No record is ever replayed or removed. */
int sg_pin_journal_recover(const char *directory, const uint8_t request[16]);
#ifdef SIGNUM_PIN_ADMIN_TESTING
void sg_pin_journal_test_fail_sync(int enabled);
#endif
#ifdef __cplusplus
}
#endif
/* Pinned-descriptor policy for non-secret qualification evidence: owned by root
 * or this user, regular single-link file, no group/other write or extended ACL. */
#ifdef __cplusplus
extern "C" {
#endif
int sg_pin_evidence_descriptor_is_safe(int fd);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
/* Create only this single child of a trusted existing Application Support
 * parent. Existing unsafe directories are rejected, never repaired. */
int sg_pin_journal_prepare_directory(const char *path);
#ifdef __cplusplus
}
#endif
