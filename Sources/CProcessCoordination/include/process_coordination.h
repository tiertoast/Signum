#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct SGTokenLease SGTokenLease;
/* One process owns a lease across module load, operation and checked teardown.
 * discovery=1: exclusive provider-wide inventory; otherwise shared provider
 * lease plus exclusive slot lease. Different slots may operate concurrently.
 * Only cooperating Signum processes are protected. Stable provider slot IDs
 * across processes are required; this is not a third-party/token daemon lock. */
SGTokenLease *sg_token_lease_acquire(const char *provider, uint64_t slot, int discovery, unsigned wait_ms);
void sg_token_lease_release(SGTokenLease *lease);
/* Worker-only: terminate on parent death, never Finalize an active vendor call. */
int sg_worker_watch_parent(void);
/* Read-only RSS sampling: 0=sample, 1=observed exit/zombie, -1=unavailable. */
int sg_process_resident_bytes(int pid, uint64_t *bytes);
#ifdef __cplusplus
}
#endif
