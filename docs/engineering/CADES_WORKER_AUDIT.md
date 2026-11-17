# CAdES one-shot worker audit

The CAdES path that starts a fresh `SignumPKCS11Worker` for each signature
writes one JSON Lines file per job:

```text
~/Library/Application Support/Signum-CAdES-Worker-Audit-v1/<job UUID>.jsonl
```

Use the timestamp and worker PID to correlate the file with macOS logs.
`timestampMs` is Unix epoch time in milliseconds. The action is `rsaSHA256`.
Each event after launch carries the worker PID. Only PKCS#11 function names,
raw numeric `CK_RV` values, numeric exit/signal codes and the final operation
phase are recorded alongside the event name and correlation fields.
`moduleLoaded` identifies the canonical module by file basename, device and
inode (compare with `stat -f '%N %d %i' /path/to/module`). The `C_Sign`
entry records the numeric mechanism and exact input byte count, without
recording the path or input itself. `0x40` is `CKM_SHA256_RSA_PKCS`. The
transport records whether it received response bytes, even if it subsequently
rejects the response or discards it on cancellation.

| Evidence | Interpretation |
| --- | --- |
| `requestNotStarted` | The CAdES path did not launch a worker or stopped before sending the complete request. A PID identifies the latter case. |
| `workerLaunched`, without `requestNotStarted` or `pkcs11Enter` for `C_Sign` | The job started without a recorded `C_Sign` entry. `requestAccepted` shows that the worker decoded the request. Earlier PKCS#11 return codes may explain how it stopped. |
| `pkcs11Enter` for `C_Sign` without `signatureVerified` | The worker reached the point immediately before the call. The token might have performed the operation. A matching return event supplies the provider's `CK_RV`, if available. |
| `signatureVerified` | The parent verified the returned signature against the approved certificate and attributes. `jobEnded` reports the final operation phase, including whether publication completed. |

`requestSent` and `requestAccepted` can appear in either order around the
EOF notification on the pipe. `workerExited` records an exit code and
`workerSignalled` records a signal number. A worker that exits after
`terminationPending` may append its exit observation after `jobEnded`.

The audit uses the existing descriptor-based owner, mode and ACL checks.
The directory is private (`0700`) and files are private (`0600`). No PIN,
documents, signatures, key material, IPC contents or certificate attributes
are recorded. Files are appended directly and survive ordinary process exits
and crashes. The audit is best effort. Storage failure, abrupt termination or
power loss can leave events missing, so absence of an entry cannot prove
the absence of a provider call. Audit failures never authorize, retry or
prevent signing. Remove old audit files when no longer needed. There is no
automatic retention policy.

This trace covers the one-shot CAdES route. The authenticated batch worker
uses a separate session protocol. Public discovery, PIN administration,
XAdES/ASiC and PAdES are outside this trace.
