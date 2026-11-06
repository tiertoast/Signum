# Daily usability fixes: review and hardware acceptance

Scope: selective workspace removal, native verification PDF viewing, and advanced
CAdES input diagnosis. No release files, tags, published artifacts, CI, HalleyMac,
or M3–M6 tests/evidence are changed. Issue #9 remains open and unqualified.

## Findings and behavior

### Selective removal

Both workspaces imposed a global busy/frozen guard. Verification also retained
array indices across asynchronous qualification, which would become invalid if
removal were simply enabled. It now resolves UUIDs after each suspension, skips
removed pending entries, discards late results, and continues unrelated work.

Signing removal revokes future approval synchronously without mutating the old
`BatchApproval` or cancelling an unrelated active operation. Remaining pending
jobs require a fresh review and PIN authorization after the current operation
and any authenticated session have drained. New plans include only nonterminal
documents; completed results and published outputs remain available.

Removing the active signing row requests controlled cancellation and keeps the
row until the operation resolves. Cancellation before private work can retire
the row; uncertain private outcomes remain visible and block further signing.
A publication already committed remains a completed result. There is no retry.
Authenticated continuation checks consent between jobs and preserves cleanup
uncertainty during retirement. Removal never deletes an original or output.

### Open in macOS Preview

The verification action opens Apple's `com.apple.Preview` explicitly using
[NSWorkspace](https://developer.apple.com/documentation/appkit/nsworkspace/open(_:withapplicationat:configuration:completionhandler:)).
It uses `VerificationReport.previewPDF`, never reopens the original path. The
same rule covers verified attached P7M payloads, including nested extraction
already performed by the verification service. CoreGraphics validates PDF
structure before any file is created; encrypted/unsupported content is rejected.

A random directory has mode 0700 and an empty ACL; its exclusive-created PDF has
an empty ACL and mode 0400. Filenames do not contain source or signer names.
Files survive row/window removal and Signum exit because Preview may still need
them. Cleanup happens when Preview terminates, or on the next open while Preview
is not running, including crash leftovers. Concurrent opens are protected from
cleanup during launch. Recovery does not follow directory symlinks or recursively
delete unknown contents. There is intentionally no timer deleting an open PDF.
Preview can save a separate copy; the original signed file remains untouched.
The UI explains that viewing does not establish signature validity. PAdES signing
placement retains its existing PDFKit workflow.

### DigitalDNA / misleading X.509 error

Ordinary CAdES, co-signing and countersigning use the same selected certificate
DER, object ID, provider, slot and bound `SigningProviderContext`; advanced jobs
use the same isolated RSA worker. No certificate filter or fallback is changed.

A reproducible non-token defect was found: `CAdESAdvanced` used the strict DER
certificate reader for the *input CMS envelope*. A valid streaming BER envelope
therefore threw `SignumError.invalidCertificate`, displayed as “The token did
not provide a valid X.509 certificate”, before any certificate/key operation.
[CMS permits BER envelopes while signed attributes require DER](https://www.rfc-editor.org/rfc/rfc5652.html#section-5.3).

The CMS envelope reader now accepts bounded constructed indefinite BER,
including chunked OCTET STRING content. It preserves existing content encoding,
signed attributes and signature values; certificates still use the unchanged
strict DER/security checks. Parser depth, node, payload, signer and certificate
limits remain enforced. Malformed/unsupported CMS produces a CMS error rather
than blaming the token. Native integrity verification remains mandatory before
and after adding a signature, including explicit countersignature relationships.

Synthetic coverage reproduces the former X.509 error, then signs ordinary CAdES,
co-signatures and countersignatures with one identical bound fixture certificate.
Stale token contexts fail before PIN/login/private operations, and the existing
slot/module/object-ID mismatch tests still pass. This establishes a software
fix, **not a confirmed root cause for the user's particular DigitalDNA/P7M**:
the original failing document and physical token were not exercised.

## Validation (6 November 2026)

macOS 27.2 arm64, Xcode 27.2, Apple Swift 6.4.2. Native helper built from this
checkout with PoDoFo 1.1.2 and OpenSSL 3.5.9; existing xmlsec/OpenSSL inputs were
read only. No dependencies were installed. This host's native libraries target a
newer macOS than 13; this is not minimum-OS or release-artifact qualification.
All build scratch, fixtures, logs and rendered screenshots are external.

- 69 focused XCTest methods passed, no failures/skips:
  `SessionDocumentRemovalTests`, `PDFPreviewPreparationTests`,
  `CAdESAdvancedTests`, `OneShotContextTests`, `SigningSessionReleaseTests`,
  `SigningReviewTests`, `SigningInteractionTests`, `BatchCleanupContractTests`.
- 51 adjacent regression methods passed, no failures/skips:
  `BatchSigningTests`, `CAdESTests`, `CAdESInputTests`,
  `CertificateSigningGateTests`, `VerificationDropLifecycleTests`,
  `SigningWorkspaceTests`, `SigningWorkspaceSelectionTests`.
- After the final CMS collection-index guard, all 18 `CAdESAdvancedTests` passed
  again. Total: **120 distinct passing methods**, not a complete-suite claim.
- App/CLI/workers and the compiled test catalog built successfully. Native
  workspace rendering and the original PAdES preview tests passed. Actual
  interactive Preview launch/zoom and real-token acceptance remain manual.
- `git diff --check` passed. No M3–M6 campaign or remote CI was run.

Earlier failed attempts are retained in external logs: shared `/private/tmp`
fixture ancestors were correctly rejected by middleware path security; the
restricted run could not exercise WindowServer/terminal checks; and one legacy
batch assertion still required the old frozen-list removal policy. The latter
now asserts removal, revoked consent, immutable old jobs, preserved existing
output and rejection of stale confirmation. No timeout, skip or security
assertion was relaxed. With private per-user fixtures and macOS session access,
the complete selected sets above passed.

For reproduction, use the dependencies and external scratch conventions in
[Building](../BUILDING.md) and [Local checks](../LOCAL_TESTING.md). Run focused
`swift test --scratch-path <new-external-build> --filter '(<classes-above>)/'`
with `PKG_CONFIG_PATH`/`PKG_CONFIG_LIBDIR` for the prepared xmlsec prefix,
`SIGNUM_TEST_PADES_HELPER` for the freshly built helper, and
`SIGNUM_TEST_XMLSEC` for its CLI. Set `SIGNUM_TEST_FIXTURE_ROOT` and
`SIGNUM_TEST_EVIDENCE_ROOT` to new private directories **under the canonical
per-user macOS temporary directory**, not shared `/private/tmp`; an active
WindowServer and controlling-terminal access are required for the adjacent set.

## Mac mini operator check (required before marking ready)

No files need uploading to prepare this PR. Use non-sensitive disposable local
copies of a PDF and an already signed attached P7M, plus the DigitalDNA token and
its usual middleware. Build this branch as a separate local app as documented;
the published Beta does not contain these changes.

1. During verification of several documents, remove completed, pending and active
   rows; remaining results must finish and removed rows must not reappear.
2. During signing A, remove pending B; A must resolve normally and remaining C
   must require fresh consent. Repeat with authenticated/temporary-PIN mode:
   there must be no automatic signature of C from the revoked plan.
3. Request removal of A before and during the token operation. An uncertain
   outcome must remain visible and must never trigger an automatic retry.
   Check for an already published output before authorizing any new attempt.
4. Open a verified PDF and a PDF inside P7M in Anteprima. Check zoom/navigation,
   original-file hashes, survival after row removal/Signum exit, and cleanup
   after quitting Preview and using the action again. Test multiple windows.
5. With the same selected DigitalDNA certificate, sign ordinary CAdES, co-sign
   an attached P7M, and countersign an explicitly chosen signature. Independently
   verify both resulting CMS files and the countersignature's parent.
6. Disconnect/change the token or selected certificate after approval: it must
   fail explicitly without selecting another certificate or requesting a retry.

If the original X.509 symptom persists, retain a non-sensitive reproducing P7M
and the stage/error text, macOS/middleware version and operation format. Public
certificate metadata may help a follow-up; never share PINs or private keys.
Do not close M3–M6 or qualify physical compatibility from these software tests.
