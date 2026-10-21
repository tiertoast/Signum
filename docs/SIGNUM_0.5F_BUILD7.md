# Signum 0.5-F — Final consolidation and Beta Build 7

Baseline `80ec17bafb242ad0b28573dbc15b10168f8a2621`, existing European trust branch.
Scope: the requested persistent CAdES signingTime preference, consolidation of the
CAdES diagnosis and isolated local Beta packaging. No new trust/qualification policy.

## Changes

Settings → Firma digitale contains **Includi data e ora della firma**, initially ON,
and the explanation: «La data e ora dichiarate della firma non costituiscono una
marca temporale certificata.» The existing preferences store/AppStorage persists
`signum.signing.includeSigningTime.v1`; the absence of a stored value means ON.
It applies to new CAdES signatures; PAdES generation remains unchanged.

The preference is copied into the review context and approved jobs. Changing it
invalidates a pending review; controls cannot alter an already frozen batch.
ON uses the system clock at CMS preparation, encoded through the existing RFC5652
UTC/GeneralizedTime routine. OFF passes nil and omits only signingTime: contentType,
messageDigest, signingCertificateV2, canonical ordering and signed content remain.
This never rewrites a previous signature or creates trusted temporal evidence.
Single-operation, direct-module and reusable-batch CAdES paths share that choice.

Consolidation fixes a timing issue introduced by automatic signingTime: a batch
manifest and a later per-job preparation could previously observe different seconds,
thus changing worker-approved attributes. The existing locked session now retains
only each manifest job's declared time and reuses it when assembling the CMS.
No document copies, new protocol/component or private-key operation are introduced.
A delayed two-document synthetic batch tests both ON and OFF through the existing
worker before publication. No real device, PIN or private key is accessed.

The previous QC/QSCD correction is preserved: missing proof/assessment produces an
indeterminate device result, distinct from a demonstrated negative/missing device.
Certificate indications, declared signingTime, proven time, revocation and QES stay
separate. No QC/QSCD certificate flag or system-clock attribute can promote QES.
OCSP/CRL clients, responder validation, cache and evidence association remain unchanged.
European E1R/E1S/E2/E4 authentication, service interpretation and historical guards
are reused; no new country/profile capability or crypto algorithm is enabled.

## Packaging and isolation

The existing packager produces **Signum 0.5 Beta — Build 7** with identifier
`io.github.tiertoast.Signum.Beta.B7`, version 0.5.0, build 7, arm64, target macOS 13.0.
The trust model recognizes the B7 identifier rather than falling back to B6.
Preferences use the separate bundle domain. Trusted lists are under
`~/Library/Application Support/io.github.tiertoast.Signum.Beta.B7/TrustedLists`;
revocation cache under `~/Library/Caches/io.github.tiertoast.Signum.Beta.B7/Revocation`.
Neither Beta 0.4 nor existing Previews are overwritten or modified.

The existing relocation/startup script accepts B7 and an optional read-only source
of authenticated TL cache bytes. The B7 smoke uses a separate copy of the existing
production cache, reauthenticates it and compares cache bytes after offline reading;
it downloads no additional lists. The packager checks deployment/architecture,
non-system dependency closure/rpaths and ad hoc seal, retaining native libraries
inside the bundle. Java/Homebrew are not runtime requirements. The ZIP is produced
from the sealed bundle. No notarization, tag, merge or Release publication occurs.

## Validation

One targeted phase passed **55 tests**: Core 36 (CAdES 6, OpenSSL integration 1,
persistent preferences 4, reusable-batch integration 15, signing review 10),
CertificateValidation 19 (European app integration 4, qualification 8, evidence
binding 7). Tests establish default ON, persistent OFF/ON, identical remaining
attributes, OpenSSL-verifiable ON/OFF signatures, readable/absent declared time,
immutable delayed batch attributes, separate multi-signer results and retained
European/QC/QSCD behavior. Existing public/synthetic fixtures are reused.

One complete official campaign follows, with regular Swift/Trust/CertificateValidation,
PAdES, PKCS#11 and packaging contracts. Sanitizers are not repeated: changes add only
Swift values under the existing session lock, no new native/memory-unsafe boundary.
Final results and artifact/checksum information are recorded in the companion JSON.

## Open limits and proposed freeze

- Positive qualification retains E2's six tested countries (IT/AT/DE/BE/FR/ES), direct
  CA/QC, post-2016 and complete temporal/revocation evidence restrictions.
- General current-time QES validation without the supported timestamp proof remains
  unimplemented; a qualified timestamp is not a universal legal requirement for QES.
- TakenOverBy, unsupported criteria/identities, incomplete/incoherent histories,
  pre-2016 classification and broad historical/LTV/PAdES-LT/LTA support remain excluded.
- No executable DSS comparison, physical token compatibility expansion or macOS 13
  runtime execution is claimed. Target metadata is not an OS 13 execution test.
- Declared signingTime uses the system clock and is not an independent time source.
- The earlier real-document online revocation problem was not reproducible in the
  authorized diagnosis; its original HTTP/DNS cause remains undetermined.

**Freeze proposal:** treat this commit and the checksum-identified Build 7 ZIP as
0.5 beta candidate. Suspend functional changes pending the user's final local
acceptance; permit only reproduced blocking defects and documentation corrections.
Keep all listed scope limits visible. Do not merge/tag/publish a release before
explicit user acceptance. This document proposes the freeze; it creates no Git tag,
automation or publication and does not assert that final user testing has occurred.

## Final result

**Passed:** one complete official campaign, 564 Swift tests (Core 434, TrustCore 19,
Authentication 34, Integration 5, CertificateValidation 72), PAdES 81 native cases
each Debug/Release, PKCS#11 58 provider cases plus 2 loader contracts, 18 packaging
contracts. No failures/skips, no post-campaign source correction or repeated suites.
Release packaging, ad hoc seal, dependency/rpath audit, relocation, system-PATH
startup and authenticated isolated B7 offline cache checks passed. The previously
authorized real two-signer CMS was also verified offline using the finished B7
helper/probe: both signatures/chains remain verified, original declared dates are
preserved, and missing temporal evidence does not promote QES/QSCD. No document,
real identifiers or content enters the repo; detailed local evidence stays outside.

The original package and ZIP, exact SHA-256, machine-readable results and logs are
in `outputs/signum-0.5f` in the task workspace. Absolute paths and checksum are in
`SIGNUM_0.5F_RESULTS.json`; the ZIP also has `SHA256SUMS.txt` beside it. No additional
TL was downloaded. User UI/physical-device final acceptance and macOS 13 runtime
testing remain unperformed; the app is a local beta candidate, not a published
release or a completed final user acceptance. No DSS comparison was added.
