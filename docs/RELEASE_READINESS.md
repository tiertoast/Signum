# Signum — Release-readiness gates

## Current 0.7 Beta status — 29 October 2026

The verified Build 14 DMG is being prepared for an explicitly authorized experimental
GitHub prerelease. [0.7 release notes](SIGNUM_0.7_RELEASE_NOTES.md) and
[artifact evidence](releases/0.7.0-beta/ArtifactManifest.json) are authoritative for
this candidate. The old 0.5 table below remains historical evidence.

- Product source `09316e046a4dd101ce74410a6eeccee6911d4783`; later release commits
  change documentation only. Exact DMG reused, not rebuilt.
- Four Phase8 packaging steps passed; launch/loader and readonly volume audit
  attest the candidate, not all functional or hardware workflows. DMG audit
  repeated for publication; source/notice kit remains in the checked bundle.
- **M3–M6 OPEN (e), deferred; stability/RC gate NOT PASSED.**
  [Issue #9](https://github.com/tiertoast/Signum/issues/9) retains the required follow-up.
- `publicationQualified:false` remains unchanged in the historical evidence.
  The author's Beta distribution decision accepts the stated experimental limits;
  no automated production qualification, Stable designation or RC pass is inferred.
- macOS 13/14 runtime, clean-Mac deployment, wider hardware/middleware,
  accessibility/manual residuals and production signing/Gatekeeper gates stay open.
  Local installation acceptance is not an OS/device matrix.
- PIN change and PUK unblocking remain disabled/unqualified on real devices.
  Existing 0.6 format subsets remain bounded; see its release notes for scope.
- Ad-hoc signature only: no Developer ID/notarization. The app may be blocked by
  Gatekeeper; no automatic weakening of macOS protection is provided.
- Repository visibility stays private; previous releases/tags remain intact.

**Historical 0.5 status:** 21 October 2026 · [v0.5.0-beta / Build 7](https://github.com/tiertoast/Signum/releases/tag/v0.5.0-beta), available as a private GitHub pre-release. This document concerns **technical and distribution readiness**, not authorization to describe every signed document as a legally qualified QES.

Earlier Alpha/Beta Foundation evidence is retained in [its historical report](SIGNUM_BETA_FOUNDATION_REPORT.md) and [the PR #2 review record](PR2_REVIEW_CORRECTIONS.md). The authoritative 0.5 validation record is the [0.5-F engineering report](archive/SIGNUM_0.5F_BUILD7.md) and [results JSON](SIGNUM_0.5F_RESULTS.json).

## Historical evidence validated in 0.5

| Area | Evidence / boundary |
| --- | --- |
| CAdES / PAdES | Local PKCS#11 signing/verification, signed-byte approval binding, no-overwrite publication, batch workflow and graphical PAdES. |
| Signed declared time | CAdES `signingTime` signed attribute, default-ON persistent opt-out; not a timestamp or legal date proof. |
| EU Trusted Lists | Signed LOTL, selective national caches, XMLDSig authentication, continuity/rollback checks; discovery of 30 territories is not 30-country QES validation. |
| Certificates/evidence | Native X.509 path and supported OCSP/CRL and temporal-evidence checks, per-signer results and conservative fail-closed outcomes. |
| eIDAS qualification | Restricted E2 profile for IT/AT/DE/BE/FR/ES, direct CA/QC/post-2016 signatures with sufficient bound historical evidence. General current-time QES validation without timestamp evidence not yet implemented. |
| Automated campaign | **564 Swift tests**, **81 PAdES Debug and 81 Release**, **58 PKCS#11 + 2 loader**, **18 packaging**; no final failures/skips. |
| Real user acceptance | User confirmed Build 7 signing/verification/UI checks on existing hardware. Real two-signer document integrity/chain verified; original online revocation discrepancy was not reproduced. |
| Packaging | Relocated self-contained arm64 ZIP, dependency/rpath and ad hoc codesign checks. Release ZIP checksum available in the GitHub pre-release. |

## Remaining gates for production-grade distribution

| Gate | Status / minimum evidence |
| --- | --- |
| macOS 13/14 runtime | **Open:** real installation and signing on these OS versions; minimum deployment metadata does not prove runtime compatibility. |
| Clean Apple Silicon deployment | **Open:** install without local build environment, separately configured supported middleware, verify bundle dependencies and error UX. |
| Broader middleware/device matrix | **Partial:** expand DigitalDNA, CNS, OpenSC and Bit4id configurations and documented supported versions. |
| Device failure handling | **Partial/open:** device removal, blocked PIN, cancellation, vendor hangs, concurrent provider conflicts and uncertain signing outcomes in controlled hardware sessions. |
| External signature interoperability | **Partial:** CAdES/PAdES coverage exists, but broad third-party corpus and XAdES/ASiC creation/verification remain on the roadmap. |
| General eIDAS/QES verification | **Limited:** supported evidence paths are deliberately narrow; no blanket EU-country/QES, PAdES-LT/LTA or historical-completeness claims. |
| Independent standards comparison | **Open:** no executed DSS comparison/equivalence claim; planned negative profiles and cross-verifier corpus remain. |
| Distribution identity | **Open:** Developer ID, hardened-runtime/vendor-library policy, notarization, Gatekeeper validation and update mechanism. |
| Third-party governance | **Open:** periodic native dependency review, library licenses/notices and release reproducibility/security maintenance. |
| Product experience | **Partial:** current GUI functional; holistic native macOS redesign planned for 0.7. |
| TSA issuance and cryptographic encryption | **Deferred to 0.9**, not required for 0.6 format milestone; verification of supported existing timestamps is separate. |

## Release discipline

1. Preserve the **0.5 Beta Build 7 baseline**, its hash-identified artifacts and earlier 0.4 release. Changes affecting signing, trust, parsing or hardware invoke targeted security tests and the relevant real-device checks.
2. Never imply that a valid CMS/PDF signature alone proves non-revocation, QES status or reliable signing time. Return explicit independent statuses and uncertainty.
3. Never silently overwrite outputs, mutate an approved document or automatically retry an uncertain private-key operation.
4. Enforce isolated local build/test workflows, without GitHub Actions, and publish only tested checksum-identified artifacts.
5. Treat GitHub **Beta pre-release** as a development milestone, not as completed notarization, security assurance or broad legal qualification.

Next development: [0.6 eIDAS current-time policy, XAdES, ASiC and practical interoperability](ROADMAP.md). Previous testing claims belong to their original historical snapshots; this page supersedes the *current-status* statements in the 0.3.3 readiness snapshot.
