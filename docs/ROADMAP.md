# Signum — Development roadmap

**Digital signatures. Simply native.**  
**Updated:** 22 October 2026 · **Platform focus:** native macOS/Apple Silicon · **Current baseline:** [v0.6.0-beta / Build 3](https://github.com/tiertoast/Signum/releases/tag/v0.6.0-beta).

This roadmap is a **plan, not a statement of delivered capabilities**. Completed release evidence remains in the linked engineering reports. The objective is a fast, vendor-independent and well-integrated native macOS signing experience, especially for document-heavy public-administration workflows. Avoid premature cross-platform complexity.

## Milestone overview

| Release | Priority and scope | State |
| --- | --- | --- |
| **0.3** | Reliability foundation: PKCS#11 worker, signed-byte approval, safe outputs | Completed |
| **0.4** | CAdES/PAdES, batches, graphical PDF signing, local integrity verification | [Released Beta Build 14](https://github.com/tiertoast/Signum/releases/tag/v0.4.0-beta.14) |
| **0.5** | EU LOTL/TLs, X.509, OCSP/CRL, historical evidence, conservative eIDAS, signingTime toggle | **[Released Beta Build 7](https://github.com/tiertoast/Signum/releases/tag/v0.5.0-beta)** |
| **0.6** | Current-time eIDAS, XAdES, ASiC, CAdES interoperability and verification reports | **Implemented A–E.1; Build 3 manually accepted; Beta publication authorized** |
| **0.7** | Native macOS GUI/UX redesign, Burgundy `#64313E` and cohesive format workflows | Planned |
| **0.8** | Reliability, interoperability, compatibility and distribution preparation | Planned |
| **0.9** | Optional TSA timestamp issuance and encryption/decryption | Deferred / low priority |
| **1.0** | Stable, maintainable release with explicitly defined supported scope | Goal |

## 0.6 — Signing formats and practical interoperability

A–E.1 are implemented on `feature/signum-0.6e-verification-reports`.
[Definitive release notes](SIGNUM_0.6_RELEASE_NOTES.md) declare the actual subsets;
[Build 3](SIGNUM_0.6_BUILD3_RC.md) consolidates the final identity presentation.
ASiC uses XAdES only; CAdES detached is a separate CMS operation.
Personal identity is informational, independent of integrity and eIDAS.
Manual Build 3 acceptance was confirmed and Beta publication authorized on
22 October 2026. The accepted ZIP is reused without rebuilding. Burgundy stays
in reports until the 0.7 GUI redesign.


The 0.6 cycle should deliver useful formats without compromising 0.5 cryptographic and trust boundaries. **No new timestamp-service dependency is required for the 0.6 baseline.**

### 0.6-A — eIDAS at verification time

- Specify and implement a defensible *current-time* verification policy for un-timestamped signatures, separate from historical validation based on reliable evidence.
- Keep signer-declared `signingTime`, observed verification time, trusted proof of existence, revocation and TL validity **independent**.
- Present certificate QC/QSCD indications independently from the verdict on whether a particular signature qualifies as QES. A lack of timestamp **alone** must not label a signature invalid/non-qualified, and missing evidence must not turn into an unsupported positive QES claim.
- Acceptance: positive, negative and indeterminate cases; realistic Italian CAdES comparisons, documented normative basis, no regression in existing E2 historical gates.

### 0.6-B — XAdES Baseline-B

- Implement **generation and independent verification** of an explicitly scoped XAdES Baseline-B XML signature profile, building on bundled libxml2/xmlsec only where suitable.
- Preserve reference/digest/document binding, canonicalization and `SignedProperties` validation. Explicitly restrict unsupported transforms, external-resource resolution and ambiguous XML signatures.
- Acceptance: interoperable files verified by independent tooling, hostile XML/wrapping/external-reference cases rejected, no private-document uploads, bounded parsing and targeted native/Swift tests.
- Larger XAdES-T/LT/LTA profiles belong to subsequent explicitly reviewed work, not a silent 0.6-B extension.

### 0.6-C — ASiC-S and ASiC-E

- Build and verify bounded **ASiC-S** and **ASiC-E** containers for the supported XAdES/CAdES signature profiles, starting from the smallest interoperable subset.
- Enforce container layout/mimetype and signature-to-payload binding; protect against ZIP path traversal, duplicate names, decompression bombs and ambiguous manifest/reference handling.
- Acceptance: validated archive creation/extraction, multiple-file cases where supported, cross-vendor interoperability and negative security fixtures. Never treat a valid ZIP alone as a verified signature.

### 0.6-D — CAdES advanced interoperability

- Add **detached CAdES**, safe co-signing/additional signers and countersignatures as distinct operations, without invalidating earlier signers.
- Existing multi-SignerInfo **verification** is not evidence that every co-signing/countersigning creation workflow is implemented.
- Acceptance: single and multi-signer reference documents, InfoCamere/OpenSSL interoperability, content and signer identity binding, atomic output and no-overwrite behavior.

### 0.6-E — Verification reports

- Offer an exportable, human-readable verification report with each signature's **integrity, certificate path, revocation, time and eIDAS qualification** as separate outcomes.
- Clearly distinguish `signingTime` from verified timestamp evidence and indeterminate results from invalid signatures. Do not invent legal conclusions.
- Acceptance: stable machine/testable report values, useful PDF/text export, support for supported CAdES/PAdES/XAdES/ASiC coverage and no leakage of PINs or document contents.

**0.6 close-out:** one consolidated regression campaign, real-token acceptance for affected signing workflows, independent interoperability corpus, and beta packaging with an honest limitations list. No GitHub Actions, no repeated full suites at every submilestone.

## 0.7 — Native macOS experience

Redesign the workflow in SwiftUI/AppKit around document preview, signatures, signer identities, formats and trustworthy verification results. Preserve direct interaction, keyboard accessibility, useful error states and batch operations; avoid UI changes that blur approval or signature/document binding. The interface should remain recognizably native, lightweight and independent of external vendor panels.

## 0.8 — Hardening and distribution

Expand real-device and real-OS coverage (notably macOS 13/14, OpenSC/Bit4id/CNS, clean-Mac installation), failure recovery, fuzz/negative parsing, interoperability and packaging review. Prepare Developer ID signing, hardened runtime, notarization, third-party licenses, updates and release governance. Distinguish declared OS minimum from verified runtime compatibility.

## 0.9 — Lower-priority optional services

- **Timestamp issuance and application:** configurable external RFC 3161 TSA credentials/endpoints; evaluate interoperable TST/TSR/TSD/M7M and PDF timestamp outputs only after explicit scope/security review. **Existing supported timestamp verification is already present in 0.5**; issuing a timestamp is a different feature.
- **Encryption/decryption:** separately scoped cryptographic formats, key/certificate recipient management, privacy and recovery/error behavior. The apparent UI simplicity is not evidence of trivial security implementation.
- External-service dependencies must be opt-in. Do not embed vendor credentials or imply a timestamp is produced locally without a TSA.

## 1.0 — Stable release gates

A clearly scoped supported-format and hardware matrix; reproducible signed/notarized distribution; independently exercised CAdES/PAdES/XAdES/ASiC interoperability; negative and recovery tests; meaningful verification reports; documentation of standards/eIDAS limits and third-party obligations. Only claim qualified-signature validation for policies that are actually demonstrated.

## Project rules

1. **macOS-first**, native performance and minimal dependencies; no forced Windows rewrite.
2. Preserve audited security boundaries: immutable approved bytes, trusted-list authentication and provenance, isolated PKCS#11 execution, certificate/document binding, verified exclusive output.
3. Distinguish crypto correctness, validity at a stated time, trust and legal qualification. Uncertain stays uncertain.
4. Focused tests during development; complete suites at milestone/build close, plus hardware checks when the signing path changes.
5. Local build and test only; **no GitHub Actions**. Keep previous releases/tags intact.
6. Defer additional formats, services or UI redesign outside a milestone rather than silently expanding its scope.

Historical evidence: [0.5-F](SIGNUM_0.5F_BUILD7.md), [0.5-E2](SIGNUM_0.5E2_EUROPEAN_CATALOG.md), [0.4](SIGNUM_0.4_PROGRESS.md). Distribution gates: [RELEASE_READINESS](RELEASE_READINESS.md).
