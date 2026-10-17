# Signum — Release-readiness gates

**Snapshot: 17 October 2026 · `main` after PR #2 · Signum 0.3.3 Alpha / Beta Foundation.**

This document separates engineering progress from permission to distribute or claim qualified electronic-signature validity. A **Beta Foundation** is a tested architecture milestone; it is **not** a public Beta release. The only authoritative evidence for local test counts and the precise implementation is in:

- [Beta Foundation report](SIGNUM_BETA_FOUNDATION_REPORT.md)
- [PR #2 review corrections](PR2_REVIEW_CORRECTIONS.md)
- [PR #2 discussion](https://github.com/tiertoast/Signum/pull/2)

## Completed engineering milestones

| Area | Evidence and scope |
| --- | --- |
| CAdES / attached `.p7m` | Real hardware signing tested with DigitalDNA/DS3; InfoCamere independently accepted resulting signatures. CMS integrity is checked before exclusive publication. |
| PAdES / signed PDF | Real hardware signing tested with DigitalDNA/DS3; InfoCamere accepted resulting signatures. Native PoDoFo helper verifies its signed output before exclusive publication. |
| Approval-to-signature binding | Immutable private snapshot, SHA-256 and approved certificate identity. |
| Signer selection | Local X.509 eligibility and provider provenance; changing the provider path invalidates previous certificates and PIN. |
| Vendor failure containment | One-shot PKCS#11 worker outside the normal GUI/CLI path, bounded pipe protocol, deadline and cancellation, TERM/KILL supervision. |
| Cooperative multiprocess coordination | Per-provider/slot locks across Signum workers and PAdES helper; OS releases leases after owner death. Not a lock respected by third-party clients. |
| Safe output publication | Same-volume staging, verify then exclusive atomic rename; no silent replacement, conservatively uncertain outcomes on interruptions. |
| Local macOS app packaging | arm64 offline build recipe with pinned native dependencies and bundled PoDoFo, `@loader_path` audit, relocation tests and ad-hoc signature verification. |

**Latest local synthetic evidence reported:** Swift **154/154**, PKCS#11 **40/40**, PAdES **63/63** in each of Debug/Release, packaging tests **10/10**, targeted Swift ASAN **17/17**, native PAdES ASAN **63/63**. Leak detection was disabled; third-party libraries were not fully instrumented; TSAN was not repeated during the final PR correction pass.

**Manual acceptance:** user confirmed the final corrected candidate `.build/pr2-bundles/final-release/Signum.app` signed in CAdES/PAdES, independently validated through InfoCamere, and passed device/provider-selection checks. This is a **single-environment hardware acceptance**, not a generalized compatibility certification.

## Open release gates

| Gate | Status | Required evidence |
| --- | --- | --- |
| Runtime macOS 13 | **Open** | Real `.app` launch, PDF preview, signature flows and ACL/snapshot/driver behavior on a macOS 13 machine. Mach-O minimum 13.0 is not runtime validation. |
| Runtime macOS 14 | **Open** | Same functional and safety matrix on macOS 14. |
| Clean Apple Silicon installation | **Open** | Fresh machine/user account without development tools; bundled PoDoFo and native helper must resolve without Homebrew or checkout dependencies. Separately install chosen PKCS#11 middleware. |
| Middleware matrix | **Partially tested** | Verify OpenSC, Bit4id, DigitalDNA and CNS variants independently, including slot lifecycle and interrupted operations. |
| Hardware failure recovery | **Open** | Controlled tests of device removal, cancellation before/after private request, process crash, busy token, and uncertain PAdES commit; no automated PIN retry. |
| Distribution identity | **Open** | Developer ID signature, hardened-runtime entitlements/library-validation design accommodating third-party vendor middleware, notarization and Gatekeeper behavior. |
| Packaging governance | **Open** | Dependency security/version review, complete third-party license/source obligations and notices, publishing/update process. |
| GUI user experience | **Partial** | Manual verification of error-state wording, selection invalidation, cancellation and no misleading success states. |
| Qualified/legal verification | **Not implemented** | Separate trust engine and evidence for EU trust lists, chain validation, revocation, timestamps and applicable ETSI/eIDAS profiles before any claims of QES/full validation. |
| XAdES and remote signing | **Not implemented** | Future roadmap; unrelated to the Beta Foundation's completion. |

## Rules for advancing

1. Preserve the tested CAdES/PAdES baseline; changes to PKCS#11 lifetime, signing formats, staging or output verification require focused regression suites **and** manual hardware tests.
2. Never infer legal qualification or full certificate trust from a positive local crypto check or an external application reporting an individual signature valid.
3. Never retry an uncertain private signing operation automatically. Preserve potentially published documents and surface the uncertainty clearly.
4. Retain local build/test workflows without GitHub Actions; do not overwrite Alpha bundles or earlier candidates.
5. Declare a distributable Beta **only after** the relevant compatibility, packaging, runtime signing and distribution-security gates are evidenced.

## Next practical milestone

**macOS compatibility and deployment qualification**, not another signature format: exercise the current bundle on macOS 13 and 14, inspect a clean-Mac install, verify vendor middleware setup, then design Developer ID signing and notarization. Detailed implementation follow-up belongs in a new reviewed development branch; it should not retroactively rewrite the 0.3.3 hardware-test evidence.

**Digital signatures. Simply native.**
