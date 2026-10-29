# Roadmap

**Signum — Digital signatures. Simply native.**

Signum's direction is a focused native macOS signing and verification experience.
This roadmap describes plans, not delivery commitments or compatibility guarantees.
Current capabilities are documented in [Features](FEATURES.md) and [Formats](FORMATS.md).

## 0.7 — Current Beta

The native signing and verification platform includes CAdES, PAdES, restricted
XAdES/ASiC profiles, document workspaces, Finder integration, device discovery,
European trust assessment and PDF/text reports. Build 14 is distributed for Apple
Silicon with an ad-hoc signature. [Current release](RELEASE_NOTES.md)

Compatibility, accessibility and stability refinements remain open. Detailed
M3–M6 follow-up belongs to [issue #9](https://github.com/tiertoast/Signum/issues/9)
and engineering records; the current Beta is not RC-qualified or Stable.

## 0.8 — Reliability and distribution

- Refine macOS compatibility, including real minimum-OS and clean-machine acceptance.
- Define device/middleware interoperability and controlled failure/recovery behavior.
- Resolve demonstrated stability issues with reproducible evidence.
- Improve keyboard, accessibility and installation experience.
- Prepare Developer ID signing, hardened-runtime policy, notarization and Gatekeeper acceptance.
- Establish a maintainable update and distribution process.

## 0.9 — Advanced capabilities

- Consider optional trusted timestamp issuance through explicitly configured RFC 3161 services.
- Extend signature-profile interoperability where supported by independent evidence.
- Consider additional cryptographic features only with a defined use case,
  security model and recovery behavior.

Verification of supported existing timestamps already exists. Issuance is a
separate future capability. TSA services must be opt-in; no embedded vendor
credentials. Encryption/decryption remains lower priority and separately scoped.

## 1.0 — Stable

- A defined and exercised OS, device, middleware and signature-profile support matrix.
- Reproducible, maintainable distribution and dependency/source governance.
- Documented security and compatibility guarantees with clear limits.
- Independent interoperability and recovery evidence for the supported scope.

Preserve immutable approval, isolated token operations, explicit evidence
boundaries and safe file output throughout. Native macOS remains the platform
focus; broader platform work must not dilute those commitments.
