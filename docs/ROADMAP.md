# Roadmap

**Signum — Digital signatures. Simply native.**

Signum's direction is a focused native macOS signing and verification experience.
This roadmap describes plans, not delivery commitments or compatibility guarantees.
Current capabilities are documented in [Features](FEATURES.md) and [Formats](FORMATS.md).

## 0.7 — Current Beta

The native signing and verification platform includes CAdES, PAdES, restricted
XAdES/ASiC profiles, document workspaces, Finder integration, device discovery,
European trust assessment and PDF/text reports. Build 18 is distributed for Apple
Silicon with an ad-hoc signature. [Current release](RELEASE_NOTES.md)

The offline RC stability gate passed on 2026-11-27 (M3–M6, five-class and
pertinent-selection campaigns, synthetic fixtures;
[record](engineering/stability/PHASE5A_CAMPAIGN_2026-11-26.json)). Real tokens,
compatibility and accessibility remain outside it, and test isolation while the
display sleeps is still open. The current Beta is not RC-qualified or Stable.

## 0.8 — Reliability and distribution

- Refine macOS compatibility, including real minimum-OS and clean-machine acceptance
  (macOS 13/14 virtual machines; real-token signing on macOS 13 needs physical hardware).
- Recognise devices and middleware (OpenSC or vendor PKCS#11) and explain clearly
  what is missing when one is not usable. Signum does not ship drivers and does not
  maintain a list of supported cards or tokens.
- Resolve demonstrated stability issues with reproducible evidence.
- Improve keyboard, accessibility and installation experience.
- Updates from GitHub Releases: launch check and automatic installation of signed
  updates (in progress).

Distribution stays ad-hoc signed: Developer ID signing and notarization are not
planned, so macOS asks for approval on first launch of a manual download.

## 0.9 — Advanced capabilities

- Consider optional trusted timestamp issuance through explicitly configured RFC 3161 services.
- Extend signature-profile interoperability where supported by independent evidence.
- Consider additional cryptographic features only with a defined use case,
  security model and recovery behavior.

Verification of supported existing timestamps already exists. Issuance is a
separate future capability. TSA services must be opt-in; no embedded vendor
credentials. Encryption/decryption remains lower priority and separately scoped.

## 1.0 — Stable

- A defined and exercised OS and signature-profile support matrix; devices and
  middleware are recognised and diagnosed rather than certified.
- Reproducible, maintainable distribution and dependency/source governance.
- Documented security and compatibility guarantees with clear limits.
- Independent interoperability and recovery evidence for the supported scope.

Preserve immutable approval, isolated token operations, explicit evidence
boundaries and safe file output throughout. Native macOS remains the platform
focus; broader platform work must not dilute those commitments.
