# Signum

**Digital signatures. Simply native.**

Signum is a lightweight, native macOS application for local digital signatures and verification, built in Swift/SwiftUI with native cryptographic helpers. It is designed for everyday document workflows, including the Italian public administration, while avoiding dependence on any single token vendor's desktop software.

> **Current Beta: Signum 0.7.0 — Build 14** ([release](https://github.com/tiertoast/Signum/releases/tag/v0.7.0-beta)). Apple Silicon arm64, ad-hoc signed, no Developer ID or notarization. **M3–M6 remain open; the RC stability gate is NOT PASSED.** The repository and release assets remain private.

For planned work, scope and milestone gates, see the **[development roadmap](docs/ROADMAP.md)**. For distribution and assurance gaps, see **[release readiness](docs/RELEASE_READINESS.md)**.

## Signum 0.7.0 Beta — Build 14

Native document workspace, signing inspector, Finder/services integration,
cumulative verification and a redesigned Devices experience. Stabilization covers
PDF revision coverage, conservative PAdES cleanup, session cancellation, exact CLI
PIN bytes and PIN buffer lifecycle. Real PIN changes and PUK unblocking remain
disabled and unqualified; the administrative foundation is synthetic only.

The exact verified DMG is reused without rebuilding: product source
`09316e046a4dd101ce74410a6eeccee6911d4783`, bundle `io.github.tiertoast.Signum`,
version 0.7.0 / build 14. Declared macOS minimum 13.0 is not a runtime qualification
on macOS 13/14. Clean-Mac and wider hardware/middleware acceptance remain open.
The author's installation acceptance concerns the local Mac only.

See [0.7 release notes](docs/SIGNUM_0.7_RELEASE_NOTES.md),
[artifact evidence](docs/releases/0.7.0-beta/ArtifactManifest.json) and
[open M3–M6 follow-up](https://github.com/tiertoast/Signum/issues/9).
No Stable or RC promotion is claimed. Earlier releases and evidence remain intact.

## Signum 0.6.0 Beta — Build 3

**Signum 0.6.0 Development Preview — Build 3** consolidates current-time eIDAS
assessment, XAdES-B enveloped, ASiC-S/E with detached XAdES, detached CAdES,
co-/counter-signatures and PDF/TXT verification reports. Manual Build 3 acceptance
was confirmed on 22 October 2026 and Beta publication authorized.
**[Signum 0.6.0 Beta](https://github.com/tiertoast/Signum/releases/tag/v0.6.0-beta)**
distributes the exact accepted Development Preview Build 3 ZIP, with its original
isolated identity and ad hoc signature; no rebuild, Developer ID or notarization.
The released 0.4/0.5 Betas and previous previews remain unchanged.

Verification summaries and reports display each signer's personal Subject name,
Italian personal codice fiscale when unambiguously present, and individual outcomes.
Company identifiers are not presented as personal fiscal codes. Missing identity
fields are explicitly unavailable; identity alone does not grant trust or QES.
In the historical 0.6 release Burgundy accents applied to reports only; the 0.7 GUI now adopts them.

See [0.6 release notes and manual checklist](docs/SIGNUM_0.6_RELEASE_NOTES.md)
and [Build 3 scope/provenance](docs/SIGNUM_0.6_BUILD3_RC.md). Profiles remain bounded:
no XAdES-T/LT/LTA, ASiC CAdES, timestamp issuance, encryption or universal eIDAS claim.

## Historical 0.5 Beta scope

| Area | Current scope |
| --- | --- |
| **CAdES** | Local PKCS#11 attached CMS/`.p7m` signing and cryptographic verification; safe batch signing; automatic signed `signingTime` attribute with a persistent ON-by-default setting to omit it when desired. |
| **PAdES** | PDF signing through a bundled native PoDoFo helper; visible/invisible appearance with PDFKit preview, placement and approved resources. |
| **Verification** | CAdES/PAdES signature integrity and independent per-signer reports; certificate-chain trust, revocation, temporal evidence and eIDAS qualification exposed separately. |
| **European Trusted Lists** | Authentic EU LOTL and selected national TLs, cryptographic XMLDSig authentication, cache continuity/rollback controls, selective acquisition and offline use of authenticated cached evidence. |
| **Certificate/revocation** | X.509 chain checks against applicable TL services; supported OCSP/CRL evidence with conservative validation of responder, binding and freshness. |
| **Time and qualification** | Verification of supported timestamp evidence; signing time *declared by the signer* is **not** an independently trusted timestamp. Positive eIDAS qualification has deliberate restrictions (below). |
| **Hardware** | Local middleware through OpenSC/Bit4id and PKCS#11, certificate/reader discovery, isolated worker process for standard signing paths. DigitalDNA and CNS configurations have been manually tested; other devices need independent acceptance. |
| **Interface** | Native macOS signing and verification panels, PDF preview and Trust Lists settings, explicit approval, cancellation and conservative error handling. |
| **Not yet implemented** | Creation/verification of XAdES and ASiC containers, remote signing, timestamp *issuance* by an external TSA, encryption/decryption. |

### Scope of eIDAS verification

Signum 0.5 distinguishes **cryptographic integrity**, **trusted certificate chain**, **revocation**, **proven temporal evidence** and **eIDAS/QSCD qualification**. The authenticated EU LOTL exposes 30 EU/EEA territories for selective national TL acquisition; that **does not imply** positive QES coverage for 30 countries.

The positive qualification policy validated so far is deliberately narrow: IT, AT, DE, BE, FR and ES, direct signer-to-CA/QC paths, applicable post-2016 profiles and sufficiently bound time/revocation evidence. Broader histories, profiles and general validation of un-timestamped signatures at the current time remain unsupported or indeterminate. A qualified electronic signature does **not** universally require a qualified timestamp, but removing temporal checks indiscriminately would be unsafe. See [European catalog evidence](docs/SIGNUM_0.5E2_EUROPEAN_CATALOG.md) and [Build 7 limitations](docs/SIGNUM_0.5F_BUILD7.md).

## Reliability and safety

- Signing uses an immutable approved document snapshot, signer/certificate binding, isolated PKCS#11 worker operation and bounded supervision.
- The signed output is verified before exclusive, atomic publication; files are never silently overwritten and uncertain private operations are not automatically retried.
- CAdES batch signing preserves the approved CMS attributes even when a job is delayed.
- Revocation, trust, declared signing time and legal qualification are **not conflated**: an absent timestamp does not make the cryptographic signature invalid, and `signingTime` alone cannot prove the date or a QES verdict.
- National Trusted List cache presence is not treated as authentication; missing, expired or inconsistent trust material fails closed.

Worker isolation reduces the impact of middleware crashes/hangs on the UI; it is **not** a privilege sandbox against hostile third-party modules. Avoid putting PINs or private document contents in logs, command arguments or issues.

## Historical 0.5 Beta validation

The frozen 0.5-F campaign passed **564 Swift tests**, **81 PAdES native cases in Debug and Release each**, **58 PKCS#11 provider cases plus 2 loader contracts**, and **18 packaging contracts**, with no reported final failures or skips. A real two-signer CAdES file was checked without adding any untrusted QES claim. The user also confirmed successful local UI/token/document tests before publication. This is development acceptance, **not** independent regulatory certification or a compatibility guarantee for all middleware.

Evidence: [0.5-F report](docs/SIGNUM_0.5F_BUILD7.md) · [machine-readable results](docs/SIGNUM_0.5F_RESULTS.json).

## Requirements and local development

- Apple Silicon; bundle declares a **macOS 13.0 minimum**, but real runtime testing on macOS 13/14 and clean-system distribution remain open.
- Build environment: Xcode/Apple command-line tools, Swift 5.9+, CMake and pinned native dependencies. Bundle includes non-system OpenSSL/PoDoFo/xmlsec/libxml2 libraries as applicable; build tooling and Homebrew are not runtime dependencies of the packaged Beta.
- A trusted, separately installed PKCS#11 middleware is necessary for hardware signing; Signum does not redistribute token vendors' drivers.

~~~bash
git clone https://github.com/tiertoast/Signum.git
cd Signum
swift build
swift test
scripts/test-pkcs11-local.sh
~~~

Some integration tests require a locally built native PDF helper and explicit environment configuration; `swift test` alone is not equivalent to the full release campaign. Consult [local testing](docs/LOCAL_TESTING.md), [release readiness](docs/RELEASE_READINESS.md), and the pinned packaging scripts before rebuilding. **No GitHub Actions** are used; builds and acceptance testing remain local.

### Architecture

- `SignumApp`: SwiftUI/AppKit GUI and PDFKit preview.
- `SignumCore`, `SignumPKCS11Worker`, `SignumCLI`: signing/verification primitives, immutable jobs, worker supervision and CLI.
- `SignumTrustCore`, `SignumTrustAuthentication`, `SignumTrustIntegration`, `SignumCertificateValidation`: European trust, authentication and certificate/evidence assessment.
- `Tools/PAdESPrototype`, native C bridges and `scripts/`: PDF signing, security boundaries, packaging and local validation.

## Next steps

The **0.5 line is frozen** except for confirmed blocking defects. The next milestone, **0.6**, prioritizes current-time eIDAS verification of signatures without timestamps, **XAdES Baseline-B, ASiC-S/ASiC-E**, CAdES interoperability and downloadable verification reports. A native UI redesign follows in 0.7. **Issuing external TSA timestamps, encryption and decryption are deferred to 0.9**, while verification of existing timestamp evidence remains available in the supported 0.5 scope.

See the [full roadmap](docs/ROADMAP.md) for planned acceptance criteria and the distinction between implemented functions and proposals.

## License

Signum original source code is available under **Apache License 2.0** ([LICENSE](LICENSE)). Bundled third-party libraries have their own licenses, notices and redistribution obligations. Signing results and eIDAS qualification claims must be understood within the documented validation profile; **this Beta is not a substitute for legal assessment or production distribution checks**.
