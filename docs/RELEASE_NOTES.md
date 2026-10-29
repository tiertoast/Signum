# Signum 0.7.0 Beta — Build 14

**Digital signatures. Simply native.**

Signum is a native macOS application for local digital signing and signature
verification. Use a compatible smart card or USB token to sign documents,
review signatures and certificate evidence, and export readable verification
reports from one document workspace.

## Highlights

- CAdES, PDF, XML and ASiC workflows with explicit document and certificate approval.
- Attached and detached CAdES, supported co-signatures and countersignatures.
- Visible or invisible PDF signatures with preview-based appearance placement.
- Unified verification with individual signer results and PDF/text report export.
- Authenticated European Trusted Lists, certificate-path and revocation assessment.
- Native SwiftUI/AppKit workspace, Finder/Services integration and device discovery.
- Supervised cryptographic workers and exclusive output handling that preserves originals.

## Supported signing formats

| Format | Available in 0.7.0 |
| --- | --- |
| CAdES attached — `.p7m` | Embed and sign a document using RSA/SHA-256 |
| CAdES detached — `.p7s` | Sign separately; verification requires the exact original |
| CAdES co-/counter-signatures | Add a content signer or countersign a selected signature in supported attached DER CMS |
| PAdES — `.pdf` | Visible or invisible PDF signature; configure page, position, text/image and orientation |
| XAdES Baseline-B — `.xml` | One enveloped RSA/SHA-256 signature with signed properties and certificate binding |
| ASiC-S / ASiC-E — `.asics` / `.asice` | One / two-to-four documents with one detached XAdES-B signature and required metadata |

These are explicitly bounded profiles. XAdES-T/LT/LTA, ASiC with CAdES,
arbitrary multi-signature XML/ASiC, timestamp issuance and encryption are not included.
[Format details](https://github.com/tiertoast/Signum/blob/main/docs/FORMATS.md)

Ordinary attached CAdES batches support per-document authentication, approved
session reuse without retaining the PIN, or optional temporary PIN retention in
memory for that batch. Temporary PIN retention increases exposure; other signing
operations require per-document authorization.

## Verification and trust

Verify supported CAdES, PDF, XML and ASiC signatures with per-signer outcomes.
Detached CAdES requires explicit selection of the signature and original content.
For PDFs, distinguish valid historical signatures from current-file coverage;
the acceptability of later edits and DocMDP/FieldMDP semantics are not certified.

Cryptographic integrity, certificate-path trust, revocation, trusted time and
eIDAS qualification are **separate assessments**. Authenticated LOTL/national
Trusted Lists, X.509, OCSP, CRL and supported existing timestamp evidence feed
the evaluation. A declared signing time is not an independently trusted timestamp.
Missing or unsupported evidence remains indeterminate.

Positive eIDAS qualification is restricted to supported direct CA/QC, post-2016
profiles for IT, AT, DE, BE, FR and ES with sufficient bound evidence. This is not
universal EU coverage or regulatory certification. Exportable PDF/text reports
are unsigned assessment snapshots, not legal attestations.

## Native macOS experience

Prepare documents in a native workspace with PDF preview and a signing inspector.
Open files from Finder, use signing/verification macOS Services, inspect devices
and certificate purposes, and keep multiple verification results together.
Application preferences include supported default-document associations and
explicit batch-authentication choices. The packaged GUI and some CLI output
currently use Italian labels.

The bundled experimental CLI offers public device/certificate discovery,
interactive attached CAdES signing and integrity checks. Its verification output
does not replace the app's full trust/revocation/eIDAS assessment.
[Workflows and CLI](https://github.com/tiertoast/Signum/blob/main/docs/USAGE.md)

## Requirements and installation

- **Version 0.7.0, Build 14; Apple Silicon arm64.** No Intel build is supplied.
- **Declared minimum macOS 13.0.** Real macOS 13/14 and clean-Mac qualification remain open.
- Compatible arm64 PKCS#11 middleware is installed separately for hardware signing.
  Verification does not require a token; no universal device/vendor compatibility is claimed.
- Native libraries are bundled. Java, Homebrew and developer tools are not runtime requirements.
- Online acquisition of fresh Trusted Lists or revocation data needs network access;
  offline assessment depends on sufficient authenticated evidence.

Download the DMG and checksum, verify them, open the DMG and drag **Signum**
to **Applications**. Select the device/certificate in Signum before signing.
The app is **ad-hoc signed, without Developer ID or notarization**; macOS may block
opening the download. It does not disable Gatekeeper or other system protections.

## Dependencies and licensing

| Component | Build 14 version | License / role |
| --- | --- | --- |
| PoDoFo | 1.1.2 | MPL-2.0; native PDF processing |
| FreeType | 2.13.3 | FTL; native font support |
| OpenSSL | 3.5.6 | Apache-2.0; cryptographic backend |
| libxml2 | 2.15.4 | MIT license notices; XML parsing |
| xmlsec | 1.3.12 | MIT-style Copyright terms; XML signatures |
| SwiftUI, AppKit, PDFKit, Security | Apple system frameworks | Native UI, PDF and certificate services |

Signum original code remains Apache-2.0. Included components retain their own
terms. Notices, corresponding native sources and `SOURCE_ACCESS.md` are bundled
under `Signum.app/Contents/Resources/ThirdPartySources/`; access to the private
repository is not needed to obtain that included kit. Portions of this software
are copyright © The FreeType Project.

## Known limitations

This is a **Beta, not Stable or RC-qualified**. Stability, accessibility,
interoperability and OS/device compatibility work remains open; detailed
M3–M6 follow-up is retained in [issue #9](https://github.com/tiertoast/Signum/issues/9).
Real PIN change and PUK unblocking are disabled/unqualified. Worker isolation is
not a privilege sandbox against hostile middleware. See the
[security scope](https://github.com/tiertoast/Signum/blob/main/docs/SECURITY.md).

This English presentation updates documentation only. The verified DMG is
unchanged and still contains its original Italian packaging notes. Technical
manifests and source provenance remain intact.

## Downloads and checksum

**[Signum-0.7.0-beta-arm64.dmg](https://github.com/tiertoast/Signum/releases/download/v0.7.0-beta/Signum-0.7.0-beta-arm64.dmg)**
— 22,766,204 bytes.

SHA256:

```text
cc5add5dab9163e44465a2b6161532ec6e5f1d5c5ed6aef98250935e9f80c2b9
```

Download the `.dmg.sha256` sidecar alongside the DMG, then run:

```sh
shasum -a 256 -c Signum-0.7.0-beta-arm64.dmg.sha256
```

`SHA256SUMS.txt` covers the standalone release files, including the current
English `ReleaseNotes.md`. Technical manifests and audits accompany the DMG.
The binary's recorded product source is `09316e046a4dd101ce74410a6eeccee6911d4783`;
later repository documentation does not change the binary's provenance.

[Product documentation](https://github.com/tiertoast/Signum/blob/main/docs/README.md)
· [Roadmap](https://github.com/tiertoast/Signum/blob/main/docs/ROADMAP.md)
