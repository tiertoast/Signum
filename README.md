<div align="center">
  <p><img src="docs/assets/signum-readme-icon.svg" alt="Signum — native macOS digital signatures" width="182" height="182"></p>
  <h1>Signum</h1>
  <p><strong>Digital signatures. Simply native.</strong></p>
  <p>A focused, native macOS workspace for digital signing and verification.<br>
  CAdES · PAdES · XAdES · ASiC</p>
  <p>
    <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-64313E?style=flat-square&amp;labelColor=4B4B4B"></a>
    <a href="docs/ARCHITECTURE.md"><img alt="Built with SwiftUI and AppKit" src="https://img.shields.io/badge/built%20with-Swift%20%2B%20AppKit-64313E?style=flat-square&amp;labelColor=4B4B4B"></a>
    <a href="docs/BUILDING.md"><img alt="Declared minimum macOS 13.0" src="https://img.shields.io/badge/platform-macOS%2013%2B-64313E?style=flat-square&amp;labelColor=4B4B4B"></a>
    <a href="docs/RELEASE_NOTES.md"><img alt="Apple Silicon release" src="https://img.shields.io/badge/architecture-Apple%20Silicon-64313E?style=flat-square&amp;labelColor=4B4B4B"></a>
  </p>
  <p>
    <a href="https://github.com/tiertoast/Signum/releases/tag/v0.7.0-beta"><img alt="Current release: 0.7.0 Beta Build 14" src="https://img.shields.io/badge/release-0.7.0%20Beta%20%7C%20Build%2014-64313E?style=flat-square&amp;labelColor=4B4B4B"></a>
    <a href="docs/USAGE.md"><img alt="Compatible PKCS#11 hardware signing" src="https://img.shields.io/badge/hardware-PKCS%2311-64313E?style=flat-square&amp;labelColor=4B4B4B"></a>
  </p>
  <p><strong><a href="https://github.com/tiertoast/Signum/releases/tag/v0.7.0-beta">Download Signum 0.7.0 Beta — Build 14</a></strong><br>
  <a href="docs/FEATURES.md">Features</a> · <a href="docs/USAGE.md">User guide</a> · <a href="docs/RELEASE_NOTES.md">Release notes</a></p>
</div>

---

Signum is a native macOS application for signing documents with a smart card or
USB token and verifying digital signatures. It brings CAdES, PAdES, XAdES and
ASiC workflows into a focused document workspace, with local cryptographic
processing and clear, separate results for integrity, trust, revocation and time.

Built with SwiftUI and AppKit, Signum works with compatible PKCS#11 middleware
rather than requiring a particular vendor's desktop signing application.

**Current distribution:** Apple Silicon · declared minimum macOS 13.0 · ad-hoc signed Beta (not notarized).

## Features

- Sign individual documents or approved batches; keep original files intact.
- Create attached or detached CAdES signatures, add co-signatures and explicitly
  selected countersignatures to supported existing CMS documents.
- Sign PDFs with an invisible signature or a visible appearance positioned in
  the document preview, including text, images and orientation controls.
- Sign XML using the supported XAdES Baseline-B profile and package documents
  in supported ASiC-S or ASiC-E containers.
- Verify supported signatures together in one workspace, with per-signer
  results and exportable PDF and plain-text reports.
- Discover devices and certificates through PKCS#11; review the selected
  certificate and destination before authorizing a signature.
- Open documents from Finder and macOS Services; work with native previews,
  a signing inspector, device information and application preferences.

[Explore the features](docs/FEATURES.md) · [Using Signum](docs/USAGE.md)

## Supported formats

Signing and verification have explicit profiles. A familiar extension alone does
not establish that a document is supported or that its signature is valid.

| Format | Signing | Verification and scope |
| --- | --- | --- |
| **CAdES attached** — `.p7m` | CMS container with embedded document; RSA/SHA-256 | Supported CMS signatures and nested layers, with individual signer results |
| **CAdES detached** — `.p7s` | Signature stored separately from the document | Requires explicit selection of the exact original content |
| **CAdES co-/counter-signatures** — `.p7m` | Add a content signer or countersign a selected signature | Supported attached DER CMS; signer relationships are retained |
| **PAdES** — `.pdf` | Visible or invisible PDF signature | Supported `ETSI.CAdES.detached` signatures; revision coverage is reported separately |
| **XAdES Baseline-B** — `.xml` | One enveloped RSA/SHA-256 signature | Restricted XML profile with signed properties and certificate binding |
| **ASiC-S / ASiC-E** — `.asics` / `.asice` | One / two-to-four documents with detached XAdES-B | One signature; complete supported payload and manifest coverage |

See [formats and profile limits](docs/FORMATS.md). Timestamp issuance,
XAdES-T/LT/LTA, ASiC with CAdES and encryption are outside the current product scope.

## Verification and trust

Signum presents five independent assessments:

| Assessment | What it answers |
| --- | --- |
| Cryptographic integrity | Does the signature match the signed bytes? |
| Certificate path | Can the signer be linked to an applicable trusted service? |
| Revocation | Is authenticated, applicable certificate-status evidence available? |
| Time | Is a time merely declared or independently supported by timestamp evidence? |
| eIDAS qualification | Do the supported certificate, service, QSCD and evidence rules support a qualification result? |

European LOTL and national Trusted Lists are authenticated before use. X.509,
OCSP, CRL and supported timestamp evidence feed the assessment; missing or
unsupported evidence remains indeterminate. A certificate's presence in a
signature does not make it trusted. Declared `signingTime` is not a trusted timestamp.

Positive qualification is limited to supported direct CA/QC, post-2016 profiles
for IT, AT, DE, BE, FR and ES, with sufficient bound evidence. This is not universal
EU coverage or regulatory certification. [Security and validation scope](docs/SECURITY.md)

## Devices and authentication

Hardware signing requires a compatible PKCS#11 library installed separately from
Signum. Device discovery and manual module selection support different middleware
setups; compatibility depends on the exact token, module, architecture and configuration.
No vendor certification or universal smart-card support is claimed.

For ordinary attached CAdES batches, authentication can be per document, reuse an
approved device session without retaining the PIN, or temporarily retain the PIN
in memory for the approved batch. Temporary PIN reuse increases exposure and is
optional. Other signing operations use per-document authorization. Real PIN change
and PUK unblocking are not enabled. [Device and batch workflows](docs/USAGE.md)

## Installation

1. Download the DMG and its checksum from the [0.7.0 Beta release](https://github.com/tiertoast/Signum/releases/tag/v0.7.0-beta).
2. Check the download, then open the DMG and drag **Signum** to **Applications**.
3. Install compatible arm64 PKCS#11 middleware if you need hardware signing.
4. Open Signum, select the device/certificate and add documents to the workspace.

```sh
shasum -a 256 -c Signum-0.7.0-beta-arm64.dmg.sha256
```

The Beta is **ad-hoc signed, without Developer ID or notarization**; macOS may
block opening the downloaded app. It does not change Gatekeeper settings.
The declared macOS 13.0 minimum is not a completed macOS 13/14 or clean-Mac
compatibility qualification. Intel builds are not provided. The packaged app
includes its native libraries; Java, Homebrew and developer tools are not runtime
requirements. Network access is needed when acquiring fresh trust/revocation data.

## Architecture and dependencies

Swift coordinates the workspace, signing approvals and validation. Isolated
workers perform PKCS#11 operations and native parsing/signing; approved snapshots
and exclusive output handling protect document and destination identity.
Worker isolation is process isolation, not a security sandbox for hostile middleware.

| Component in Build 14 | Purpose | License / platform |
| --- | --- | --- |
| PoDoFo **1.1.2** | PDF processing and signing helper | MPL-2.0 distribution choice |
| FreeType **2.13.3** | Font support within the native stack | FreeType License (FTL) |
| OpenSSL **3.5.6** | CMS, certificate and cryptographic operations | Apache-2.0 |
| libxml2 **2.15.4** | XML parsing and canonicalization | MIT license notices |
| xmlsec **1.3.12** | XML signature processing | MIT-style license / bundled Copyright |
| SwiftUI, AppKit, PDFKit, Security | Native interface, PDF preview and certificate services | Apple system frameworks |
| PKCS#11 middleware | Access to the operator's token or smart card | Separately installed; vendor-specific terms |

Versions are taken from the released `BuildManifest.json`. Third-party components
and their own notices remain distinct from Signum's license.
[Architecture and acknowledgments](docs/ARCHITECTURE.md)

## Building and integration

The source uses Swift Package Manager and a CMake native helper. A prepared native
prefix and Apple development tools are required; `swift build` alone does not
assemble the complete application. Follow [Building from source](docs/BUILDING.md)
for the supported packager and development prerequisites.

The bundled experimental `SignumCLI` supports device discovery, certificate
listing, attached CAdES signing and integrity verification. Its results do not
replace the app's certificate, revocation and eIDAS assessments. Finder opening,
macOS Services and source-level Swift libraries are also available; there is no
published stable HTTP API or general JSON automation contract.
[CLI and integration details](docs/USAGE.md#cli-and-integration)

## Beta scope, roadmap and contributing

This is a **Beta**, with compatibility, accessibility, interoperability and
stability work still open. It is not Stable or RC-qualified. Detailed engineering
follow-up, including M3–M6, is kept in [issue #9](https://github.com/tiertoast/Signum/issues/9)
and the [engineering documentation](docs/engineering/README.md).

See the [roadmap](docs/ROADMAP.md) for reliability and distribution, optional
trusted timestamp issuance and the path to a defined Stable support matrix.
For contributions, open an issue with the expected behavior, format and relevant
software versions. Remove PINs, personal documents and identifying certificate
data from reports. Keep changes focused and follow the local verification guidance
in [Building](docs/BUILDING.md); the project does not use GitHub Actions.

## License

Signum's original code is licensed under [Apache License 2.0](LICENSE).
Bundled libraries and source materials retain their own licenses. The release
includes notices and corresponding native source materials under
`Signum.app/Contents/Resources/ThirdPartySources/`, including `SOURCE_ACCESS.md`.
FreeType credit: portions of this software are copyright © The FreeType Project.

[Documentation](docs/README.md) · [Security](docs/SECURITY.md) · [Release notes](docs/RELEASE_NOTES.md)
