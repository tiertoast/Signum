# Signum

**Digital signatures. Simply native.**

A lightweight, native macOS application for signing documents with local PKCS#11 hardware. Built with **Swift, SwiftUI, PDFKit and Apple's Security framework**, with a dedicated native PoDoFo engine for PDF signatures.

Signum aims to make document signing practical and understandable, particularly in document-heavy workflows such as the Italian public administration, without locking users into a particular token vendor's desktop interface.

> **Current status — 17 October 2026:** **0.3.3 Alpha · Beta Foundation integrated into `main`.**
> CAdES and PAdES have both passed real DigitalDNA/DS3 signing tests and independent checks with InfoCamere Sign. **This is not a public Beta or production-ready eIDAS validation product.** No signed, notarized distribution is available yet.

## Capabilities

| Area | Current implementation |
| --- | --- |
| **CAdES** | Attached CMS/`.p7m` signing with PKCS#11 RSA/SHA-256, signed attributes including `signingCertificateV2`; cryptographic verification before publication. |
| **PAdES** | Incremental PDF signing through the bundled PoDoFo helper; optional minimal text-based visible signature appearance. |
| **Devices** | Local PKCS#11 module discovery, reader/token selection, certificate display and local X.509 signing-eligibility checks. Tested with Bit4id DigitalDNA/DS3; other middleware requires its own validation. |
| **User interface** | Native resizable SwiftUI workspace, PDFKit preview, interactive PDF signature-field placement and explicit document approval. |
| **CLI** | Device discovery, certificate listing, signing diagnostic, CAdES signing and attached-CMS integrity verification. |
| **Local verification** | Verify `.p7m` CMS integrity and extract the original content. This is **not** certificate trust or qualified-signature validation. |
| **XAdES** | Planned, **not implemented**. |
| **Remote signing** | Future possibility, **not implemented**. |

The current PDF appearance is intentionally limited: custom image/logo and date profiles are **not yet embedded** in the produced signature appearance.

## The invisible work that makes signing reliable

The 0.3.3 Reliability Foundation and subsequent Beta Foundation are substantial **architecture and security** milestones, not just UI changes:

1. **Approved bytes stay approved.** Signum captures a private, immutable document snapshot, binds it to SHA-256 and uses those bytes for preview/approval and signing rather than silently rereading a changed original.
2. **Isolated PKCS#11 execution.** The GUI and CLI delegate token operations to a short-lived `SignumPKCS11Worker` process; vendor code is no longer loaded by their ordinary signing/discovery paths.
3. **Bounded work, recoverable UI.** Process supervision provides timeouts, cancellation, crash handling and bounded child-process capacity. A hung vendor call is not treated as a cancellable Swift task.
4. **Cooperative device coordination.** Cross-process leases coordinate Signum's own workers and PDF helper by provider/slot. They cannot prevent conflicts with third-party applications or all physical-token aliases.
5. **Verified, exclusive publication.** CAdES and PAdES outputs are checked before an atomic, no-overwrite commit. Interrupted signing is handled conservatively; an uncertain result is **never retried automatically**.
6. **Certificate and provider binding.** Local X.509 eligibility, selected certificate identity and provider provenance are checked; changing the middleware path invalidates the prior selection and PIN.
7. **Self-contained local app packaging.** The arm64 build recipe embeds its required PoDoFo dynamic library, audits dependencies/`@rpath`, checks signatures and refuses to overwrite earlier bundles. PKCS#11 middleware remains installed separately.

The isolated worker protects the GUI from crashes and hangs; **it is not a sandbox against malicious vendor code running with the user's privileges**. The historical in-process Core API remains present for tests/compatibility and is not covered by this isolation.

Read [the Beta Foundation engineering report](docs/SIGNUM_BETA_FOUNDATION_REPORT.md) and [the PR #2 review corrections](docs/PR2_REVIEW_CORRECTIONS.md) for the implementation details and limitations.

## Validation evidence

The latest correction cycle recorded these **local, synthetic** results:

| Verification | Reported result |
| --- | --- |
| Swift suite (native PAdES integration explicitly enabled) | **154 / 154** |
| PKCS#11 suite | **40 / 40** |
| PAdES tests, Debug and Release | **63 / 63** each |
| Packaging Python tests | **10 / 10** |
| Targeted Swift ASAN | **17 / 17** |
| Native PAdES ASAN | **63 / 63** |

AddressSanitizer runs disabled leak detection and did not instrument every third-party library. ThreadSanitizer was exercised in earlier foundation work, but **not rerun** in the final review-correction cycle.

**Real hardware:** the development candidate was manually tested with a Bit4id DigitalDNA signing certificate; both CAdES and PAdES were accepted as valid by **InfoCamere Sign**. The final provider-selection checks were also reported as passed. These are manual user-reported acceptance tests, **not** a certification or a broad vendor compatibility claim.

## Requirements

- **macOS 13.0+ declared minimum** in the package, bundled Info.plist and arm64 native build recipe. Runtime compatibility on macOS **13 and 14**, and installation on a clean Mac, **have not yet been established**.
- **Apple Silicon** for the current reproducible local bundle recipe.
- Xcode / Apple command-line build tools, Swift 5.9+ and local CMake for building.
- An **independently installed, trusted PKCS#11 middleware** for the token (for example OpenSC or vendor middleware). Signum does not distribute proprietary token drivers.

## Build and test locally

The repository is currently a development project; it does not ship a public installer.

```bash
git clone https://github.com/tiertoast/Signum.git
cd Signum
swift build
swift test
scripts/test-pkcs11-local.sh
```

`swift test` alone may skip the optional native PAdES end-to-end integration unless `SIGNUM_TEST_PADES_HELPER` points to a locally built helper; consult the two engineering reports for the exact full-suite configuration.

### Reproducible local app bundle

The packaging recipe requires three **locally available, SHA-256-pinned** source archives in `.build/native-src` (OpenSSL 3.5.4, FreeType 2.13.3, PoDoFo 1.1.2) and a working CMake binary (the default is `.build/native-tools/cmake/data/bin/cmake`). It performs **no network downloads or global installations**. Choose **new, unused output paths**:

```bash
python3 scripts/build-beta-native.py --output .build/native-local-01
python3 scripts/build-beta-app.py --configuration release \
  --native-prefix .build/native-local-01/prefix \
  --output .build/bundles/local-01/Signum.app

codesign --verify --deep --strict --verbose=2 \
  .build/bundles/local-01/Signum.app
open -n .build/bundles/local-01/Signum.app
```

This produces a **locally ad-hoc-signed** development bundle, not a Developer ID–signed or notarized application. The script audits the Mach-O deployment targets and load paths and tests a relocated copy. It will not replace an existing app. Never assume that its availability on your development Mac establishes compatibility with an unconfigured Mac.

### CLI examples

Build the full Swift package first so the sibling worker is present, then use:

```bash
swift run SignumCLI list [absolute_module_path]
swift run SignumCLI certs <slot> [absolute_module_path]
swift run SignumCLI sign-test <slot> <cert_ID_hex> [absolute_module_path]
swift run SignumCLI sign-cades <slot> <cert_ID_hex> <input> <new-output.p7m> [absolute_module_path]
swift run SignumCLI verify-cades <signed.p7m> [new-extracted-output]
```

In the examples above, replace angle-bracket placeholders with real values; brackets denote optional arguments. The default middleware path is `/Library/bit4id/pkcs11/libbit4xpki.dylib`. Signing requests explicit approval, then reads the PIN privately from the terminal. **Never put a real PIN in command arguments, logs, tickets or commits.** Do not retry an uncertain signature automatically: repeated incorrect attempts can lock the device.

## Architecture

- `SignumApp` — native SwiftUI interface, document approval and PDFKit preview.
- `SignumCore` — immutable job/snapshot, CMS construction and verification, supervised processes, worker IPC and state machine.
- `SignumPKCS11Worker` — one-shot, isolated middleware execution with bounded private IPC.
- `CPKCS11`, `CCertificatePolicy`, `CProcessCoordination`, `COutputPermissions` — native token bridge, local certificate policy, cooperative locking and filesystem safeguards.
- `Tools/PAdESPrototype` / `signum-pades-local` — PoDoFo-based native PDF signing, verification and exclusive output publication.
- `SignumCLI` — developer-facing diagnostic and CAdES commands.
- `scripts/build-beta-*.py` — local, audited arm64 native dependencies and standalone app-bundle creation.

Builds and tests are local; **there are no GitHub Actions workflows**.

## Security and legal scope

Signum verifies **cryptographic integrity** in the implemented workflows. It does **not** currently determine whether a certificate is trusted, revoked, qualified under eIDAS, valid at the asserted signing time or compliant with complete ETSI baseline/long-term-validation profiles. `openssl cms -verify -noverify` deliberately **disables certificate-chain verification**.

Do not treat these tests as legal validation of qualified electronic signatures or rely on this experimental version for confidential/production signing workflows. PIN bytes exist transiently in Swift and middleware memory; complete zeroization is not guaranteed. An external PKCS#11 module must be independently vetted before loading.

## What comes next

1. Validate behavior on real **macOS 13/14** systems and an otherwise clean Apple Silicon Mac; expand the OpenSC/Bit4id/CNS driver matrix.
2. Exercise cancellation, token removal, vendor hangs, provider changes and recovery with controlled hardware tests.
3. Complete distribution readiness: dependency/license review, Developer ID signing, suitable hardened-runtime/library-validation policy, notarization and installation testing.
4. Improve the visual PAdES appearance and application experience without weakening the signing invariants.
5. In a later, independently reviewed phase: EU trust lists, certificate chains, revocation, timestamps, ETSI profiles, plus possible XAdES and remote signing.

**No public Beta release is implied by the name “Beta Foundation.”** See [release-readiness gates](docs/RELEASE_READINESS.md) for the criteria still open.

## License

Signum's original code is licensed under **Apache License 2.0**; see [LICENSE](LICENSE). Third-party sources retain their own licenses and notices. The offline packaging recipe includes available notices for PoDoFo, OpenSSL, FreeType and bundled components, but **distribution obligations still require a separate review**. No Bit4id, InfoCamere or other proprietary middleware is redistributed.
