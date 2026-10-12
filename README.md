# Signum

**Native macOS electronic-signature client — early open-source technical proof of concept.**

The long-term goal is a lightweight SwiftUI client supporting ETSI/eIDAS PAdES, CAdES and XAdES documents, local PKCS#11 hardware and remote signing. **Version 0.3.2-alpha is an experimental PKCS#11 and CAdES candidate:** it detects tokens, lists public X.509 certificates, runs a synthetic RSA/SHA-256 signing test, and has a CLI proof-of-concept that can package a small document into an **attached CMS `.p7m`**. The package is NOT yet independently validated against the ETSI CAdES-B-B profile. It does NOT produce PAdES or qualified electronic signatures, and it does not validate certificate trust.

## Requirements and setup

- macOS 13+ (Apple Silicon supported), Swift 5.9+ / Xcode Command Line Tools.
- A *separately installed* PKCS#11 driver supporting your token. No proprietary driver ships with Signum.

```bash
git clone https://github.com/tiertoast/Signum.git
cd Signum
swift test
swift run SignumCLI list
swift run SignumCLI certs 1
swift run SignumCLI sign-test 1 445333
```

**Important:** With the previously observed Bit4id `777` permissions, even `list` will now be blocked until permissions are inspected and fixed as described below.

The commands use the default system path `/Library/bit4id/pkcs11/libbit4xpki.dylib`. You can append an absolute module path to any command; replace slot and certificate ID with values shown by your own device. The `sign-test` command requests the PIN using the terminal, **never as an argument or environment variable**.

### Experimental CAdES (.p7m) — LOCAL TEST ONLY

This PoC emits an **attached** CMS SignedData with three signed attributes:
`contentType`, `messageDigest` and `signingCertificateV2` (ESSCertIDv2 SHA-256).
It signs the DER signed-attribute SET with `CKM_SHA256_RSA_PKCS` on the token and checks that raw signature using macOS Security.framework. Document size is currently limited to 16 MiB, a single signer and RSA/SHA-256. It embeds only the signing certificate (no revocation or timestamp evidence). **Conformance and interoperability are unverified until externally tested.**

Before entering a real PIN, verify the module's original code signature and ensure the installed PKCS#11 library, adjacent `.conf` file, and `.rc` resources are not writable by group or other users. The PKCS#11 loader now rejects unsafe permission bits **before calling dlopen**, including for read-only token discovery. On the previously observed root-owned Bit4id installation these paths had mode `777`; after inspecting the paths and confirming the driver is genuine, an administrator may correct them locally:

```bash
sudo chmod -R go-w /Library/bit4id/pkcs11/libbit4xpki.dylib \
  /Library/bit4id/pkcs11/libbit4xpki.dylib.conf \
  /Library/bit4id/pkcs11/libbit4xpki.dylib.rc
codesign --verify --verbose=2 /Library/bit4id/pkcs11/libbit4xpki.dylib
```

This is a limited filesystem permission check, **not** a complete malware, configuration or dependency verification solution. Do not adjust vendor software without checking local policies, backups and vendor support.

On a Mac with a working DigitalDNA (check slot and ID first via `swift run SignumCLI list` and `certs`):

```bash
printf 'Signum CMS local test\n' > /tmp/signum-test.txt
swift run SignumCLI sign-cades 1 445333 /tmp/signum-test.txt /tmp/signum-test.txt.p7m
openssl cms -verify -inform DER -binary -noverify \
  -in /tmp/signum-test.txt.p7m -out /tmp/signum-extracted.txt
cmp /tmp/signum-test.txt /tmp/signum-extracted.txt && echo "CMS integrity OK"
```

Alternatively, run `bash scripts/verify-cades-local.sh /tmp/signum-test.txt.p7m /tmp/signum-test.txt`.

The `-noverify` flag **deliberately disables trust-chain checking**; this test only verifies CMS cryptographic integrity. Do not treat its success as validation of an eIDAS-qualified signature. For CAdES baseline profile checks use an independently configured ETSI-aware validator such as EU DSS.

**No PINs, certificates or private data should be committed to the repository.** Do not use your production documents while testing.

### X.509 holder and device identification (0.2.1 alpha)

The native GUI displays the certificate holder's **given name and surname**, a personal Italian **codice fiscale** when actually present in the public X.509 subject, and the certificate issuer. This does not involve the token PIN or export any private key. If a field is absent or malformed, the GUI falls back to the original PKCS#11 certificate label (e.g., `DS3`).

Token rows show the PKCS#11 token label, model, and the physical reader's `CK_SLOT_INFO.slotDescription`. Familiar devices such as DigitalDNA and CNS are labeled **Token USB** and **Smart card**. These are model-based UI descriptions, **not authoritative detection of the actual USB transport**; an unknown device remains a generic PKCS#11 device.

The certificate identity is shown locally in the GUI. No certificate personal data is stored in the repository or printed in debug output. A displayed name/CF is informational and is not a substitute for certificate trust and eIDAS qualification verification.

### GUI CAdES signing and reader startup recovery (0.2.2 alpha)

- Start the real macOS app bundle, **not** `swift run SignumApp`, for reliable keyboard focus.
- Select the DigitalDNA token and its signature certificate (typically `DS3`) or another suitable card/certificate.
- Select **Firma documento CAdES**, choose a **test file** with **Scegli file…** or drag it to the drop area, enter the device PIN, then click **Firma .p7m**.
- Choose a **new** output path. Signum will not silently overwrite an existing file. The input must be 1 byte to 16 MiB.
- To independently verify the resulting attached CMS, run `bash scripts/verify-cades-local.sh <generated.p7m> <original-file>` or check it in InfoCamere Sign. Verification through this script does not check legal qualification, trust, validity at signing time or ETSI conformance.

The GUI has a compact fixed-size layout. When an inserted card briefly reports PKCS#11 `CKR_TOKEN_NOT_RECOGNIZED` (`0xE1`), the app skips that reader without hiding the other available devices, retries enumeration **once** after 450 ms, and provides an explicit manual refresh button. This automatic retry does **not** attempt PIN authentication.

The app remains an **experimental CAdES proof of concept** and is not for production documents. PINs are passed only to the installed hardware middleware, but complete in-memory erasure and driver isolation are not yet implemented.

### Local CAdES verification (0.2.3-alpha)

Signum now has a **Verifica .p7m** GUI mode that requires **no token or PIN**. Select or drop a signed file, click **Verifica**, inspect cryptographically verified attached CMS layers/signers, and optionally **Estrai originale…** into a new output file (never overwrites existing files). Nested CMS envelopes are verified from outermost to innermost, up to 5 layers. The original document may be retained in app memory for extraction until you leave or reload the panel.

Run the same verifier directly, without loading any PKCS#11 provider:

```bash
swift run SignumCLI verify-cades /path/to/example.pdf.p7m
swift run SignumCLI verify-cades /path/to/example.pdf.p7m /path/to/new-extracted.pdf
```

The verifier invokes the **system /usr/bin/openssl** in a separate local process (no network). It checks CMS signature integrity with the **-noverify** option, which **intentionally skips certificate trust/chain validation**. It does not yet check revocation, QES qualification, timestamps, ETSI compliance or complete certificate profile status. Its DER reader targets attached CMS SignedData; some external BER or detached variants are intentionally unsupported. Both input and nested payload have a 64 MiB limit, with a maximum of 5 nested layers. Signer display names are untrusted certificate metadata until full validation is implemented.

Tests can be run solely on your Mac with `swift test`; the integration test creates temporary, locally signed CMS fixtures using macOS OpenSSL and checks tampering rejection. **Never report this as full legal signature verification.**

### Native SwiftUI development application

```bash
swift run SignumApp
# Development-only unsigned .app bundle:
bash scripts/build-app.sh
open build/Signum.app
```

You may open `Package.swift` in Xcode for building and testing the package. The packaging script makes a local, **unsigned** application; signing, hardened runtime, entitlements and notarization are later milestones.

### Local GUI signing test

On your Mac, connect your DigitalDNA and/or CNS, launch the actual macOS bundle with `bash scripts/build-app.sh` and `open -n "$PWD/build/Signum.app"`, select a token and certificate, enter its PIN into the protected field, and click **Firma e verifica**. The button signs **only a hard-coded test string** via PKCS#11 and verifies it with Security.framework. Its success message is `Verified OK`; it does not produce a PDF/P7M. The GUI disables selection and reload operations while the test runs, and clears its PIN field when you initiate the test. If an authentication error occurs, do not automatically retry: repeated wrong PINs can block a smart card.

All builds and tests are performed **locally** using `swift test` and `swift run`; no GitHub Actions workflows are used.


## Signum 0.3.2 Alpha — Experimental visible PAdES appearance

The PAdES helper can now create a real PDF widget normal appearance (`/AP /N`)
**before** the signing operation. When a position is selected, the SwiftUI app
sends an ASCII display name after the PIN through a private stdin pipe; the
helper uses PoDoFo to draw a minimal text-only stamp (white background, thin
border, "Firmato digitalmente da" and the certificate holder name).

**The configured image, logo, and date are not yet embedded** in this
first rendering pass. The preview has been aligned with the text-only output.
The appearance describes the signer; it is not evidence of validity by itself.
Test only with a disposable PDF. After rebuilding the helper and application,
check (1) whether the stamp is visible in a PDF reader, and (2) whether
InfoCamere still reports a valid PAdES signature. If either fails, do not use
the output for work documents. No signing binaries or tests run in GitHub Actions.

```bash
cd ~/Signum
git pull --ff-only
cmake --build .build/signum-pades --config Release
swift test
bash scripts/build-app.sh
open -n "$PWD/build/Signum.app"
```

## Signum 0.3.1 Alpha — Resizable workspace and PAdES engine

Signum uses a resizable split window for signing. Device/certificate controls are on the left and PDFKit preview occupies the right panel in PAdES mode. The window and central divider can both be resized.

PAdES signing is experimental and requires the optional local PoDoFo helper. Build it in Tools/PAdESPrototype, then rerun scripts/build-app.sh so the helper is included. If it is not installed the GUI disables PAdES signing. All compilation and validation are local on macOS. CAdES and verification remain available.

The selected rectangle defines a PDF signature field. Custom image/text PDF signature appearances are not yet embedded, even though the interface previews their configuration. Verify every experimental PDF with InfoCamere Sign before relying on the output. Trust, revocation, timestamps and qualified status remain outside the scope of the current implementation.

## Signum 0.3.0 Alpha — PAdES user-interface milestone

The graphical app now offers **Firma documento**, **Verifica .p7m** and **Impostazioni**.
The signing mode has a format selector: **CAdES (.p7m)** is working as previously tested; **PAdES (.pdf)** provides native PDFKit preview and interactive signature-field placement (click or drag), with zero-based PDF page coordinates; **XAdES** is listed as *prossimamente* and disabled.

The Settings pane stores one local graphic appearance profile (text/image, optional date, PNG/JPEG). The visual preview is an **unsaved PDFKit annotation**, never an actual signed PDF appearance. The graphic profile is for **PAdES, not CAdES**; a CMS `.p7m` contains no visual page.

**The PAdES button is intentionally disabled pending proof of the PoDoFo/PKCS#11 integration.** No fake or invalid PDF signatures are generated from the GUI. The hardware diagnostic test is removed from the GUI but remains available through `swift run SignumCLI sign-test`.

An independent C++ PoDoFo proof-of-concept is included in **Tools/PAdESPrototype**. It signs a PDF incrementally using a token's PKCS#11 RSA key via the external signing service. It is *not* part of the default Swift build and *not yet tested on the user's Mac*. Read its local build instructions and verify every produced PDF with InfoCamere Sign before enabling production use. It does not yet create a real graphical appearance stream.

To check the current SwiftUI milestone only (no PAdES signing):

```bash
cd ~/Signum
git pull --ff-only
swift test
bash scripts/build-app.sh
open -n "$PWD/build/Signum.app"
```

Check that CAdES signing and `.p7m` verification still work, open a test PDF in PAdES mode, choose a page and move the preview rectangle, and save a sample graphic appearance in Settings.
All compilation and tests must be done **locally on macOS**. No GitHub Actions workflows exist.

## Architecture

- `SignumApp` — native SwiftUI front end (read-only device discovery and explicit signing test).
- `SignumCore` — Swift PKCS#11 façade, experimental DER/CMS builder, and independent RSA verification with Apple's Security.framework.
- `CPKCS11` — C dynamic loader for PKCS#11, using the upstream p11-kit header. No private keys are exported.
- `SignumCLI` — command line diagnosis and cryptographic proof of concept.
- `Tests` — Swift unit tests, with hardware integration tests performed on a real Mac.

## Safety limitations

**Do not use this PoC for confidential, production or legal signing workflows.** The test signs a built-in synthetic string, not the user's documents. A chosen PKCS#11 module is loaded in-process with `dlopen`: review its signature and file permissions before loading. A world-writable (`777`) middleware module is unsafe. The GUI signing test now runs in the background while its token controls are disabled. Future versions should verify module provenance, isolate driver execution, serialize all provider operations and harden secret handling.

PINs are not written to disk or logs, but transient copies may remain in Swift memory; complete memory zeroization is not yet guaranteed. Context-specific PIN authentication is supported for `CKA_ALWAYS_AUTHENTICATE`. **Incorrect PIN entry can lock a token; do not repeatedly retry failures.** Never paste PINs, personal certificate information or private-key contents into tickets, logs or commits.

## Roadmap

1. Verify experimental CAdES/CMS output with OpenSSL and an ETSI-aware validator; correct any format errors.
2. Harden driver loading, secure PIN handling, and add hardware-mocked tests.
3. Add incremental PDF PAdES with a suitable audited library.
4. Implement EU trust-list validation, revocation, timestamping and long-term profiles.
5. Add optional remote CSC signing and release packaging/notarization.

## License

Signum's original source code is offered under Apache License 2.0 (see `LICENSE`). The bundled `pkcs11.h` comes from p11-kit and preserves its upstream redistribution notice. **No proprietary Bit4id, InfoCamere or other vendor binaries are redistributed.**
