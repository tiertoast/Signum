# Signum

**Native macOS electronic-signature client — early open-source technical proof of concept.**

The long-term goal is a lightweight SwiftUI client supporting ETSI/eIDAS PAdES, CAdES and XAdES documents, local PKCS#11 hardware and remote signing. **Version 0.2.0-alpha is an experimental PKCS#11 and CAdES candidate:** it detects tokens, lists public X.509 certificates, runs a synthetic RSA/SHA-256 signing test, and has a CLI proof-of-concept that can package a small document into an **attached CMS `.p7m`**. The package is NOT yet independently validated against the ETSI CAdES-B-B profile. It does NOT produce PAdES or qualified electronic signatures, and it does not validate certificate trust.

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
