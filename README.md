# Signum

**Native macOS electronic-signature client — early open-source technical proof of concept.**

The long-term goal is a lightweight SwiftUI client supporting ETSI/eIDAS PAdES, CAdES and XAdES documents, local PKCS#11 hardware and remote signing. **Version 0.1.0 is only an experimental PKCS#11 demonstration:** it detects tokens, lists public X.509 certificates and runs a synthetic RSA/SHA-256 signing test verified independently using macOS Security.framework. It **does not** yet produce signed documents, PAdES, CAdES or qualified signatures.

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

The commands use the default system path `/Library/bit4id/pkcs11/libbit4xpki.dylib`. You can append an absolute module path to any command; replace slot and certificate ID with values shown by your own device. The `sign-test` command requests the PIN using the terminal, **never as an argument or environment variable**.

### Native SwiftUI development application

```bash
swift run SignumApp
# Development-only unsigned .app bundle:
bash scripts/build-app.sh
open build/Signum.app
```

You may open `Package.swift` in Xcode for building and testing the package. The packaging script makes a local, **unsigned** application; signing, hardened runtime, entitlements and notarization are later milestones.

## Architecture

- `SignumApp` — native SwiftUI front end (read-only device discovery and explicit signing test).
- `SignumCore` — Swift PKCS#11 façade and independent RSA verification with Apple's Security.framework.
- `CPKCS11` — C dynamic loader for PKCS#11, using the upstream p11-kit header. No private keys are exported.
- `SignumCLI` — command line diagnosis and cryptographic proof of concept.
- `Tests` — Swift unit tests, with hardware integration tests performed on a real Mac.

## Safety limitations

**Do not use this PoC for confidential, production or legal signing workflows.** The test signs a built-in synthetic string, not the user's documents. A chosen PKCS#11 module is loaded in-process with `dlopen`: review its signature and file permissions before loading. A world-writable (`777`) middleware module is unsafe. Future versions should verify module provenance, isolate driver execution and perform UI operations asynchronously.

PINs are not written to disk or logs, but transient copies may remain in Swift memory; complete memory zeroization is not yet guaranteed. Context-specific PIN authentication is supported for `CKA_ALWAYS_AUTHENTICATE`. **Incorrect PIN entry can lock a token; do not repeatedly retry failures.** Never paste PINs, personal certificate information or private-key contents into tickets, logs or commits.

## Roadmap

1. Harden driver loading and secure PIN handling; add independent device mock tests.
2. Implement interoperable CAdES/CMS signatures.
3. Add incremental PDF PAdES with a suitable audited library.
4. Implement EU trust-list validation, revocation, timestamping and long-term profiles.
5. Add optional remote CSC signing and release packaging/notarization.

## License

Signum's original source code is offered under Apache License 2.0 (see `LICENSE`). The bundled `pkcs11.h` comes from p11-kit and preserves its upstream redistribution notice. **No proprietary Bit4id, InfoCamere or other vendor binaries are redistributed.**
