# Signum PAdES Engine — Reliability Foundation

Native macOS helper used by SignumApp when bundled. SwiftPM builds the app but
not this C++ helper. This development branch requires **PoDoFo 1.1.2** and
**OpenSSL 3.x**; no global installation is performed by the test script.

## Signing and verification

- SignumCore acquires an owner-private CoW document snapshot before user approval.
  PDFKit previews the snapshot's immutable bytes, not the original URL.
- The helper requires job/snapshot UUIDs and the approved document SHA-256, checks
  that fingerprint before provider/PIN access, then signs only the loaded bytes.
- PoDoFo incrementally signs an in-memory copy of that bounded, verified input.
- The external service supplies SHA-256 DigestInfo to PKCS#11 CKM_RSA_PKCS;
  the token's private key is never exported.
- The shared SignumCore local certificate policy runs before the PIN is read;
  a second DER binding/policy check precedes authentication under the provider lock.
  Only eligible RSA 2048–8192-bit keys are accepted; the reservation uses key size.
  Unknown usage/critical-extension semantics fail closed as indeterminate.
- The text-only appearance stream and page coordinates are preserved.
- Complete output is written to private staging on the destination volume.
- CoreGraphics parses the PDF independently of PoDoFo. OpenSSL verifies the
  detached CMS, signed attributes and signature against the expected certificate.
- The verifier also checks ByteRange/Contents coverage, source prefix, page
  content/resources/geometry, preservation of existing annotations and the new
  signature widget. Only then is the file published with exclusive atomic rename.
- This verifies integrity, **not** certificate trust, revocation, timestamps,
  eIDAS qualification or full ETSI conformance.

Encrypted PDFs, certified PDFs with a catalog `/Perms`, unsupported signature
filters/digests, cyclic/oversized resource graphs and unexpected PDF layouts fail
closed. See [the part 2 report](../../docs/0.3.3-reliability-foundation-part2.md)
for the precise scope and residual limits.

## Local offline tests

With dependencies in `.build/native-prefix` and CMake available:

```bash
scripts/test-pades-local.sh
```

The script also detects the private CMake wheel under `.build/native-tools`.
`SIGNUM_CMAKE`, `SIGNUM_CTEST`, `SIGNUM_NATIVE_PREFIX` and
`SIGNUM_PADES_TEST_BUILD` can override the local paths. The test executable uses
only generated PDF/certificate/software-key fixtures. Subprocess cases launch
the real helper with synthetic input and a test-only PKCS#11 mock, keeping stdin
open and empty to prove that document/protocol/certificate failures precede any PIN read. No installed provider, PIN or
physical token is used. No CI is configured or invoked.

For a separate Release helper:

```bash
cmake -S Tools/PAdESPrototype -B .build/signum-pades-release \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$PWD/.build/native-prefix" \
  -DOPENSSL_ROOT_DIR="$PWD/.build/native-prefix"
cmake --build .build/signum-pades-release --parallel 6
```

## App bridge and manual hardware checks

The GUI supplies PIN/name through a private stdin pipe, never argv/environment.
It requires `--verified-output-v3`; older helpers fail rather than reporting
success without snapshot binding, certificate policy and integrity verification.
Stderr is drained while the process runs and retained at a
bounded size. Timeout/abnormal exit with a possible committed file produces an
uncertain result and never an automatic retry or deletion of that file.

This is an internal app/helper contract, not a public integration API. Invocations
without v3, `--job-id`, `--snapshot-id`, `--expected-document-sha256`, and
`--expected-cert-sha256` fail before authentication. Old direct invocations must be
replaced by explicitly approved snapshot jobs. Signum's CLI uses the same Core
snapshot/job invariants for CAdES and asks for approval before the PIN prompt.

Acquisition currently requires a filesystem supporting native CoW cloning on the
same volume as the private macOS temporary area. Unsupported/cross-volume inputs
fail closed; there is no streaming-copy fallback that could mix concurrent source
writes. Later original-file edits never update an approved snapshot. Re-select the
file to acquire/approve a new version. See the part 5 report for cleanup limits.

`scripts/build-app.sh` can bundle `.build/signum-pades/signum-pades-local` in a
separate development app. Native runtime libraries still require a reproducible
packaging/distribution step (SG-17); these local binaries are not a public release.

Hardware tests require explicit user authorization, a synthetic PDF and manual PIN
entry. Independent InfoCamere/other-validator interoperability checks remain to be
performed. Do not infer qualified status from the visible stamp.

PoDoFo remains an external LGPL-2.0-or-later OR MPL-2.0 dependency; no third-party
source or binary is committed. Secrets may still remain in Swift/middleware memory
(SG-12); this portion does not claim a complete middleware or PIN security review.
