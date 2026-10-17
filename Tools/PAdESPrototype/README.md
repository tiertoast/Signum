# Signum PAdES Engine — Reliability Foundation

Native macOS helper used by SignumApp when bundled. SwiftPM builds the app but
not this C++ helper. This development branch requires **PoDoFo 1.1.2** and
**OpenSSL 3.x**; no global installation is performed by the test script.

## Signing and verification

- PoDoFo incrementally signs an in-memory copy of a bounded PDF source.
- The external service supplies SHA-256 DigestInfo to PKCS#11 CKM_RSA_PKCS;
  the token's private key is never exported.
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
only generated PDF/certificate/software-key fixtures. It never loads a PKCS#11
provider, uses a PIN or accesses a physical token. No CI is configured or invoked.

For a separate Release helper:

```bash
cmake -S Tools/PAdESPrototype -B .build/signum-pades-release \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$PWD/.build/native-prefix" \
  -DOPENSSL_ROOT_DIR="$PWD/.build/native-prefix"
cmake --build .build/signum-pades-release --parallel 6
```

## App bridge and manual hardware checks

The GUI supplies PIN/name through a private stdin pipe, never argv/environment.
It requires `--verified-output-v1`; older helpers fail rather than reporting an
unverified success. Stderr is drained while the process runs and retained at a
bounded size. Timeout/abnormal exit with a possible committed file produces an
uncertain result and never an automatic retry or deletion of that file.

`scripts/build-app.sh` can bundle `.build/signum-pades/signum-pades-local` in a
separate development app. Native runtime libraries still require a reproducible
packaging/distribution step (SG-17); these local binaries are not a public release.

Hardware tests require explicit user authorization, a synthetic PDF and manual PIN
entry. Independent InfoCamere/other-validator interoperability checks remain to be
performed. Do not infer qualified status from the visible stamp.

PoDoFo remains an external LGPL-2.0-or-later OR MPL-2.0 dependency; no third-party
source or binary is committed. Secrets may still remain in Swift/middleware memory
(SG-12); this portion does not claim a complete middleware or PIN security review.
