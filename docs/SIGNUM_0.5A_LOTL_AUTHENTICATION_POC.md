# Signum 0.5-A — Local LOTL / Italy authentication proof

20 October 2026. Branch: `feature/signum-0.5a-trusted-lists-foundation`.
Base: `6249309`. Status: locally verified, isolated proof; no GUI integration.

`SignumTrustAuthentication` consumes `SignumTrustCore` through a native C bridge.
The signing engine, workers, GUI and PAdES engine were not edited and do not
depend on it. No Actions, push, merge, tag, release or main-branch update was made.

## Official-file results

| Observation | EU LOTL | AgID Italian TL |
|---|---|---|
| XML version / sequence | 6 / 397 | 6 / 224 |
| Issue time (UTC) | 2026-10-15 14:06:46 | 2026-09-24 07:16:56 |
| Next update (UTC) | 2027-04-07 11:06:46 | 2027-03-24 08:16:56 |
| Providers / services | 0 / 0 (pointer list) | 56 / 562 |
| Native authentication | passed | passed after LOTL |

Signer certificate SHA-256:

- EU: `e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1`
- Italy: `ddf02ac377a55fbda3709158a15fe1a10330743413ff1de72a91edb6ee285661`

Original XML SHA-256:

- EU: `a36d0053df1afa96c88ede817a585b3168afeba84c1984a0e6cc5642453e70e6`
- Italy: `4dc43dc5ee19c23d1b65262b8df65ac7c4f16f12727e59175fa76e092e0a6889`

The EU signer matches certificate **2** of [OJ C/2026/1944](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:C_202601944),
15 April 2026. All six section-1 SHA-256 certificate digests are pinned in
`EUTrustPolicy`. SHA-1 is unused. Embedded DER is only a candidate: its exact
digest must match external policy before xmlsec receives its public key. An
embedded chain or self-signature cannot create an anchor. The Italian signer
must match the certificate identities in the **authenticated** Italian XML
pointer (six certificates). The pinned Italian URL is
https://eidas.agid.gov.it/TL/TSL-IT.xml . Acquisition occurs only after LOTL success.

The [official EU dashboard](https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls/tl/IT)
was inspected in the browser on 20 October: “Signature Valid”, AgID, TLv6,
sequence 224, RSA/SHA256. The [DSS live summary](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/tl-info)
reported `TOTAL_PASSED` for EU 397 and Italy 224, with 56 Italian providers and
562 services, matching this proof. Dashboard/DSS render local times; this table
uses XML timestamps in UTC. DSS's Italian `.sha2` warning does not replace
XML signature checks. No user document was uploaded for this comparison.

## Native implementation

Evaluated libxml2 alone (XML/XSD/canonicalization, no complete XMLDSig policy),
OpenSSL alone (primitives/DER, no XML processing), and xmlsec with OpenSSL.
The implementation uses xmlsec + libxml2 + OpenSSL in process, without Java,
subprocess verification or a network key resolver.

The supported TLv6 subset follows [ETSI TS 119 612 v2.4.1](https://www.etsi.org/deliver/etsi_TS/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf)
Annex B and XAdES-BASELINE-B structures: one enveloped root signature,
exclusive canonicalization, root and SignedProperties references,
SigningCertificateV2 digest, optional issuer/serial binding, SigningTime and
DataObjectFormat bound to the root reference. xmlsec verifies both reference
digests and SignatureValue with the separately authorized key.

Checks include:

- 64-MiB UTF-8, depth/node bounds, no DTD/entities, fixed bundled XSDs;
- one TL root/direct Signature, unique unqualified Id attributes;
- only empty/root-ID and SignedProperties-ID references; no external/file URLs,
  XPointer, RetrievalMethod, KeyInfoReference, Manifest or KeyValue;
- exact enveloped + exclusive-c14n root transforms, no XPath/XSLT;
- RSA/ECDSA SHA-256/384/512, SHA-2 digests, minimum 112-bit key strength;
- exact signer DER, signed certificate digest and IssuerSerialV2 consistency;
- no extra unsigned signature objects/properties or algorithm parameters;
- absolute namespace-aware parser paths: regression coverage prevents metadata
  injection in ds:Object, which the enveloped transform excludes;
- explicit supported critical-extension containers/eight-URI vocabulary;
  unknown critical content and qualification criteria fail closed;
- provenance/signature before issue/expiry/territory/version/sequence continuity;
  changed bytes under a reused sequence fail when previous state exists.

Schema provenance and local import rewrites are recorded in
`Sources/SignumTrustAuthentication/Schemas/PROVENANCE.md`.

## Reset and pivot chain

The [Commission's procedure](https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html)
was checked against the OJ notice. Current LOTL 397 lists the 2026 OJ URL before
old pivots 378, 341, 335, 300 and 282. Therefore **zero post-reset pivots** are
needed now; old pivots are not reused as current anchors.

`LOTLPivotChain` verifies caller-supplied pivots oldest first. Each authenticates
with the *previous* authorized certificate set; its authenticated EU pointer
then authorizes the next set. Signed history, OJ boundary, chronology, sequence
and agreement with the current chain are checked. Expired archived pivots may
authenticate transitions, but cannot authorize a national list as current data.
Synthetic fixtures prove an expired A→B pivot and reject B without A's pivot,
unapproved pivots, duplicates and a retired A key after transition. Discovery
URLs alone never grant trust. The 15-day overlap is not a chain-verification bypass.

Only the existing EC location and eu-lotl-pivot-N.xml URLs are supported.
Location migration/emergency OJ replacement require explicit policy updates.
Historical TLv5/BES chains are rejected; the raw parser still accepts v5 as
untrusted. The probe/cache implement today's zero-pivot reset; future rotations
require explicit library pivot inputs and a cache-format extension. Missing
pivots fail closed.

## Acquisition and snapshots

`Tools/TrustPoC/acquire.sh DIRECTORY` uses HTTPS, a 10-second connection limit,
45-second total limit, 64-MiB bounds and **no redirects**. It verifies LOTL and
its Italian pointer before connecting to AgID. Both verified XML files are
stored in one atomic `verified.json` envelope. Existing bytes are reauthenticated
before continuity checks; a failed update preserves the file. Reload always
reauthenticates and checks freshness. Expired data yields an error, never a
current result.

Snapshot use is a local single-writer proof, without distributed locking,
protection from deletion of local state, a refresh service or stale-data UI.
First bootstrap cannot detect a still-valid replay predating the first locally
accepted revision. These limits do not turn offline bytes into a trust verdict.

## Build, tests and macOS

Host: arm64 Apple Silicon, macOS 27.2, Apple Swift 6.4 / SDK 27.0.
Baseline before edits: **18/18 dedicated tests passed**.
Final dedicated tests: **32/32 passed** (18 ingestion/continuity + 14 native
XCTest methods), with both dependency combinations:

1. Homebrew xmlsec 1.3.12, libxml2 2.15.4, OpenSSL 4.0.3.
2. Source-built xmlsec 1.3.12, libxml2 2.15.4, OpenSSL 3.5.6, target **macOS 13.0**,
   XSLT disabled. Executable/dependency load commands were inspected.

Homebrew bottles target macOS 27 and are not a macOS-13 distribution. Source
builds resolve that deployment-target mismatch. Actual execution on macOS 13
and Intel/x86_64 remain **unverified**. No universal/notarized shipping package
is delivered; source-built dylibs use local installation paths.

From repository root:

```sh
# Development-host dependencies, if needed:
brew install libxmlsec1 pkgconf
Tools/TrustPoC/native.sh test --filter 'SignumTrust(Core|Authentication)Tests'
Tools/TrustPoC/native.sh run SignumTrustProbe \
  Tests/SignumTrustAuthenticationTests/Fixtures/eu-lotl.xml \
  Tests/SignumTrustAuthenticationTests/Fixtures/it.xml

# Local dependency build with the macOS 13 deployment target:
Tools/TrustPoC/build-native13.sh
export SIGNUM_TRUST_NATIVE_PREFIX="$PWD/.build/trust-native13-deps/prefix"
Tools/TrustPoC/native.sh test --scratch-path .build/trust-native13 \
  --filter 'SignumTrust(Core|Authentication)Tests'
Tools/TrustPoC/acquire.sh .build/verified-trusted-lists
```

The source script pins archive hashes and installs under `.build`. Initial
Homebrew dependency installation hit a p11-kit configuration permission error;
installation of the required native libraries succeeded. No PKCS#11
configuration or security permission was changed.

Committed XML/DER fixtures run offline at a fixed clock. The generator uses
throwaway keys, deleted afterward; regeneration intentionally creates different
random keys/signature bytes. Official fixtures stay unchanged. `manifest.json`
records corpus hashes. Positive and negative tests cover official EU/IT,
root/SignedProperties/SignatureValue tampering, unauthorized certificates,
wrapping/IDs, external/file/XPointer references, downgrade, DTD, critical
extensions, validly signed invalid certificate/format properties, expiry,
future time, rollback, rotation and atomic snapshot preservation.

AddressSanitizer: **14/14 native tests passed**, with no sanitizer finding.
The Swift/C bridge is instrumented; external dependency libraries are not.

The broader `swift test` was also attempted: **430 SignumCore tests, 39 failures**.
Diagnostics include missing mandatory existing PAdES helper/native fixtures and
dependent launch failures. No full-suite success is claimed. The unchanged
repository runner needs its separate PoDoFo/OpenSSL/FreeType/Poppler setup
(`scripts/test-local.py --group swift ...`). Those signing-engine prerequisites
were not replaced or bypassed. Full integration remains gated on that environment.

## Limits of this proof

This authenticates signed-list provenance, not full ETSI conformance certification.
The profile is deliberately narrow: exactly two references, one signer
certificate, one DataObjectFormat, no unsigned XAdES properties/transform
parameters. Other legitimate profiles fail closed. Critical-service extensions
are recognized structurally/vocabulary-wise; they are not qualification rules
or qualification conclusions exposed by this component.

No X.509 path building, service-certificate trust, OCSP/CRL, trusted signing time,
certificate validity/revocation decision or qualified-signature verdict is
implemented. Signed SigningTime remains a claim. Authentication derives from
OJ/pivot/LOTL certificate-identity authorization. Subsequent 0.5-B/C/D phases
and production hardening remain separate.

Digital signatures. Simply native.
