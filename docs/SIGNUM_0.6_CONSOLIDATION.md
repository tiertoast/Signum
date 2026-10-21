# Signum 0.6 consolidation — Development Preview Build 1

Baseline `287e83848c95126529d4b6da4262275ab879bf58`, branch
`feature/signum-0.6c-asic`. Scope: consolidate A/B/C and package the existing
functionality for local acceptance. No new signature/trust profile is introduced.

## Integrated scope and packaging changes

- A: independent integrity, path, revocation, time and qualification results;
  current assessment when no proven timestamp exists, with the existing conservative
  evidence requirements. Declared signingTime never supplies a proven time.
- B: the declared RSA/SHA-256 XAdES-B-B enveloped subset, immutable approval and
  existing supervised PKCS#11 worker; XMLDSig and XML security protections retained.
- C: one-document ASiC-S and 2–4-document ASiC-E, detached XAdES-B-B signatures over
  every payload and the E manifest. Strict bounded ZIP validation and byte association.
- No application engine, worker protocol, CAdES/PAdES generator or UI redesign change.

The existing preview packager accepts `--version 0.6.0 --build-number 1`, preserving
all old preview identities. The identity is
`io.github.tiertoast.Signum.DevelopmentPreview.V06.B1`, version 0.6.0, build 1;
name **Signum 0.6 Development Preview — Build 1**. It already matches the production
trust model's DevelopmentPreview identity guard, so no cache-policy rewrite is needed.
Preferences use that bundle domain. Trusted Lists use
`~/Library/Application Support/io.github.tiertoast.Signum.DevelopmentPreview.V06.B1/TrustedLists`;
revocation uses `~/Library/Caches/io.github.tiertoast.Signum.DevelopmentPreview.V06.B1/Revocation`.
Neither an earlier bundle nor its preferences/cache is overwritten.

The local runner explicitly links its existing native prefix as a test-only rpath,
so new test executables resolve the shared XML/crypto libraries without global loader
configuration. Distribution binaries are independently processed by the existing
packager: private dependency closure, loader-relative paths, arm64 and minimum OS
audit, development-path rejection, nested hashes, ad hoc signatures and relocation.
Existing native libraries are reused, including system libz; nothing is installed.
The packager does not repeat the already executed native regression suite.

## Validation protocol and limits

One official regular campaign: `scripts/test-local.py --group complete
--skip-sanitizers --native-prefix ../a3-native-v3/prefix --output-root
../06-complete-campaign`. Environment supplies the same private pkg-config prefix,
`SIGNUM_TEST_XMLSEC` pointing to its xmlsec1, and `SIGNUM_TEST_PYTHON` to the existing
Python interpreter. Tests use public/synthetic fixtures, mock providers and credentials;
no physical device, real PIN, private key or personal document is requested.
No new sanitizer campaign, DSS setup, benchmark or general review is performed.

The relocated bundle smoke uses a copy of the existing authenticated IT/EU cache,
reauthenticates it offline and confirms that cache bytes remain unchanged. It starts
the GUI with a system-only PATH, audits actually loaded libraries and closes only
its test process after startup, making diagnostic logs stable. This establishes
startup, not the user's manual end-to-end acceptance or physical-token compatibility.

Retained limits:

- Only declared XAdES/ASiC profiles and resource caps from the B/C reports; one XML
  signer, RSA PKCS#1/SHA-256, no XAdES-T/LT/LTA, ASiC countersignatures or CAdES detached.
- Current/historical qualification retains the six tested countries IT/AT/DE/BE/FR/ES,
  direct CA/QC, post-2016 and complete supported evidence requirements. Missing or
  unsupported evidence stays indeterminate; current OCSP good is not historical proof.
- No claim of general ETSI conformance, executable DSS equivalence or LTV/LT/LTA.
- Ad hoc signing only: no Developer ID, notarization or production distribution approval.
- arm64 and deployment target 13.0 are checked in every bundled Mach-O. Actual
  execution is on macOS 27.2; macOS 13 execution has not been tested.
- Hardware signing needs compatible user-installed PKCS#11 middleware. Verification
  and the included engines do not require Java/Homebrew at runtime. Legacy
  verify-cades uses the system OpenSSL command; unified verification uses bundled crypto.

## Manual acceptance remaining

Open the relocated Preview (or drag the original app to a separate location), then:

1. Check title/version 0.6.0, build 1, and Settings → Elenchi fiduciari in the isolated
   domain. No preferences or cached state is imported automatically from earlier apps.
2. Verify a known CAdES/PAdES without timestamp; keep declared time, observation time,
   current/historical assessment, revocation and qualification distinct. A missing
   revocation proof must not become a positive qualification.
3. With the user's own middleware/device, sign and verify a small supported XML,
   one-document ASiC-S and a 2–4-document ASiC-E; inspect the approved document list.
4. Verify an altered payload and an unsupported/unsafe container: neither may show
   successful integrity. Cancel signing before authentication and test an occupied
   output destination without permitting replacement.
5. Reopen offline and check the explicit freshness/evidence limitations. Hardware/PIN
   and real-document checks are deliberately left to the user; none ran automatically.

Final counts, source commit and artifact checksums follow in the delivery section.

## Complete campaign result

Passed one complete official regular campaign: **598 Swift tests** (SignumTrustIntegrationTests 5, SignumTrustCoreTests 19, SignumTrustAuthenticationTests 34, SignumCoreTests 457, SignumCertificateValidationTests 83), PAdES 81 native cases each Debug/Release, PKCS#11 58 provider cases and
2 loader contracts, and 19 runner/packaging contracts. No failed/skipped test,
application source correction or repeated suite. Native/Swift sanitizers were not
repeated. The output root is `outputs/signum-0.6-consolidation`; the complete original
run and logs are in `work/06-complete-campaign/20261021T183435Z-07b63ab219`.
