# Signum 0.5-E1R — Trust architecture barrier and RSA-PSS

Baseline `81c6af9545dcd55c3dce48856d30193fc5b8652d`, same branch
`feature/signum-0.5e-european-trust`. 21 October 2026. This increment implements
only the A/B security boundary and fixed-parameter XMLDSig PSS. No historical
qualifier/OtherCriteria interpreter, E2/E3/E4, GUI change or Build 6.

## Two capabilities, separate construction

`AuthenticatedTLDocument` contains immutable original XML, SHA-256 revision,
territory/sequence/issue/expiry in its parsed document, signer DER/fingerprint,
externally authorized certificate digests, authorizing references and verified
pivot references, and the applied cryptographic policy identifier. Its initializer
is file-private to the authenticator. `authenticateDocument` establishes provenance
with the caller's external certificate policy; it never returns service authority.
Official entry points retain OJ C/2026/1944 and LOTL/pivot authorization. National
results record the authorizing LOTL digest and destination; pivot-chain results
record the pinned journal reference and the verified pivot URL/digest sequence.
The raw XML makes this provenance reproducible with the retained cache/pivots.

`TLInterpreter.interpret` produces `InterpretedTrustCatalog`, whose constructor
is file-private to the interpreter. It exposes `usableProviders`, separately
indexed `excludedServices` with reasons, and complete/partial/blocked state.
Raw `document` remains available for diagnostics, pointer discovery and continuity;
**no certificate trust consumer uses its raw provider list**. The legacy name
`AuthenticatedTL` is a source-compatible alias for the interpreted capability,
not an alias for the new provenance-only type. Existing application signatures
therefore remain source-compatible without GUI changes.

Only interpreted catalogs are accepted by public chain, TSA, evidence and
qualification services. There is no overload promoting a provenance-only document
to an anchor set. A caller may explicitly request interpretation, which always
applies the barrier. Pure primitive verification with an explicitly supplied key
still produces its existing primitive result, not a high-level proven-time or
QES verdict; the public integrated qualification API computes its own evidence.

## Consumer inventory

| Path | Boundary enforced |
| --- | --- |
| `CertificatePathValidator.evaluate` and internal `identities` | Interpreted catalog input; anchors only from usableProviders |
| `TSAAuthorization.evaluate` | Interpreted input, usable providers only; existing TSA type/status/window checks |
| `SignatureEvidenceValidationService` | Interpreted input; TL certificate candidates only from usable providers; B and TSA calls retain same boundary |
| `SignatureQualificationService.validate/assess` | Interpreted input; historical matching, endpoint path checks and qualifier lookup all use usable providers |
| `TrustedListCatalogProviding.currentCatalog` | Existing legacy return name now denotes interpreted catalog |
| `TLRefreshView.currentItaly/currentNational`, `TLSnapshot.load/readVerified` | Raw XML reauthenticated and reinterpreted on every read |
| `TLBundle`, JSON cache | Stores raw XML/pivots; no serialized service capability is trusted |
| LOTL/pivot/national pointer authorization | Globally blocked interpretation cannot authorize a new national destination or pivot rollover |
| Probe | Reports XML metadata, interpretation state, usable/excluded counts and reasons separately |

The independent signature-integrity report, signing engine, PDF appearances and
PKCS#11 source remain unchanged. Current TL metadata counts in existing UI remain
raw list statistics, not claims that every listed service is an eligible anchor.
No UI redesign or new UI labels are introduced in this increment.

## Conservative interpretation, not a new full interpreter

The existing D `TLQualificationRules` implementation is moved intact to TrustCore,
with a small protocol supplying certificate policy/Key Usage facts. The D decoder
conforms to that protocol; the same evaluator still computes actual applicable
qualifiers. No new certificate parsing, OCSP/CRL or RFC3161 implementation is added.

The catalog syntax pass reuses these rules with synthetic facts solely to detect
unsupported syntax: it consumes only nil/non-nil, never the artificial boolean
match or output qualifiers. Thus a known nonmatching policy is preserved for
actual evaluation, while an unknown criterion is not silently treated as false.
Existing namespace, assertion, KU/PolicySet and depth restrictions remain.

Known AdditionalServiceInformation subtypes already recognized by the native
profile (signatures, seals, website authentication and RootCA-QC) are retained as
interpretable metadata. They do not themselves produce an eSig/QES result; the
existing D rules still determine their applicability and supported profile.
Unsupported critical extension containers, qualifiers or criteria exclude the
service. For this milestone, one unsupported historical event excludes the whole
service: current properties are never borrowed to reinterpret that event.
Independent services remain available. Known but not yet interpreted legacy
SSCD/LegalPerson/OtherCriteria and critical TakenOverBy therefore remain excluded.
Noncritical unknown qualification criteria are also conservatively excluded;
other unknown noncritical metadata cannot authorize any positive assertion.

Critical content outside an exact, namespace-aware current/history service
extension path blocks the entire catalog. Critical extension structure is checked
by the interpreter; XSD structure validation and all XML signature safety bounds
remain native. Unknown global scope cannot be hidden by omitting a provider tree
from the raw parser.

“Usable” in the reported counts means within this interpretation profile. It does
not mean granted at every date, suitable for every purpose, a qualified certificate,
or QES: B/C/D still enforce type, status, time, exact identities and evidence.
No country-specific interpretation exception is present.

## RSA-PSS

The native URI registry adds fixed-parameter `sha256-rsa-MGF1`,
`sha384-rsa-MGF1` and `sha512-rsa-MGF1` from RFC 9231 §2.3.10. Generic `#rsa-pss`,
SHA-1, unknown URIs and child algorithm parameters remain rejected. The existing
no-parameter check also applies to canonicalization and digest methods.

xmlsec 1.3.12/OpenSSL 3.5.6 perform PSS verification. In the source-built xmlsec
backend, `src/openssl/signatures.c` explicitly sets PSS salt length to digest
size; for unrestricted RSA SPKI keys, MGF1 uses the signature digest and OpenSSL
enforces EMSA-PSS trailer 0xBC. For RSA and RSA-PSS SPKI keys, a short OpenSSL
verification-context preflight explicitly sets PSS padding, signature digest,
MGF1 digest and exact digest-sized salt. Every setter must accept those values.
This validates SPKI restrictions without letting them override the fixed XML
profile: compatible restricted keys (including the official German TL key) are
accepted; incompatible digest/MGF/salt restrictions and non-RSA keys are rejected.
The signature/reference verification itself remains in xmlsec.
No AUTO salt policy or weak-algorithm fallback is added. Synthetic signatures
with actual wrong salt length, actual different MGF digest, and actual wrong
encoded-message trailer are rejected. An EC certificate authorized as the claimed
signer cannot verify an RSA-PSS signature. Explicit parameter children are tested
separately from those cryptographic encoding mismatches.

C14N, root/SignedProperties reference checks, certificate authorization and digest
binding, unique IDs, wrapping defenses, no external URI resolution, key strength,
XAdES structure, bundled XSD and resource limits remain unchanged. Only semantic
criticalVocabulary/OtherCriteria checks move to the interpreter, together with
all consumer gates above. There is no change to the native dependency versions.

## Frozen official XML results

LOTL 397 is authenticated with the existing OJ policy. All six exact national
files complete native XML signature/reference verification before interpretation.
No network access or new trust source is required by these tests.

| Country | XML authenticated | Usable | Excluded | Interpretation | Exclusion reasons |
| --- | --- | ---: | ---: | --- | --- |
| IT | Yes | 412 | 150 | partial | 121 critical TakenOverBy; 29 unsupported qualifier/criterion |
| AT | Yes | 100 | 0 | complete | none |
| DE | Yes, RSA-PSS | 683 | 296 | partial | 1 critical TakenOverBy; 295 unsupported qualifier/criterion |
| BE | Yes | 92 | 48 | partial | unsupported qualifier/criterion, including legacy semantics |
| FR | Yes | 260 | 102 | partial | unsupported qualifier/criterion, including legacy semantics |
| ES | Yes | 337 | 102 | partial | unsupported qualifier/criterion, including OtherCriteria |

No entire official catalog is blocked in this corpus. The synthetic unscoped
critical fixture blocks its entire catalog. Exclusion counts are conservative
service-wide counts, not counts of unknown XML nodes or only the four previously
identified examples. A service with multiple issues is counted once with its
first blocking reason. Unknown critical information is never deleted from the
source XML or converted into an implicit favorable match.

The IT exclusions are an explicit coverage restriction for previously unprocessed
semantics, not a cryptographic regression or a qualification assertion. The
unchanged supported Italian synthetic chain/TSA/revocation/time/QES cases must
still pass end-to-end; broader historical coverage is deferred. New European
QES positives are not introduced: D's Italy/time/evidence profile is unchanged.

## Tests and reproduction

Ten `TrustArchitectureTests` methods cover distinct provenance/capabilities,
service-local isolation with a working sibling, denied CA path/QES, denied TSA
and high-level proven time, global critical scope, authenticated cache reload
and forged serialized capabilities, unknown vs false criteria, three positive
PSS algorithms and negative signatures/properties/references/URI/parameters/
unauthorized signer/actual salt/MGF/trailer/key incompatibility and a restricted
RSA-PSS SPKI override attempt. A further
`EuropeanBarrierTests` method verifies the six frozen official documents and
prints machine-readable `E1R-OFFICIAL` records. Existing per-signature CMS/PDF
binding and existing D positive cases are reused.

The fixture generator reuses the C/D generators and disposable keys; lxml and
cryptography are existing development-runtime tooling only. Neither is a new
product dependency. Committed fixtures contain only public certificates, signed
synthetic documents/evidence and signed public TLs; no private keys survive.
Raw XML and DER fixture hashes are recorded alongside their corpora.

```sh
export SIGNUM_TRUST_NATIVE_PREFIX="$PWD/../native13/prefix"
export SIGNUM_TEST_PADES_HELPER="$PWD/.build/c-bind-native/signum-pades-local"
Tools/TrustPoC/native.sh test --jobs 4 \
 --filter '(^|\.)(TrustArchitectureTests|EuropeanBarrierTests)/'
PKG_CONFIG_PATH="$PWD/../native13/prefix/lib/pkgconfig" \
 python3 scripts/test-local.py --group complete \
 --native-prefix "$PWD/../a3-native-v3/prefix" \
 --cmake /opt/homebrew/bin/cmake --ctest /opt/homebrew/bin/ctest \
 --poppler /opt/homebrew/bin/pdftoppm --output-root "$PWD/../e1r-final-campaign"
```

One complete campaign ran with the existing official runner, without editing
its groups or bypassing prerequisites. Development failures are retained in logs: an omitted helper env in
the initial legacy test invocation; two missing try annotations in a new test;
then a new test failing to pass the helper explicitly and a mutation missing the
SignatureValue Id attribute. These were test harness issues corrected locally,
not ignored assertions or relaxed production cryptography. The corrected targeted
legacy and barrier suites pass; negative xmlsec diagnostics are expected.

A final adversarial probe found a real backend parameter-default hazard:
xmlsec accepted a synthetic SHA256 fixed-URI signature whose restricted RSA-PSS
SPKI imposed MGF1 SHA384. This newly added test failed once against the unguarded
implementation, after correcting fixture generation (explicit OpenSSL config)
and a missing generated resource. An initial guard that rejected every RSA-PSS
SPKI key was too restrictive: the focused four-target run passed 109/110 tests,
but rejected the genuine German TL. That guard is replaced by explicit OpenSSL
parameter-compatibility checks, not a country exception. The subsequent targeted
run passes all ten architecture tests and the six-country official fixture test
(11/11). The full campaign had already passed; this order and the intermediate
failure are retained rather than presenting a second complete run.
The fixture is publicly reproducible with `generate-e1r-pss-key-fixture.py`; it
retains no private key. No cryptographic check was relaxed.

Host arm64/macOS 27.2; target 13.0 retained. No actual macOS 13 execution, physical
token test, new application bundle, Java, new dependencies, general code review,
merge/tag/release, Actions, main/previous branch/Beta 0.4/HalleyMac changes.

References: [RFC 9231 §2.3.10](https://www.rfc-editor.org/rfc/rfc9231.html#section-2.3.10),
[TS 119 612 V2.4.1 §5.5.9.2](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf),
[TS 119 615 V1.3.1 §4.2–4.5](https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.03.01_60/ts_119615v010301p.pdf).

### Compile-time boundary control

An independent `swiftc -typecheck` positive control accepts an interpreted catalog
for all four public entry points (path, TSA, evidence, qualification). The same
source with `AuthenticatedTLDocument` substituted fails type checking at those
calls. Module loading succeeds in the positive control, so the negative result
is a type incompatibility, not a missing-header/module error. Sources and complete
compiler diagnostics are retained in the local `work/e1r-type-boundary` evidence.

## Final official campaign

`work/e1r-final-campaign/20261021T071625Z-ebd03744aa/results.json` reports
`status: passed`; every recorded build/test step exited zero. The campaign ran
once. Local evidence is copied to `outputs/signum-0.5e1r/official-campaign`.

| Gate | Result |
| --- | --- |
| Normal Swift suite | 539 passed, 0 failures: Core 430, TrustCore 19, Authentication 34, Integration 5, CertificateValidation 51 |
| Native PAdES | 81 cases each in Debug and Release, passed |
| Native PKCS#11 | 58 provider cases and 2 loader contracts, passed (2 CTest entries) |
| Packaging/runner contracts | 17 passed |
| Official runner ASan/TSan | Swift selected Core suites 212/212 each; PKCS#11 ASan/TSan and PAdES ASan passed |

The runner sanitizer selection covers the existing Core/native contracts; it does
not execute the newly added Authentication/CertificateValidation tests, nor does
it instrument prebuilt third-party libraries. A separate final ASan run of the
ten new architecture tests and the six-country official fixture test passed
11/11 after the compatibility correction, with the C wrapper instrumented.
Prebuilt xmlsec/OpenSSL/libxml2 remain uninstrumented. ASan leak detection follows the
runner's existing `detect_leaks=0` configuration. These results are not a claim of
complete sanitizer coverage of the new trust boundary.

The normal full-suite result predates the restricted-SPKI correction and tenth
architecture test. The four-target post-campaign run checked existing B/C/D and
integration regressions (109 passed) and exposed the overly restrictive DE guard
(one failure). The final 11-test run checks the corrected key compatibility, all
three PSS variants and negative vectors, the complete barrier, and the six official
TLs; all pass. Exact intermediate and final results are recorded in
`SIGNUM_0.5E1R_VALIDATION_RESULTS.json`; the complete campaign is not repeated.
The independent compile-time positive/negative boundary controls also passed.

No unresolved regression is accepted. Remaining limitations are conservative
service exclusions, no full historical/OtherCriteria interpreter, generic
parameterized PSS unsupported, existing qualification
coverage unchanged, frozen-fixture rather than new live-country acquisition,
and no macOS 13 runtime or new app-bundle validation.
