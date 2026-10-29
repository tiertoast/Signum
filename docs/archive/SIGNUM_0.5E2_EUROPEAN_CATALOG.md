# Signum 0.5-E2 — European catalog and historical validation

Baseline: `8052dcd37e8e32549cbbf7f60c54c6203eb0c498` (E1S).
Scope: Swift trust coordination and validation. No GUI, signing, PAdES, PKCS#11,
native primitive, dependency or bundle changes. No Build 6.

## Coordinated catalog

`EuropeanTrustCatalogService` shares one authenticated EU LOTL/pivot journal and
continuity state. Available EU/EEA territories come from authenticated machine-list
pointers. An empty initial refresh fetches the LOTL only; national acquisition is
explicit or restricted to already selected countries. Concurrent refreshes coalesce.
National envelopes reuse the A/E1 downloader, authentication, stable file locks,
rollback policy and atomic replacement. Failed downloads preserve prior bytes;
previously cached national XML must still authenticate against the latest shared
LOTL before being exposed as current. Removed signing keys are not grandfathered.

Shared commits recheck the LOTL high-water and pivot prefix under a stable catalog
lock; national commits recheck the latest shared authorization before their own
existing atomic save. Missing shared state alongside national caches fails closed.
Partial failure in one territory does not discard successful siblings. Refreshes
are bounded to four national downloads and 128 MiB aggregate national XML, with the
existing per-response limits, at most 16 pivots/64 MiB EU material and a 512 MiB
cache quota. No automatic eviction erases continuity. Automatic refresh belongs to
the caller's cancellable task; it creates no resident process.

`EuropeanValidation` connects the coordinator to the existing signature validator.
Actual certificate signature/issuer matches select candidate services in cached
lists. Country attributes are only bounded download hints (at most two), never
trust evidence; explicit selection handles absent/unhelpful hints. Similar names or
the same identity in different countries do not select a preferred service.
Offline mode performs no downloads and can qualify only with sufficient currently
fresh authenticated TLs and bound cryptographic evidence.

## Historical policy

`Signum-E2-direct-CAQC-eSig-2016-v1` enables classification for IT, AT, DE, BE, FR and
ES only. Other EU/EEA national lists may be authenticated/cached, but their positive
qualification gate stays closed. This is tested profile coverage, not a claim that
every certificate or service in those six countries is supported.

Qualification uses the C timestamp proof and a B path evaluated at that proven
instant; declared signingTime is never substituted. C exposes the exact path used
for revocation (`revocationPath`). Existing bound OCSP/CRL primitives must prove
status throughout the timestamp interval and through observation. A current good
response issued after the historical proof cannot prove earlier validity.
Historical service withdrawal can coexist with qualification at a proven earlier
instant only when the entire supported evidence window is covered.

From certificate issuance through proof, every service event must resolve the same
authenticated certificate identity, granted CA/QC status and supported criteria.
Each event supplies its own qualifiers. Different raw qualifier sets are accepted
only when they produce the same effective certificate-specific qualified/eSig/QSCD
profile; contrary or unknown transitions remain indeterminate. Positive signatures
are restricted to the direct signer→CA/QC profile, not arbitrary intermediate paths.
Integrity, present-time path, revocation, proven time and qualification stay distinct.

## Fixtures, evidence and limits

E1R/E1S signature, timestamp and revocation fixtures are reused unchanged. New E2
synthetic signed LOTL/national fixtures test selection, shared/national rotation,
rollback, partial failures, offline restart, cancellation, download bounds, duplicate
identities and equivalent/conflicting historical qualifiers. Their private signing
keys are disposable and are not distributed. The manifest records public hashes.
Frozen official IT/AT/DE/BE/FR/ES XML tests establish authentication/interpretation
interoperability; positive QES tests use synthetic certificates and evidence, not
real signatures from all six countries. No indiscriminate live-country crawl occurs.

TakenOverBy, incoherent timelines, unsupported criteria/identities, incomplete proof,
pre-2016 classification, managed-on-behalf QSCD and archived evidence outside the
supported temporal window stay excluded/indeterminate. There is no archived TL key
search, general historical validation or LTV/PAdES-LT/LTA claim. Cache envelopes
retain legacy duplicate LOTL bytes; no new database or migration is introduced.
An owner deleting all continuity files can reset local state, as with the prior
cache; this is not a tamper-proof persistent counter. The application GUI continues
to use its existing provider; the new coordinator is integrated at the typed engine
API, leaving application wiring/packaging to the explicitly excluded E4 work.
DSS execution was not added in E2; no new DSS equivalence claim is made.

References: [ETSI TS 119 615 V1.3.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.03.01_60/ts_119615v010301p.pdf),
§4.3–4.5, and the E1R/E1S reports for authentication and interpretation boundaries.

## Validation

The targeted phase ran Authentication (34 passed) and CertificateValidation (67,
initially one failed assertion). The assertion incorrectly required exactly one
provenance reference; the implementation correctly retained national and LOTL
references. It now verifies the authorizing LOTL URL and XML digest instead.
Two earlier compile diagnostics were corrected before that execution; no repeated
failure of the same cause occurred. One complete official campaign follows this
localized test correction. Sanitizers are omitted because no native code or new
memory-unsafe boundary changed; all regular complete gates remain mandatory.
Final counts and gate outcomes are recorded in `SIGNUM_0.5E2_RESULTS.json`.

Final campaign: **passed**, once, on the macOS arm64 development host. Swift:
555 tests (Core 430, TrustCore 19, Authentication 34, Integration 5,
CertificateValidation 67, including all 8 new E2 cases). PAdES: 81 native cases in
each Debug/Release; PKCS#11: 58 provider cases and 2 loader contracts; packaging:
18 contracts. Zero final failures/skips; no mandatory regular gate left open.
No post-campaign source correction or additional test campaign was necessary.
Local logs are retained under `outputs/signum-0.5e2` in the task workspace; their
hashes and the official runner configuration/results are in the companion JSON.
Execution on macOS 13 was not tested. No new application build was generated.
