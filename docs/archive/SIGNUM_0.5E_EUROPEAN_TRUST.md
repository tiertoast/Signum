# Signum 0.5-E — E1 interoperability gate blocked

> Historical E1 report. [E1R](SIGNUM_0.5E1R_TRUST_BARRIER.md) supersedes the
> authentication/interpretation coupling and records successful cryptographic
> authentication of the six frozen lists, with unsupported services excluded.
> This does not declare full European qualification or start E2/E3/E4.

21 October 2026. Baseline `c307431147a84f13d2945edbe23ce906e2c4f529`.
Branch `feature/signum-0.5e-european-trust`.

**Partial E1 only. The European-coverage gate has not passed. E2, E3 and E4
were not started; Build 6 was not produced.** The requested stop on substantial
blockers applies to the national TL incompatibilities below. Passing focused
unit tests does not imply support for every EU/EEA TL.

## Reused components and changes

The existing TL authenticator, bounded downloader, refresh actor, pivot validator,
continuity policy and atomic snapshot store are extended, without rewriting their
cryptographic implementations. There is no new dependency. OJ C/2026/1944 pins,
XMLDSig/XAdES security policy, canonicalization, references, SignedProperties,
critical-extension rejection and pivot rotation checks remain unchanged.

The raw parser captures the machine-readable MIME type only at the exact signed
pointer path and namespace. `nationalPointer` selects one XML pointer from a
current authenticated LOTL for an EU/EEA territory (30 codes; EL, not GR; UK
excluded). PDF pointers are not selected. This describes selectable destinations,
**not 30 authenticated national lists**. Download authorization is derived from
that pointer, and its certificate DER digests authorize the national signature.
Certificates embedded in a national document cannot authorize themselves.

`TLRefreshService(country:)` defaults to IT for compatibility. A caller selects
a country and a separate cache file; only that national list is fetched. The
bounded production downloader requires an authenticated pointer to fetch a new
national URL; its general `fetch(URL)` entry point still rejects arbitrary URLs.
The signed SK pointer uses HTTP; it is selectable without granting transport
confidentiality or weakening mandatory XML authentication. No redirects, cookies,
credentials or HTTP cache; existing 15/45-second and 64-MiB limits remain.

Snapshots include an explicit country, reauthenticate raw XML on read, retain
pivot history, enforce territory identity under the existing stable writer lock,
and apply the existing national/EU rollback checks. Legacy envelopes default to
IT. The historical JSON field `italy` stores the national bytes; it is retained
for format compatibility. `currentNational` exposes only current data;
`currentItaly` is nil for other countries. Expiry, cancellation, automatic refresh
of the selected country and last-valid-cache preservation reuse the A.2 logic.

There is **no application-wide European catalog manager**, automatic country
selection from document certificates, global LOTL high-water mark shared between
country files, Settings extension or European qualification integration yet.
The existing app continues to use Italy. Independent country envelopes repeat
LOTL bytes and inherit A.2's local-state deletion/replay limitations. Non-Italian
lists still cannot produce QES through the unchanged D evaluator.

## Real official TL observations

The public national XML files were retrieved only from the six locations in the
independently reauthenticated LOTL 397. No personal document, token, PIN or user
certificate was accessed or sent. All observations used the production pins and
native verifier; no synthetic anchor was substituted.

| Country | Native authentication | Observed result |
| --- | --- | --- |
| AT | Passed | TLv6 75; 8 providers, 100 services |
| IT | Passed | TLv6 224; 56 providers, 562 services |
| BE | Rejected | `unsupported critical extension vocabulary` |
| DE | Rejected | `unsupported signature algorithm` |
| ES | Rejected | `unsupported critical qualification criteria` |
| FR | Rejected | `unsupported critical extension vocabulary` |

Austria expires 15 December 2026 15:44:12 UTC. Its exact public XML is committed
as a fixture with a SHA-256 manifest. All six downloads, their hashes, algorithms,
locations and exact probe output are recorded in
[SIGNUM_0.5E_E1_RESULTS.json](../SIGNUM_0.5E_E1_RESULTS.json).
The four rejected files are **not declared authentic or invalid signatures**:
preflight rejects unsupported structures before completing XML signature checks.

Specific interoperability gaps identified by static inspection of those downloads:

- DE declares `http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1`.
  The native TL signature allowlist currently covers RSA PKCS#1 and ECDSA SHA-2,
  not RSA-PSS. Supporting it needs explicit algorithm/parameter policy and
  positive/negative fixtures, not removal of the allowlist.
- BE includes legacy `QCSSCDStatusAsInCert` in critical qualification metadata;
  FR includes legacy `QCNoSSCD`. These are outside the current vocabulary and
  need interpretation coordinated with the qualification evaluator.
- ES contains nonempty `otherCriteriaList`. The verifier explicitly rejects
  these criteria. Their semantics must be supported before qualification can
  safely consume the affected services. Simply allowing unknown critical data
  would bypass the current security boundary.

These observations establish a substantial authentication/interoperability gate,
not a reason to mark European signatures trusted under a reduced policy. No
allowlist or critical-content checks were relaxed to make the examples pass.

A live download of the LOTL endpoint returned an HTML network-error page with
“Connection refused” (HTTP transport completed, XML rejected `invalidRoot`).
The official LOTL fixture, hash `a36d0053df1afa96c88ede817a585b3168afeba84c1984a0e6cc5642453e70e6`,
was reauthenticated against OJ pins and is current through 7 April 2027.
Thus national authentication was tested against that authenticated snapshot;
a successful end-to-end live LOTL refresh is **not** claimed.

## Reproduction and validation

Use an absolute development prefix; Xcode's backend changes working directory.
The first build attempt used a relative prefix and failed to find native headers;
the corrected absolute-prefix build passed. This was a developer invocation
problem, not a fallback to other cryptographic dependencies.

```sh
export SIGNUM_TRUST_NATIVE_PREFIX="$PWD/../native13/prefix"
Tools/TrustPoC/native.sh test --jobs 4 --filter '(^|\.)EuropeanTests/'
Tools/TrustPoC/native.sh test --jobs 4 --filter \
 '(^|\.)(AuthenticationTests|RefreshTests|HTTPSTests|TrustedListParserTests|TLContinuityPolicyTests|TrustedListsIntegrationTests)/'
# Direct authentication, no network:
.build/out/Products/Debug/SignumTrustProbe national \
 Tests/SignumTrustAuthenticationTests/Fixtures/eu-lotl.xml AT \
 Tests/SignumTrustAuthenticationTests/Fixtures/European/at.xml
# Production refresh of a caller-selected country (fails closed if LOTL unavailable):
.build/out/Products/Debug/SignumTrustProbe country-refresh AT /new/cache/AT.json
.build/out/Products/Debug/SignumTrustProbe country-offline AT /new/cache/AT.json
```

Four new tests cover pointer MIME path/namespace/duplicate/wrapping defenses, selection of all 30 authenticated machine-readable
pointers, exclusion of PDF/UK/EU and expired LOTL, official Austrian authentication,
wrong-country/tampering rejection, selective refresh, atomic per-country cache,
offline fallback, expiry and cross-country cache substitution. Existing trust
regressions cover pivot/key rotations, rollback, malformed signatures, XML
wrapping, unauthorized references, failed-update preservation and cancellation.
Focused gate results: 30 existing Authentication/Refresh/HTTPS + 18 existing
TrustCore + 5 existing integration tests passed. Three new European tests and
one new parser-security test also passed: **57 distinct test cases, zero test
failures**. The initial 11 parser cases were additionally run during development;
this repeat is not added to the distinct count. Negative crypto cases emit
expected xmlsec diagnostics without XCTest failures.

The E3 complete SignumCore/PAdES/PKCS#11 campaign and E4 packaging checks were
not run because E1 is blocked. No Build 6, sanitizer campaign, macOS-13 runtime
claim, general code review or changes to signing, GUI, eIDAS verdicts or old bundles.
Host: arm64/macOS 27.2; source deployment target remains 13.0.

## DSS and remaining gates

No executable DSS comparison was performed: work stopped at E1, before the E3
interoperability milestone. The official DSS documentation consulted identifies
6.5 (28 August 2026); that is **not** a tested reference version. There is no
reference trust source, validation policy or evaluation-time comparison to report,
and no DSS equivalence claim. Java was not installed or added to the bundle.

Remaining: authenticate the unsupported national profiles without bypassing
critical semantics; complete country catalog management and rotation corpus;
then E2 historical issuance/qualification transitions and offline evidence policy;
then E3 multi-country signatures, executable DSS comparison and official full
regressions; only after those gates, E4 UI integration and isolated Build 6.
The D restrictions and C historical-revocation/profile limitations remain in force.
No additional QES-positive case or LTV/PAdES-LT/LTA conformance is asserted.

Primary references: [ETSI TS 119 612 V2.4.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf),
[ETSI TS 119 615 V1.3.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.03.01_60/ts_119615v010301p.pdf),
[Commission pivot procedure](https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html),
[DSS documentation](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html).

No main/previous branch/Beta 0.4/HalleyMac changes, GitHub Actions, merge, tag or
release. Stop at this documented gate.
