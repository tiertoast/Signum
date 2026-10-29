# Signum 0.5-E3 — European interoperability and DSS comparison

21 October 2026. Baseline E2: `35400423b3f9b22a8f74e21d9e7a6b24df3b2feb`.
Branch: `feature/signum-0.5e-european-trust` (initially clean).
**Documentation only. No new test execution, cryptographic verification, corpus,
engine correction, application build, packaging or sanitizer campaign.**

## Evidence and method

**Observed previously:** the E2 complete campaign and its retained logs, identified
by SHA-256 in `SIGNUM_0.5E2_RESULTS.json`; E1R/E1S reports and frozen fixtures.
**Observed in E3:** bounded checks of those results, E2 historical guards/test
expectations and existing DSS metadata; no repetition of the earlier static audit.
**Documented:** official ETSI procedures and the pinned DSS source findings already
collected in the earlier interoperability investigation.
**Not verified:** DSS fixture verdicts, current live national lists, real signatures
from all six countries, full ETSI conformance and application European wiring.

No ready DSS distribution was identified in the task/work roots or Applications;
the standard local DSS Maven repository is absent. The prior audit likewise found
no runnable distribution. `work/dss-paths.txt` is a repository tree listing, **not**
a local DSS installation. The collected Java source files are reference material,
not an executable environment. No Java/DSS install, Maven resolution, remote demo
submission or personal-document access was attempted. This bounded inventory does
not assert the absence of DSS anywhere else on the Mac.

## Three different outcomes

The existing official test authenticates EU LOTL 397 with OJ C/2026/1944 and then
national XML, using fixed evaluation time **2026-10-21T06:00:00Z**. E2's retained
`EuropeanBarrierTests` output records the following E1S interpretation results:

| Country | XML authenticated | Interpretable services | Excluded | Interpretation |
|---|---|---:|---:|---|
| IT | yes | 434 | 128 | partial |
| AT | yes | 86 | 14 | partial |
| DE | yes, including fixed-profile RSA-PSS | 971 | 8 | partial |
| BE | yes | 139 | 1 | partial |
| FR | yes | 322 | 40 | partial |
| ES | yes | 438 | 1 | partial |

These are **reused E2 observations**, not fresh E3 authentication or QES counts.
Usable services still require a matching certificate identity, appropriate type,
status, date and evidence. Exclusions include TakenOverBy (IT/DE), incoherent
chronologies (IT/AT/DE/BE/FR), unsupported qualification semantics (IT/FR), and an
unsupported historical identity (ES). The ES limitation includes the previously
reported oversized historical SKI representation. No exclusion was removed to
increase counts. Authentication, interpretation and individual-signature
qualification are separate, consistent with TS 119 615 §4.1–4.5.

E2's synthetic `EuropeanCatalogTests` passed all eight cases. For IT/AT/DE/BE/FR/ES,
the **same synthetic direct-CA/QC certificate identities and signed content** are
used with separately signed national territory variants. This verifies the
country-independent engine/profile gate, not six independently issued national
QES signatures. BG remains indeterminate. Matching duplicated identities across
IT/AT remains ambiguous instead of preferring a country/name. These fixtures use
explicit **test-only** LOTL signing pins; they never establish production OJ trust.

## Bounded comparison with DSS 6.5

Reference: official tag **6.5**, commit
`eb5e8598522c03a738cf7722082aa2d1de6da7ee`. Source URLs and recorded digests are
included in the comparison plan. This fixes the reference; no assertion about
being the latest version is needed. The earlier source audit is reused below.
**DSS execution policy, active trust source and evaluation clock: not configured;
no execution occurred.** Documentation/source findings cannot establish equivalent
verdicts, nor a concrete differing verdict on the corpus.

| Topic | Signum evidence through E2 | Reused DSS source/document finding | Comparison limit |
|---|---|---|---|
| LOTL/TL authentication | OJ/pivots, national pins, reference binding and RSA-PSS tests passed | TL job, parsing, validation and synchronization are separate; explicit signature/expiry strategy exists | No DSS authentication of these bytes; record effective flags, never rely on strategy defaults |
| Service identity/history | Same-service DER/SKI/SubjectName resolver; own half-open timeline; unresolved/ambiguous excluded | TrustServiceConverter retains status intervals and event extensions | Converter evidence alone does not prove equal historical identity matching |
| Criteria | E1S recursive all/atLeastOne/none, KU/PolicySet, DN OIDs/EKU; unknown is unsupported, not false | CriteriaListConverter includes DN/EKU and QCStatement conditions | DSS documents a broader criterion repertoire; no existing QCStatement-criterion fixture comparison or normative defect established |
| QC versus QSCD | QC status, eSig type and device evidence are distinct; actual certificate facts are required | ServiceQualification/QSCDByTL/consistency checks distinguish qualifiers and regimes | No equality of final classification inferred from shared vocabulary |
| BE legacy AsInCert | Recognized as certificate-dependent SSCD evidence in its regime | Legacy qualifier and regime strategies are represented | Pre-2016 full Signum signature classification remains unsupported |
| FR NoSSCD | Explicit negative device evidence, distinct from non-QC | Legacy negative device qualifier represented | Actual historical FR signature verdict not compared |
| ES otherCriteriaList | Subject DN OID presence tested structurally; status is checked independently | DN condition and criteria conversion represented | No real ES signer selected by this criterion was validated against DSS |
| Historical transitions | E2 evaluates each event's own criteria and accepts equivalent effective profiles | DSS retains event properties and has regime/consistency logic | Signum requires stable granted identity/profile throughout issuance→proof; no claim that DSS uses this same restrictive rule |
| Missing evidence | No proven time, unknown trust, conflicting qualifiers or insufficient revocation prevent QES; offline may succeed with sufficient evidence | DSS has independent qualification/consistency and validation-policy processing | No mapping of Signum states to DSS indication/subindication without actual reports |

**Confirmed differences in scope/policy:** Signum deliberately restricts positive
classification to six tested territories, direct CA/QC issuance, the post-2016
profile and complete bounded temporal evidence. It excludes some service histories
and criterion kinds represented in DSS's broader source model. Its requirement
for unchanged effective qualification over the full issuance-to-proof interval,
and for revocation evidence covering proof through observation, is a conservative
supported-profile restriction, not a demonstrated ETSI requirement for every
signature profile. It can leave signatures indeterminate that a broader validator
might assess; that last possibility remains an **inference**, not an observed DSS
verdict. Structural expansion belongs to a later milestone, not an E3 patch.

**No confirmed normative implementation defect or executable DSS verdict divergence
was demonstrated. No code change is justified by this investigation.** This does
not certify full conformance or prove that no defect exists.

## Reproducible deferred DSS comparison

`SIGNUM_0.5E3_DSS_COMPARISON_PLAN.json` defines ten comparison groups, exact existing
fixture paths/hashes, fixed observation clocks, trust setup and the corresponding
existing test entry points. It contains **planned**, not executed, DSS results.
No new corpus is generated. E1R/E1S/E2 and Qualification corpora retain separate
clocks/anchors; their files must not be mixed arbitrarily.

In E4, only after an explicitly available DSS environment/adapter exists:

1. Pin DSS version/commit and runtime; hash the **actual** validation policy and
   cryptographic constraints. Record time, timezone, TL authentication/expiry flags,
   OJ anchor fingerprints, pivot sequence, all TL digests and revocation sources.
2. For official XML use the frozen OJ/LOTL inputs; for synthetic cases configure
   isolated test trust and label it synthetic. Importing a CA directly into DSS
   would bypass TL authentication, so it cannot prove full LOTL/TL equivalence.
3. Keep network disabled; use only existing embedded/detached fixture evidence.
   Preserve each SignerInfo/PDF ByteRange association. Record certificate issuance,
   declared signingTime, proven timestamp interval and observation time separately.
4. Capture DSS DiagnosticData, DetailedReport and SimpleReport (including per-signer
   indication/subindication, qualification and reasons) plus Signum's five results.
   Compare authentication/interpretation independently from full signature results.
5. Compare verdicts only with the same inputs, anchors, clocks and explicit policy
   constraints. A policy that cannot model Signum's restricted profile is a
   documented policy difference, not an equal-policy discrepancy. Do not rewrite
   signed XML to accommodate either validator. The current-good-after-proof case
   is an existing in-memory policy test, not a forged authenticated OCSP response.

No runnable DSS adapter is supplied or claimed ready: implementing/configuring it
would exceed E3's no-complex-environment rule. No command presented here runs E4.

## E4 final validation matrix — planned, not executed

| Gate | Reuse / scope | Required evidence |
|---|---|---|
| Complete regression | Official runner: Core, Trust, PAdES, PKCS#11; sanitizer only when justified by E4 changes | One final campaign and exact failures/skips; E2's pass is not an E4 pass |
| European end-to-end | Existing six-country XML plus E1R/E1S/E2/Qualification fixtures through the integrated app/backend | Provenance, per-country freshness/exclusions and five independent per-signer results; positive/negative/offline cases |
| DSS executable comparison | Ten plan groups; no personal documents or remote demo | Pinned environment, effective policy/trust/clock, raw reports; otherwise explicitly unexecuted |
| macOS / autonomous packaging | arm64, target 13.0, dependency closure, rpath, ad hoc signature, moved bundle | No runtime Java/Homebrew requirement; actual host version recorded; macOS 13 execution only if performed |
| Build 6 local acceptance | Isolated bundle ID/cache/preferences, launch, selective update and offline read, existing verification flow | No overwrite of prior builds; signer-specific results and comprehensible unavailable/indeterminate states |

No E4 gate is marked passed by this document. No Build 6 was generated.

## References

- [E2 report](SIGNUM_0.5E2_EUROPEAN_CATALOG.md) and
  [recorded results](../SIGNUM_0.5E2_RESULTS.json); E1R/E1S reports in this directory.
- Earlier static DSS evidence: task workspace
  `outputs/signum-0.5e-trust-investigation/evidence/dss-sources.json` and the
  accompanying `SIGNUM_0.5E_ETSI_INTEROPERABILITY.md`; source findings reused.
- [ETSI TS 119 615 V1.3.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.03.01_60/ts_119615v010301p.pdf),
  §4.1–4.5; no complete implementation claim.
- [ETSI TS 119 612 V2.4.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf),
  §5.5.9.2, §5.6.3, Annex J (as referenced in the existing E1S investigation).
- [Pinned DSS CriteriaListConverter](https://github.com/esig/dss/blob/eb5e8598522c03a738cf7722082aa2d1de6da7ee/dss-tsl-validation/src/main/java/eu/europa/esig/dss/tsl/function/converter/CriteriaListConverter.java)
  and the other pinned official source URLs in the JSON plan.
