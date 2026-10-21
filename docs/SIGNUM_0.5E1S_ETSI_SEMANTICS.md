# Signum 0.5-E1S — ETSI criteria and historical qualifications

Baseline `bd7f14260c4581162759c3cedcbe3a51d62d3ad9`; same European trust branch.
Scope: Swift interpretation and consumers; no GUI, signing, PKCS#11, C verifier,
dependencies or bundle changes. AuthenticatedTLDocument / InterpretedTrustCatalog
and E1R RSA-PSS remain the authentication boundary. Interpretation policy is
`Signum-TL-Interpretation-E1S-v1`; raw caches are reinterpreted on load.

## Changes

- `TLQualificationRules` recognizes SSCD legacy URIs (With/No/StatusAsInCert)
  and QCForLegalPerson while retaining original URIs. Syntax validation no longer
  supplies artificial certificate facts. Conflicting applicable qualifiers fail
  closed; QCForLegalPerson cannot promote an electronic-signature QES result.
- General OID filters: Subject DN attribute presence and explicit certificate EKU,
  inside the ETSI additional-types namespace in otherCriteriaList; recursive
  all/atLeastOne/none, KU and PolicySet retained. Unknown nodes, invalid OIDs,
  unavailable facts and conflicting qualifiers remain unsupported/ambiguous,
  distinct from a definite nonmatch. Every branch is inspected.
- Existing strict DER ingestion supplies actual subject attribute OIDs, EKU and
  SKI; certificate signatures/path validation remain in the unchanged B primitive.
- SSCD and QSCD device evidence uses the 2016-06-30T22:00:00Z regime boundary.
  AsInCert requires certificate evidence; No is not missing information. Wrong
  regime or conflicting statements do not produce positive device evidence.
- The raw parser preserves historical SubjectName/SKI. The normalized timeline
  verifies descending signed order, unique dates and issue-time consistency before
  deriving half-open event intervals. Each event retains its own identity/state/
  criteria/extensions and remains associated with the authenticated source catalog.
- A historical SKI can resolve to a full certificate already authenticated in
  the **same service**, with matching SubjectName when supplied and a unique
  key/subject group. No DER is required inside that event. A document's arbitrary
  certificate or a display name alone cannot supply an anchor. Ambiguous/unresolved
  identities produce no usable anchor for that evaluation.
- B, TSA and D share the timeline and identity resolver. D checks issuance and
  proof against their own events; transitions require the same anchor, granted
  CA/QC state and identical applicable qualifier sets across the covered interval.
  Different/insufficient histories remain indeterminate. No current qualifier is
  copied to the past. A bad timeline excludes that service, retaining siblings.

## Validation policy and limits

The full synthetic E1R corpus is reused. Only four newly signed synthetic TL
variants and a disposable test-only TL signer are added; no private key is kept.
They exercise SKI/SubjectName history without DER, negative historic qualifiers,
unresolved SKI and duplicate historical dates. Existing CMS/PDF, evidence and
certificate fixtures are not regenerated. Official six-country XML remains frozen.

One targeted phase precedes one official complete campaign. `--skip-sanitizers`
is an explicit runner option, recorded in its setup, with a contract test proving
that it preserves all regular complete gates. No native/cryptographic primitive
changes require rerunning the E1R sanitizer campaign. Final counts and any failures
are recorded below and in `SIGNUM_0.5E1S_RESULTS.json`.

Limitations: TakenOverBy and unknown critical extensions remain excluded; there is
no archived-TL search for historical keys absent from the authenticated service's
DER pool. DN correspondence is conservative (supported X.500 aliases/numeric OIDs,
escaping, quoted values and multi-valued RDNs), not a general X.500 matching engine;
unrecognized representations fail closed. DER aliases with differing identity
encodings may remain ambiguous. Full pre-2016 signature classification, managed-
on-behalf QSCD and legacy-policy-only certificate qualification remain unsupported.
D retains its existing Italy/online/proven-time/revocation sufficiency gates;
interpretable service counts are not counts of authorized anchors or QES signatures.
No positive country classification is inferred from a successful XML signature.
Bounded raw SKI values are preserved even if outside the interpreter's supported
1–128 byte profile; only the affected service is excluded. In the frozen ES file
two historical SKI entries carry 294-byte values. Frozen AT has 14 current status
dates later than the TL issue time; these were already barred from B's anchors
in E1R, and are now excluded visibly at the interpretation boundary.
No Build 6 or E2/E3/E4 work is included; no macOS 13 runtime claim is made.

## Normative references

[TS 119 612 V2.4.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf),
§5.5.9.2.2–.3, §5.6.3 and Annex J: criteria, qualifiers, historic identity and migration.
[TS 119 615 V1.3.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.03.01_60/ts_119615v010301p.pdf),
§4.3.4 (including order/duplicate checks), §4.4 and §4.5.4: certificate association,
qualification and regime-dependent device evidence. This implementation does not
claim complete implementation of every procedure or historical signature profile.

## Targeted phase findings

The initial targeted invocation compiled and ran all three relevant targets.
It exposed (1) an overly strong monotonic-count assertion that failed on the
newly visible AT future-date exclusions, (2) a raw SKI bound rejecting the entire
ES document rather than isolating unsupported identity semantics, and (3) new
synthetic TL variants whose issue time preceded their newly created current
state. Corrections preserve the raw resource bound, exclude unsupported identities
locally, justify count decreases by explicit new exclusion reasons, and fix only
the new fixture issue dates. Existing E1R fixtures are unchanged. Diagnostic
parser probes used copies outside the repository; none bypasses authentication.
The final campaign follows these corrections; no second full campaign is planned.

## Final results

One official complete campaign passed: 547 Swift tests (Core 430, TrustCore 19,
Authentication 34, Integration 5, CertificateValidation 59), native PAdES 81 cases
each Debug/Release, PKCS#11 58 provider cases plus 2 loader contracts, and 18
packaging/runner contracts. No sanitizer campaign was repeated.

The complete run exposed residual coverage of the standard OIDAsURN representation
in PolicySet. A subsequent small OID-decoder correction requires its urn:oid:
prefix and still rejects malformed/unknown qualifier encodings. Only the relevant
CertificateValidation target and the six-country official authentication test were
rerun: 60/60 passed, including the added positive/negative OID assertions and all
existing B/C/D, TSA, per-signature and E1R barrier cases in that target. There was
no second full campaign. No unresolved test failure remains.

| Country | E1R usable/excluded | E1S final usable/excluded |
| --- | ---: | ---: |
| IT | 412/150 | 434/128 |
| AT | 100/0 | 86/14 |
| DE | 683/296 | 971/8 |
| BE | 92/48 | 139/1 |
| FR | 260/102 | 322/40 |
| ES | 337/102 | 438/1 |

All six XML signatures completed verification, including German RSA-PSS. No whole
catalog is blocked. Final exclusions: 126 critical TakenOverBy, 62 inconsistent
timelines, one unsupported SKI representation service, three remaining unsupported
or ambiguous qualification profiles. A service with multiple issues is counted
once, under its first exclusion reason; removing an earlier semantic exclusion
can expose a later TakenOverBy reason. Counts describe interpretation, not positive
trust, qualified service status at every time, or signature qualification.

Commands: the targeted phase used `Tools/TrustPoC/native.sh test --jobs 4` with
filter `(SignumCertificateValidationTests|SignumTrustAuthenticationTests|SignumTrustCoreTests)\.`;
the final campaign used `python3 scripts/test-local.py --group complete --skip-sanitizers`
with the existing native prefixes, CMake/CTest and Poppler. The post-correction
filter was `(SignumCertificateValidationTests\.|EuropeanBarrierTests/)`. Logs and
runner metadata are retained in `outputs/signum-0.5e1s`; machine-readable counts
and initial failures are in `SIGNUM_0.5E1S_RESULTS.json`.
