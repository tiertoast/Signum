# Signum 0.6-A — Current-time eIDAS validation

Baseline: `fad24b1415010b6bd35ee113491b884f0f678dfe` (0.5.0 Beta Build 7).
Branch: `feature/signum-0.6a-current-time-validation`.

## Evaluation contract

`SignatureEvaluationMode` adds explicit `currentTime` and retains `historical`
(the API default, preserving E2 callers). `bestAvailable`, selected by the existing
verification workspace, resolves **per signer** to historical when time is proven,
otherwise current. It does not retry a failing historical qualification as current.
An invalid timestamp prevents a positive current qualification; an absent or
unproven timestamp does not itself prevent one. Timestamp results remain independent.

Current mode evaluates at the fixed `observedAt` observation instant supplied by
the verification session. It does not parse `signingTime` into an evaluation date
or manufacture RFC 3161 evidence. `verificationDate`, `evaluatedAt`, resolved mode,
original declared time and independently proven time remain distinct.

A current positive requires verified signature integrity; a currently valid,
unambiguous direct X.509 path to an authenticated granted CA/QC service; a fresh
national TL; supported QCStatements/qualifiers identifying a qualified signature
certificate and QSCD; contentCommitment key usage; and authenticated good revocation
covering the same path and observation instant. The existing issuance-to-evaluation
service/identity/profile continuity check is retained. Current revocation statements
cannot be reused as historical proof.

The C evidence service retains its current signer revocation path when explicit
current mode is requested, even if an independently verified timestamp exists.
Historical mode keeps the original timestamp interval, TSA authorization and
historical revocation-window guards. Current checks require thisUpdate no later
than the observation instant and nextUpdate strictly later. Revocation verifier
execution may occur later within the same finite session (its existing monotonic
clock is retained); that does not move the qualification date. A newly generated
response whose thisUpdate is after the observation instant conservatively remains
insufficient for that assessment. Expiration during assessment suppresses a positive;
one signer's stale evidence does not suppress another signer's qualification.

Missing revocation, invalid/expired certificates, withdrawn or ambiguous services,
unsupported criteria, contradictory QSCD evidence, absent TL coverage and incomplete
histories remain indeterminate with reasons. Offline mode can succeed with sufficient
authenticated local evidence; connectivity alone never determines qualification.
No automatic advanced-signature classification was added.

## Application

The existing Verifica panel uses `bestAvailable` through both European catalog and
single-list entry points. It displays observation date, current versus historical
evaluation date, qualified-certificate status, signature qualification and QSCD,
retaining the independent integrity, path, revocation and time results. Declared
time is still displayed as declared. No redesign or settings change is introduced.

## Normative references and scope

- [ETSI EN 319 102-1 V1.4.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf),
  clauses 5.2.5–5.2.6, 5.3 and 5.6: basic/current validation and past validation
  with proofs of existence are distinct processes.
- [ETSI TS 119 615 V1.2.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.02.01_60/ts_119615v010201p.pdf),
  clauses 4.4–4.5: QC and QSCD determination use certificate and TL information
  at the pertinent date. A qualified timestamp is not a universal QES prerequisite.

This is Signum's bounded profile, not a claim of complete implementation of either
standard. Existing IT/AT/DE/BE/FR/ES, direct-CA/QC, post-2016 limits remain. TakenOverBy,
managed-on-behalf QSCD, unsupported criteria/identities and inconsistent histories
remain excluded. A current positive does not establish the actual signing date,
historical validity, LTV/LT/LTA, or acceptability of later PDF changes. No DSS
comparison, additional crypto primitive, network endpoint or dependency is introduced.

## Targeted validation

32 targeted tests pass: 7 new current-time tests, 1 new six-country coverage test,
8 existing qualification tests, 8 existing European catalog tests, 7 existing
binding tests and 1 existing European verification-workspace test.

The new CMS test removes only the unsigned signatureTimeStamp attribute from the
existing synthetic multi-signer CMS, rebuilds DER containers and re-verifies actual
integrity with the unchanged native helper. The PDF missing-time case deliberately
removes evidence from extracted records: it is a component test, not a claim of
having created a new untimestamped PDF fixture. Existing full CMS/PDF tests still
verify their original signed bytes. Coverage includes current positives, default
historical indeterminacy without proof, missing/stale/future/revoked evidence,
path binding, expired/uncovered TL, withdrawn services, unsupported criteria,
QSCD absent/attested, declared-time independence, invalid integrity/timestamp,
multi-signer independence, offline sufficiency and retained historical outcomes.

Only focused Swift tests ran. Initial test compilation/setup issues (test protocol
conformance/import and native-library lookup) were corrected; no executed test
failure remains. Tests use the already available native prefix/helper. Native
runtime lookup is supplied by a test-command rpath, without changing packaging.
Successful logs: `outputs/signum-0.6a-targeted-4.log` (31 tests) and
`outputs/signum-0.6a-countries-3.log` (1 additional test), outside the repository.
No full regression, sanitizer, distribution build, packaging, PR, tag or release
was performed. Full campaigns remain deferred to XAdES/ASiC milestone closure.
