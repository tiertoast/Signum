# CAdES declared time and unassessed QSCD — focused correction

Baseline Build 6 `08100d8038635b5fa2a87642b4719c7beaa74970`.
A user-supplied multi-signer CMS was examined locally. No document, extracted
content, real signer identifiers or private-document fixture is committed here;
the detailed local report is outside this repository.

## Reproduced findings and changes

The Signum CMS builder emitted contentType, messageDigest and signingCertificateV2
but no signingTime. `CAdES.Prepared` now records a local declared time at preparation
(default system clock, explicitly injectable for tests) as another signed attribute.
The immutable attributes remain DER-sorted; messageDigest, ESSCertIDv2 and the signed
payload are unchanged. RFC 5652 §11.3 Time encoding uses UTC seconds, UTCTime for
1950–2049 and GeneralizedTime otherwise. Non-finite or unsupported dates fail before
signing. This attribute is an unauthenticated clock claim protected by the signature,
not an RFC3161 proof, and does not modify existing documents retroactively.

The qualification helper previously defaulted QSCD to notDemonstrated even when a
prior missing-time guard prevented its evaluation. The default is now indeterminate;
explicit negative/unqualified outcomes retain notDemonstrated, while positive results
still require the unchanged policy. The early time explanation distinguishes actual
QcCompliance/QcSSCD certificate indications from an uncompleted signature assessment.
Only the corresponding three-state GUI message changes; no layout redesign.

The original Build 6 authenticated revocation for both real signers in an explicitly
authorized, isolated online diagnostic. The original reported online failure did not
reproduce; no surviving HTTP/DNS/response trace establishes its historical cause.
No revocation primitive, endpoint restriction, responder rule, freshness window,
cache authorization or signer-evidence binding was modified.

## Policy boundary

The existing E2 profile requires supported bound timestamp/revocation evidence for
a positive signature qualification. This is a restricted supported profile, **not**
a general eIDAS requirement that every QES carry a qualified timestamp (see eIDAS
Article 3(12)). A certificate's QC/QSCD indications do not alone establish a QES.
Removing the time guard or trusting signingTime would be unsafe and is not done.
Current-time qualification needs an explicit assessment basis separate from historical
proof and declared time; that broader change is deferred, not silently approximated.
Integrity, path, revocation, time and qualification remain independent.

## Focused validation

One post-change test session passed **38 tests**: CAdESTests (5),
CAdESVerificationIntegrationTests (1), EvidenceBindingTests (7),
QualificationTests (8), RevocationEvidenceTests (12), TimestampEvidenceTests (5).
Coverage: UTC/GeneralizedTime boundaries and invalid dates; new synthetic Signum CMS
independently verified by OpenSSL and read by the native helper; separate signer
revocation without timestamps; good/revoked/unknown/stale/tampered OCSP/CRL,
unauthorized responders, offline/cache behavior, unassessed QSCD and no undue QES.
Existing public/synthetic fixtures and ephemeral test-only software keys are reused;
no real PIN/private key is accessed. No live document query is part of the tests.
No full campaign, new app build, packaging or DSS run was performed.

References: [RFC 5652 §11.3](https://www.rfc-editor.org/rfc/rfc5652#section-11.3),
[RFC 5035](https://www.rfc-editor.org/rfc/rfc5035),
[eIDAS Article 3](https://eur-lex.europa.eu/eli/reg/2014/910/oj), and the existing
E2/E3 policy reports. No new external standards fetch was performed: network
permission was restricted to the explicitly authorized certificate OCSP/CRL hosts.
