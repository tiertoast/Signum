# Signum 0.6 — Final polish / Development Preview Build 3

Baseline `2aa4110b3eede2d743659dd26d33f1930bd51eac`; existing 0.6-E branch.

## Identity boundary

The existing CertificateIdentityReader is reused, not duplicated. Presentation
reads only SignatureVerificationResult.signerDER, with its certificate fingerprint
matching; no arbitrary embedded certificate, DN display string, signer order or
country is used as proof of identity/trust. All supported formats share this result.
Personal name uses unambiguous Subject givenName + surname. CN-only/incomplete
personal names are unavailable; the original Subject remains in details.
Structured personal Italian CF: serialNumber TINIT-, exact Italian bare CF, or the
existing personal CNS CF/DEVICE-ID CN profile when serialNumber is absent. Supports
omocodia; no arbitrary substring scan. VAT/NTR/company IDs excluded. Duplicate
conflicting Subject attributes become unavailable. CF extraction is not a registry
or checksum attestation; all existing crypto/path/revocation/time/eIDAS gates remain.

The summary and details of the existing GUI show name, CF and individual integrity;
PDF/TXT share the same bound identity and independent five outcomes. A4, Burgundy
reports, native UI styling and bounded exclusive output retained. Large signer
sets continue across summary pages; identities/outcomes are never merged together.

## Focused validation

26 focused tests pass (8 certificate identity, 18 reports), including Italian,
foreign, corporate, missing/ambiguous fields, omocodia, malformed DER, mismatched
certificate fingerprints, distinct signer/counter identities and outcomes across
CAdES/PAdES/XML/ASiC reports, first-page PDF and TXT summary, safe writes and layout.
An initial local-variable naming compilation collision was corrected before tests.
The five-page updated synthetic PDF was rendered and every page visually inspected.

Build 3 identity: `io.github.tiertoast.Signum.DevelopmentPreview.V06.B3`, version
0.6.0, build 3; existing Build 1/2 and release 0.5 identity recipes preserved.
Only packaging metadata and identity presentation/extraction change in this task;
no new signature profile, dependency, eIDAS policy or signing/worker operation.

Full regression, exact source commit and packaging evidence are recorded in the
subsequent delivery section. Notes/checklist: SIGNUM_0.6_RELEASE_NOTES.md.
No merge/tag/release/branch deletion is authorized before manual acceptance.
