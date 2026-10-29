# Signum 0.6-E — Verification reports

Baseline `d399771cecd58addbc99fe7c0e0c572fa6342a06`;
branch `feature/signum-0.6e-verification-reports`.
Scope: presentation/export of completed or explicitly incomplete verification results.
No signing, trust, revocation, timestamp or qualification rule is changed.

## Architecture and integration

`SignumVerificationReports` depends on the existing Core and CertificateValidation
modules, using only system Foundation/CoreGraphics/CoreText/PDFKit. It adds no package,
font, command-line tool or runtime installation requirement. The GUI adds a per-document
**Esporta rapporto → PDF / Testo (.txt)** menu without changing the verification layout.
Rendering and secure writing run off the main actor.

`VerificationReportDocument` snapshots allowlisted presentation fields from the typed
VerificationReport and CompleteSignatureValidationResult values already belonging to
the workspace row. It does not call the verifiers, parse source documents, reinterpret
qualification or infer trust from names/certificate flags. Unknown/duplicate signature
IDs, inconsistent child result IDs and mismatched observation dates are refused.
The caller owns the association to the report; the workspace's existing request guard
retains that association. The exporter is not a cryptographic attestation of its input.

The existing assessment clock is unchanged. Its observation date is now retained on
the workspace row for later export, rather than substituting the current export time.
Export date, verification date, declared signingTime, path/eIDAS assessment instant,
RFC 3161 token time and independently proven time are separately identified.
Missing assessments are explicitly **Non valutata**, never silently promoted or
fabricated. The five independent outcomes and their engine reasons are always shown.

## Contents and design

PDF and UTF-8 TXT share the same immutable presentation model. Included: document name,
actual format, source SHA-256, detached-content SHA-256 where provided, verification
date, per-signer certificate subject/issuer/fingerprint, algorithms, CMS level/path,
co-signature groups and exact counter-parent SignatureValue hashes, PDF signed revision
and later-change flags, X.509 path/service references, revocation/time evidence metadata,
QC/QSCD outcomes, qualification basis and limitations. Unsupported/invalid documents
can be reported without inventing individual signer results.

The A4 PDF uses native fonts, generous margins, restrained teal/navy accents, a first
page overview with five-outcome signer cards, per-signer detail sections, a shared
technical appendix, scope notes and numbered running headers/footers. Long paragraphs
and unbroken strings paginate; full identities remain in details if abbreviated in a
summary card. ReportLab/Java/Homebrew are not application runtime requirements.
The user-supplied InfoCamere PDF was consulted locally as a structural/style reference;
no logo, personal content or vendor verdict was copied into the synthetic examples.

The presentation handles CAdES attached/detached, co-/counter-signatures, PAdES, XAdES
and ASiC through their existing typed reports. It does not claim broader profile
support than those reports. In particular it does not reopen an ASiC to discover extra
payload metadata or extend the CAdES/XAdES/TL profile during export.

## Privacy and safe publication

No originals, previews, DER certificates, signature octets, raw CMS attributes,
revocation responses or timestamp tokens are retained in the presentation model or
attached to the PDF. No PIN, provider path, private key or cache path is read. Names,
certificate DNs and engine reasons can contain identifying information needed to read
the result; this is stated in the report. Control/bidi characters are visibly escaped
so input strings cannot create misleading TXT rows or override displayed text direction.
Text is drawn directly, without HTML/markup interpretation or automatic links/actions.

Both formats reuse SignumFileOutput staging, readback validation and exclusive atomic
publication. Wrong extensions, occupied files and final symlinks are refused; the
save panel's overwrite confirmation does not bypass the exclusive writer. Rendering
failure never publishes partial output. Limits: 32 signers, 2,000,000 UTF-8 bytes of
projected text, 512 PDF pages and 32 MiB PDF output. Oversized reports fail explicitly,
without truncating engine reasons. Reports are unsigned and unencrypted; they do not
claim legal validity, PDF/A, PDF/UA, LTV, LT/LTA or trusted creation timestamps.

## Targeted validation and visual acceptance

**14 distinct targeted tests have final passing outcomes.** Coverage includes:

- PDF/TXT contents, five independent states/reasons and different verification/export/
  declared/proven dates; positive and indeterminate qualification only as typed.
- Invalid signatures, revoked certificates, missing assessments, current evaluation
  without timestamp, authorized TSA metadata and separate OCSP/CRL update/revocation dates.
- Multiple signers, co-signers, counter-parent binding and per-signer verdict isolation.
- All implemented format dispatch labels, detached hash, unsigned/damaged input and
  unsupported cases without invented signer relationships.
- Direct comparison against an actual offline native engine/qualification invocation
  on the existing synthetic `valid-untrusted.cms` fixture.
- Workspace observation-date retention through later export/cancellation.
- Exclusion of source/DER/token sentinel data; control/bidi escaping; long Unicode
  names/reasons and unbroken text; page/column geometry and resource rejection.
- Exclusive TXT/PDF publication, occupied destination/symlink rejection, extension checks,
  staging cleanup, PDF readability, A4 pages and absence of PDF annotations.

An initial GUI compilation whitespace error and a PDF hash line-wrap issue were
corrected. Only affected tests were repeated; earlier logs remain intact. The final
five-page synthetic example was rendered using Poppler and **all five pages visually
inspected**, including the revised column spacing, technical appendix and footer/page
transitions. No source/policy change followed visual acceptance.

Local evidence and example artifacts are in `outputs/signum-0.6e/`: `results.json`,
`targeted-compile-fix.log`, `layout-and-engine.log`, `final-layout.log`,
`timestamp-evidence.log`, `workspace-date.log`, and
`examples-delivery/Signum-rapporto-esempio.pdf` / `.txt`. These examples demonstrate
synthetic typed results and are not a verification of the user's personal document.

No complete regression, sanitizer, distribution build, app packaging, real token/PIN,
PR, main merge, tag, release, GitHub Action or other repository modification occurred.
The existing Beta and Development Preview remain unchanged. End-to-end interaction
with a newly packaged GUI is deferred; the source integration compiles and its date
retention path is covered by the workspace test. Stop after commit/push and reports.
