# Features

Signum combines document preparation, hardware signing and signature validation
in one native macOS workspace. For exact profiles, see [Formats](FORMATS.md).

## Signing

- **CAdES:** create an attached CMS document or a detached signature; add a
  co-signature to supported attached CMS, or countersign a specifically selected
  existing signature. A countersignature signs that signature value, not the document.
- **PAdES:** sign PDFs invisibly or place a visible appearance in the preview.
  Configure page, position, dimensions, orientation, text and optional PNG/JPEG
  artwork. Appearance and document choices are frozen into the approval.
- **XAdES:** sign supported unsigned XML using the restricted Baseline-B enveloped profile.
- **ASiC:** package one document in ASiC-S or two-to-four documents in ASiC-E,
  signed with the supported detached XAdES profile.
- **Batches:** approve explicit documents and destinations, track results and
  cancel remaining work. Optional session/PIN sharing is restricted to ordinary
  attached CAdES batches; other operations require individual authorization.

Signing uses the selected token's private key through installed PKCS#11 middleware.
Changing a document, certificate, format, appearance or destination invalidates the
pending approval. Original documents are preserved and existing outputs are not overwritten.

## Verification and reports

The verification workspace accepts supported CAdES, PDF, XML and ASiC inputs,
including explicit original-content selection for detached CAdES. It reports
individual signers and supported countersignature relationships. For PDFs it
separates a valid signed historical revision from coverage of the current file.

Certificate-path validation, authenticated OCSP/CRL evidence, supported timestamps
and authenticated European Trusted Lists produce separate trust, revocation,
time and eIDAS assessments. The available evidence determines whether an outcome
is positive, negative or indeterminate; integrity alone does not settle the others.

Export an A4 **PDF** or **plain-text** verification report with per-signer outcomes,
reasons, certificate information and declared/proven dates. Reports are unsigned
and are not a legal opinion, timestamp, PDF/A or archival-validation certificate.

## Devices and native workflows

- Device, token and certificate discovery; certificate purpose and selection information.
- Automatic route selection where supported, plus explicit manual PKCS#11 module configuration.
- Public device-security information; real PIN administration and PUK recovery remain disabled.
- Native document workspace with PDF preview, signing inspector and per-document removal.
- Finder document opening and separate signing/verification macOS Services.
- Cumulative verification queue, native window ownership and application preferences.
- Optional default-application registration for supported document types.

The GUI and some command output currently use Italian labels. English repository
documentation does not imply an English-localized binary. Keyboard/accessibility
and manual compatibility checks remain part of Beta refinement.

See [Using Signum](USAGE.md) for workflows and [Security](SECURITY.md) for boundaries.
