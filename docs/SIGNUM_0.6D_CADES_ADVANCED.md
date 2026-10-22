# Signum 0.6-D — Advanced CAdES

Baseline `f90c314127d2c3e8b7d8724ca0692a148f6b753f`; branch
`feature/signum-0.6d-cades-advanced`. No distribution build, change to the accepted
Preview, PR, merge, tag, release, dependency installation or GitHub Action.

## Implemented operations

**Detached `.p7s`:** the existing CAdES builder emits the same signed attributes
and SignerInfo with omitted eContent. Verification requires explicitly selected
external bytes, supplied to OpenSSL's existing per-signer CMS verification path.
The parent/native protocol has a separate bounded detached input frame. It rejects
an attached CMS rather than letting external input override embedded content.
Missing content is not verifiable, incorrect content is invalid, and unverified
content is never offered as an authenticated original. The report identifies the
external content SHA-256; no URL or sibling file is loaded automatically.

**Co-sign:** adds one top-level SignerInfo to an attached SignedData. All existing
SignerInfos (including unsigned attributes), eContentInfo bytes, CRLs, certificate
identities and signatures are retained. Only unsigned enclosing SETs/containers,
certificate/digest sets and the new SignerInfo are assembled. This signs the common
payload, not a new wrapper around the existing CMS. Every prior supported signature
must verify before invoking the worker, and all signatures verify before publication.

**Counter-sign:** an explicit, unique SHA-256 SignatureValue identity chooses an
outer SignedData signer or one of its recursive counter-signers. Signed attributes
contain messageDigest over the **contents octets** of that selected SignatureValue,
SigningCertificateV2 and optional declared signingTime; they omit content-type.
The new SignerInfo is placed in the selected signer's unsigned counterSignature
attribute, OID `1.2.840.113549.1.9.6`. Existing signed fields and existing counter
values remain byte-identical. This does not create another co-signer of the content.
Signer selection never relies on subject, country, display name or list order.

`CAdESAdvanced` provides the bounded DER editor and prepared operation. It reuses
`CAdES.Prepared`, the existing RSA-SHA256 worker action, parent-side key check and
SigningOperation transitions, immutable snapshots, explicit batch approval,
exclusive destination planning and staged atomic publication. The shared one-shot
execution harness also retains XAdES/ASiC behavior. Automatic/reusable CAdES batch
authentication remains restricted to the original attached operation; advanced
operations use per-document authorization without protocol changes or PIN retention.

## Verification and trust boundaries

The existing isolated native inspector recognizes all supported co-signers and
recursive counter-signers and returns individual certificate, signature, attributes,
evidence, signer path and parent SignatureValue identity. A synthetic internal CMS
view is used only to reuse metadata/evidence extraction: it is never published or
used to alter original signed bytes. Counter verification independently checks
RSA/SHA-256, signed-attribute uniqueness and bounds, forbidden content-type,
messageDigest over the exact parent value, ESS certificate binding and the RSA
signature using OpenSSL. Counter timestamps/revocation values retain their own
SignatureValue association, never the parent's by default.

A counter with an unverified parent does not receive a positive integrity/qualification
assessment. Recognized counter structures outside the declared algorithm/ESS profile
remain not verifiable. Ambiguous signer certificate identifiers are rejected rather
than selecting an arbitrary certificate from the bag. Embedded certificates remain
untrusted inputs to the existing X.509/eIDAS engine. Independent integrity, path,
revocation, time and qualification are retained; signingTime is never a timestamp.
No new trust or qualification policy is introduced.

The legacy system-OpenSSL `verify-cades`/CAdESVerifier path now explicitly refuses
CMS with counterSignature attributes, because its command verifies top-level signers
only. It directs callers to the unified verification panel/service rather than
reporting a partial success as complete. Attached/co-signed CMS without counters
and the existing outer-layer signing check retain their original behavior.

## GUI

The current format menu adds detached CAdES, co-sign and counter-sign operations.
Counter-sign requires an explicit selection in the current-document panel; the
selection invalidates the pending review and is frozen into the approved job and
its description. A missing/stale target prevents approval. Destinations use `.p7s`,
`-cofirmato.p7m` and `-controfirmato.p7m` with the existing collision/exclusive rules.
Verification adds “Verifica .p7s e originale…” with two explicit file selections.
Counter reasons and parent/signer-path details distinguish them from co-signers.
No redesign, physical token or private credential is needed for verification.

## Profile and resource limits

- DER SignedData with id-data; creation remains issuer-and-serial, RSA PKCS#1 v1.5,
  SHA-256, SigningCertificateV2 and the existing signingTime preference.
- Co-/counter-signing requires attached nonempty content, supported original
  signatures and unambiguous identities. No editing of BER/indefinite-length CMS,
  detached existing containers or inner nested SignedData objects. Existing nested
  CMS verification is retained; target selection applies to the outer SignedData
  and its recursive counters, not to encapsulated CMS layers.
- Counter verification initially supports RSA 2048–8192/SHA-256 with signed attributes
  and SigningCertificateV2. Other RFC 5652 optional counter forms, EC/PSS counters or
  legacy SigningCertificate are reported outside this profile, not accepted silently.
- At most 32 signers/counters per inspected CMS, 4 counter levels, 64 certificates
  of at most 64 KiB, 64 attributes per signer, 1 MiB per counter SignerInfo/attribute,
  SignatureValue at most 16 KiB for inspection; generated worker signatures retain
  their original RSA size limits. Duplicate target signature identities are excluded.
  Full-count and maximum-depth additions are rejected before private authentication.
- Existing source cap 100 MiB and output/verification cap 132 MiB remain. Detached
  verification accepts two individually bounded inputs, with an exact size-prefixed
  frame of at most 264 MiB + 8 bytes; the existing 1 GiB native RSS supervision,
  timeouts, CPU bounds, cancellation and 8 MiB metadata output limit apply.
- These are CAdES/CMS operations, not ASiC CAdES support. No ASiCManifest/SigReference,
  new timestamp, encryption, XAdES extension or broader eIDAS country profile is added.

## Focused validation

**75 distinct focused tests have final passing outcomes**, including **16 new tests**
(15 advanced CAdES and one individual trust integration). Initial setup failures were
corrected and only affected cases rerun; no full campaign or sanitizer ran.

Coverage: detached binary association, absent/wrong/unsafe original, attached-content
substitution, co-sign byte preservation including unknown unsigned attributes,
multiple signers, nested counters, target selection/freeze, moved and altered counters,
parent-content failure, forbidden counter content-type, ambiguous certificate SID,
DER/count/depth limits before worker use, cancellation, invalid worker result,
occupied output and immutable snapshot after original modification. Synthetic worker
signing/publication passes for all three operations; no real device or PIN is used.
The trust integration retains individual indeterminate path/revocation/time/QES for
untrusted synthetic certificates. Existing targeted coverage passed: CAdES 6,
memory contracts 4, attached/OpenSSL integration 1, unified CMS/PDF verification 15,
XAdES 9, ASiC 14, current-time qualification 7 and XAdES/ASiC/trust integration 4
(the last group includes the new advanced CMS trust case).

Local evidence outside the repo: `outputs/signum-0.6d/results.json`, native build log,
`targeted-compile-fix.log`, `corrected-targets.log`, `preflight-limits.log`, and
`legacy-and-identity.log`. Earlier failed logs are retained, not overwritten.
`public-interop/` contains only synthetic original/signed files and checksums;
private fixture keys remain temporary and are removed by test cleanup.

## Independent interoperability and observed divergence

- Generated detached/co-signed CMS verifies with macOS LibreSSL 3.3.6 CLI using
  binary content and disabled chain trust (`-noverify`), independently of Signum's
  native CMS parser. OpenSSL 3 co-sign generation is accepted by Signum.
- Counter RSA signatures and parent-value SHA-256 are checked independently with
  the OpenSSL `dgst` CLI. This is not a claim that `cms -verify` validates the complete
  counter graph; the counter-specific structural/binding tests do that in Signum.
- A bounded reproduction shows LibreSSL 3.3.6 `cms -resign` omitting the mandatory
  content-type attribute in the newly added top-level SignerInfo, while its CLI
  returns success. The corresponding OpenSSL 3 output includes content-type and
  verifies. Signum retains OpenSSL 3's rejection of the incomplete form; no checks
  are relaxed to match the legacy tool. Test fixture generation uses OpenSSL 3 for
  that reverse co-sign case. This does not affect Signum's generated co-signatures.
- InfoCamere Sign Desktop is installed. Native app control was attempted and timed
  out (`timeoutReached`); no InfoCamere result is claimed and no personal document
  was opened or sent. Application-level comparison remains a manual check for E.

References: [RFC 5652 §§5, 11.1–11.4](https://www.rfc-editor.org/rfc/rfc5652.html),
[RFC 5035](https://www.rfc-editor.org/rfc/rfc5035.html),
[OpenSSL CMS verification](https://docs.openssl.org/3.5/man3/CMS_verify/), and
[OpenSSL CMS command](https://docs.openssl.org/3.5/man1/openssl-cms/).
Full regression, general sanitizers, packaged GUI/hardware acceptance and a new
Development Preview remain deferred to 0.6-E. No overall conformance, DSS equivalence,
LTV or LT/LTA result is claimed.
