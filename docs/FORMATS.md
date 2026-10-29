# Signature formats and profiles

Support is determined by structure, algorithms and coverage, not by the filename.
Unsupported profiles are reported explicitly. Signing support is narrower than
general verification and does not imply standards certification.

## Signing and verification

| Operation | Files / signed content | Creation profile | Verification scope and limits |
| --- | --- | --- | --- |
| CAdES attached | `.p7m`, embedded content | DER CMS SignedData, RSA PKCS#1 v1.5/SHA-256, SigningCertificateV2, optional declared signingTime | Supported CMS signers and nested layers; certificate trust is assessed separately in the app |
| CAdES detached | `.p7s`, separate original | Same signed attributes, without embedded content | Exact original must be explicitly selected; no guessing from sibling files or URLs |
| CAdES co-signature | Supported attached `.p7m` | Add a top-level signer over the same content, preserving prior signatures | Existing supported signatures must verify before addition and before publication |
| CAdES countersignature | Supported attached `.p7m` | Sign an explicitly selected signer's SignatureValue | Bounded recursive counters, RSA/SHA-256 signed-attribute and certificate-binding profile; relationship to parent retained |
| PAdES | `.pdf` | Detached CMS PDF signature, visible or invisible appearance | Supported Adobe.PPKLite / ETSI.CAdES.detached dictionaries and ByteRange signatures reachable from the current AcroForm |
| XAdES Baseline-B | `.xml` | One enveloped XAdES-B-B signature, RSA/SHA-256, exclusive canonicalization, SigningCertificateV2 and signed properties | Same restricted XML profile; embedded certificate is an identity input, not a trust anchor |
| ASiC-S | `.asics`, one nonempty document | One detached XAdES-B-B signature | Payload coverage and required archive layout checked |
| ASiC-E | `.asice`, two-to-four nonempty documents | One detached XAdES-B-B signature plus signed ODF manifest | All supported payloads and exact manifest bytes covered; no unsigned extra files |

CMS/ASN.1 processing follows the supported RFC 5652/SigningCertificateV2 structures;
XAdES and ASiC implement bounded profiles based on ETSI EN 319 132-1 and
EN 319 162-1. These references describe the implementation's profile, not a claim
of complete implementation of every option in those standards.

## Profile details

**CAdES.** Co-/counter-sign editing accepts DER id-data with attached, nonempty
content and unambiguous supported signer identities. It does not edit existing
BER/indefinite-length or detached containers. Counter targets belong to the outer
SignedData and its recursive counters, not an inner encapsulated CMS layer.
Up to 32 signers/counters and four counter levels are inspected. Other supported
CMS verification algorithms do not automatically become available for creation
or counter-signature validation.

**PDF.** Placement controls page, rectangle and appearance orientation; a visible
stamp is not itself the cryptographic signature. Cryptographic validity of an
older revision does not prove current-file coverage. Signum does not certify
DocMDP/FieldMDP compliance, the acceptability of subsequent edits, or PAdES-LT/LTA.
It does not enumerate every signature hidden outside the current AcroForm.

**XML.** UTF-8 XML 1.0 with one application root and one final-child signature;
RSA certificates 2048–8192 bits, SHA-256 and exclusive canonicalization without
comments. The whole document and SignedProperties are referenced. DTD/entities,
external/file references, XPath/XSLT transforms, ambiguous IDs and unsupported
signature/property structures are rejected. XML serialization can normalize
lexical form; it is not the byte-preserving container model of CAdES.

**ASiC.** Flat payload files, required `mimetype`, one `META-INF/signatures.xml`
and, for ASiC-E, `META-INF/manifest.xml`. Creation uses ZIP STORE; verification
accepts the supported STORE/DEFLATE subset. ZIP64, encryption, symlinks, path
traversal, duplicate/ambiguous names and excessive expansion are rejected.
ZIP headers are structurally checked; the signature covers referenced payloads,
not every byte of the ZIP encoding. Nested archives are opaque payloads.

## Resource limits

| Resource | Current bound |
| --- | --- |
| Ordinary signing input / session | 100 MiB per document / 128 MiB in-memory session |
| General output / verification input | 132 MiB, subject to stricter format limits |
| XAdES XML | 8 MiB; depth 64; 100,000 nodes |
| ASiC archive | 24 MiB; 8 MiB per payload, 16 MiB combined |
| ASiC entries / expansion | At most 7 entries; 16 MiB + 128 KiB total expansion; ratio at most 100:1 |
| Verification report | 32 signers; 512 PDF pages; 32 MiB PDF output |

Additional structural bounds apply. A file below a byte limit may still be
unsupported because of its profile, properties or signature relationships.

## Time and unsupported capabilities

The optional declared-time preference applies to **CAdES**. XAdES/ASiC include
claimed SigningTime; PDFs record their signature date. None of these is an
independent timestamp. Verification can evaluate supported existing timestamp
evidence; Signum does not currently request or issue trusted timestamps.

No XAdES-T/LT/LTA, ASiC CAdES, arbitrary multi-signature XML/ASiC, document encryption,
remote-signing service or universal eIDAS/QES qualification is claimed.

[Verification and security](SECURITY.md) · [Implementation reference map](engineering/README.md)
