# Signum 0.6-B — XAdES Baseline-B enveloped

Baseline: `99525ad98be9a2160ccfb690f563e02920027817` (0.6-A).
Branch: `feature/signum-0.6b-xades-baseline`.
The document-only changes from main `6bab15e` are incorporated verbatim in README,
RELEASE_READINESS and ROADMAP. No 0.6-A implementation or documentation is replaced.

## Declared profile

First **XAdES-B-B enveloped** subset, based on
[ETSI EN 319 132-1 V1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf),
clauses 4.4, 5.2.1, 5.2.2, 5.2.4 and 6.3 (including table 2): direct incorporation,
claimed UTC SigningTime, SigningCertificateV2 and signed DataObjectFormat.
[XMLDSig processing](https://www.w3.org/TR/xmldsig-core1/) and
[exclusive canonicalization](https://www.w3.org/TR/xml-exc-c14n/) remain the
cryptographic reference model. This is a declared subset, not a general XAdES
conformance/interoperability certification.

- XML 1.0, UTF-8 (optional BOM); one application root and exactly one ds:Signature
  as its last element child. An existing XML signature cannot be signed again.
- RSA PKCS#1 v1.5 with SHA-256, RSA certificates 2048–8192 bits, SHA-256 digests;
  exclusive canonicalization without comments for SignedInfo and references.
- Exactly two references: URI="" over the entire document with enveloped-signature
  followed by exclusive c14n, and #SignedProperties with exclusive c14n and the
  mandatory SignedProperties Type URI. No selected-subtree/payload-only signing.
- One directly incorporated QualifyingProperties with Target bound to Signature Id;
  signed SigningTime, SigningCertificateV2 with SHA-256 DER certificate digest,
  and one DataObjectFormat bound to the document reference, MIME application/xml.
- One explicit signer certificate in KeyInfo, cryptographically bound through
  SigningCertificateV2. It identifies the signer, never authorizes its trust.
- Baseline-B always includes claimed SigningTime. The existing optional CMS
  signingTime preference continues to affect CAdES only; the XAdES UI explains this.
- Limits: 8 MiB XML input/output/canonical buffers, depth 64, 100,000 nodes,
  128 attributes per element, 256-character ID values, 4 KiB canonical SignedInfo,
  64 KiB certificate and 1 KiB RSA signature. Serialization overhead counts toward
  the output limit. Declared SigningTime uses a fixed UTC second format, year >=1970.

Other signature algorithms/canonicalizations, optional qualifying properties,
IssuerSerialV2, certificate chains in KeyInfo, detached/enveloping signatures,
multiple XML signatures/countersignatures, XAdES-T/LT/LTA and ASiC are outside this
first profile. No service, policy or archive timestamp is introduced.

## Implementation and boundaries

`CXMLSecurity/xades.c` reuses libxml2 canonicalization/parsing, xmlsec reference
and signature verification, and the existing OpenSSL backend. Native initialization
is shared once, thread-safely, with the existing TL verifier. The latter's schema,
algorithm whitelist, anchor selection and semantic checks remain unchanged.

Preparation canonicalizes the approved XML infoset and SignedProperties, fills
reference digests and returns canonical SignedInfo. The **unchanged** one-shot
PKCS#11 worker signs only these bounded bytes using its existing RSA-SHA256 action,
provider/certificate context, supervision, PIN handling and parent-side key check.
No XML, destination or original-file path is sent to the worker. No private key
enters the parent. A reusable automatic CAdES batch is not enabled for XAdES:
multiple selected XML files use existing per-document approval/authentication.

`SigningJob` validates unsigned XML before authentication. Snapshot identity,
certificate, format, destination and directory identity are frozen in the existing
review. Output is `name-firmato.xml`, with existing collision reservation. Finishing
checks the complete XMLDSig and certificate binding, then the existing exclusive
transactional writer rechecks staged bytes and snapshot identity before publication.
Cancellation and uncertain private-operation outcomes do not trigger retries.
An occupied destination cannot be overwritten.

The existing Verifica service dispatches XML directly to the bounded native verifier,
without requiring the CMS/PDF helper. Successful verification exports the exact
verified certificate, SignatureValue and declared time into the existing typed
report. Cryptographic/reference/certificate-binding failures are invalid; unsafe,
malformed or unsupported structures are not verifiable. No XML extraction or
business-content rendering is performed. XML signing operates on the XML infoset;
serialization may normalize lexical representations, unlike byte-preserving CMS.

The unchanged 0.6-A X.509/revocation/eIDAS service consumes that report. Claimed
SigningTime never becomes proof of existence. Current qualification still needs
all existing path, authenticated TL, QC/QSCD and revocation conditions. No trust is
inferred from embedded KeyInfo. Positive qualification remains bounded to the
existing six-country/direct-CAQC/post-2016 profile; this milestone does not expand it.
The new end-to-end trust test establishes independent integrity and indeterminate
trust/revocation/qualification for an untrusted synthetic signer; it does not claim
an additional positive XML QES interoperability corpus.

## XML security

Parsing rejects DTD/entities before parsing, NULs, non-UTF-8 bytes/declarations,
XML versions other than 1.0, comments, PI, XInclude elements and xml:base. Network
parsing is disabled; NO_XXE is additionally enabled when available. No process-global
entity loader is replaced and no schema URL is fetched.

ID-like attributes are bounded, registered and unique across the complete document;
multiple ID-like attributes on one element and ambiguous namespaced IDs are rejected.
Signature namespace elements cannot be hidden in the application payload. Exact
signature/properties grammar and cardinalities reject wrapping and unsigned objects.
QualifyingProperties Target, SignedProperties reference, certificate digest and
DataObjectFormat binding are checked independently of signature-value verification.
External/file references, xpointer, RetrievalMethod, KeyInfoReference, Manifest,
XPath/XSLT, unexpected transforms or algorithm parameters are rejected before
xmlsec execution. Reference URI and transform whitelists also restrict the backend.
Unsupported input never falls back to a weaker verifier.

## Focused validation

**11 targeted tests pass**: 9 XAdES core tests and 2 trust-integration tests.
A subsequent focused rerun of the generation/report test covers the added UTF-8
BOM/leading-whitespace detection and early verification cancellation. No full suite,
general regression, sanitizer, application package or Beta was produced.

Coverage: generation and native verification; XMLDSig interoperability in both
directions; changed payload, SignedProperties, certificate/digests; wrapping,
duplicate IDs/signatures and uncovered objects; external/file/xpointer references;
XPath/XSLT and algorithm parameters; DTD/XXE, encoding/version, malformed XML,
depth/size bounds; existing worker with synthetic software token; immutable source
snapshot; invalid signatures/cancellation without output; review/format freeze and
pre-authentication rejection; concurrent TL and document verification; independent
integrity, declared time and untrusted-certificate outcomes.

Independent XMLDSig tool: existing **xmlsec1 1.3.12 (OpenSSL)** from the native prefix.
No DSS comparison. The generated self-signed certificate is explicitly supplied as
trusted to this fixture-only CLI invocation. Reverse generation uses the explicitly
loaded private RSA key (`--enabled-key-data rsa --lax-key-search`), not embedded X509
key selection. This is a test key-selection configuration, not a Signum trust rule.
Initial failures were corrected: native-header export/enum compilation, CLI runtime
library lookup, and CLI certificate/private-key selection. No test failure remains.

Successful logs outside the repository: `outputs/signum-0.6b-final.log` (11 tests),
`outputs/signum-0.6b-bom-cancellation.log` (one focused post-change test).
Tests require the existing native prefix, software fixture OpenSSL, and xmlsec1
(selected by SIGNUM_TEST_XMLSEC or PATH); these are development test prerequisites,
not new runtime requirements. Native PKCS#11 hardware and a packaged GUI launch
were not tested. Consolidated regression and packaging remain deferred to 0.6-C.
