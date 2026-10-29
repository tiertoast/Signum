# Signum 0.6-C — ASiC-S / ASiC-E with detached XAdES-B

Baseline: `75f318ff56299ed1ca006dec331bdfb1349dac49` (0.6-B).
Branch: `feature/signum-0.6c-asic`.

## Supported profiles

Native creation and verification of bounded ASiC-S and ASiC-E with **one detached
XAdES-B-B signature**. Reference:
[ETSI EN 319 162-1 V1.1.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf),
clauses 4.3.3, 4.4.3, 5.3, A.1, A.5 and A.6; the XAdES subset remains based on
[ETSI EN 319 132-1 V1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf).
This implements declared profiles, not universal ASiC/ETSI conformance certification.

| Profile | Signed content | Required archive entries |
| --- | --- | --- |
| ASiC-S, `.asics` | Exactly one nonempty document | `mimetype`, payload, `META-INF/signatures.xml` |
| ASiC-E, `.asice` | Two to four nonempty documents and the ODF manifest | `mimetype`, payloads, `META-INF/manifest.xml`, `META-INF/signatures.xml` |

`mimetype` is first, stored uncompressed with no extra header fields, and contains
exactly application/vnd.etsi.asic-s+zip or application/vnd.etsi.asic-e+zip. Signature
XML has an `asic:XAdESSignatures` root in `http://uri.etsi.org/02918/v1.2.1#` and one
Signature child. Every payload is directly referenced by canonical percent-encoded
relative URI from the **container root**, not from META-INF. Payload references
hash the exact original bytes, including XML payloads; no transformations apply.

The shared 0.6-B SignedProperties grammar, SigningCertificateV2 binding, declared UTC
SigningTime, RSA PKCS#1 v1.5 SHA-256 and exclusive canonicalization remain. Each
payload has a signed DataObjectFormat with MIME application/octet-stream; the
manifest uses application/xml. SignedInfo is limited to 4 KiB by the existing worker.

ASiC-E includes an ODF 1.2 manifest identifying the root media type and every
payload. Metadata is checked by namespace and attributes, allowing equivalent
prefixes, whitespace and attribute order. Its **exact bytes**, not a regenerated
serialization, are included as an additional detached reference. Duplicate, missing,
unknown or inconsistent manifest entries are rejected. No additional META-INF files
are accepted, and no document may remain uncovered. The mimetype and ZIP headers
are structurally checked rather than themselves being XAdES data references.
Legitimate recompression/header changes need not invalidate payload signatures;
there is no claim of a byte-for-byte signature over the entire ZIP encoding.

## ZIP and memory boundaries

`ASiCZIP` is a strict ZIP32 reader/writer; no entry is extracted or executed.
Creation uses STORE. Verification supports STORE and raw DEFLATE, using the macOS
SDK/system zlib via `libz`: no downloaded package, Java or Homebrew runtime dependency.

| Bound | Limit |
| --- | --- |
| Archive bytes | 24 MiB |
| Payload | 8 MiB each, 16 MiB combined |
| All expanded entries | 16 MiB + 128 KiB |
| Entries | At most 7 |
| Signature XML / manifest / mimetype | 128 KiB / 16 KiB / 64 bytes |
| Inflation ratio | At most 100:1 per entry |
| Payload basename | At most 96 UTF-8 bytes, canonical NFC |
| Native object frame | At most 5 objects, bounded to 17 MiB |

All central and local records, flags, methods, sizes, CRC fields, names, offsets and
entry intervals are validated **before** allocating decompression outputs. Entries
must be contiguous, non-overlapping and consistently ordered between the local and
central directories; no hidden local files, leading/trailing data or alternate end
records are accepted. Inflation must consume exactly the declared input and produce
exactly the declared output. CRC-32 checks precede signature validation.

Rejected: encrypted ZIP, ZIP64, multi-disk, descriptors, comments, extra fields,
explicit directory records, symlinks/non-regular entry modes, traversal/absolute paths,
backslashes, ambiguous names, duplicate or case-colliding entries, unsupported
compression and excessive inflation. Names containing URI delimiters, percent signs,
controls, bidi overrides, dot segments or reserved portable basenames are rejected.
Payloads are top-level files. Acquired macOS filenames are normalized to NFC;
pre-existing ZIP names must already have that exact encoding. Nested archives may
be opaque signed payloads but are never recursively expanded or verified.

These are deliberately narrower limits than the full ASiC/ZIP specifications;
otherwise valid archives with unsupported packaging/properties are not verifiable.

## Detached verification and retained protections

The existing native XAdES implementation is extended with an explicit detached
object map. Common XML parsing, ID checks, certificate identification, signed
properties, algorithms and canonicalization are reused. The enveloped API still
accepts only the existing document-root and SignedProperties references.

Detached URIs must correspond exactly, once each, to the validated in-memory object
map. Data and SignedProperties digests are checked, then canonical SignedInfo and
SignatureValue are verified with the existing OpenSSL backend. **No global xmlsec
I/O callback is installed, and no filesystem or network resolver is enabled.**
The enveloped xmlsec URI/transform whitelist is unchanged. DTD, XXE, wrapping,
duplicate IDs, indirect keys, algorithm parameters, external/file references,
XPath/XSLT and unsupported properties remain rejected. The detached profile permits
no transforms on raw payloads and only exclusive c14n on SignedProperties.
Reference/DataObjectFormat order follows the sorted object map in this first profile;
alternate URI spellings, subtree references and multi-signature containers are not
supported.

A typed ASiC verification report carries the verified signer DER, SignatureValue and
declared time into the unchanged 0.6-A X.509/revocation/eIDAS service. Integrity does
not grant trust to KeyInfo, and signingTime is not proof of existence. Existing
country, direct-CAQC, temporal and revocation sufficiency limits remain. No new QES,
LTV, LT/LTA, timestamp, evidence-record or long-term preservation claim is made.

## Approval, worker, GUI and atomic output

ASiC-S acquisition freezes one unsigned container per selected source. ASiC-E
acquisition freezes the complete two-to-four-file selection into one unsigned
container and one job; acquisition failure does not silently drop a member.
Original documents use the existing coherent snapshots before container assembly.
An unsigned intermediate ZIP is only an immutable approval snapshot, not a completed
signed ASiC. Snapshot labels/destination suggestions describe a virtual container
beside the first source; only retained snapshot bytes are signed.

The existing review freezes format, certificate/provider context, complete payload
names and SHA-256 values, unsigned-container identity and destination/directory
identity. Names and approval metadata are prepared off-main. Changing originals
after acquisition does not change the signed set. Acquired containers cannot be
converted through per-document format controls; choose the new-document format and
acquire again. The current UI adds ASiC-S/E choices and displays contained names,
limits and results without a redesign. No automatic extraction is offered.

The unchanged PKCS#11 worker receives canonical SignedInfo through the existing
bounded RSA-SHA256 request, never document or destination paths. Per-document PIN,
provider binding, cancellation and uncertain outcomes are reused. The exclusive
transactional writer revalidates the complete staged container, signer and snapshot
before publication; occupied destinations cannot be overwritten. Reusable automatic
CAdES authentication sessions are not enabled for ASiC.

## Focused validation and interoperability

14 ASiC core tests plus one ASiC trust-integration test pass. Eleven focused 0.6-B
preservation tests (9 enveloped XAdES, 2 trust/TL integration) also passed against
the shared native extension. Initial Unicode-byte normalization and temporary-path
test issues were corrected; only relevant focused tests were rerun.

Coverage includes ASiC-S/E, four documents and Unicode/percent-encoded references,
raw-byte association, modified/swapped/missing/extra/renamed documents, bad references,
manifest semantics versus exact signed bytes, duplicate names, symlinks, traversal,
overlaps, header disagreement, CRC, encryption, unsupported/corrupt compression,
size/ratio/metadata caps, snapshot immutability, synthetic PKCS#11 signing, failed or
cancelled operations, occupied destinations, grouped approval and indeterminate
trust/revocation with an untrusted signer. No physical device or personal document
was used.

Independent tools already available locally:

- `/usr/bin/unzip -t` checks generated archive structure/CRC.
- Python standard-library zipfile repacks the archive with DEFLATE; native verification
  accepts it, establishing cross-reader ZIP interoperability within the stated limits.
- xmlsec1 1.3.12/OpenSSL verifies Signum detached references and signatures. Reverse
  signatures generated by that CLI are placed into the ZIP and accepted by Signum.
  The test explicitly trusts only the synthetic fixture certificate and uses the
  supplied private RSA key for reverse generation, as in 0.6-B. A fixture copy of
  signature XML is placed at the test root so the generic CLI resolves data from the
  ASiC container root. These are XMLDSig/ZIP comparisons, not a DSS or general ASiC
  conformance verdict. No personal data is sent to a remote service.

Evidence outside the repository: `outputs/signum-0.6c-targeted.log` (initial focused
session and unchanged enveloped/TL cases), `outputs/signum-0.6c-corrections.log`,
`outputs/signum-0.6c-acquisition-security.log`, `outputs/signum-0.6c-metadata-limits.log`,
and `outputs/signum-0.6c-final.log` (final ASiC/qualification component session).
Only changed/relevant components ran. No full regression, general sanitizer, app
package, Beta, PR, tag or release was created. No packaged UI launch or macOS 13
runtime execution is claimed.

## CAdES detached evaluation — deferred to 0.6-D

The existing CAdES Prepared object already hashes the document into signed CMS
attributes, so generation alone could be extended relatively narrowly. However,
its finish method always emits attached eContent and the current native verification
contract handles attached content/extraction. Safe ASiC support additionally needs
an explicit external-content verification contract, SignerInfo/content binding,
ESS handling and negative tests. ASiC-E CAdES also introduces the distinct
ASiCManifest/SigReference profile rather than the XAdES direct-reference/ODF layout.
Those coordinated changes exceed a generator toggle. They are deferred to 0.6-D;
no CAdES generator, CMS verifier, PAdES signing or PKCS#11 protocol is changed here.
