# Security, privacy and validation scope

Signum keeps cryptographic operations local and uses explicit approvals, bounded
parsers and conservative output handling. These controls do not constitute
independent certification, universal interoperability or a legal opinion.

## Signing boundaries

- Approval binds immutable document bytes, the selected certificate, operation,
  destination and relevant PDF appearance. Changes require a new approval.
- PKCS#11 operations use supervised workers. Private keys remain in the
  token/provider; PINs are not command-line arguments, environment settings or
  persistent preferences. Optional temporary batch PIN retention increases
  in-memory exposure and is restricted to approved attached CAdES and PAdES
  batches. In an authenticated batch the PDF helper runs as a remote signer: it
  loads no middleware and never receives the PIN; the worker signs only an exact
  SHA-256 DigestInfo (CKM_RSA_PKCS) for a PDF job named in the approved manifest.
- Output is staged, checked and published exclusively; existing files are not
  silently overwritten. Uncertain private operations do not trigger retries.
- A provider refusal that the worker proves happened before any `C_Sign` (for
  example an incorrect, invalid or locked PIN) is an ordinary failure, not an
  uncertain outcome. After an incorrect PIN the same approved document can be
  authorized again; Signum reports low/final attempt counters when the token
  publishes them and never retries automatically.
- Worker isolation reduces crash/hang impact but is not a privilege sandbox.
  A malicious middleware library still runs as the user; install only trusted modules.
- The middleware file identity (device, inode, size, mtime and ctime) is checked
  again before signing. ctime is kept on purpose: `mtime` can be reset with
  `utimes`, `ctime` cannot, so an in-place rewrite of a manually selected
  (user-owned) module is still detected. Loading or reading the module does not
  change it; only metadata writes do (on a root-owned module, an administrator).
- Worker and helper processes start with a fixed minimal environment (`PATH`,
  `HOME`, `TMPDIR`, `LC_ALL=C`). Nothing is inherited, so variables such as
  `OPENSSL_CONF` or `DYLD_*` cannot redirect the middleware or its crypto library.
  Middleware configuration is read from its own files (for example `*.conf` next
  to the module); GUI apps do not receive shell variables in any case.
- Real PIN changes and PUK unblocking remain disabled/unqualified.

## Validation results

Integrity, certificate-path trust, revocation, temporal evidence and eIDAS
qualification are separate. A signer-supplied time does not prove the signing
date. A present, valid timestamp must also be bound to the relevant signature and
authorized TSA/evidence context. A missing timestamp alone does not determine
whether all other qualification requirements can be met.

The app can evaluate supported current-time or historical evidence. Historical
qualification requires sufficient independently proven time and applicable
revocation/service history; current OCSP good does not establish past validity.
Positive eIDAS qualification remains limited to supported direct CA/QC,
post-2016 IT/AT/DE/BE/FR/ES profiles with sufficient certificate, QSCD, service and
revocation evidence. Unsupported criteria, missing histories and contradictory
information remain indeterminate. An authenticated national TL is not a promise
that every certificate or signature from that territory is qualified.

For PDF, valid historical signatures and current-document coverage are distinct.
DocMDP/FieldMDP semantics and the acceptability of later changes are not certified.
Reports are unsigned assessment snapshots, not legally certified evidence or
PDF/A, PDF/UA, LTV or LT/LTA assurances.

## Network and privacy

Local signing and parsing do not upload document contents to a signing service.
Trust-list acquisition and online OCSP/CRL checks contact their configured or
validated endpoints and reveal normal network metadata. OCSP requests identify
the certificate being checked; they are not anonymous. Offline assessment needs
sufficient authenticated cached or embedded evidence and may be indeterminate.
OCSP/CRL endpoints whose addresses are all public are tried over IPv4 first and
then IPv6. A manual HTTP/HTTPS proxy from the macOS network settings is used,
honouring its bypass list; PAC/WPAD, SOCKS and authenticated proxies are not
supported and fall back to a direct connection.

PINs, private documents and identifying certificate data do not belong in issue
reports. Exported verification reports intentionally contain signer/certificate
information; handle them as potentially personal data. Diagnostic output may
contain paths or public certificate information even when it contains no PIN.

## Beta and distribution boundaries

The release is arm64, ad-hoc signed and not Developer ID signed/notarized. The
minimum macOS 13.0 declaration is not a completed OS/clean-machine qualification.
Broader token/middleware compatibility, failure handling, accessibility and
stability checks remain open. M3–M6 are tracked in [issue #9](https://github.com/tiertoast/Signum/issues/9);
the RC stability gate is not passed. No Stable claim or general QES certification applies.

Report security concerns without secrets or exploitable personal documents.
The repository has no published security-response SLA. For development evidence,
see [Engineering](engineering/README.md); for product scope, see [Formats](FORMATS.md).
