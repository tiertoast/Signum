# Using Signum

## Install

Use the [Signum 0.7.0 Beta release](https://github.com/tiertoast/Signum/releases/tag/v0.7.0-beta).
Download the arm64 DMG and its `.sha256` sidecar into the same directory:

```sh
shasum -a 256 -c Signum-0.7.0-beta-arm64.dmg.sha256
```

Open the DMG and drag Signum to Applications. The app declares macOS 13.0 or later
on Apple Silicon; this minimum does not establish completed testing on every
supported OS. The Beta has an ad-hoc signature, without Developer ID/notarization,
and macOS may block opening it. Signum does not disable system protections.

Native libraries are bundled. Hardware signing additionally requires compatible
arm64 PKCS#11 middleware installed by the operator; it is not included in Signum.
Verification does not need a token. Fresh Trusted Lists or certificate-status
lookups need network access; offline results depend on sufficient authenticated
cached or embedded evidence.

## Prepare a device

Open the Devices area, discover the token and review its certificates. If the
installed module is not discovered, configure its actual PKCS#11 library manually;
do not assume one vendor-specific path applies to every installation.
Select a certificate eligible for the requested operation. A visible certificate
or a discovered token is not a hardware compatibility certification.

PIN change and PUK unblocking are not operational features of this Beta. Use only
the appropriate vendor-supported recovery procedure for the exact device.

## Sign documents

1. Add documents to the signing workspace, or send selected files through the
   signing macOS Service. Finder opening routes documents into Signum but never
   authorizes a signature by itself.
2. Select each document's format and destination in the signing inspector.
   For visible PDF signatures, set the page, appearance, position and orientation.
3. Select the token and certificate. For a counter-signature, explicitly select
   which existing signature to countersign.
4. Review and approve the frozen documents, certificate, format and destinations.
   Enter the device PIN only when requested by the signing workflow.
5. Review the results. Existing destination files are not overwritten; uncertain
   private-operation outcomes are not retried automatically.

For detached CAdES, keep the exact original with the `.p7s` signature. Co-signing
adds a signer to the document content; counter-signing signs the selected signature.
For ASiC-S select one document; for ASiC-E select two-to-four documents within the
[profile limits](FORMATS.md).

## Batch authentication

Ordinary attached CAdES batches support three explicit policies:

| Policy | Behavior |
| --- | --- |
| Per document | Request authentication separately for each document |
| Automatic session reuse | Attempt to reuse the approved device session without storing the PIN |
| Temporary PIN | Retain the PIN in memory for the approved batch; greater exposure than per-document authentication |

Reuse remains bound to the approved batch/device context. It is not a persistent
PIN store or permission to sign later documents. Detached, advanced CAdES, PAdES,
XAdES and ASiC operations use per-document authorization. Device middleware can
impose additional authentication requirements.

## Verify and export

Add supported signed documents to the verification workspace; the queue can hold
multiple documents. For a detached `.p7s`, use the action that requests both the
signature and original content. Review each signer's integrity, certificate path,
revocation, time and qualification independently. An indeterminate result calls
for the reason shown, not an assumption of validity or invalidity.

For PDFs, inspect whether the current file is covered or whether only an older
signed revision is valid. Export a PDF or text report from the verification
results. Reports contain identifying certificate and signer information and are
unsigned snapshots of the assessment, not a legal certification.

## CLI and integration

`SignumCLI` is bundled under `Signum.app/Contents/Helpers/`. Its experimental,
human-readable interface is narrower than the GUI:

| Command | Scope |
| --- | --- |
| `list [absolute_module_path]` | Discover public token information |
| `certs <slot> [absolute_module_path]` | List certificates and signing eligibility information |
| `sign-test <slot> <cert_ID_hex> [absolute_module_path]` | Hardware proof operation; does not sign a document |
| `sign-cades <slot> <cert_ID_hex> <input> <output.p7m> [absolute_module_path]` | Interactive attached CAdES signing only |
| `verify <document>` | Unified format dispatch and cryptographic-integrity reporting; not the app's full trust/eIDAS assessment |
| `verify-cades <signed.p7m> [extracted-output]` | Legacy system-OpenSSL CMS integrity/extraction path; refuses countersignatures |

Example of an integrity check with the installed app:

```sh
/Applications/Signum.app/Contents/Helpers/SignumCLI verify signed-document.pdf
```

Provide the real module path explicitly for device commands; the built-in default
is vendor-specific. Signing requests the PIN from the terminal, not an argument,
and `sign-cades` requires an explicit interactive approval of the snapshot.
Some output and the approval prompt are Italian. The CLI does not expose detached
verification pairs, PDF/XML/ASiC signing, report export or a stable JSON API.

Finder document handling and macOS Services are the supported desktop entry points.
Swift Package products expose source-level libraries for core/trust functionality;
internal worker/helper protocols and `SignumTrustProbe` are implementation/diagnostic
interfaces, not a stable third-party SDK, daemon or HTTP service.
