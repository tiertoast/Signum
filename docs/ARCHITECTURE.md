# Architecture and dependencies

Signum is a native Swift/SwiftUI/AppKit application with C/C++ cryptographic and
PDF components. The application coordinates the workflow; token operations and
native document inspection use bounded subprocess interfaces.

| Layer | Responsibility |
| --- | --- |
| `SignumApp` | Native workspace, PDF preview, Finder/Services routing, signing review and verification presentation |
| `SignumCore` | Immutable snapshots, format preparation, approvals, worker supervision, batches and exclusive file output |
| `SignumPKCS11Worker` / `CPKCS11` | Token discovery, certificate access and approved PKCS#11 signing operations |
| `signum-pades-local` | PoDoFo PDF signing and supported PDF/CMS inspection and evidence extraction |
| Trust and certificate-validation modules | Authenticated European Trusted Lists, X.509, revocation, temporal evidence and qualification policy |
| Verification-report modules | PDF and text presentation of independent per-signer outcomes |
| `SignumCLI` | Experimental terminal discovery, attached CAdES signing and integrity inspection |

## Data and process boundaries

An approved job binds the source snapshot, signing certificate, operation,
destination and any PDF appearance. The isolated worker signs the prepared bytes;
private keys stay with the token/provider. Parent-side checks bind the result back
to the expected key and document before exclusive staged publication.
Cancellation, timeouts and uncertain results do not authorize an automatic retry.

The source snapshot is a private copy taken through the pinned source
descriptor: a copy-on-write clone on the private area's volume, a bounded
descriptor copy (re-read and compared) on other volumes or for Finder-locked
files. Preview, hash and signature always cover that private copy.
Signed output is staged next to the destination and published without ever
replacing an existing name. On APFS/HFS+ the staging is private (0700/0600, empty
ACL, inherited final ACL) and published with `RENAME_EXCL`. On volumes without real
permissions or exclusive rename (FAT, exFAT, SMB, NFS) the privacy policy is
skipped, identity checks remain, and the name is reserved with `O_EXCL` before a
rename over that still-empty reservation (`sg_output_publish_exclusive`).
Visible PDF stamps of a session have one owner, `PDFStampBoard` (SignumApp). The
stamp last confirmed in the editor is the template; "Applica a tutti" copies it to
every other pending PDF at the same visible margins (last page follows last page)
and keeps copies in sync with added PDFs, template edits and certificate changes.
The PDF open in the editor is never overwritten, nothing changes while the batch
is frozen, and every stamp is bound to the selected certificate and reviewed.

The middleware runs in processes with the user's permissions. Isolation limits
crash/hang impact but does not make arbitrary vendor code trustworthy or sandbox it.
The app uses Apple PDFKit/CoreGraphics/CoreText for preview and appearance;
PoDoFo applies the native PDF signature. XML uses libxml2/xmlsec with explicit
reference, transform and resource restrictions. ASiC uses a bounded ZIP32 layer
and the supported detached XAdES profile.

## Build 14 dependency inventory

Versions below come from the released `BuildManifest.json`, not an unpinned
package-manager installation.

| Dependency | Version | Role | Distribution terms |
| --- | --- | --- | --- |
| PoDoFo | 1.1.2 | PDF manipulation/signature helper | MPL-2.0 selected from upstream alternatives |
| FreeType | 2.13.3 | Font support in the native stack | FTL selected; additional bundled notices retained |
| OpenSSL | 3.5.6 | CMS, X.509 and cryptographic backend | Apache-2.0 |
| libxml2 | 2.15.4 | XML parsing/canonicalization | MIT license notices |
| xmlsec | 1.3.12 | XMLDSig processing | MIT-style Copyright terms |
| Apple frameworks | System supplied | SwiftUI, AppKit, PDFKit, Security, CoreGraphics, CoreText, Foundation/CoreFoundation | Apple platform components |
| zlib | System supplied | Bounded ASiC DEFLATE support | System library; no separately downloaded runtime package |
| PKCS#11 middleware | Operator supplied | Smart-card/token access | Vendor-specific, separately installed |

The app bundles the non-system native libraries required by its release manifest.
FreeType is part of the native build and need not appear as a separate dylib.
PoDoFo's incorporated components carry their own notices; the complete inventory
is in the shipped notice/source material rather than a claim of independently
installed versions for every embedded component. Java and Homebrew are not
application runtime dependencies. CAdES post-signing verification and the
`verify-cades` CLI command use the bundled OpenSSL in-process; no system
`/usr/bin/openssl` is required at runtime.

## Licensing and corresponding source

Signum original code is [Apache-2.0](../LICENSE). This does not relicense its dependencies.
The release bundles notices and a corresponding PoDoFo/FreeType source kit at
`Contents/Resources/ThirdPartySources/`, with `SOURCE_ACCESS.md`, provenance,
archives and component-specific terms. Recipients can obtain the included kit
without access to the private Git repository. Schema notices remain separate.
Portions of this software are copyright © The FreeType Project.

Technical provenance and legal originals are retained without translation or
rewriting. [Engineering and source records](engineering/README.md)
