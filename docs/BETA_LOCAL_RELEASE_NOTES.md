# Signum 0.7.0 Beta — Build 18

Packaging notes included in the DMG. For the full release notes, see
[Release notes](RELEASE_NOTES.md) or the GitHub release page.

Build 18 targets Apple Silicon arm64 and declares macOS 13.0. Distribution is
ad-hoc signed, without Developer ID or notarization; macOS may block opening the
downloaded app. PKCS#11 middleware is installed separately. Included libraries,
notices and source-access materials retain their own terms; Signum original code
remains Apache-2.0.

Changes since Build 17: cancelled documents can be signed again with "Riprova"
(never an uncertain outcome); a changed or ineligible certificate is reported as
such; File › Aggiungi documenti… (⌘O); project links in Informazioni su Signum
and an Aiuto menu with the bundled licences and sources; clearer, consistent
interface text.

Changes in Build 17 (since Build 14): a PIN refused by the token is an ordinary, retryable
refusal and is never retried automatically; one PIN can sign an approved batch of
PDF and CAdES documents; documents can be signed from USB drives, external disks,
network shares and Finder-locked files; PDF stamps can be applied to every PDF of
a batch; revocation retrieval prefers IPv4 and honours the macOS HTTP/HTTPS proxy;
CAdES verification uses the bundled OpenSSL.

A local build or startup/loader audit is not complete OS, device or functional
qualification. The offline RC stability gate (synthetic fixtures) passed on
2026-11-27; real tokens and middleware are outside it. Production distribution,
clean-Mac, accessibility and broader compatibility acceptance remain separate.
The app does not disable system protections.
