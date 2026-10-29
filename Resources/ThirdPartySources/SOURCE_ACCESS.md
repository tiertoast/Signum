# Source access — Signum 0.7.0 Beta preparation, Phase 6b

Status: NOT YET QUALIFIED FOR DISTRIBUTION. These are the verified expected
upstream archives. Correspondence with the existing native binaries and the
complete patch inventory remain unattested. Do not represent this kit as
satisfying corresponding-source obligations until those gaps are closed.

The author has selected MPL 2.0 for the PoDoFo library and FTL for the FreeType
engine. Other components retain their own licenses; the selections do not
relicense every file in these archives. PoDoFo tools are GPL; no such tool
binary is introduced. All original archive notices are retained.

## Concrete delivery route

The prepared route is source-with-artifact: the existing packaging recipe
copies this entire directory into `Signum.app/Contents/Resources/ThirdPartySources`.
Recipients can select the app in Finder, Show Package Contents, then open that
path without needing access to the private Signum repository or an account.
Alongside this file they will find:

- `podofo.tar.gz` — PoDoFo 1.1.2, SHA256
  `d6ffe6fc173ac6d6e5b00f5cb9db01990cab1bdf7cc03bdeffce3013bc9ec63a`.
  Original: https://github.com/podofo/podofo/archive/refs/tags/1.1.2.tar.gz
  Retrieved from the official codeload endpoint recorded in SOURCE_INVENTORY.json.
- `freetype.tar.xz` — FreeType 2.13.3, SHA256
  `0550350666d427c74daeb85d5ac7bb353acba5f76956395995311a9c6f063289`.
  Original: https://download.savannah.gnu.org/releases/freetype/freetype-2.13.3.tar.xz
  Official redirect and final mirror recorded in SOURCE_INVENTORY.json.
- `SOURCE_INVENTORY.json` — acquisition URLs, SHA256, component member hashes
  and outstanding limitations. `Evidence/` records source comparisons and the
  exact configuration-header differences observed in the existing prefix.

The archives include their original MPL/FTL texts and vendored sources/notices.
The app's sibling `Contents/Resources/Notices` provides readable license texts
and acknowledgments, including FreeType Team and extra upstream notices.

Before shipping, add the actual local patches or a supported attestation of
an empty diff, the original build record and evidence connecting these sources
to the shipped binary hashes. A matching archive/installed header does not
prove the unobserved private sources. Do not remove this warning until verified.
No download, build, signing or publication is performed by these instructions.
