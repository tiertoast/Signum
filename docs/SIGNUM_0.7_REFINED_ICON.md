# 0.7 Refined icon integration — local validation

Date: 22 October 2026. Base: `61fa0b7` (main after the 0.6 verification reports merge).
Branch: `feature/signum-0.7-refined-icon`.

## Scope

Integrates the selected Refined artwork from Apple Icon Composer's `Icon Exports.zip`
(archive SHA-256 `c381183d0f3377b1197a10c3818b9acb04b642d382b15f8852c1add7aed9a5a8`).
See [asset provenance and regeneration](../Resources/AppIcon/README.md).

Adds the static multi-resolution `AppIcon.icns`, bundle plist declaration, copying
before signing, and icon hash in the build manifest. A separate 0.7.0 Development
Preview Build 1 identifier allows coexistence with 0.6. Debug/Release are both
available in the existing preview packager. No Xcode project exists; SwiftPM
builds executables and the audited packager creates the macOS application.

No changes to `Sources/`, `Package.swift`, signing/verification logic, test fixtures,
or HalleyMac. Existing 0.5/0.6 preview identities are preserved. The foundational
plist version is unchanged; preview packaging supplies the 0.7 version.

Two build portability fixes were needed on Xcode 27.1: use an absolute logical
`/Signum` prefix for compiler path mapping (relative `.` produced checkout-parent
paths in Debug module metadata), and configure libxml2's system configuration
directory as `/etc` (its default embedded the private staging prefix). Dependency
versions and portability/signature audits remain unchanged.

## Local checks

- Xcode 27.1 / Apple Swift 6.4, Apple Silicon host; deployment target macOS 13.
- 21 Python packaging/runner tests passed, including all icon representation slots
  and isolated 0.7 identity. Initial assertions were updated for 0.7 support and
  iconutil's `ic04`/`ic05` representation encodings.
- 20 targeted Swift tests passed: 2 AppVersion and 18 VerificationReportExport.
  Tests require the locally built PAdES helper and a linker rpath for the private
  native libraries; initial attempts without these prerequisites failed at setup.
- Complete Debug and Release app packaging passed: app/CLI/worker/helper,
  native dependency closure, minimum OS, ad-hoc code signature, relocation and
  synthetic CLI-to-worker discovery.
- 10 packaged synthetic contract checks passed for each configuration.
- Both GUIs remained alive for four seconds. Dynamic loader logs passed the
  bundle-only library audit; only the smoke-test processes were terminated.
- Finder's `NSWorkspace.icon(forFile:)` and the launched app's
  `NSRunningApplication.icon` produced identical 256px images in each configuration.
  Their appearance was inspected alongside decoded ICNS sizes on light/dark
  backgrounds. All ten iconset PNGs decode. Regeneration produces the same ICNS
  SHA-256: `cfd50fe5108c163abe21a6d9322e1b60028f52f82d5d021b8a54c881a7ec146e`.

The original PNG artwork is retained byte-for-byte. There is no layered `.icon`
source in the attachment, so dynamic Icon Composer appearance/material behavior
is outside this static integration. This is targeted validation, not a new full
engine acceptance campaign, real-token test, or runtime test on macOS 13/14.

## Reproduce

```sh
swift scripts/build-app-icon.swift
python3 -m unittest discover -s scripts/tests -v
# Build pinned native sources using the existing private recipe first.
python3 scripts/build-preview-app.py --version 0.7.0 --build-number 1 \
  --configuration debug --output /new/path/Debug/Signum.app \
  --native-prefix /private/prefix --cmake /local/cmake
# Repeat with --configuration release and a new output path.
python3 scripts/test-packaged-bindings.py --bundle /new/path/Debug/Signum.app
SIGNUM_TEST_PADES_HELPER=/local/signum-pades-local \
PKG_CONFIG_PATH=/private/prefix/lib/pkgconfig \
PKG_CONFIG_LIBDIR=/private/prefix/lib/pkgconfig \
swift test --scratch-path .build/icon-swift-tests \
  -Xlinker -rpath -Xlinker /private/prefix/lib \
  --filter 'AppVersionTests|VerificationReportExportTests'
```

Local evidence is under `.build/icon-*.log` and `.build/icon-validation/`.
No GitHub Actions, release, tag, DMG, Developer ID signing or notarization was
performed. Existing installed apps and other checkouts were not replaced.
