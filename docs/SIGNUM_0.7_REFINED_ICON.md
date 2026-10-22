# 0.7 Refined — native Icon Composer integration

Updated 22 October 2026 on `feature/signum-0.7-refined-icon` (draft PR #7).
This supersedes the earlier flattened-PNG integration.

## Source and packaging

The user supplied `/Users/andreaoregioni/Downloads/Icon.icon`. Its icon.json and
both SVG assets are preserved byte-for-byte in `Resources/AppIcon.icon`.
The selected Refined layer, hidden alternative, transforms and materials remain
as authored. No manual inset or flattening is performed.

The audited local packager invokes Apple's actool for macOS 13, producing
Assets.car and AppIcon.icns. It merges Apple's generated icon metadata into the
bundle plist, records both output hashes, then signs and audits the complete app.
The 0.7 preview identifier still coexists with 0.6. No Sources, Package.swift,
engine logic, dependency versions or HalleyMac changes were made.

## Local validation

Xcode 27.1 / Apple Silicon. Native compilation initially failed because the
installed Xcode lacked CoreSimulator.framework. Its matching XcodeSystemResources.pkg
was extracted into ignored `.build/xcode-system-resources` and used through a
build-tool-only DYLD_FRAMEWORK_PATH (including CoreSimulator's nested Frameworks).
This override is never passed to product startup, native library builds or audits.
The attempted first-launch setup was stopped; no system installation was required.
A normally initialized Xcode needs no override.

Validation passed: 21 Python packaging/runner tests including real actool
compilation; Debug and Release complete bundle builds, ad-hoc signatures, native
closure and relocation; 10 synthetic packaged binding checks per configuration.
Both GUIs survived four seconds with audited loaded libraries. Finder and running
app icon images matched byte-for-byte at 256px in each configuration. Both asset
hashes match the manifests, and the source matches the user document. Evidence is
under `.build/composer-*.log` and `.build/icon-validation/Composer-*`.
These are targeted checks, not a full engine regression or real macOS 13 runtime
test. Native appearance was inspected on the current host; older-system fallback
was decoded separately. No release, tag, DMG, GitHub Actions or installation.

## Reproduce

```sh
python3 -m unittest discover -s scripts/tests -v
python3 scripts/build-preview-app.py --version 0.7.0 --build-number 1 \
  --configuration release --output /new/path/Signum.app \
  --native-prefix /private/prefix --cmake /local/cmake
python3 scripts/test-packaged-bindings.py --bundle /new/path/Signum.app
```

Use a new output path for every build, and repeat with configuration debug.
See `Resources/AppIcon/README.md` for source and integration details.
