# Signum Refined

`Refined-Default-1024.png` is the unmodified `Icon-iOS-Default-1024@1x.png`
from the user's Apple Icon Composer **Icon Exports.zip**, selected as Refined.
SHA-256: `e558bf5f1769775b98f58ad797adb25a0040687a8e0763ac931eedd9dae90f6a`.

The archive contains flattened default, dark, clear and tinted PNG exports,
not a layered `.icon` document. The default export is the static app identity;
no automatic appearance switching or Liquid Glass layers are claimed.

Run from the repository root on macOS:

```sh
swift scripts/build-app-icon.swift
```

This generates `Resources/AppIcon.icns` using AppKit and Apple's `iconutil`.
The original artwork fills its 1024px canvas; the generator centers it in an
824px square, preserving its baked rounded corners and transparent corners.
The resulting transparent margin keeps the icon proportionate in macOS.
All ten macOS 1x/2x slots (16, 32, 128, 256, 512pt) are included.

The supported app packager copies the ICNS to `Contents/Resources` before
code signing, declares `CFBundleIconFile` in `Contents/Info.plist`, and records
its SHA-256 in `BuildManifest.json`. This supplies Finder, Dock and the standard
About-panel app icon without a runtime override.

There is no checked-in `.xcodeproj` or asset catalog. Xcode opens `Package.swift`;
`swift build` / Xcode's package executable do not assemble a Finder `.app`.
Use `scripts/build-preview-app.py` for the actual app bundle. No SwiftPM resource
declaration is needed for this bundle-level resource. If a dedicated Xcode app
target is added later, it must copy this ICNS and use the same plist key (or
migrate explicitly to a layered Icon Composer source).

Apple references:
[CFBundleIconFile](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CoreFoundationKeys.html),
[App icons](https://developer.apple.com/design/human-interface-guidelines/app-icons).
