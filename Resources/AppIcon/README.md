# Signum Refined — Icon Composer source

`../AppIcon.icon` is a byte-for-byte copy of the user-supplied
`Downloads/Icon.icon` document, renamed only at the enclosing directory level.
The visible layer is `Signum-Refined-White-Transparent.svg`; its transform,
background, shadows, translucency and hidden alternative layer are unchanged.

The app packager compiles this document with Xcode's `actool`, targeting macOS
13 and the Mac device family. It includes both generated `Assets.car` (native
layered icon) and `AppIcon.icns` (older-system fallback), merging the compiler's
`CFBundleIconName` and `CFBundleIconFile` metadata before code signing. Both
outputs are hashed in the build manifest. No manual padding or raster conversion
is applied. The previous flattened PNG workflow has been removed.

Xcode must have its required components installed. Open `Package.swift` to work
in Xcode, then use `scripts/build-preview-app.py` for a complete `.app` bundle;
SwiftPM alone builds executables. A future Xcode app target should use this same
Icon Composer document as its AppIcon source.

[Apple's Icon Composer integration documentation](https://developer.apple.com/documentation/xcode/creating-your-app-icon-using-icon-composer)
