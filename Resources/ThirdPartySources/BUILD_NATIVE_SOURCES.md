# Rebuilding the covered libraries without the private Signum repository

The original PoDoFo1.1.2 and FreeType2.13.3 source archives are beside this file.
Their SHA256 values and acquired URLs are recorded in SOURCE_INVENTORY.json.
PoDoFo's MPL applies to the library; other bundled components retain their
own terms. FreeType's engine is used under FTL with separate module notices.
No Signum product source is needed to build these libraries themselves.

For the new controlled run, NATIVE_BUILD_PROVENANCE.json records the exact
compiler/SDK versions, complete configure/build/install commands, options,
unchanged source inventories, dependency/output hashes and verification results.
It exists only after that run succeeds; historical evidence is not substituted.

On macOS arm64, use a new external SOURCE_ROOT, BUILD_ROOT and PREFIX. Verify
archive SHA256 before extraction. The sources have one top-level directory per
archive. Provide OpenSSL3.5.6 and libxml2 2.15.4 matching headers/dylibs in PREFIX
(or specify their locations explicitly); their public source projects do not
require access to Signum. The controlled Signum run copies the already validated
versions into its NEW prefix and records their exact binary/header hashes.
xmlsec1.3.12 is similarly reused for later Signum verification, not rebuilt here.

Use CMake with Release, arm64, CMAKE_OSX_DEPLOYMENT_TARGET=13.0,
CMAKE_OSX_SYSROOT set to the installed SDK, CMAKE_INSTALL_PREFIX=PREFIX,
CMAKE_PREFIX_PATH=PREFIX, explicit Apple clang/clang++, and file-prefix-map of
the new build root to a logical path. Disable user/system package registries,
PkgConfig discovery and Homebrew library search paths.

1. FreeType: BUILD_SHARED_LIBS=OFF; FT_DISABLE_HARFBUZZ/BROTLI/BZIP2/PNG=ON.
   Configure its source with `cmake -S SOURCE_ROOT/freetype-2.13.3 -B BUILD_ROOT/ft`
   and the options above; `cmake --build BUILD_ROOT/ft`, then
   `cmake --install BUILD_ROOT/ft`. macOS SDK zlib may be linked; preserve the
   actual generated configuration in the build record.
2. PoDoFo: PODOFO_BUILD_LIB_ONLY=ON, PODOFO_BUILD_STATIC=OFF,
   PODOFO_WITH_FONTMANAGER=OFF, PODOFO_WITH_AFDKO=OFF;
   OPENSSL_ROOT_DIR=PREFIX, OPENSSL_USE_STATIC_LIBS=FALSE;
   FREETYPE_LIBRARY_RELEASE=PREFIX/lib/libfreetype.a and
   FREETYPE_INCLUDE_DIRS=PREFIX/include/freetype2;
   LIBXML2_INCLUDE_DIR=PREFIX/include/libxml2,
   LIBXML2_LIBRARY=PREFIX/lib/libxml2.dylib; disable CMake discovery of JPEG,
   PNG, TIFF, LCMS2 and Doxygen. Configure `SOURCE_ROOT/podofo-1.1.2` out of source,
   build and install with the same platform options. No source patches are
   applied by the Phase7 driver; before/after source hashes must prove this.
3. Inspect all dylibs with otool/lipo and ensure no private library resolves
   outside the new prefix. The controlled run uses local ad-hoc signatures on
   its own copies for Apple Silicon loading; no Apple identity/notarization.

These steps preserve the libraries' replacement/rebuildability and do not
require private Signum credentials. The separate Signum helper integration
check in rebuild-beta-native.py does require the authorized Signum worktree;
that is a product qualification step, not a restriction on the covered sources.
Do not treat these instructions or a successful native run as public-release
approval. Preserve source, notices and any changes for every shipped build.
