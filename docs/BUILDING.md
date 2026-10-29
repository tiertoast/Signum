# Building from source

The supported product target is macOS on Apple Silicon. A development build is
not the released binary and does not inherit its artifact checksum or qualification.
Building the Swift package alone does not assemble the complete application.

## Requirements

- Apple development tools providing Swift 5.9 or later, clang, a macOS SDK, Xcode
  asset compilation and signing tools. Use a toolchain compatible with the source.
- Python 3, CMake/CTest 3.23 or later and pkg-config tooling.
- A prepared arm64 native prefix with PoDoFo 1.1.2, OpenSSL, FreeType,
  libxml2 and xmlsec/OpenSSL headers, libraries and package metadata.
- For the current Beta staging route: the controlled native-prefix manifest,
  inventory, corresponding source kit and successful checkpoint summary required
  by `scripts/native_profile_contract.py`.
- For the complete local checks: xmlsec CLI, Python `zipfile`, Poppler `pdftoppm`,
  system OpenSSL for synthetic keys and an active macOS WindowServer session.

The Build 14 versions are listed in [Architecture](ARCHITECTURE.md). Installing
unversioned packages does not reproduce that inventory or its source provenance.
Token middleware is needed for real hardware use, not synthetic local checks.

## Get the source

```sh
git clone https://github.com/tiertoast/Signum.git
cd Signum
```

Access to this repository is currently restricted. Use the `v0.7.0-beta` tag when
inspecting the exact release source baseline; `main` includes later documentation.
The product revision recorded in the binary's manifest is
`09316e046a4dd101ce74410a6eeccee6911d4783`.

## Native prerequisites

The current packager consumes a prepared, verified native prefix; it does not
install dependencies. Preserve its accompanying manifests and source kit, not
just a copied `lib` directory. The supplied native recipes distinguish the
preview dependency stack from the older Beta recipe. The controlled rebuild
rebuilds PoDoFo/FreeType while validating and reusing the other pinned libraries
from an approved base prefix.

Consult [native source instructions](../Resources/ThirdPartySources/BUILD_NATIVE_SOURCES.md)
and the [native checkpoint contract](PHASE7_NATIVE_CHECKPOINT.md) before preparing
that input. Original PoDoFo/FreeType archives are included; a fresh machine also
needs the matching base libraries, tools and their input archives. There is no
single-command bootstrap from an otherwise unprepared Mac. Do not substitute
an unrelated prefix or bypass the source/notice gate to get a successful bundle.

## Assemble a local app

From a clean checkout, including ignored files, provide an existing verified
prefix and **new external** output/scratch paths. Replace the illustrative paths
below with absolute paths in your development environment:

```sh
python3 scripts/build-beta-app.py   --configuration release   --native-prefix /absolute/path/to/verified-native/prefix   --cmake /absolute/path/to/cmake   --scratch-root /absolute/path/to/new-build-scratch   --output /absolute/path/to/new-output/Signum.app   --public-beta-build 14   --bundle-id io.github.tiertoast.Signum.LocalBuild   --trust-probe include   --signing-mode adhoc
```

The local bundle ID separates preferences from the released app. The script
builds the required app, CLI, workers and helper, checks dependency closure and
resources, stages the bundle, signs it ad hoc and checks relocation. It refuses
existing destinations. It does not provide Developer ID signing/notarization or
authorize a release. `scripts/build-app.sh` is retired and deliberately fails.

Use the current script's `--help` for exact options. Keep source, native inputs,
build scratch and existing release artifacts separate. Changing documentation
or source and rebuilding creates a new local artifact even if version metadata
is unchanged; do not present it as the published Build 14 DMG.

## Local verification for contributions

The supported runner is `python3 scripts/test-local.py`; it uses synthetic fixtures
and providers, does not request real PINs, and writes to new external directories.
Supply the prepared prefix and tools explicitly. For example:

```sh
python3 scripts/test-local.py --group complete   --native-prefix /absolute/path/to/native/prefix   --cmake /absolute/path/to/cmake --ctest /absolute/path/to/ctest   --xmlsec /absolute/path/to/native/prefix/bin/xmlsec1   --python /absolute/path/to/python3 --poppler /absolute/path/to/pdftoppm   --output-root /absolute/path/to/test-results
```

`--check` validates prerequisites and builds the XCTest catalog without running
cases; it is not a purely static check. Focused groups are partial evidence, not
a complete-suite pass. Consult [Local testing](LOCAL_TESTING.md) and preserve
failed results. Real-device, OS and accessibility acceptance remain separate.
No GitHub Actions are configured; no build or test execution is implied by these instructions.
