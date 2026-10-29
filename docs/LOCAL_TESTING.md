# Local development checks

Use `python3 scripts/test-local.py` from the repository root. The runner uses
synthetic fixtures and providers, not installed hardware middleware or personal
PINs. It does not install dependencies or run remote CI.

## Prerequisites

Follow [Building](BUILDING.md) for the native prefix, Apple tools, CMake/CTest,
xmlsec CLI, Python and Poppler requirements. UI/PDFKit groups and the complete
suite need an active WindowServer session. All output and scratch directories
must be new and external to the checkout.

## Groups

| Group | Scope |
| --- | --- |
| `complete` | Complete Swift catalog plus native, packaging and configured sanitizer checks |
| `swift` | Swift catalog with required native helper |
| `pure-swift`, `native-helper`, `poppler`, `synthetic-pkcs11`, `integration`, `ui` | Explicit focused selections defined by the manifest |
| `pkcs11`, `pades` | Native harnesses |
| `packaging` | Python runner/packaging contracts |
| `sanitizers` | Configured targeted sanitizer checks |

Focused selections are partial evidence. Missing mandatory prerequisites,
unexpected skips, missing catalog entries and empty successful runs are failures,
not complete-suite passes. `--check` validates tools and builds the compiled
catalog without executing cases; it still creates external build artifacts.

The runner reads `scripts/local-test-groups.json`, discovers the compiled XCTest
catalog and records executed methods rather than accepting a historical test count.
Explicit tool options are shown in [Building](BUILDING.md). Environment alternatives
include `SIGNUM_NATIVE_PREFIX`, `SIGNUM_CMAKE`, `SIGNUM_CTEST`,
`SIGNUM_TEST_XMLSEC`, `SIGNUM_TEST_PYTHON` and `SIGNUM_TEST_POPPLER`.

## Evidence and safety

The runner creates a unique external execution directory with build scratch,
fixtures, logs and `results.json`. Commands have deadlines and owned child-process
cleanup. Preserve red results; do not reuse a successful last attempt as evidence
that an earlier failure disappeared. ASAN's configured `detect_leaks=0` is not
leak qualification; targeted TSAN does not certify the whole application.

Run campaigns sharing process/device coordination sequentially. Real token,
minimum-OS, clean-Mac and interactive/accessibility checks are separate.
The [stability record](SUITE_STABILITY.md) and [issue #9](https://github.com/tiertoast/Signum/issues/9)
retain the open timing/cancellation follow-up.

## Packaging checks

`scripts/build-beta-app.py` is the supported packager; `scripts/build-app.sh`
is retired. A new diagnostic bundle can be checked using:

```sh
python3 scripts/test-packaged-bindings.py --bundle /absolute/path/to/new/Signum.app
```

This uses synthetic providers and preserves the bundle; it is not hardware acceptance.
For the native ASAN image-teardown constraint, see the preserved
[engineering record](SIGNUM_0.4_C1_ASAN_GATE.md).
