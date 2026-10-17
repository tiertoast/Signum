# Local PKCS#11 lifecycle tests

Run from the Signum checkout:

```bash
scripts/test-pkcs11-local.sh
```

Requires local CMake and the Mac compiler. The script detects the private CMake
installation under `.build/native-tools` used by the preceding portions;
`SIGNUM_CMAKE`, `SIGNUM_CTEST`, `SIGNUM_PROVIDER_TEST_BUILD` override paths.
No package installation or remote CI is performed.

The fixture is a separate, test-only dynamic library. It exports a PKCS#11 2.40
function table and controls for failures, shared login, call counters and blocking
barriers. It never opens a device, validates/stores a PIN, uses a real certificate
or performs RSA. Signature bytes and credential input are synthetic placeholders.
The fixture is never linked into SignumApp or copied into its bundle.

The production `pkcs11_shim.c` is compiled unchanged into the test executable.
Each case copies the fixture to its own private temporary directory. Tests cover
lifetime, aliases, concurrent calls, borrowed initialization, authentication,
cleanup quarantine, removal and isolation of a separate exec process. CTest runs
40 cases within one test with a 60-second timeout.

ThreadSanitizer can be reproduced with another build directory:

```bash
cmake -S Tools/PKCS11Tests -B .build/pkcs11-tests-tsan \
  -DCMAKE_BUILD_TYPE=Debug \
  '-DCMAKE_C_FLAGS=-fsanitize=thread -g -O1' \
  '-DCMAKE_CXX_FLAGS=-fsanitize=thread -g -O1' \
  '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=thread' \
  '-DCMAKE_MODULE_LINKER_FLAGS=-fsanitize=thread'
cmake --build .build/pkcs11-tests-tsan --parallel 6
ctest --test-dir .build/pkcs11-tests-tsan --output-on-failure -V
```

The Swift suite separately compiles the same fixture under its private `.build/`
folder and tests the public Swift facade and asynchronous retirement. It has no
optional environment switch or skipped mock prerequisite.

SG-04 adds test-only public DER injection and deterministic certificate replacement.
The Swift certificate suites exercise both checked native signing entry points,
ensuring rejected/replaced certificates cause no C_Login or C_Sign, while an
eligible fixture reaches one synthetic signing attempt and fails final verification
of the mock's deliberately invalid signature. The 40 lifecycle cases are preserved.
The checked entry points link the same Security.framework-backed local policy as
SignumCore and the standalone PAdES helper; raw primitives remain internal test tools.
