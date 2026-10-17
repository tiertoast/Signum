#!/usr/bin/env bash
# Local, synthetic tests only. Never opens a PKCS#11 provider or asks for a PIN.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "PAdES integrity tests require macOS." >&2
  exit 1
fi
cmake_tool="${SIGNUM_CMAKE:-cmake}"
ctest_tool="${SIGNUM_CTEST:-ctest}"
if [[ -x .build/native-tools/cmake/data/bin/cmake && -z "${SIGNUM_CMAKE:-}" ]]; then
  cmake_tool="$PWD/.build/native-tools/cmake/data/bin/cmake"
  ctest_tool="$PWD/.build/native-tools/cmake/data/bin/ctest"
fi
native_prefix="${SIGNUM_NATIVE_PREFIX:-$PWD/.build/native-prefix}"
native_build="${SIGNUM_PADES_TEST_BUILD:-$PWD/.build/signum-pades}"
"$cmake_tool" -S Tools/PAdESPrototype -B "$native_build" \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH="$native_prefix" \
  -DOPENSSL_ROOT_DIR="$native_prefix" -DSIGNUM_BUILD_OFFLINE_TESTS=ON
"$cmake_tool" --build "$native_build" --parallel 6
"$ctest_tool" --test-dir "$native_build" --output-on-failure --verbose
