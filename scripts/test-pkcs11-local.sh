#!/usr/bin/env bash
# Builds a synthetic provider and exercises the production C bridge, locally.
set -euo pipefail
cd "$(dirname "$0")/.."
cmake_tool="${SIGNUM_CMAKE:-cmake}"
ctest_tool="${SIGNUM_CTEST:-ctest}"
if [[ -x .build/native-tools/cmake/data/bin/cmake && -z "${SIGNUM_CMAKE:-}" ]]; then
  cmake_tool="$PWD/.build/native-tools/cmake/data/bin/cmake"
  ctest_tool="$PWD/.build/native-tools/cmake/data/bin/ctest"
fi
provider_build="${SIGNUM_PROVIDER_TEST_BUILD:-$PWD/.build/pkcs11-tests}"
"$cmake_tool" -S Tools/PKCS11Tests -B "$provider_build" -DCMAKE_BUILD_TYPE=Debug
"$cmake_tool" --build "$provider_build" --parallel 6
"$ctest_tool" --test-dir "$provider_build" --output-on-failure --verbose
