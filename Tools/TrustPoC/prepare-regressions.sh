#!/bin/bash
# Prepare the unchanged official runner's native prerequisites locally.
# Prerequisites: brew install cmake freetype fontconfig jpeg-turbo libpng libtiff poppler pkgconf
set -euo pipefail
cd "$(dirname "$0")/../.."
for tool in cmake ctest pdftoppm pkg-config; do command -v "$tool" >/dev/null; done
prefix="${SIGNUM_TRUST_NATIVE_PREFIX:-$PWD/.build/trust-native13-deps/prefix}"
if [[ ! -f "$prefix/include/openssl/cms.h" ]]; then
  if [[ -n "${SIGNUM_TRUST_NATIVE_PREFIX:-}" ]]; then echo "Build the specified native prefix first" >&2; exit 2; fi
  Tools/TrustPoC/build-native13.sh
fi
mkdir -p .build/trust-regression-deps
source_root="$PWD/.build/trust-regression-deps"
archive="$source_root/podofo-1.1.2.tar.gz"
if [[ ! -f "$archive" ]]; then
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 120 --max-filesize 65000000 \
    https://github.com/podofo/podofo/archive/refs/tags/1.1.2.tar.gz -o "$archive"
fi
printf '%s  %s\n' d6ffe6fc173ac6d6e5b00f5cb9db01990cab1bdf7cc03bdeffce3013bc9ec63a "$archive" | shasum -a 256 -c -
tar -xf "$archive" -C "$source_root"
cmake -S "$source_root/podofo-1.1.2" -B "$source_root/podofo-build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
  -DCMAKE_PREFIX_PATH="$prefix;$(brew --prefix)" -DOPENSSL_ROOT_DIR="$prefix" \
  -DPODOFO_BUILD_TEST=OFF -DPODOFO_BUILD_EXAMPLES=OFF -DPODOFO_BUILD_TOOLS=OFF -DPODOFO_BUILD_UNSUPPORTED_TOOLS=OFF
cmake --build "$source_root/podofo-build" --parallel 4
cmake --install "$source_root/podofo-build"
# Runner's explicit header prerequisite check; library remains the Homebrew dependency.
if [[ ! -e "$prefix/include/freetype2" ]]; then ln -s "$(brew --prefix freetype)/include/freetype2" "$prefix/include/freetype2"; fi
printf 'Official runner prefix: %s\n' "$prefix"
