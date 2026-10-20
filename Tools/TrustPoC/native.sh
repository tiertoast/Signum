#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ -n "${SIGNUM_TRUST_NATIVE_PREFIX:-}" ]]; then
  export PKG_CONFIG_PATH="$SIGNUM_TRUST_NATIVE_PREFIX/lib/pkgconfig"
else
  brew_prefix="$(brew --prefix)"
  export PKG_CONFIG_PATH="$brew_prefix/opt/libxml2/lib/pkgconfig:$brew_prefix/opt/openssl@4/lib/pkgconfig:$brew_prefix/opt/openssl@3/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
fi
# Use the same libxml2 headers and runtime as xmlsec, never Apple's older headers.
exec swift "$@"
