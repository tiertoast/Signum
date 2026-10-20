#!/bin/bash
# Build-time prerequisites: Apple tools, CMake, pkg-config. No runtime Homebrew dependency.
set -euo pipefail
cd "$(dirname "$0")/../.."
output="${1:?Specify a NEW private native build directory}"
mkdir -p .build/preview-native-src
fetch() {
  local file=".build/preview-native-src/$1" digest="$2" url="$3"
  if [[ ! -f "$file" ]]; then
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --connect-timeout 10 --max-time 120 --max-filesize 65000000 "$url" -o "$file"
  fi
  printf '%s  %s\n' "$digest" "$file" | shasum -a 256 -c -
}
fetch openssl.tar.gz deae7c80cba99c4b4f940ecadb3c3338b13cb77418409238e57d7f31f2a3b736 https://github.com/openssl/openssl/releases/download/openssl-3.5.6/openssl-3.5.6.tar.gz
fetch libxml2.tar.xz 98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821 https://download.gnome.org/sources/libxml2/2.15/libxml2-2.15.4.tar.xz
fetch xmlsec.tar.gz 24045199af12d93fe5fdbbbf7e386e823e4842071e9432e2b90ac108b889a923 https://github.com/lsh123/xmlsec/releases/download/1.3.12/xmlsec1-1.3.12.tar.gz
fetch freetype.tar.xz 0550350666d427c74daeb85d5ac7bb353acba5f76956395995311a9c6f063289 https://download.savannah.gnu.org/releases/freetype/freetype-2.13.3.tar.xz
fetch podofo.tar.gz d6ffe6fc173ac6d6e5b00f5cb9db01990cab1bdf7cc03bdeffce3013bc9ec63a https://github.com/podofo/podofo/archive/refs/tags/1.1.2.tar.gz
exec python3 scripts/build-preview-native.py --output "$output" --cmake "$(command -v cmake)"
