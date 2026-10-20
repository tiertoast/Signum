#!/bin/bash
# Local-only dependencies. No Homebrew install, system changes or GUI integration.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p .build/trust-native13-deps
native_root="$(cd .build/trust-native13-deps && pwd)"
export MACOSX_DEPLOYMENT_TARGET=13.0
export PKG_CONFIG_PATH="$native_root/prefix/lib/pkgconfig"
fetch() {
  local filename="$1" digest="$2" url="$3"
  if [[ ! -f "$native_root/$filename" ]]; then
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --connect-timeout 10 --max-time 120 --max-filesize 65000000 "$url" -o "$native_root/$filename"
  fi
  printf '%s  %s\n' "$digest" "$native_root/$filename" | shasum -a 256 -c -
}
fetch libxml2.tar.xz 98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821 \
  https://download.gnome.org/sources/libxml2/2.15/libxml2-2.15.4.tar.xz
fetch openssl.tar.gz deae7c80cba99c4b4f940ecadb3c3338b13cb77418409238e57d7f31f2a3b736 \
  https://github.com/openssl/openssl/releases/download/openssl-3.5.6/openssl-3.5.6.tar.gz
fetch xmlsec.tar.gz 24045199af12d93fe5fdbbbf7e386e823e4842071e9432e2b90ac108b889a923 \
  https://github.com/lsh123/xmlsec/releases/download/1.3.12/xmlsec1-1.3.12.tar.gz
cd "$native_root"
for archive in libxml2.tar.xz openssl.tar.gz xmlsec.tar.gz; do tar -xf "$archive"; done
(
  cd openssl-3.5.6
  ./Configure darwin64-arm64-cc --prefix="$native_root/prefix" --libdir=lib shared no-tests -mmacosx-version-min=13.0
  make -j4
  make install_sw
)
(
  cd libxml2-2.15.4
  ./configure --prefix="$native_root/prefix" --without-python --without-lzma --without-zlib CFLAGS='-O2 -mmacosx-version-min=13.0'
  make -j4
  make install
)
(
  cd xmlsec1-1.3.12
  ./configure --prefix="$native_root/prefix" --with-openssl="$native_root/prefix" --with-libxml="$native_root/prefix" \
    --without-libxslt --without-gnutls --without-nss --disable-crypto-dl CFLAGS='-O2 -mmacosx-version-min=13.0'
  make -j4
  make install
)
printf 'Dependency prefix: %s\n' "$native_root/prefix"
