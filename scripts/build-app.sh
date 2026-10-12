#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Signum.app can only be packaged on macOS" >&2
  exit 1
fi
swift build -c release --product SignumApp
APP="build/Signum.app"
mkdir -p "$APP/Contents/MacOS"
cp .build/release/SignumApp "$APP/Contents/MacOS/Signum"
cp Resources/Info.plist "$APP/Contents/Info.plist"

# Optional separately-built PoDoFo helper. Always clear stale copies so that
# an earlier experimental binary cannot silently remain enabled.
rm -rf "$APP/Contents/Helpers"
HELPER=".build/signum-pades/signum-pades-local"
if [[ -x "$HELPER" ]]; then
  mkdir -p "$APP/Contents/Helpers"
  cp "$HELPER" "$APP/Contents/Helpers/signum-pades-local"
  chmod 755 "$APP/Contents/Helpers/signum-pades-local"
  echo "[PAdES] Local helper included (still requires independent validation)."
else
  echo "[PAdES] Helper absent: PDF signing will remain disabled."
fi

echo "Created $APP (unsigned development build; do not distribute)."
