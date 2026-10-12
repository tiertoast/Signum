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
echo "Created $APP (unsigned development build; do not distribute)."
