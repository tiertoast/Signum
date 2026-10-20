#!/usr/bin/env bash
set -euo pipefail
cat >&2 <<'MESSAGE'
ERROR: scripts/build-app.sh is retired: it could produce an incomplete app without SignumPKCS11Worker.
Use the official packager from the repository root with a NEW output path:
  python3 scripts/build-beta-app.py --output /new/path/Signum.app --configuration release --native-prefix /local/prefix --cmake /local/cmake
See docs/LOCAL_TESTING.md for prerequisites, Debug/Release audits and synthetic bundle tests.
No bundle has been created or modified.
MESSAGE
exit 2
