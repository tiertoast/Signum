#!/bin/bash
# A.2 reuses the in-process bounded refresh/cache/pivot pipeline.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ $# != 1 ]]; then echo "usage: $0 OUTPUT_DIRECTORY" >&2; exit 2; fi
mkdir -p "$1"
output_dir="$(cd "$1" && pwd)"
exec Tools/TrustPoC/native.sh run SignumTrustProbe refresh "$output_dir/verified.json"
