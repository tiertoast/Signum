#!/bin/bash
# Explicit local two-step acquisition. No redirects or arbitrary pointer fetching.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ $# != 1 ]]; then echo "usage: $0 OUTPUT_DIRECTORY" >&2; exit 2; fi
mkdir -p "$1"
output_dir="$(cd "$1" && pwd)"
staging_dir="$(mktemp -d "$output_dir/.acquire.XXXXXX")"
trap 'rm -rf "$staging_dir"' EXIT
curl --fail --silent --show-error --proto '=https' --connect-timeout 10 --max-time 45 --max-filesize 67108864 \
  https://ec.europa.eu/tools/lotl/eu-lotl.xml -o "$staging_dir/eu-lotl.xml"
# This command must succeed under OJ policy before any AgID connection occurs.
Tools/TrustPoC/native.sh run SignumTrustProbe "$staging_dir/eu-lotl.xml"
curl --fail --silent --show-error --proto '=https' --connect-timeout 10 --max-time 45 --max-filesize 67108864 \
  https://eidas.agid.gov.it/TL/TSL-IT.xml -o "$staging_dir/it.xml"
Tools/TrustPoC/native.sh run --skip-build SignumTrustProbe "$staging_dir/eu-lotl.xml" "$staging_dir/it.xml" --snapshot "$output_dir/verified.json"
