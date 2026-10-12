#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: bash scripts/verify-cades-local.sh <signed.p7m> <original-document>" >&2
  exit 2
fi

SIGNED="$1"
ORIGINAL="$2"
TMP_FILE="$(mktemp /tmp/signum-cms-verify.XXXXXX)"
trap 'rm -f "$TMP_FILE"' EXIT

echo "Checking CMS cryptographic integrity with OpenSSL (TRUST NOT VERIFIED)..."
openssl cms -verify -inform DER -binary -noverify -in "$SIGNED" -out "$TMP_FILE"
cmp "$ORIGINAL" "$TMP_FILE"

echo "Verified OK — CMS signature and encapsulated document match."
echo "Warning: This DOES NOT verify eIDAS qualification, revocation, certificate chain or ETSI baseline profile."
