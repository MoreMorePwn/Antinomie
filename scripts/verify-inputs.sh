#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# verify-inputs.sh — verify the pinned Debian source inputs against the hashes
# recorded in the adapter. Refuses to continue on any mismatch.
#
#   usage: scripts/verify-inputs.sh [adapter]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

ADAPTER="${1:-debian-6.12.94-1-trixie}"
PKG="$REPO/src/antinomie/packaging/$ADAPTER"
[ -d "$PKG" ] || { echo "verify-inputs: no such adapter: $ADAPTER" >&2; exit 1; }
# shellcheck source=/dev/null
. "$PKG/adapter.conf"

check() {
  local file="$1" expected="$2" got
  [ -f "$file" ] || { echo "verify-inputs: missing file: $file" >&2; exit 1; }
  got="$(sha256sum "$file" | awk '{print $1}')"
  if [ "$got" != "$expected" ]; then
    printf 'verify-inputs: hash mismatch: %s\n  expected %s\n  got      %s\n' \
      "$file" "$expected" "$got" >&2
    exit 1
  fi
  printf 'verify-inputs: ok %s\n' "$file"
}

check "$REPO/$INPUT_ORIG"   "$INPUT_SHA_ORIG"
check "$REPO/$INPUT_DEBTAR" "$INPUT_SHA_DEBTAR"
