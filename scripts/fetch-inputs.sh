#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# fetch-inputs.sh — ensure the pinned Debian source inputs are present and match
# the adapter's recorded SHA-256. Only the large upstream orig tarball is fetched
# on demand; the small .dsc and .debian.tar.xz stay tracked in git.
#
# Source order: the live Debian pool first, then snapshot.debian.org as a
# permanent fallback (the archive path is discovered from the package page).
#
#   usage: scripts/fetch-inputs.sh [adapter]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

ADAPTER="${1:-debian-6.12.94-1-trixie}"
PKG="$REPO/src/antinomie/packaging/$ADAPTER"
[ -d "$PKG" ] || { echo "fetch-inputs: no such adapter: $ADAPTER" >&2; exit 1; }
# shellcheck source=/dev/null
. "$PKG/adapter.conf"

DEST="$REPO/$INPUT_ORIG"
NAME="$(basename "$INPUT_ORIG")"

verify() {
  [ -f "$DEST" ] || return 1
  [ "$(sha256sum "$DEST" | awk '{print $1}')" = "$INPUT_SHA_ORIG" ]
}

if verify; then
  printf 'fetch-inputs: present and verified: %s\n' "$NAME"
  exit 0
fi

command -v curl >/dev/null || { echo "fetch-inputs: curl is required" >&2; exit 1; }
mkdir -p "$(dirname "$DEST")"
tmp="$(mktemp "$(dirname "$DEST")/.${NAME}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

try() {
  printf 'fetch-inputs: downloading %s\n' "$1"
  curl -fL --retry 3 --retry-delay 2 -C - -o "$tmp" "$1"
}

live="https://deb.debian.org/debian/pool/main/l/linux/$NAME"
if ! try "$live"; then
  echo "fetch-inputs: live pool failed; falling back to snapshot.debian.org" >&2
  page="https://snapshot.debian.org/package/linux/$SOURCE_VERSION/"
  snap_path="$(curl -fsL --max-time 60 "$page" \
    | grep -oE "/archive/debian/[0-9TZ]+/pool/main/l/linux/$NAME" | head -1 || true)"
  [ -n "$snap_path" ] || { echo "fetch-inputs: no snapshot path found for $NAME" >&2; exit 1; }
  try "https://snapshot.debian.org$snap_path"
fi

got="$(sha256sum "$tmp" | awk '{print $1}')"
if [ "$got" != "$INPUT_SHA_ORIG" ]; then
  printf 'fetch-inputs: hash mismatch for %s\n  expected %s\n  got      %s\n' \
    "$NAME" "$INPUT_SHA_ORIG" "$got" >&2
  exit 1
fi

mv -f "$tmp" "$DEST"
trap - EXIT
printf 'fetch-inputs: fetched and verified %s\n' "$NAME"