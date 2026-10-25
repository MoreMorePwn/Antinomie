#!/usr/bin/env bash
#
# commit.sh — export one commit of an adapter's author repo as the next patch
# of the guest series, regenerate the Quilt view, and stage both in this repo.
#
#   usage: [ADAPTER=name] scripts/commit.sh [commit-ish]
#
# Prerequisite: the change is already committed in work/<adapter>/core. The
# mail-format patch in src/antinomie/core/<line> is the canonical copy; the
# DEP-3 Quilt patch is generated from it by scripts/sync-quilt-view.py, with
# the commit's subject as Description and its body as the long description (a
# last paragraph of Origin:/Forwarded:/Bug: lines sets those fields). See
# src/antinomie/patches/README.md for changing an existing topic patch instead.
# Afterwards the generated files are staged; finish with a normal
# `git commit` / `git push` in this repository.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

ADAPTER="${ADAPTER:-debian-6.12.94-1-trixie}"
PKG="$REPO/src/antinomie/packaging/$ADAPTER"
[ -d "$PKG" ] || { echo "commit: no such adapter: $ADAPTER" >&2; exit 1; }
# shellcheck source=/dev/null
. "$PKG/adapter.conf"

CORE="$REPO/work/$ADAPTER/core"
VIEW="$REPO/src/antinomie/patches/$ADAPTER/antinomie"
COREDIR="$REPO/src/antinomie/core/$UPSTREAM_LINE"

[ -e "$CORE/.git" ] || { echo "commit: author repo missing; run scripts/bootstrap.sh first" >&2; exit 1; }
mkdir -p "$VIEW" "$COREDIR"

COMMIT="${1:-HEAD}"
cd "$CORE"
COMMIT="$(git rev-parse --verify "${COMMIT}^{commit}")"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "commit: uncommitted changes in $CORE; commit them first" >&2
  exit 1
fi

# ---- show what will become the patch ---------------------------------------
git show --stat --no-color --format='commit %h%n%s%n%n%b' "$COMMIT"
read -r -p "Show full diff? [y/N] " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
  git show --no-color --format= "$COMMIT" | ${PAGER:-less}
fi
read -r -p "Export it as the next series patch? [y/N] " ans
[[ "$ans" =~ ^[Yy]$ ]] || exit 1

# ---- next series number ----------------------------------------------------
last="$(ls "$COREDIR" 2>/dev/null | sed -n 's/^\([0-9]\{4\}\)-.*/\1/p' | sort -n | tail -1)"
# 10# keeps zero-padded numbers such as 0008 from being read as octal.
num=$(( 10#${last:-0} + 1 ))

# ---- export the canonical patch, then derive the Quilt view ----------------
corepatch="$(git format-patch -N -o "$COREDIR" --start-number "$num" -1 "$COMMIT")"
python3 "$REPO/scripts/sync-quilt-view.py"

# ---- stage in this repo ----------------------------------------------------
cd "$REPO"
git add "$corepatch" "$VIEW"
git status --short

cat <<EOF

Core patch:     $corepatch
Quilt view:     $VIEW (regenerated)

Next:
  git commit -m "$(git -C "$CORE" log -1 --format=%s "$COMMIT")"
  git push
EOF
