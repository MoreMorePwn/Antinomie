#!/usr/bin/env bash
#
# commit.sh — turn one commit in an adapter's author repo into a DEP-3 Quilt
# patch, add it to the adapter's series, and stage everything in this repo.
#
#   usage: [ADAPTER=name] scripts/commit.sh [commit-ish]
#
# Prerequisite: the change is already committed in work/<adapter>/core.
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
SERIES="$VIEW/series"
COREDIR="$REPO/src/antinomie/core/$UPSTREAM_LINE"

[ -d "$CORE/.git" ] || { echo "commit: author repo missing; run scripts/bootstrap.sh first" >&2; exit 1; }
mkdir -p "$VIEW" "$COREDIR"

COMMIT="${1:-HEAD}"
cd "$CORE"
COMMIT="$(git rev-parse --verify "${COMMIT}^{commit}")"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "commit: uncommitted changes in $CORE; commit them first" >&2
  exit 1
fi

# ---- show what will become the patch ---------------------------------------
git show --stat --no-color --format='commit %h%n%s%n%n' "$COMMIT"
read -r -p "Show full diff? [y/N] " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
  git show --no-color --format= "$COMMIT" | ${PAGER:-less}
fi

# ---- DEP-3 metadata --------------------------------------------------------
subject="$(git log -1 --format=%s "$COMMIT")"
read -r -p "Description [$subject]: " desc; desc="${desc:-$subject}"
read -r -p "Long description (optional): " body
author="$(git log -1 --format='%an <%ae>' "$COMMIT")"
read -r -p "Author [$author]: " a; author="${a:-$author}"
read -r -p "Origin [project]: " origin; origin="${origin:-project}"
read -r -p "Forwarded [no]: " fwd; fwd="${fwd:-no}"
today="$(date +%F)"
read -r -p "Last-Update [$today]: " lu; lu="${lu:-$today}"
read -r -p "Bug/CVE (optional): " bug

# ---- next series number ----------------------------------------------------
last="$(ls "$VIEW" 2>/dev/null | sed -n 's/^\([0-9]\{4\}\)-.*/\1/p' | sort -n | tail -1)"
num="$(printf '%04d' $(( ${last:-0} + 1 )))"

# ---- filename --------------------------------------------------------------
slug="$(printf '%s' "$desc" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-')"
slug="${slug#-}"; slug="${slug%-}"; slug="${slug#antinomie-}"
fname="${num}-antinomie-${slug}.patch"

# ---- write the Quilt patch (DEP-3 header + diff) ---------------------------
{
  printf 'Description: %s\n' "$desc"
  printf 'Author: %s\n'      "$author"
  printf 'Origin: %s\n'      "$origin"
  printf 'Forwarded: %s\n'   "$fwd"
  printf 'Last-Update: %s\n' "$lu"
  [ -n "$bug" ] && printf 'Bug: %s\n' "$bug"
  printf '\n'
  [ -n "$body" ] && printf '%s\n' "$body"
  printf '\n---\n'
  git show --no-color --format= --no-ext-diff "$COMMIT"
} > "$VIEW/$fname"

# ---- add to the adapter series ---------------------------------------------
grep -qxF "$fname" "$SERIES" 2>/dev/null || printf '%s\n' "$fname" >> "$SERIES"

# ---- export the mail-format core patch -------------------------------------
corepatch="$(git format-patch -o "$COREDIR" --start-number "$((10#$num))" -1 "$COMMIT")"

# ---- stage in this repo ----------------------------------------------------
cd "$REPO"
git add "$VIEW/$fname" "$SERIES" "$corepatch"
git status --short

cat <<EOF

Patch written:  $VIEW/$fname
Series:         $SERIES
Core patch:     $corepatch

Next:
  git commit -m "antinomie: ${desc}"
  git push
EOF
