#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# bootstrap.sh — build the disposable work trees for an adapter from the
# tracked text in src/. Safe to re-run; existing work trees are left as-is.
#
#   usage: scripts/bootstrap.sh [adapter]
#
# Produces, under work/<adapter>/:
#   <SOURCE_DIRNAME>/   extracted kernel tree (upstream + full Debian series)
#   core/               Git author repo based on that tree
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

ADAPTER="${1:-debian-6.12.94-1-trixie}"
PKG="$REPO/src/antinomie/packaging/$ADAPTER"
[ -d "$PKG" ] || { echo "bootstrap: no such adapter: $ADAPTER" >&2; exit 1; }
# shellcheck source=/dev/null
. "$PKG/adapter.conf"

WORK="$REPO/work/$ADAPTER"
TREE="$WORK/$SOURCE_DIRNAME"
CORE="$WORK/core"

say() { printf '[bootstrap] %s\n' "$*"; }

for t in git dpkg-source quilt sha256sum; do
  command -v "$t" >/dev/null || { echo "bootstrap: missing tool: $t" >&2; exit 1; }
done

say "adapter: $ADAPTER ($DISTRO $RELEASE, linux $SOURCE_VERSION)"

# 0. fetch the large upstream input on demand, then verify the pinned inputs
"$SCRIPT_DIR/fetch-inputs.sh" "$ADAPTER"
"$SCRIPT_DIR/verify-inputs.sh" "$ADAPTER"

# 1. extract the Quilt build tree (upstream + Debian main series)
if [ ! -d "$TREE" ]; then
  say "extracting to $TREE"
  mkdir -p "$WORK"
  cp "$REPO/$INPUT_DSC" "$REPO/$INPUT_ORIG" "$REPO/$INPUT_DEBTAR" "$WORK/"
  ( cd "$WORK" && dpkg-source -x "$(basename "$INPUT_DSC")" )
else
  say "build tree already present: $TREE"
fi

# 2. create the Git author tree on the Debian-patched baseline
if [ ! -d "$CORE/.git" ]; then
  say "creating author repo: $CORE"
  cp -a "$TREE" "$CORE"
  (
    cd "$CORE"
    git init -q
    git config user.email >/dev/null 2>&1 || git config user.email "antinomie@localhost"
    git config user.name  >/dev/null 2>&1 || git config user.name  "Antinomie Builder"
    printf '.pc/\ndebian/build/\ndebian/stamps/\n*.deb\n' >> .git/info/exclude
    # The kernel .gitignore ignores everything at the top level (`/*` with
    # `!/debian/`), which would hide the source tree and block adding new
    # files. Neutralise it in the author repo; .gitignore is not kernel code,
    # so this never reaches a generated patch.
    sed -i -e '/ignore everything at the top level/d' \
           -e '/included in our repository/d' \
           -e '/^\/\*$/d' -e '/^!\/debian\/$/d' .gitignore
    git add -A -f
    git reset -q -- .pc 2>/dev/null || true
    git commit -q -m "baseline: $ADAPTER ($SOURCE_VERSION)"
    git branch -M "$UPSTREAM_LINE"
    git tag "baseline/$ADAPTER"

    shopt -s nullglob
    patches=("$REPO"/src/antinomie/core/"$UPSTREAM_LINE"/*.patch)
    if [ ${#patches[@]} -gt 0 ]; then
      say "replaying ${#patches[@]} core patch(es)"
      git am "${patches[@]}"
      git tag "antinomie/$ADAPTER"
    else
      say "no core patches yet (first-patch bootstrap)"
    fi
  )
else
  say "author repo already present: $CORE"
fi

say "done"
say "next: edit in $CORE, commit, then run scripts/commit.sh"
