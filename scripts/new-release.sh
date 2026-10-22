#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
# Create a fresh version branch; never bump, push, or publish automatically.
set -euo pipefail

if [[ $# != 1 || ! $1 =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo 'usage: scripts/new-release.sh X.Y.Z' >&2
    exit 1
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
if [[ -n $(git status --porcelain=v1) ]]; then
    echo 'new-release: commit or preserve existing changes before starting a version' >&2
    exit 1
fi

current_version="$(python3 - "$1" <<'PY'
import sys
import re
from pathlib import Path

text = Path('src/antinomie/monitor/Cargo.toml').read_text()
section = re.search(r'(?ms)^\[workspace\.package\]\s*\n(.*?)(?=^\[|\Z)', text)
version = re.search(r'^version\s*=\s*"(\d+\.\d+\.\d+)"\s*(?:#.*)?$', section[1], re.M) if section else None
if version is None:
    raise SystemExit('new-release: cannot read the workspace package version')
current = version[1]
if tuple(map(int, sys.argv[1].split('.'))) <= tuple(map(int, current.split('.'))):
    raise SystemExit('new-release: the new version must be greater than the current version')
print(current)
PY
)"
if [[ $(git branch --show-current) != "release-$current_version" ]]; then
    echo "new-release: start from the current release-$current_version branch" >&2
    exit 1
fi

branch="release-$1"
if git show-ref --verify --quiet "refs/heads/$branch" ||
    git show-ref --verify --quiet "refs/remotes/origin/$branch"; then
    echo "new-release: $branch already exists; do not reuse a release branch" >&2
    exit 1
fi

git switch -c "$branch"
printf 'Created %s. Update the workspace version and changelog when implementing this release.\n' "$branch"
