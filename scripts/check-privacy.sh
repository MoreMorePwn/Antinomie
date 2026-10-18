#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# check-privacy.sh — fail when tracked files name a developer machine: a home
# folder other than the guest and example accounts below, a WSL drive mount,
# a Windows drive path, an agent folder or the developer checkout's name.
#
#   usage: scripts/check-privacy.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Accounts that exist inside guests or stand for "any user" in examples.
allowed='analyst|user|me|builder|qauser|runner'
found=0
report() {
    if [[ -n $1 ]]; then
        printf '%s\n' "$1"
        found=1
    fi
}
report "$(git grep -nIE "/home/[A-Za-z0-9._-]+" -- . ':!scripts/check-privacy.sh' |
    grep -vE "/home/($allowed)([/\"': ]|\$)" || true)"
report "$(git grep -nIE '/mnt/[a-z]/|\b[C-Z]:\\\\|\.claude\b|\.codex\b|antinomie-work\b' \
    -- . ':!scripts/check-privacy.sh' ':!.gitignore' \
    ':!src/antinomie/monitor/crates/monitor-core/assets/rules' || true)"
if [[ $found == 1 ]]; then
    echo "machine-specific paths found (see above)" >&2
    exit 1
fi
echo "no machine-specific paths"
