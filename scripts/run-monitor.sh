#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary="$repo/work/monitor-host/antinomie-monitor"
if [[ ! -x "$binary" ]]; then
    printf 'Host executable not found. Build it first: %s/scripts/build-monitor-host.sh\n' "$repo" >&2
    exit 1
fi
export ANTINOMIE_BUNDLE=${ANTINOMIE_BUNDLE:-"$repo/work/debian-6.12.94-1-trixie/images/monitor-base"}
exec "$binary" "$@"
