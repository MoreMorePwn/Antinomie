#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export ANTINOMIE_BUNDLE=${ANTINOMIE_BUNDLE:-"$repo/work/debian-6.12.94-1-trixie/images/monitor-base"}
exec cargo run --manifest-path "$repo/src/antinomie/monitor/Cargo.toml" \
    -p antinomie-monitor-ui -- "$@"
