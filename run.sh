#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# run.sh — start Antinomie from this checkout, rebuilding it first when
# anything it is built from changed (Cargo decides; an up-to-date build takes
# a second or two). Arguments go to the app, e.g. ./run.sh --data-dir DIR.
#
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bash "$repo/scripts/build-monitor-host.sh" >/dev/null
exec "$repo/scripts/run-monitor.sh" "$@"
