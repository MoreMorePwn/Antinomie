#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target_dir="$repo/src/antinomie/monitor/target"
output_dir="$repo/work/monitor-host"

cargo build --manifest-path "$repo/src/antinomie/monitor/Cargo.toml" \
    --target-dir "$target_dir" --release --locked \
    -p antinomie-monitor-ui --bin antinomie-monitor

mkdir -p "$output_dir"
staged=$(mktemp "$output_dir/.antinomie-monitor.XXXXXX")
trap 'rm -f "$staged"' EXIT
install -m 0755 "$target_dir/release/antinomie-monitor" "$staged"
mv -f "$staged" "$output_dir/antinomie-monitor"
printf 'Host executable: %s\n' "$output_dir/antinomie-monitor"
