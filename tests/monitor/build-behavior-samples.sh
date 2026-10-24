#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# build-behavior-samples.sh — build the Antinomie behavior samples.
#
#   usage: tests/monitor/build-behavior-samples.sh OUTPUT_DIR [--dynamic]
#
# Writes OUTPUT_DIR/ant-sample-all (every scenario) and one ant-sample-<scenario>
# per scenario. Static by default, so the samples run on the BusyBox and
# minimal guests; --dynamic links glibc like the default workload build.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source_dir="$here/behavior-samples"
output=${1:?usage: build-behavior-samples.sh OUTPUT_DIR [--dynamic]}
mode=${2:-}
mkdir -p "$output"
output=$(cd "$output" && pwd)

link=(-static)
case $mode in
    "") ;;
    --dynamic) link=() ;;
    *)
        echo "unknown option $mode" >&2
        exit 2
        ;;
esac

cflags=(-O2 -g -Wall -Wextra -D_GNU_SOURCE -I"$source_dir")
# Everything but main.c is compiled once; main.c carries the scenario choice.
shared=(common net beaconing discovery probes anti-analysis stage credential-access impact)
objects=$(mktemp -d)
trap 'rm -rf "$objects"' EXIT
for name in "${shared[@]}"; do
    gcc "${cflags[@]}" -c "$source_dir/$name.c" -o "$objects/$name.o"
done
link_all() { # SCENARIO-OR-EMPTY OUTPUT
    local define=()
    [[ -n $1 ]] && define=(-DSINGLE_SCENARIO="\"$1\"")
    gcc "${cflags[@]}" "${define[@]}" "$source_dir/main.c" "$objects"/*.o -o "$2" "${link[@]}" -lm
}
link_all "" "$output/ant-sample-all"
# The registry in main.c is the list of scenarios; build one binary for each.
mapfile -t scenarios < <("$output/ant-sample-all" --list | awk -F'\t' '!/^#/ {print $1}')
if [[ ${#scenarios[@]} -eq 0 ]]; then
    echo "ant-sample-all --list printed no scenarios" >&2
    exit 1
fi
for scenario in "${scenarios[@]}"; do
    link_all "$scenario" "$output/ant-sample-$scenario"
done

if [[ ${#link[@]} -gt 0 ]]; then
    for file in "$output"/ant-sample-* "$output/ant-sample-all"; do
        if readelf -lW "$file" | grep -q INTERP; then
            echo "$file is dynamically linked; rebuild statically" >&2
            exit 1
        fi
    done
fi

echo "built in $output:"
(cd "$output" && ls -1 ant-sample-* | sed 's/^/  /')
