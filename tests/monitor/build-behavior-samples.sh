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

cflags=(-O2 -g -Wall -Wextra -Wno-unused-result -D_GNU_SOURCE -I"$source_dir")
sources=("$source_dir/main.c" "$source_dir/net.c" "$source_dir/beaconing.c" "$source_dir/discovery.c"
         "$source_dir/anti-analysis.c" "$source_dir/credential-access.c")
scenarios=(recon http-beacon dns-tunnel tls-sni udp-beacon download dga persistence memfd-exec
           ptrace-antidebug cred-read rule-markers)

gcc "${cflags[@]}" "${sources[@]}" -o "$output/ant-sample-all" "${link[@]}"
for scenario in "${scenarios[@]}"; do
    gcc "${cflags[@]}" -DSINGLE_SCENARIO="\"$scenario\"" "${sources[@]}" \
        -o "$output/ant-sample-$scenario" "${link[@]}"
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
