#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# build-fixtures.sh — build the guest conformance fixtures.
#
#   usage: tests/monitor/conformance/build-fixtures.sh OUTPUT_DIR
#
# Static programs for the BusyBox guests (CC names the compiler, default gcc):
#   trace-fixture   the syscall trace oracle fixture (trace/fixture/*.c)
#   ant-workload     the stress samples (tests/monitor/workload), every module
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
output=${1:?usage: build-fixtures.sh OUTPUT_DIR}
mkdir -p "$output"

cc=${CC:-gcc}
cflags=(-static -O2 -g -Wall -Wextra -Werror -pthread -D_GNU_SOURCE)
fixture="$here/trace/fixture"
"$cc" "${cflags[@]}" -I"$fixture" "$fixture"/*.c -o "$output/trace-fixture"

workload="$here/../workload"
"$cc" -static -O2 -g -Wall -Wextra -Wno-unused-result -pthread -D_GNU_SOURCE -I"$workload" \
    "$workload"/main.c "$workload"/load.c "$workload"/process.c "$workload"/files.c \
    "$workload"/network.c "$workload"/kernel.c "$workload"/memory.c "$workload"/detect.c \
    "$workload"/indicators.c -o "$output/ant-workload"
echo "built $output/trace-fixture $output/ant-workload"
