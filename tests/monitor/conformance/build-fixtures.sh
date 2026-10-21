#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# build-fixtures.sh — build the guest conformance fixtures.
#
#   usage: tests/monitor/conformance/build-fixtures.sh OUTPUT_DIR
#
# Static x86-64 programs for the BusyBox guests:
#   trace-fixture   the syscall trace oracle fixture (trace/fixture/*.c)
#   ant-torture     the stress samples (tests/monitor/torture), every module
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
output=${1:?usage: build-fixtures.sh OUTPUT_DIR}
mkdir -p "$output"

cflags=(-static -O2 -g -Wall -Wextra -Werror -pthread -D_GNU_SOURCE)
fixture="$here/trace/fixture"
gcc "${cflags[@]}" -I"$fixture" "$fixture"/*.c -o "$output/trace-fixture"

torture="$here/../torture"
gcc -static -O2 -g -Wall -Wextra -Wno-unused-result -pthread -D_GNU_SOURCE -I"$torture" \
    "$torture"/main.c "$torture"/load.c "$torture"/process.c "$torture"/files.c \
    "$torture"/network.c "$torture"/kernel.c "$torture"/memory.c "$torture"/detect.c \
    "$torture"/indicators.c -o "$output/ant-torture"
echo "built $output/trace-fixture $output/ant-torture"
