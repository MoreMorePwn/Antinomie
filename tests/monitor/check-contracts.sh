#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Checks that the transport and control files the host builds from match the
# kernel's. The kernel's copy is what the canonical patch series
# (src/antinomie/core/6.12) produces, so the check replays the series' hunks
# for these files into a scratch folder and needs no kernel source tree; set
# ANTINOMIE_SOURCE_TREE to compare with a tree instead.
#
#   usage: check-contracts.sh [--update]
#
# --update copies the kernel's files over the host's copies (src/antinomie/
# transport, monitor/protocol/control.h) instead of failing on a difference.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
transport="$repo/src/antinomie/transport"
control="$repo/src/antinomie/monitor/protocol/control.h"
update=0
[[ "${1:-}" == "--update" ]] && update=1

kernel="${ANTINOMIE_SOURCE_TREE:-}"
if [[ -z "$kernel" ]]; then
    kernel=$(mktemp -d)
    trap 'rm -rf -- "$kernel"' EXIT
    includes=()
    for file in kernel/antinomie/{abi.h,bootstrap.c,bootstrap_layout.h,guest.c,queue.h,control_wire.h} \
        include/linux/antinomie.h; do
        includes+=("--include=$file")
    done
    # git apply outside a repository applies the patch to the working folder.
    (
        cd "$kernel"
        for patch in "$repo"/src/antinomie/core/6.12/*.patch; do
            git apply -p1 "${includes[@]}" "$patch"
        done
    )
fi

status=0
compare() { # host copy, kernel file
    if cmp -s "$1" "$2"; then
        return
    fi
    if ((update)); then
        cp -- "$2" "$1"
        echo "updated ${1#"$repo"/}"
    else
        echo "differs from the kernel's: ${1#"$repo"/} (kernel: ${2#"$kernel"/})" >&2
        diff -u "$1" "$2" | head -20 >&2 || true
        status=1
    fi
}
for name in abi.h bootstrap.c bootstrap_layout.h guest.c queue.h; do
    compare "$transport/$name" "$kernel/kernel/antinomie/$name"
done
compare "$transport/guest_api.h" "$kernel/include/linux/antinomie.h"
compare "$control" "$kernel/kernel/antinomie/control_wire.h"
if ((status)); then
    echo "Kernel/host contracts differ; run tests/monitor/check-contracts.sh --update" >&2
    exit 1
fi
echo "Kernel/host transport and control contracts match"
