#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
kernel="$repo/work/debian-6.12.94-1-trixie/core"
transport="$repo/src/antinomie/transport"
for name in abi.h bootstrap.c bootstrap_layout.h guest.c queue.h; do
    cmp "$transport/$name" "$kernel/kernel/antinomie/$name"
done
cmp "$transport/guest_api.h" "$kernel/include/linux/antinomie.h"
cmp "$repo/src/antinomie/monitor/protocol/control.h" \
    "$kernel/kernel/antinomie/control_wire.h"
echo "Kernel/host contracts match; V7 sources unchanged"
