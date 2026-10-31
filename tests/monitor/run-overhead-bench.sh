#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# run-overhead-bench.sh — Phase 3: the same pinned four-thread
# workload (tests/monitor/overhead-bench.c) on four vCPUs under three kernels
# states, REPEAT times each:
#
#   off        minimal profile with CONFIG_ANTINOMIE=n, bench as initramfs /init
#   idle       the shipped minimal kernel, bench as /init (never monitored)
#   recording  the shipped BusyBox bundle, bench launched through the monitor
#
#   usage: tests/monitor/run-overhead-bench.sh BUNDLE OUT_DIR [REPEAT]
#
# The off/idle boots use the backend's accelerator, machine type and default
# CPU model, but no disk or display devices. Recording data goes to tmpfs.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
bundle=$(realpath "$1")
out=$(realpath -m "$2")
repeat=${3:-3}
source_tree="$repo/work/debian-6.12.94-1-trixie/core"
on_tree="$repo/work/monitor-build"
off_tree="$repo/work/monitor-build-noant"
mkdir -p "$out" "$off_tree"

cc -static -O2 -Wall -Wextra -Werror -pthread "$repo/tests/monitor/overhead-bench.c" \
    -o "$out/overhead-bench"

# The off kernel is the shipped minimal configuration with only Antinomie off.
cp "$on_tree/.config" "$off_tree/.config"
"$source_tree/scripts/config" --file "$off_tree/.config" --disable ANTINOMIE
make -C "$source_tree" O="$off_tree" olddefconfig >/dev/null
if grep -q '^CONFIG_ANTINOMIE=y' "$off_tree/.config"; then
    echo "CONFIG_ANTINOMIE survived in the off kernel" >&2
    exit 1
fi
make -C "$source_tree" O="$off_tree" -j"${JOBS:-8}" bzImage >"$out/off-kernel-build.log" 2>&1
scripts_diff=$("$source_tree/scripts/diffconfig" "$on_tree/.config" "$off_tree/.config")
printf '%s\n' "$scripts_diff" >"$out/off-config-diff.txt"

cat >"$out/initramfs.list" <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
file /init $out/overhead-bench 0755 0 0
EOF
"$on_tree/usr/gen_init_cpio" "$out/initramfs.list" >"$out/initramfs.cpio"

boot() {
    local label=$1 kernel=$2 log=$3
    timeout 300 qemu-system-x86_64 -accel kvm -machine q35 -m 1024 -smp 4 \
        -kernel "$kernel" -initrd "$out/initramfs.cpio" \
        -append "console=ttyS0 quiet panic=-1 -- $label" \
        -nographic -no-reboot -monitor none >"$log" 2>&1
    grep -q 'BENCH DONE failures=0' "$log"
}

for round in $(seq 1 "$repeat"); do
    boot off "$off_tree/arch/x86/boot/bzImage" "$out/off-$round.log"
    boot idle "$on_tree/arch/x86/boot/bzImage" "$out/idle-$round.log"
    data="/dev/shm/antinomie-bench-$round"
    rm -rf "$data"
    cat >"$out/recording-$round.json" <<EOF
{"data_dir": "$data", "headless": true, "import": "$bundle",
 "vm": {"name": "Overhead bench", "cpus": 4, "ram_mib": 1024, "disk_gib": 1},
 "boot_timeout": 60,
 "uploads": [{"source": "$out/overhead-bench", "destination": "/tmp/overhead-bench"}],
 "runs": [{"path": "/tmp/overhead-bench", "args": ["recording"], "uid": 1000, "gid": 1000,
           "done": "BENCH DONE", "timeout": 300}]}
EOF
    "$repo/src/antinomie/monitor/target/debug/examples/guest-run" "$out/recording-$round.json" \
        >"$out/recording-$round.report.json" 2>"$out/recording-$round.err"
    rm -rf "$data"
done
python3 "$repo/tests/monitor/summarize-overhead.py" "$out"
