#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_tree="$repo/work/debian-6.12.94-1-trixie/core"
build_tree="$repo/work/monitor-build"
jobs=${JOBS:-8}
if [[ ! -f "$source_tree/kernel/antinomie/recorder.c" ]]; then
    echo "Guest recorder source missing from author tree" >&2
    exit 1
fi
bash "$repo/tests/monitor/check-contracts.sh"
mkdir -p "$build_tree"
if [[ ! -f "$build_tree/.config" ]]; then
    make -C "$source_tree" O="$build_tree" x86_64_defconfig
fi
config="$source_tree/scripts/config"
for symbol in ANTINOMIE SMP UNIX98_PTYS DEVTMPFS DEVTMPFS_MOUNT EXT4_FS \
    VIRTIO VIRTIO_PCI VIRTIO_BLK VIRTIO_NET NET INET TTY VT VT_CONSOLE \
    VGA_CONSOLE SERIAL_8250 SERIAL_8250_CONSOLE BLK_DEV_INITRD RD_GZIP \
    PRINTK TMPFS PROC_FS SYSFS; do
    "$config" --file "$build_tree/.config" --enable "$symbol"
done
"$config" --file "$build_tree/.config" --set-str INITRAMFS_SOURCE ""
make -C "$source_tree" O="$build_tree" olddefconfig
make -C "$source_tree" O="$build_tree" -j"$jobs" bzImage
echo "$build_tree/arch/x86/boot/bzImage"
