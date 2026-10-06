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
    PRINTK TMPFS PROC_FS SYSFS IKCONFIG \
    CGROUPS CGROUP_PIDS FHANDLE INOTIFY_USER SIGNALFD TIMERFD EPOLL \
    UNIX SYSVIPC POSIX_MQUEUE SECCOMP SECCOMP_FILTER \
    TMPFS_POSIX_ACL TMPFS_XATTR EXT4_FS_POSIX_ACL EXT4_FS_SECURITY \
    DRM DRM_VIRTIO_GPU DRM_VIRTIO_GPU_KMS DRM_BOCHS DRM_FBDEV_EMULATION FB FRAMEBUFFER_CONSOLE \
    INPUT INPUT_EVDEV INPUT_KEYBOARD INPUT_MOUSE KEYBOARD_ATKBD MOUSE_PS2 \
    SERIO SERIO_I8042 VIRTIO_INPUT HID HID_GENERIC USB_SUPPORT USB \
    USB_XHCI_HCD USB_XHCI_PCI USB_HID RTC_CLASS RTC_DRV_CMOS; do
    "$config" --file "$build_tree/.config" --enable "$symbol"
done
"$config" --file "$build_tree/.config" --disable IKCONFIG_PROC
"$config" --file "$build_tree/.config" --set-str INITRAMFS_SOURCE ""
make -C "$source_tree" O="$build_tree" olddefconfig
make -C "$source_tree" O="$build_tree" -j"$jobs" bzImage
echo "$build_tree/arch/x86/boot/bzImage"
