#!/usr/bin/env bash
#
# build-monitor-kernel.sh — build the patched guest kernel for one profile.
#
#   usage: scripts/build-monitor-kernel.sh [minimal|debian]
#
# minimal (default): upstream x86_64_defconfig plus the symbols below, all
#   built in; output in work/monitor-build. Used by the BusyBox base.
# debian: the pinned Debian amd64 configuration (debian/config/config, then
#   kernelarch-x86/config, then amd64/config) with only the deviations listed
#   in DEBIAN_BUILTIN and below; output in work/monitor-build-debian, with
#   stripped modules installed under modules-install/. Used by the Debian base.
#
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
profile=${1:-minimal}
source_tree="$repo/work/debian-6.12.94-1-trixie/core"
debian_config="$repo/work/debian-6.12.94-1-trixie/linux-6.12.94/debian/config"
jobs=${JOBS:-8}
case "$profile" in
    minimal) build_tree="$repo/work/monitor-build" ;;
    debian) build_tree="$repo/work/monitor-build-debian" ;;
    *) echo "usage: $0 [minimal|debian]" >&2; exit 2 ;;
esac
if [[ ! -f "$source_tree/kernel/antinomie/recorder.c" ]]; then
    echo "Guest recorder source missing from author tree" >&2
    exit 1
fi
bash "$repo/tests/monitor/check-contracts.sh"
mkdir -p "$build_tree"
config="$source_tree/scripts/config"

# Symbols pinned Debian 13 enables that syscall coverage and realism depend on.
DEBIAN_PARITY="BPF_SYSCALL BPF_JIT CHECKPOINT_RESTORE KEYS KEY_DH_OPERATIONS
    SECURITY_YAMA USER_NS"
# Enabled in the minimal profile only, for prctl coverage; pinned Debian leaves
# both unset, so the debian profile keeps them off.
MINIMAL_EXTRA="ANON_VMA_NAME SCHED_CORE"
# Built in for both profiles: the bootstrap initrd has no module loader, and the
# fixed display needs virtio-gpu before userspace starts.
DEBIAN_BUILTIN="ANTINOMIE UNIX98_PTYS IKCONFIG VIRTIO VIRTIO_PCI VIRTIO_BLK EXT4_FS
    DRM DRM_VIRTIO_GPU DRM_VIRTIO_GPU_KMS DRM_FBDEV_EMULATION FRAMEBUFFER_CONSOLE"

require_symbols() {
    local missing=0 symbol
    for symbol in "$@"; do
        if ! grep -qx "CONFIG_$symbol=y" "$build_tree/.config"; then
            echo "required CONFIG_$symbol=y did not survive olddefconfig" >&2
            missing=1
        fi
    done
    return "$missing"
}

if [[ $profile == minimal ]]; then
    if [[ ! -f "$build_tree/.config" ]]; then
        make -C "$source_tree" O="$build_tree" x86_64_defconfig
    fi
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
        USB_XHCI_HCD USB_XHCI_PCI USB_HID RTC_CLASS RTC_DRV_CMOS $DEBIAN_PARITY $MINIMAL_EXTRA; do
        "$config" --file "$build_tree/.config" --enable "$symbol"
    done
    "$config" --file "$build_tree/.config" --disable IKCONFIG_PROC
    "$config" --file "$build_tree/.config" --set-str INITRAMFS_SOURCE ""
    make -C "$source_tree" O="$build_tree" olddefconfig
    # shellcheck disable=SC2086
    require_symbols ANTINOMIE IKCONFIG $DEBIAN_PARITY $MINIMAL_EXTRA
    make -C "$source_tree" O="$build_tree" -j"$jobs" bzImage
    echo "$build_tree/arch/x86/boot/bzImage"
    exit 0
fi

fragments=("$debian_config/config" "$debian_config/kernelarch-x86/config"
           "$debian_config/amd64/config")
for fragment in "${fragments[@]}"; do
    [[ -f $fragment ]] || { echo "missing Debian config fragment $fragment; run scripts/bootstrap.sh" >&2; exit 1; }
done
# The unmodified Debian configuration, resolved by this tree, is kept beside the
# build so the deviations below are recorded rather than implied.
reference="$build_tree/debian-reference"
rm -rf "$reference"
mkdir -p "$reference"
cat "${fragments[@]}" > "$reference/.config"
make -C "$source_tree" O="$reference" olddefconfig >/dev/null
cp "$reference/.config" "$build_tree/.config"
for symbol in $DEBIAN_BUILTIN; do
    "$config" --file "$build_tree/.config" --enable "$symbol"
done
"$config" --file "$build_tree/.config" --disable IKCONFIG_PROC
# The image builders read the embedded configuration from a gzip bzImage
# (pinned format); Debian compresses with zstd.
"$config" --file "$build_tree/.config" --disable KERNEL_ZSTD --enable KERNEL_GZIP
# Debian's signing key is not available; the build generates its own.
"$config" --file "$build_tree/.config" --set-str MODULE_SIG_KEY "certs/signing_key.pem"
"$config" --file "$build_tree/.config" --set-str SYSTEM_TRUSTED_KEYS ""
"$config" --file "$build_tree/.config" --set-str SYSTEM_REVOCATION_KEYS ""
make -C "$source_tree" O="$build_tree" olddefconfig
# shellcheck disable=SC2086
require_symbols $DEBIAN_BUILTIN $DEBIAN_PARITY KERNEL_GZIP
"$source_tree/scripts/diffconfig" "$reference/.config" "$build_tree/.config" \
    > "$build_tree/antinomie-config-deviations.txt"
# LOCALVERSION= keeps the release exactly 6.12.94 (no "+" for an untagged tree).
make -C "$source_tree" O="$build_tree" LOCALVERSION= -j"$jobs" bzImage modules
rm -rf "$build_tree/modules-install"
make -C "$source_tree" O="$build_tree" LOCALVERSION= INSTALL_MOD_PATH="$build_tree/modules-install" \
    INSTALL_MOD_STRIP=1 modules_install >/dev/null
echo "$build_tree/arch/x86/boot/bzImage"
