#!/usr/bin/env bash
#
# build-monitor-kernel.sh — build the patched guest kernel for one profile.
#
#   usage: scripts/build-monitor-kernel.sh [minimal|debian]
#
# Environment: ANTINOMIE_SOURCE_TREE, ANTINOMIE_BUILD_TREE, ANTINOMIE_DEBIAN_CONFIG
# and ANTINOMIE_SERIES_DIR replace the repository work-tree defaults.
# ANTINOMIE_SOURCE_PREPARED=1 states that the caller (scripts/build-base.py)
# created the source tree itself from the pinned inputs and ANTINOMIE_SERIES_DIR,
# so the author-tree git check is skipped. ANTINOMIE_CCACHE_DIR compiles through
# ccache with that cache directory, when ccache is installed.
#
# minimal (default): upstream x86_64_defconfig plus the symbols below, all
#   built in, with DWARF debug information in vmlinux; output in
#   work/monitor-build. Used by the BusyBox base.
# debian: the pinned Debian amd64 configuration (debian/config/config, then
#   kernelarch-x86/config, then amd64/config) with only the deviations listed
#   in DEBIAN_BUILTIN and below; output in work/monitor-build-debian, with
#   stripped modules installed under modules-install/. Used by the Debian base.
#
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
profile=${1:-minimal}
source_tree=${ANTINOMIE_SOURCE_TREE:-"$repo/work/debian-6.12.94-1-trixie/core"}
debian_config=${ANTINOMIE_DEBIAN_CONFIG:-"$repo/work/debian-6.12.94-1-trixie/linux-6.12.94/debian/config"}
series_dir=${ANTINOMIE_SERIES_DIR:-"$repo/src/antinomie/core/6.12"}
prepared=${ANTINOMIE_SOURCE_PREPARED:-0}
jobs=${JOBS:-8}
case "$profile" in
    minimal) build_tree=${ANTINOMIE_BUILD_TREE:-"$repo/work/monitor-build"} ;;
    debian) build_tree=${ANTINOMIE_BUILD_TREE:-"$repo/work/monitor-build-debian"} ;;
    *) echo "usage: $0 [minimal|debian]" >&2; exit 2 ;;
esac
if [[ ! -f "$source_tree/kernel/antinomie/recorder.c" ]]; then
    echo "Guest recorder source missing from author tree" >&2
    exit 1
fi
if [[ $prepared != 1 ]]; then
    bash "$repo/tests/monitor/check-contracts.sh"
fi
mkdir -p "$build_tree"
config="$source_tree/scripts/config"
# A new patch series changes the source id in every object's configuration
# header but not their preprocessed code: ccache's preprocessor mode still
# hits, so only the files the series touched are compiled again.
compiler=()
if [[ -n ${ANTINOMIE_CCACHE_DIR:-} ]] && command -v ccache >/dev/null; then
    export CCACHE_DIR=$ANTINOMIE_CCACHE_DIR CCACHE_MAXSIZE=${CCACHE_MAXSIZE:-8G}
    export CCACHE_BASEDIR=$source_tree CCACHE_NOHASHDIR=1 CCACHE_COMPILERCHECK=content
    mkdir -p "$CCACHE_DIR"
    compiler=(CC="ccache gcc" HOSTCC="ccache gcc")
    ccache --zero-stats >/dev/null
fi

# The kernel states its source as CONFIG_ANTINOMIE_SOURCE_ID
# "<revision>:<series sha256>": the contract revision from the control header
# and a hash of the committed core patch list. Only a clean author tree that is
# exactly the pinned baseline plus that series, or a tree build-base.py created
# from them, gets one; ANTINOMIE_DEV_BUILD=1 builds an unversioned development
# kernel instead.
revision=$(awk '$1 == "#define" && $2 == "ANTC_REVISION" { print $3 }' \
    "$source_tree/kernel/antinomie/control_wire.h")
[[ $revision =~ ^[1-9][0-9]*$ ]] || { echo "ANTC_REVISION missing from control_wire.h" >&2; exit 1; }
source_id=""
shopt -s nullglob
patches=("$series_dir"/*.patch)
shopt -u nullglob
if [[ ${ANTINOMIE_DEV_BUILD:-0} == 1 ]]; then
    echo "development build: source not verified, kernel is unversioned" >&2
elif [[ ${#patches[@]} -eq 0 ]]; then
    echo "no core patches in $series_dir" >&2
    exit 1
elif [[ $prepared == 1 ]]; then
    series=$(cd "$series_dir" && sha256sum -- *.patch | sha256sum | cut -d' ' -f1)
    source_id="$revision:$series"
    echo "kernel source id $source_id (prepared tree)" >&2
else
    if [[ -n $(git -C "$source_tree" status --porcelain --untracked-files=no) ]]; then
        echo "author tree has uncommitted changes; commit and export them with" \
            "scripts/commit.sh, or set ANTINOMIE_DEV_BUILD=1" >&2
        exit 1
    fi
    index=$(mktemp)
    trap 'rm -f "$index"' EXIT
    GIT_INDEX_FILE=$index git -C "$source_tree" read-tree baseline/debian-6.12.94-1-trixie
    GIT_INDEX_FILE=$index git -C "$source_tree" apply --cached "${patches[@]}"
    expected=$(GIT_INDEX_FILE=$index git -C "$source_tree" write-tree)
    actual=$(git -C "$source_tree" rev-parse 'HEAD^{tree}')
    if [[ $expected != "$actual" ]]; then
        echo "author tree $actual is not baseline + core patch series ($expected);" \
            "export it with scripts/commit.sh or rebuild it with scripts/bootstrap.sh" >&2
        exit 1
    fi
    series=$(cd "$series_dir" && sha256sum -- *.patch | sha256sum | cut -d' ' -f1)
    source_id="$revision:$series"
    echo "kernel source id $source_id" >&2
fi

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

require_source_id() {
    if ! grep -qxF "CONFIG_ANTINOMIE_SOURCE_ID=\"$source_id\"" "$build_tree/.config"; then
        echo "CONFIG_ANTINOMIE_SOURCE_ID did not survive olddefconfig" >&2
        return 1
    fi
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
    # DWARF in vmlinux, for the base's Volatility symbol table (as Debian).
    "$config" --file "$build_tree/.config" --disable DEBUG_INFO_NONE \
        --enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
    "$config" --file "$build_tree/.config" --set-str INITRAMFS_SOURCE ""
    "$config" --file "$build_tree/.config" --set-str ANTINOMIE_SOURCE_ID "$source_id"
    make -C "$source_tree" O="$build_tree" olddefconfig
    # shellcheck disable=SC2086
    require_symbols ANTINOMIE IKCONFIG DEBUG_INFO $DEBIAN_PARITY $MINIMAL_EXTRA
    require_source_id
    make -C "$source_tree" O="$build_tree" "${compiler[@]}" -j"$jobs" bzImage
    [[ ${#compiler[@]} -eq 0 ]] || ccache --show-stats >&2
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
"$config" --file "$build_tree/.config" --set-str ANTINOMIE_SOURCE_ID "$source_id"
make -C "$source_tree" O="$build_tree" olddefconfig
# shellcheck disable=SC2086
require_symbols $DEBIAN_BUILTIN $DEBIAN_PARITY KERNEL_GZIP DEBUG_INFO
require_source_id
"$source_tree/scripts/diffconfig" "$reference/.config" "$build_tree/.config" \
    > "$build_tree/antinomie-config-deviations.txt"
# LOCALVERSION= keeps the release exactly 6.12.94 (no "+" for an untagged tree).
make -C "$source_tree" O="$build_tree" "${compiler[@]}" LOCALVERSION= -j"$jobs" bzImage modules
[[ ${#compiler[@]} -eq 0 ]] || ccache --show-stats >&2
rm -rf "$build_tree/modules-install"
make -C "$source_tree" O="$build_tree" LOCALVERSION= INSTALL_MOD_PATH="$build_tree/modules-install" \
    INSTALL_MOD_STRIP=1 modules_install >/dev/null
echo "$build_tree/arch/x86/boot/bzImage"
