#!/usr/bin/env bash
#
# build-monitor-kernel.sh — build the patched guest kernel for one profile.
#
#   usage: scripts/build-monitor-kernel.sh [minimal|debian]
#
# Environment: ANTINOMIE_SOURCE_TREE, ANTINOMIE_BUILD_TREE, ANTINOMIE_DEBIAN_CONFIG
# and ANTINOMIE_SERIES_DIR replace the repository work-tree defaults.
# ANTINOMIE_PRINT_TOOLCHAIN=1 prints the compiler's and the linker's version
# lines as the kernel records them in its banner ("cc: ...", "ld: ...") and
# builds nothing.
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
# The minimal profile compiles with Debian 13's own compiler where the host has
# it (Debian's kernel build names x86_64-linux-gnu-gcc-14, as /proc/version
# then shows); the debian profile keeps the host's gcc. The banner records the
# first line of each tool's --version (scripts/mkcompile_h, CC_VERSION_TEXT).
cc=gcc
if [[ $profile == minimal ]] && command -v x86_64-linux-gnu-gcc-14 >/dev/null; then
    cc=x86_64-linux-gnu-gcc-14
fi
if [[ ${ANTINOMIE_PRINT_TOOLCHAIN:-0} == 1 ]]; then
    printf 'cc: %s\nld: %s\n' "$("$cc" --version | head -n 1)" "$(ld --version | head -n 1)"
    exit 0
fi
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
[[ $cc == gcc ]] || compiler=(CC="$cc" HOSTCC="$cc")
if [[ -n ${ANTINOMIE_CCACHE_DIR:-} ]] && command -v ccache >/dev/null; then
    export CCACHE_DIR=$ANTINOMIE_CCACHE_DIR CCACHE_MAXSIZE=${CCACHE_MAXSIZE:-8G}
    export CCACHE_BASEDIR=$source_tree CCACHE_NOHASHDIR=1 CCACHE_COMPILERCHECK=content
    mkdir -p "$CCACHE_DIR"
    compiler=(CC="ccache $cc" HOSTCC="ccache $cc")
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

# The build string (/proc/version, uname -v) is the one Debian's own build of
# the pinned package writes (debian/rules.real): the kernel team's address, the
# package version and its changelog date. Never the name of the user and the
# machine that built this kernel, nor the time; the build is reproducible.
adapter="$repo/src/antinomie/packaging/debian-6.12.94-1-trixie/adapter.conf"
adapter_value() { sed -n "s/^$1=//p" "$adapter"; }
source_version=$(adapter_value SOURCE_VERSION)
source_epoch=$(adapter_value SOURCE_DATE_EPOCH)
maintainer=$(adapter_value SOURCE_MAINTAINER)
[[ $source_version && $source_epoch =~ ^[0-9]+$ && $maintainer == *@* ]] ||
    { echo "build identity missing from $adapter" >&2; exit 1; }
export KBUILD_BUILD_USER=${maintainer%@*} KBUILD_BUILD_HOST=${maintainer#*@}
export KBUILD_BUILD_VERSION=1 KBUILD_BUILD_TIMESTAMP="@$source_epoch"
KBUILD_BUILD_VERSION_TIMESTAMP="Debian $source_version ($(date -u -d "@$source_epoch" +%F))"
export KBUILD_BUILD_VERSION_TIMESTAMP

# Symbols pinned Debian 13 enables that syscall coverage and realism depend on.
# SECURITY_DMESG_RESTRICT: as on Debian, only root reads the kernel log.
DEBIAN_PARITY="BPF_SYSCALL BPF_JIT CHECKPOINT_RESTORE KEYS KEY_DH_OPERATIONS
    SECURITY_YAMA USER_NS SECURITY_DMESG_RESTRICT"
# Enabled in the minimal profile only, for prctl coverage; pinned Debian leaves
# both unset, so the debian profile keeps them off.
MINIMAL_EXTRA="ANON_VMA_NAME SCHED_CORE"
# Root disk controllers the stealth profile offers besides virtio (SATA through
# q35's AHCI, NVMe), built in for the minimal profile: the bootstrap initrd has
# no module loader. The Debian profile keeps Debian's modules (virtio root only).
DISK_BUSES="ATA SATA_AHCI SCSI BLK_DEV_SD BLK_DEV_NVME"
# Debian 13's configuration where a program can see it (uname, /proc,
# /sys/kernel/security/lsm, the cgroup controllers, /proc/filesystems,
# perf_event_paranoid, kernel_max), for the minimal profile: the pinned
# package's LSM set and order with AppArmor active, the memory controller and
# cgroup BPF, HZ 250, 8192 CPUs, its hardening and scheduler defaults, efivarfs
# built in (no module loader at boot), FUSE, nftables and fq_codel; no 9p, no
# cgroup debug controller, no legacy TIOCSTI.
DEBIAN_SHAPE="SECURITY SECURITYFS SECURITY_NETWORK SECURITY_PATH AUDIT
    SECURITY_APPARMOR SECURITY_APPARMOR_HASH DEFAULT_SECURITY_APPARMOR SECURITY_LANDLOCK
    SECURITY_LOCKDOWN_LSM LOCK_DOWN_KERNEL_FORCE_NONE SECURITY_TOMOYO BPF_LSM SECURITY_IPE
    INTEGRITY IMA EVM MEMCG CGROUP_BPF DEBUG_KERNEL MAXSMP HZ_250
    SECURITY_PERF_EVENTS_RESTRICT EFIVAR_FS FANOTIFY FANOTIFY_ACCESS_PERMISSIONS FUSE_FS
    NF_TABLES NF_TABLES_INET NET_SCH_FQ_CODEL NET_SCH_DEFAULT DEFAULT_FQ_CODEL SCHED_AUTOGROUP
    INIT_ON_ALLOC_DEFAULT_ON HARDENED_USERCOPY SLAB_FREELIST_HARDENED SLAB_FREELIST_RANDOM"
DEBIAN_SHAPE_OFF="CGROUP_DEBUG NET_9P 9P_FS LEGACY_TIOCSTI NETCONSOLE HZ_1000 DEFAULT_SECURITY_SELINUX
    DEFAULT_PFIFO_FAST"
DEBIAN_LSM="landlock,lockdown,yama,loadpin,safesetid,integrity,apparmor,selinux,smack,tomoyo,bpf,ipe"
# Debian's kernel release suffix (uname -r 6.12.94+deb13-amd64).
DEBIAN_LOCALVERSION="+deb13-amd64"
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
        USB_XHCI_HCD USB_XHCI_PCI USB_HID RTC_CLASS RTC_DRV_CMOS $DISK_BUSES \
        $DEBIAN_PARITY $MINIMAL_EXTRA $DEBIAN_SHAPE; do
        "$config" --file "$build_tree/.config" --enable "$symbol"
    done
    for symbol in IKCONFIG_PROC $DEBIAN_SHAPE_OFF; do
        "$config" --file "$build_tree/.config" --disable "$symbol"
    done
    "$config" --file "$build_tree/.config" --set-str LSM "$DEBIAN_LSM"
    # The release is Debian's, 6.12.94+deb13-amd64, also when an author tree is
    # a git checkout (no -g<commit>, no extra "+").
    "$config" --file "$build_tree/.config" --set-str LOCALVERSION "$DEBIAN_LOCALVERSION"
    "$config" --file "$build_tree/.config" --disable LOCALVERSION_AUTO
    # DWARF in vmlinux, for the base's Volatility symbol table (as Debian),
    # and BTF from it (/sys/kernel/btf, as Debian: systemd's bpf-restrict-fs
    # needs it), which takes pahole; the series keeps the recorder out of it.
    "$config" --file "$build_tree/.config" --disable DEBUG_INFO_NONE \
        --enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT --enable DEBUG_INFO_BTF \
        --enable DEBUG_INFO_BTF_MODULES
    "$config" --file "$build_tree/.config" --set-str INITRAMFS_SOURCE ""
    "$config" --file "$build_tree/.config" --set-str ANTINOMIE_SOURCE_ID "$source_id"
    make -C "$source_tree" O="$build_tree" "${compiler[@]}" olddefconfig
    # shellcheck disable=SC2086
    require_symbols ANTINOMIE IKCONFIG DEBUG_INFO $DISK_BUSES $DEBIAN_PARITY $MINIMAL_EXTRA \
        $DEBIAN_SHAPE
    require_symbols DEBUG_INFO_BTF DEBUG_INFO_BTF_MODULES ||
        { echo "DEBUG_INFO_BTF takes pahole 1.21 or newer (package dwarves)" >&2; exit 1; }
    grep -qx 'CONFIG_HZ=250' "$build_tree/.config" && grep -qx 'CONFIG_NR_CPUS=8192' "$build_tree/.config" &&
        grep -qxF "CONFIG_LSM=\"$DEBIAN_LSM\"" "$build_tree/.config" ||
        { echo "Debian's HZ, NR_CPUS or LSM order did not survive olddefconfig" >&2; exit 1; }
    require_source_id
    # Debian's own configuration as the pinned package resolves it: the base's
    # /boot/config (the running kernel's would name the profile).
    fragments=("$debian_config/config" "$debian_config/kernelarch-x86/config"
               "$debian_config/amd64/config")
    if [[ -f ${fragments[0]} ]]; then
        rm -rf "$build_tree/debian-reference"
        mkdir -p "$build_tree/debian-reference"
        cat "${fragments[@]}" > "$build_tree/debian-reference/.config"
        make -C "$source_tree" O="$build_tree/debian-reference" "${compiler[@]}" olddefconfig >/dev/null
        mv "$build_tree/debian-reference/.config" "$build_tree/debian-config"
        rm -rf "$build_tree/debian-reference"
    fi
    # The few options the profile leaves modular (netfilter targets, a thermal
    # driver) are built and installed, so the base carries a module tree.
    make -C "$source_tree" O="$build_tree" "${compiler[@]}" LOCALVERSION= -j"$jobs" bzImage modules
    [[ ${ANTINOMIE_CCACHE_DIR:-} == "" ]] || ! command -v ccache >/dev/null || ccache --show-stats >&2
    rm -rf "$build_tree/modules-install"
    make -C "$source_tree" O="$build_tree" "${compiler[@]}" LOCALVERSION= \
        INSTALL_MOD_PATH="$build_tree/modules-install" INSTALL_MOD_STRIP=1 modules_install >/dev/null
    # The guest reads this BTF: nothing of the recorder may be in it.
    python3 "$repo/scripts/check-kernel-btf.py" --vmlinux "$build_tree/vmlinux" \
        --system-map "$build_tree/System.map" --modules "$build_tree/modules-install"
    # The banner /proc/version shows. Debian Minimal's must be Debian's own
    # (KERNEL_BANNER, which build-debian-image.py checks); only Debian 13's
    # compiler and linker write it.
    banner=$(strings -n 40 "$build_tree/vmlinux" | grep -m 1 '^Linux version .* #[0-9]' || true)
    printf '%s\n' "$banner" > "$build_tree/kernel-banner"
    echo "kernel banner: $banner" >&2
    expected=$(adapter_value KERNEL_BANNER)
    expected=${expected#\'}
    expected=${expected%\'}
    if [[ $banner != "$expected" ]]; then
        echo "warning: the banner is not Debian's ($expected); Debian Minimal needs a kernel" \
            "built with Debian 13's toolchain" >&2
    fi
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
python3 "$repo/scripts/check-kernel-btf.py" --vmlinux "$build_tree/vmlinux" \
    --system-map "$build_tree/System.map" --modules "$build_tree/modules-install"
echo "$build_tree/arch/x86/boot/bzImage"
