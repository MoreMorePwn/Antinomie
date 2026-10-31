#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# build-monitor-kernel.sh — build the patched guest kernel for one profile.
#
#   usage: scripts/build-monitor-kernel.sh [minimal|stock]
#
# Environment: ANTINOMIE_SOURCE_TREE, ANTINOMIE_BUILD_TREE, ANTINOMIE_DEBIAN_CONFIG
# and ANTINOMIE_SERIES_DIR replace the repository work-tree defaults.
# ANTINOMIE_PRINT_TOOLCHAIN=1 prints the compiler's and the linker's version
# lines as the kernel records them in its banner ("cc: ...", "ld: ...") and
# builds nothing.
# ANTINOMIE_ARCH selects the guest architecture: x86_64 (default) or arm64,
# which cross-compiles with aarch64-linux-gnu-gcc-14 (the container image has
# Debian 13's). Each architecture's own symbols for the minimal profile are in
# src/antinomie/packaging/kconfig/<arch>/minimal.cfg. The stock profile is
# amd64's only for now (Debian arm64 follows the BusyBox arm64 base).
# ANTINOMIE_CONFIG_ONLY=1 stops once the minimal configuration is resolved and
# checked (the .config is in the build tree) and builds nothing.
# ANTINOMIE_SOURCE_PREPARED=1 states that the caller (scripts/build-base.py)
# created the source tree itself from the pinned inputs and ANTINOMIE_SERIES_DIR,
# so the author-tree git check is skipped. ANTINOMIE_CCACHE_DIR compiles through
# ccache with that cache directory, when ccache is installed.
#
# minimal (default): the architecture's upstream defconfig (x86_64_defconfig,
#   arm64's defconfig) plus the symbols below and the architecture's own, all
#   built in, with DWARF debug information in vmlinux; output in
#   work/monitor-build (work/monitor-build-arm64 for arm64). Used by the
#   BusyBox base.
# stock: the pinned Debian amd64 configuration (debian/config/config, then
#   kernelarch-x86/config, then amd64/config) with nothing changed but the
#   recorder (and the embedded configuration the image builders read): Debian's
#   module ABI, BTF, function tracer and module-signing certificate (the public
#   certificate of Debian's own build, module-signing.pem in the adapter), so
#   Debian's own signed modules load. Only the kernel image is built; output in
#   work/monitor-build-stock. Used by the Debian bases (Minimal and the
#   desktops), which install Debian's kernel packages. ANTINOMIE_DEBIAN_IMAGE names Debian's linux-image package
#   to compare the kernel's exports, BTF and traceable functions with.
#
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
profile=${1:-minimal}
source_tree=${ANTINOMIE_SOURCE_TREE:-"$repo/work/debian-6.12.94-1-trixie/core"}
debian_config=${ANTINOMIE_DEBIAN_CONFIG:-"$repo/work/debian-6.12.94-1-trixie/linux-6.12.94/debian/config"}
series_dir=${ANTINOMIE_SERIES_DIR:-"$repo/src/antinomie/core/6.12"}
prepared=${ANTINOMIE_SOURCE_PREPARED:-0}
jobs=${JOBS:-8}
arch=${ANTINOMIE_ARCH:-x86_64}
# Per architecture: the kernel's ARCH and cross prefix, its defconfig, image
# target, Debian configuration fragments (below debian/config), release suffix
# and the adapter key of Debian's banner for it.
case "$arch" in
    x86_64)
        kernel_arch=x86 cross="" defconfig=x86_64_defconfig image=bzImage
        image_path=arch/x86/boot/bzImage
        debian_fragments=(config kernelarch-x86/config amd64/config)
        debian_suffix=amd64 banner_key=KERNEL_BANNER tree_suffix=""
        shape_symbols=MAXSMP nr_cpus=8192 ;;
    arm64)
        kernel_arch=arm64 cross=aarch64-linux-gnu- defconfig=defconfig image=Image
        image_path=arch/arm64/boot/Image
        debian_fragments=(config arm64/config)
        debian_suffix=arm64 banner_key=KERNEL_BANNER_ARM64 tree_suffix=-arm64
        shape_symbols=ARM64_VA_BITS_52 nr_cpus=512 ;;
    *) echo "unknown ANTINOMIE_ARCH $arch (x86_64 or arm64)" >&2; exit 2 ;;
esac
case "$profile" in
    minimal) build_tree=${ANTINOMIE_BUILD_TREE:-"$repo/work/monitor-build$tree_suffix"} ;;
    stock) build_tree=${ANTINOMIE_BUILD_TREE:-"$repo/work/monitor-build-stock"} ;;
    *) echo "usage: $0 [minimal|stock]" >&2; exit 2 ;;
esac
if [[ $profile == stock && $arch != x86_64 ]]; then
    echo "the stock profile is built for amd64 only (Debian $arch comes later)" >&2
    exit 2
fi
# Both profiles compile with Debian 13's own compiler where the host has it
# (Debian's kernel build names x86_64-linux-gnu-gcc-14, as /proc/version then
# shows). A foreign architecture always takes Debian 13's cross compiler
# (aarch64-linux-gnu-gcc-14, the name Debian's arm64 build shows). The banner
# records the first line of each tool's --version (scripts/mkcompile_h,
# CC_VERSION_TEXT).
cc=gcc
if [[ -n $cross ]]; then
    cc=${cross}gcc-14
elif command -v x86_64-linux-gnu-gcc-14 >/dev/null; then
    cc=x86_64-linux-gnu-gcc-14
fi
if [[ ${ANTINOMIE_PRINT_TOOLCHAIN:-0} == 1 ]]; then
    printf 'cc: %s\nld: %s\n' "$("$cc" --version | head -n 1)" "$("${cross}ld" --version | head -n 1)"
    exit 0
fi
command -v "$cc" >/dev/null || { echo "compiler $cc is not installed" >&2; exit 1; }
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
# A cross build names the target with ARCH and CROSS_COMPILE (binutils) and
# keeps the host's gcc for host programs.
target=()
[[ -z $cross ]] || target=(ARCH="$kernel_arch" CROSS_COMPILE="$cross")
compiler=()
if [[ -n $cross ]]; then
    compiler=(CC="$cc")
elif [[ $cc != gcc ]]; then
    compiler=(CC="$cc" HOSTCC="$cc")
fi
if [[ -n ${ANTINOMIE_CCACHE_DIR:-} ]] && command -v ccache >/dev/null; then
    export CCACHE_DIR=$ANTINOMIE_CCACHE_DIR CCACHE_MAXSIZE=${CCACHE_MAXSIZE:-8G}
    export CCACHE_BASEDIR=$source_tree CCACHE_NOHASHDIR=1 CCACHE_COMPILERCHECK=content
    mkdir -p "$CCACHE_DIR"
    if [[ -n $cross ]]; then
        compiler=(CC="ccache $cc")
    else
        compiler=(CC="ccache $cc" HOSTCC="ccache $cc")
    fi
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
# both unset.
MINIMAL_EXTRA="ANON_VMA_NAME SCHED_CORE"
# Root disk controllers the stealth profile offers besides virtio (SATA through
# q35's AHCI, NVMe), built in for the minimal profile: the bootstrap initrd has
# no module loader. The stock profile keeps Debian's modules.
DISK_BUSES="ATA SATA_AHCI SCSI BLK_DEV_SD BLK_DEV_NVME"
# Debian 13's configuration where a program can see it (uname, /proc,
# /sys/kernel/security/lsm, the cgroup controllers, /proc/filesystems,
# perf_event_paranoid, kernel_max), for the minimal profile: the pinned
# package's LSM set and order with AppArmor active, the memory controller and
# cgroup BPF, HZ 250, its CPU count (8192 on amd64, 512 on arm64), its hardening and scheduler defaults, efivarfs
# built in (no module loader at boot), FUSE, nftables and fq_codel; no 9p, no
# cgroup debug controller, no legacy TIOCSTI.
DEBIAN_SHAPE="SECURITY SECURITYFS SECURITY_NETWORK SECURITY_PATH AUDIT
    SECURITY_APPARMOR SECURITY_APPARMOR_HASH DEFAULT_SECURITY_APPARMOR SECURITY_LANDLOCK
    SECURITY_LOCKDOWN_LSM LOCK_DOWN_KERNEL_FORCE_NONE SECURITY_TOMOYO BPF_LSM SECURITY_IPE
    INTEGRITY IMA EVM MEMCG CGROUP_BPF DEBUG_KERNEL $shape_symbols HZ_250
    SECURITY_PERF_EVENTS_RESTRICT EFIVAR_FS FANOTIFY FANOTIFY_ACCESS_PERMISSIONS FUSE_FS
    NF_TABLES NF_TABLES_INET NET_SCH_FQ_CODEL NET_SCH_DEFAULT DEFAULT_FQ_CODEL SCHED_AUTOGROUP
    INIT_ON_ALLOC_DEFAULT_ON HARDENED_USERCOPY SLAB_FREELIST_HARDENED SLAB_FREELIST_RANDOM"
DEBIAN_SHAPE_OFF="CGROUP_DEBUG NET_9P 9P_FS LEGACY_TIOCSTI NETCONSOLE HZ_1000 DEFAULT_SECURITY_SELINUX
    DEFAULT_PFIFO_FAST"
DEBIAN_LSM="landlock,lockdown,yama,loadpin,safesetid,integrity,apparmor,selinux,smack,tomoyo,bpf,ipe"
# Debian's kernel release suffix (uname -r 6.12.94+deb13-amd64, -arm64).
DEBIAN_LOCALVERSION="+deb13-$debian_suffix"

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

# The banner check of the minimal and stock profiles: a Debian base's must be
# Debian's own (KERNEL_BANNER, which build-debian-image.py checks); only Debian
# 13's compiler and linker write it.
check_banner() {
    local banner expected
    banner=$(strings -n 40 "$build_tree/vmlinux" | grep -m 1 '^Linux version .* #[0-9]' || true)
    printf '%s\n' "$banner" > "$build_tree/kernel-banner"
    echo "kernel banner: $banner" >&2
    expected=$(adapter_value "$banner_key")
    expected=${expected#\'}
    expected=${expected%\'}
    if [[ $banner != "$expected" ]]; then
        echo "warning: the banner is not Debian's ($expected); a Debian base needs a kernel" \
            "built with Debian 13's toolchain" >&2
    fi
}

if [[ $profile == minimal ]]; then
    if [[ ! -f "$build_tree/.config" ]]; then
        make -C "$source_tree" "${target[@]}" O="$build_tree" "$defconfig"
    fi
    # The architecture's own devices (consoles, keyboard, RTC, display).
    arch_symbols=$(sed -e 's/#.*//' "$repo/src/antinomie/packaging/kconfig/$arch/minimal.cfg")
    # shellcheck disable=SC2086
    for symbol in ANTINOMIE SMP UNIX98_PTYS DEVTMPFS DEVTMPFS_MOUNT EXT4_FS \
        VIRTIO VIRTIO_PCI VIRTIO_BLK VIRTIO_NET NET INET TTY VT VT_CONSOLE \
        BLK_DEV_INITRD RD_GZIP \
        PRINTK TMPFS PROC_FS SYSFS IKCONFIG \
        CGROUPS CGROUP_PIDS FHANDLE INOTIFY_USER SIGNALFD TIMERFD EPOLL \
        UNIX SYSVIPC POSIX_MQUEUE SECCOMP SECCOMP_FILTER \
        TMPFS_POSIX_ACL TMPFS_XATTR EXT4_FS_POSIX_ACL EXT4_FS_SECURITY \
        DRM DRM_VIRTIO_GPU DRM_VIRTIO_GPU_KMS DRM_FBDEV_EMULATION FB FRAMEBUFFER_CONSOLE \
        INPUT INPUT_EVDEV INPUT_KEYBOARD INPUT_MOUSE \
        VIRTIO_INPUT HID HID_GENERIC USB_SUPPORT USB \
        USB_XHCI_HCD USB_XHCI_PCI USB_HID RTC_CLASS $arch_symbols $DISK_BUSES \
        $DEBIAN_PARITY $MINIMAL_EXTRA $DEBIAN_SHAPE; do
        "$config" --file "$build_tree/.config" --enable "$symbol"
    done
    for symbol in IKCONFIG_PROC $DEBIAN_SHAPE_OFF; do
        "$config" --file "$build_tree/.config" --disable "$symbol"
    done
    "$config" --file "$build_tree/.config" --set-str LSM "$DEBIAN_LSM"
    # x86's MAXSMP sets its 8192; arm64 names Debian's count itself.
    [[ $arch == x86_64 ]] || "$config" --file "$build_tree/.config" --set-val NR_CPUS "$nr_cpus"
    # The release is Debian's, 6.12.94+deb13-amd64 (-arm64), also when an author tree is
    # a git checkout (no -g<commit>, no extra "+").
    "$config" --file "$build_tree/.config" --set-str LOCALVERSION "$DEBIAN_LOCALVERSION"
    "$config" --file "$build_tree/.config" --disable LOCALVERSION_AUTO
    # DWARF in vmlinux, for the base's Volatility symbol table (as Debian),
    # and BTF from it (/sys/kernel/btf, as Debian: systemd's bpf-restrict-fs
    # needs it), which takes pahole; the series keeps the recorder out of it.
    # Full DWARF: arm64's defconfig reduces it, which leaves no BTF.
    "$config" --file "$build_tree/.config" --disable DEBUG_INFO_NONE --disable DEBUG_INFO_REDUCED \
        --enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT --enable DEBUG_INFO_BTF \
        --enable DEBUG_INFO_BTF_MODULES
    "$config" --file "$build_tree/.config" --set-str INITRAMFS_SOURCE ""
    "$config" --file "$build_tree/.config" --set-str ANTINOMIE_SOURCE_ID "$source_id"
    make -C "$source_tree" "${target[@]}" O="$build_tree" "${compiler[@]}" olddefconfig
    # shellcheck disable=SC2086
    require_symbols ANTINOMIE IKCONFIG DEBUG_INFO $DISK_BUSES $DEBIAN_PARITY $MINIMAL_EXTRA \
        $DEBIAN_SHAPE
    require_symbols DEBUG_INFO_BTF DEBUG_INFO_BTF_MODULES ||
        { echo "DEBUG_INFO_BTF takes pahole 1.21 or newer (package dwarves)" >&2; exit 1; }
    grep -qx 'CONFIG_HZ=250' "$build_tree/.config" && grep -qx "CONFIG_NR_CPUS=$nr_cpus" "$build_tree/.config" &&
        grep -qxF "CONFIG_LSM=\"$DEBIAN_LSM\"" "$build_tree/.config" ||
        { echo "Debian's HZ, NR_CPUS or LSM order did not survive olddefconfig" >&2; exit 1; }
    require_source_id
    [[ ${ANTINOMIE_CONFIG_ONLY:-0} != 1 ]] || { echo "$build_tree/.config"; exit 0; }
    # Debian's own configuration as the pinned package resolves it: the base's
    # /boot/config (the running kernel's would name the profile).
    fragments=("${debian_fragments[@]/#/$debian_config/}")
    if [[ -f ${fragments[0]} ]]; then
        rm -rf "$build_tree/debian-reference"
        mkdir -p "$build_tree/debian-reference"
        cat "${fragments[@]}" > "$build_tree/debian-reference/.config"
        make -C "$source_tree" "${target[@]}" O="$build_tree/debian-reference" "${compiler[@]}" olddefconfig >/dev/null
        mv "$build_tree/debian-reference/.config" "$build_tree/debian-config"
        rm -rf "$build_tree/debian-reference"
    fi
    # The few options the profile leaves modular (netfilter targets, a thermal
    # driver) are built and installed, so the base carries a module tree.
    make -C "$source_tree" "${target[@]}" O="$build_tree" "${compiler[@]}" LOCALVERSION= -j"$jobs" "$image" modules
    [[ ${ANTINOMIE_CCACHE_DIR:-} == "" ]] || ! command -v ccache >/dev/null || ccache --show-stats >&2
    rm -rf "$build_tree/modules-install"
    make -C "$source_tree" "${target[@]}" O="$build_tree" "${compiler[@]}" LOCALVERSION= \
        INSTALL_MOD_PATH="$build_tree/modules-install" INSTALL_MOD_STRIP=1 modules_install >/dev/null
    # The guest reads this BTF: nothing of the recorder may be in it.
    python3 "$repo/scripts/check-kernel-btf.py" --vmlinux "$build_tree/vmlinux" \
        --system-map "$build_tree/System.map" --modules "$build_tree/modules-install"
    # The banner /proc/version shows.
    check_banner
    echo "$build_tree/$image_path"
    exit 0
fi

if [[ $profile == stock ]]; then
    fragments=("$debian_config/config" "$debian_config/kernelarch-x86/config"
               "$debian_config/amd64/config")
    for fragment in "${fragments[@]}"; do
        [[ -f $fragment ]] || { echo "missing Debian config fragment $fragment; run scripts/bootstrap.sh" >&2; exit 1; }
    done
    reference="$build_tree/debian-reference"
    rm -rf "$reference"
    mkdir -p "$reference"
    cat "${fragments[@]}" > "$reference/.config"
    make -C "$source_tree" O="$reference" "${compiler[@]}" olddefconfig >/dev/null
    cp "$reference/.config" "$build_tree/.config"
    cp "$reference/.config" "$build_tree/debian-config"
    rm -rf "$reference"
    # Debian's build signs its modules with a key it makes for that build
    # alone and builds that key's certificate in (debian/rules.real, as
    # output/signing_key.pem of the build tree); the certificate, read from
    # Debian's kernel, takes the same place here, so the kernel trusts exactly
    # Debian's modules. No key is generated and no module is signed.
    mkdir -p "$build_tree/output"
    cp "$repo/src/antinomie/packaging/debian-6.12.94-1-trixie/module-signing.pem" \
        "$build_tree/output/signing_key.pem"
    "$config" --file "$build_tree/.config" --set-str MODULE_SIG_KEY "output/signing_key.pem"
    "$config" --file "$build_tree/.config" --set-str SYSTEM_TRUSTED_KEYS ""
    # The image builders read the embedded configuration from a gzip bzImage;
    # nothing in the guest reads it (no /proc/config.gz).
    "$config" --file "$build_tree/.config" --enable ANTINOMIE --enable IKCONFIG \
        --disable IKCONFIG_PROC --disable KERNEL_ZSTD --enable KERNEL_GZIP
    "$config" --file "$build_tree/.config" --set-str LOCALVERSION "$DEBIAN_LOCALVERSION"
    # Debian's build salts the build ID note (/sys/kernel/notes) with the
    # release (debian/bin/gencontrol.py: BUILD_SALT).
    "$config" --file "$build_tree/.config" --set-str BUILD_SALT "6.12.94$DEBIAN_LOCALVERSION"
    "$config" --file "$build_tree/.config" --set-str ANTINOMIE_SOURCE_ID "$source_id"
    make -C "$source_tree" O="$build_tree" "${compiler[@]}" olddefconfig
    require_symbols ANTINOMIE IKCONFIG KERNEL_GZIP MODVERSIONS MODULE_SIG DEBUG_INFO_BTF \
        FUNCTION_TRACER DYNAMIC_FTRACE BPF_LSM
    require_source_id
    # Nothing else of Debian's configuration may change: no symbol the
    # recorder selects, no driver built in.
    "$source_tree/scripts/diffconfig" "$build_tree/debian-config" "$build_tree/.config" \
        > "$build_tree/antinomie-config-deviations.txt"
    allowed="ANTINOMIE|ANTINOMIE_SOURCE_ID|IKCONFIG|IKCONFIG_PROC|KERNEL_GZIP|KERNEL_ZSTD|LOCALVERSION|MODULE_SIG_KEY|BUILD_SALT"
    unexpected=$(grep -vE "^[-+ ]($allowed) " \
        "$build_tree/antinomie-config-deviations.txt" || true)
    if [[ -n $unexpected ]]; then
        echo "the stock profile changes Debian's configuration beyond the recorder:" >&2
        echo "$unexpected" >&2
        exit 1
    fi
    make -C "$source_tree" O="$build_tree" "${compiler[@]}" LOCALVERSION= -j"$jobs" bzImage
    [[ ${ANTINOMIE_CCACHE_DIR:-} == "" ]] || ! command -v ccache >/dev/null || ccache --show-stats >&2
    python3 "$repo/scripts/check-kernel-btf.py" --vmlinux "$build_tree/vmlinux" \
        --system-map "$build_tree/System.map"
    # Debian's exports, structure layouts and traceable functions.
    abi_check=("$repo/scripts/check-kernel-abi.py" --vmlinux "$build_tree/vmlinux"
               --system-map "$build_tree/System.map" --symvers "$build_tree/vmlinux.symvers")
    if [[ -n ${ANTINOMIE_DEBIAN_IMAGE:-} ]]; then
        abi_check+=(--debian-image "$ANTINOMIE_DEBIAN_IMAGE")
    fi
    python3 "${abi_check[@]}"
    check_banner
    echo "$build_tree/arch/x86/boot/bzImage"
    exit 0
fi
