#!/usr/bin/env python3
"""Build a Debian 13 bundle (a desktop, or the console-only Minimal base) for the
pinned Antinomie kernel with mmdebstrap.

The root filesystem is bootstrapped into a tarball (rootless with
--mode=unshare, or as root inside the QEMU builder) and turned into an ext4
image with mkfs.ext4 -d; no libguestfs appliance and no mounted host
filesystems are used.
"""
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import random
import re
import shlex
import shutil
import socket
import struct
import subprocess
import tarfile
import tempfile
import uuid

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "work/debian-xfce-base"
# The Debian installer's desktop choices: tasksel task, display manager,
# default session (an xsessions or wayland-sessions entry), label, minimum RAM.
DESKTOPS = {
    "xfce": ("task-xfce-desktop", "lightdm", "xfce", "Xfce", 2048),
    "gnome": ("task-gnome-desktop", "gdm3", "gnome", "GNOME", 4096),
    "gnome-flashback": ("task-gnome-flashback-desktop", "gdm3",
                        "gnome-flashback-metacity", "GNOME Flashback", 2048),
    "kde": ("task-kde-desktop", "sddm", "plasma", "KDE Plasma", 4096),
    "cinnamon": ("task-cinnamon-desktop", "lightdm", "cinnamon", "Cinnamon", 2048),
    "mate": ("task-mate-desktop", "lightdm", "mate", "MATE", 2048),
    "lxde": ("task-lxde-desktop", "lightdm", "LXDE", "LXDE", 2048),
    "lxqt": ("task-lxqt-desktop", "sddm", "lxqt", "LXQt", 2048),
}
# The installer's software choice with no desktop selected: the Debian Minimal
# base, console login only (serial and virtual terminals), no X or display
# manager. It keeps APT and the userspace below, boots in far less memory and
# needs no kernel modules when the kernel builds in CONSOLE_BUILTIN (the
# minimal kernel profile does).
CONSOLE = "none"
CONSOLE_PROFILE = {"id": "debian-minimal", "label": "Debian 13 (Minimal)",
                   "min_ram_mib": 1024, "min_disk_gib": 4,
                   "requires_credentials": True, "graphical": False}
CONSOLE_IMAGE_SIZE = 4 << 30
# What a module-less kernel must build in for the console base to boot, mount
# its root, run systemd and take a DHCP address.
CONSOLE_BUILTIN = ("EXT4_FS", "VIRTIO_BLK", "VIRTIO_NET", "DEVTMPFS", "CGROUPS", "FHANDLE",
                   "UNIX", "INET", "PACKET")


def profile(desktop):
    """Guest profile of the base: one per desktop, and the console base."""
    if desktop == CONSOLE:
        return dict(CONSOLE_PROFILE)
    label, ram = DESKTOPS[desktop][3], DESKTOPS[desktop][4]
    return {"id": "debian-" + desktop, "label": f"Debian 13 ({label})",
            "min_ram_mib": ram, "min_disk_gib": 16,
            "requires_credentials": True, "graphical": True}


PROFILE = profile("xfce")
APPEND = "root=/dev/vda rw rootwait console=tty0 console=ttyS0 panic=-1"
# The console base's command line is the one GRUB gives a Debian install: the
# kernel image, the root by filesystem UUID (each VM's own: the app names the
# UUID provisioning gave its disk), mounted read-only for the boot-time fsck,
# and quiet; no serial console and no panic=-1. The bootstrap initrd finds the
# UUID on whichever bus the stealth profile chose (virtio, SATA, NVMe).
CONSOLE_APPEND = "BOOT_IMAGE=/boot/vmlinuz-{release} root=UUID={uuid} ro quiet"
# The console base's disk is the installer's guided "all files in one
# partition" on a BIOS PC: an MBR table, the root at 1 MiB (bootable), where
# fstab's comment says the installer saw it. Provisioning grows the root to the
# VM's disk and adds the swap partition (sda5 in an extended sda2) for its RAM.
CONSOLE_ROOT_DEVICE = "/dev/sda1"
CONSOLE_ROOT_OFFSET = 1 << 20
CONSOLE_ROOT_SIZE = 3 << 30
FSTAB_HEADER = """# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# systemd generates mount units based on this file, see systemd.mount(5).
# Please run 'systemctl daemon-reload' after you make changes here.
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
"""
FSTAB_ROOT = "UUID={uuid} /               ext4    errors=remount-ro 0       1\n"
FSTAB_CDROM = "/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0\n"
HOSTS = """127.0.0.1	localhost
127.0.1.1	{hostname}

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
"""
# apt-setup's sources.list after a netinst install from a USB stick with the
# network mirror chosen ({media} is the image's label, {mirror} the mirror).
SOURCES_LIST = """#deb cdrom:[{media}]/ trixie contrib main non-free-firmware

deb {mirror}/ trixie main non-free-firmware
deb-src {mirror}/ trixie main non-free-firmware

deb http://security.debian.org/debian-security trixie-security main non-free-firmware
deb-src http://security.debian.org/debian-security trixie-security main non-free-firmware

# trixie-updates, to get updates before a point release is made;
# see https://www.debian.org/doc/manuals/debian-reference/ch02.en.html#_updates_and_backports
deb {mirror}/ trixie-updates main non-free-firmware
deb-src {mirror}/ trixie-updates main non-free-firmware

# This system was installed using small removable media
# (e.g. netinst, live or single CD). The matching "deb cdrom"
# entries were disabled at the end of the installation process.
# For information about how to use removable media with apt,
# see https://wiki.debian.org/AptMedia
"""
SUITE = "trixie"
SECURITY_MIRROR = "http://security.debian.org/debian-security"
IMAGE_SIZE = 16 << 30
NETWORK_INTERFACES = """source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
"""
# The desktop's task plus its recommends mirrors a Debian ISO desktop install
# (for Xfce: desktop-base, xfce4-goodies, power-manager, notifyd, locker, apps,
# fonts). Guest integration packages stay excluded per the kernel-only control
# contract.
PACKAGES = ("systemd-sysv", "sudo", "dbus-x11", "dbus-user-session", "network-manager",
            "xserver-xorg-input-libinput", "iproute2", "iputils-ping",
            "procps", "psmisc", "less", "vim-tiny", "curl", "wget",
            "ca-certificates", "file", "bash-completion", "locales",
            "fonts-dejavu-core", "e2fsprogs", "keyboard-configuration",
            "console-setup", "tzdata")
# The console base is what the Debian installer leaves with no desktop chosen:
# its "standard system utilities" task (mmdebstrap's standard variant: the
# required, important and standard priorities) with recommends (exim4 as the
# local MTA on 127.0.0.1:25, timesyncd, dbus-user-session, the ispell
# dictionaries), the installer's own additions below, and the language task
# tasksel picks for the locale (task-english for English). Each entry says why
# it is there; src/antinomie/packaging/debian-minimal-trixie/packages.txt is
# the committed manifest (requested and resolved packages of the verified build).
CONSOLE_PACKAGES = (
    ("tasksel", "the installer's task selector (tasksel-data names the language task)"),
    ("installation-report", "installed by the Debian installer"),
    ("discover", "the installer's hardware detection, kept on the installed system"),
    ("laptop-detect", "installed by the installer for tasksel's laptop question"),
    ("eject", "installed by the installer"),
    ("initramfs-tools", "the installer's initramfs generator (busybox, zstd by recommends)"),
    ("keyboard-configuration", "the chosen console keyboard layout"),
    ("console-setup", "applies the layout and font on the virtual terminals"),
    ("sudo", "the installer adds it when root gets no password; the per-VM account uses it"),
    ("grub-pc", "the installer's boot loader for a BIOS PC (each VM's grub.cfg is written for it)"),
    ("os-prober", "installed with GRUB by the installer"),
)
# The installer's interfaces file without its stanza for the wired NIC:
# provisioning writes that per VM for the interface its stealth profile's NIC
# slot gets (bundle stealth_support "onboardnic": enp0s25 at PCI 00:19.0,
# enp0s31f6 at 00:1f.6), so udev names it as on that machine whichever model
# the profile picks.
CONSOLE_INTERFACES = """# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback
"""
# apt's history names the commands mmdebstrap ran; the installer's read like
# this (its packages: those an entry installed on request).
HISTORY_AWK = r"""NR == FNR {
    if ($0 ~ /^Start-Date:/) n++
    if ($0 ~ /^Install: /) {
        list = ""
        count = split(substr($0, 10), items, /\), /)
        for (i = 1; i <= count; i++)
            if (items[i] !~ /automatic/) { split(items[i], name, ":"); list = list " " name[1] }
        packages[n] = list
    }
    next
}
/^Start-Date:/ { m++ }
/^Commandline:/ {
    print "Commandline: apt-get -o APT::Status-Fd=4 -o APT::Keep-Fds::=5 -o APT::Keep-Fds::=6 -q -y --no-remove install" packages[m]
    next
}
{ print }
"""
# Installer-style answers. Values are checked again inside the new system
# against its locale, keyboard and time zone data.
DEFAULTS = {"name": "", "desktop": "xfce", "hostname": "debian", "locale": "en_US.UTF-8",
            "keyboard_layout": "us",
            "keyboard_variant": "", "timezone": "Etc/UTC", "standard": False,
            "mirror": "http://deb.debian.org/debian", "proxy": ""}
# The installer preselects "standard system utilities"; the console base keeps
# that default when the answer is not given.
CONSOLE_DEFAULTS = {"standard": True}
PATTERNS = {"locale": r"[a-z]{2,3}(?:_[A-Z]{2})?(?:@[a-z]+)?\.UTF-8",
            "keyboard_layout": r"[a-z]{2,8}", "keyboard_variant": r"[a-z0-9_-]{0,32}",
            "timezone": r"[A-Z][A-Za-z_+-]*(?:/[A-Za-z0-9_+-]+){0,2}",
            "mirror": r"https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+",
            "proxy": r"(?:https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+)?"}
MIN_E2FSPROGS = (1, 47, 1)


def monitor_helpers():
    spec = importlib.util.spec_from_file_location(
        "monitor_image", REPO / "scripts/build-monitor-image.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def kernel_release(kernel):
    with kernel.open("rb") as source:
        header = source.read(0x210)
        if len(header) < 0x210 or header[0x202:0x206] != b"HdrS":
            raise RuntimeError("kernel must be an x86 Linux bzImage")
        source.seek(0x200 + struct.unpack_from("<H", header, 0x20e)[0])
        release = source.read(512).split(b"\0", 1)[0].decode("ascii")
    if not re.match(r"6\.12\.94(?:[-+ ]|$)", release):
        raise RuntimeError("kernel must retain pinned Linux 6.12.94")
    return release


def module_tree(modules, release):
    """Return the installed module directory matching the kernel release."""
    if modules is None:
        return None
    tree = modules / "lib/modules" / release.split()[0]
    if not (tree / "modules.dep").is_file():
        raise RuntimeError(f"--modules lacks lib/modules/{release.split()[0]}/modules.dep")
    return tree


def kernel_uses_modules(config):
    return config is not None and any(line.endswith("=m")
                                      for line in config.read_text().splitlines())


def built_in(config, symbols):
    """Whether the kernel config builds every symbol in (not as a module)."""
    if config is None:
        return False
    lines = set(config.read_text().splitlines())
    return all(f"CONFIG_{symbol}=y" in lines for symbol in symbols)


def initrd_provenance(root, provenance):
    notices = root / "usr/share/antinomie-initrd-provenance"
    files = {}
    packages = {}
    helpers = monitor_helpers()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path == root / "init":
            continue
        relative = str(path.relative_to(root))
        source = {"bin/busybox": Path("/usr/bin/busybox"),
                  "bin/resize2fs": Path(shutil.which("resize2fs"))}.get(
                      relative, Path("/") / relative)
        ownership = subprocess.check_output(
            ["dpkg-query", "--search", str(source.resolve())], text=True).splitlines()
        owner = ownership[0].split(": ", 1)[0]
        metadata = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n",
             owner], text=True).strip().split("\t")
        if len(metadata) != 5:
            raise RuntimeError("unexpected host package metadata for " + owner)
        packages[owner] = dict(zip(("package", "version", "architecture",
                                   "source_package", "source_version"), metadata))
        files["/" + relative] = {"package": owner, "sha256": helpers.checksum(path)}
    notices.mkdir(parents=True)
    for owner in sorted(packages):
        package = owner.split(":", 1)[0]
        target = notices / "packages" / package
        target.mkdir(parents=True)
        shutil.copy2(Path("/usr/share/doc") / package / "copyright", target / "copyright")
    shutil.copytree("/usr/share/common-licenses", notices / "common-licenses")
    shutil.copy2("/etc/os-release", notices / "host-os-release")
    shutil.copy2(REPO / "LICENSE", notices / "project-LICENSE")
    shutil.copy2(REPO / "scripts/build-monitor-image.py", notices / "bootstrap-recipe.py")
    record = {"packages": packages, "files": files,
              "origin": "Installed host packages copied into the bootstrap initrd",
              "recipe": "bootstrap-recipe.py:initrd_tree"}
    (notices / "packages.json").write_text(json.dumps(record, indent=2) + "\n")
    shutil.copytree(notices, provenance / "initrd")


def make_initrd(output, staging, provenance):
    root = staging / "initrd-tree"
    root.mkdir()
    monitor_helpers().initrd_tree(root)
    initrd_provenance(root, provenance)
    names = ["."] + [str(p.relative_to(root)) for p in sorted(root.rglob("*"))]
    cpio = subprocess.run(["cpio", "--create", "--format=newc", "--null", "--owner=0:0"],
                          cwd=root, input=b"\0".join(os.fsencode(n) for n in names) + b"\0",
                          capture_output=True, check=True)
    gzip = subprocess.run(["gzip", "-n", "-9"], input=cpio.stdout,
                          capture_output=True, check=True)
    output.write_bytes(gzip.stdout)


def options(values):
    """Validate installer answers; unknown keys are rejected."""
    unknown = set(values) - set(DEFAULTS)
    if unknown:
        raise RuntimeError("unknown image options: " + ", ".join(sorted(unknown)))
    result = {**DEFAULTS, **(CONSOLE_DEFAULTS if values.get("desktop") == CONSOLE else {}),
              **values}
    monitor_helpers().valid_hostname(result["hostname"])
    if not isinstance(result["name"], str):
        raise RuntimeError("base name must be text")
    result["name"] = monitor_helpers().valid_name(result["name"])
    for key, pattern in PATTERNS.items():
        if not isinstance(result[key], str) or not re.fullmatch(pattern, result[key]):
            raise RuntimeError(f"invalid {key.replace('_', ' ')} {result[key]!r}")
    if ".." in result["timezone"]:
        raise RuntimeError("invalid time zone")
    if not isinstance(result["standard"], bool):
        raise RuntimeError("standard must be true or false")
    if result["desktop"] not in DESKTOPS and result["desktop"] != CONSOLE:
        raise RuntimeError(f"unknown desktop {result['desktop']!r}")
    return result


def packages(desktop):
    """Packages to install: the common set plus the desktop's task, or the
    console base's own set."""
    if desktop == CONSOLE:
        return tuple(package for package, _ in CONSOLE_PACKAGES)
    task = DESKTOPS[desktop][0]
    extra = ("lightdm-gtk-greeter",) if desktop == "xfce" else ()
    return PACKAGES + (task,) + extra


def kernel_append(desktop, release=None, root_uuid=None):
    if desktop == CONSOLE:
        return CONSOLE_APPEND.format(release=release.split()[0], uuid=root_uuid)
    return APPEND


def fstab(desktop, root_uuid=None):
    """The console base's fstab is the installer's (root by UUID on any disk bus,
    errors=remount-ro, the CD drive); the desktops keep virtio's /dev/vda (their
    SATA and NVMe drivers are modules)."""
    if desktop == CONSOLE:
        return (FSTAB_HEADER + f"# / was on {CONSOLE_ROOT_DEVICE} during installation\n"
                + FSTAB_ROOT.format(uuid=root_uuid) + FSTAB_CDROM)
    return "/dev/vda / ext4 defaults 0 1\n"


def stealth_support(desktop, config, kernel):
    """bundle.json stealth_support: SATA and NVMe roots only for the console
    base, and only when its kernel builds those controllers in."""
    support = monitor_helpers().stealth_support(config, kernel, root_buses=desktop == CONSOLE)
    return support + ["onboardnic"] if desktop == CONSOLE else support


def image_size(desktop):
    return CONSOLE_IMAGE_SIZE if desktop == CONSOLE else IMAGE_SIZE


def display(desktop):
    """Display manager and default session; none for the console base."""
    return (CONSOLE, CONSOLE) if desktop == CONSOLE else DESKTOPS[desktop][1:3]


def customization_script():
    """Run inside the new root: arguments hostname locale layout variant timezone
    display-manager session (both "none" for the console base) and, for the
    console base, the root filesystem's UUID."""
    return """#!/bin/sh
set -eu
hostname=$1 locale=$2 layout=$3 variant=$4 zone=$5 manager=$6 session=$7 rootuuid=${8:-} mirror=${9:-}
export DEBIAN_FRONTEND=noninteractive
test "$(. /etc/os-release; printf '%s' "$ID:$VERSION_ID")" = debian:13
test "$(dpkg --print-architecture)" = amd64
grep -qx "$locale UTF-8" /usr/share/i18n/SUPPORTED || { echo "unsupported locale $locale" >&2; exit 1; }
test -f "/usr/share/zoneinfo/$zone" || { echo "unknown time zone $zone" >&2; exit 1; }
if [ "$manager" = none ]; then
    test ! -e /etc/X11/default-display-manager || { echo "the console base has a display manager" >&2; exit 1; }
else
    test -f "/usr/share/xsessions/$session.desktop" || test -f "/usr/share/wayland-sessions/$session.desktop" || \\
        { echo "desktop session $session is not installed" >&2; exit 1; }
    test "$(cat /etc/X11/default-display-manager)" = "/usr/sbin/$manager" || \\
        { echo "display manager is not $manager" >&2; exit 1; }
fi
awk -v l="$layout" '/^! layout/ {s = 1; next} /^!/ {s = 0} s && $1 == l {f = 1} END {exit !f}' \\
    /usr/share/X11/xkb/rules/evdev.lst || { echo "unknown keyboard layout $layout" >&2; exit 1; }
if [ -n "$variant" ]; then
    awk -v v="$variant" -v l="$layout:" '/^! variant/ {s = 1; next} /^!/ {s = 0} s && $1 == v && $2 == l {f = 1} END {exit !f}' \\
        /usr/share/X11/xkb/rules/evdev.lst || { echo "unknown keyboard variant $variant for $layout" >&2; exit 1; }
fi
# Debian's own kernels go (the base boots its own); the console base's own
# kernel packages stay.
remove=$(dpkg-query -W -f='${binary:Package} ${db:Status-Status}\\n' | awk -v keep="$manager" '$2 == "installed" && ($1 ~ /^openssh-server(:|$)/ || $1 ~ /^qemu-guest-agent(:|$)/ || $1 ~ /^spice-vdagent(:|$)/ || $1 ~ /^cloud-init/ || $1 ~ /^cloud-guest-utils(:|$)/ || ($1 ~ /^linux-image-/ && keep != "none")) {print $1}')
if [ -n "$remove" ]; then
    apt-get -o APT::Get::AllowUnauthenticated=false -y purge $remove
fi
# Mask only units a package still ships: a mask for an absent unit would name
# the agents a sandbox leaves out.
for unit in ssh.service sshd.service ssh.socket qemu-guest-agent.service spice-vdagentd.service cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service; do
    if [ -e "/usr/lib/systemd/system/$unit" ] || [ -e "/lib/systemd/system/$unit" ]; then
        systemctl mask "$unit"
    fi
done
for name in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
    userdel -r "$name"
done
for name in $(awk -F: '$3 == 1000 {print $1}' /etc/group); do
    groupdel "$name"
done
passwd -l root
rm -f /etc/ssh/ssh_host_* /var/lib/dbus/machine-id
truncate -s 0 /etc/machine-id
# systemd-resolved's postinst keeps the resolv.conf it replaced: the build
# host's (its nameserver and search domain).
rm -f /etc/.resolv.conf.systemd-resolved.bak
# No automatic or guest login; the chosen desktop is the default session.
case $manager in
lightdm)
    mkdir -p /etc/lightdm/lightdm.conf.d
    greeter=
    if [ "$session" = xfce ]; then greeter='greeter-session=lightdm-gtk-greeter\\n'; fi
    printf "[Seat:*]\\n${greeter}user-session=%s\\nautologin-user=\\nautologin-guest=false\\nallow-guest=false\\n" "$session" > /etc/lightdm/lightdm.conf.d/50-seat.conf
    ;;
gdm3)
    sed -i 's/^#*\\s*AutomaticLoginEnable\\s*=.*/AutomaticLoginEnable = false/' /etc/gdm3/daemon.conf
    ;;
sddm)
    mkdir -p /etc/sddm.conf.d
    printf '[Autologin]\\nUser=\\nSession=%s\\n' "$session" > /etc/sddm.conf.d/10-session.conf
    ;;
none)
    # Console base: logins on the serial console and the virtual terminals;
    # ifupdown runs dhcpcd for the wired NIC, as the installer sets it up
    # (provisioning adds its stanza).
    printf '%s' """ + shlex.quote(CONSOLE_INTERFACES) + """ > /etc/network/interfaces
    # /tmp stays on the root disk, as on BusyBox: what a sample drops there is
    # in the VM's disk (Disks tab, disk dumps, checkpoints), not only in RAM.
    # A condition in a drop-in, as "systemctl edit" leaves it, not a mask.
    mkdir -p /etc/systemd/system/tmp.mount.d
    printf '[Unit]\\nConditionPathIsMountPoint=/tmp\\n' > /etc/systemd/system/tmp.mount.d/override.conf
    mkdir -p /media/cdrom0
    ln -s cdrom0 /media/cdrom
    # apt-setup's sources.list, named after the netinst image of this point
    # release (built when base-files was), and the indexes it lists.
    built=$(zcat /usr/share/doc/base-files/changelog.gz | sed -n 's/^ -- .*>  //p' | head -n 1)
    media="Debian GNU/Linux $(cat /etc/debian_version).0 _Trixie_ - Official amd64 NETINST with firmware $(date -u -d "$built" +%Y%m%d-%H:%M)"
    sources=""" + shlex.quote(SOURCES_LIST) + """
    url=$(printf '%s' "$mirror" | sed 's/[&|\\]/\\\\&/g')
    printf '%s' "$sources" | sed -e "s|{media}|$media|" -e "s|{mirror}|$url|g" > /etc/apt/sources.list
    apt-get -o Acquire::Languages=en update
    # Answers the installer leaves in the debconf database.
    printf 'tasksel tasksel/first multiselect standard\\npopularity-contest popularity-contest/participate boolean false\\n' | debconf-set-selections || true
    # tasksel's language task for the locale (task-english for English).
    task=$(awk -v l="${locale%%_*}" '/^Task:/ {t = $2} /^Test-lang:/ {for (i = 2; i <= NF; i++) if ($i == l) print t}' /usr/share/tasksel/descs/debian-tasks.desc | head -n 1)
    if [ -n "$task" ]; then
        apt-get -o APT::Get::AllowUnauthenticated=false -y install "task-$task"
    fi
    ;;
esac
if [ "$manager" = none ]; then
    systemctl set-default multi-user.target
else
    systemctl set-default graphical.target
fi
if [ -n "$rootuuid" ]; then
    { printf '%s' """ + shlex.quote(FSTAB_HEADER + f"# / was on {CONSOLE_ROOT_DEVICE} during installation\n") + """
      printf """ + shlex.quote(FSTAB_ROOT.format(uuid="%s").replace("\n", "\\n")) + """ "$rootuuid"
      printf '%s' """ + shlex.quote(FSTAB_CDROM) + """; } > /etc/fstab
else
    printf '/dev/vda / ext4 defaults 0 1\\n' > /etc/fstab
fi
[ "$manager" = none ] || printf '%s' """ + shlex.quote(NETWORK_INTERFACES) + """ > /etc/network/interfaces
printf '%s\\n' "$hostname" > /etc/hostname
# Packages configured while the build host's name was the system's take the
# chosen one (exim4's mail name and local domains).
if [ -f /etc/exim4/update-exim4.conf.conf ]; then
    printf 'exim4-config exim4/mailname string %s\\nexim4-config exim4/dc_other_hostnames string %s\\n' "$hostname" "$hostname" | debconf-set-selections
    printf 'SUBST exim4/dc_other_hostnames fqdn %s\\n' "$hostname" | debconf-communicate exim4-config >/dev/null
    printf '%s\\n' "$hostname" > /etc/mailname
    sed -i "s/^dc_other_hostnames=.*/dc_other_hostnames='$hostname'/" /etc/exim4/update-exim4.conf.conf
    update-exim4.conf
fi
hosts=""" + shlex.quote(HOSTS) + """
printf '%s' "$hosts" | sed "s/{hostname}/$hostname/" > /etc/hosts
# Locale, keyboard and time zone as the installer answers them: through
# debconf, so locale.gen is the full commented list and the answers stay.
printf 'locales locales/locales_to_be_generated multiselect %s UTF-8\\nlocales locales/default_environment_locale select %s\\n' "$locale" "$locale" | debconf-set-selections
rm -f /etc/locale.gen
dpkg-reconfigure -f noninteractive locales
printf 'keyboard-configuration keyboard-configuration/xkb-keymap select %s\\nkeyboard-configuration keyboard-configuration/layoutcode string %s\\nkeyboard-configuration keyboard-configuration/variantcode string %s\\n' "$layout" "$layout" "$variant" | debconf-set-selections
printf 'XKBMODEL="pc105"\\nXKBLAYOUT="%s"\\nXKBVARIANT="%s"\\nXKBOPTIONS=""\\n\\nBACKSPACE="guess"\\n' "$layout" "$variant" > /etc/default/keyboard
area=${zone%%/*} city=${zone#*/}
printf 'tzdata tzdata/Areas select %s\\ntzdata tzdata/Zones/%s select %s\\n' "$area" "$area" "$city" | debconf-set-selections
ln -sf "/usr/share/zoneinfo/$zone" /etc/localtime
rm -f /etc/timezone
dpkg-reconfigure -f noninteractive tzdata
# The installer's hardware clock answer, and D-Bus's link to the machine ID.
printf '0.0 0 0.0\\n0\\nUTC\\n' > /etc/adjtime
ln -sf /etc/machine-id /var/lib/dbus/machine-id
# Build-time apt and dpkg settings (recommends, proxy, left-out documentation)
# are not part of the image.
rm -f /etc/apt/apt.conf.d/99mmdebstrap /etc/dpkg/dpkg.cfg.d/99mmdebstrap
audit=$(dpkg --audit)
if [ -n "$audit" ]; then
    printf '%s\\n' "$audit" >&2
    exit 1
fi
apt-get -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false check
dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\t${source:Version}\\t${db:Status-Status}\\n' > /tmp/packages.tsv
if [ "$manager" = none ] && [ -f /var/log/apt/history.log ]; then
    awk """ + shlex.quote(HISTORY_AWK) + """ /var/log/apt/history.log /var/log/apt/history.log > /tmp/history.log
    cat /tmp/history.log > /var/log/apt/history.log
    rm -f /tmp/history.log
fi
if [ "$manager" = none ]; then
    # The resolver the installer's DHCP lease named; dhcpcd rewrites it at boot.
    printf 'nameserver 192.168.1.1\\n' > /etc/resolv.conf
    find /var/cache/apt/archives -name '*.deb' -delete
else
    apt-get clean
fi
"""


# The console base's /boot, module tree and kernel packages are Debian's own:
# linux-image-6.12.94+deb13-amd64 and linux-image-amd64 6.12.94-1 exactly as
# linux-signed-amd64 6.12.94+1 shipped them (Debian's signed image, its
# configuration, System.map and modules; dpkg --verify finds nothing to report).
# QEMU boots the Antinomie kernel with -kernel, so the guest never holds it;
# its own modules go to /usr/lib/modules/RELEASE/updates (KERNEL_MODULES_DIR),
# where modprobe prefers them to Debian's of the same name. They come from
# trixie-security on the day it published them, through snapshot.debian.org:
# the archive's signed InRelease is checked against the Debian archive
# keyring, the Packages index against its hash there, and each package
# against the index and the SHA-256 pinned here.
DEBIAN_KERNEL_ARCHIVE = "https://snapshot.debian.org/archive/debian-security/20260621T081639Z"
DEBIAN_KERNEL_SUITE = "trixie-security"
DEBIAN_KERNEL_INDEX = "main/binary-amd64/Packages.xz"
DEBIAN_KERNEL_PACKAGES = (
    ("linux-image-6.12.94+deb13-amd64", "6.12.94-1",
     "e38184e9aee8814cc12559abd10437ff2970c12cd01339e871b881abd9a5344e"),
    ("linux-image-amd64", "6.12.94-1",
     "b37181a3638eea668b6b58f73b58bdb6dadffdd085d8c0a9bda7be1e276eb4ce"),
)
ARCHIVE_KEYRINGS = (Path("/usr/share/keyrings/debian-archive-keyring.pgp"),
                    Path("/usr/share/keyrings/debian-archive-keyring.gpg"))
KERNEL_MODULES_DIR = "updates"


def deb_name(package, version):
    return f"{package}_{version}_amd64.deb"


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(url, target, proxy=""):
    """Download url to target (written whole or not at all)."""
    import urllib.request
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    opener = urllib.request.build_opener(*handlers)
    partial = target.with_name(target.name + ".part")
    try:
        with opener.open(url, timeout=120) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output, 1 << 20)
        os.replace(partial, target)
    except OSError as error:
        partial.unlink(missing_ok=True)
        raise RuntimeError(f"cannot download {url}: {error}") from error


def verified_release(signed, work):
    """The text of an InRelease file that a key of the Debian archive keyring
    signed (only what the signature covers)."""
    keyring = next((path for path in ARCHIVE_KEYRINGS if path.is_file()), None)
    if keyring is None:
        raise RuntimeError("the Debian archive keyring is missing (install debian-archive-keyring)")
    output = work / "Release.verified"
    if shutil.which("gpgv"):
        command = ["gpgv", "--keyring", str(keyring), "--output", str(output), str(signed)]
    elif shutil.which("sqv"):
        command = ["sqv", "--keyring", str(keyring), "--output", str(output), "--message",
                   str(signed)]
    else:
        raise RuntimeError("gpgv or sqv is required to check the Debian archive's signature")
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0 or not output.is_file():
        raise RuntimeError("the Debian archive's InRelease does not verify: "
                           + result.stderr.strip()[-400:])
    return output.read_text()


def release_hash(release, path):
    """SHA-256 and size of path in a Release file's SHA256 list."""
    section = None
    for line in release.splitlines():
        if not line.startswith(" "):
            section = line.split(":", 1)[0]
            continue
        fields = line.split()
        if section == "SHA256" and len(fields) == 3 and fields[2] == path:
            return fields[0], int(fields[1])
    raise RuntimeError(f"the Debian archive's Release does not list {path}")


def index_entries(packages, wanted):
    """Filename, size and SHA-256 of each (package, version) in a Packages index."""
    found = {}
    for stanza in packages.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line and not line[0].isspace() and ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        key = (fields.get("Package"), fields.get("Version"))
        if key in wanted and fields.get("Architecture") == "amd64":
            found[key] = (fields["Filename"], int(fields["Size"]), fields["SHA256"])
    missing = sorted(f"{name} {version}" for name, version in set(wanted) - set(found))
    if missing:
        raise RuntimeError("the Debian archive's index lacks " + ", ".join(missing))
    return found


def debian_kernel_debs(cache, work, proxy=""):
    """Debian's kernel packages (DEBIAN_KERNEL_PACKAGES), from cache when a
    copy there matches its pinned SHA-256, else downloaded into cache (or work)
    through the archive's signed index."""
    directory = cache or work
    directory.mkdir(parents=True, exist_ok=True)
    debs = [directory / deb_name(name, version) for name, version, _ in DEBIAN_KERNEL_PACKAGES]
    pinned = {path: sha for path, (_, _, sha) in zip(debs, DEBIAN_KERNEL_PACKAGES)}
    if all(path.is_file() and sha256_file(path) == pinned[path] for path in debs):
        print("Debian kernel packages verified in " + str(directory), flush=True)
        return debs
    index = work / "kernel-index"
    index.mkdir(parents=True, exist_ok=True)
    try:
        entries = signed_index_entries(index, proxy)
        for path, (name, version, sha) in zip(debs, DEBIAN_KERNEL_PACKAGES):
            filename, size, indexed = entries[(name, version)]
            if indexed != sha:
                raise RuntimeError(f"{name} {version}: the signed index names another file "
                                   "than the pinned one")
            if path.is_file() and sha256_file(path) == sha:
                continue
            print(f"downloading {name} {version} ({size >> 20} MiB)", flush=True)
            fetch(f"{DEBIAN_KERNEL_ARCHIVE}/{filename}", path, proxy)
            if path.stat().st_size != size or sha256_file(path) != sha:
                path.unlink()
                raise RuntimeError(f"{path.name} does not match the Debian archive's index")
    finally:
        shutil.rmtree(index)
    return debs


def signed_index_entries(index, proxy=""):
    """The pinned packages' index entries, from the archive's Packages index
    whose hash its signed InRelease lists (both downloaded into index)."""
    import lzma
    dists = f"{DEBIAN_KERNEL_ARCHIVE}/dists/{DEBIAN_KERNEL_SUITE}"
    fetch(f"{dists}/InRelease", index / "InRelease", proxy)
    release = verified_release(index / "InRelease", index)
    expected, size = release_hash(release, DEBIAN_KERNEL_INDEX)
    listed = index / "Packages.xz"
    fetch(f"{dists}/{DEBIAN_KERNEL_INDEX}", listed, proxy)
    if sha256_file(listed) != expected or listed.stat().st_size != size:
        raise RuntimeError(f"{DEBIAN_KERNEL_INDEX} does not match the signed Release")
    return index_entries(lzma.decompress(listed.read_bytes()).decode(),
                         {(name, version) for name, version, _ in DEBIAN_KERNEL_PACKAGES})


def modules_archive(tree, target):
    """The Antinomie kernel's own modules (*.ko under tree/kernel) as a tar for
    /usr/lib/modules/RELEASE/updates, owned by root, timestamps kept."""
    def owned_by_root(info):
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        return info

    with tarfile.open(target, "w", format=tarfile.PAX_FORMAT) as archive:
        base = tree / "kernel"
        for path in sorted(base.rglob("*.ko")) if base.is_dir() else ():
            archive.add(path, arcname=str(path.relative_to(base)), filter=owned_by_root)
    return target


# What the bootstrap writes into provenance/; a cached root filesystem keeps them.
ROOTFS_PROVENANCE = ("packages.tsv", "os-release", "package-docs.tar.gz", "apt-lists.tar.gz",
                     "customize.sh", "mmdebstrap.json", "bootstrap.log")
# A cached root filesystem older than this is bootstrapped again, so package
# updates (security fixes) still arrive.
ROOTFS_CACHE_DAYS = int(os.environ.get("ANTINOMIE_ROOTFS_CACHE_DAYS", "30"))


def rootfs_identity(values, kernel_hashes=()):
    """What the root filesystem depends on: this recipe, the answers that shape
    it (the base name and the apt proxy do not) and the console base's kernel
    inputs (Debian's packages and the Antinomie kernel's modules), by SHA-256."""
    keys = ("desktop", "hostname", "locale", "keyboard_layout", "keyboard_variant",
            "timezone", "standard", "mirror")
    identity = {"format": 1,
                "recipe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "options": {key: values[key] for key in keys}}
    if kernel_hashes:
        identity["kernel_packages"] = list(kernel_hashes)
    return identity


def load_rootfs_cache(cache, values, staging, provenance, log, kernel_hashes=()):
    """Unpack a cached root filesystem tarball that matches this recipe and is
    recent enough; return its record, or None to bootstrap."""
    if cache is None or not cache.is_file():
        return None
    try:
        with tarfile.open(cache) as archive:
            manifest = json.load(archive.extractfile("rootfs-cache.json"))
            if manifest.get("identity") != rootfs_identity(values, kernel_hashes):
                print("cached root filesystem is from another recipe or answers; bootstrapping",
                      flush=True)
                return None
            built = datetime.fromisoformat(manifest["built_at"])
            if datetime.now(timezone.utc) - built > timedelta(days=ROOTFS_CACHE_DAYS):
                print(f"cached root filesystem is older than {ROOTFS_CACHE_DAYS} days; "
                      "bootstrapping for current packages", flush=True)
                return None
            for name in ROOTFS_PROVENANCE:
                member = archive.getmember("provenance/" + name)
                with archive.extractfile(member) as source, (provenance / name).open("wb") as target:
                    shutil.copyfileobj(source, target)
            for name in ("rootfs.tar", INODE_TIMES):
                with archive.extractfile(name) as source, \
                        (staging / name).open("wb") as target:
                    shutil.copyfileobj(source, target, 1 << 20)
    except (tarfile.TarError, KeyError, ValueError, OSError, TypeError) as error:
        print(f"cached root filesystem unusable ({error}); bootstrapping", flush=True)
        for name in ("rootfs.tar", INODE_TIMES):
            (staging / name).unlink(missing_ok=True)
        return None
    print(f"using the root filesystem bootstrapped {manifest['built_at']}", flush=True)
    log.write(f"root filesystem reused from the cache, bootstrapped {manifest['built_at']}\n")
    return manifest["root"] | {"reused_from_cache": True}


def save_rootfs_cache(cache, tarball, provenance, root, values, kernel_hashes=()):
    """Store the bootstrapped root filesystem (before kernel modules) atomically."""
    partial = cache.with_name(cache.name + ".part")
    cache.parent.mkdir(parents=True, exist_ok=True)
    manifest = json.dumps({"identity": rootfs_identity(values, kernel_hashes), "root": root,
                           "built_at": root["root_built_at"]}).encode()
    with tarfile.open(partial, "w") as archive:
        entry = tarfile.TarInfo("rootfs-cache.json")
        entry.size = len(manifest)
        archive.addfile(entry, io.BytesIO(manifest))
        for name in ROOTFS_PROVENANCE:
            archive.add(provenance / name, arcname="provenance/" + name)
        archive.add(tarball, arcname="rootfs.tar")
        archive.add(tarball.with_name(INODE_TIMES), arcname=INODE_TIMES)
    os.replace(partial, cache)
    print(f"root filesystem cached in {cache}", flush=True)


def add_modules(tarball, modules):
    """Append the kernel's modules (owned by root) to the root filesystem tarball."""
    def owned_by_root(info):
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        return info

    with tarfile.open(tarball, "a", format=tarfile.PAX_FORMAT) as archive:
        names = set(archive.getnames())
        for directory in ("./usr", "./usr/lib", "./usr/lib/modules"):
            if directory not in names and directory[2:] not in names:
                entry = tarfile.TarInfo(directory)
                entry.type = tarfile.DIRTYPE
                entry.mode = 0o755
                archive.addfile(owned_by_root(entry))
        archive.add(modules, arcname=f"./usr/lib/modules/{modules.name}", filter=owned_by_root)


def bootstrap_mode():
    return "root" if os.geteuid() == 0 else "unshare"


def mmdebstrap_command(values, tarball, script, provenance, times=None, kernel_debs=(),
                       kernel_modules=None):
    """The mmdebstrap invocation; hooks run as (namespace) root with "$1" the new root.
    A desktop's kernel modules are added to the tarball afterwards
    (add_modules), so the bootstrapped system can be cached and reused with
    another kernel; the console base installs Debian's kernel packages
    (kernel_debs) and puts the Antinomie kernel's modules (kernel_modules, a
    tar) beside theirs."""
    q = shlex.quote
    console = values["desktop"] == CONSOLE
    times = times or tarball.with_name(INODE_TIMES)
    command = ["mmdebstrap", "--mode=" + bootstrap_mode(),
               "--variant=" + ("standard" if values["standard"] else "important"),
               "--architectures=amd64", "--format=tar",
               "--include=" + ",".join(packages(values["desktop"])),
               '--aptopt=APT::Install-Recommends "true"',
               "--aptopt=APT::Get::AllowUnauthenticated \"false\"",
               "--aptopt=Acquire::AllowInsecureRepositories \"false\"",
               "--aptopt=Acquire::Retries \"3\""]
    if values["proxy"]:
        command.append(f'--aptopt=Acquire::http::Proxy "{values["proxy"]}"')
        command.append(f'--aptopt=Acquire::https::Proxy "{values["proxy"]}"')
    if console:
        # The package indexes and apt's caches of them stay, as after the
        # installer's apt update (the downloaded packages go), and so do the
        # installation's logs (dpkg, alternatives, apt history).
        command += ["--skip=cleanup/apt/lists", "--skip=cleanup/apt/cache",
                    "--skip=cleanup/reproducible"]
    # Files cross into and out of the new root through mmdebstrap's upload and
    # download hooks, which run as the invoking user: in unshare mode a plain
    # hook runs as the namespace's root, which cannot read or write the
    # invoking user's private staging directory.
    # The kernel packages go in first, as the installer installs the kernel
    # before the rest; apt brings what they depend on and recommend.
    for deb in kernel_debs:
        command.append(f'--customize-hook=upload {q(str(deb))} /tmp/{deb.name}')
    if kernel_debs:
        command.append('--customize-hook=chroot "$1" apt-get -o APT::Get::AllowUnauthenticated=false '
                       '-y install ' + " ".join(f"/tmp/{deb.name}" for deb in kernel_debs))
        command.append('--customize-hook=rm -f ' + " ".join(f'"$1/tmp/{deb.name}"'
                                                         for deb in kernel_debs))
        release = DEBIAN_KERNEL_PACKAGES[0][0].removeprefix("linux-image-")
        packaged = " ".join(name for name, _, _ in DEBIAN_KERNEL_PACKAGES)
        if kernel_modules is not None:
            updates = f"/usr/lib/modules/{release}/{KERNEL_MODULES_DIR}"
            # The module indexes name only these: an index of Debian's would
            # have udev and the kernel try them all (refused, each with an
            # error in the kernel log) and make ours depend on theirs. Debian's
            # tree is excluded for this one depmod run (-C), so the image keeps
            # no depmod.d file; the initramfs Debian's postinst built from all
            # of Debian's modules stays.
            unpack = (f"mkdir -p {updates} && tar -x --no-same-owner -C {updates} "
                      "-f /tmp/kernel-modules.tar && "
                      f"printf 'search {KERNEL_MODULES_DIR}\\nexclude kernel\\n' "
                      "> /tmp/kernel-modules.conf && "
                      f"depmod -a -C /tmp/kernel-modules.conf {release} && "
                      f"! grep -qv '^{KERNEL_MODULES_DIR}/' /usr/lib/modules/{release}/modules.dep")
            command.append(f"--customize-hook=upload {q(str(kernel_modules))} "
                           "/tmp/kernel-modules.tar")
            command.append(f'--customize-hook=chroot "$1" sh -c {q(unpack)}')
            command.append('--customize-hook=rm -f "$1/tmp/kernel-modules.tar" '
                           '"$1/tmp/kernel-modules.conf"')
        # Debian's files as Debian shipped them: nothing for dpkg to report.
        verify = 'test -z "$(dpkg --verify ' + packaged + ')"'
        command.append(f'--customize-hook=chroot "$1" sh -c {q(verify)}')
    command.append(f'--customize-hook=upload {q(str(script))} /tmp/antinomie-customize.sh')
    manager, session = display(values["desktop"])
    arguments = " ".join([q(values[key]) for key in
                          ("hostname", "locale", "keyboard_layout", "keyboard_variant", "timezone")]
                         + [q(manager), q(session)])
    if console:
        # mkfs.ext4 gives the root this UUID (fstab_uuid reads it back, also
        # from a cached root filesystem); the mirror goes into sources.list.
        arguments += " " + str(uuid.uuid4()) + " " + q(values["mirror"].rstrip("/"))
    command.append(f'--customize-hook=chroot "$1" sh /tmp/antinomie-customize.sh {arguments}')
    command.append('--customize-hook=rm -f "$1/tmp/antinomie-customize.sh"')
    # The package inventory leaves the image with the build's provenance.
    for path in ("/tmp/packages.tsv", "/etc/os-release"):
        command.append(f'--customize-hook=download {path} {q(str(provenance / Path(path).name))}')
    command.append('--customize-hook=rm -f "$1/tmp/packages.tsv"')
    for path, name in (("usr/share/doc", "package-docs.tar.gz"), ("var/lib/apt/lists", "apt-lists.tar.gz")):
        command.append(f'--customize-hook=tar -C "$1" -czf "$1/tmp/{name}" {path}')
        command.append(f'--customize-hook=download /tmp/{name} {q(str(provenance / name))}')
        command.append(f'--customize-hook=rm -f "$1/tmp/{name}"')
    # Last: every path's access, change, birth and modification time as the
    # installation left them, for the ext4 image (mkfs.ext4 -d takes only
    # modification times from the tarball).
    command.append("--customize-hook=find \"$1\" -xdev -printf " + q(TIMES_FORMAT)
                   + ' > "$1/tmp/inode-times"')
    command.append(f'--customize-hook=download /tmp/inode-times {q(str(times))}')
    command.append('--customize-hook=rm -f "$1/tmp/inode-times"')
    mirror = values["mirror"].rstrip("/")
    command += [SUITE, str(tarball),
                f"deb {mirror} {SUITE} main", f"deb {mirror} {SUITE}-updates main",
                f"deb {SECURITY_MIRROR} {SUITE}-security main"]
    return command


# Places in the image where a build-host file would land (configuration,
# state, homes); package payloads under /usr and the package indexes are not
# scanned for host names that could also be ordinary words there.
LEAK_SCAN = ("etc/", "var/", "root/", "home/")
LEAK_SKIP = ("var/lib/apt/lists/", "var/cache/apt/", "var/lib/dpkg/info/")
# A Tailscale MagicDNS search domain and WSL's resolver address: the
# development hosts' resolv.conf, which mmdebstrap copies into the new root.
HOST_LEAK_PATTERNS = (re.compile(rb"\btail[0-9a-f]{4,}\.ts\.net\b"),
                      re.compile(rb"\bnameserver[ \t]+10\.255\.255\.254\b"))


def host_resolver_patterns(resolv=Path("/etc/resolv.conf")):
    """The build host's own nameservers and search domains as patterns (loopback
    stubs such as systemd-resolved's 127.0.0.53 are on every Debian system)."""
    try:
        text = resolv.read_text(errors="replace")
    except OSError:
        return []
    patterns = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0].startswith(("#", ";")):
            continue
        if fields[0] == "nameserver" and not fields[1].startswith(("127.", "::1")):
            patterns.append(re.compile(rb"\bnameserver[ \t]+" + re.escape(fields[1].encode())
                                       + rb"(?![0-9.:])"))
        elif fields[0] in ("search", "domain"):
            patterns += [re.compile(rb"(?<![A-Za-z0-9.-])" + re.escape(domain.encode())
                                    + rb"(?![A-Za-z0-9-])")
                         for domain in fields[1:] if "." in domain.strip(".")]
    return patterns


def host_name_patterns(chosen, names=None):
    """The build host's own name, which packages configured during the build
    can record (exim4's mail name): every name but the one the image takes and
    the installer's default."""
    if names is None:
        names = {socket.gethostname(), socket.getfqdn()}
    return [re.compile(rb"(?i)(?<![A-Za-z0-9-])" + re.escape(name.encode())
                       + rb"(?![A-Za-z0-9-])")
            for name in sorted(names)
            if len(name) >= 4 and name.split(".")[0].lower() not in
            {chosen.lower(), "debian", "localhost"}]


def check_image_leaks(tarball, patterns=None, hostname="debian"):
    """Fail the build when the root filesystem names Antinomie in a path, masks a
    unit no package ships, or carries the build host's resolver configuration
    or name."""
    patterns = HOST_LEAK_PATTERNS + tuple(
        host_resolver_patterns() + host_name_patterns(hostname) if patterns is None
        else patterns)
    problems = []
    units, masks = set(), []
    with tarfile.open(tarball) as archive:
        for member in archive:
            name = member.name[2:] if member.name.startswith("./") else member.name
            if "antinomie" in name.lower():
                problems.append(f"/{name} names Antinomie")
            if name.startswith(("usr/lib/systemd/system/", "lib/systemd/system/")):
                units.add(name.rsplit("/", 1)[1])
            if (name.startswith("etc/systemd/system/") and member.issym()
                    and member.linkname == "/dev/null"):
                masks.append(name)
            if (not member.isfile() or not name.startswith(LEAK_SCAN)
                    or name.startswith(LEAK_SKIP) or member.size > 16 << 20):
                continue
            data = archive.extractfile(member).read()
            if any(pattern.search(data) for pattern in patterns):
                problems.append(f"/{name} holds the build host's name or resolver")
    problems += [f"/{mask} masks a unit no package ships" for mask in masks
                 if mask.rsplit("/", 1)[1] not in units]
    if problems:
        raise RuntimeError("image carries build traces: " + "; ".join(problems[:10]))


# find(1) -printf for the recorded times: path, atime, ctime, birth time and
# mtime (seconds with nanoseconds), NUL-separated.
TIMES_FORMAT = r"%P\0%A@\0%C@\0%B@\0%T@\0"
INODE_TIMES = "inode-times"
# Mount points find stats through to the filesystem mounted there.
TIMES_MOUNTS = ("dev", "proc", "sys", "run")


def parse_time(text):
    """find's "SECONDS.FRACTION" as (seconds, nanoseconds); None for unknown (-1)."""
    whole, _, fraction = text.partition(".")
    if not whole.isdigit():
        return None
    return int(whole), int((fraction + "000000000")[:9] or 0)


def read_inode_times(path):
    """{tar path: (atime, ctime, birth, mtime)} from the recorded find output."""
    fields = path.read_bytes().split(b"\0")
    times = {}
    for index in range(0, len(fields) - 4, 5):
        name = fields[index].decode("utf-8", "surrogateescape")
        if name.split("/", 1)[0] in TIMES_MOUNTS:
            continue
        times[name] = tuple(parse_time(field.decode()) for field in fields[index + 1:index + 5])
    return times


def install_timeline(tarball, recorded, rng):
    """Per path (tar name without "./"): atime, ctime, crtime and mtime as
    (seconds, nanoseconds), and the installation's first and last moment.

    A path keeps the times its installation gave it (mmdebstrap's tarball
    clamps modification times to the moment it started): changed no earlier
    than modified, born no later than changed, accessed no earlier than born
    (tar gives an extracted file its package's time as access time). A path
    the installation did not record (added afterwards) was born when the
    installation ended."""
    known = [value for times in recorded.values() for value in times[1:3] if value]
    start, end = min(known), max(known)
    plan = {}
    with tarfile.open(tarball) as archive:
        for member in archive:
            name = member.name.rstrip("/")
            name = "" if name == "." else name[2:] if name.startswith("./") else name
            if member.islnk():
                continue
            atime, ctime, birth, mtime = recorded.get(name, (None,) * 4)
            mtime = mtime or (int(member.mtime), 0)
            if ctime is None:
                ctime = max(mtime, (end[0], rng.randrange(10 ** 9)))
            ctime = max(ctime, mtime)
            birth = min(birth or ctime, ctime)
            atime = max(atime or ctime, birth)
            plan[name] = (atime, ctime, birth, mtime)
    return plan, start, end


def debugfs_path(name):
    """A path as one debugfs argument (inside quotes, a backslash is itself:
    systemd's escaped unit names keep theirs)."""
    if any(c in name for c in '"\n'):
        raise RuntimeError(f"unsupported path for debugfs {name!r}")
    return '"/' + name + '"'


def apply_timeline(raw, plan, start, end, staging, log, rng):
    """Write the timeline into the image, and the superblock of a filesystem
    the installer made just before it (mkfs, one mount at /target, its writes)."""
    commands = []
    for name, times in plan.items():
        path = debugfs_path(name) if name else "/"
        for field, (seconds, nanoseconds) in zip(("atime", "ctime", "crtime", "mtime"), times):
            commands.append(f"set_inode_field {path} {field} @{seconds}")
            commands.append(f"set_inode_field {path} {field}_extra {nanoseconds << 2}")
    stats = subprocess.run(["debugfs", "-R", "stats", str(raw)], check=True,
                           capture_output=True, text=True).stdout
    blocks = int(re.search(r"^Block count:\s*(\d+)", stats, re.M)[1])
    free = int(re.search(r"^Free blocks:\s*(\d+)", stats, re.M)[1])
    size = int(re.search(r"^Block size:\s*(\d+)", stats, re.M)[1])
    written = (blocks - free) * size // 1024
    commands += [f"ssv mtime @{start[0] - rng.randrange(5, 20)}", "ssv mnt_count 1",
                 "ssv last_mounted /target",
                 f"ssv kbytes_written {written + written * rng.randrange(20, 45) // 100}"]
    script = staging / "times.debugfs"
    script.write_text("\n".join(commands) + "\n")
    # debugfs stamps its own last write time on close.
    subprocess.run(["debugfs", "-w", "-f", str(script), str(raw)], check=True,
                   stdout=subprocess.DEVNULL, stderr=log,
                   env=os.environ | {"E2FSPROGS_FAKE_TIME": str(end[0] + rng.randrange(2, 9))})
    script.unlink()
    return len(plan)


def e2fsprogs_version():
    output = subprocess.run(["mke2fs", "-V"], capture_output=True, text=True).stderr
    match = re.search(r"mke2fs (\d+)\.(\d+)(?:\.(\d+))?", output)
    if not match:
        raise RuntimeError("cannot read the mke2fs version")
    return tuple(int(part or 0) for part in match.groups())


def apply_xattrs(tarball, raw, staging, log):
    """mkfs.ext4 -d drops extended attributes from a tarball; set them again (capabilities)."""
    commands = []
    values = staging / "xattr-values"
    values.mkdir()
    with tarfile.open(tarball) as archive:
        for member in archive:
            for key, value in member.pax_headers.items():
                if not key.startswith("SCHILY.xattr."):
                    continue
                name = key[len("SCHILY.xattr."):]
                name_in_tar = member.name[2:] if member.name.startswith("./") else member.name
                path = "/" + name_in_tar.strip("/") if name_in_tar not in ("", ".") else "/"
                if any(c in path for c in '"\n') or any(c in name for c in '" \n'):
                    raise RuntimeError(f"unsupported extended attribute entry {path!r}")
                data = values / str(len(commands))
                data.write_bytes(value.encode("utf-8", "surrogateescape"))
                commands.append(f'ea_set -f {data} "{path}" {name}')
    if commands:
        script = staging / "xattrs.debugfs"
        script.write_text("\n".join(commands) + "\n")
        subprocess.run(["debugfs", "-w", "-f", str(script), str(raw)], check=True,
                       stdout=log, stderr=subprocess.STDOUT)
    shutil.rmtree(values)
    return len(commands)


def debugfs_cat(raw, path):
    return subprocess.run(["debugfs", "-R", f"cat {path}", str(raw)], check=True,
                          capture_output=True, text=True).stdout


def fstab_uuid(tarball):
    """The root UUID the console base's fstab names, from the root filesystem tarball."""
    with tarfile.open(tarball) as archive:
        text = archive.extractfile("./etc/fstab").read().decode()
    match = re.search(r"^UUID=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) "
                      r"+/ ", text, re.M)
    if not match or text != fstab(CONSOLE, match[1]):
        raise RuntimeError("console base fstab does not mount its root by UUID")
    return match[1]


def filesystem_uuid(raw):
    output = subprocess.run(["debugfs", "-R", "stats", str(raw)], check=True,
                            capture_output=True, text=True).stdout
    match = re.search(r"^Filesystem UUID:\s*(\S+)$", output, re.M)
    return match[1] if match else None


def validate_image(raw, desktop=None, root_uuid=None):
    desktop = desktop or DEFAULTS["desktop"]
    if debugfs_cat(raw, "/etc/fstab") != fstab(desktop, root_uuid):
        raise RuntimeError("image has unexpected fstab")
    if desktop == CONSOLE and filesystem_uuid(raw) != root_uuid:
        raise RuntimeError("root filesystem UUID does not match fstab")
    shadow = debugfs_cat(raw, "/etc/shadow").splitlines()
    if not any(line.startswith(("root:!", "root:*")) for line in shadow):
        raise RuntimeError("base root password must be locked")
    passwd = debugfs_cat(raw, "/etc/passwd").splitlines()
    if any(1000 <= int(line.split(":")[2]) < 65534 for line in passwd):
        raise RuntimeError("base must not contain preset ordinary user accounts")
    groups = debugfs_cat(raw, "/etc/group").splitlines()
    if any(int(line.split(":")[2]) == 1000 for line in groups):
        raise RuntimeError("base must leave GID 1000 free for per-VM credentials")


def console_disk(raw, size, rng):
    """The console base's MBR disk with its one (bootable) root partition; the
    root filesystem is made inside it at CONSOLE_ROOT_OFFSET."""
    with raw.open("xb") as target:
        target.truncate(size)
    layout = (f"label: dos\nlabel-id: 0x{rng.randrange(1 << 32):08x}\n"
              f"start={CONSOLE_ROOT_OFFSET // 512}, size={CONSOLE_ROOT_SIZE // 512}, "
              "type=83, bootable\n")
    subprocess.run(["sfdisk", "--quiet", "--no-reread", "--no-tell-kernel", str(raw)],
                   input=layout, text=True, check=True, stdout=subprocess.DEVNULL)
    return f"{raw}?offset={CONSOLE_ROOT_OFFSET}"


def root_image(values, raw, staging, provenance, log, modules=None, cache=None,
               console_kernel=None):
    """The root filesystem image. console_kernel (the console base): the
    SHA-256 of its kernel inputs ("hashes"), a function that returns Debian's
    kernel packages ("debs", called only when the root is bootstrapped) and the
    tar of the Antinomie kernel's modules ("modules", or None)."""
    tarball = staging / "rootfs.tar"
    times = staging / INODE_TIMES
    kernel_hashes = console_kernel["hashes"] if console_kernel else ()
    root = load_rootfs_cache(cache, values, staging, provenance, log, kernel_hashes)
    if root is None:
        script = staging / "customize.sh"
        script.write_text(customization_script())
        shutil.copy2(script, provenance / "customize.sh")
        kernel_debs = console_kernel["debs"]() if console_kernel else ()
        command = mmdebstrap_command(values, tarball, script, provenance, times, kernel_debs,
                                     console_kernel["modules"] if console_kernel else None)
        (provenance / "mmdebstrap.json").write_text(json.dumps(command, indent=2) + "\n")
        # mmdebstrap assembles the system in $TMPDIR; /tmp is a small tmpfs on
        # Debian 13 (and in the cloud builder), far too small for a desktop.
        # The installer runs in UTC, so its logs (dpkg, apt) are in UTC.
        subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT,
                       env=os.environ | {"TMPDIR": str(staging), "TZ": "UTC"})
        root = {"bootstrap": "mmdebstrap", "mode": bootstrap_mode(),
                "variant": "standard" if values["standard"] else "important",
                "suite": SUITE, "mirror": values["mirror"], "security_mirror": SECURITY_MIRROR,
                "root_built_at": datetime.now(timezone.utc).isoformat(),
                "reused_from_cache": False}
        if cache is not None:
            log.flush()
            shutil.copy2(log.name, provenance / "bootstrap.log")
            save_rootfs_cache(cache, tarball, provenance, root, values, kernel_hashes)
    check_image_leaks(tarball, hostname=values["hostname"])
    if modules is not None:
        add_modules(tarball, modules)
    size = image_size(values["desktop"])
    root_uuid = fstab_uuid(tarball) if values["desktop"] == CONSOLE else None
    rng = random.SystemRandom()
    plan, start, end = install_timeline(tarball, read_inode_times(times), rng)
    # The installer partitions and formats the disk a minute or two before it
    # installs the first package.
    made = {"E2FSPROGS_FAKE_TIME": str(start[0] - rng.randrange(40, 160))}
    if values["desktop"] == CONSOLE:
        device = console_disk(raw, size, rng)
        placement = ["-E", f"offset={CONSOLE_ROOT_OFFSET}"]
        extent = [f"{CONSOLE_ROOT_SIZE >> 10}k"]
    else:
        with raw.open("xb") as target:
            target.truncate(size)
        device, placement, extent = str(raw), [], []
    subprocess.run(["mkfs.ext4", "-q", "-F", *(["-U", root_uuid] if root_uuid else []),
                    *placement, "-d", str(tarball), str(raw), *extent],
                   check=True, stdout=log, stderr=subprocess.STDOUT, env=os.environ | made)
    xattrs = apply_xattrs(tarball, device, staging, log)
    timed = apply_timeline(device, plan, start, end, staging, log, rng)
    tarball.unlink()
    validate_image(device, values["desktop"], root_uuid)
    return root | {
            "root_filesystem": "ext4", "root_size": size, "root_uuid": root_uuid,
            "conversion": "mkfs.ext4 -d tarball; extended attributes and the installation's "
                          "access, change and birth times set with debugfs",
            "extended_attributes": xattrs, "timed_paths": timed,
            "kernel_modules": None if modules is None else f"/usr/lib/modules/{modules.name}"}


def build(kernel, output, kernel_config=None, modules=None, allow_unversioned=False,
          values=None, work=None, app_version=None, rootfs_cache=None, symbols=None,
          kernel_package_cache=None):
    if output.exists():
        raise RuntimeError("output already exists; choose a new unpublished bundle path")
    values = options(values or {})
    release = kernel_release(kernel)
    if kernel_uses_modules(kernel_config) and modules is None and not (
            values["desktop"] == CONSOLE and built_in(kernel_config, CONSOLE_BUILTIN)):
        raise RuntimeError("kernel config builds modules; pass --modules with its install root")
    tree = module_tree(modules, release)
    helpers = monitor_helpers()
    helpers.fixed_display_config(kernel_config, kernel)
    helpers.stamp_revision({}, kernel, allow_unversioned)
    if e2fsprogs_version() < MIN_E2FSPROGS:
        raise RuntimeError("mkfs.ext4 from e2fsprogs 1.47.1 or newer is required (tarball input)")
    output.parent.mkdir(parents=True, exist_ok=True)
    work = work or output.parent
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="debian-image-", dir=work) as name:
        staging = Path(name)
        if bootstrap_mode() == "unshare":
            # mmdebstrap builds the root inside (TMPDIR), and the namespace's
            # root, a subordinate UID, must reach it; nothing here is listable.
            staging.chmod(0o711)
        bundle = staging / "bundle"
        provenance = bundle / "provenance"
        provenance.mkdir(parents=True)
        shutil.copy2(kernel, bundle / "kernel")
        raw = staging / "root.raw"
        log_path = staging / "bootstrap.log"
        console_kernel = None
        if values["desktop"] == CONSOLE:
            # The console base installs Debian's own kernel packages, which
            # must be the release the Antinomie kernel reports; its modules
            # go beside Debian's.
            if release.split()[0] != DEBIAN_KERNEL_PACKAGES[0][0].removeprefix("linux-image-"):
                raise RuntimeError(f"kernel release {release.split()[0]} is not Debian's "
                                   f"{DEBIAN_KERNEL_PACKAGES[0][0]}")
            packages_dir = staging / "kernel-packages"
            packages_dir.mkdir()
            packages_dir.chmod(0o755)
            archive = None if tree is None else modules_archive(
                tree, packages_dir / "kernel-modules.tar")
            console_kernel = {
                "hashes": [sha for _, _, sha in DEBIAN_KERNEL_PACKAGES]
                + ([sha256_file(archive)] if archive else []),
                "debs": lambda: debian_kernel_debs(kernel_package_cache, packages_dir,
                                                   values["proxy"]),
                "modules": archive}
            tree = None
        try:
            with log_path.open("w") as log:
                root = root_image(values, raw, staging, provenance, log, tree, rootfs_cache,
                                  console_kernel)
        except (RuntimeError, subprocess.CalledProcessError):
            # The log dies with the staging directory; show why it failed.
            lines = log_path.read_text(errors="replace").splitlines()
            print("--- last bootstrap log lines ---", flush=True)
            print("\n".join(lines[-80:]), flush=True)
            raise
        if not root.get("reused_from_cache"):
            shutil.copy2(log_path, provenance / "bootstrap.log")
        subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "qcow2",
                        str(raw), str(bundle / "base.qcow2")], check=True)
        raw.unlink()
        make_initrd(bundle / "initrd.gz", staging, provenance)
        hashes = {item: helpers.checksum(bundle / item)
                  for item in ("kernel", "initrd.gz", "base.qcow2")}
        record = {"built_at": datetime.now(timezone.utc).isoformat(),
                  "options": values, "root": root,
                  "apt_authentication": "Debian signed indexes; insecure repositories disallowed",
                  "package_install_recommends": True,
                  "requested_packages": list(packages(values["desktop"])),
                  "package_inventory": "packages.tsv",
                  "kernel_sha256": hashes["kernel"], "kernel_release": release,
                  "tools": {tool: subprocess.run([tool, "--version"], capture_output=True,
                                                 text=True).stdout.strip().splitlines()[0]
                            for tool in ("mmdebstrap", "qemu-img")}}
        record["provenance_sha256"] = {str(p.relative_to(provenance)): helpers.checksum(p)
            for p in sorted(provenance.rglob("*")) if p.is_file()}
        (provenance / "build.json").write_text(json.dumps(record, indent=2) + "\n")
        manifest = {"format": 1, "kernel_version": "6.12.94", "schema_id": 1,
                    "kernel": "kernel", "initrd": "initrd.gz", "base_disk": "base.qcow2",
                    "kernel_append": kernel_append(values["desktop"], release,
                                                   root.get("root_uuid")),
                    "guest": profile(values["desktop"]),
                    "sha256": hashes}
        if symbols:
            shutil.copy2(symbols, bundle / "symbols.json.xz")
            manifest["symbols"] = "symbols.json.xz"
            hashes["symbols.json.xz"] = helpers.checksum(bundle / "symbols.json.xz")
        helpers.stamp_revision(manifest, bundle / "kernel", allow_unversioned, app_version)
        if values["name"]:
            manifest["name"] = values["name"]
        # NetworkManager (systemd-networkd on the console base) takes the NAT's
        # DHCP answer. A desktop's root stays /dev/vda (APPEND, fstab) and Debian
        # builds the SATA and NVMe drivers as modules; the console base mounts
        # its root by UUID, so its kernel decides (built-in controllers only).
        manifest["stealth_support"] = stealth_support(values["desktop"], kernel_config,
                                                      bundle / "kernel")
        if helpers.fixed_display_config(kernel_config, bundle / "kernel"):
            manifest["fixed_display"] = True
            shutil.copy2(kernel_config, provenance / "kernel.config")
            helpers.fixed_display_config(provenance / "kernel.config", bundle / "kernel")
            manifest["kernel_config_sha256"] = helpers.checksum(provenance / "kernel.config")
            manifest["build_provenance"] = {"parent_identity": None,
                "kernel_sha256": hashes["kernel"], "base_disk_sha256": hashes["base.qcow2"],
                "initrd_sha256": hashes["initrd.gz"],
                "kernel_config_sha256": manifest["kernel_config_sha256"]}
        (bundle / "bundle.json").write_text(json.dumps(manifest, indent=2) + "\n")
        # Publish only a completed bundle, never overwrite an existing base.
        bundle.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--kernel-config", type=Path,
                        help="matching kernel .config; validates built-in fixed-display support")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--symbols", type=Path,
                        help="the kernel's Volatility symbol table (scripts/make-kernel-symbols.py)")
    parser.add_argument("--modules", type=Path,
                        help="modules_install root (INSTALL_MOD_PATH) matching the kernel")
    parser.add_argument("--allow-unversioned", action="store_true",
                        help="accept a development kernel without a source id")
    parser.add_argument("--kernel-package-cache", type=Path,
                        help="directory that keeps Debian's kernel packages for the console "
                             "base (checked against their pinned SHA-256; downloaded and "
                             "verified against the archive's signed index when missing)")
    parser.add_argument("--options", type=Path,
                        help="JSON object of installer answers (desktop: a DESKTOPS id or "
                             "\"none\" for the console-only Debian Minimal base, hostname, "
                             "locale, keyboard_layout, keyboard_variant, timezone, standard, "
                             "mirror, proxy)")
    parser.add_argument("--work", type=Path, help="directory for temporary build files")
    parser.add_argument("--app-version", help="Antinomie version building this base")
    parser.add_argument("--rootfs-cache", type=Path,
                        help="reuse this bootstrapped root filesystem if it matches the recipe "
                             "and answers and is recent, else bootstrap and write it")
    args = parser.parse_args()
    if not args.kernel.is_file():
        parser.error("an existing patched Linux 6.12.94 kernel is required")
    for tool in ("mmdebstrap", "mkfs.ext4", "mke2fs", "debugfs", "qemu-img", "cpio", "gzip",
                 "busybox", "resize2fs", "dpkg-query", "tar", "sfdisk", "dpkg-deb"):
        if shutil.which(tool) is None:
            parser.error("required installed tool missing: " + tool)
    try:
        values = json.loads(args.options.read_text()) if args.options else {}
        if not isinstance(values, dict):
            raise RuntimeError("options must be a JSON object")
        build(args.kernel, args.output, args.kernel_config, args.modules,
              args.allow_unversioned, values, args.work, args.app_version, args.rootfs_cache,
              args.symbols, args.kernel_package_cache)
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, "Debian image build failed: " + str(error) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
