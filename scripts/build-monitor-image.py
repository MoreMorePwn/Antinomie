#!/usr/bin/env python3
"""Create a reproducible minimal guest bundle without mounting host filesystems."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import struct
import tempfile
import zlib

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "work/debian-6.12.94-1-trixie/images/monitor-base"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bundle_identity(manifest, hashes):
    """Match storage.rs content identity; absent extensions preserve legacy bytes."""
    compact = lambda value: json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    digest = hashlib.sha256(compact([manifest.get("kernel_append", ""),
        manifest.get("kernel_version", ""), manifest.get("schema_id", 0)]))
    guest = manifest.get("guest")
    if guest is not None:
        digest.update(b"antinomie-guest-profile-v1")
        digest.update(compact({key: guest[key] for key in
            ("id", "label", "min_ram_mib", "min_disk_gib", "requires_credentials", "graphical")}))
    if manifest.get("fixed_display", False):
        digest.update(b"antinomie-fixed-display-v1")
    provenance = manifest.get("build_provenance")
    if provenance is not None:
        digest.update(b"antinomie-build-provenance-v1")
        digest.update(compact({key: provenance[key] for key in
            ("parent_identity", "kernel_sha256", "base_disk_sha256", "initrd_sha256", "kernel_config_sha256")}))
    for key in ("kernel", "base_disk", "initrd"):
        digest.update(b"\x01" + bytes.fromhex(hashes[key]) if key in hashes else b"\x00")
    if "symbols" in hashes:
        digest.update(b"antinomie-volatility-symbols-v1" + bytes.fromhex(hashes["symbols"]))
    return digest.hexdigest()


def gunzip_bounded(data, limit):
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    result = decoder.decompress(data, limit + 1)
    if len(result) > limit or not decoder.eof:
        raise RuntimeError("kernel/config gzip is incomplete or exceeds its size limit")
    return result, decoder.unused_data


def embedded_config(kernel):
    """Read IKCONFIG from the pinned gzip-compressed x86 bzImage format."""
    with kernel.open("rb") as source:
        data = source.read((64 << 20) + 1)
    if len(data) > 64 << 20 or len(data) < 0x250 or data[0x202:0x206] != b"HdrS":
        raise RuntimeError("unsupported or oversized x86 bzImage")
    offset, length = struct.unpack_from("<II", data, 0x248)
    begin = ((data[0x1f1] or 4) + 1) * 512 + offset
    if length == 0 or begin + length > len(data):
        raise RuntimeError("invalid bzImage compressed payload extent")
    try:
        payload, _ = gunzip_bounded(data[begin:begin + length], 256 << 20)
        marker = b"IKCFG_ST\x1f\x8b\x08"
        start = payload.find(marker)
        if start < 0:
            raise RuntimeError("fixed display requires embedded CONFIG_IKCONFIG=y")
        config, rest = gunzip_bounded(payload[start + 8:], 2 << 20)
        if not rest.startswith(b"IKCFG_ED"):
            raise RuntimeError("invalid embedded kernel configuration trailer")
        return config
    except zlib.error as error:
        raise RuntimeError("fixed display requires the pinned gzip bzImage compression") from error


def source_identity(kernel):
    """The kernel's CONFIG_ANTINOMIE_SOURCE_ID as (revision, series sha256), or None."""
    for line in embedded_config(kernel).decode().splitlines():
        if line.startswith("CONFIG_ANTINOMIE_SOURCE_ID="):
            value = line.split("=", 1)[1].strip('"')
            break
    else:
        return None
    if not value:
        return None
    match = re.fullmatch(r"([1-9][0-9]{0,8}):([0-9a-f]{64})", value)
    if not match:
        raise RuntimeError("invalid CONFIG_ANTINOMIE_SOURCE_ID " + repr(value))
    return int(match[1]), match[2]


REVISIONS = REPO / "src/antinomie/monitor/protocol/revisions.json"
VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})")


def first_app_version(revision):
    """The first Antinomie version that shipped a guest contract revision."""
    for entry in json.loads(REVISIONS.read_text())["revisions"]:
        if entry["revision"] == revision:
            return entry["first_app_version"]
    raise RuntimeError(f"revision {revision} is missing from {REVISIONS.name}; "
                       "add it with the release that introduces it")


def workspace_version():
    """The app version of a repository checkout, if this is one."""
    cargo = REPO / "src/antinomie/monitor/Cargo.toml"
    if not cargo.is_file():
        return None
    match = re.search(r'^\[workspace\.package\][^\[]*?^version = "([^"]+)"', cargo.read_text(),
                      re.M | re.S)
    return match[1] if match else None


def valid_name(name):
    """A base's display name: up to 64 printable characters (empty: automatic)."""
    name = name.strip()
    if len(name) > 64 or any(not character.isprintable() for character in name):
        raise RuntimeError("base name must be at most 64 printable characters")
    return name


# First app version that knows bases with a Volatility symbol table.
SYMBOLS_APP_VERSION = "0.4.0"


def stamp_revision(manifest, kernel, allow_unversioned, app_version=None):
    """Record the patch revision and series the kernel was built from, the
    oldest app version that can run it and the app version that built it."""
    identity = source_identity(kernel)
    if identity is None:
        if not allow_unversioned:
            raise RuntimeError("kernel has no Antinomie source id (development build); "
                               "pass --allow-unversioned to build an unversioned base")
        return
    manifest["antinomie_revision"], manifest["antinomie_source"] = identity
    manifest["min_app_version"] = first_app_version(identity[0])
    if "symbols" in manifest:
        # Older apps compute the base identity without the symbol table.
        manifest["min_app_version"] = max(manifest["min_app_version"], SYMBOLS_APP_VERSION,
                                          key=lambda v: tuple(map(int, v.split("."))))
    built_with = app_version or workspace_version()
    if built_with is not None:
        if not VERSION.fullmatch(built_with):
            raise RuntimeError(f"invalid app version {built_with!r}")
        manifest["built_with"] = built_with


def fixed_display_config(config, kernel=None):
    """Validate the matching build configuration supplied by the image builder."""
    if config is None:
        return False
    if kernel is None or config.read_bytes() != embedded_config(kernel):
        raise RuntimeError("supplied config does not match the kernel's embedded IKCONFIG")
    values = dict(line.split("=", 1) for line in config.read_text().splitlines()
                  if line.startswith("CONFIG_") and "=" in line)
    for name in ("DRM", "DRM_VIRTIO_GPU", "DRM_VIRTIO_GPU_KMS", "DRM_FBDEV_EMULATION", "FRAMEBUFFER_CONSOLE"):
        if values.get("CONFIG_" + name) != "y":
            raise RuntimeError(f"fixed display requires CONFIG_{name}=y in matching kernel config")
    return True


# The EFI stub of a kernel with guest patch 0051 claims the bootstrap page before
# it places the kernel; its warning text is the mark of that patch in a bzImage
# (the stub is not part of the compressed payload).
UEFI_BOOT_PAGE_MARK = b"Bootstrap page 0x%llx is not free"


def stealth_support(config, kernel, root_buses=True, dhcp=True):
    """Stealth profile entries the base can boot with, for bundle.json.

    uefi: the kernel boots through its EFI stub without landing on the bootstrap
    page; sata, nvme: the initrd finds the root disk on that bus and the kernel
    has the controller built in; dhcp: the guest takes its address from the
    NAT's DHCP server, so any NAT network works. A base without the field boots
    from virtio under SeaBIOS on 10.0.2.0/24 only."""
    support = []
    values = {}
    if config is not None:
        values = dict(line.split("=", 1) for line in Path(config).read_text().splitlines()
                      if line.startswith("CONFIG_") and "=" in line)
    built_in = lambda *names: all(values.get("CONFIG_" + name) == "y" for name in names)
    if built_in("EFI", "EFI_STUB") and UEFI_BOOT_PAGE_MARK in Path(kernel).read_bytes():
        support.append("uefi")
    if root_buses and built_in("ATA", "SATA_AHCI", "SCSI", "BLK_DEV_SD"):
        support.append("sata")
    if root_buses and built_in("BLK_DEV_NVME"):
        support.append("nvme")
    if dhcp:
        support.append("dhcp")
    return support


def install_binary(source, root, destination=None):
    source = Path(source)
    target = root / (destination or str(source)).lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    dependency_list = subprocess.run(["ldd", str(source)], capture_output=True, text=True)
    if dependency_list.returncode and "not a dynamic executable" not in dependency_list.stderr:
        raise RuntimeError(f"cannot inspect dependencies for {source}: {dependency_list.stderr}")
    for line in dependency_list.stdout.splitlines():
        dependency = re.search(r"(?:=>\s+)?(/\S+)\s+\(", line)
        if dependency:
            path = Path(dependency.group(1))
            dest = root / str(path).lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)


def write_file(root, path, content, mode=0o644):
    target = root / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    target.chmod(mode)


HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def valid_hostname(name):
    """One lowercase RFC 1123 label, as the installer's hostname question takes."""
    if not HOSTNAME.fullmatch(name):
        raise RuntimeError(f"invalid hostname {name!r}: use 1-63 of a-z, 0-9 and '-'")
    return name


def base_tree(root, hostname="debian"):
    for directory in ("bin", "sbin", "usr/bin", "usr/sbin", "etc", "dev", "proc", "sys", "run", "tmp", "root", "home/user", "var/log"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "tmp").chmod(0o1777)
    (root / "home/user").chmod(0o700)
    install_binary("/usr/bin/busybox", root, "/bin/busybox")
    applets = subprocess.check_output(["/usr/bin/busybox", "--list"], text=True).splitlines()
    for applet in applets:
        if applet != "busybox":
            (root / "bin" / applet).symlink_to("busybox")
    (root / "sbin/init").symlink_to("../bin/busybox")
    write_file(root, "/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000:user,,,:/home/user:/bin/sh\n")
    write_file(root, "/etc/group", "root:x:0:\nuser:x:1000:\n")
    write_file(root, "/etc/hostname", hostname + "\n")
    # Written at boot from the NAT's DHCP answer.
    write_file(root, "/etc/resolv.conf", "")
    write_file(root, "/etc/udhcpc/default.script", """#!/bin/sh
case "$1" in
deconfig)
    ip addr flush dev "$interface"
    ip link set "$interface" up
    ;;
bound|renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/${mask:-24}" ${broadcast:+broadcast "$broadcast"} dev "$interface"
    # A NAT that isolates the VM answers without a router or DNS server: its
    # own address (the DHCP server's) then takes both roles, as a home router.
    for gateway in ${router:-$serverid}; do
        ip route replace default via "$gateway" dev "$interface"
        break
    done
    : > /etc/resolv.conf
    [ -n "$domain" ] && echo "search $domain" >> /etc/resolv.conf
    for server in ${dns:-$serverid}; do
        echo "nameserver $server" >> /etc/resolv.conf
    done
    ;;
esac
""", 0o755)
    write_file(root, "/etc/inittab", "::sysinit:/etc/init.d/rcS\ntty1::respawn:/bin/getty -n -l /bin/sh 0 tty1\nttyS0::respawn:/bin/getty -n -l /bin/sh 115200 ttyS0\n::ctrlaltdel:/bin/reboot\n::shutdown:/bin/sync\n::shutdown:/bin/umount -a -r\n")
    write_file(root, "/etc/init.d/rcS", """#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /dev/pts /run
mount -t devpts devpts /dev/pts
chmod 1777 /tmp
hostname "$(cat /etc/hostname)"
ip link set lo up
if ip link show eth0 >/dev/null 2>&1; then
    # The address, gateway and DNS server come from the NAT's DHCP server, as
    # on a PC behind a home router (the VM's stealth profile picks the network).
    ip link set eth0 up
    udhcpc -i eth0 -s /etc/udhcpc/default.script -f -q -n -t 5 -T 1 >/dev/null 2>&1 ||
        echo 'Guest DHCP failed'
fi
echo 'BusyBox guest ready'
""", 0o755)


def initrd_tree(root):
    for directory in ("bin", "dev", "proc", "sys", "newroot"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    install_binary("/usr/bin/busybox", root, "/bin/busybox")
    for applet in ("sh", "mount", "mkdir", "sleep", "switch_root", "echo", "cat", "findfs"):
        (root / "bin" / applet).symlink_to("busybox")
    install_binary(shutil.which("resize2fs"), root, "/bin/resize2fs")
    write_file(root, "/init", """#!/bin/sh
export PATH=/bin
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
mount -t proc proc /proc
mount -t sysfs sysfs /sys
# A Debian-shaped command line names the root by filesystem UUID and asks for
# it read-only (the boot's fsck, then fstab's remount); without one the root
# is the VM's only disk. Either is on the bus the stealth profile chose:
# virtio, SATA or NVMe.
uuid= mode=rw
for arg in $(cat /proc/cmdline); do
    case $arg in
    root=UUID=*) uuid=${arg#root=UUID=} ;;
    ro) mode=ro ;;
    rw) mode=rw ;;
    esac
done
root=
for n in 1 2 3 4 5 6 7 8 9 10; do
    if [ -n "$uuid" ]; then
        root=$(findfs "UUID=$uuid" 2>/dev/null) && break
    else
        for disk in /dev/vda /dev/sda /dev/nvme0n1; do
            [ -b $disk ] && root=$disk && break 2
        done
    fi
    sleep 1
done
# No filesystem with that UUID (a disk from before its VM had one of its
# own): the root partition or the disk.
if [ -z "$root" ]; then
    for disk in /dev/vda1 /dev/sda1 /dev/nvme0n1p1 /dev/vda /dev/sda /dev/nvme0n1; do
        [ -b $disk ] && root=$disk && break
    done
fi
mount -t ext4 -o rw ${root:-/dev/vda} /newroot || exec sh
# Grow the filesystem to the VM's disk while mounted: offline, resize2fs
# refuses a filesystem mounted since its last full check (every base disk).
resize2fs $root || echo 'Guest filesystem resize failed'
if [ $mode = ro ]; then
    mount -o remount,ro /newroot
fi
mount --move /dev /newroot/dev
mount --move /proc /newroot/proc
mount --move /sys /newroot/sys
exec switch_root /newroot /sbin/init
""", 0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--kernel-config", type=Path,
                        help="matching kernel .config; validates built-in fixed-display support")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--symbols", type=Path,
                        help="the kernel's Volatility symbol table (scripts/make-kernel-symbols.py)")
    parser.add_argument("--base-size-mib", type=int, default=256)
    parser.add_argument("--allow-unversioned", action="store_true",
                        help="accept a development kernel without a source id")
    parser.add_argument("--hostname", default="debian")
    parser.add_argument("--app-version", help="Antinomie version building this base")
    parser.add_argument("--name", default="", help="display name of the base")
    parser.add_argument("--work", type=Path, default=REPO / "work",
                        help="directory for temporary build files")
    args = parser.parse_args()
    try:
        valid_hostname(args.hostname)
        name = valid_name(args.name)
    except RuntimeError as error:
        parser.error(str(error))
    fixed_display = fixed_display_config(args.kernel_config, args.kernel)
    try:
        stamp_revision({}, args.kernel, args.allow_unversioned)
    except RuntimeError as error:
        parser.error(str(error))
    if not args.kernel.is_file() or args.base_size_mib < 128:
        parser.error("existing kernel and base size of at least 128 MiB required")
    args.output.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="monitor-image-", dir=args.work) as temporary:
        staging = Path(temporary)
        root = staging / "root"
        root.mkdir()
        base_tree(root, args.hostname)
        raw = staging / "base.raw"
        with raw.open("wb") as image:
            image.truncate(args.base_size_mib << 20)
        # No volume label: an installer leaves the root filesystem unnamed.
        run("mkfs.ext4", "-q", "-F", "-d", str(root), str(raw))
        # Imported staging files belong to the builder, not the guest user.
        metadata = staging / "ownership.debugfs"
        commands = []
        for path in [root] + sorted(root.rglob("*")):
            guest_path = "/" + str(path.relative_to(root)) if path != root else "/"
            owner = 1000 if guest_path == "/home/user" else 0
            commands.extend((f"set_inode_field {guest_path} uid {owner}",
                             f"set_inode_field {guest_path} gid {owner}"))
        metadata.write_text("\n".join(commands) + "\n")
        run("debugfs", "-w", "-f", str(metadata), str(raw), stdout=subprocess.DEVNULL)
        run("qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(args.output / "base.qcow2"))
        initrd = staging / "initrd"
        initrd.mkdir()
        initrd_tree(initrd)
        names = ["."] + [str(p.relative_to(initrd)) for p in sorted(initrd.rglob("*"))]
        cpio = subprocess.run(["cpio", "--create", "--format=newc", "--null", "--owner=0:0"], cwd=initrd,
                              input=b"\0".join(os.fsencode(n) for n in names) + b"\0", capture_output=True, check=True)
        compressed = subprocess.run(["gzip", "-n", "-9"], input=cpio.stdout, capture_output=True, check=True)
        (args.output / "initrd.gz").write_bytes(compressed.stdout)
    shutil.copy2(args.kernel, args.output / "kernel")
    manifest = {"format": 1, "kernel_version": "6.12.94", "schema_id": 1,
                "kernel": "kernel", "initrd": "initrd.gz", "base_disk": "base.qcow2",
                "kernel_append": "console=tty0 console=ttyS0 panic=-1",
                "sha256": {name: checksum(args.output / name)
                           for name in ("kernel", "initrd.gz", "base.qcow2")}}
    if args.symbols:
        shutil.copy2(args.symbols, args.output / "symbols.json.xz")
        manifest["symbols"] = "symbols.json.xz"
        manifest["sha256"]["symbols.json.xz"] = checksum(args.output / "symbols.json.xz")
    stamp_revision(manifest, args.output / "kernel", args.allow_unversioned, args.app_version)
    if name:
        manifest["name"] = name
    manifest["stealth_support"] = stealth_support(args.kernel_config, args.output / "kernel")
    if fixed_display:
        manifest["fixed_display"] = True
        shutil.copy2(args.kernel_config, args.output / "kernel.config")
        fixed_display_config(args.output / "kernel.config", args.output / "kernel")
        manifest["kernel_config_sha256"] = checksum(args.output / "kernel.config")
        manifest["build_provenance"] = {"parent_identity": None,
            "kernel_sha256": manifest["sha256"]["kernel"],
            "base_disk_sha256": manifest["sha256"]["base.qcow2"],
            "initrd_sha256": manifest["sha256"]["initrd.gz"],
            "kernel_config_sha256": manifest["kernel_config_sha256"]}
    (args.output / "bundle.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
