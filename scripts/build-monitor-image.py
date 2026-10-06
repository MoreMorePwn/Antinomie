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


def fixed_display_config(config, kernel=None):
    """Validate the matching build configuration supplied by the image builder."""
    if config is None:
        return False
    if kernel is None or config.read_bytes() != embedded_config(kernel):
        raise RuntimeError("supplied config does not match the kernel's embedded IKCONFIG")
    values = dict(line.split("=", 1) for line in config.read_text().splitlines()
                  if line.startswith("CONFIG_") and "=" in line)
    for name in ("DRM", "DRM_BOCHS", "DRM_FBDEV_EMULATION", "FRAMEBUFFER_CONSOLE"):
        if values.get("CONFIG_" + name) != "y":
            raise RuntimeError(f"fixed display requires CONFIG_{name}=y in matching kernel config")
    return True


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


def base_tree(root):
    for directory in ("bin", "sbin", "usr/bin", "usr/sbin", "etc", "dev", "proc", "sys", "run", "tmp", "root", "home/analyst", "var/log"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "tmp").chmod(0o1777)
    (root / "home/analyst").chmod(0o700)
    install_binary("/usr/bin/busybox", root, "/bin/busybox")
    applets = subprocess.check_output(["/usr/bin/busybox", "--list"], text=True).splitlines()
    for applet in applets:
        if applet != "busybox":
            (root / "bin" / applet).symlink_to("busybox")
    (root / "sbin/init").symlink_to("../bin/busybox")
    write_file(root, "/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nanalyst:x:1000:1000:Analyst:/home/analyst:/bin/sh\n")
    write_file(root, "/etc/group", "root:x:0:\nanalyst:x:1000:\n")
    write_file(root, "/etc/hostname", "localhost\n")
    write_file(root, "/etc/resolv.conf", "nameserver 10.0.2.3\n")
    write_file(root, "/etc/inittab", "::sysinit:/etc/init.d/rcS\ntty1::respawn:/bin/getty -n -l /bin/sh 0 tty1\nttyS0::respawn:/bin/getty -n -l /bin/sh 115200 ttyS0\n::ctrlaltdel:/bin/reboot\n::shutdown:/bin/sync\n::shutdown:/bin/umount -a -r\n")
    write_file(root, "/etc/init.d/rcS", """#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /dev/pts /run
mount -t devpts devpts /dev/pts
chmod 1777 /tmp
hostname localhost
ip link set lo up
if ip link show eth0 >/dev/null 2>&1; then
    ip link set eth0 up
    ip addr add 10.0.2.15/24 dev eth0
    ip route add default via 10.0.2.2
fi
echo 'BusyBox guest ready'
""", 0o755)


def initrd_tree(root):
    for directory in ("bin", "dev", "proc", "sys", "newroot"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    install_binary("/usr/bin/busybox", root, "/bin/busybox")
    for applet in ("sh", "mount", "mkdir", "sleep", "switch_root", "echo"):
        (root / "bin" / applet).symlink_to("busybox")
    install_binary(shutil.which("resize2fs"), root, "/bin/resize2fs")
    write_file(root, "/init", """#!/bin/sh
export PATH=/bin
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
mount -t proc proc /proc
mount -t sysfs sysfs /sys
for n in 1 2 3 4 5 6 7 8 9 10; do
    [ -b /dev/vda ] && break
    sleep 1
done
resize2fs /dev/vda || echo 'Guest filesystem resize failed'
mount -t ext4 -o rw /dev/vda /newroot || exec sh
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
    parser.add_argument("--base-size-mib", type=int, default=256)
    args = parser.parse_args()
    fixed_display = fixed_display_config(args.kernel_config, args.kernel)
    if not args.kernel.is_file() or args.base_size_mib < 128:
        parser.error("existing kernel and base size of at least 128 MiB required")
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="monitor-image-", dir=REPO / "work") as temporary:
        staging = Path(temporary)
        root = staging / "root"
        root.mkdir()
        base_tree(root)
        raw = staging / "base.raw"
        with raw.open("wb") as image:
            image.truncate(args.base_size_mib << 20)
        run("mkfs.ext4", "-q", "-F", "-L", "antinomie", "-d", str(root), str(raw))
        # Imported staging files belong to the builder, not the guest analyst.
        metadata = staging / "ownership.debugfs"
        commands = []
        for path in [root] + sorted(root.rglob("*")):
            guest_path = "/" + str(path.relative_to(root)) if path != root else "/"
            owner = 1000 if guest_path == "/home/analyst" else 0
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
