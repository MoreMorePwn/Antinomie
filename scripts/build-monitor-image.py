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
import tempfile

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
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--base-size-mib", type=int, default=256)
    args = parser.parse_args()
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
    (args.output / "bundle.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
