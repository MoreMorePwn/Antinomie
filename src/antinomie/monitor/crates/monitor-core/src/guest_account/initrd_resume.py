"""Give a provisioned Debian disk's initramfs its resume device.

Runs inside the guest (python3 -I, through guestfish) after provisioning wrote
/etc/initramfs-tools/conf.d/resume. The Debian installer writes that file just
before it installs the kernel, so update-initramfs copies it into every
initramfs as conf/conf.d/resume (and adds no zz-resume-auto). The base's
initramfs was made before the VM had a swap partition: this puts the file into
each /boot/initrd.img-* as mkinitramfs would have, changing nothing else but
what places the image on this disk (the device and inode numbers its files had
in mkinitramfs's directory on the build machine become the installed root's),
and recompresses it as mkinitramfs does (zstd -q -9 -T0 from a pipe).

usage: initrd_resume.py RESUME-LINE INSTALL-DEVICE
    RESUME-LINE     the file's line, e.g. RESUME=UUID=<uuid> or RESUME=none
    INSTALL-DEVICE  MAJOR:MINOR of the partition the installer installed to
"""
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import glob
import os
import random
import subprocess
import sys

CONF_DIR = "/etc/initramfs-tools/conf.d"
RESUME_ENTRY = b"conf/conf.d/resume"
AUTO_ENTRY = b"conf/conf.d/zz-resume-auto"
TRAILER = b"TRAILER!!!"
MAGIC = b"070701"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
# newc header fields, in order (each eight hex digits after the magic).
INO, MODE, UID, GID, NLINK, MTIME, FILESIZE, DEVMAJOR, DEVMINOR = range(9)
NAMESIZE = 11
# GNU cpio pads an archive to whole 512-byte blocks.
BLOCK = 512


def read_archive(data, offset):
    """One newc archive from offset: [fields, name, body] per member (the
    trailer last) and the offset just past it."""
    members = []
    while True:
        if data[offset:offset + 6] != MAGIC:
            raise ValueError("not a newc cpio archive")
        fields = [int(data[offset + 6 + 8 * i:offset + 14 + 8 * i], 16) for i in range(13)]
        name_end = offset + 110 + fields[NAMESIZE]
        start = (name_end + 3) & ~3
        end = start + fields[FILESIZE]
        if end > len(data):
            raise ValueError("truncated cpio archive")
        members.append([fields, data[offset + 110:name_end - 1], data[start:end]])
        offset = (end + 3) & ~3
        if members[-1][1] == TRAILER:
            return members, offset


def write_archive(members):
    out = bytearray()
    for fields, name, body in members:
        fields[NAMESIZE] = len(name) + 1
        fields[FILESIZE] = len(body)
        out += MAGIC + b"".join(b"%08X" % value for value in fields) + name + b"\0"
        out += b"\0" * (-len(out) % 4) + body
        out += b"\0" * (-len(out) % 4)
    return bytes(out + b"\0" * (-len(out) % BLOCK))


def sort_key(name):
    # mkinitramfs sorts find(1)'s "./" paths with LC_ALL=C.
    return b"." if name == b"." else b"./" + name


def split_image(data):
    """The uncompressed archives mkinitramfs puts first (early microcode,
    compressed modules), kept as they are, and the compressed main archive."""
    offset = 0
    while data.startswith(MAGIC, offset):
        _, offset = read_archive(data, offset)
        while offset < len(data) and data[offset] == 0:
            offset += 1
    if not data.startswith(ZSTD_MAGIC, offset):
        raise ValueError("main archive is not zstd-compressed (initramfs.conf COMPRESS=zstd)")
    return data[:offset], data[offset:]


def place(members, device, rng):
    """Device and inode numbers as on the installed root: the members keep
    their order and links, renumbered from near /var/tmp, where mkinitramfs
    makes its directory."""
    numbers = sorted({fields[INO] for fields, name, _ in members if name != TRAILER})
    span = numbers[-1] - numbers[0] if numbers else 0
    stats = os.statvfs("/")
    base = os.stat("/var/tmp").st_ino + rng.randrange(1, 64)
    if base + span >= stats.f_files:
        base = max(12, stats.f_files - span - 1)
    for fields, name, _ in members:
        if name == TRAILER:
            continue
        fields[INO] = base + fields[INO] - numbers[0]
        fields[DEVMAJOR], fields[DEVMINOR] = device


def add_resume(members, line, mtime):
    """conf/conf.d/resume as update-initramfs copies it (cp -p), in sorted
    order; an automatic choice no longer applies."""
    members[:] = [member for member in members if member[1] != AUTO_ENTRY]
    body = line.encode() + b"\n"
    for member in members:
        if member[1] == RESUME_ENTRY:
            member[0][MTIME] = mtime
            member[2] = body
            return
    by_name = {name: fields for fields, name, _ in members}
    neighbour = by_name.get(b"conf/initramfs.conf") or by_name[b"conf/conf.d"]
    used = {fields[INO] for fields in by_name.values()}
    number = neighbour[INO] + 1
    while number in used:
        number += 1
    fields = [number, 0o100644, 0, 0, 1, mtime, 0, neighbour[DEVMAJOR], neighbour[DEVMINOR],
              0, 0, 0, 0]
    index = next(i for i, (_, name, _) in enumerate(members)
                 if name == TRAILER or sort_key(name) > sort_key(RESUME_ENTRY))
    members.insert(index, [fields, RESUME_ENTRY, body])


def patch_image(path, line, mtime, device, rng):
    status = os.stat(path)
    with open(path, "rb") as source:
        head, compressed = split_image(source.read())
    main = subprocess.run(["zstd", "-q", "-d", "-c"], input=compressed, check=True,
                          stdout=subprocess.PIPE).stdout
    members, end = read_archive(main, 0)
    if main[end:].strip(b"\0"):
        raise ValueError("data after the main archive")
    place(members, device, rng)
    add_resume(members, line, mtime)
    packed = subprocess.run(["zstd", "-q", "-9", "-T0", "-c"], input=write_archive(members),
                            check=True, stdout=subprocess.PIPE).stdout
    with open(path, "r+b") as target:
        target.write(head + packed)
        target.truncate()
        os.fsync(target.fileno())
    os.utime(path, ns=(status.st_atime_ns, status.st_mtime_ns))


def main():
    line, device = sys.argv[1], tuple(int(part) for part in sys.argv[2].split(":"))
    if not (line.startswith("RESUME=") and "\n" not in line and len(device) == 2):
        raise SystemExit(__doc__)
    rng = random.SystemRandom()
    images = sorted(glob.glob("/boot/initrd.img-*"))
    # The installer writes the file a little before the kernel's package is
    # unpacked (its image's change time on this disk).
    kernels = [os.stat(path).st_ctime for path in glob.glob("/boot/vmlinuz-*")]
    written = int(min(kernels)) - rng.randrange(20, 90) if kernels else None
    conf = os.path.join(CONF_DIR, "resume")
    with open(conf, "w") as target:
        target.write(line + "\n")
    os.chmod(conf, 0o644)
    if written is not None:
        os.utime(conf, (written, written))
        os.utime(CONF_DIR, (written, written))
    for image in images:
        patch_image(image, line, int(os.stat(conf).st_mtime), device, rng)


if __name__ == "__main__":
    main()
