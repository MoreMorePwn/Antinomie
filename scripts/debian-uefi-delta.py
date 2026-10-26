#!/usr/bin/env python3
"""What the UEFI layout of a Debian Minimal base changes in its root filesystem.

usage: debian-uefi-delta.py BIOS-ROOT UEFI-ROOT DELTA-TAR LAYOUT-JSON

Run by scripts/build-debian-image.py inside mmdebstrap's namespace, where both
roots are readable: BIOS-ROOT is the console base as built (GRUB for a BIOS
PC), UEFI-ROOT a copy of it taken before the boot loader was installed, then
given the installer's UEFI boot loader. DELTA-TAR holds every path of UEFI-ROOT
that is new or differs (type, mode, owner, size, modification time, link
target or device), with its contents; LAYOUT-JSON lists the BIOS root's paths
the UEFI root lacks (deepest first) and each delta path's access, change and
modification times as the UEFI installation left them. The app applies both
when it derives a base's UEFI disk once (src/antinomie/monitor/crates/
monitor-core/src/uefi_disk.rs).
"""
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import json
import os
import stat
import sys
import tarfile

# Mount points and scratch space: the directories count, not what is in them.
CONTENTS_SKIPPED = ("proc", "sys", "dev", "run", "tmp")


def entries(base):
    """{relative path: lstat} below base, without the skipped contents."""
    found = {}
    for directory, subdirectories, files in os.walk(base):
        relative = os.path.relpath(directory, base)
        if relative in CONTENTS_SKIPPED:
            subdirectories[:] = []
            continue
        for name in subdirectories + files:
            path = name if relative == "." else os.path.join(relative, name)
            found[path] = os.lstat(os.path.join(base, path))
    return found


def signature(base, path, info):
    link = os.readlink(os.path.join(base, path)) if stat.S_ISLNK(info.st_mode) else None
    return (info.st_mode, info.st_uid, info.st_gid,
            info.st_size if not stat.S_ISDIR(info.st_mode) else 0,
            info.st_mtime_ns, link, info.st_rdev)


def owned_numeric(member):
    member.uname = member.gname = ""
    return member


def main():
    bios, uefi, delta, layout = sys.argv[1:5]
    before, after = entries(bios), entries(uefi)
    changed = sorted(path for path, info in after.items()
                     if path not in before
                     or signature(bios, path, before[path]) != signature(uefi, path, info))
    removed = sorted(set(before) - set(after), key=lambda path: (-path.count("/"), path))
    times = {}
    with tarfile.open(delta, "w", format=tarfile.PAX_FORMAT) as archive:
        for path in changed:
            archive.add(os.path.join(uefi, path), arcname=path, recursive=False,
                        filter=owned_numeric)
            info = after[path]
            times[path] = [info.st_atime_ns, info.st_ctime_ns, info.st_mtime_ns]
    with open(layout, "w") as target:
        json.dump({"format": 1, "removed": removed, "times": times}, target)
        target.write("\n")


if __name__ == "__main__":
    main()
