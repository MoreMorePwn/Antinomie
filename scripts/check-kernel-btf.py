#!/usr/bin/env python3
"""Check that a built guest kernel's BTF names nothing of Antinomie.

    check-kernel-btf.py --vmlinux FILE [--system-map FILE] [--modules DIR]
                        [--unfiltered FILE]

The guest reads the kernel's BTF (/sys/kernel/btf/vmlinux, and one file per
loaded module). The series builds the recorder without debug information and
filters what its headers leave in stock objects (patch "keep the recorder out
of the kernel's BTF"); this check reads the result independently of that
filter and fails when:

- a string of vmlinux's .BTF is a recorder name (ant_*, antc_*, __ant_*,
  ANT_*, anything with antinomie, in any case; a BTF string table holds only
  the names its types use; stock vmlinux BTF has none of them);
- a string of a module's .BTF has antinomie in it, or is a recorder name that
  pahole's unfiltered vmlinux BTF had (--unfiltered, by default
  .btf.vmlinux.full beside vmlinux): stock modules have ant_* names of their
  own (wireless drivers' antenna fields), so the pattern alone cannot judge
  them;
- with --system-map, a vmlinux BTF function is a function of the recorder's
  own code (System.map's ant_text_begin..ant_text_end), whatever its name,
  and no stock function has that name (the recorder is never a module, and a
  module's static functions may share a name with one of the recorder's).

--modules searches DIR for modules (*.ko, *.ko.xz). Exit status 0 when
clean, 1 with the findings, 2 when a file has no BTF.
"""
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import argparse
from pathlib import Path
import re
import struct
import sys

FORBIDDEN = re.compile(rb"^_*antc?_|antinomie", re.IGNORECASE)
BTF_MAGIC = 0xEB9F
KIND_FUNC = 12
# Bytes after the 12-byte type header, per kind (vlen = entry count).
FIXED_EXTRA = {1: 4, 3: 12, 14: 4, 17: 4}
ENTRY_SIZE = {4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}


class MissingBtf(Exception):
    pass


def elf_section(data, wanted):
    """The bytes of section `wanted` of an ELF image, or None."""
    if data[:4] != b"\x7fELF":
        raise MissingBtf("not an ELF file")
    wide, order = data[4] == 2, "<" if data[5] == 1 else ">"
    if wide:
        shoff, = struct.unpack_from(order + "Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 0x3A)
        layout = order + "IIQQQQI"
    else:
        shoff, = struct.unpack_from(order + "I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 0x2E)
        layout = order + "IIIIIII"

    def header(index):
        name, _, _, _, offset, size, link = struct.unpack_from(layout, data, shoff + index * shentsize)
        return name, offset, size, link

    if shnum == 0:
        shnum = header(0)[2]
    if shstrndx == 0xFFFF:
        shstrndx = header(0)[3]
    _, names_at, names_size, _ = header(shstrndx)
    names = data[names_at:names_at + names_size]
    for index in range(shnum):
        name, offset, size, _ = header(index)
        if names[name:names.index(b"\0", name)] == wanted:
            return data[offset:offset + size]
    return None


def parse_btf(raw):
    """(strings, [(kind, name offset)]) of a raw BTF blob, either byte order."""
    if len(raw) < 24:
        raise MissingBtf("BTF too short")
    if struct.unpack_from("<H", raw)[0] == BTF_MAGIC:
        order = "<"
    elif struct.unpack_from(">H", raw)[0] == BTF_MAGIC:
        order = ">"
    else:
        raise MissingBtf("bad BTF magic")
    _, _, _, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from(order + "HBBIIIII", raw)
    strings = raw[hdr_len + str_off:hdr_len + str_off + str_len]
    types = []
    at, end = hdr_len + type_off, hdr_len + type_off + type_len
    while at < end:
        name, info, _ = struct.unpack_from(order + "III", raw, at)
        kind, vlen = (info >> 24) & 0x1F, info & 0xFFFF
        types.append((kind, name))
        at += 12 + FIXED_EXTRA.get(kind, 0) + ENTRY_SIZE.get(kind, 0) * vlen
    return strings, types


def strings_of(table):
    return [s for s in table.split(b"\0") if s]


def text_at(table, offset):
    return table[offset:table.index(b"\0", offset)] if 0 <= offset < len(table) else b""


def recorder_functions(system_map):
    """Function names only the recorder's code has, from System.map."""
    symbols = []
    for line in Path(system_map).read_text(errors="replace").splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols.append((int(fields[0], 16), fields[1], fields[2]))
    bounds = {name: address for address, _, name in symbols
              if name in ("ant_text_begin", "ant_text_end")}
    if len(bounds) != 2:
        return set()
    inside, outside = set(), set()
    for address, kind, name in symbols:
        if kind.lower() != "t" or name in bounds:
            continue
        if bounds["ant_text_begin"] <= address < bounds["ant_text_end"]:
            inside.add(name.encode())
        else:
            outside.add(name.encode())
    return inside - outside


def check(label, raw, recorder, base_strings=None, names=None):
    """Findings in one BTF: strings that are recorder names (the pattern, or for
    a module `names` and antinomie) and the recorder's functions."""
    strings, types = parse_btf(raw)
    if names is None:
        def bad(name):
            return FORBIDDEN.search(name) is not None
    else:
        def bad(name):
            return name in names or b"antinomie" in name.lower()
    findings = [f"{label}: BTF string {name.decode(errors='replace')!r}"
                for name in strings_of(strings) if bad(name)]
    if recorder:
        start = len(base_strings) if base_strings is not None else 0
        for kind, offset in types:
            if kind != KIND_FUNC:
                continue
            name = text_at(base_strings, offset) if offset < start else text_at(strings, offset - start)
            if name in recorder:
                findings.append(f"{label}: BTF function {name.decode()} is the recorder's")
    return findings, strings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--vmlinux", required=True)
    parser.add_argument("--system-map")
    parser.add_argument("--modules")
    parser.add_argument("--unfiltered")
    args = parser.parse_args(argv)
    unfiltered = Path(args.unfiltered) if args.unfiltered else \
        Path(args.vmlinux).parent / ".btf.vmlinux.full"
    recorder = recorder_functions(args.system_map) if args.system_map else set()
    try:
        raw = elf_section(Path(args.vmlinux).read_bytes(), b".BTF")
        if raw is None:
            raise MissingBtf(f"{args.vmlinux} has no .BTF section")
        findings, base_strings = check("vmlinux", raw, recorder)
        names = set()
        if unfiltered.is_file():
            names = {name for name in strings_of(parse_btf(unfiltered.read_bytes())[0])
                     if FORBIDDEN.search(name)}
        modules = []
        if args.modules:
            modules = sorted(p for p in Path(args.modules).rglob("*.ko*")
                             if p.name.endswith((".ko", ".ko.xz")))
        for module in modules:
            data = module.read_bytes()
            if module.suffix == ".xz":
                import lzma  # only for compressed modules; not every Python has it
                data = lzma.decompress(data)
            raw = elf_section(data, b".BTF")
            if raw is None:
                raise MissingBtf(f"{module} has no .BTF section")
            found, _ = check(module.name, raw, set(), base_strings, names)
            findings += found
    except MissingBtf as error:
        print(f"check-kernel-btf: {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"check-kernel-btf: {finding}", file=sys.stderr)
    print(f"check-kernel-btf: vmlinux and {len(modules)} module(s): "
          + ("clean" if not findings else f"{len(findings)} finding(s)"))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
