#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check a built guest kernel against Debian's: exports, structure layouts,
traceable functions.

    check-kernel-abi.py --vmlinux FILE --system-map FILE [--symvers FILE]
                        [--debian-image FILE] [--report FILE]

The stock kernel profile builds Debian's configuration with the recorder in,
so that Debian's own modules load into it and the guest sees Debian's kernel
(patches "keep stock structure layouts" and "keep the recorder out of the
function tracer"). This check fails when:

- a function the function tracer can attach to (vmlinux's __mcount_loc, the
  list tracefs's available_filter_functions shows) is the recorder's: inside
  System.map's ant_text_begin..ant_text_end, or named like the recorder
  (ant_*, antc_*, antinomie); always checked when vmlinux has the table;
- a function of the recorder has the name of a stock one: pahole would give a
  stock function Debian inlines a BTF entry for the recorder's symbol, and a
  name would resolve to two functions (fentry, kprobes); always checked;
- with --debian-image (Debian's linux-image package, its vmlinuz, or that
  kernel as an ELF file):
  - an exported symbol differs from Debian's kernel: missing, extra, another
    licence (EXPORT_SYMBOL or _GPL) or another modversions CRC (read from
    both kernels' __ksymtab and __kcrctab sections; --symvers, the build's
    vmlinux.symvers, is compared too);
  - the BTF differs: a named structure or union with another size or other
    members (name, offset, bit size, type), one only one kernel has, or a
    different number of types. Identical BTF (byte for byte) is reported as
    such: then Debian's module BTF, encoded against Debian's vmlinux type
    ids, is valid on this kernel too.

--report writes every difference (not only the first ones) to FILE. Exit
status 0 when clean, 1 with findings, 2 when an input cannot be read.
"""
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import argparse
import io
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile

RECORDER_NAME = re.compile(r"^_*antc?_|antinomie", re.IGNORECASE)
BTF_MAGIC = 0xEB9F
KIND_NAMES = {1: "int", 2: "ptr", 3: "array", 4: "struct", 5: "union", 6: "enum", 7: "fwd",
              8: "typedef", 9: "volatile", 10: "const", 11: "restrict", 12: "func",
              13: "func_proto", 14: "var", 15: "datasec", 16: "float", 17: "decl_tag",
              18: "type_tag", 19: "enum64"}
# Bytes after the 12-byte type header, per kind (vlen = entry count).
FIXED_EXTRA = {1: 4, 3: 12, 14: 4, 17: 4}
ENTRY_SIZE = {4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}
SHOWN = 40


class InputError(Exception):
    pass


class Elf:
    """Sections of a little-endian ELF64 image (a vmlinux)."""

    def __init__(self, data):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise InputError("not a little-endian 64-bit ELF file")
        self.data = data
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        headers = [struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize) for i in range(shnum)]
        names = headers[shstrndx]
        table = data[names[4]:names[4] + names[5]]
        self.sections = {}
        for name, kind, _, address, offset, size in headers:
            label = table[name:table.index(b"\0", name)].decode()
            self.sections[label] = (address, offset, size, kind)

    def section(self, name):
        if name not in self.sections:
            return None
        _, offset, size, kind = self.sections[name]
        return b"" if kind == 8 else self.data[offset:offset + size]

    def read(self, address, size):
        """Bytes at a virtual address, from the section that holds it."""
        for start, offset, length, kind in self.sections.values():
            if kind != 8 and start <= address and address + size <= start + length:
                return self.data[offset + address - start:offset + address - start + size]
        raise InputError(f"address {address:#x} is in no section")

    def cstring(self, address):
        for start, offset, length, kind in self.sections.values():
            if kind != 8 and start <= address < start + length:
                at = offset + address - start
                return self.data[at:self.data.index(b"\0", at)].decode()
        raise InputError(f"address {address:#x} is in no section")


def debian_vmlinux(path):
    """Debian's kernel as an ELF image, from its linux-image package, its
    vmlinuz (a zstd payload: Debian's compression) or the ELF itself."""
    data = Path(path).read_bytes()
    if data.startswith(b"!<arch>\n"):
        data = deb_vmlinuz(data)
    if data[:4] == b"\x7fELF":
        return data
    zstd = shutil.which("zstd")
    if zstd is None:
        raise InputError("zstd is needed to unpack Debian's vmlinuz")
    at = data.find(b"\x28\xb5\x2f\xfd")
    while at >= 0:
        result = subprocess.run([zstd, "-dcq"], input=data[at:], capture_output=True)
        if result.stdout[:4] == b"\x7fELF":
            return result.stdout
        at = data.find(b"\x28\xb5\x2f\xfd", at + 1)
    raise InputError(f"{path}: no zstd-compressed kernel found")


def deb_vmlinuz(data):
    """boot/vmlinuz-* of a .deb (an ar archive with a data.tar member)."""
    at = 8
    while at + 60 <= len(data):
        name = data[at:at + 16].decode().strip().rstrip("/")
        size = int(data[at + 48:at + 58].decode().strip())
        member = data[at + 60:at + 60 + size]
        if name.startswith("data.tar"):
            if name.endswith(".xz") and shutil.which("xz"):
                # Not every Python has lzma; xz-utils is a build tool anyway.
                member = subprocess.run(["xz", "-dc"], input=member, capture_output=True,
                                        check=True).stdout
            with tarfile.open(fileobj=io.BytesIO(member)) as archive:
                for entry in archive:
                    if re.fullmatch(r"(\./)?boot/vmlinuz-.*", entry.name) and entry.isfile():
                        return archive.extractfile(entry).read()
            raise InputError("the package has no boot/vmlinuz")
        at += 60 + size + (size & 1)
    raise InputError("the package has no data.tar member")


def exports(elf):
    """{name: (crc, licence)} from __ksymtab(_gpl) and __kcrctab(_gpl): with
    position-relative entries (x86-64), each struct kernel_symbol is three
    32-bit offsets, value, name and namespace, from their own fields."""
    found = {}
    for licence, table, crcs in (("EXPORT_SYMBOL", "__ksymtab", "__kcrctab"),
                                 ("EXPORT_SYMBOL_GPL", "__ksymtab_gpl", "__kcrctab_gpl")):
        if table not in elf.sections:
            continue
        address, _, size, _ = elf.sections[table]
        raw = elf.section(table)
        crc = elf.section(crcs) or b""
        if len(raw) % 12 or (crc and len(crc) != len(raw) // 3):
            raise InputError(f"{table} and {crcs} do not pair up")
        for index in range(len(raw) // 12):
            _, name_offset, _ = struct.unpack_from("<iii", raw, index * 12)
            name = elf.cstring(address + index * 12 + 4 + name_offset)
            value = struct.unpack_from("<I", crc, index * 4)[0] if crc else None
            found[name] = (value, licence)
    return found


def symvers(path):
    found = {}
    for line in Path(path).read_text().splitlines():
        fields = line.split("\t")
        if len(fields) >= 4 and fields[2] == "vmlinux":
            found[fields[1]] = (int(fields[0], 16), fields[3])
    return found


def compare_exports(label, ours, theirs):
    findings = []
    for name in sorted(set(theirs) - set(ours)):
        findings.append(f"{label}: Debian exports {name}, this kernel does not")
    for name in sorted(set(ours) - set(theirs)):
        findings.append(f"{label}: this kernel exports {name}, Debian's does not")
    for name in sorted(set(ours) & set(theirs)):
        if ours[name][1] != theirs[name][1]:
            findings.append(f"{label}: {name} is {ours[name][1]} here, {theirs[name][1]} in Debian")
        elif ours[name][0] is not None and ours[name][0] != theirs[name][0]:
            findings.append(f"{label}: {name} CRC {ours[name][0]:#010x}, "
                            f"Debian's {theirs[name][0]:#010x}")
    return findings


class Btf:
    """The types of a raw BTF blob: [(kind, name, info, size_or_type, extra, entries)]."""

    def __init__(self, raw):
        if len(raw) < 24 or struct.unpack_from("<H", raw)[0] != BTF_MAGIC:
            raise InputError("bad BTF")
        _, _, _, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from("<HBBIIIII", raw)
        self.strings = raw[hdr_len + str_off:hdr_len + str_off + str_len]
        self.types = [None]
        at, end = hdr_len + type_off, hdr_len + type_off + type_len
        while at < end:
            name, info, size_type = struct.unpack_from("<III", raw, at)
            kind, vlen = (info >> 24) & 0x1F, info & 0xFFFF
            at += 12
            extra = raw[at:at + FIXED_EXTRA.get(kind, 0)]
            at += len(extra)
            step = ENTRY_SIZE.get(kind, 0)
            entries = [struct.unpack_from("<" + "I" * (step // 4), raw, at + i * step)
                       for i in range(vlen)] if step else []
            at += step * vlen
            self.types.append((kind, self.text(name), info, size_type, extra, entries))

    def text(self, offset):
        return self.strings[offset:self.strings.index(b"\0", offset)].decode()

    def describe(self, type_id, depth=0):
        """A short name of a type, for comparing members."""
        if type_id == 0:
            return "void"
        kind, name, _, size_type, extra, entries = self.types[type_id]
        if name or depth > 3:
            return f"{KIND_NAMES.get(kind, kind)} {name}"
        if kind in (2, 8, 9, 10, 11, 18):
            return f"{KIND_NAMES[kind]}({self.describe(size_type, depth + 1)})"
        if kind == 3:
            elem, _, count = struct.unpack("<III", extra)
            return f"{self.describe(elem, depth + 1)}[{count}]"
        if kind == 13:
            params = ", ".join(self.describe(param[1], depth + 1) for param in entries)
            return f"proto {self.describe(size_type, depth + 1)}({params})"
        return f"anon {KIND_NAMES.get(kind, kind)} size {size_type}"

    def layouts(self):
        """{name: [layout, ...]} of every named structure and union."""
        found = {}
        for kind, name, info, size, _, entries in self.types[1:]:
            if kind not in (4, 5) or not name:
                continue
            bitfields = (info >> 31) & 1
            members = []
            for member_name, member_type, offset in entries:
                bits, at = (offset >> 24, offset & 0xFFFFFF) if bitfields else (0, offset)
                members.append((self.text(member_name), at, bits, self.describe(member_type)))
            found.setdefault(f"{KIND_NAMES[kind]} {name}", []).append((size, tuple(members)))
        return found


def compare_btf(ours_raw, theirs_raw):
    if ours_raw == theirs_raw:
        return [], "BTF identical to Debian's"
    ours, theirs = Btf(ours_raw), Btf(theirs_raw)
    findings = []
    mine, debian = ours.layouts(), theirs.layouts()
    for name in sorted(set(debian) - set(mine)):
        findings.append(f"BTF: {name} only in Debian's kernel")
    for name in sorted(set(mine) - set(debian)):
        findings.append(f"BTF: {name} only in this kernel")
    for name in sorted(set(mine) & set(debian)):
        if sorted(mine[name]) == sorted(debian[name]):
            continue
        a, b = sorted(mine[name])[0], sorted(debian[name])[0]
        detail = f"size {a[0]} (Debian {b[0]})" if a[0] != b[0] else "members differ"
        for left, right in zip(a[1], b[1]):
            if left != right:
                detail += f"; first difference: {left} (Debian {right})"
                break
        else:
            if len(a[1]) != len(b[1]):
                detail += f"; {len(a[1])} members (Debian {len(b[1])})"
        findings.append(f"BTF: {name}: {detail}")
    summary = (f"BTF differs: {len(ours.types) - 1} types (Debian {len(theirs.types) - 1}), "
               f"{len(findings)} named structure/union difference(s)")
    if len(ours.types) != len(theirs.types):
        findings.append(f"BTF: {len(ours.types) - 1} types, Debian's kernel "
                        f"{len(theirs.types) - 1}: Debian's module BTF does not match")
    elif not findings:
        findings.append("BTF: same structures, other bytes: Debian's module BTF may not match")
    return findings, summary


def system_map(path):
    symbols = []
    for line in Path(path).read_text(errors="replace").splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols.append((int(fields[0], 16), fields[1], fields[2]))
    return sorted(symbols)


def traceable(elf, symbols):
    """Findings for the function tracer's call sites (__mcount_loc, kept in
    .init.data between __start_mcount_loc and __stop_mcount_loc), or None
    when the kernel has no function tracer."""
    by_name = {name: address for address, _, name in symbols}
    if "__start_mcount_loc" not in by_name:
        return None, 0
    start, stop = by_name["__start_mcount_loc"], by_name["__stop_mcount_loc"]
    raw = elf.read(start, stop - start)
    sites = struct.unpack("<%dQ" % (len(raw) // 8), raw)
    begin, end = by_name.get("ant_text_begin"), by_name.get("ant_text_end")
    functions = [(address, name) for address, kind, name in symbols if kind.lower() == "t"]
    import bisect
    starts = [address for address, _ in functions]
    findings = set()
    for site in sites:
        if begin is not None and begin <= site < end:
            findings.add(f"traceable: a recorder function at {site:#x}")
            continue
        index = bisect.bisect_right(starts, site) - 1
        if index >= 0 and RECORDER_NAME.search(functions[index][1]):
            findings.add(f"traceable: {functions[index][1]}")
    return sorted(findings), len(sites)


def shared_names(symbols):
    """Findings for recorder functions named like a function outside it."""
    by_name = {name: address for address, _, name in symbols}
    begin, end = by_name.get("ant_text_begin"), by_name.get("ant_text_end")
    if begin is None or end is None:
        return []
    inside, outside = set(), set()
    for address, kind, name in symbols:
        if kind.lower() != "t" or name.startswith("__pfx_") or name in ("ant_text_begin",
                                                                       "ant_text_end"):
            continue
        (inside if begin <= address < end else outside).add(name)
    return [f"name: the recorder's {name} has a stock function's name"
            for name in sorted(inside & outside)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--vmlinux", required=True)
    parser.add_argument("--system-map", required=True)
    parser.add_argument("--symvers")
    parser.add_argument("--debian-image")
    parser.add_argument("--report")
    args = parser.parse_args(argv)
    findings, notes = [], []
    try:
        ours = Elf(Path(args.vmlinux).read_bytes())
        symbols = system_map(args.system_map)
        findings += shared_names(symbols)
        traced, sites = traceable(ours, symbols)
        if traced is None:
            notes.append("no function tracer")
        else:
            findings += traced
            notes.append(f"{sites} traceable call sites, none of the recorder"
                         if not traced else f"{sites} traceable call sites")
        if args.debian_image:
            debian = Elf(debian_vmlinux(args.debian_image))
            reference = exports(debian)
            mine = exports(ours)
            findings += compare_exports("exports", mine, reference)
            if args.symvers:
                findings += compare_exports("vmlinux.symvers", symvers(args.symvers), reference)
            notes.append(f"{len(reference)} Debian exports compared")
            mine_btf, debian_btf = ours.section(".BTF"), debian.section(".BTF")
            if mine_btf is None or debian_btf is None:
                raise InputError("a kernel has no .BTF section")
            found, summary = compare_btf(mine_btf, debian_btf)
            findings += found
            notes.append(summary)
    except (InputError, OSError, ValueError, struct.error, tarfile.TarError,
            subprocess.CalledProcessError) as error:
        print(f"check-kernel-abi: {error}", file=sys.stderr)
        return 2
    if args.report:
        Path(args.report).write_text("".join(f"{line}\n" for line in findings))
    for finding in findings[:SHOWN]:
        print(f"check-kernel-abi: {finding}", file=sys.stderr)
    if len(findings) > SHOWN:
        print(f"check-kernel-abi: ... {len(findings) - SHOWN} more", file=sys.stderr)
    print("check-kernel-abi: " + "; ".join(notes) + ": "
          + ("clean" if not findings else f"{len(findings)} finding(s)"))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
