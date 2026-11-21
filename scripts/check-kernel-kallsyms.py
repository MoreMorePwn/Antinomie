#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check that a built guest kernel's /proc/kallsyms names nothing of the recorder.

    check-kernel-kallsyms.py --system-map FILE | --symbols FILE
                             --objects PATH... | --names FILE
                             [--series DIR] [--write-names FILE]

/proc/kallsyms lists every kernel symbol by name to any program. The guest
kernel leaves the recorder's own out (kernel/antinomie/stealth.c,
ant_symbol_hidden()): a symbol of kernel/antinomie is hidden by its address,
between a pair of labels ant_<kind>_begin and ant_<kind>_end that
kernel/antinomie/sections.h puts at the start and the end of each kind of
section the recorder uses, and any symbol is hidden by its name when
ant_symbol_name() matches it (ant_* and what the build names after it). A
recorder symbol in a section kind without a pair, with a name that does not
match, is listed. This check fails when:

- a symbol the recorder's objects define (--objects: kernel/antinomie's
  built-in.a, or its object files or directory) lies outside every label pair
  of System.map and is not named like the recorder. A name stock code also
  has (a static `lock`, `__func__.12`) counts as the recorder's only as often
  as the objects define it: the check fails when fewer copies of it lie
  inside the pairs than the recorder has;
- with --series, a patch of the series defines a function or variable in a
  stock file (anything outside the recorder's own files) whose name is new to
  that file and not named like the recorder, unless it is always inline: the
  address check sees only kernel/antinomie, and such a name is a symbol only
  this kernel has.

--symbols reads a base bundle's Volatility table (symbols.json or .json.xz)
instead of System.map, and --names a list of recorder symbol names (one per
line) instead of objects; with both, each name has one address, so a name
stock code also has is judged by whichever copy the table kept.
--write-names writes the recorder's names that stock code does not have (all
their copies are inside the pairs) and that are not named like the recorder:
the names a program must never find in /proc/kallsyms (stealth-probe reads
such a list). Exit status 0 when clean, 1 with findings, 2 when an input
cannot be read.
"""
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import struct
import sys

PAIR = re.compile(r"^ant_(\w+)_(begin|end)$")
SHOWN = 60
# ELF constants
SHT_SYMTAB = 2
SHF_ALLOC = 0x2
SHN_UNDEF, SHN_LORESERVE = 0, 0xFF00
STT_SECTION, STT_FILE = 3, 4
# Sections the final link drops: their symbols never reach System.map.
DROPPED = (".discard", ".modinfo", ".comment", ".debug", ".BTF")
# The recorder's own files (everything a patch adds under these), as opposed
# to the stock files its hooks change.
RECORDER_FILES = re.compile(r"^(kernel/antinomie/|include/linux/antinomie|arch/[^/]+/include/asm/antinomie"
                            r"|scripts/antinomie)")
SECTION_ATTRIBUTES = {"__initdata", "__initconst", "__ro_after_init", "__read_mostly", "__maybe_unused",
                      "__used", "__refdata", "__cacheline_aligned", "__page_aligned_data",
                      "__page_aligned_bss"}
ATTRIBUTE_CALLS = {"__aligned", "__section", "__attribute__", "__printf", "__alloc_size"}


class InputError(Exception):
    pass


def ant_symbol_name(name):
    """kernel/antinomie/stealth.c's ant_symbol_name()."""
    return name.startswith("ant_") or "_ant_" in name or "antinomie" in name


def read_system_map(path):
    symbols = []
    for line in Path(path).read_text(errors="replace").splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] not in ("U", "w", "v"):
            symbols.append((int(fields[0], 16), fields[1], fields[2]))
    if not symbols:
        raise InputError(f"{path}: no symbols")
    return symbols


def read_symbols_json(path):
    raw = Path(path).read_bytes()
    if path.endswith(".xz"):
        import lzma  # only for a compressed table; not every Python has it
        try:
            raw = lzma.decompress(raw)
        except lzma.LZMAError as error:
            raise InputError(f"{path}: {error}")
    table = json.loads(raw).get("symbols")
    if not isinstance(table, dict):
        raise InputError(f"{path}: no symbols table")
    return [(entry["address"] & 0xFFFFFFFFFFFFFFFF, "?", name)
            for name, entry in table.items() if name and "address" in entry]


def label_pairs(symbols):
    """{kind: (begin, end)} of the ant_<kind>_begin/_end labels both present."""
    found = {}
    for address, _, name in symbols:
        match = PAIR.match(name)
        if match:
            found.setdefault(match.group(1), {})[match.group(2)] = address
    pairs = {kind: (ends["begin"], ends["end"]) for kind, ends in found.items()
             if len(ends) == 2 and ends["begin"] <= ends["end"]}
    if "text" not in pairs:
        raise InputError("System.map has no ant_text_begin/ant_text_end: not a recorder kernel")
    return pairs


class ElfFile:
    def __init__(self, data, label):
        if data[:4] != b"\x7fELF":
            raise InputError(f"{label}: not an ELF file")
        self.wide, self.order, self.data, self.label = data[4] == 2, "<" if data[5] == 1 else ">", data, label
        o = self.order
        if self.wide:
            self.shoff, = struct.unpack_from(o + "Q", data, 0x28)
            self.shentsize, self.shnum, self.shstrndx = struct.unpack_from(o + "HHH", data, 0x3A)
        else:
            self.shoff, = struct.unpack_from(o + "I", data, 0x20)
            self.shentsize, self.shnum, self.shstrndx = struct.unpack_from(o + "HHH", data, 0x2E)
        if self.shnum == 0 and self.shoff:
            self.shnum = self.section(0)["size"]
        if self.shstrndx == 0xFFFF:
            self.shstrndx = self.section(0)["link"]
        names = self.section(self.shstrndx)
        self.shstrtab = data[names["offset"]:names["offset"] + names["size"]]

    def section(self, index):
        at = self.shoff + index * self.shentsize
        if self.wide:
            name, kind, flags, _, offset, size, link, _, _, entsize = \
                struct.unpack_from(self.order + "IIQQQQIIQQ", self.data, at)
        else:
            name, kind, flags, _, offset, size, link, _, _, entsize = \
                struct.unpack_from(self.order + "IIIIIIIIII", self.data, at)
        return {"name": name, "type": kind, "flags": flags, "offset": offset, "size": size,
                "link": link, "entsize": entsize}

    @staticmethod
    def text(table, offset):
        end = table.find(b"\0", offset)
        return table[offset:end if end >= 0 else len(table)].decode(errors="replace")

    def defined_symbols(self):
        """Names of the symbols defined in allocated sections the link keeps."""
        sections = [self.section(i) for i in range(self.shnum)]
        names = [self.text(self.shstrtab, s["name"]) for s in sections]
        for symtab in (s for s in sections if s["type"] == SHT_SYMTAB):
            strings = sections[symtab["link"]]
            strtab = self.data[strings["offset"]:strings["offset"] + strings["size"]]
            size = symtab["entsize"] or (24 if self.wide else 16)
            for at in range(symtab["offset"] + size, symtab["offset"] + symtab["size"], size):
                if self.wide:
                    name, info, _, shndx, _, _ = struct.unpack_from(self.order + "IBBHQQ", self.data, at)
                else:
                    name, _, _, info, _, shndx = struct.unpack_from(self.order + "IIIBBH", self.data, at)
                if shndx == SHN_UNDEF or shndx >= SHN_LORESERVE or (info & 0xF) in (STT_SECTION, STT_FILE):
                    continue
                section = sections[shndx]
                if not section["flags"] & SHF_ALLOC or names[shndx].startswith(DROPPED):
                    continue
                symbol = self.text(strtab, name)
                # Local labels and the arm64 mapping symbols ($x, $d) never reach System.map.
                if symbol and not symbol.startswith((".L", "$")):
                    yield symbol


def archive_members(path):
    """The object files of an archive: a kbuild thin built-in.a names them,
    a regular archive holds them."""
    data = path.read_bytes()
    thin = data.startswith(b"!<thin>\n")
    if not thin and not data.startswith(b"!<arch>\n"):
        raise InputError(f"{path}: not an archive")
    at, longnames = 8, b""
    while at + 60 <= len(data):
        header = data[at:at + 60]
        name, size = header[:16].decode().rstrip(), int(header[48:58].decode().strip() or 0)
        at += 60
        stored = not thin or name in ("/", "//", "/SYM64/")
        body = data[at:at + size] if stored else b""
        if name == "//":
            longnames = body
        elif name not in ("/", "/SYM64/"):
            if name.startswith("/") and name[1:].isdigit():
                offset = int(name[1:])
                name = longnames[offset:longnames.index(b"/\n", offset)].decode()
            else:
                name = name.rstrip("/")
            if thin:
                yield name, resolve_member(path, name)
            else:
                yield name, body
        if stored:
            at += size + (size & 1)


def resolve_member(archive, name):
    """A thin archive's member path: relative to the archive, or to the build
    tree root (kbuild writes paths like kernel/antinomie/bootstrap.o)."""
    member = Path(name)
    candidates = [member] if member.is_absolute() else \
        [archive.parent / member] + [parent / member for parent in archive.parents] + \
        [archive.parent / member.name]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.read_bytes()
    raise InputError(f"{archive}: member {name} not found")


def recorder_symbols(paths):
    """Counter of the names the recorder's objects define."""
    counts = Counter()
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            items = [(p.name, p.read_bytes()) for p in sorted(path.glob("*.o"))]
        elif path.suffix == ".a":
            items = list(archive_members(path))
        else:
            items = [(path.name, path.read_bytes())]
        if not items:
            raise InputError(f"{path}: no object files")
        for label, data in items:
            counts.update(ElfFile(data, label).defined_symbols())
    return counts


def check_symbols(symbols, recorder):
    """Findings: recorder symbols outside every label pair, not named like the
    recorder. Also returns the recorder names stock code does not have."""
    pairs = label_pairs(symbols)
    inside, outside = Counter(), {}
    for address, kind, name in symbols:
        if name not in recorder or PAIR.match(name):
            continue
        if any(begin <= address < end for begin, end in pairs.values()):
            inside[name] += 1
        else:
            outside.setdefault(name, []).append((address, kind))
    findings, only = [], []
    for name, count in sorted(recorder.items()):
        if ant_symbol_name(name) or PAIR.match(name):
            continue
        if name in outside and inside[name] < count:
            for address, kind in outside[name]:
                findings.append(f"{name} ({kind} {address:#x}) is the recorder's, outside every "
                                f"label pair, and not named like the recorder")
        elif name not in outside and inside[name]:
            only.append(name)
    return findings, only, pairs


def definition(line):
    """(name, always inline) of the function or variable an added line of a
    patch defines at file scope, or None. A heuristic for the kernel's style:
    a definition starts in the first column with its type, and a macro that
    defines a variable is DEFINE_*(name, ...) or DEFINE_PER_CPU*(type, name)."""
    text = line[1:]
    if not re.match(r"[A-Za-z_]", text) or text.rstrip().endswith("\\") or \
            re.match(r"(typedef|extern|return|if|else|for|while|switch|case|goto|do)\b", text):
        return None
    macro = re.match(r"(?:static\s+)?((?:DEFINE|DECLARE)_\w+)\s*\(([^)]*)\)", text)
    if macro:
        args = [arg.strip() for arg in macro.group(2).split(",")]
        name = args[-1] if macro.group(1).startswith("DEFINE_PER_CPU") else args[0]
        return (name, False) if re.match(r"^[A-Za-z_]\w*$", name) else None
    head = re.match(r"([^(\[=;{]*)([(\[=;])", text)
    if not head:
        return None
    tokens = head.group(1).replace("*", " ").split()
    # An attribute with arguments before the name's delimiter: x __aligned(8) = ...
    if head.group(2) == "(" and tokens and tokens[-1] in ATTRIBUTE_CALLS:
        tokens.pop()
    if head.group(2) != "(":
        while tokens and tokens[-1] in SECTION_ATTRIBUTES:
            tokens.pop()
    # A type and a name at least; a prototype (ending in ");") defines nothing.
    if len(tokens) < 2 or not all(re.match(r"^[A-Za-z_]\w*$", token) for token in tokens) or \
            tokens[0] in ("struct", "union", "enum") and len(tokens) == 2 and head.group(2) == ";" or \
            head.group(2) == "(" and text.rstrip().endswith(");"):
        return None
    return tokens[-1], "__always_inline" in tokens


def series_definitions(series_dir):
    """Findings: functions and variables the series defines in a stock file
    under a name that file did not have before the series (never on a removed
    or context line before a patch added it), not named like the recorder and
    not always inline as the series leaves them."""
    stock, latest = {}, {}
    for patch in sorted(Path(series_dir).glob("*.patch")):
        current, added, removed = None, {}, set()
        for line in patch.read_text(errors="replace").splitlines():
            if line.startswith("+++ "):
                current = line[6:] if line.startswith("+++ b/") else None
                continue
            if line.startswith("--- ") or current is None or RECORDER_FILES.match(current):
                continue
            if line.startswith(("-", " ")):
                stock.setdefault(current, set()).update(
                    word for word in re.findall(r"[A-Za-z_]\w*", line[1:]) if (current, word) not in latest)
                found = definition(line) if line.startswith("-") else None
                if found:
                    removed.add((current, found[0]))
            elif line.startswith("+"):
                found = definition(line)
                if found:
                    added[(current, found[0])] = (patch.name, found[1])
        # A definition a patch removes and does not add back is gone.
        for key in removed - set(added):
            latest.pop(key, None)
        latest.update(added)
    return [f"{patch}: {path} defines {name}, a name only this kernel has (not ant_*)"
            for (path, name), (patch, inline) in sorted(latest.items())
            if not inline and not ant_symbol_name(name) and name not in stock.get(path, set())]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--system-map")
    source.add_argument("--symbols")
    names = parser.add_mutually_exclusive_group(required=True)
    names.add_argument("--objects", nargs="+")
    names.add_argument("--names")
    parser.add_argument("--series")
    parser.add_argument("--write-names")
    args = parser.parse_args(argv)
    try:
        symbols = read_system_map(args.system_map) if args.system_map else read_symbols_json(args.symbols)
        if args.objects:
            recorder = recorder_symbols(args.objects)
        else:
            recorder = Counter(line.strip() for line in Path(args.names).read_text().splitlines()
                               if line.strip() and not line.startswith("#"))
        if not recorder:
            raise InputError("no recorder symbols")
        findings, only, pairs = check_symbols(symbols, recorder)
        if args.series:
            findings += series_definitions(args.series)
    except (InputError, OSError, ValueError, KeyError, struct.error) as error:
        print(f"check-kernel-kallsyms: {error}", file=sys.stderr)
        return 2
    if args.write_names:
        Path(args.write_names).write_text("".join(f"{name}\n" for name in only))
    for finding in findings[:SHOWN]:
        print(f"check-kernel-kallsyms: {finding}", file=sys.stderr)
    if len(findings) > SHOWN:
        print(f"check-kernel-kallsyms: ... {len(findings) - SHOWN} more", file=sys.stderr)
    print(f"check-kernel-kallsyms: {len(recorder)} recorder names, {len(pairs)} label pairs "
          f"({', '.join(sorted(pairs))}): "
          + ("clean" if not findings else f"{len(findings)} finding(s)"))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
