#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""The guest kernel's /proc/kallsyms names nothing of the recorder.

- scripts/check-kernel-kallsyms.py (run by every kernel build) finds symbols
  of the recorder's objects outside every label pair of System.map that are
  not named like the recorder, and new names the series gives stock files;
- the series labels every kind of section the recorder's objects use
  (sections.h), and ant_symbol_hidden() checks every pair;
- the build script runs the check for every profile, and the app's kit
  carries it.
"""
import contextlib
import importlib.util
import io
import re
import struct
import tempfile
import unittest
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SERIES = REPO / "src/antinomie/core/6.12"
BUILD = REPO / "scripts/build-monitor-kernel.sh"
spec = importlib.util.spec_from_file_location("check_kernel_kallsyms",
                                              REPO / "scripts/check-kernel-kallsyms.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def elf_object(sections, symbols):
    """A little-endian ELF64 relocatable object. sections: [(name, flags)];
    symbols: [(name, section name or None for undefined, type)]."""
    names = [""] + [name for name, _ in sections] + [".symtab", ".strtab", ".shstrtab"]
    shstrtab, offsets = b"", {}
    for name in names:
        offsets[name] = len(shstrtab)
        shstrtab += name.encode() + b"\0"
    strtab, symtab = b"\0", bytes(24)
    index = {name: i + 1 for i, (name, _) in enumerate(sections)}
    for name, section, kind in symbols:
        at = len(strtab)
        strtab += name.encode() + b"\0"
        symtab += struct.pack("<IBBHQQ", at, (1 << 4) | kind, 0, index.get(section, 0), 0, 0)
    body = symtab + strtab + shstrtab
    shoff = 64 + len(body)
    symtab_at, strtab_at, shstrtab_at = 64, 64 + len(symtab), 64 + len(symtab) + len(strtab)
    headers = bytes(64)
    for name, flags in sections:
        headers += struct.pack("<IIQQQQIIQQ", offsets[name], 1, flags, 0, 64, 0, 0, 0, 1, 0)
    strtab_index = len(sections) + 2
    headers += struct.pack("<IIQQQQIIQQ", offsets[".symtab"], 2, 0, 0, symtab_at, len(symtab),
                           strtab_index, 1, 8, 24)
    headers += struct.pack("<IIQQQQIIQQ", offsets[".strtab"], 3, 0, 0, strtab_at, len(strtab), 0, 0, 1, 0)
    headers += struct.pack("<IIQQQQIIQQ", offsets[".shstrtab"], 3, 0, 0, shstrtab_at, len(shstrtab),
                           0, 0, 1, 0)
    header = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9) + struct.pack(
        "<HHIQQQIHHHHHH", 1, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(sections) + 4, len(sections) + 3)
    return header + body + headers


def thin_archive(members):
    """A kbuild-style thin archive naming `members` (no symbol index)."""
    longnames = b"".join(name.encode() + b"/\n" for name in members)
    longnames += b"\n" * (len(longnames) & 1)
    data = b"!<thin>\n" + b"//".ljust(16) + b" " * 32 + str(len(longnames)).encode().ljust(10) + b"`\n"
    data += longnames
    at = 0
    for name in members:
        data += f"/{at}".encode().ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) \
            + b"644".ljust(8) + b"1".ljust(10) + b"`\n"
        at += len(name) + 2
    return data


ALLOC, EXEC = 0x2, 0x4
FUNC, OBJECT, NOTYPE, SECTION = 2, 1, 0, 3

SYSTEM_MAP = """\
ffffffff81000000 T _stext
ffffffff81000100 T ant_text_begin
ffffffff81000110 t park_current
ffffffff81000200 t lock_helper
ffffffff81000300 W ant_text_end
ffffffff81000300 t stock_function
ffffffff81100000 T ant_unlikely_begin
ffffffff81100005 t park_current.cold
ffffffff81100010 W ant_unlikely_end
ffffffff81200000 d lock
ffffffff81300000 D ant_data_begin
ffffffff81300010 d lock
ffffffff81300020 W ant_data_end
ffffffff81400000 d pci_rules
ffffffff81500000 t facade_pci_param
ffffffff81500100 t ant_boot_gpa_param
ffffffff81600000 T ant_core_live_begin
"""


class CheckTests(unittest.TestCase):
    def run_check(self, recorder, text=SYSTEM_MAP):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "System.map"
            path.write_text(text)
            return check.check_symbols(check.read_system_map(path), Counter(recorder))

    def test_symbols_outside_every_pair_are_findings_unless_named_like_the_recorder(self):
        findings, only, pairs = self.run_check({"park_current": 1, "park_current.cold": 1,
                                                "pci_rules": 1, "facade_pci_param": 1,
                                                "ant_boot_gpa_param": 1, "lock_helper": 1})
        self.assertEqual(sorted(pairs), ["data", "text", "unlikely"], "a lone _begin is no pair")
        flagged = sorted(finding.split()[0] for finding in findings)
        self.assertEqual(flagged, ["facade_pci_param", "pci_rules"])
        self.assertEqual(sorted(only), ["lock_helper", "park_current", "park_current.cold"])

    def test_a_stock_namesake_counts_only_as_often_as_the_recorder_defines_it(self):
        findings, only, _ = self.run_check({"lock": 1})
        self.assertEqual(findings, [], "one recorder lock inside the pairs, one stock lock outside")
        self.assertNotIn("lock", only, "stock code has the name too")
        findings, _, _ = self.run_check({"lock": 2})
        self.assertEqual(len(findings), 1, "the recorder's second lock is outside")
        self.assertIn("0xffffffff81200000", findings[0])

    def test_a_kernel_without_the_labels_cannot_be_checked(self):
        with self.assertRaises(check.InputError):
            self.run_check({"x": 1}, "ffffffff81000000 T _stext\n")

    def test_the_names_rule_is_stealth_c_s(self):
        for name in ("ant_x", "__pfx_ant_x", "__setup_ant_x", "__initcall__kmod_x__1_2_ant_x_init7",
                     "antinomie_options"):
            self.assertTrue(check.ant_symbol_name(name), name)
        for name in ("facade_pci_param", "pci_rules", "want_x", "giant"):
            self.assertFalse(check.ant_symbol_name(name), name)
        stealth = "".join(line[1:] for line in patch_hunks("kernel/antinomie/stealth.c"))
        self.assertIn('return !strncmp(name, "ant_", 4) || strstr(name, "_ant_") || '
                      'strstr(name, "antinomie");', stealth)


class ObjectTests(unittest.TestCase):
    def test_objects_give_their_defined_symbols_in_kept_allocated_sections(self):
        data = elf_object(
            [(".text", ALLOC | EXEC), (".init.text", ALLOC | EXEC), (".data..ro_after_init", ALLOC),
             (".discard.addressable", ALLOC), (".modinfo", 0)],
            [("park_current", ".text", FUNC), ("facade_pci_param", ".init.text", FUNC),
             ("pci_rules", ".data..ro_after_init", OBJECT), ("__UNIQUE_ID_x", ".discard.addressable", OBJECT),
             ("__UNIQUE_ID_license", ".modinfo", OBJECT), ("printk", None, NOTYPE),
             (".text", ".text", SECTION), (".LC0", ".text", NOTYPE), ("$x", ".text", NOTYPE)])
        names = sorted(check.ElfFile(data, "x.o").defined_symbols())
        self.assertEqual(names, ["facade_pci_param", "park_current", "pci_rules"])

    def test_a_thin_built_in_archive_names_its_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "kernel/antinomie"
            directory.mkdir(parents=True)
            (directory / "a.o").write_bytes(elf_object([(".text", ALLOC | EXEC)], [("lock", ".text", FUNC)]))
            (directory / "b.o").write_bytes(elf_object([(".data", ALLOC)], [("lock", ".data", OBJECT)]))
            (directory / "built-in.a").write_bytes(thin_archive(["a.o", "b.o"]))
            self.assertEqual(check.recorder_symbols([directory / "built-in.a"]), Counter({"lock": 2}))
            (directory / "built-in.a").write_bytes(thin_archive(["a.o", "gone.o"]))
            with self.assertRaises(check.InputError):
                check.recorder_symbols([directory / "built-in.a"])

    def test_the_command_fails_on_a_leak_and_writes_the_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "System.map").write_text(SYSTEM_MAP)
            (tmp / "r.o").write_bytes(elf_object(
                [(".text", ALLOC | EXEC), (".data..ro_after_init", ALLOC)],
                [("park_current", ".text", FUNC), ("pci_rules", ".data..ro_after_init", OBJECT)]))
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                status = check.main(["--system-map", str(tmp / "System.map"), "--objects", str(tmp / "r.o"),
                                     "--write-names", str(tmp / "names.txt")])
            self.assertEqual(status, 1)
            self.assertIn("pci_rules", err.getvalue())
            self.assertEqual((tmp / "names.txt").read_text(), "park_current\n")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(check.main(["--system-map", str(tmp / "none"), "--names", str(tmp / "x")]), 2)


class SeriesLintTests(unittest.TestCase):
    PATCHES = {
        "0001-a.patch": """\
+++ b/drivers/of/fdt.c
@@ -1,3 +1,6 @@
 static ssize_t of_fdt_raw_read(struct file *filp)
+static const void *of_fdt_raw_blob;
+static const void *ant_fdt_blob;
+static DEFINE_MUTEX(blob_lock);
+int ant_parse(char *str);
+static inline bool live_core(void)
+static inline bool core_note_alloc(void)
-static void free_note_info(struct elf_note_info *info, int x)
+static void free_note_info(struct elf_note_info *info)
+++ b/kernel/antinomie/facade.c
+static int pci_rules[4] __ro_after_init;
""",
        "0002-b.patch": """\
+++ b/drivers/of/fdt.c
-static inline bool live_core(void)
+static __always_inline bool live_core(void)
""",
    }

    def test_new_names_in_stock_files_are_findings_unless_named_or_always_inline(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in self.PATCHES.items():
                (Path(tmp) / name).write_text(text)
            findings = check.series_definitions(tmp)
        named = sorted(re.search(r"defines (\S+),", finding).group(1) for finding in findings)
        self.assertEqual(named, ["blob_lock", "core_note_alloc", "of_fdt_raw_blob"])

    def test_the_series_gives_no_stock_file_a_name_only_this_kernel_has(self):
        self.assertEqual(check.series_definitions(SERIES), [])


def patch_hunks(path):
    """The added lines of every core patch hunk on `path`."""
    added, inside = [], False
    for patch in sorted(SERIES.glob("*.patch")):
        for line in patch.read_text().splitlines():
            if line.startswith("diff --git "):
                inside = line.split()[2] == "a/" + path
            elif inside and line.startswith("+") and not line.startswith("+++"):
                added.append(line)
    return added


def added_text(path):
    """What the series' patches add to `path`, joined."""
    return "\n".join(line[1:] for line in patch_hunks(path))


class SeriesTests(unittest.TestCase):
    KINDS = {"text", "unlikely", "rodata", "ro_after_init", "data", "read_mostly", "once", "bss",
             "percpu", "init_text", "init_data", "init_rodata", "init_setup"}

    def test_sections_h_labels_every_kind_and_stealth_c_checks_every_pair(self):
        sections = added_text("kernel/antinomie/sections.h")
        labelled = set(re.findall(r"ANT_SECTION_LABEL\(ant_(\w+)_##where", sections))
        self.assertEqual(labelled, self.KINDS)
        self.assertIn('#define ANT_SECTION_BIND_end ".weak"', sections)
        stealth = added_text("kernel/antinomie/stealth.c")
        checked = set(re.findall(r"\{ ant_(\w+)_begin, ant_\1_end \}", stealth))
        self.assertEqual(checked, self.KINDS)
        self.assertIn("} ant_section_labels[] __initconst = {", stealth)
        self.assertIn("ant_sections[ARRAY_SIZE(ant_section_labels)] __ro_after_init;", stealth)
        self.assertIn("early_initcall(ant_stealth_init);", stealth)

    def test_every_profile_runs_the_check_and_the_kit_carries_it(self):
        script = BUILD.read_text()
        self.assertIn('check-kernel-kallsyms.py" --system-map "$build_tree/System.map"', script)
        self.assertIn('--objects "$build_tree/kernel/antinomie/built-in.a" --series "$series_dir"', script)
        self.assertEqual(len(re.findall(r"^\s+check_kallsyms$", script, re.MULTILINE)), 2,
                         "minimal and extra, and stock")
        kit = (REPO / "src/antinomie/monitor/crates/monitor-core/build.rs").read_text()
        self.assertIn('"scripts/check-kernel-kallsyms.py",', kit)


if __name__ == "__main__":
    unittest.main()
