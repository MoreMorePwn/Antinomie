#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""The guest kernel's BTF names nothing of Antinomie.

- scripts/check-kernel-btf.py (run by every kernel build) finds recorder names
  and the recorder's own functions in vmlinux and module BTF;
- the series' BTF filter (scripts/antinomie_btf.py, added by a core patch)
  removes them from a vmlinux and a module BTF and keeps everything else;
- the series builds the recorder without debug information and runs the
  filter after pahole; the build script enables BTF and runs the check.
"""
import contextlib
import importlib.util
import io
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SERIES = REPO / "src/antinomie/core/6.12"
BUILD = REPO / "scripts/build-monitor-kernel.sh"
spec = importlib.util.spec_from_file_location("check_kernel_btf", REPO / "scripts/check-kernel-btf.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

INT, PTR, STRUCT, ENUM, FWD, FUNC, FUNC_PROTO, VAR, DATASEC, DECL_TAG = 1, 2, 4, 6, 7, 12, 13, 14, 15, 17


def patch_files():
    """{path: [patch file, ...]} of the files the core series touches."""
    touched = {}
    for patch in sorted(SERIES.glob("*.patch")):
        for line in patch.read_text().splitlines():
            if line.startswith("diff --git a/"):
                touched.setdefault(line.split()[2][2:], []).append(patch)
    return touched


def added_file(path):
    """The content of a file one core patch adds (the only patch touching it)."""
    patches = patch_files().get(path, [])
    if len(patches) != 1:
        raise AssertionError(f"{path}: expected one core patch adding it, found {patches}")
    lines, inside = [], False
    for line in patches[0].read_text().splitlines():
        if line.startswith("diff --git "):
            inside = line.split()[2] == "a/" + path
        elif inside and line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    return "\n".join(lines) + "\n"


def patch_hunks(path):
    """The added lines of every core patch hunk on `path`."""
    added, inside = [], False
    for patch in sorted(SERIES.glob("*.patch")):
        for line in patch.read_text().splitlines():
            if line.startswith("diff --git "):
                inside = line.split()[2] == "a/" + path
            elif inside and line.startswith("+") and not line.startswith("+++"):
                added.append(line[1:])
    return "\n".join(added)


class Writer:
    """A raw BTF blob, built type by type (ids from first_id)."""

    def __init__(self, first_id=1, base_strings=b""):
        self.types, self.first = [], first_id
        self.base = base_strings
        self.strings = bytearray(b"" if base_strings else b"\0")
        self.offsets = {}

    def name(self, text):
        if not text:
            return 0
        text = text.encode()
        at = self.base.find(b"\0" + text + b"\0")
        if at >= 0:
            return at + 1
        if text not in self.offsets:
            self.offsets[text] = len(self.base) + len(self.strings)
            self.strings += text + b"\0"
        return self.offsets[text]

    def add(self, kind, name, word, extra=b"", vlen=0):
        self.types.append(struct.pack("<III", self.name(name), (kind << 24) | vlen, word) + extra)
        return self.first + len(self.types) - 1

    def int(self, name, size):
        return self.add(INT, name, size, struct.pack("<I", size * 8))

    def struct(self, name, size, members):
        extra = b"".join(struct.pack("<III", self.name(n), t, bits) for n, t, bits in members)
        return self.add(STRUCT, name, size, extra, len(members))

    def enum(self, name, values):
        extra = b"".join(struct.pack("<Ii", self.name(n), v) for n, v in values)
        return self.add(ENUM, name, 4, extra, len(values))

    def proto(self, ret, params):
        extra = b"".join(struct.pack("<II", self.name(n), t) for n, t in params)
        return self.add(FUNC_PROTO, "", ret, extra, len(params))

    def blob(self):
        body = b"".join(self.types)
        return struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(body), len(body),
                           len(self.strings)) + body + bytes(self.strings)


def elf_with(sections):
    """A little-endian ELF64 relocatable holding `sections` ({name: bytes})."""
    names = b"\0" + b"".join(n.encode() + b"\0" for n in list(sections) + [".shstrtab"])
    data, offsets = bytearray(), []
    for content in list(sections.values()) + [names]:
        offsets.append(64 + len(data))
        data += content
    shoff = 64 + len(data)
    headers = bytearray(64)
    name_at = 1
    for (name, content), offset in zip(list(sections.items()) + [(".shstrtab", names)], offsets):
        kind = 3 if name == ".shstrtab" else 1
        headers += struct.pack("<IIQQQQIIQQ", name_at, kind, 0, 0, offset, len(content), 0, 0, 1, 0)
        name_at += len(name) + 1
    count = len(sections) + 2
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 1, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64,
                                 count, count - 1)
    return header + bytes(data) + bytes(headers)


def vmlinux_btf():
    """A vmlinux-like BTF with the recorder's names in it, and its ids."""
    w = Writer()
    ids = {}
    ids["int"] = w.int("int", 4)
    ids["u64"] = w.int("long long unsigned int", 8)
    ids["ant_task"] = w.struct("ant_task", 16, [("cookie", ids["u64"], 0), ("state", ids["int"], 64)])
    ids["ant_ptr"] = w.add(PTR, "", ids["ant_task"])
    ids["task_struct"] = w.struct("task_struct", 32, [
        ("pid", ids["int"], 0), ("ant_cookie", ids["u64"], 64),
        ("ant_monitor", ids["ant_ptr"], 128), ("tgid", ids["int"], 192)])
    ids["task_ptr"] = w.add(PTR, "", ids["task_struct"])
    ids["mode"] = w.enum("ant_mode", [("ANT_MODE_OFF", 0), ("ANT_MODE_ON", 1)])
    ids["stock_enum"] = w.enum("pid_type", [("PIDTYPE_PID", 0), ("ANT_PIDTYPE", 9),
                                            ("PIDTYPE_MAX_ANT_GAIN", 10)])
    ids["proto"] = w.proto(ids["int"], [("task", ids["task_ptr"])])
    ids["fork"] = w.add(FUNC, "do_fork", ids["proto"], vlen=1)
    ids["ant_proto"] = w.proto(ids["int"], [("monitor", ids["ant_ptr"])])
    ids["ant_func"] = w.add(FUNC, "ant_monitor_task", ids["ant_proto"], vlen=1)
    ids["tag"] = w.add(DECL_TAG, "rcu", ids["task_struct"], struct.pack("<i", 3))
    ids["percpu_ant"] = w.add(VAR, "ant_cpu_state", ids["int"], struct.pack("<I", 1))
    ids["percpu_stock"] = w.add(VAR, "runqueues", ids["int"], struct.pack("<I", 1))
    ids["datasec"] = w.add(DATASEC, ".data..percpu", 8, struct.pack("<III", ids["percpu_ant"], 0, 4)
                           + struct.pack("<III", ids["percpu_stock"], 4, 4), vlen=2)
    ids["orphan"] = w.add(FWD, "linux_binprm", 0)
    return w, ids


class Parsed:
    """Names and members of a raw BTF blob, through the filter's own parser."""

    def __init__(self, filt, raw, base=None):
        self.btf = filt.Btf(raw)
        self.base = base
        self.first = len(base.btf.types) + 1 if base else 1

    def string(self, offset):
        if self.base and offset < len(self.base.btf.strings):
            return self.base.string(offset)
        local = offset - (len(self.base.btf.strings) if self.base else 0)
        return self.btf.strings[local:self.btf.strings.index(b"\0", local)].decode()

    def type(self, type_id):
        if self.base and type_id < self.first:
            return self.base.type(type_id)
        return self.btf.types[type_id - self.first]

    def named(self, name):
        found = [i + self.first for i, t in enumerate(self.btf.types) if self.string(t[0]) == name]
        return found[0] if found else None


class CheckTests(unittest.TestCase):
    def test_the_check_finds_recorder_names_and_functions_and_passes_clean_btf(self):
        w, _ = vmlinux_btf()
        findings, _ = check.check("vmlinux", w.blob(), set())
        self.assertEqual({f.split("'")[1] for f in findings},
                         {"ant_task", "ant_cookie", "ant_monitor", "ant_mode", "ANT_MODE_OFF",
                          "ANT_MODE_ON", "ANT_PIDTYPE", "ant_monitor_task", "ant_cpu_state"})
        clean = Writer()
        proto = clean.proto(0, [])
        clean.add(FUNC, "decode_frame", proto)
        clean.add(FUNC, "want_reply", proto)
        clean.add(FUNC, "constant_tsc", proto)
        clean.add(FUNC, "ant_gain_set", proto)
        clean.add(FUNC, "NL80211_ATTR_MAX_ANT_GAIN", proto)
        # In a module only the recorder's own names (and antinomie) count.
        self.assertEqual(check.check("x.ko", clean.blob(), set(), b"", {b"ant_task"})[0], [])
        self.assertEqual(len(check.check("x.ko", clean.blob(), set(), b"", {b"ant_gain_set"})[0]), 1)
        findings, _ = check.check("vmlinux", clean.blob(), {b"decode_frame"})
        self.assertEqual(findings, ["vmlinux: BTF string 'ant_gain_set'",
                                    "vmlinux: BTF function decode_frame is the recorder's"])
        self.assertEqual(check.check("vmlinux", clean.blob(), set())[0],
                         ["vmlinux: BTF string 'ant_gain_set'"])

    def test_the_recorder_functions_come_from_its_text_range_less_stock_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            system_map = Path(tmp) / "System.map"
            system_map.write_text(
                "ffffffff81000000 T do_fork\n"
                "ffffffff81100000 T ant_text_begin\n"
                "ffffffff81100010 t decode_frame\n"
                "ffffffff81100020 t init_once\n"
                "ffffffff81100030 D some_data\n"
                "ffffffff81200000 T ant_text_end\n"
                "ffffffff81300000 t init_once\n")
            self.assertEqual(check.recorder_functions(system_map), {b"decode_frame"})

    def test_the_command_reads_elf_sections_and_reports_missing_btf(self):
        w, _ = vmlinux_btf()
        with tempfile.TemporaryDirectory() as tmp:
            vmlinux = Path(tmp) / "vmlinux"
            vmlinux.write_bytes(elf_with({".text": b"\x90" * 8, ".BTF": w.blob()}))
            modules = Path(tmp) / "modules"
            modules.mkdir()
            run = [sys.executable, "-I", str(REPO / "scripts/check-kernel-btf.py"),
                   "--vmlinux", str(vmlinux), "--modules", str(modules)]
            self.assertEqual(subprocess.run(run, capture_output=True).returncode, 1)
            (modules / "x.ko").write_bytes(elf_with({".text": b""}))
            vmlinux.write_bytes(elf_with({".BTF": Writer().blob()}))
            self.assertEqual(subprocess.run(run, capture_output=True).returncode, 2)
            (modules / "x.ko").unlink()
            result = subprocess.run(run, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


class FilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        path = Path(cls.tmp.name) / "antinomie_btf.py"
        path.write_text(added_file("scripts/antinomie_btf.py"))
        spec = importlib.util.spec_from_file_location("antinomie_btf", path)
        cls.filt = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.filt)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_vmlinux(self, w):
        tmp = Path(self.tmp.name)
        (tmp / "vmlinux").write_bytes(elf_with({".BTF": w.blob()}))
        with contextlib.redirect_stderr(io.StringIO()):
            self.filt.filter_vmlinux(tmp / "vmlinux", tmp / "full", tmp / "map", tmp / "out")
        self.assertEqual((tmp / "full").read_bytes(), w.blob())
        return (tmp / "out").read_bytes()

    def test_vmlinux_btf_loses_the_recorder_and_keeps_stock_layout(self):
        w, _ = vmlinux_btf()
        out = self.run_vmlinux(w)
        self.assertEqual(check.check("vmlinux", out, set())[0], [])
        btf = Parsed(self.filt, out)
        task = btf.type(btf.named("task_struct"))
        self.assertEqual(task[2], 32)
        self.assertEqual([(btf.string(m[0]), m[2]) for m in task[3]], [("pid", 0), ("tgid", 192)])
        # A stock name with _ANT_ inside it stays (nl80211 has one).
        stock_enum = btf.type(btf.named("pid_type"))
        self.assertEqual([btf.string(e[0]) for e in stock_enum[3]],
                         ["PIDTYPE_PID", "PIDTYPE_MAX_ANT_GAIN"])
        self.assertEqual(stock_enum[1] & 0xFFFF, 2)
        # The member tag moved with its member (index 3 -> 1).
        tag = btf.type(btf.named("rcu"))
        self.assertEqual((tag[2], tag[3]), (btf.named("task_struct"), 1))
        fork = btf.type(btf.named("do_fork"))
        param = btf.type(fork[2])[3][0]
        self.assertEqual(btf.type(btf.type(param[1])[2])[0], task[0])
        datasec = btf.type(btf.named(".data..percpu"))
        self.assertEqual([btf.string(btf.type(e[0])[0]) for e in datasec[3]], ["runqueues"])
        # Unreferenced stock types stay; what only the recorder used goes.
        self.assertIsNotNone(btf.named("linux_binprm"))
        names = {btf.string(t[0]) for t in btf.btf.types}
        self.assertNotIn("monitor", names)
        self.assertNotIn("cookie", names)
        self.assertEqual(len(btf.btf.types), 11)

    def test_vmlinux_keeps_the_strings_pahole_left_unused(self):
        # pahole's table keeps strings no type uses (Debian's BTF has them);
        # the filter keeps them in place, but not the removed types' and
        # members' names, nor an unused recorder name.
        w, _ = vmlinux_btf()
        w.name("orphan_param")
        w.name("ant_orphan")
        names = Parsed(self.filt, self.run_vmlinux(w)).btf.strings.split(b"\0")
        self.assertIn(b"orphan_param", names)
        for gone in (b"ant_orphan", b"monitor", b"cookie", b"ant_task"):
            self.assertNotIn(gone, names)
        self.assertLess(names.index(b"task_struct"), names.index(b"orphan_param"))

    def test_module_btf_is_remapped_onto_the_filtered_vmlinux(self):
        w, ids = vmlinux_btf()
        out = self.run_vmlinux(w)
        tmp = Path(self.tmp.name)
        m = Writer(first_id=len(w.types) + 1, base_strings=bytes(w.strings))
        own_ptr = m.add(PTR, "", ids["ant_task"])
        holder = m.struct("nft_holder", 32, [("task", ids["task_ptr"], 0), ("ant_task", own_ptr, 64),
                                             ("owner", own_ptr, 128), ("state", ids["ant_ptr"], 192)])
        proto = m.proto(ids["int"], [("holder", holder)])
        m.add(FUNC, "nft_holder_init", proto)
        m.add(FUNC, "ant_monitor_task", proto)
        (tmp / "x.ko").write_bytes(elf_with({".BTF": m.blob()}))
        with contextlib.redirect_stderr(io.StringIO()):
            self.filt.filter_module(tmp / "x.ko", tmp / "full", tmp / "map", tmp / "x.btf")
        raw = (tmp / "x.btf").read_bytes()
        _, base_strings = check.check("vmlinux", out, set())
        recorder = {b"ant_task", b"ant_cookie", b"ant_monitor"}
        self.assertEqual(check.check("x.ko", raw, set(), base_strings, recorder)[0], [])
        base = Parsed(self.filt, out)
        module = Parsed(self.filt, raw, base)
        holder = module.type(module.named("nft_holder"))
        # Members named after the recorder or pointing at its types went; the
        # size stays and the stock pointer points at the filtered task_struct.
        self.assertEqual(holder[2], 32)
        self.assertEqual([(module.string(m[0]), m[2]) for m in holder[3]], [("task", 0)])
        task_ptr = module.type(holder[3][0][1])
        self.assertEqual(module.string(module.type(task_ptr[2])[0]), "task_struct")
        self.assertEqual(len(module.btf.types), 3)
        self.assertIsNotNone(module.named("nft_holder_init"))
        self.assertIsNone(module.named("ant_monitor_task"))
        # "cookie" is gone from the base, so a module using it carries it.
        m2 = Writer(first_id=len(w.types) + 1, base_strings=bytes(w.strings))
        # A module's own ant_* name that vmlinux never had is a stock one
        # (wireless drivers' antenna fields): it stays.
        m2.struct("nft_cookie", 16, [("cookie", ids["u64"], 0), ("ant_gain", ids["int"], 64)])
        (tmp / "y.ko").write_bytes(elf_with({".BTF": m2.blob()}))
        with contextlib.redirect_stderr(io.StringIO()):
            self.filt.filter_module(tmp / "y.ko", tmp / "full", tmp / "map", tmp / "y.btf")
        module = Parsed(self.filt, (tmp / "y.btf").read_bytes(), base)
        members = module.type(module.named("nft_cookie"))[3]
        self.assertEqual([module.string(m[0]) for m in members], ["cookie", "ant_gain"])
        member = members[0]
        self.assertEqual(module.string(member[0]), "cookie")
        self.assertEqual(module.string(module.type(member[1])[0]), "long long unsigned int")


class SeriesTests(unittest.TestCase):
    def test_the_series_keeps_the_recorder_out_of_btf(self):
        self.assertIn("ccflags-remove-y += $(DEBUG_CFLAGS)", patch_hunks("kernel/antinomie/Makefile"))
        self.assertIn("antinomie_btf.py vmlinux", patch_hunks("scripts/link-vmlinux.sh"))
        self.assertIn("antinomie_btf.py module", patch_hunks("scripts/Makefile.modfinal"))
        self.assertIn("--btf_base .btf.vmlinux.full", patch_hunks("scripts/Makefile.modfinal"))

    def test_the_build_enables_btf_and_checks_every_kernel(self):
        script = BUILD.read_text()
        self.assertRegex(script, r"--enable DEBUG_INFO_BTF\b")
        self.assertIn("require_symbols DEBUG_INFO_BTF DEBUG_INFO_BTF_MODULES", script)
        checks = re.findall(r'check-kernel-btf\.py" --vmlinux "\$build_tree/vmlinux"', script)
        self.assertEqual(len(checks), 3, "every profile runs the BTF check")


if __name__ == "__main__":
    unittest.main()
