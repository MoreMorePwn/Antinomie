#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""The stock kernel profile is Debian's kernel with the recorder in.

- scripts/check-kernel-abi.py (run by every stock-profile build) compares the
  exports and modversions CRCs, the BTF and the traceable functions with
  Debian's own kernel, read from its package;
- the stock profile changes nothing else of Debian's configuration, trusts
  Debian's module-signing certificate and runs the check; Debian Minimal is
  built on it.
"""
import importlib.util
import io
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "scripts/build-monitor-kernel.sh"
spec = importlib.util.spec_from_file_location("check_kernel_abi", REPO / "scripts/check-kernel-abi.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

STRUCT, INT = 4, 1
BASE = 0xFFFFFFFF82000000


def btf(structs):
    """A BTF blob: an int, then one struct per (name, size, [(member, bit offset)])."""
    strings = b"\0int\0"
    types = struct.pack("<III", 1, INT << 24, 4) + struct.pack("<I", 32)
    for name, size, members in structs:
        name_at = len(strings)
        strings += name.encode() + b"\0"
        types += struct.pack("<III", name_at, (STRUCT << 24) | len(members), size)
        for member, offset in members:
            member_at = len(strings)
            strings += member.encode() + b"\0"
            types += struct.pack("<III", member_at, 1, offset)
    header = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(types), len(types), len(strings))
    return header + types + strings


def vmlinux(exports, structs, mcount=()):
    """An ELF64 vmlinux with __ksymtab(_gpl), __kcrctab(_gpl), __ksymtab_strings,
    .BTF and the mcount table (.init.data); exports: [(name, crc, gpl)]."""
    names = b"".join(name.encode() + b"\0" for name, _, _ in exports)
    layout = [("__ksymtab_strings", names)]
    tables = {}
    for gpl in (False, True):
        chosen = [entry for entry in exports if entry[2] == gpl]
        tables[gpl] = chosen
        layout.append(("__ksymtab_gpl" if gpl else "__ksymtab", bytes(12 * len(chosen))))
        layout.append(("__kcrctab_gpl" if gpl else "__kcrctab",
                       b"".join(struct.pack("<I", crc) for _, crc, _ in chosen)))
    layout.append((".BTF", btf(structs)))
    layout.append((".init.data", b"".join(struct.pack("<Q", site) for site in mcount)))
    addresses, at = {}, BASE
    for name, data in layout:
        addresses[name] = at
        at += (len(data) + 15) & ~15
    sections = dict(layout)
    strings_at = addresses["__ksymtab_strings"]
    offsets = {name: names.index(name.encode() + b"\0") for name, _, _ in exports}
    for gpl in (False, True):
        table = "__ksymtab_gpl" if gpl else "__ksymtab"
        raw = b""
        for index, (name, _, _) in enumerate(tables[gpl]):
            field = addresses[table] + index * 12 + 4
            raw += struct.pack("<iii", 0, strings_at + offsets[name] - field, 0)
        sections[table] = raw
    shstr = b"\0" + b"".join(name.encode() + b"\0" for name, _ in layout) + b".shstrtab\0"
    body, headers = b"", [bytes(64)]
    data_at = 64
    for name, _ in layout:
        content = sections[name]
        headers.append(struct.pack("<IIQQQQIIQQ", shstr.index(name.encode() + b"\0"), 1, 2,
                                   addresses[name], data_at + len(body), len(content), 0, 0, 1, 0))
        body += content
    headers.append(struct.pack("<IIQQQQIIQQ", shstr.index(b".shstrtab\0"), 3, 0, 0,
                               data_at + len(body), len(shstr), 0, 0, 1, 0))
    body += shstr
    shoff = data_at + len(body)
    header = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(headers), len(headers) - 1)
    return header + body + b"".join(headers), addresses


def system_map(addresses, mcount_count, functions):
    start = addresses[".init.data"]
    lines = [f"{start:016x} D __start_mcount_loc", f"{start + 8 * mcount_count:016x} D __stop_mcount_loc"]
    lines += [f"{address:016x} T {name}" for address, name in functions]
    return "\n".join(lines) + "\n"


EXPORTS = [("printk", 0x1111, False), ("kmalloc_trace", 0x2222, True)]
STRUCTS = [("task_struct", 64, [("state", 0), ("flags", 32)])]
TEXT = 0xFFFFFFFF81000000
FUNCTIONS = [(TEXT, "schedule"), (TEXT + 0x100, "ant_text_begin"), (TEXT + 0x100, "ant_monitor_enter"),
             (TEXT + 0x200, "ant_text_end"), (TEXT + 0x300, "do_exit")]


class CheckTests(unittest.TestCase):
    def run_check(self, ours, theirs, mcount=(TEXT, TEXT + 0x300), our_exports=EXPORTS,
                  symvers=None):
        with tempfile.TemporaryDirectory() as name:
            tmp = Path(name)
            image, addresses = vmlinux(our_exports, ours, mcount)
            (tmp / "vmlinux").write_bytes(image)
            (tmp / "System.map").write_text(system_map(addresses, len(mcount), FUNCTIONS))
            (tmp / "debian").write_bytes(vmlinux(EXPORTS, theirs)[0])
            args = ["--vmlinux", str(tmp / "vmlinux"), "--system-map", str(tmp / "System.map"),
                    "--debian-image", str(tmp / "debian"), "--report", str(tmp / "report")]
            if symvers is not None:
                (tmp / "symvers").write_text(symvers)
                args += ["--symvers", str(tmp / "symvers")]
            import contextlib
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = check.main(args)
            return status, (tmp / "report").read_text().splitlines()

    def test_debians_own_kernel_is_clean(self):
        self.assertEqual(self.run_check(STRUCTS, STRUCTS), (0, []))
        symvers = "0x00001111\tprintk\tvmlinux\tEXPORT_SYMBOL\t\n" \
                  "0x00002222\tkmalloc_trace\tvmlinux\tEXPORT_SYMBOL_GPL\t\n" \
                  "0x00003333\tnf_x\tnet/x\tEXPORT_SYMBOL\t\n"
        self.assertEqual(self.run_check(STRUCTS, STRUCTS, symvers=symvers), (0, []))

    def test_a_changed_layout_is_found(self):
        grown = [("task_struct", 136, [("state", 0), ("flags", 32)])]
        status, report = self.run_check(grown, STRUCTS)
        self.assertEqual(status, 1)
        self.assertIn("BTF: struct task_struct: size 136 (Debian 64)", report[0])
        moved = [("task_struct", 64, [("state", 0), ("flags", 96)])]
        status, report = self.run_check(moved, STRUCTS)
        self.assertIn("first difference: ('flags', 96", report[0])
        status, report = self.run_check(STRUCTS + [("ant_task", 8, [])], STRUCTS)
        self.assertEqual(report[0], "BTF: struct ant_task only in this kernel")
        self.assertIn("Debian's module BTF does not match", report[-1])

    def test_exports_and_crcs_are_debians(self):
        changed = [("printk", 0x1112, False), ("kmalloc_trace", 0x2222, True)]
        status, report = self.run_check(STRUCTS, STRUCTS, our_exports=changed)
        self.assertEqual(report, ["exports: printk CRC 0x00001112, Debian's 0x00001111"])
        extra = EXPORTS + [("ant_send", 0x3333, True)]
        status, report = self.run_check(STRUCTS, STRUCTS, our_exports=extra)
        self.assertEqual(report, ["exports: this kernel exports ant_send, Debian's does not"])
        status, report = self.run_check(STRUCTS, STRUCTS, symvers="0x00001111\tprintk\tvmlinux\tEXPORT_SYMBOL_GPL\t\n")
        self.assertIn("vmlinux.symvers: Debian exports kmalloc_trace, this kernel does not", report)
        self.assertIn("vmlinux.symvers: printk is EXPORT_SYMBOL_GPL here, EXPORT_SYMBOL in Debian",
                      report)

    def test_no_recorder_function_is_traceable(self):
        status, report = self.run_check(STRUCTS, STRUCTS, mcount=(TEXT, TEXT + 0x104))
        self.assertEqual((status, report), (1, [f"traceable: a recorder function at {TEXT + 0x104:#x}"]))
        functions = FUNCTIONS + [(TEXT + 0x400, "ant_uring_begin")]
        with tempfile.TemporaryDirectory() as name:
            tmp = Path(name)
            image, addresses = vmlinux(EXPORTS, STRUCTS, (TEXT + 0x404,))
            elf = check.Elf(image)
            (tmp / "map").write_text(system_map(addresses, 1, functions))
            found, sites = check.traceable(elf, check.system_map(tmp / "map"))
            self.assertEqual((found, sites), (["traceable: ant_uring_begin"], 1))

    def test_arm64_sites_are_read_before_their_function(self):
        # arm64 with call ops records two NOPs before each function: the site
        # of a stock function right after a recorder function (or after the
        # recorder's end marker) is that stock function's.
        functions = FUNCTIONS + [(TEXT + 0x21c, "gid_cmp"), (TEXT + 0x400, "ant_uring_begin"),
                                 (TEXT + 0x440, "io_read")]
        sites = (TEXT + 0x21c - 8, TEXT + 0x440 - 8, TEXT + 0x300 - 8, TEXT + 0x110 - 8)
        with tempfile.TemporaryDirectory() as name:
            tmp = Path(name)
            image, addresses = vmlinux(EXPORTS, STRUCTS, sites)
            image = bytearray(image)
            image[0x12:0x14] = check.EM_AARCH64.to_bytes(2, "little")
            elf = check.Elf(bytes(image))
            (tmp / "map").write_text(system_map(addresses, len(sites), functions))
            found, count = check.traceable(elf, check.system_map(tmp / "map"))
            # Only the recorder function at +0x110 (its site is at +0x108).
            self.assertEqual((found, count), ([f"traceable: a recorder function at {TEXT + 0x108:#x}"], 4))
            # Read as x86-64, the io_read site would be ant_uring_begin's.
            found, _ = check.traceable(check.Elf(vmlinux(EXPORTS, STRUCTS, sites)[0]),
                                       check.system_map(tmp / "map"))
            self.assertIn("traceable: ant_uring_begin", found)
            self.assertIn("traceable: ant_text_end", found)

    def test_a_header_inline_kept_out_of_line_in_stock_files_is_no_finding(self):
        # arm64 inlines spin_lock_irq(); GCC keeps __raw_spin_lock_irq out of
        # line in some files, the recorder's among them.
        lines = system_map({".init.data": BASE}, 0, FUNCTIONS).splitlines()
        copy = lambda address: f"{address:016x} t __raw_spin_lock_irq"
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "map"
            path.write_text("\n".join(lines + [copy(TEXT + 0x180), copy(TEXT + 0x600),
                                                copy(TEXT + 0x700)]) + "\n")
            self.assertEqual(check.shared_names(check.system_map(path)), [])
            # One stock copy: the name was that function's alone.
            path.write_text("\n".join(lines + [copy(TEXT + 0x180), copy(TEXT + 0x600)]) + "\n")
            self.assertEqual(check.shared_names(check.system_map(path)),
                             ["name: the recorder's __raw_spin_lock_irq has a stock function's name"])

    def test_no_recorder_function_has_a_stock_name(self):
        functions = FUNCTIONS + [(TEXT + 0x180, "put_event"), (TEXT + 0x500, "put_event"),
                                 (TEXT + 0x180, "__pfx_do_exit")]
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "map"
            path.write_text(system_map({".init.data": BASE}, 0, functions))
            self.assertEqual(check.shared_names(check.system_map(path)),
                             ["name: the recorder's put_event has a stock function's name"])
            path.write_text(system_map({".init.data": BASE}, 0, FUNCTIONS))
            self.assertEqual(check.shared_names(check.system_map(path)), [])

    def test_debians_package_is_read(self):
        if shutil.which("zstd") is None:
            self.skipTest("zstd missing")
        elf = vmlinux(EXPORTS, STRUCTS)[0]
        packed = subprocess.run(["zstd", "-q", "-c"], input=elf, capture_output=True, check=True).stdout
        vmlinuz = b"MZ bzImage setup" + bytes(64) + packed + b"trailer"
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            entry = tarfile.TarInfo("./boot/vmlinuz-6.12.94+deb13-amd64")
            entry.size = len(vmlinuz)
            archive.addfile(entry, io.BytesIO(vmlinuz))
        member = data.getvalue()
        deb = b"!<arch>\n" + f"{'data.tar/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(member):<10}`\n".encode() + member
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "linux.deb"
            path.write_bytes(deb)
            self.assertEqual(check.debian_vmlinux(path), elf)
            (Path(name) / "vmlinuz").write_bytes(vmlinuz)
            self.assertEqual(check.debian_vmlinux(Path(name) / "vmlinuz"), elf)


    def test_debians_arm64_package_is_read_from_its_image_and_module_symvers(self):
        elf, _ = vmlinux(EXPORTS, STRUCTS)
        ours = check.Elf(elf)
        blob = ours.section(".BTF")
        # The Image as loaded: a header with the arm64 magic, code holding a
        # stray BTF magic, the BTF, more data. Its System.map is Debian's stub.
        image = bytearray(0x200) + b"\x9f\xeb\x01\x00" + bytes(60) + blob + bytes(0x100)
        image[0x38:0x3c] = check.ARM64_IMAGE_MAGIC
        stub = b"ffffffffffffffff B The real System.map is in the linux-image-<version>-dbg package\n"
        symvers = "".join(f"0x{crc:08x}\t{name}\tvmlinux\tEXPORT_SYMBOL{'_GPL' if gpl else ''}\t\n"
                          for name, crc, gpl in EXPORTS)
        symvers += "0x12345678\text4_get_inode\tfs/ext4/ext4\tEXPORT_SYMBOL\t\n"

        def deb(members):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w") as archive:
                for path, content in members.items():
                    entry = tarfile.TarInfo(path)
                    entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content))
            member = data.getvalue()
            return (b"!<arch>\n" + f"{'data.tar/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}"
                    f"{len(member):<10}`\n".encode() + member)

        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "linux-arm64.deb"
            path.write_bytes(deb({"./boot/vmlinuz-6.12.94+deb13-arm64": bytes(image),
                                  "./boot/System.map-6.12.94+deb13-arm64": stub}))
            headers = Path(name) / "linux-headers-arm64.deb"
            headers.write_bytes(deb({
                "./usr/src/linux-headers-6.12.94+deb13-arm64/Module.symvers": symvers.encode()}))
            for source in (headers, Path(name) / "Module.symvers"):
                (Path(name) / "Module.symvers").write_text(symvers)
                debian = check.debian_kernel(path, source)
                self.assertIsInstance(debian, check.DebianImage)
                # vmlinux's exports only, with their licences and CRCs.
                self.assertEqual(check.debian_exports(debian), check.exports(ours))
                self.assertEqual(debian.section(".BTF"), blob)
            # The bare Image reads the same.
            (Path(name) / "vmlinuz").write_bytes(bytes(image))
            self.assertEqual(check.debian_kernel(Path(name) / "vmlinuz", headers).section(".BTF"),
                             blob)
            # Without Module.symvers the exports are unknown.
            with self.assertRaises(check.InputError):
                check.debian_kernel(path)
            # Two complete blobs: which is the kernel's is unknown.
            (Path(name) / "twice").write_bytes(bytes(image) + blob)
            with self.assertRaises(check.InputError):
                check.debian_kernel(Path(name) / "twice", headers)


class ProfileTests(unittest.TestCase):
    def test_the_stock_profile_is_debians_configuration(self):
        script = BUILD.read_text()
        stock = script[script.index("if [[ $profile == stock ]]; then"):]
        stock = stock[:stock.index("\nfi\n")]
        # Debian's resolved configuration, its signing-key path holding Debian's
        # certificate, and only the recorder and the embedded configuration on top.
        self.assertIn('cat "${fragments[@]}" > "$reference/.config"', stock)
        self.assertIn('"$build_tree/output/signing_key.pem"', stock)
        self.assertIn('--set-str MODULE_SIG_KEY "output/signing_key.pem"', stock)
        self.assertIn("allowed=\"ANTINOMIE|ANTINOMIE_SOURCE_ID|IKCONFIG|IKCONFIG_PROC|KERNEL_GZIP|"
                      "KERNEL_ZSTD|LOCALVERSION|MODULE_SIG_KEY|BUILD_SALT\"", stock)
        self.assertIn('--set-str BUILD_SALT "6.12.94$DEBIAN_LOCALVERSION"', stock)
        self.assertIn("FUNCTION_TRACER DYNAMIC_FTRACE BPF_LSM", stock)
        # Only the image (bzImage, arm64's Image), never Debian's modules.
        build = stock[stock.index('LOCALVERSION= \\'):]
        self.assertIn('-j"$jobs" "$image"\n', build)
        self.assertNotIn(" modules", build.split("\n")[1])
        # Each architecture's own certificate; arm64's Image is not compressed.
        self.assertIn('debian-6.12.94-1-trixie/$signing"', stock)
        self.assertIn("--disable KERNEL_ZSTD --enable KERNEL_GZIP", stock.split("if [[ $arch == x86_64 ]]")[1])
        self.assertIn('check-kernel-abi.py" --vmlinux', stock)
        self.assertIn('--debian-image "$ANTINOMIE_DEBIAN_IMAGE"', stock)

    def test_the_certificate_is_debians_build_key(self):
        pem = REPO / "src/antinomie/packaging/debian-6.12.94-1-trixie/module-signing.pem"
        if shutil.which("openssl") is None:
            self.skipTest("openssl missing")
        out = subprocess.run(["openssl", "x509", "-in", str(pem), "-noout", "-subject", "-serial",
                              "-fingerprint", "-sha256"], capture_output=True, text=True, check=True)
        # OpenSSL 3.0 prints "CN = ...", later versions "CN=...".
        self.assertIn("CN=Build time autogenerated kernel key", out.stdout.replace(" = ", "="))
        # The signer serial Debian's modules name (modinfo -F sig_key ext4.ko.xz).
        self.assertIn("serial=2C0CF1742BAB754265C4800A1AB38D82A313624B", out.stdout)
        self.assertIn("C9:3C:88:15:4A:5B:FB:62:1D:83:21:40:19:C1:60:97:13:3A:EE:39:A1:D5:65:74:"
                      "95:64:41:A1:2A:4E:62:42", out.stdout)


    def test_the_arm64_certificate_is_debians_arm64_build_key(self):
        pem = REPO / "src/antinomie/packaging/debian-6.12.94-1-trixie/module-signing-arm64.pem"
        if shutil.which("openssl") is None:
            self.skipTest("openssl missing")
        out = subprocess.run(["openssl", "x509", "-in", str(pem), "-noout", "-subject", "-serial",
                              "-fingerprint", "-sha256"], capture_output=True, text=True, check=True)
        self.assertIn("CN=Build time autogenerated kernel key", out.stdout.replace(" = ", "="))
        # The signer serial Debian's arm64 modules name (modinfo -F sig_key
        # ext4.ko.xz of linux-image-6.12.94+deb13-arm64 6.12.94-1).
        self.assertIn("serial=39896D984ABB860B4592AB68060447BCC51E45D4", out.stdout)
        self.assertIn("E8:01:9A:AE:89:40:DA:8E:48:BD:62:08:9A:44:FA:DA:A5:B5:71:64:C0:C4:F2:6A:"
                      "60:46:A7:0D:E1:39:23:7E", out.stdout)


if __name__ == "__main__":
    unittest.main()
