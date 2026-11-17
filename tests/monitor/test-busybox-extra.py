#!/usr/bin/env python3
"""The BusyBox camera base (profile busybox-extra, ANT-T0558): its recipe
(scripts/busybox_extra.py), its orchestrator profile and the stand-in vendor
program; no kernel build, no network."""
# SPDX-License-Identifier: GPL-3.0-only
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, REPO / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


image = load("monitor_image", "scripts/build-monitor-image.py")
extra = load("busybox_extra", "scripts/busybox_extra.py")
base = load("build_base", "scripts/build-base.py")
BARE_ELF = b"\x7fELF\x02\x01\x01" + bytes(57)


class RecipeTests(unittest.TestCase):
    def test_the_root_password_hash_is_crypts_md5_scheme(self):
        # Checked against `openssl passwd -1 -salt SALT PASSWORD`.
        self.assertEqual(extra.md5_crypt("vizxv", "Dh4u0K9q"), "$1$Dh4u0K9q$8RFvrDB4ayd/OfLrvQ4jU.")
        self.assertEqual(extra.md5_crypt("a" * 40, "saltsalt"),
                         "$1$saltsalt$xbcEYb2v/vQerF.rDxN620")
        salt = extra.password_salt("dahua-xvr")
        self.assertRegex(salt, r"^[./0-9A-Za-z]{8}$")
        self.assertEqual(salt, extra.password_salt("dahua-xvr"), "reproducible")

    def test_the_flash_layout_is_the_mtdparts_option(self):
        flash = extra.DEVICE_PROFILES["dahua-xvr"]["flash"]
        self.assertEqual(extra.mtdparts(flash),
                         "mtdparts=hi_sfc:256k(boot),2048k(kernel),12288k(rootfs),-(config)")
        fixed = sum(size for _, size in flash["partitions"] if size)
        self.assertLess(fixed, flash["size_kib"])
        for _, size in flash["partitions"]:
            self.assertEqual((size or 0) % flash["erase_kib"], 0, "whole erase blocks")
        self.assertEqual(flash["size_kib"] % flash["erase_kib"], 0)

    def test_every_device_profile_is_complete_and_the_first_is_the_default(self):
        self.assertEqual(extra.device_profile()[0], next(iter(extra.DEVICE_PROFILES)))
        with self.assertRaisesRegex(RuntimeError, "unknown device profile"):
            extra.device_profile("nope")
        for name, device in extra.DEVICE_PROFILES.items():
            image.valid_hostname(device["hostname"])
            self.assertRegex(device["mac_prefix"], r"^[0-9a-f]{2}(:[0-9a-f]{2}){2}$", name)
            self.assertTrue(0 < device["vendor_port"] < 65536)
            self.assertTrue(device["program"].startswith("/usr/bin/"))
            names = [part for part, _ in device["flash"]["partitions"]]
            self.assertEqual(names, ["boot", "kernel", "rootfs", "config"], name)
            # The app's default hostname for the profile is the first device's.
        app = (REPO / "src/antinomie/monitor/crates/monitor-core/src/build.rs").read_text()
        self.assertIn(f'"{extra.DEVICE_PROFILES[extra.DEFAULT_DEVICE]["hostname"]}".into()', app)

    def test_the_packages_are_pinned_for_every_architecture_of_the_bases(self):
        self.assertEqual(set(extra.PACKAGES), set(image.USERLANDS))
        for arch, packages in extra.PACKAGES.items():
            self.assertEqual([name for name, _, _ in packages],
                             ["iptables", "libxtables12", "libip4tc2", "libip6tc2"], arch)
            for _, version, sha in packages:
                self.assertRegex(version, r"^\d")
                self.assertRegex(sha, r"^[0-9a-f]{64}$")
            self.assertTrue(set(extra.COMPILERS[arch]), arch)

    def test_the_kernel_symbols_are_words_the_kernel_script_reads(self):
        words = re.sub(r"#.*", "", (REPO / "src/antinomie/packaging/kconfig/busybox-extra.cfg")
                       .read_text()).split()
        self.assertTrue(words)
        for word in words:
            self.assertRegex(word, r"^(!?[A-Z0-9_]+|[A-Z0-9_]+=\d+)$")
        for wanted in ("SOFT_WATCHDOG", "MTD_BLOCK2MTD", "MTD_CMDLINE_PARTS", "BLK_DEV_RAM",
                       "IP_NF_IPTABLES", "IP_NF_NAT", "JFFS2_FS", "!ITCO_WDT", "!MTD_PHYSMAP"):
            self.assertIn(wanted, words)
        script = (REPO / "scripts/build-monitor-kernel.sh").read_text()
        self.assertIn("kconfig/busybox-extra.cfg", script)
        self.assertIn("extra) build_tree=", script)


class CameraTreeTests(unittest.TestCase):
    """extra_tree on a BusyBox base tree made from stand-ins of the pinned packages."""

    def userland(self, root, arch):
        tree = Path(root) / "packages"
        owners = {"usr/bin/busybox": "busybox-static"}
        (tree / "usr/bin").mkdir(parents=True)
        (tree / "usr/bin/busybox").write_bytes(b"busybox")
        (tree / "usr/bin/busybox").chmod(0o755)
        multiarch = image.LIBRARY_DIRS[arch][0]
        loader = Path(image.GLIBC_LOADERS[arch]).name
        (tree / multiarch / "xtables").mkdir(parents=True)
        for name in image.GLIBC_LIBRARIES + (loader,):
            (tree / multiarch / name).write_bytes(BARE_ELF + name.encode())
            owners[f"{multiarch}/{name}"] = "libc6"
        for name, package in (("libxtables.so.12", "libxtables12"), ("libip4tc.so.2", "libip4tc2"),
                              ("libip6tc.so.2", "libip6tc2")):
            (tree / multiarch / name).write_bytes(BARE_ELF + name.encode())
            owners[f"{multiarch}/{name}"] = package
        (tree / "usr/sbin").mkdir(parents=True)
        (tree / "usr/sbin/xtables-legacy-multi").write_bytes(BARE_ELF + b"multi")
        owners["usr/sbin/xtables-legacy-multi"] = "iptables"
        for name in ("libxt_tcp.so", "libxt_NAT.so", "libebt_ip.so", "libarpt_mangle.so"):
            (tree / multiarch / "xtables" / name).write_bytes(BARE_ELF + name.encode())
            owners[f"{multiarch}/xtables/{name}"] = "iptables"
        (tree / multiarch / "xtables/libxt_REDIRECT.so").symlink_to("libxt_NAT.so")
        userland = image.Userland(tree, [], owners, arch)
        userland.applets = lambda: ["[", "cat", "sh", "telnetd", "crond"]
        return userland

    def camera_tree(self, arch="x86_64"):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        userland = self.userland(directory.name, arch)
        root = Path(directory.name) / "root"

        def install(source, root_, destination, userland_):
            target = root_ / destination.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

        def build(arch_, port, output):
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(f"camera {arch_} {port}".encode())
            return output

        with patch.object(image, "install_binary", install), \
                patch.object(extra, "build_camera", build):
            image.base_tree(root, "xvr", userland, image.CONSOLES[arch])
            additions = extra.extra_tree(root, userland, image, None, Path(directory.name))
        return root, userland, additions

    def test_the_services_start_from_the_start_script_after_the_network(self):
        root, _, additions = self.camera_tree()
        rcs = (root / "etc/init.d/rcS").read_text()
        services = rcs.index("syslogd\nklogd\ncrond\ntelnetd -b 0.0.0.0\n")
        self.assertLess(rcs.index("udhcpc"), services)
        self.assertLess(services, rcs.index("echo 'BusyBox guest ready'"))
        self.assertIn("setsid /usr/bin/sonia </dev/null >/dev/null 2>&1 &", rcs)
        # The DHCP client keeps its lease (no -f, no -q).
        self.assertIn("udhcpc -i eth0 -s /etc/udhcpc/default.script -n -t 5 -T 1 -p /run/", rcs)
        self.assertNotIn("-f -q", rcs)
        self.assertEqual((root / "usr/bin/sonia").read_bytes(), b"camera x86_64 37777")
        self.assertEqual([service["ports"] for service in additions["base_services"][:2]],
                         [[23], [80, 554, 37777]])

    def test_the_flash_watchdog_and_mac_prefix_are_set_up_at_boot(self):
        root, _, additions = self.camera_tree()
        rcs = (root / "etc/init.d/rcS").read_text()
        self.assertIn("echo /dev/ram0,64KiB,hi_sfc > /sys/module/block2mtd/parameters/block2mtd",
                      rcs)
        # 64 KiB doubled four times to 1 MiB, copied 16 times: 16 MiB.
        self.assertIn("for i in $(seq 4); do", rcs)
        self.assertIn("while [ $i -lt 16 ]", rcs)
        self.assertIn("mount -t jffs2 /dev/mtdblock3 /mnt/mtd", rcs)
        # The services first: a run may start before the start script ends.
        self.assertLess(rcs.index("setsid /usr/bin/sonia"), rcs.index("block2mtd"))
        self.assertLess(rcs.index("block2mtd"), rcs.index("echo 'BusyBox guest ready'"))
        mac = rcs.index("ip link set eth0 address 3c:ef:8c:${mac#*:*:*:}")
        self.assertLess(rcs.index("if ip link show eth0"), mac)
        self.assertLess(mac, rcs.index("    ip link set eth0 up"))
        self.assertEqual(additions["kernel_append"],
                         "mtdparts=hi_sfc:256k(boot),2048k(kernel),12288k(rootfs),-(config) "
                         "softdog.soft_noboot=1")
        device = additions["device"]
        self.assertEqual((device["profile"], device["maker"], device["watchdog"]),
                         ("dahua-xvr", "Dahua", "/dev/watchdog"))
        self.assertTrue((root / "mnt/mtd").is_dir())
        self.assertEqual((root / "var/spool/cron/crontabs").stat().st_mode & 0o777, 0o700)

    def test_root_has_the_makers_default_password_and_the_identity_files(self):
        root, _, _ = self.camera_tree()
        passwd = (root / "etc/passwd").read_text().splitlines()
        hashed = passwd[0].split(":")[1]
        self.assertTrue(passwd[0].startswith("root:$1$"))
        salt = hashed.split("$")[2]
        self.assertEqual(extra.md5_crypt("vizxv", salt), hashed)
        self.assertEqual(passwd[1], "user:x:1000:1000:user,,,:/home/user:/bin/sh")
        self.assertEqual((root / "etc/version").read_text(), "V4.001.0000000.4.R\n")
        self.assertEqual((root / "etc/model").read_text(), "DH-XVR5104HS-I3\n")
        self.assertEqual((root / "etc/build_date").read_text(), "2022-06-14\n")
        self.assertEqual((root / "etc/hostname").read_text(), "xvr\n")

    def test_iptables_legacy_and_its_libraries_sit_beside_glibc(self):
        root, userland, additions = self.camera_tree()
        self.assertEqual(os.readlink(root / "usr/sbin/iptables"), "xtables-legacy-multi")
        self.assertEqual(os.readlink(root / "usr/sbin/ip6tables-save"), "xtables-legacy-multi")
        for name in ("libxtables.so.12", "libip4tc.so.2", "libip6tc.so.2"):
            self.assertTrue((root / "lib" / name).is_file(), name)
        self.assertEqual(userland.installed["lib/libxtables.so.12"], "libxtables12")
        extensions = root / "usr/lib/x86_64-linux-gnu/xtables"
        self.assertEqual(sorted(path.name for path in extensions.iterdir()),
                         ["libxt_NAT.so", "libxt_REDIRECT.so", "libxt_tcp.so"])
        self.assertEqual(os.readlink(extensions / "libxt_REDIRECT.so"), "libxt_NAT.so")
        self.assertEqual(additions["device"]["iptables_extensions"], 2)
        # No second C library in the multiarch folder.
        self.assertFalse((root / "usr/lib/x86_64-linux-gnu/libc.so.6").exists())

    def test_an_extension_that_needs_a_missing_library_is_left_out(self):
        real = image.elf_needs

        def needs(path):
            if Path(path).name == "libxt_NAT.so":
                return ["libnetfilter_conntrack.so.3", "libc.so.6"], None
            return real(path)

        with patch.object(image, "elf_needs", needs):
            root, _, _ = self.camera_tree()
        names = sorted(path.name for path in (root / "usr/lib/x86_64-linux-gnu/xtables").iterdir())
        self.assertEqual(names, ["libxt_tcp.so"])

    def test_an_arm64_camera_base_names_its_loader_and_its_compiler(self):
        root, _, _ = self.camera_tree("arm64")
        self.assertEqual((root / "usr/bin/sonia").read_bytes(), b"camera arm64 37777")
        self.assertTrue((root / "usr/lib/aarch64-linux-gnu/xtables/libxt_tcp.so").is_file())
        with patch.object(shutil, "which", return_value=None), \
                self.assertRaisesRegex(RuntimeError, "aarch64-linux-gnu-gcc-14"):
            extra.compiler("arm64")


def run_in_netns(program, client):
    """Run the vendor program as root of a new network namespace and the
    client script against it; the client's output."""
    script = Path(program).parent / "client.py"
    script.write_text(client)
    shell = """ip link set lo up
"$1" &
pid=$!
sleep 0.5
"$2" -I "$3"
status=$?
kill $pid
exit $status
"""
    return subprocess.run(["unshare", "-rn", "sh", "-c", shell, "sh", str(program), sys.executable,
                           str(script)], capture_output=True, text=True, timeout=60)


def netns_works():
    if not (shutil.which("unshare") and shutil.which("ip")):
        return False
    probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
    return probe.returncode == 0


class CameraProgramTests(unittest.TestCase):
    @unittest.skipUnless(any(shutil.which(name) for name in extra.COMPILERS["x86_64"])
                         and os.uname().machine == "x86_64", "needs an x86-64 compiler and host")
    def test_it_builds_freestanding_and_static_for_x86_64(self):
        with tempfile.TemporaryDirectory() as name:
            program = extra.build_camera("x86_64", 37777, Path(name) / "sonia")
            data = program.read_bytes()
            self.assertEqual(data[:4], b"\x7fELF")
            needed, interpreter = image.elf_needs(program)
            self.assertEqual((needed, interpreter), ([], None))
            self.assertLess(len(data), 64 * 1024)

    @unittest.skipUnless(shutil.which("aarch64-linux-gnu-gcc-14")
                         or shutil.which("aarch64-linux-gnu-gcc"), "needs the arm64 compiler")
    def test_it_builds_for_arm64(self):
        with tempfile.TemporaryDirectory() as name:
            program = extra.build_camera("arm64", 37777, Path(name) / "sonia")
            data = program.read_bytes()
            self.assertEqual(int.from_bytes(data[18:20], "little"), 183, "EM_AARCH64")
            self.assertEqual(image.elf_needs(program), ([], None))

    @unittest.skipUnless(os.uname().machine == "x86_64" and netns_works()
                         and any(shutil.which(name) for name in extra.COMPILERS["x86_64"]),
                         "needs an x86-64 host with user and network namespaces")
    def test_it_answers_like_a_camera_that_wants_a_login(self):
        client = r"""
import socket
def talk(port, data):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        if data:
            s.sendall(data)
        s.settimeout(5)
        chunks = []
        try:
            while chunk := s.recv(4096):
                chunks.append(chunk)
        except socket.timeout:
            chunks.append(b"<timeout>")
        return b"".join(chunks)
web = talk(80, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
assert web.startswith(b"HTTP/1.1 200 OK\r\n"), web[:80]
head, body = web.split(b"\r\n\r\n", 1)
length = int([l for l in head.split(b"\r\n") if l.startswith(b"Content-Length:")][0].split()[1])
assert length == len(body) and b"WEB SERVICE" in body and b"password" in body
options = talk(554, b"OPTIONS rtsp://127.0.0.1/ RTSP/1.0\r\nCSeq: 7\r\n\r\n")
assert options.startswith(b"RTSP/1.0 200 OK\r\nCSeq: 7\r\n") and b"DESCRIBE" in options, options
describe = talk(554, b"DESCRIBE rtsp://127.0.0.1/ RTSP/1.0\r\nCSeq: 8\r\n\r\n")
assert describe.startswith(b"RTSP/1.0 401 Unauthorized\r\nCSeq: 8\r\n"), describe
assert b"WWW-Authenticate: Digest" in describe
vendor = talk(37777, b"\xa0\x00\x00\x00")
assert vendor in (b"", b"<timeout>"), vendor
print("CAMERA OK")
"""
        with tempfile.TemporaryDirectory() as name:
            program = extra.build_camera("x86_64", 37777, Path(name) / "sonia")
            result = run_in_netns(program, client)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CAMERA OK", result.stdout)


class OrchestratorTests(unittest.TestCase):
    def test_the_profile_builds_its_own_kernel_with_busyboxs_recipe(self):
        kernel, recipe, options, _ = base.PROFILES["busybox-extra"]
        self.assertEqual((kernel, recipe), ("extra", "build-monitor-image.py"))
        self.assertEqual(options, {"hostname", "name", "device"})
        self.assertIn("busybox-extra", base.ARM64_PROFILES)
        self.assertFalse(base.foreign("busybox-extra", "arm64"), "nothing runs under emulation")

    def test_a_change_to_the_extra_symbols_misses_only_the_extra_kernels_cache(self):
        with patch.object(base, "toolchain", return_value={"cc": "gcc", "ld": "ld"}):
            minimal = base.kernel_identity("minimal")
            extra_kernel = base.kernel_identity("extra", "arm64")
        self.assertNotIn("extra_config_sha256", minimal)
        self.assertEqual(extra_kernel["extra_config_sha256"], base.checksum(base.EXTRA_CONFIG))
        self.assertEqual(extra_kernel["profile"], "extra")

    def test_the_image_recipe_is_told_the_profile_and_the_device(self):
        with tempfile.TemporaryDirectory() as name, \
                patch.object(base, "run") as run:
            work = Path(name)
            base.build_image("busybox-extra", {"device": "dahua-xvr", "hostname": "dvr"}, work,
                             work, work / "out", "0.9.0", None, work / "inputs", "arm64")
        command = [str(word) for word in run.call_args.args]
        self.assertIn("build-monitor-image.py", command[1])
        for pair in (["--profile", "busybox-extra"], ["--device", "dahua-xvr"],
                     ["--hostname", "dvr"], ["--arch", "arm64"]):
            index = command.index(pair[0])
            self.assertEqual(command[index:index + 2], pair)
        with tempfile.TemporaryDirectory() as name, patch.object(base, "run") as run:
            work = Path(name)
            base.build_image("busybox", {}, work, work, work / "out", None, None, None)
        self.assertNotIn("--profile", [str(word) for word in run.call_args.args])

    def test_a_job_with_a_device_is_accepted_only_for_the_camera_base(self):
        with tempfile.TemporaryDirectory() as name:
            job = Path(name) / "job.json"
            job.write_text(json.dumps({"format": 1, "profile": "busybox-extra", "arch": "arm64",
                                       "options": {"device": "dahua-xvr"}}))
            self.assertEqual(base.load_job(job)[0], "busybox-extra")
            job.write_text(json.dumps({"format": 1, "profile": "busybox",
                                       "options": {"device": "dahua-xvr"}}))
            with self.assertRaisesRegex(RuntimeError, "not offered for busybox"):
                base.load_job(job)

    def test_the_kit_and_the_published_recipe_carry_the_camera_files(self):
        kit = (REPO / "src/antinomie/monitor/crates/monitor-core/build.rs").read_text()
        publish = (REPO / "scripts/publish-base-sources.py").read_text()
        for path in ("scripts/busybox_extra.py", "src/antinomie/packaging/kconfig/busybox-extra.cfg",
                     "src/antinomie/packaging/busybox-extra/camera.c"):
            self.assertIn(f'"{path}"', kit)
            self.assertIn(f'"{path}"', publish)
            self.assertTrue((REPO / path).is_file())


if __name__ == "__main__":
    unittest.main()
