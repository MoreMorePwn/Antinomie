#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""ant-sample-evasive: both paths of the gate, with fixture directories instead of a real guest.

--test-root DIR makes the checks read their /sys and /proc files below DIR, and DIR/overrides
fakes the ones that are not files (CPU count, RAM, ...). Run from the repository root:
python3 tests/monitor/test-evasive-sample.py
"""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCES = sorted((HERE / "behavior-samples").glob("*.c"))
spec = importlib.util.spec_from_file_location("sinkhole", HERE / "sinkhole.py")
sink_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sink_module)

CLEAN_CPUINFO = (
    "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz\n"
    "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep vmx\n\n"
)
VM_CPUINFO = (
    "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: QEMU Virtual CPU version 2.5+\n"
    "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep hypervisor\n\n"
)


def fixture(root, *, dmi, cpuinfo, mac, vendor, disk, clocksource, uptime, overrides, extra=()):
    files = {
        "sys/class/net/eth0/address": mac,
        "sys/class/net/eth0/device/vendor": vendor,
        f"sys/block/{disk[0]}/device/model": disk[1] if disk[1] else None,
        "sys/devices/system/clocksource/clocksource0/current_clocksource": clocksource,
        "proc/cpuinfo": cpuinfo,
        "proc/uptime": f"{uptime} 100.00",
        "proc/1/cgroup": "0::/init.scope",
        "proc/self/cgroup": "0::/",
        "proc/self/status": "Name:\tx\nTracerPid:\t0\n",
        "proc/self/maps": "00400000-00401000 r-xp 00000000 08:01 1 /bin/x\n",
        "overrides": overrides,
    }
    for name, value in dmi.items():
        files[f"sys/class/dmi/id/{name}"] = value
    for name, value in extra:
        files[name] = value
    for name, value in files.items():
        path = Path(root) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if value is None:
            continue
        path.write_text(value + "\n" if name != "overrides" else value)
    if disk[1] is None:
        (Path(root) / "sys/block" / disk[0]).mkdir(parents=True, exist_ok=True)


def clean(root):
    fixture(root, dmi={"sys_vendor": "LENOVO", "product_name": "11JN0047US", "board_vendor": "LENOVO",
                       "bios_vendor": "LENOVO", "chassis_type": "35"},
            cpuinfo=CLEAN_CPUINFO, mac="3c:fd:fe:01:02:03", vendor="0x8086", disk=("sda", "Samsung SSD 860"),
            clocksource="tsc", uptime="90000.12",
            overrides="cpus=8\nram=17179869184\ndisk=500000000000\nprocs=120\ntraceme=ok\n")


def qemu(root):
    fixture(root, dmi={"sys_vendor": "QEMU", "product_name": "Standard PC (Q35 + ICH9, 2009)",
                       "board_vendor": "QEMU", "bios_vendor": "SeaBIOS", "chassis_type": "1"},
            cpuinfo=VM_CPUINFO, mac="52:54:00:12:34:56", vendor="0x1af4", disk=("vda", None),
            clocksource="kvm-clock", uptime="42.00",
            overrides="cpus=2\nram=2147483648\ndisk=8589934592\nprocs=60\ntraceme=ok\n")


@unittest.skipUnless(shutil.which("gcc"), "needs gcc")
class Evasive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        cls.evasive = Path(cls.build.name) / "ant-sample-evasive"
        cls.suite = Path(cls.build.name) / "ant-sample-all"
        common = ["gcc", "-O1", "-D_GNU_SOURCE", f"-I{HERE / 'behavior-samples'}"]
        subprocess.run(common + ['-DSINGLE_SCENARIO="evasive"'] + [str(s) for s in SOURCES]
                       + ["-o", str(cls.evasive), "-lm"], check=True, capture_output=True)
        subprocess.run(common + [str(s) for s in SOURCES] + ["-o", str(cls.suite), "-lm"],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.root = Path(self.work.name) / "fixture"
        self.workdir = Path(self.work.name) / "run"

    def tearDown(self):
        self.work.cleanup()

    def run_binary(self, binary, *args, timeout=60):
        return subprocess.run([str(binary), "--test-root", str(self.root), "--workdir", str(self.workdir),
                               "--evade-sleep", "0", *args],
                              capture_output=True, text=True, timeout=timeout)

    def test_a_vm_evades_and_names_the_checks(self):
        qemu(self.root)
        done = self.run_binary(self.evasive, "--host", "127.0.0.1", "--port", "9")
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertIn("verdict=evade", done.stdout)
        for text in ("dmi sys_vendor=QEMU", "mac VM prefix (52:54:00:12:34:56)", "cpuinfo hypervisor flag set",
                     "block device vda is virtio", "clocksource kvm-clock"):
            self.assertIn(text, done.stdout)
        # the sandbox hints: 2 CPUs and 2 GiB are fine, a fresh boot and few processes are not enough
        self.assertIn("sandbox_hints=1/3", done.stdout)
        line = next(row for row in done.stderr.splitlines() if row.startswith("EVADE vm:"))
        self.assertIn("dmi sys_vendor=QEMU", line)
        self.assertEqual(done.stdout.count("EVADE vm:"), 1)
        # nothing of the chain
        for text in ("download", "GET http", "persistence", "beacon"):
            self.assertNotIn(f"PASS        {text}", done.stdout)
        self.assertIn("hello", done.stdout)

    def test_a_clean_machine_proceeds_through_the_whole_chain(self):
        clean(self.root)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        options = sink_module.parse_args(
            ["--http-port", "0", "--alt-http-port", "0", "--tls-port", "0", "--alt-tls-port", "0",
             "--udp-port", "0", "--dns-port", "0", "--ssh-port", "0", "--irc-port", "0",
             "--shell-port", "0", "--log", str(Path(directory.name) / "sink.log")])
        import io
        sink = sink_module.Sink(options, out=io.StringIO())
        sink.start()
        try:
            done = self.run_binary(self.evasive, "--host", "127.0.0.1", "--port", str(sink.bound["http"]),
                                   "--delay", "0", "--why")
            stats = sink.stats.snapshot()
        finally:
            sink.shutdown()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("verdict=proceed", done.stdout)
        self.assertNotIn("EVADE", done.stderr)
        self.assertIn("sha256", done.stdout)
        self.assertIn("marker file written", done.stdout)
        for scenario in ("recon", "download", "beacon-loop", "evasive"):
            self.assertIn(scenario, stats, stats)
        self.assertEqual(stats["beacon-loop"]["events"], 10)
        self.assertIn("persistence", done.stdout)
        self.assertIn("every check clean", done.stdout)

    def test_ignore_skips_a_category(self):
        qemu(self.root)
        done = self.run_binary(self.evasive, "--host", "127.0.0.1", "--port", "9", "--ignore", "vm,sandbox,debugger")
        self.assertIn("verdict=proceed", done.stdout)
        self.assertNotIn("dmi sys_vendor", done.stdout)

    def test_why_prints_the_stealth_entry_of_each_check(self):
        clean(self.root)
        done = self.run_binary(self.evasive, "--host", "127.0.0.1", "--port", "9", "--why", "--ignore", "debugger")
        self.assertIn("[Stealth: CPU > Hide the hypervisor CPU flag]", done.stdout)
        self.assertIn("[Stealth: Network > MAC address]", done.stdout)
        self.assertIn("[Stealth: Hardware identity > System maker]", done.stdout)
        self.assertIn("skipped (--ignore)", done.stdout)

    def test_a_debugger_or_container_evades_on_its_own(self):
        clean(self.root)
        (self.root / "proc/self/status").write_text("TracerPid:\t4242\n")
        (self.root / ".dockerenv").write_text("")
        done = self.run_binary(self.evasive, "--host", "127.0.0.1", "--port", "9")
        self.assertIn("EVADE debugger: TracerPid=4242", done.stdout)
        self.assertIn("EVADE container: /.dockerenv present", done.stdout)

    def test_many_sandbox_hints_evade(self):
        clean(self.root)
        (self.root / "overrides").write_text("cpus=1\nram=536870912\ndisk=2147483648\nprocs=5\ntraceme=ok\n")
        done = self.run_binary(self.evasive, "--host", "127.0.0.1", "--port", "9")
        self.assertIn("EVADE sandbox: 1 CPU; 512 MiB of RAM", done.stdout)

    def test_the_main_binary_gates_only_with_the_flag(self):
        qemu(self.root)
        with_flag = self.run_binary(self.suite, "--evade", "--host", "127.0.0.1", "--port", "9")
        self.assertIn("verdict=evade", with_flag.stdout)
        self.assertIn("SUMMARY     scenarios=0", with_flag.stdout)
        without = subprocess.run([str(self.suite), "--list"], capture_output=True, text=True)
        self.assertIn("evasive\t", without.stdout)
        # a bare run leaves the evasive scenario out: the suite is unchanged
        names = [row.split("\t")[0] for row in without.stdout.splitlines()[1:]]
        self.assertIn("evasive", names)

    def test_bad_ignore_is_refused(self):
        done = subprocess.run([str(self.evasive), "--ignore", "nonsense"], capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)


if __name__ == "__main__":
    unittest.main()
