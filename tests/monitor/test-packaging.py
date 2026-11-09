#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Packaging checks: the systemd units, the examples and the install scripts."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGING = ROOT / "packaging"


def settings(path):
    """Directive -> list of values, from the [Service] section."""
    values = {}
    section = None
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
        elif section == "[Service]" and "=" in line:
            key, value = line.split("=", 1)
            values.setdefault(key, []).append(value)
    return values


class UnitTests(unittest.TestCase):
    units = ("antinomie-auto.service", "antinomie-auto.user.service")

    def test_stop_and_restart_follow_the_design(self):
        for name in self.units:
            s = settings(PACKAGING / name)
            self.assertEqual(s["Type"], ["simple"], name)
            self.assertEqual(s["Restart"], ["on-failure"], name)
            self.assertEqual(s["KillMode"], ["mixed"], name)
            self.assertGreaterEqual(int(s["TimeoutStopSec"][0]), 360, name)

    def test_hardening_is_present(self):
        for name in self.units:
            s = settings(PACKAGING / name)
            self.assertEqual(s["NoNewPrivileges"], ["yes"], name)
            self.assertEqual(s["ProtectSystem"], ["strict"], name)
            self.assertEqual(s["PrivateTmp"], ["yes"], name)
            self.assertIn("AF_UNIX", s["RestrictAddressFamilies"][0], name)
            # bubblewrap makes user namespaces
            self.assertIn("user", s["RestrictNamespaces"][0].split(), name)
            # QEMU and the YARA-X engine generate code at run time
            self.assertNotIn("MemoryDenyWriteExecute", s, name)
            self.assertNotIn("PrivateDevices", s, name)

    def test_system_unit_lets_qemu_open_kvm(self):
        s = settings(PACKAGING / "antinomie-auto.service")
        self.assertIn("/dev/kvm rw", s["DeviceAllow"])
        self.assertEqual(s["DevicePolicy"], ["closed"])
        self.assertIn("kvm", s["SupplementaryGroups"][0].split())
        self.assertEqual(s["StateDirectory"], ["antinomie"])

    def test_units_start_the_daemon_on_a_data_folder_of_its_own(self):
        for name in self.units:
            exec_start = settings(PACKAGING / name)["ExecStart"][0]
            self.assertRegex(exec_start, r"antinomie-cli --data-dir \S+ .*auto daemon$", name)
            self.assertNotRegex(exec_start, r"%h/antinomie\s", name)  # not the window's folder

    def test_default_policy_example_is_what_auto_init_writes(self):
        source = (ROOT / "src/antinomie/monitor/crates/service/src/config/mod.rs").read_text()
        body = re.search(r'DEFAULT_POLICY: &str = r#"(.*?)"#;', source, re.S).group(1)
        example = (PACKAGING / "policies/default.toml.example").read_text()
        self.assertTrue(example.endswith(body))


class ScriptTests(unittest.TestCase):
    def test_scripts_build_ship_and_install_the_cli(self):
        for name in ("scripts/build-monitor-host.sh", "scripts/build-release.sh", "install.sh"):
            self.assertIn("antinomie-cli", (ROOT / name).read_text(), name)
        self.assertIn("packaging", (ROOT / "scripts/build-release.sh").read_text())


if __name__ == "__main__":
    unittest.main()
