#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Packaging checks: 0.9.0 ships the desktop app only.

The command line (antinomie-cli), the Auto daemon, its systemd units, the
service.toml example and the presets are not built, installed or packed in 0.9.0.
0.9.1 reverts the commit that removed them and restores the checks of the units
and examples that this file had (git log -- tests/monitor/test-packaging.py).
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ("scripts/build-monitor-host.sh", "scripts/build-release.sh", "install.sh")


class DesktopOnlyTests(unittest.TestCase):
    def test_scripts_do_not_build_ship_or_install_the_cli(self):
        for name in SCRIPTS:
            self.assertNotIn("antinomie-cli", (ROOT / name).read_text(), name)

    def test_release_archive_has_no_packaging_folder(self):
        self.assertNotIn("packaging", (ROOT / "scripts/build-release.sh").read_text())
        self.assertFalse((ROOT / "packaging").exists())

    def test_release_archive_holds_the_window_and_its_menu_entry(self):
        release = (ROOT / "scripts/build-release.sh").read_text()
        for item in ("antinomie-monitor", "antinomie.desktop", "antinomie.svg", "install.sh"):
            self.assertIn(item, release, item)
        install = (ROOT / "install.sh").read_text()
        for item in ("antinomie-monitor", "antinomie.desktop", "antinomie.svg"):
            self.assertIn(item, install, item)

    def test_release_build_names_only_the_window(self):
        release = (ROOT / "scripts/build-release.sh").read_text()
        self.assertIn("cargo build --release --locked -p antinomie-monitor-ui --bin antinomie-monitor", release)

    def test_nightly_does_not_build_the_cli(self):
        nightly = (ROOT / ".github/workflows/nightly.yml").read_text()
        self.assertNotIn("-p antinomie-cli", nightly)

    def test_ci_still_tests_the_cli_and_service_crates(self):
        # They stay in the workspace; CI builds and tests the whole workspace.
        manifest = (ROOT / "src/antinomie/monitor/Cargo.toml").read_text()
        for crate in ("crates/cli", "crates/service"):
            self.assertIn(crate, manifest, crate)


if __name__ == "__main__":
    unittest.main()
