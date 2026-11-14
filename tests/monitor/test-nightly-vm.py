#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""tests/ci/nightly-vm.py: which BusyBox base the nightly runs, from fixture catalogs (no network)."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "tests/ci/nightly-vm.py"
spec = importlib.util.spec_from_file_location("nightly_vm", SCRIPT)
nightly = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nightly)


def entry(identity, created, arch=None, kind="busybox", min_app="0.9.0"):
    base = {"identity": identity, "label": identity, "kind": kind, "created": created,
            "min_app_version": min_app, "files": []}
    if arch:
        base["arch"] = arch
    return base


# The r22 catalog: the arm64 BusyBox is the newest by version and creation time.
CATALOG = {"bases": [
    entry("old", "2026-11-05T10:00:00Z", min_app="0.8.0"),
    entry("x86", "2026-11-11T21:29:00Z"),
    entry("arm", "2026-11-11T22:08:00Z", arch="arm64"),
    entry("debian", "2026-11-11T23:00:00Z", kind="debian"),
]}


class PickBase(unittest.TestCase):
    def test_default_is_x86_64_even_when_arm64_is_newer(self):
        self.assertEqual(nightly.pick_base(CATALOG, "0.9.0")["identity"], "x86")
        self.assertEqual(nightly.pick_base(CATALOG, "0.9.0", "x86-64")["identity"], "x86")

    def test_order_in_the_catalog_does_not_matter(self):
        flipped = {"bases": list(reversed(CATALOG["bases"]))}
        self.assertEqual(nightly.pick_base(flipped, "0.9.0")["identity"], "x86")

    def test_arm64_can_be_chosen(self):
        self.assertEqual(nightly.pick_base(CATALOG, "0.9.0", "arm64")["identity"], "arm")
        self.assertEqual(nightly.pick_base(CATALOG, "0.9.0", "aarch64")["identity"], "arm")

    def test_an_older_app_keeps_to_bases_it_runs(self):
        self.assertEqual(nightly.pick_base(CATALOG, "0.8.3")["identity"], "old")
        with self.assertRaises(SystemExit):
            nightly.pick_base(CATALOG, "0.8.3", "arm64")

    def test_unknown_architecture_is_refused(self):
        with self.assertRaises(SystemExit):
            nightly.pick_base(CATALOG, "0.9.0", "riscv")


if __name__ == "__main__":
    unittest.main()
