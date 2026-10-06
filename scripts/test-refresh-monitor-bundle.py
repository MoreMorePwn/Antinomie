#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Focused immutable refresh and configuration capability regressions."""
import importlib.util
import gzip
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "refresh_bundle", Path(__file__).with_name("refresh-monitor-bundle.py"))
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.kernel = self.root / "bzImage"
        self.config = self.root / "config"
        self.config.write_text("\n".join("CONFIG_" + name + "=y" for name in
            ("DRM", "DRM_BOCHS", "DRM_FBDEV_EMULATION", "FRAMEBUFFER_CONSOLE")))
        self.write_kernel()
        for name in ("kernel", "disk", "initrd"):
            (self.source / name).write_bytes(name.encode())
        self.manifest = {"kernel": "kernel", "base_disk": "disk", "initrd": "initrd",
                         "kernel_version": "6.12.94", "schema_id": 1,
                         "kernel_append": "console=tty0"}
        self.save_manifest()
        self.output = self.root / "new"

    def save_manifest(self):
        (self.source / "bundle.json").write_text(json.dumps(self.manifest))

    def write_kernel(self):
        data = bytearray(0x400)
        data[0x202:0x206] = b"HdrS"
        data[0x1f1] = 1
        struct.pack_into("<H", data, 0x20e, 0x100)
        data[0x300:0x30a] = b"6.12.94\0\0\0"
        compressed = gzip.compress(b"IKCFG_ST" + gzip.compress(self.config.read_bytes()) + b"IKCFG_ED")
        struct.pack_into("<II", data, 0x248, 0, len(compressed))
        self.kernel.write_bytes(data + compressed)

    def run_refresh(self):
        with patch.object(refresh.subprocess, "check_output", return_value='{"format":"qcow2"}'):
            return refresh.refresh(self.source, self.kernel, self.config, self.output)

    def test_preserves_disk_initrd_and_source(self):
        self.run_refresh()
        manifest = json.loads((self.output / "bundle.json").read_text())
        self.assertTrue(manifest["fixed_display"])
        self.assertNotIn("base_identity", manifest)
        self.assertEqual((self.output / "base.qcow2").read_bytes(), b"disk")
        self.assertEqual((self.output / "initrd").read_bytes(), b"initrd")
        self.assertEqual((self.output / "kernel").read_bytes(), self.kernel.read_bytes())
        self.assertEqual(json.loads((self.source / "bundle.json").read_text()), self.manifest)
        record = json.loads((self.output / "provenance/refresh.json").read_text())
        self.assertEqual(record["source_base_identity"], manifest["build_provenance"]["parent_identity"])
        self.assertEqual(len(record["source_base_identity"]), 64)
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.run_refresh()

    def test_rejects_unsupported_config(self):
        self.config.write_text("CONFIG_DRM_BOCHS=m\n")
        self.write_kernel()
        with self.assertRaisesRegex(RuntimeError, "CONFIG_DRM"):
            self.run_refresh()
        self.assertFalse(self.output.exists())

    def test_rejects_artifact_escape(self):
        self.manifest["base_disk"] = "../bzImage"
        self.save_manifest()
        with self.assertRaisesRegex(RuntimeError, "inside its directory"):
            self.run_refresh()

    def test_rejects_checksum_mismatch(self):
        self.manifest["sha256"] = {"disk": "wrong"}
        self.save_manifest()
        with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
            self.run_refresh()
        self.assertFalse(self.output.exists())

    def test_legacy_config_unknown_and_optional_initrd(self):
        self.assertFalse(refresh.helpers().monitor_helpers().fixed_display_config(None))
        del self.manifest["initrd"]
        self.save_manifest()
        self.run_refresh()
        self.assertIsNone(json.loads((self.output / "bundle.json").read_text())["initrd"])

    def test_rejects_overlay_source(self):
        with patch.object(refresh.subprocess, "check_output",
                          return_value='{"format":"qcow2","backing-filename":"old"}'):
            with self.assertRaisesRegex(RuntimeError, "standalone qcow2"):
                refresh.refresh(self.source, self.kernel, self.config, self.output)

    def test_atomic_publish_does_not_replace_empty_directory(self):
        unpublished = self.root / "unpublished"
        unpublished.mkdir()
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            refresh.publish_new(unpublished, self.output)
        self.assertTrue(unpublished.is_dir())

    def test_rejects_kernel_config_mismatch(self):
        self.config.write_text(self.config.read_text() + "\nCONFIG_IKCONFIG=y\n")
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            self.run_refresh()

    def test_rejects_corrupt_installed_parent(self):
        self.manifest["base_identity"] = "a" * 64
        self.save_manifest()
        with self.assertRaisesRegex(RuntimeError, "source base identity mismatch"):
            self.run_refresh()

    def test_rejects_malformed_payload_extent(self):
        data = bytearray(self.kernel.read_bytes())
        struct.pack_into("<II", data, 0x248, 0xfffffff0, 1024)
        self.kernel.write_bytes(data)
        with self.assertRaisesRegex(RuntimeError, "payload extent"):
            self.run_refresh()

    def test_copy_time_config_mismatch_does_not_publish(self):
        copy = refresh.shutil.copy2
        def swapped(source, destination):
            result = copy(source, destination)
            if Path(destination).name == "kernel.config":
                Path(destination).write_text("CONFIG_DRM_BOCHS=y\n")
            return result
        with patch.object(refresh.shutil, "copy2", side_effect=swapped):
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                self.run_refresh()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
