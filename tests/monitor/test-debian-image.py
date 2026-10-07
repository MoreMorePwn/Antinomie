#!/usr/bin/env python3
"""Focused image contract and rollback tests; no network or appliance required."""
# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import tempfile
import struct
import subprocess
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("debian_image", REPO / "scripts/build-debian-image.py")
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)


class FakeGuest:
    def __init__(self, distro="debian", version="13", arch="x86_64", filesystem="ext4"):
        self.values = {"inspect-get-distro": distro, "inspect-get-major-version": version,
                       "inspect-get-arch": arch, "vfs-type": filesystem}

    def command(self, command, root):
        return self.values[command]


class DebianImageTests(unittest.TestCase):
    def test_authenticated_locked_builder(self):
        command = image.builder_command(Path("/tmp/source"), Path("/tmp/script"), Path("/tmp/cache"))
        self.assertIn("--check-signature", command)
        self.assertNotIn("--no-check-signature", command)
        self.assertEqual(command[command.index("--root-password") + 1], "disabled")
        self.assertNotIn("--firstboot", command)
        self.assertEqual(command[command.index("--size") + 1], "16G")

    def test_foreign_or_non_ext4_template_rejected(self):
        image.validate_root(FakeGuest(), "/dev/sda1")
        for values in ({"distro": "ubuntu"}, {"version": "12"},
                       {"arch": "aarch64"}, {"filesystem": "xfs"}):
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                image.validate_root(FakeGuest(**values), "/dev/sda1")

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "existing"
            output.mkdir()
            marker = output / "user-data"
            marker.write_text("unchanged")
            with self.assertRaises(RuntimeError):
                image.build(Path("kernel"), output)
            self.assertEqual(marker.read_text(), "unchanged")

    def test_catalog_failure_cleans_unpublished_state(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "new"
            kernel = Path(name) / "kernel"
            kernel.write_bytes(b"kernel")
            with patch.object(image, "kernel_release", return_value="6.12.94"), \
                    patch.object(image.subprocess, "run", side_effect=RuntimeError("catalog failed")):
                with self.assertRaises(RuntimeError):
                    image.build(kernel, output)
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(name).iterdir()), [kernel])

    def test_kernel_version_checked_from_bzimage_header(self):
        with tempfile.TemporaryDirectory() as name:
            kernel = Path(name) / "kernel"
            data = bytearray(0x300)
            data[0x202:0x206] = b"HdrS"
            struct.pack_into("<H", data, 0x20e, 0x40)
            for version in (b"6.12.94-custom", b"6.13.0", b"6.12.940"):
                data[0x240:0x280] = version + b"\0" * (64 - len(version))
                kernel.write_bytes(data)
                if version == b"6.12.94-custom":
                    self.assertEqual(image.kernel_release(kernel), version.decode())
                else:
                    with self.assertRaises(RuntimeError):
                        image.kernel_release(kernel)

    def test_modular_kernel_requires_matching_installed_modules(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = root / "config"
            config.write_text("CONFIG_EXT4_FS=y\nCONFIG_SND=m\n")
            self.assertTrue(image.kernel_uses_modules(config))
            config.write_text("CONFIG_EXT4_FS=y\n# CONFIG_SND is not set\n")
            self.assertFalse(image.kernel_uses_modules(config))
            self.assertIsNone(image.module_tree(None, "6.12.94 (builder) #1"))
            with self.assertRaises(RuntimeError):
                image.module_tree(root, "6.12.94 (builder) #1")
            tree = root / "lib/modules/6.12.94"
            tree.mkdir(parents=True)
            (tree / "modules.dep").write_text("")
            self.assertEqual(image.module_tree(root, "6.12.94 (builder) #1"), tree)
            with self.assertRaises(RuntimeError):
                image.module_tree(root, "6.12.95 (builder) #1")

    def test_profile_contract(self):
        self.assertEqual(image.PROFILE, {"id": "debian-xfce", "label": "Debian 13 (Xfce)",
            "min_ram_mib": 2048, "min_disk_gib": 16, "requires_credentials": True, "graphical": True})
        self.assertEqual(image.APPEND, "root=/dev/vda rw rootwait console=tty0 console=ttyS0 panic=-1")

    def test_customization_has_valid_shell_and_authenticated_full_desktop_apt(self):
        script = image.customization_script()
        subprocess.run(["sh", "-n"], input=script, text=True, check=True)
        self.assertNotIn("--no-install-recommends install", script)
        self.assertIn(" -y install ", script)
        self.assertIn("APT::Update::Error-Mode=any", script)
        self.assertIn("Acquire::AllowInsecureRepositories=false", script)
        self.assertIn("APT::Get::AllowUnauthenticated=false", script)
        self.assertIn("dpkg --audit", script)
        self.assertIn("passwd -l root", script)
        self.assertIn("auto lo", script)
        self.assertIn("task-xfce-desktop", script)
        self.assertIn("spice-vdagent", script)


if __name__ == "__main__":
    unittest.main()
