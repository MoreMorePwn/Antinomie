#!/usr/bin/env python3
"""Focused image contract and rollback tests; no network or mmdebstrap run required."""
# SPDX-License-Identifier: GPL-3.0-only
import importlib.util
import io
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("debian_image", REPO / "scripts/build-debian-image.py")
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)


class DebianImageTests(unittest.TestCase):
    def test_mmdebstrap_is_authenticated_and_carries_the_answers(self):
        values = image.options({"hostname": "lab", "locale": "de_DE.UTF-8",
                                "keyboard_layout": "de", "keyboard_variant": "nodeadkeys",
                                "timezone": "Europe/Berlin", "standard": True,
                                "mirror": "http://mirror.example/debian/",
                                "proxy": "http://proxy.example:3128"})
        with patch.object(image.os, "geteuid", return_value=1000):
            command = image.mmdebstrap_command(values, Path("/w/rootfs.tar"), Path("/w/c.sh"),
                                               Path("/w/prov"))
        self.assertEqual(command[0], "mmdebstrap")
        self.assertIn("--mode=unshare", command)
        self.assertIn("--variant=standard", command)
        self.assertIn("--format=tar", command)
        self.assertIn('--aptopt=APT::Get::AllowUnauthenticated "false"', command)
        self.assertIn('--aptopt=Acquire::AllowInsecureRepositories "false"', command)
        self.assertIn('--aptopt=APT::Install-Recommends "true"', command)
        self.assertIn('--aptopt=Acquire::http::Proxy "http://proxy.example:3128"', command)
        include = next(arg for arg in command if arg.startswith("--include="))
        self.assertIn("task-xfce-desktop", include)
        self.assertNotIn("openssh-server", include)
        self.assertEqual(command[-5:], ["trixie", "/w/rootfs.tar",
            "deb http://mirror.example/debian trixie main",
            "deb http://mirror.example/debian trixie-updates main",
            "deb http://security.debian.org/debian-security trixie-security main"])
        hooks = [arg for arg in command if arg.startswith("--customize-hook=")]
        self.assertTrue(any("antinomie-customize.sh lab de_DE.UTF-8 de nodeadkeys Europe/Berlin" in h
                            for h in hooks), hooks)
        # Kernel modules are appended to the tarball later, not bootstrapped.
        self.assertFalse(any("modules" in h for h in hooks))
        with patch.object(image.os, "geteuid", return_value=0):
            root = image.mmdebstrap_command(image.options({}), Path("/w/r.tar"), Path("/w/c.sh"),
                                            Path("/w/p"))
        self.assertIn("--mode=root", root)
        self.assertIn("--variant=important", root)
        self.assertFalse(any("Proxy" in arg for arg in root))
        self.assertFalse(any("modules" in arg for arg in root))

    def test_desktops_follow_the_installer_and_set_their_display_manager(self):
        self.assertEqual(set(image.DESKTOPS), {"xfce", "gnome", "gnome-flashback", "kde",
                                               "cinnamon", "mate", "lxde", "lxqt"})
        self.assertEqual(image.options({})["desktop"], "xfce")
        xfce = image.packages("xfce")
        self.assertIn("task-xfce-desktop", xfce)
        self.assertIn("lightdm-gtk-greeter", xfce)
        gnome = image.packages("gnome")
        self.assertIn("task-gnome-desktop", gnome)
        self.assertFalse(any("xfce" in package or "lightdm" in package for package in gnome))
        self.assertEqual(image.profile("kde")["label"], "Debian 13 (KDE Plasma)")
        self.assertEqual(image.profile("kde")["id"], "debian-kde")
        self.assertEqual(image.profile("gnome")["min_ram_mib"], 4096)
        self.assertEqual(image.profile("xfce"), image.PROFILE)
        with patch.object(image.os, "geteuid", return_value=0):
            command = image.mmdebstrap_command(image.options({"desktop": "kde"}),
                                               Path("/w/r.tar"), Path("/w/c.sh"), Path("/w/p"))
        include = next(arg for arg in command if arg.startswith("--include="))
        self.assertIn("task-kde-desktop", include)
        self.assertTrue(any(arg.endswith("Etc/UTC sddm plasma") for arg in command), command)
        with self.assertRaises(RuntimeError):
            image.options({"desktop": "windows"})

    def test_console_base_has_no_desktop_and_keeps_apt_and_the_tools(self):
        values = image.options({"desktop": image.CONSOLE})
        self.assertEqual(image.CONSOLE, "none")
        self.assertEqual(image.profile("none"), {
            "id": "debian-minimal", "label": "Debian 13 (Minimal)", "min_ram_mib": 1024,
            "min_disk_gib": 4, "requires_credentials": True, "graphical": False})
        self.assertNotIn("none", image.DESKTOPS)
        self.assertEqual(image.image_size("none"), 4 << 30)
        self.assertEqual(image.image_size("xfce"), image.IMAGE_SIZE)
        console = image.packages("none")
        self.assertEqual(len(console), len(set(console)))
        for package in ("systemd-sysv", "systemd-resolved", "sudo", "openssh-client", "python3",
                        "curl", "wget", "ca-certificates", "iproute2", "procps", "less",
                        "vim-tiny", "locales", "keyboard-configuration", "tzdata"):
            self.assertIn(package, console)
        for package in console:
            self.assertFalse(package.startswith(("task-", "xserver", "lightdm", "gdm", "sddm",
                                                 "network-manager", "openssh-server",
                                                 "dbus-x11", "fonts-")), package)
        self.assertTrue(all(reason for _, reason in image.CONSOLE_PACKAGES))
        with patch.object(image.os, "geteuid", return_value=1000):
            command = image.mmdebstrap_command(values, Path("/w/r.tar"), Path("/w/c.sh"),
                                               Path("/w/p"))
        self.assertIn('--aptopt=APT::Install-Recommends "false"', command)
        self.assertIn("--variant=important", command)
        for option in image.CONSOLE_DPKG:
            self.assertIn("--dpkgopt=" + option, command)
        self.assertIn("--dpkgopt=path-include=/usr/share/doc/*/copyright", command)
        self.assertTrue(any(arg.endswith("Etc/UTC none none") for arg in command), command)
        # The desktops keep the installer's recommends and their documentation.
        desktop = image.mmdebstrap_command(image.options({}), Path("/w/r.tar"), Path("/w/c.sh"),
                                           Path("/w/p"))
        self.assertFalse(any(arg.startswith("--dpkgopt=") for arg in desktop))
        script = image.customization_script()
        self.assertIn("systemctl set-default multi-user.target", script)
        self.assertIn("80-antinomie-dhcp.network", script)
        self.assertIn("systemctl mask tmp.mount", script)
        self.assertIn("Type=ether", script)
        self.assertIn("rm -f /etc/apt/apt.conf.d/99mmdebstrap /etc/dpkg/dpkg.cfg.d/99mmdebstrap",
                      script)

    def test_console_manifest_lists_the_requested_packages(self):
        manifest = (REPO / "src/antinomie/packaging/debian-minimal-trixie/packages.txt").read_text()
        requested = [line.split()[1] for line in manifest.splitlines()
                     if line.startswith("requested ")]
        self.assertEqual(requested, list(image.packages("none")))
        resolved = [line.split("\t") for line in manifest.splitlines()
                    if line.startswith("installed\t")]
        names = {fields[1].split(":")[0] for fields in resolved}
        self.assertTrue(set(requested) <= names)
        self.assertFalse(names & {"openssh-server", "network-manager", "xserver-xorg-core",
                                  "qemu-guest-agent", "cloud-init"})

    def test_files_cross_the_new_root_as_the_invoking_user(self):
        # In unshare mode a plain hook runs as the namespace's root, which can
        # neither read the staged script nor write the provenance directory.
        with patch.object(image.os, "geteuid", return_value=1000):
            command = image.mmdebstrap_command(image.options({}), Path("/w/r.tar"),
                                               Path("/w/c.sh"), Path("/w/p"))
        hooks = [arg[len("--customize-hook="):] for arg in command
                 if arg.startswith("--customize-hook=")]
        self.assertIn("upload /w/c.sh /tmp/antinomie-customize.sh", hooks)
        self.assertIn("download /etc/os-release /w/p/os-release", hooks)
        self.assertIn("download /tmp/package-docs.tar.gz /w/p/package-docs.tar.gz", hooks)
        for hook in hooks:
            if not hook.startswith(("upload ", "download ")):
                self.assertNotIn("/w/", hook)

    def test_console_base_needs_no_modules_when_the_kernel_builds_them_in(self):
        with tempfile.TemporaryDirectory() as name:
            config = Path(name) / "config"
            config.write_text("".join(f"CONFIG_{symbol}=y\n" for symbol in image.CONSOLE_BUILTIN)
                              + "CONFIG_EFIVAR_FS=m\n")
            self.assertTrue(image.kernel_uses_modules(config))
            self.assertTrue(image.built_in(config, image.CONSOLE_BUILTIN))
            config.write_text("CONFIG_EXT4_FS=y\nCONFIG_VIRTIO_NET=m\n")
            self.assertFalse(image.built_in(config, image.CONSOLE_BUILTIN))
            self.assertFalse(image.built_in(None, image.CONSOLE_BUILTIN))
            kernel = Path(name) / "kernel"
            kernel.write_bytes(b"kernel")
            for desktop in ("xfce", "none"):
                with self.subTest(desktop=desktop), \
                        patch.object(image, "kernel_release", return_value="6.12.94"), \
                        self.assertRaisesRegex(RuntimeError, "--modules"):
                    image.build(kernel, Path(name) / "out", config, values={"desktop": desktop})

    def test_options_are_validated(self):
        self.assertEqual(image.options({})["hostname"], "debian")
        self.assertEqual(image.options({"name": "  Lab desktop  "})["name"], "Lab desktop")
        for bad in ({"hostname": "Bad_Name"}, {"locale": "en_US.ISO-8859-1"},
                    {"keyboard_layout": "US"}, {"keyboard_variant": "a b"},
                    {"timezone": "../etc/passwd"}, {"timezone": "Europe/../../x"},
                    {"mirror": "ftp://x"}, {"proxy": "http://a b"}, {"standard": "yes"},
                    {"name": "x" * 65}, {"name": "bad\nname"}, {"name": 3},
                    {"unknown": 1}):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                image.options(bad)

    def test_tarball_extended_attributes_survive_into_ext4(self):
        if image.e2fsprogs_version() < image.MIN_E2FSPROGS or not shutil.which("debugfs"):
            self.skipTest("needs mkfs.ext4 1.47.1 with tarball input and debugfs")
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            capability = bytes([1, 0, 0, 2, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            tarball = root / "rootfs.tar"
            with tarfile.open(tarball, "w", format=tarfile.PAX_FORMAT) as archive:
                for path in ("./usr", "./usr/bin"):
                    directory = tarfile.TarInfo(path)
                    directory.type = tarfile.DIRTYPE
                    directory.mode = 0o755
                    archive.addfile(directory)
                entry = tarfile.TarInfo("./usr/bin/ping")
                entry.size = 2
                entry.mode = 0o755
                entry.pax_headers = {"SCHILY.xattr.security.capability":
                                     capability.decode("utf-8", "surrogateescape")}
                archive.addfile(entry, io.BytesIO(b"hi"))
            raw = root / "root.raw"
            with raw.open("wb") as target:
                target.truncate(64 << 20)
            subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(tarball), str(raw)], check=True)
            with (root / "log").open("w") as log:
                self.assertEqual(image.apply_xattrs(tarball, raw, root, log), 1)
            listing = subprocess.run(["debugfs", "-R", "ea_list /usr/bin/ping", str(raw)],
                                     capture_output=True, text=True, check=True).stdout
            self.assertIn("security.capability", listing)

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "existing"
            output.mkdir()
            marker = output / "user-data"
            marker.write_text("unchanged")
            with self.assertRaises(RuntimeError):
                image.build(Path("kernel"), output)
            self.assertEqual(marker.read_text(), "unchanged")

    def test_root_filesystem_cache_is_reused_only_for_the_same_recipe_and_answers(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            staging, provenance = root / "staging", root / "provenance"
            staging.mkdir()
            provenance.mkdir()
            rootfs = staging / "rootfs.tar"
            with tarfile.open(rootfs, "w", format=tarfile.PAX_FORMAT) as archive:
                for directory in ("./", "./etc", "./usr", "./usr/lib"):
                    entry = tarfile.TarInfo(directory)
                    entry.type = tarfile.DIRTYPE
                    archive.addfile(entry)
                data = b"debian\n"
                entry = tarfile.TarInfo("./etc/hostname")
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
            for file in image.ROOTFS_PROVENANCE:
                (provenance / file).write_text(file)
            values = image.options({"desktop": "gnome"})
            record = {"bootstrap": "mmdebstrap", "root_built_at": "2026-10-09T00:00:00+00:00",
                      "reused_from_cache": False}
            cache = root / "cache/rootfs.tar"
            now = image.datetime(2026, 10, 10, tzinfo=image.timezone.utc)
            image.save_rootfs_cache(cache, rootfs, provenance, record, values)
            rootfs.unlink()
            shutil.rmtree(provenance)
            provenance.mkdir()
            log = io.StringIO()
            with patch.object(image, "datetime", wraps=image.datetime) as clock:
                clock.now.return_value = now
                clock.fromisoformat = image.datetime.fromisoformat
                reused = image.load_rootfs_cache(cache, values, staging, provenance, log)
                self.assertTrue(reused["reused_from_cache"])
                self.assertEqual((provenance / "packages.tsv").read_text(), "packages.tsv")
                with tarfile.open(rootfs) as archive:
                    self.assertIn("./etc/hostname", archive.getnames())
                other = image.options({"desktop": "xfce"})
                self.assertIsNone(image.load_rootfs_cache(cache, other, staging, provenance, log))
                clock.now.return_value = now + image.timedelta(days=image.ROOTFS_CACHE_DAYS)
                self.assertIsNone(image.load_rootfs_cache(cache, values, staging, provenance, log))
            # Modules are appended, owned by root, under /usr/lib/modules.
            modules = root / "lib/modules/6.12.94"
            (modules / "kernel").mkdir(parents=True)
            (modules / "modules.dep").write_text("")
            image.add_modules(rootfs, modules)
            with tarfile.open(rootfs) as archive:
                names = archive.getnames()
                self.assertIn("./usr/lib/modules", names)
                dep = archive.getmember("./usr/lib/modules/6.12.94/modules.dep")
                self.assertEqual((dep.uid, dep.gid, dep.uname), (0, 0, "root"))

    def test_bootstrap_failure_cleans_unpublished_state(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "new"
            kernel = Path(name) / "kernel"
            kernel.write_bytes(b"kernel")
            helpers = image.monitor_helpers()
            with patch.object(image, "kernel_release", return_value="6.12.94"), \
                    patch.object(helpers, "stamp_revision"), \
                    patch.object(image, "monitor_helpers", return_value=helpers), \
                    patch.object(image, "e2fsprogs_version", return_value=(1, 47, 2)), \
                    patch.object(image.subprocess, "run", side_effect=RuntimeError("mirror down")):
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

    def test_customization_has_valid_shell_and_installer_answers(self):
        script = image.customization_script()
        subprocess.run(["sh", "-n"], input=script, text=True, check=True)
        self.assertIn("Acquire::AllowInsecureRepositories=false", script)
        self.assertIn("dpkg --audit", script)
        self.assertIn("passwd -l root", script)
        self.assertIn("auto lo", script)
        self.assertIn("spice-vdagent", script)
        self.assertIn("/usr/share/i18n/SUPPORTED", script)
        self.assertIn("/etc/default/keyboard", script)
        self.assertIn("/etc/localtime", script)
        self.assertIn("/etc/hostname", script)
        self.assertIn("rm -f /etc/apt/apt.conf.d/99mmdebstrap", script)
        self.assertIn("/etc/X11/default-display-manager", script)
        self.assertIn("allow-guest=false", script)
        self.assertIn("AutomaticLoginEnable = false", script)


if __name__ == "__main__":
    unittest.main()
