#!/usr/bin/env python3
"""Focused image contract and rollback tests; no network or mmdebstrap run required."""
# SPDX-License-Identifier: GPL-3.0-only
import hashlib
import importlib.util
import os
import io
import json
from pathlib import Path
import re
import shutil
import struct
import sys
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("debian_image", REPO / "scripts/build-debian-image.py")
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)


helper_spec = importlib.util.spec_from_file_location(
    "initrd_resume",
    REPO / "src/antinomie/monitor/crates/monitor-core/src/guest_account/initrd_resume.py")
initrd_resume = importlib.util.module_from_spec(helper_spec)
helper_spec.loader.exec_module(initrd_resume)


def newc(members):
    """A newc archive of (name, mode, ino, nlink, mtime, body) members."""
    entries = [[[ino, mode, 0, 0, nlink, mtime, 0, 8, 48, 0, 0, 0, 0], name, body]
               for name, mode, ino, nlink, mtime, body in members]
    entries.append([[0] * 5 + [0, 0, 0, 0, 0, 0, 0, 0], b"TRAILER!!!", b""])
    return initrd_resume.write_archive(entries)


class InitrdResumeTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("zstd"), "zstd is required")
    def test_resume_goes_into_the_initramfs_as_update_initramfs_copies_it(self):
        early = newc([(b"kernel", 0o40755, 7, 2, 100, b""),
                      (b"kernel/x86/microcode.bin", 0o100644, 8, 1, 100, b"ucode")])
        main = newc([(b".", 0o40755, 500, 4, 200, b""),
                     (b"conf", 0o40755, 501, 3, 200, b""),
                     (b"conf/arch.conf", 0o100644, 520, 1, 200, b"DPKG_ARCH=amd64\n"),
                     (b"conf/conf.d", 0o40755, 502, 2, 200, b""),
                     (b"conf/conf.d/zz-resume-auto", 0o100644, 522, 1, 200, b"RESUME=/dev/sdb2\n"),
                     (b"conf/initramfs.conf", 0o100644, 521, 1, 150, b"MODULES=most\n"),
                     (b"init", 0o100755, 510, 1, 150, b"#!/bin/sh\n"),
                     (b"usr/bin/sh", 0o100755, 530, 2, 150, b""),
                     (b"usr/bin/busybox", 0o100755, 530, 2, 150, b"\x7fELF")])
        packed = subprocess.run(["zstd", "-q", "-9", "-c"], input=main, check=True,
                                capture_output=True).stdout
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "initrd.img-6.12.94+deb13-amd64"
            path.write_bytes(early + packed)
            os.utime(path, (1000, 2000))
            rng = __import__("random").Random(7)
            initrd_resume.patch_image(str(path), "RESUME=UUID=abc", 1900, (8, 1), rng)
            data = path.read_bytes()
            # The uncompressed archives before the main one stay as they were.
            self.assertTrue(data.startswith(early))
            self.assertEqual(os.stat(path).st_mtime, 2000)
            head, rest = initrd_resume.split_image(data)
            self.assertEqual(head, early)
            unpacked = subprocess.run(["zstd", "-q", "-d", "-c"], input=rest, check=True,
                                      capture_output=True).stdout
            self.assertEqual(len(unpacked) % 512, 0)
            members, _ = initrd_resume.read_archive(unpacked, 0)
            names = [name for _, name, _ in members]
            # Sorted in among the rest, the automatic choice gone, links kept.
            self.assertEqual(names, [b".", b"conf", b"conf/arch.conf", b"conf/conf.d",
                                     b"conf/conf.d/resume", b"conf/initramfs.conf", b"init",
                                     b"usr/bin/sh", b"usr/bin/busybox", b"TRAILER!!!"])
            by_name = {name: (fields, body) for fields, name, body in members}
            fields, body = by_name[b"conf/conf.d/resume"]
            self.assertEqual(body, b"RESUME=UUID=abc\n")
            self.assertEqual(fields[initrd_resume.MODE], 0o100644)
            self.assertEqual(fields[initrd_resume.MTIME], 1900)
            self.assertEqual(fields[initrd_resume.NLINK], 1)
            inos = [f[initrd_resume.INO] for f, name, _ in members if name != b"TRAILER!!!"]
            self.assertEqual(len(set(inos)), len(inos) - 1)
            self.assertEqual(by_name[b"usr/bin/sh"][0][0], by_name[b"usr/bin/busybox"][0][0])
            # The build machine's device and inode numbers become this disk's.
            for f, name, _ in members[:-1]:
                self.assertEqual((f[initrd_resume.DEVMAJOR], f[initrd_resume.DEVMINOR]), (8, 1))
            self.assertEqual(by_name[b"conf/initramfs.conf"][0][0] - by_name[b"."][0][0], 21)
            self.assertLess(max(inos), os.statvfs("/").f_files)
            # Provisioning again replaces the answer rather than adding one.
            initrd_resume.patch_image(str(path), "RESUME=none", 1950, (8, 1), rng)
            _, rest = initrd_resume.split_image(path.read_bytes())
            members, _ = initrd_resume.read_archive(
                subprocess.run(["zstd", "-q", "-d", "-c"], input=rest, check=True,
                               capture_output=True).stdout, 0)
            resumes = [body for _, name, body in members if name == b"conf/conf.d/resume"]
            self.assertEqual(resumes, [b"RESUME=none\n"])
            # Anything but a zstd main archive is refused, the file untouched.
            path.write_bytes(early + b"\x1f\x8b" + packed)
            with self.assertRaises(ValueError):
                initrd_resume.patch_image(str(path), "RESUME=none", 1950, (8, 1), rng)
            self.assertEqual(path.read_bytes(), early + b"\x1f\x8b" + packed)


def gpt_disk(path, first=2048, last=1331199, unique=bytes(range(16))):
    """A disk image whose GPT names an EFI system partition first."""
    header = bytearray(512)
    header[0:8] = b"EFI PART"
    struct.pack_into("<Q", header, 72, 2)
    entry = bytearray(512)
    entry[0:16] = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
    entry[16:32] = unique
    struct.pack_into("<QQ", entry, 32, first, last)
    path.write_bytes(bytes(512) + header + entry)


class BootEntryTests(unittest.TestCase):
    """The bootstrap initrd's "debian" UEFI boot entry, run with BusyBox
    against a variable directory standing in for efivarfs."""

    def run_entry(self, disk, variables):
        with tempfile.TemporaryDirectory() as tree:
            image.monitor_helpers().initrd_tree(Path(tree))
            init = (Path(tree) / "init").read_text()
        start = init.index("efi_hex() {")
        functions = init[start:init.index("\npart=${root#/dev/}", start)]
        functions = (functions.replace("vars=/sys/firmware/efi/efivars", f"vars={variables}")
                     .replace("/efivar", f"{variables}/.staged"))
        script = "chattr() { :; }\nmount() { return 1; }\n" + functions + f"\nefi_entry {disk}\n"
        subprocess.run(["busybox", "sh", "-c", script], check=True)

    @unittest.skipUnless(shutil.which("busybox") and shutil.which("chattr")
                         and shutil.which("resize2fs"), "busybox, chattr and resize2fs are required")
    def test_debian_entry_goes_first_and_points_at_the_esp(self):
        guid = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            disk, variables = root / "disk", root / "vars"
            variables.mkdir()
            gpt_disk(disk)
            # The firmware's own entries and order.
            (variables / f"Boot0000-{guid}").write_bytes(b"\x07\0\0\0firmware")
            (variables / f"Boot0001-{guid}").write_bytes(b"\x07\0\0\0disk")
            (variables / f"BootOrder-{guid}").write_bytes(b"\x07\0\0\0\x01\0\x00\0")
            self.run_entry(disk, variables)
            entry = (variables / f"Boot0002-{guid}").read_bytes()
            option = entry[4:]
            self.assertEqual(entry[:4], b"\x07\0\0\0")
            self.assertEqual(struct.unpack_from("<IH", option), (1, 98))
            self.assertEqual(option[6:20], "debian\0".encode("utf-16-le"))
            path = option[20:]
            self.assertEqual(len(path), 98)
            self.assertEqual(path[:4], b"\x04\x01\x2a\x00")
            self.assertEqual(struct.unpack_from("<IQQ", path, 4), (1, 2048, 1331200 - 2048))
            self.assertEqual(path[24:40], bytes(range(16)))
            self.assertEqual(path[40:42], b"\x02\x02")
            self.assertEqual(path[42:46], b"\x04\x04\x34\x00")
            self.assertEqual(path[46:94].decode("utf-16-le"), "\\EFI\\debian\\shimx64.efi\0")
            self.assertEqual(path[94:], b"\x7f\xff\x04\x00")
            self.assertEqual((variables / f"BootOrder-{guid}").read_bytes(),
                             b"\x07\0\0\0\x02\0\x01\0\x00\0")
            # A second boot changes nothing; a disk laid out again replaces
            # the entry in place.
            self.run_entry(disk, variables)
            self.assertEqual(sorted(p.name[:8] for p in variables.iterdir()
                                    if p.name.startswith("Boot0")),
                             ["Boot0000", "Boot0001", "Boot0002"])
            gpt_disk(disk, unique=bytes(range(16, 32)))
            self.run_entry(disk, variables)
            self.assertEqual((variables / f"Boot0002-{guid}").read_bytes()[4 + 20 + 24:4 + 20 + 40],
                             bytes(range(16, 32)))
            self.assertEqual((variables / f"BootOrder-{guid}").read_bytes(),
                             b"\x07\0\0\0\x02\0\x01\0\x00\0")
            self.assertFalse((variables / ".staged").exists())
            # Not an ESP first (or no GPT): nothing is written.
            (variables / f"Boot0002-{guid}").unlink()
            disk.write_bytes(bytes(2048))
            self.run_entry(disk, variables)
            self.assertFalse((variables / f"Boot0002-{guid}").exists())


class UefiLayoutTests(unittest.TestCase):
    def test_boot_loaders_come_last_as_grub_installer_installs_them(self):
        # Bootstrapped without a boot loader; the requested list keeps grub-pc.
        self.assertNotIn("grub-pc", image.packages("none"))
        self.assertNotIn("os-prober", image.packages("none"))
        self.assertIn("grub-pc", image.requested_packages("none"))
        script = image.boot_loader_script()
        subprocess.run(["sh", "-n"], input=script, text=True, check=True)
        bios, uefi = script.split("uefi)")
        self.assertLess(bios.index("install os-prober"), bios.index("install grub-pc"))
        self.assertLess(uefi.index("install os-prober"), uefi.index("install grub-efi-amd64"))
        self.assertLess(uefi.index("install grub-efi-amd64"), uefi.index("install shim-signed"))
        self.assertIn("mkdir -p /boot/efi", uefi)
        self.assertIn("grub2/force_efi_extra_removable boolean true", uefi)
        self.assertIn("# / was on /dev/sda2 during installation", uefi)
        self.assertIn("/boot/efi       vfat    umask=0077      0       1", uefi)
        # The root line, not fstab's "# / was on" comment, gives the UUID.
        fstab = ("# / was on /dev/sda1 during installation\nUUID=abc / ext4 "
                 "errors=remount-ro 0 1\n")
        root = subprocess.run(["awk", "$1 !~ /^#/ && $2 == \"/\" {print $1}"], input=fstab,
                              text=True, capture_output=True, check=True).stdout
        self.assertEqual(root, "UUID=abc\n")
        self.assertIn("$1 !~ /^#/ && $2 == \"/\"", uefi)
        finish = image.finish_script()
        subprocess.run(["sh", "-n"], input=finish, text=True, check=True)
        self.assertIn("manager=none", finish)
        self.assertIn("rm -f /etc/apt/apt.conf.d/99mmdebstrap", finish)
        # The console customization stops where FINISH starts; a desktop's
        # runs it inline.
        self.assertIn('[ "$manager" != none ] || exit 0', image.customization_script())
        with patch.object(image.os, "geteuid", return_value=1000):
            command = image.mmdebstrap_command(image.options({"desktop": image.CONSOLE}),
                                               Path("/w/r.tar"), Path("/w/c.sh"), Path("/w/p"))
        hooks = [arg[len("--customize-hook="):] for arg in command
                 if arg.startswith("--customize-hook=")]
        order = [next(i for i, hook in enumerate(hooks) if marker in hook) for marker in (
            "antinomie-customize.sh debian", 'mkdir "$1/tmp/uefi-root"',
            "boot-loader.sh bios", "boot-loader.sh uefi", 'chroot "$1" sh /tmp/finish.sh',
            "debian-uefi-delta.py\" \"$1\"", 'rm -rf --one-file-system "$1/tmp/uefi-root"',
            "download /tmp/uefi-root.tar", "download /tmp/packages.tsv", "inode-times")]
        self.assertEqual(order, sorted(order), hooks)
        copy = next(hook for hook in hooks if 'mkdir "$1/tmp/uefi-root"' in hook)
        self.assertIn("--exclude='./dev/*'", copy)
        desktop = image.mmdebstrap_command(image.options({}), Path("/w/r.tar"), Path("/w/c.sh"),
                                           Path("/w/p"))
        self.assertFalse(any("uefi" in arg for arg in desktop))

    def test_the_delta_holds_what_the_uefi_system_changes(self):
        delta_spec = importlib.util.spec_from_file_location(
            "uefi_delta", REPO / "scripts/debian-uefi-delta.py")
        delta = importlib.util.module_from_spec(delta_spec)
        delta_spec.loader.exec_module(delta)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bios, uefi = root / "bios", root / "uefi"
            for system in (bios, uefi):
                for path in ("usr/lib/grub", "etc", "tmp", "proc/1"):
                    (system / path).mkdir(parents=True)
                (system / "etc/hostname").write_text("debian\n")
                os.utime(system / "etc/hostname", (100, 100))
                (system / "tmp/scratch").write_text("x")
            (bios / "usr/lib/grub/i386-pc").mkdir()
            (bios / "usr/lib/grub/i386-pc/boot.img").write_bytes(b"mbr")
            (uefi / "usr/lib/grub/x86_64-efi").mkdir()
            (uefi / "usr/lib/grub/x86_64-efi/grub.efi").write_bytes(b"efi")
            (uefi / "tmp/other").write_text("y")
            for system in (bios, uefi):
                for directory in ("usr/lib/grub", "usr/lib", "usr", "etc", "tmp", "proc"):
                    os.utime(system / directory, (200, 200))
            out = root / "delta.tar"
            layout = root / "layout.json"
            with patch.object(sys, "argv", ["x", str(bios), str(uefi), str(out), str(layout)]):
                delta.main()
            with tarfile.open(out) as archive:
                names = archive.getnames()
            self.assertEqual(names, ["usr/lib/grub/x86_64-efi", "usr/lib/grub/x86_64-efi/grub.efi"])
            record = json.loads(layout.read_text())
            self.assertEqual(record["removed"], ["usr/lib/grub/i386-pc/boot.img",
                                                 "usr/lib/grub/i386-pc"])
            self.assertEqual(set(record["times"]), set(names))
            # The app's record: geometry, removals and times per path.
            staging = root / "staging"
            bundle = root / "bundle"
            staging.mkdir()
            bundle.mkdir()
            shutil.copy2(out, staging / "uefi-root.tar")
            shutil.copy2(layout, staging / "uefi-layout.json")
            summary = image.uefi_layout(staging, bundle)
            self.assertEqual(summary, {"paths": 2, "removed": 2})
            written = json.loads((bundle / "uefi-layout.json").read_text())
            self.assertEqual(written["label"], "gpt")
            self.assertEqual(written["esp"]["first_sector"], 2048)
            self.assertEqual(written["root"]["first_sector"], (650 << 20) // 512)
            self.assertEqual(written["esp"]["first_sector"] + written["esp"]["sectors"],
                             written["root"]["first_sector"])
            times = written["times"]["usr/lib/grub/x86_64-efi/grub.efi"]
            self.assertEqual(len(times), 4)
            self.assertLessEqual(times[3], times[1])
            with tarfile.open(bundle / "uefi-root.tar.xz") as archive:
                self.assertEqual(archive.getnames(), names)
            self.assertFalse((staging / "uefi-root.tar").exists())


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
        # The installer's additions on top of its standard task.
        for package in ("tasksel", "installation-report", "discover", "laptop-detect", "eject",
                        "initramfs-tools", "keyboard-configuration", "console-setup", "sudo"):
            self.assertIn(package, console)
        # Not installed by the installer: curl (wget is standard) and
        # systemd-resolved (ifupdown and dhcpcd write resolv.conf).
        for package in ("curl", "systemd-resolved", "systemd-networkd"):
            self.assertNotIn(package, console)
        for package in console:
            self.assertFalse(package.startswith(("task-", "xserver", "lightdm", "gdm", "sddm",
                                                 "network-manager", "openssh-server",
                                                 "dbus-x11", "fonts-")), package)
        self.assertTrue(all(reason for _, reason in image.CONSOLE_PACKAGES))
        with patch.object(image.os, "geteuid", return_value=1000):
            command = image.mmdebstrap_command(values, Path("/w/r.tar"), Path("/w/c.sh"),
                                               Path("/w/p"))
        # The installer's standard task with recommends, documentation kept,
        # the package indexes kept.
        self.assertIn('--aptopt=APT::Install-Recommends "true"', command)
        self.assertIn("--variant=standard", command)
        self.assertFalse(any(arg.startswith("--dpkgopt=") for arg in command))
        self.assertIn("--skip=cleanup/apt/lists", command)
        self.assertIn("--skip=cleanup/apt/cache", command)
        unticked = image.mmdebstrap_command(image.options({"desktop": "none", "standard": False}),
                                            Path("/w/r.tar"), Path("/w/c.sh"), Path("/w/p"))
        self.assertIn("--variant=important", unticked)
        customize = next(arg for arg in command if "antinomie-customize.sh debian" in arg)
        self.assertRegex(customize, r"Etc/UTC none none [0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                                    r"[89ab][0-9a-f]{3}-[0-9a-f]{12} http://deb.debian.org/debian$")
        # The desktops keep the installer's recommends and their documentation.
        desktop = image.mmdebstrap_command(image.options({}), Path("/w/r.tar"), Path("/w/c.sh"),
                                           Path("/w/p"))
        self.assertFalse(any(arg.startswith("--dpkgopt=") for arg in desktop))
        script = image.customization_script()
        self.assertIn("systemctl set-default multi-user.target", script)
        # ifupdown's file as the installer leaves it, without the wired NIC's
        # stanza: provisioning writes it for the VM's NIC slot.
        self.assertTrue(image.CONSOLE_INTERFACES.endswith("auto lo\niface lo inet loopback\n"))
        self.assertNotIn("# The primary network interface", image.CONSOLE_INTERFACES)
        self.assertNotIn("allow-hotplug", image.CONSOLE_INTERFACES)
        # The app's provisioning recognises the stanza by the installer's comment.
        account = (Path(image.__file__).parent.parent / "src/antinomie/monitor/crates/monitor-core/"
                   "src/guest_account.rs").read_text()
        self.assertIn("/^# The primary network interface$/", account)
        self.assertNotIn("systemd-networkd", script)
        self.assertNotIn("systemd-resolved.service", script)
        self.assertNotIn("/etc/systemd/network/", script)
        self.assertIn("/usr/share/tasksel/descs/debian-tasks.desc", script)
        self.assertIn("exim4/mailname", script)
        self.assertIn("rm -f /etc/apt/apt.conf.d/99mmdebstrap /etc/dpkg/dpkg.cfg.d/99mmdebstrap",
                      script)

    def test_console_root_is_found_by_uuid_on_any_disk_bus(self):
        root = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
        # The installer's fstab: its header, the root by UUID with
        # errors=remount-ro, the CD drive.
        fstab = image.fstab("none", root)
        self.assertTrue(fstab.startswith("# /etc/fstab: static file system information.\n"))
        self.assertIn(f"\n# / was on {image.CONSOLE_ROOT_DEVICE} during installation\n"
                      f"UUID={root} /               ext4    errors=remount-ro 0       1\n", fstab)
        self.assertTrue(fstab.endswith("/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto"
                                       "     0       0\n"))
        self.assertEqual(image.fstab("xfce"), "/dev/vda / ext4 defaults 0 1\n")
        self.assertEqual(image.kernel_append("xfce"), image.APPEND)
        # GRUB's command line for a Debian install: no serial console, no panic=-1.
        self.assertEqual(image.kernel_append("none", "6.12.94+deb13-amd64 (x) #1", root),
                         f"BOOT_IMAGE=/boot/vmlinuz-6.12.94+deb13-amd64 root=UUID={root} ro quiet")
        script = image.customization_script()
        self.assertIn("rootuuid=${8:-} mirror=${9:-}", script)
        self.assertIn("printf 'UUID=%s /               ext4    errors=remount-ro 0       1\\n'"
                      " \"$rootuuid\"", script)
        with tempfile.TemporaryDirectory() as name:
            tarball = Path(name) / "rootfs.tar"
            for text, ok in ((image.fstab("none", root), True),
                             (image.fstab("xfce"), False),
                             (f"UUID={root} / ext4 defaults 0 1\n", False)):
                with tarfile.open(tarball, "w") as archive:
                    data = text.encode()
                    entry = tarfile.TarInfo("./etc/fstab")
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
                if ok:
                    self.assertEqual(image.fstab_uuid(tarball), root)
                else:
                    with self.assertRaises(RuntimeError):
                        image.fstab_uuid(tarball)
            if image.e2fsprogs_version() >= image.MIN_E2FSPROGS and shutil.which("debugfs"):
                raw = Path(name) / "root.raw"
                with raw.open("wb") as target:
                    target.truncate(16 << 20)
                subprocess.run(["mkfs.ext4", "-q", "-F", "-U", root, str(raw)], check=True)
                self.assertEqual(image.filesystem_uuid(raw), root)

    def test_only_the_console_base_claims_sata_and_nvme_and_only_when_built_in(self):
        with tempfile.TemporaryDirectory() as name:
            config, kernel = Path(name) / "config", Path(name) / "kernel"
            kernel.write_bytes(b"no EFI stub page claim")
            buses = "".join(f"CONFIG_{symbol}=y\n" for symbol in
                            ("ATA", "SATA_AHCI", "SCSI", "BLK_DEV_SD", "BLK_DEV_NVME"))
            config.write_text(buses)
            self.assertEqual(image.stealth_support("none", config, kernel),
                             ["sata", "nvme", "dhcp", "onboardnic"])
            self.assertEqual(image.stealth_support("xfce", config, kernel), ["dhcp"])
            # Debian's own configuration builds the controllers as modules.
            config.write_text(buses.replace("SATA_AHCI=y", "SATA_AHCI=m")
                              .replace("BLK_DEV_NVME=y", "BLK_DEV_NVME=m"))
            self.assertEqual(image.stealth_support("none", config, kernel), ["dhcp", "onboardnic"])

    def test_console_manifest_lists_the_requested_packages(self):
        manifest = (REPO / "src/antinomie/packaging/debian-minimal-trixie/packages.txt").read_text()
        requested = [line.split()[1] for line in manifest.splitlines()
                     if line.startswith("requested ")]
        self.assertEqual(requested, list(image.requested_packages("none")))
        resolved = [line.split("\t") for line in manifest.splitlines()
                    if line.startswith("installed\t")]
        names = {fields[1].split(":")[0] for fields in resolved}
        self.assertTrue(set(requested) <= names)
        self.assertFalse(names & {"openssh-server", "network-manager", "xserver-xorg-core",
                                  "qemu-guest-agent", "cloud-init", "curl", "systemd-resolved"})
        # What the installer's standard task with recommends brings.
        self.assertTrue({"exim4-daemon-light", "systemd-timesyncd", "man-db", "lsof",
                         "bind9-dnsutils", "ifupdown", "dhcpcd-base", "task-english",
                         "tasksel-data"} <= names)

    def test_console_configuration_is_the_installers(self):
        script = image.customization_script()
        sources = image.SOURCES_LIST.format(media="Debian GNU/Linux 13.1.0 _Trixie_ - Official "
                                            "amd64 NETINST with firmware 20250906-10:22",
                                            mirror="http://deb.debian.org/debian")
        self.assertTrue(sources.startswith("#deb cdrom:[Debian GNU/Linux 13.1.0 _Trixie_"))
        for line in ("deb http://deb.debian.org/debian/ trixie main non-free-firmware",
                     "deb-src http://deb.debian.org/debian/ trixie main non-free-firmware",
                     "deb http://security.debian.org/debian-security trixie-security main "
                     "non-free-firmware",
                     "deb http://deb.debian.org/debian/ trixie-updates main non-free-firmware",
                     "# This system was installed using small removable media"):
            self.assertIn(line + "\n", sources)
        self.assertIn("apt-get -o Acquire::Languages=en update", script)
        self.assertIn("# The following lines are desirable for IPv6 capable hosts\n", image.HOSTS)
        # Locale, time zone and keyboard through debconf, as the installer.
        self.assertIn("locales locales/default_environment_locale select", script)
        self.assertIn("rm -f /etc/locale.gen\ndpkg-reconfigure -f noninteractive locales", script)
        self.assertIn("dpkg-reconfigure -f noninteractive tzdata", script)
        self.assertIn("rm -f /etc/timezone", script)
        self.assertNotIn("> /etc/timezone", script)
        self.assertIn("printf '0.0 0 0.0\\n0\\nUTC\\n' > /etc/adjtime", script)
        self.assertIn("ln -sf /etc/machine-id /var/lib/dbus/machine-id", script)
        self.assertIn("tasksel tasksel/first multiselect standard", script)
        # /tmp stays on disk through a drop-in, not a mask.
        self.assertNotIn("systemctl mask tmp.mount", script)
        self.assertIn("ConditionPathIsMountPoint=/tmp", script)
        self.assertIn("/etc/systemd/system/tmp.mount.d/override.conf", script)
        with patch.object(image.os, "geteuid", return_value=1000):
            command = image.mmdebstrap_command(image.options({"desktop": image.CONSOLE,
                                                              "mirror": "http://m.example/debian/"}),
                                               Path("/w/r.tar"), Path("/w/c.sh"), Path("/w/p"))
        # The installation's logs stay; the mirror reaches sources.list.
        self.assertIn("--skip=cleanup/reproducible", command)
        customize = next(arg for arg in command if "antinomie-customize.sh" in arg
                         and "chroot" in arg)
        self.assertTrue(customize.endswith(" http://m.example/debian"), customize)

    def test_image_names_no_antinomie_file_and_masks_only_shipped_units(self):
        script = image.customization_script()
        # Every file the recipe writes into the image has a stock-looking name.
        for path in re.findall(r"(?:> |-p )(/(?:etc|var|usr)/\S+)", script):
            self.assertNotIn("antinomie", path.lower(), path)
        self.assertIn('if [ -e "/usr/lib/systemd/system/$unit" ]', script)
        self.assertIn("rm -f /etc/.resolv.conf.systemd-resolved.bak", script)
        self.assertNotIn("/var/lib/antinomie-image", script)
        with patch.object(image.os, "geteuid", return_value=1000):
            command = image.mmdebstrap_command(image.options({"desktop": image.CONSOLE}),
                                               Path("/w/r.tar"), Path("/w/c.sh"), Path("/w/p"))
        hooks = [arg[len("--customize-hook="):] for arg in command
                 if arg.startswith("--customize-hook=")]
        download = hooks.index("download /tmp/packages.tsv /w/p/packages.tsv")
        self.assertGreater(hooks.index('rm -f "$1/tmp/packages.tsv"'), download)

    def _tarball(self, root, files, links=()):
        tarball = Path(root) / "rootfs.tar"
        with tarfile.open(tarball, "w", format=tarfile.PAX_FORMAT) as archive:
            for name, text in files.items():
                data = text.encode()
                entry = tarfile.TarInfo("./" + name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
            for name, target in links:
                entry = tarfile.TarInfo("./" + name)
                entry.type = tarfile.SYMTYPE
                entry.linkname = target
                archive.addfile(entry)
        return tarball

    def test_build_host_name_is_a_trace_but_not_the_image_name(self):
        patterns = image.host_name_patterns("debian", {"MikiMiku", "MikiMiku.localdomain",
                                                       "debian", "localhost", "lab"})
        self.assertEqual(len(patterns), 2)
        self.assertTrue(any(p.search(b"mikimiku.localdomain\n") for p in patterns))
        self.assertFalse(any(p.search(b"debian\n127.0.1.1 lab\n") for p in patterns))
        self.assertEqual(image.host_name_patterns("lab", {"lab.example"}), [])
        with tempfile.TemporaryDirectory() as name:
            tarball = self._tarball(name, {"etc/mailname": "MikiMiku.localdomain\n"})
            with self.assertRaisesRegex(RuntimeError, "build traces"):
                image.check_image_leaks(tarball, patterns)

    def test_build_fails_on_build_host_traces(self):
        clean = {"etc/hostname": "debian\n",
                 "usr/lib/systemd/system/tmp.mount": "[Mount]\n",
                 "usr/lib/systemd/resolv.conf": "nameserver 127.0.0.53\n",
                 "usr/share/doc/x/README": "see http://ts.net.example/ and 10.255.255.254\n",
                 "etc/apt/sources.list": "deb http://deb.debian.org/debian trixie main\n"}
        host = Path(tempfile.mkdtemp()) / "resolv.conf"
        self.addCleanup(shutil.rmtree, host.parent)
        host.write_text("# generated by WSL\nnameserver 10.255.255.254\nnameserver 127.0.0.53\n"
                        "search taild7cded.ts.net corp.example.org lan\n")
        patterns = image.host_resolver_patterns(host)
        self.assertEqual(len(patterns), 3)  # 127.0.0.53 and the dotless "lan" are not host-specific
        self.assertEqual(image.host_resolver_patterns(host.parent / "missing"), [])
        bad = (
            ({"etc/.resolv.conf.systemd-resolved.bak":
              "nameserver 10.255.255.254\nsearch taild7cded.ts.net\n"}, ()),
            ({"etc/resolv.conf": "search tail0a1b2c.ts.net\n"}, ()),
            ({"var/log/installer/syslog": "domain corp.example.org\n"}, ()),
            # debconf keeps what a package's configuration asked (exim4's FQDN).
            ({"var/cache/debconf/config.dat": "Value: MikiMiku.taild7cded.ts.net\n"}, ()),
            ({"var/lib/antinomie-image/packages.tsv": "bash\n"}, ()),
            ({"etc/tmpfiles.d/antinomie-resolv.conf": "L+ /etc/resolv.conf\n"}, ()),
            ({}, (("etc/systemd/system/qemu-guest-agent.service", "/dev/null"),)),
        )
        with tempfile.TemporaryDirectory() as name:
            image.check_image_leaks(self._tarball(name, clean, (
                ("etc/systemd/system/tmp.mount", "/dev/null"),)), patterns)
            for files, links in bad:
                with self.subTest(files=files, links=links), \
                        self.assertRaisesRegex(RuntimeError, "build traces"):
                    image.check_image_leaks(self._tarball(name, {**clean, **files}, links),
                                            patterns)

    def test_installation_times_reach_every_path(self):
        # find -printf output: path, atime, ctime, birth, mtime.
        record = b"".join(field + b"\0" for field in (
            b"", b"1761385000.100000000", b"1761385010.200000000", b"1761384990.300000000",
            b"1761385010.200000000",
            b"etc", b"1761385100.5", b"1761385100.5", b"1761384995.000000001", b"1761385100.5",
            b"etc/hostname", b"1761385050.123456789", b"1761385040.987654321", b"-1",
            b"1761385040.987654321",
            b"usr/bin/bash", b"1761385060.111111111", b"1761385020.222222222",
            b"1761385020.222222222", b"1752339501.000000000",
            b"proc", b"1700000000.0", b"1700000000.0", b"1700000000.0", b"1700000000.0"))
        self.assertEqual(image.parse_time("1761385040.987654321"), (1761385040, 987654321))
        self.assertEqual(image.parse_time("12.5"), (12, 500000000))
        self.assertIsNone(image.parse_time("-1"))
        self.assertEqual(image.debugfs_path("usr/lib/systemd/system/system-systemd\\x2dcryptsetup.slice"),
                         '"/usr/lib/systemd/system/system-systemd\\x2dcryptsetup.slice"')
        with self.assertRaises(RuntimeError):
            image.debugfs_path('etc/a"b')
        with tempfile.TemporaryDirectory() as name:
            times = Path(name) / "inode-times"
            times.write_bytes(record)
            recorded = image.read_inode_times(times)
            self.assertNotIn("proc", recorded)
            self.assertIsNone(recorded["etc/hostname"][2])
            tarball = Path(name) / "rootfs.tar"
            with tarfile.open(tarball, "w", format=tarfile.PAX_FORMAT) as archive:
                for path, mtime, data in (("./", 1761385010, None), ("./etc", 1761385200, None),
                                          ("./etc/hostname", 1761385040, b"debian\n"),
                                          ("./usr", 1761385000, None),
                                          ("./usr/bin", 1761385000, None),
                                          ("./usr/bin/bash", 1752339501, b"#!"),
                                          ("./etc/added-later", 1761385300, b"x")):
                    entry = tarfile.TarInfo(path)
                    entry.mtime = mtime
                    if data is None:
                        entry.type = tarfile.DIRTYPE
                    else:
                        entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data or b""))
            rng = image.random.Random(1)
            plan, start, end = image.install_timeline(tarball, recorded, rng)
            # Access times are not part of the timeline (tar gives package times).
            self.assertEqual(start, (1761384990, 300000000))
            self.assertEqual(end, (1761385100, 500000000))
            for path, (atime, ctime, birth, mtime) in plan.items():
                with self.subTest(path=path):
                    self.assertGreaterEqual(ctime, mtime)
                    self.assertLessEqual(birth, ctime)
                    self.assertGreaterEqual(atime, birth)
                    self.assertGreater(ctime[0], 86400)
            # The installation's own times and nanoseconds survive.
            self.assertEqual(plan["etc/hostname"][:2], ((1761385050, 123456789),
                                                       (1761385040, 987654321)))
            self.assertEqual(plan["etc/hostname"][3], (1761385040, 987654321))
            # Unknown birth: born when changed. Package files keep their mtime.
            self.assertEqual(plan["etc/hostname"][2], plan["etc/hostname"][1])
            self.assertEqual(plan["usr/bin/bash"][3], (1752339501, 0))
            # The record's modification times win over the tarball's clamped ones.
            self.assertEqual(plan["etc"][3], (1761385100, 500000000))
            # Not recorded: changed when the installation ended, or later.
            self.assertGreaterEqual(plan["etc/added-later"][1][0], 1761385300)
            self.assertEqual(plan[""][1], (1761385010, 200000000))
            if image.e2fsprogs_version() >= image.MIN_E2FSPROGS and shutil.which("debugfs"):
                raw = Path(name) / "root.raw"
                with raw.open("wb") as target:
                    target.truncate(32 << 20)
                subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(tarball), str(raw)],
                               check=True)
                with (Path(name) / "log").open("w") as log:
                    self.assertEqual(image.apply_timeline(raw, plan, start, end, Path(name), log,
                                                          rng), len(plan))
                stat = subprocess.run(["debugfs", "-R", "stat /etc/hostname", str(raw)],
                                      capture_output=True, text=True, check=True).stdout
                self.assertIn("ctime: 0x68fc9a50:eb79a2c4", stat)
                self.assertIn("atime: 0x68fc9a5a:1d6f3454", stat)
                self.assertIn("crtime: 0x68fc9a50:eb79a2c4", stat)
                self.assertIn("mtime: 0x68fc9a50:eb79a2c4", stat)
                # The record's modification time replaces the tarball's.
                etc = subprocess.run(["debugfs", "-R", "stat /etc", str(raw)],
                                     capture_output=True, text=True, check=True).stdout
                self.assertIn("mtime: 0x68fc9a8c:77359400", etc)
                stats = subprocess.run(["dumpe2fs", "-h", str(raw)], capture_output=True,
                                       text=True, check=True).stdout
                self.assertRegex(stats, r"Mount count:\s+1\n")
                self.assertRegex(stats, r"Last mounted on:\s+/target\n")
                self.assertRegex(stats, r"Last write time:\s+\w+ Oct 2[56] \d\d:\d\d:\d\d 2025\n")

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
        # The installation's inode times are recorded after every change.
        self.assertTrue(hooks[-3].startswith('find "$1" -xdev -printf '), hooks[-3])
        self.assertEqual(hooks[-2], "download /tmp/inode-times /w/inode-times")
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
            (staging / image.INODE_TIMES).write_bytes(b"etc\0" + b"1\0" * 4)
            values = image.options({"desktop": "gnome"})
            record = {"bootstrap": "mmdebstrap", "root_built_at": "2026-10-09T00:00:00+00:00",
                      "reused_from_cache": False}
            cache = root / "cache/rootfs.tar"
            now = image.datetime(2026, 10, 10, tzinfo=image.timezone.utc)
            image.save_rootfs_cache(cache, rootfs, provenance, record, values)
            rootfs.unlink()
            (staging / image.INODE_TIMES).unlink()
            shutil.rmtree(provenance)
            provenance.mkdir()
            log = io.StringIO()
            with patch.object(image, "datetime", wraps=image.datetime) as clock:
                clock.now.return_value = now
                clock.fromisoformat = image.datetime.fromisoformat
                reused = image.load_rootfs_cache(cache, values, staging, provenance, log)
                self.assertTrue(reused["reused_from_cache"])
                self.assertEqual((provenance / "packages.tsv").read_text(), "packages.tsv")
                # The installation's inode times come back with the tarball.
                self.assertEqual((staging / image.INODE_TIMES).read_bytes(), b"etc\0" + b"1\0" * 4)
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
            for version in (b"6.12.94-custom", b"6.12.94+deb13-amd64", b"6.13.0", b"6.12.940"):
                data[0x240:0x280] = version + b"\0" * (64 - len(version))
                kernel.write_bytes(data)
                if version.startswith(b"6.12.94") and version != b"6.12.940":
                    self.assertEqual(image.kernel_release(kernel), version.decode())
                else:
                    with self.assertRaises(RuntimeError):
                        image.kernel_release(kernel)

    def test_debian_minimal_kernel_carries_debians_banner(self):
        import gzip

        def bzimage(banner):
            payload = gzip.compress(b"\0" * 64 + banner.encode() + b"\n\0" + b"\0" * 64)
            data = bytearray(0x400)
            data[0x1f1] = 1
            data[0x202:0x206] = b"HdrS"
            struct.pack_into("<II", data, 0x248, 0, len(payload))
            return bytes(data) + payload

        debian = image.debian_banner()
        # Debian's build of the pinned package, from its /boot/vmlinuz.
        self.assertEqual(debian, "Linux version 6.12.94+deb13-amd64 (debian-kernel@lists.debian.org) "
                         "(x86_64-linux-gnu-gcc-14 (Debian 14.2.0-19) 14.2.0, GNU ld (GNU Binutils "
                         "for Debian) 2.44) #1 SMP PREEMPT_DYNAMIC Debian 6.12.94-1 (2026-06-20)")
        with tempfile.TemporaryDirectory() as name:
            kernel = Path(name) / "kernel"
            kernel.write_bytes(bzimage(debian))
            self.assertEqual(image.kernel_banner(kernel), debian)
            # The same kernel linked by a newer binutils is refused for the console base.
            other = debian.replace("GNU ld (GNU Binutils for Debian) 2.44",
                                   "GNU ld (GNU Binutils for Debian) 2.47")
            kernel.write_bytes(bzimage(other))
            self.assertEqual(image.kernel_banner(kernel), other)
            helpers = unittest.mock.Mock()
            helpers.fixed_display_config.return_value = False
            # The host's e2fsprogs is not what this checks: a runner older than
            # 1.47.1 would stop the build before the banner is read.
            with patch.object(image, "kernel_release", return_value="6.12.94+deb13-amd64"), \
                    patch.object(image, "monitor_helpers", return_value=helpers), \
                    patch.object(image, "e2fsprogs_version", return_value=image.MIN_E2FSPROGS), \
                    self.assertRaisesRegex(RuntimeError, "2.47.*is not Debian's"):
                image.build(kernel, Path(name) / "out", values={"desktop": image.CONSOLE},
                            allow_unversioned=True)
            self.assertFalse((Path(name) / "out").exists())
            kernel.write_bytes(b"not a kernel")
            with self.assertRaisesRegex(RuntimeError, "bzImage"):
                image.kernel_banner(kernel)

    @unittest.skipUnless(os.environ.get("ANTINOMIE_NETWORK_TESTS") and shutil.which("zstd"),
                         "set ANTINOMIE_NETWORK_TESTS=1 (and install zstd) to read Debian's image")
    def test_pinned_banner_is_the_one_in_debians_image(self):
        with tempfile.TemporaryDirectory() as name:
            work = Path(name)
            deb = image.debian_kernel_debs(None, work)[0]
            listing = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(deb)], check=True,
                                     capture_output=True).stdout
            with tarfile.open(fileobj=io.BytesIO(listing)) as archive:
                vmlinuz = archive.extractfile("./boot/vmlinuz-6.12.94+deb13-amd64").read()
            (work / "vmlinuz").write_bytes(vmlinuz)
            self.assertEqual(image.kernel_banner(work / "vmlinuz"), image.debian_banner())

    def test_console_disk_is_the_installers_partitioned_disk(self):
        if not shutil.which("sfdisk"):
            self.skipTest("needs sfdisk")
        with tempfile.TemporaryDirectory() as name:
            raw = Path(name) / "root.raw"
            device = image.console_disk(raw, image.CONSOLE_IMAGE_SIZE, image.random.Random(5))
            self.assertEqual(device, f"{raw}?offset={1 << 20}")
            table = json.loads(subprocess.run(["sfdisk", "--json", str(raw)], check=True,
                                              capture_output=True, text=True).stdout)
            [root] = table["partitiontable"]["partitions"]
            self.assertEqual(table["partitiontable"]["label"], "dos")
            self.assertEqual((root["start"], root["size"], root["type"], root.get("bootable")),
                             (2048, image.CONSOLE_ROOT_SIZE // 512, "83", True))
        self.assertEqual(image.CONSOLE_ROOT_DEVICE, "/dev/sda1")
        self.assertIn("# / was on /dev/sda1 during installation",
                      image.fstab("none", "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"))

    def test_kernel_packages_are_debians_own_verified_through_the_signed_index(self):
        # The pinned packages are linux-signed-amd64 6.12.94+1's, for the
        # release the Antinomie kernel reports.
        self.assertEqual([(name, version) for name, version, _ in image.DEBIAN_KERNEL_PACKAGES],
                         [("linux-image-6.12.94+deb13-amd64", "6.12.94-1"),
                          ("linux-image-amd64", "6.12.94-1")])
        self.assertTrue(image.DEBIAN_KERNEL_ARCHIVE.startswith(
            "https://snapshot.debian.org/archive/debian-security/"))
        release = ("Origin: Debian\nSHA256:\n 00ff 12 main/binary-amd64/Packages\n"
                   " abcd 34 main/binary-amd64/Packages.xz\n")
        self.assertEqual(image.release_hash(release, "main/binary-amd64/Packages.xz"),
                         ("abcd", 34))
        with self.assertRaises(RuntimeError):
            image.release_hash(release, "main/binary-i386/Packages.xz")
        index = ("Package: linux-image-amd64\nVersion: 6.12.94-1\nArchitecture: amd64\n"
                 "Description: x\n multi-line\nFilename: pool/a.deb\nSize: 9\nSHA256: aa\n\n"
                 "Package: linux-image-amd64\nVersion: 6.12.95-1\nArchitecture: amd64\n"
                 "Filename: pool/b.deb\nSize: 8\nSHA256: bb\n")
        self.assertEqual(image.index_entries(index, {("linux-image-amd64", "6.12.94-1")}),
                         {("linux-image-amd64", "6.12.94-1"): ("pool/a.deb", 9, "aa")})
        with self.assertRaisesRegex(RuntimeError, "lacks linux-image-amd64 6.12.93-1"):
            image.index_entries(index, {("linux-image-amd64", "6.12.93-1")})
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            # Copies matching their pinned SHA-256 are used as they are; nothing
            # is downloaded.
            pinned = [(name, version, hashlib.sha256(name.encode()).hexdigest())
                      for name, version, _ in image.DEBIAN_KERNEL_PACKAGES]
            cache = root / "cache"
            cache.mkdir()
            for name, version, _ in pinned:
                (cache / image.deb_name(name, version)).write_bytes(name.encode())
            with patch.object(image, "DEBIAN_KERNEL_PACKAGES", tuple(pinned)), \
                    patch.object(image, "fetch", side_effect=AssertionError("downloaded")):
                debs = image.debian_kernel_debs(cache, root / "work")
            self.assertEqual([deb.parent for deb in debs], [cache, cache])
            # A copy that does not match goes back to the archive, whose
            # InRelease must verify.
            (cache / debs[0].name).write_bytes(b"tampered")
            fetched = []
            def fake_fetch(url, target, proxy=""):
                fetched.append(url)
                target.write_bytes(b"-----BEGIN PGP SIGNED MESSAGE-----\nforged\n")
            with patch.object(image, "DEBIAN_KERNEL_PACKAGES", tuple(pinned)), \
                    patch.object(image, "fetch", side_effect=fake_fetch):
                with self.assertRaisesRegex(RuntimeError, "does not verify"):
                    image.debian_kernel_debs(cache, root / "work")
            self.assertEqual(fetched, [image.DEBIAN_KERNEL_ARCHIVE
                                       + "/dists/trixie-security/InRelease"])
            # The Antinomie kernel's modules: its .ko files, owned by root.
            tree = root / "lib/modules/6.12.94+deb13-amd64"
            (tree / "kernel/net/netfilter").mkdir(parents=True)
            (tree / "kernel/net/netfilter/xt_mark.ko").write_bytes(b"ko")
            (tree / "modules.order").write_text("")
            archive = image.modules_archive(tree, root / "modules.tar")
            with tarfile.open(archive) as members:
                self.assertEqual([(m.name, m.uid, m.uname) for m in members],
                                 [("net/netfilter/xt_mark.ko", 0, "root")])
        # They go in before the rest of the customization: Debian's packages,
        # then the modules under updates/ with depmod, then dpkg --verify.
        with patch.object(image.os, "geteuid", return_value=1000):
            command = image.mmdebstrap_command(image.options({"desktop": image.CONSOLE}),
                                               Path("/w/r.tar"), Path("/w/c.sh"), Path("/w/p"),
                                               kernel_debs=(Path("/w/k/a.deb"), Path("/w/k/b.deb")),
                                               kernel_modules=Path("/w/k/m.tar"))
        hooks = [arg[len("--customize-hook="):] for arg in command
                 if arg.startswith("--customize-hook=")]
        install = hooks.index('chroot "$1" apt-get -o APT::Get::AllowUnauthenticated=false -y '
                              'install /tmp/a.deb /tmp/b.deb')
        modules = hooks.index("upload /w/k/m.tar /tmp/kernel-modules.tar")
        updates = "/usr/lib/modules/6.12.94+deb13-amd64/updates"
        # The module index names only them (the search order for this run).
        depmod = hooks.index(f"chroot \"$1\" sh -c 'mkdir -p {updates} && tar -x --no-same-owner "
                             f"-C {updates} -f /tmp/kernel-modules.tar && printf '\"'\"'search "
                             "updates\\nexclude kernel\\n'\"'\"' > /tmp/kernel-modules.conf && "
                             "depmod -a -C /tmp/kernel-modules.conf 6.12.94+deb13-amd64 && ! grep "
                             "-qv '\"'\"'^updates/'\"'\"' /usr/lib/modules/6.12.94+deb13-amd64/"
                             "modules.dep'")
        verify = hooks.index('chroot "$1" sh -c \'test -z "$(dpkg --verify '
                             'linux-image-6.12.94+deb13-amd64 linux-image-amd64)"\'')
        self.assertLess(hooks.index("upload /w/k/a.deb /tmp/a.deb"), install)
        self.assertLess(install, modules)
        self.assertLess(modules, depmod)
        self.assertLess(depmod, verify)
        self.assertLess(verify, hooks.index("upload /w/c.sh /tmp/antinomie-customize.sh"))
        # After the customization (whose packages have update-initramfs run
        # again), the initramfs is built once more from Debian's own module
        # index, as on any install, and the index of ours is restored.
        rebuild = hooks.index(f'chroot "$1" sh -c {image.shlex.quote(image.initramfs_rebuild())}')
        self.assertLess(hooks.index('rm -f "$1/tmp/antinomie-customize.sh"'), rebuild)
        self.assertLess(rebuild, next(i for i, hook in enumerate(hooks) if "inode-times" in hook))
        steps = image.initramfs_rebuild()
        self.assertLess(steps.index("search kernel\\nexclude updates"),
                        steps.index("update-initramfs -u -k 6.12.94+deb13-amd64"))
        self.assertLess(steps.index("update-initramfs"), steps.index("search updates\\nexclude kernel"))
        self.assertIn("lsinitramfs /boot/initrd.img-6.12.94+deb13-amd64 | grep -q "
                      "'^usr/lib/modules/6.12.94+deb13-amd64/kernel/'", steps)
        self.assertTrue(steps.endswith("! grep -qv '^updates/' "
                                       "/usr/lib/modules/6.12.94+deb13-amd64/modules.dep"))
        # Without modules of ours Debian's index stays and nothing is rebuilt.
        with patch.object(image.os, "geteuid", return_value=1000):
            plain = image.mmdebstrap_command(image.options({"desktop": image.CONSOLE}),
                                             Path("/w/r.tar"), Path("/w/c.sh"), Path("/w/p"),
                                             kernel_debs=(Path("/w/k/a.deb"),))
        self.assertFalse(any("update-initramfs" in arg for arg in plain))
        # The customization purges Debian's kernels, not the console base's own.
        self.assertIn('($1 ~ /^linux-image-/ && keep != "none")', image.customization_script())
        # The cache knows the kernel inputs by their hashes.
        values = image.options({"desktop": image.CONSOLE})
        first = image.rootfs_identity(values, ("aa", "bb"))
        self.assertEqual(first["kernel_packages"], ["aa", "bb"])
        self.assertNotEqual(first, image.rootfs_identity(values, ("aa", "cc")))
        self.assertNotIn("kernel_packages", image.rootfs_identity(values))
        # No Antinomie-made kernel package or /boot file is left in the recipe.
        recipe = Path(image.__file__).read_text()
        for gone in ("KERNEL_CONTROL", "KERNEL_IMAGE_MODE", "dpkg-deb\", \"--root-owner-group"):
            self.assertNotIn(gone, recipe)

    @unittest.skipUnless(os.environ.get("ANTINOMIE_NETWORK_TESTS"),
                         "set ANTINOMIE_NETWORK_TESTS=1 to check the signed index online")
    def test_pinned_kernel_packages_are_in_the_signed_archive_index(self):
        with tempfile.TemporaryDirectory() as name:
            entries = image.signed_index_entries(Path(name))
        for name, version, sha in image.DEBIAN_KERNEL_PACKAGES:
            self.assertEqual(entries[(name, version)][2], sha)

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
