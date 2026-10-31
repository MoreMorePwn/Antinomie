#!/usr/bin/env python3
"""Contract tests for scripts/publish-base-sources.py and the source records the
image builders write into bundle.json; no network, no kernel build."""
# SPDX-License-Identifier: GPL-3.0-only
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import unittest.mock

REPO = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publish = load("publish_base_sources", "scripts/publish-base-sources.py")
builder = load("build_monitor_image", "scripts/build-monitor-image.py")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sha1(data):
    return hashlib.sha1(data).hexdigest()


def dsc(files):
    lines = "".join(f" {sha256(data)} {len(data)} {name}\n" for name, data in files.items())
    return f"Format: 3.0 (quilt)\nSource: x\nChecksums-Sha256:\n{lines}Files:\n md5 1 x\n".encode()


class FakeSnapshot(publish.Snapshot):
    """A snapshot.debian.org holding fixed source packages."""

    def __init__(self, packages):
        super().__init__("https://snapshot.invalid")
        self.packages = packages
        self.downloads = []

    def source_files(self, source, version):
        if (source, version) not in self.packages:
            raise publish.SourceError(f"{source} {version} is not on snapshot.debian.org")
        return [(name, sha1(data), f"https://snapshot.invalid/{source}/{name}", len(data))
                for name, data in self.packages[(source, version)].items()]

    def fetch(self, url, destination=None):
        source, name = url.rsplit("/", 2)[-2:]
        self.downloads.append(name)
        data = next(files[name] for (package, _), files in self.packages.items()
                    if package == source and name in files)
        Path(destination).write_bytes(data)


def source_package(source, version, extra=None):
    # File names carry the version without its epoch.
    stem = f"{source}_{version.split(':')[-1]}"
    files = {f"{stem}.orig.tar.xz": b"orig " + source.encode(),
             f"{stem}.debian.tar.xz": b"debian " + source.encode()}
    files.update(extra or {})
    files[f"{stem}.dsc"] = dsc(files)
    return files


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.linux = source_package("linux", "1.0-1")
        self.packages = {("linux", "1.0-1"): self.linux,
                         ("busybox", "1:1.37.0-6"): source_package("busybox", "1:1.37.0-6")}
        self.repo = self.root / "repo"
        series = self.repo / publish.SERIES_DIR
        series.mkdir(parents=True)
        (series / "0001-a.patch").write_text("patch a\n")
        (series / "0002-b.patch").write_text("patch b\n")
        adapter = self.repo / publish.ADAPTER
        adapter.mkdir(parents=True)
        (adapter / "adapter.conf").write_text(
            "SOURCE_VERSION=1.0-1\n"
            "INPUT_ORIG=src/debian/linux_1.0-1.orig.tar.xz\n"
            "INPUT_DEBTAR=src/debian/linux_1.0-1.debian.tar.xz\n"
            f"INPUT_SHA_ORIG={sha256(self.linux['linux_1.0-1.orig.tar.xz'])}\n"
            f"INPUT_SHA_DEBTAR={sha256(self.linux['linux_1.0-1.debian.tar.xz'])}\n")
        (adapter / "series.fence").write_text("# fence\n")
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts/build-monitor-kernel.sh").write_text("#!/bin/sh\n")
        self.series = publish.series_hash(series)
        self.bundle = self.root / "bundle"
        (self.bundle / "provenance").mkdir(parents=True)
        (self.bundle / "kernel.config").write_text("CONFIG_ANTINOMIE=y\n")
        self.record = {"kernel": {"source_package": "linux", "source_version": "1.0-1",
                                  "antinomie_revision": 16, "antinomie_source": self.series},
                       "packages": [{"package": "busybox", "version": "1:1.37.0-6+b1",
                                     "architecture": "amd64", "source_package": "busybox",
                                     "source_version": "1:1.37.0-6"}]}
        self.write_bundle(self.record)

    def write_bundle(self, guest_sources):
        manifest = {"format": 1, "kernel_version": "6.12.94", "schema_id": 1, "kernel": "kernel",
                    "kernel_append": "console=ttyS0", "base_disk": "base.qcow2",
                    "sha256": {"kernel": "11" * 32, "base.qcow2": "22" * 32}}
        if guest_sources is not None:
            manifest["guest_sources"] = guest_sources
        (self.bundle / "bundle.json").write_text(json.dumps(manifest))

    def run_publish(self, **kwargs):
        self.snapshot = FakeSnapshot(self.packages)
        return publish.publish(self.bundle, self.root / "out", self.repo, self.root / "cache",
                               self.snapshot, **kwargs)

    def test_dsc_checksums_are_read_with_sizes(self):
        found = publish.dsc_checksums(dsc({"a.tar.xz": b"abc"}).decode())
        self.assertEqual(found, {"a.tar.xz": (sha256(b"abc"), 3)})

    def test_busybox_base_publishes_kernel_and_userland_sources(self):
        manifest = self.run_publish(identity="ab" * 32)
        out = self.root / "out"
        kernel_id = f"linux-1.0-1-antinomie-r16-{self.series[:8]}"
        self.assertEqual(manifest["kernel"]["id"], kernel_id)
        for relative in ("debian/linux_1.0-1/linux_1.0-1.dsc",
                         "debian/linux_1.0-1/linux_1.0-1.orig.tar.xz",
                         f"kernels/{kernel_id}/patches/0001-a.patch",
                         f"kernels/{kernel_id}/patches/0002-b.patch",
                         f"kernels/{kernel_id}/recipe/scripts/build-monitor-kernel.sh",
                         f"kernels/{kernel_id}/recipe/{publish.ADAPTER}/adapter.conf",
                         "userland/busybox_1.37.0-6/busybox_1.37.0-6.dsc",
                         f"bases/{'ab' * 32}/kernel.config",
                         f"bases/{'ab' * 32}/SOURCES.json"):
            self.assertTrue((out / relative).is_file(), relative)
        for relative, digest in manifest["files"].items():
            self.assertEqual(publish.sha256_file(out / relative), digest, relative)
        self.assertEqual(manifest["userland"][0]["binary_packages"], ["busybox 1:1.37.0-6+b1"])
        self.assertIsNone(manifest["inventory"])

    def test_series_that_differs_from_the_kernels_is_refused(self):
        (self.repo / publish.SERIES_DIR / "0003-c.patch").write_text("patch c\n")
        with self.assertRaisesRegex(publish.SourceError, "patch series hashes to"):
            self.run_publish(identity="ab" * 32)
        self.assertFalse((self.root / "out/kernels").exists())

    def test_a_download_that_disagrees_with_the_dsc_is_refused(self):
        files = self.packages[("busybox", "1:1.37.0-6")]
        files["busybox_1.37.0-6.debian.tar.xz"] = b"tampered"
        with self.assertRaisesRegex(publish.SourceError, "does not match the checksum"):
            self.run_publish(identity="ab" * 32)

    def test_a_download_that_disagrees_with_the_repository_pin_is_refused(self):
        files = self.packages[("linux", "1.0-1")]
        files["linux_1.0-1.dsc"] = dsc({**{k: v for k, v in files.items() if k != "linux_1.0-1.dsc"},
                                        "linux_1.0-1.orig.tar.xz": b"other"})
        files["linux_1.0-1.orig.tar.xz"] = b"other"
        with self.assertRaisesRegex(publish.SourceError, "pinned by the repository"):
            self.run_publish(identity="ab" * 32)

    def test_a_file_no_package_owns_cannot_be_published(self):
        self.record["packages"].append({"package": None, "path": "/opt/tool"})
        self.write_bundle(self.record)
        with self.assertRaisesRegex(publish.SourceError, "no package owns"):
            self.run_publish(identity="ab" * 32)

    def test_a_bundle_without_any_package_record_is_refused(self):
        self.write_bundle({"kernel": self.record["kernel"]})
        with self.assertRaisesRegex(publish.SourceError, "records no packages"):
            self.run_publish(identity="ab" * 32)
        self.run_publish(identity="ab" * 32, packages_file=self._packages_file())

    def _packages_file(self):
        path = self.root / "packages.json"
        path.write_text(json.dumps(self.record["packages"]))
        return path

    def test_a_debian_base_gets_an_inventory_with_snapshot_links(self):
        (self.bundle / "provenance/packages.tsv").write_text(
            "7zip\t25.01+dfsg-1~deb13u2\tamd64\t7zip\t25.01+dfsg-1~deb13u2\tinstalled\n"
            "gone\t1\tamd64\tgone\t1\tconfig-files\n")
        manifest = self.run_publish(identity="ab" * 32)
        table = (self.root / f"out/bases/{'ab' * 32}/packages.tsv").read_text().splitlines()
        self.assertEqual(manifest["inventory_packages"], 1)
        self.assertEqual(len(table), 2)
        self.assertTrue(table[1].endswith("https://snapshot.debian.org/package/7zip/"
                                          "25.01%2Bdfsg-1~deb13u2/"))

    def test_published_files_are_not_downloaded_again(self):
        self.run_publish(identity="ab" * 32)
        first = len(self.snapshot.downloads)
        self.run_publish(identity="ab" * 32)
        self.assertGreater(first, 0)
        self.assertEqual(self.snapshot.downloads, [])

    def test_series_hash_matches_the_shell_rule_the_kernel_build_uses(self):
        import subprocess
        shell = subprocess.run("sha256sum -- *.patch | sha256sum", shell=True, check=True,
                               cwd=self.repo / publish.SERIES_DIR, capture_output=True,
                               text=True).stdout.split()[0]
        self.assertEqual(self.series, shell)


class BuilderRecordTests(unittest.TestCase):
    def test_stamp_revision_records_the_kernel_source_identity(self):
        manifest = {}
        series = "cd" * 32
        with unittest.mock.patch.object(builder, "source_identity", return_value=(16, series)):
            builder.stamp_revision(manifest, Path("kernel"), False, "0.6.0")
        record = manifest["guest_sources"]["kernel"]
        self.assertEqual(record["source_package"], "linux")
        self.assertEqual(record["source_version"], "6.12.94-1")
        self.assertEqual((record["antinomie_revision"], record["antinomie_source"]), (16, series))

    def test_host_package_names_the_source_package_and_version(self):
        calls = iter([unittest.mock.Mock(returncode=0, stdout="busybox: /usr/bin/busybox\n")])
        with unittest.mock.patch.object(builder.subprocess, "run", side_effect=lambda *a, **k: next(calls)), \
                unittest.mock.patch.object(builder.subprocess, "check_output",
                    return_value="busybox\t1:1.37.0-6+b1\tamd64\tbusybox\t1:1.37.0-6\n"):
            record = builder.host_package("/usr/bin/busybox")
        self.assertEqual(record, {"package": "busybox", "version": "1:1.37.0-6+b1",
                                  "architecture": "amd64", "source_package": "busybox",
                                  "source_version": "1:1.37.0-6"})

    def test_a_file_without_an_owning_package_is_kept_visible(self):
        builder.INSTALLED_PACKAGES.clear()
        with unittest.mock.patch.object(builder, "host_package", return_value=None):
            builder.record_package(Path("/opt/tool"))
        self.assertEqual(builder.INSTALLED_PACKAGES, {"/opt/tool": {"package": None, "path": "/opt/tool"}})
        builder.INSTALLED_PACKAGES.clear()


if __name__ == "__main__":
    unittest.main()
