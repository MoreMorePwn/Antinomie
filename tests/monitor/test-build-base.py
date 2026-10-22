#!/usr/bin/env python3
"""Orchestrator contract tests (scripts/build-base.py); no kernel build."""
# SPDX-License-Identifier: MIT
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import unittest.mock

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("build_base", REPO / "scripts/build-base.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class BuildBaseTests(unittest.TestCase):
    def test_series_hash_matches_the_kernel_build_script(self):
        shell = subprocess.run("sha256sum -- *.patch | sha256sum", shell=True, cwd=base.SERIES,
                               capture_output=True, text=True, check=True).stdout.split()[0]
        self.assertEqual(base.series_hash(), shell)

    def test_adapter_pins_the_source_package(self):
        conf = base.adapter()
        self.assertEqual(conf["SOURCE_DIRNAME"], "linux-6.12.94")
        self.assertEqual(len(conf["INPUT_SHA_ORIG"]), 64)
        self.assertEqual(base.checksum(REPO / conf["INPUT_DEBTAR"]), conf["INPUT_SHA_DEBTAR"])

    def test_jobs_accept_only_the_options_a_profile_offers(self):
        with tempfile.TemporaryDirectory() as name:
            job = Path(name) / "job.json"
            cases = [({"format": 1, "profile": "busybox", "options": {"hostname": "a"}}, None),
                     ({"format": 1, "profile": "debian-xfce", "options": {"locale": "en_US.UTF-8"}}, None),
                     ({"format": 1, "profile": "busybox", "options": {"locale": "x"}}, "not offered"),
                     ({"format": 2, "profile": "busybox"}, "format 1"),
                     ({"format": 1, "profile": "windows"}, "unknown profile"),
                     ({"format": 1, "profile": "busybox", "options": []}, "object")]
            for value, error in cases:
                job.write_text(json.dumps(value))
                with self.subTest(value=value):
                    if error is None:
                        self.assertEqual(base.load_job(job)[:2], (value["profile"], value.get("options", {})))
                    else:
                        with self.assertRaisesRegex(RuntimeError, error):
                            base.load_job(job)

    def test_busybox_answers_left_out_take_the_recipes_defaults(self):
        # The recipe's defaults (hostname debian) are the app's: no build path
        # names the guest localhost.
        commands = []
        with unittest.mock.patch.object(base, "run", lambda *args, **_: commands.append(args)):
            for values in ({}, {"hostname": "lab", "name": "Lab"}):
                base.build_image("busybox", values, Path("/b"), Path("/w"), Path("/o"))
        self.assertNotIn("--hostname", commands[0])
        self.assertNotIn("localhost", commands[0])
        self.assertEqual(commands[1][-4:], ("--hostname", "lab", "--name", "Lab"))
        recipe = (REPO / "scripts/build-monitor-image.py").read_text()
        self.assertIn('parser.add_argument("--hostname", default="debian")', recipe)
        app = (REPO / "src/antinomie/monitor/crates/monitor-core/src/build.rs").read_text()
        self.assertIn('hostname: "debian".into()', app)

    def test_missing_or_wrong_tarball_is_refused_before_unpacking(self):
        with tempfile.TemporaryDirectory() as name:
            inputs, work = Path(name) / "inputs", Path(name) / "work"
            inputs.mkdir()
            work.mkdir()
            with self.assertRaisesRegex(RuntimeError, "pinned SHA-256"):
                base.prepare_source(inputs, work)
            (inputs / "linux_6.12.94.orig.tar.xz").write_bytes(b"not the tarball")
            with self.assertRaisesRegex(RuntimeError, "pinned SHA-256"):
                base.prepare_source(inputs, work)
            self.assertEqual(list(work.iterdir()), [])


    def test_kernel_cache_round_trip_and_mismatch(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            kept = root / "kept"
            (kept / "arch/x86/boot").mkdir(parents=True)
            (kept / "arch/x86/boot/bzImage").write_bytes(b"kernel")
            (kept / ".config").write_text("CONFIG_X=y\n")
            (kept / "symbols.json.xz").write_bytes(b"isf")
            modules = kept / "modules-install/lib/modules/6.12.94"
            modules.mkdir(parents=True)
            (modules / "modules.dep").write_text("")
            (modules / "build").symlink_to("/build/work/kernel-debian")
            cache = root / "cache/kernel-debian.tar"
            base.save_cached_kernel(cache, kept, "debian")
            work = root / "work"
            work.mkdir()
            loaded = base.load_cached_kernel(cache, "debian", work)
            self.assertEqual((loaded / "arch/x86/boot/bzImage").read_bytes(), b"kernel")
            self.assertEqual((loaded / "symbols.json.xz").read_bytes(), b"isf")
            self.assertTrue((loaded / "modules-install/lib/modules/6.12.94/modules.dep").is_file())
            self.assertFalse((loaded / "modules-install/lib/modules/6.12.94/build").is_symlink())
            self.assertIsNone(base.load_cached_kernel(cache, "minimal", work))
            self.assertIsNone(base.load_cached_kernel(root / "missing.tar", "debian", work))
            cache.write_bytes(b"not a tar")
            self.assertIsNone(base.load_cached_kernel(cache, "debian", work))
            self.assertIsNone(base.load_cached_kernel(None, "debian", work))
            # A kernel cached before bases carried a symbol table is rebuilt.
            (kept / "symbols.json.xz").unlink()
            base.save_cached_kernel(cache, kept, "debian")
            self.assertIsNone(base.load_cached_kernel(cache, "debian", work))


if __name__ == "__main__":
    unittest.main()
