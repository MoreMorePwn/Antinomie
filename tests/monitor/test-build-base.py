#!/usr/bin/env python3
"""Orchestrator contract tests (scripts/build-base.py); no kernel build."""
# SPDX-License-Identifier: GPL-3.0-only
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

    def test_debian_minimal_needs_the_toolchain_debians_banner_names(self):
        # The kernel build script reports what it would compile and link with.
        found = base.toolchain("minimal")
        self.assertEqual(set(found), {"cc", "ld"})
        self.assertTrue(found["ld"].startswith("GNU ld"))
        self.assertEqual(base.debian_toolchain(),
                         {"cc": "x86_64-linux-gnu-gcc-14 (Debian 14.2.0-19) 14.2.0",
                          "ld": "GNU ld (GNU Binutils for Debian) 2.44"})
        trixie = base.debian_toolchain()
        with unittest.mock.patch.object(base, "toolchain", return_value=trixie):
            base.require_debian_toolchain("minimal")
        newer = dict(trixie, ld="GNU ld (GNU Binutils for Debian) 2.47")
        with unittest.mock.patch.object(base, "toolchain", return_value=newer), \
                self.assertRaisesRegex(RuntimeError, "2.47.*QEMU builder"):
            base.require_debian_toolchain("minimal")
        # The orchestrator refuses before preparing any source.
        with tempfile.TemporaryDirectory() as name, \
                unittest.mock.patch.object(base, "toolchain", return_value=newer):
            job = Path(name) / "job.json"
            job.write_text(json.dumps({"format": 1, "profile": "debian-minimal"}))
            result = subprocess.run(
                ["python3", "-c", "import sys,runpy; sys.argv=sys.argv[1:]; "
                 "runpy.run_path(sys.argv[0], run_name='__main__')",
                 str(REPO / "scripts/build-base.py"), "--job", str(job), "--inputs", name,
                 "--work", str(Path(name) / "work"), "--output", str(Path(name) / "out")],
                capture_output=True, text=True)
            if base.toolchain("minimal") != trixie:
                self.assertEqual(result.returncode, 1)
                self.assertIn("::error this host's kernel", result.stdout)
                self.assertFalse((Path(name) / "work/source").exists())
        # A cached kernel names the toolchain that built it.
        self.assertEqual(base.kernel_identity("minimal")["toolchain"], found)

    def fake_engine(self, directory, name, version_exit=0, stderr="", rootless="false",
                    have_image=True):
        """A stand-in `podman` or `docker` on PATH that logs its calls."""
        log = Path(directory) / f"{name}.log"
        script = Path(directory) / name
        script.write_text(f"""#!/bin/sh
echo "$@" >> '{log}'
case "$1" in
  version) [ {version_exit} -eq 0 ] || {{ echo '{stderr}' >&2; exit {version_exit}; }}; echo 26.1.5 ;;
  info) echo '{rootless}' ;;
  image) {'exit 0' if have_image else 'exit 1'} ;;
  ps) echo stale1 ;;
esac
exit 0
""")
        script.chmod(0o755)
        return log

    def test_the_container_builder_picks_rootless_podman_then_docker(self):
        with tempfile.TemporaryDirectory() as name, \
                unittest.mock.patch.dict("os.environ", {"PATH": name}):
            self.fake_engine(name, "podman", rootless="true")
            self.fake_engine(name, "docker")
            self.assertEqual(base.pick_container_engine("auto"), ("podman", True))
            self.assertEqual(base.pick_container_engine("docker"), ("docker", False))
            Path(name, "podman").unlink()
            self.assertEqual(base.pick_container_engine("auto"), ("docker", False))
            with self.assertRaisesRegex(RuntimeError, "podman is not installed"):
                base.pick_container_engine("podman")
        with tempfile.TemporaryDirectory() as name, \
                unittest.mock.patch.dict("os.environ", {"PATH": name}):
            self.fake_engine(name, "docker", version_exit=1, stderr="permission denied")
            with self.assertRaisesRegex(RuntimeError, "root-equivalent"):
                base.pick_container_engine("auto")
        with tempfile.TemporaryDirectory() as name, \
                unittest.mock.patch.dict("os.environ", {"PATH": name}):
            self.fake_engine(name, "docker", version_exit=1, stderr="Cannot connect to the "
                             "Docker daemon at unix:///x. Is the docker daemon running?")
            with self.assertRaisesRegex(RuntimeError, "daemon is not reachable"):
                base.pick_container_engine("docker")

    def test_the_image_tag_follows_the_dockerfile_and_pins_its_toolchain(self):
        text = base.CONTAINER_DOCKERFILE.read_text()
        self.assertEqual(base.container_tag(),
                         "antinomie-builder:" + base.checksum(base.CONTAINER_DOCKERFILE)[:12])
        self.assertRegex(text, r"(?m)^FROM debian:trixie@sha256:[0-9a-f]{64}$")
        self.assertIn("snapshot.debian.org/archive/debian/%s/", text)
        # Debian 13's compiler and linker, by exact version, write the banner.
        self.assertIn("gcc-14=14.2.0-19", text)
        self.assertIn("binutils=2.44-3", text)

    def test_a_container_build_mounts_its_folders_and_always_removes_the_container(self):
        for engine, rootless in (("podman", "true"), ("docker", "false")):
            with tempfile.TemporaryDirectory() as name, \
                    unittest.mock.patch.dict("os.environ", {"PATH": name,
                                                            "ANTINOMIE_BUILD_NICE": "15"}):
                log = self.fake_engine(name, engine, rootless=rootless, have_image=False)
                root = Path(name)
                job = root / "job.json"
                job.write_text("{}")
                args = unittest.mock.Mock(
                    job=job, inputs=root / "inputs", work=root / "work", output=root / "o/out",
                    jobs=3, keep_kernel_build=False, kernel_cache=root / "k/kernel.tar",
                    image_cache=root / "i/rootfs.tar", ccache=root / "cc")
                self.assertEqual(base.run_in_container(args, engine), 0)
                calls = log.read_text().splitlines()
                tag = base.container_tag()
                # The missing image is built from the kit's Dockerfile first.
                self.assertTrue(any(c.startswith(f"build --label org.antinomie.builder=1 -t {tag}")
                                    for c in calls), calls)
                (run,) = [c for c in calls if c.startswith("run ")]
                for part in ("--rm", "--init", "--label org.antinomie.build=1",
                             "--cap-add=SYS_ADMIN", f"-v {root}/o:/out:rw",
                             f"-v {root}/k:/cache/kernels:rw", f"-v {root}/i:/cache/images:rw",
                             f"-v {root}/cc:/ccache:rw", "-v " + str(base.KIT) + ":/kit:ro",
                             f"ANTINOMIE_BUILDER_IMAGE={tag}", "--output /out/out",
                             "--kernel-cache /cache/kernels/kernel.tar",
                             "--image-cache /cache/images/rootfs.tar", "--jobs 3"):
                    self.assertIn(part, run)
                self.assertEqual("chown -R" in run, engine == "docker", run)
                self.assertIn("nice -n 15", run.replace("'", ""))
                # The container is removed, and stale ones of earlier builds too.
                self.assertTrue(any(c.startswith("rm -f antinomie-build-") for c in calls))
                self.assertIn("rm -f stale1", calls)

    def test_a_kernel_cached_by_the_container_builder_serves_other_builders(self):
        with tempfile.TemporaryDirectory() as name:
            work = Path(name)
            kept = work / "kept"
            for file in ("arch/x86/boot/bzImage", ".config", "symbols.json.xz"):
                (kept / file).parent.mkdir(parents=True, exist_ok=True)
                (kept / file).write_text("x")
            identity = {"format": 1, "profile": "minimal", "series": "s"}
            cache = work / "kernel.tar"
            with unittest.mock.patch.object(base, "kernel_identity", side_effect=lambda _: dict(identity)), \
                    unittest.mock.patch.dict("os.environ",
                                             {"ANTINOMIE_BUILDER_IMAGE": "antinomie-builder:abc"}):
                base.save_cached_kernel(cache, kept, "minimal")
                with base.tarfile.open(cache) as archive:
                    manifest = json.load(archive.extractfile("kernel-cache.json"))
                self.assertEqual(manifest["builder"], {"image": "antinomie-builder:abc"})
            with unittest.mock.patch.object(base, "kernel_identity", side_effect=lambda _: dict(identity)):
                self.assertIsNotNone(base.load_cached_kernel(cache, "minimal", work))
                changed = dict(identity, series="other")
            with unittest.mock.patch.object(base, "kernel_identity", side_effect=lambda _: dict(changed)):
                self.assertIsNone(base.load_cached_kernel(cache, "minimal", work))

    def test_jobs_accept_only_the_options_a_profile_offers(self):
        with tempfile.TemporaryDirectory() as name:
            job = Path(name) / "job.json"
            cases = [({"format": 1, "profile": "busybox", "options": {"hostname": "a"}}, None),
                     ({"format": 1, "profile": "debian-xfce", "options": {"locale": "en_US.UTF-8"}}, None),
                     ({"format": 1, "profile": "debian-minimal",
                       "options": {"locale": "en_US.UTF-8", "standard": True}}, None),
                     ({"format": 1, "profile": "debian-minimal", "options": {"desktop": "xfce"}},
                      "not offered"),
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

    def test_debian_minimal_is_the_console_recipe_on_the_minimal_kernel(self):
        self.assertEqual(base.PROFILES["debian-minimal"][:2], ("minimal", "build-debian-image.py"))
        self.assertEqual(base.PROFILES["busybox"][0], "minimal")
        commands = []
        with tempfile.TemporaryDirectory() as name, \
                unittest.mock.patch.object(base, "run", lambda *args, **_: commands.append(args)):
            work, kernel = Path(name) / "work", Path(name) / "kernel"
            work.mkdir()
            kernel.mkdir()
            base.build_image("debian-minimal", {"hostname": "lab"}, kernel, work, Path("/o"))
            answers = json.loads((work / "options.json").read_text())
            self.assertEqual(answers, {"hostname": "lab", "desktop": "none"})
            # A minimal kernel without modules: none are passed.
            self.assertNotIn("--modules", commands[0])
            self.assertNotIn("--debian-config", commands[0])
            # Debian's kernel packages are kept with the other Debian inputs.
            self.assertNotIn("--kernel-package-cache", commands[0])
            base.build_image("debian-minimal", {}, kernel, work, Path("/o"), inputs=Path("/in"))
            self.assertEqual(commands[-1][-2:], ("--kernel-package-cache", Path("/in")))
            commands.pop()
            (kernel / "modules-install").mkdir()
            base.build_image("debian-xfce", {"desktop": "gnome"}, kernel, work, Path("/o"))
            self.assertIn("--modules", commands[1])
            self.assertEqual(json.loads((work / "options.json").read_text()), {"desktop": "gnome"})

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
            (kept / "debian-config").write_text("CONFIG_Y=m\n")
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
            self.assertEqual((loaded / "debian-config").read_text(), "CONFIG_Y=m\n")
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
