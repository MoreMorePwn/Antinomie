#!/usr/bin/env python3
"""Orchestrator contract tests (scripts/build-base.py); no kernel build."""
# SPDX-License-Identifier: GPL-3.0-only
import importlib.util
import json
import os
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
  ps) echo "stale1 99999999"; echo "mine $PPID" ;;
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
                for part in ("--rm", "--init", f"--label org.antinomie.build={os.getpid()}",
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
                self.assertNotIn("mine", " ".join(c for c in calls if c.startswith("rm -f")))

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

    def test_debian_minimal_is_the_console_recipe_on_the_stock_kernel(self):
        self.assertEqual(base.PROFILES["debian-minimal"][:2], ("stock", "build-debian-image.py"))
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
            # The stock kernel builds no modules (Debian's load): none are passed.
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

    def test_the_stock_kernel_is_compared_with_debians_image(self):
        calls = []
        with tempfile.TemporaryDirectory() as name, \
                unittest.mock.patch.object(base, "run", lambda *args, **kw: calls.append((args, kw))):
            work = Path(name)
            base.build_kernel("stock", work / "tree", work, 2, debian_image=Path("/in/linux.deb"))
            base.build_kernel("minimal", work / "tree", work, 2)
        self.assertEqual(calls[0][0][2], "stock")
        self.assertEqual(calls[0][1]["env"]["ANTINOMIE_DEBIAN_IMAGE"], "/in/linux.deb")
        self.assertNotIn("ANTINOMIE_DEBIAN_IMAGE", calls[1][1]["env"])
        # The package comes from the inputs through the image recipe's verified fetch.
        fetched = []

        class Recipe:
            @staticmethod
            def debian_kernel_debs(cache, work, proxy=""):
                fetched.append((cache, proxy))
                return [cache / "linux-image.deb", cache / "meta.deb"]

        with tempfile.TemporaryDirectory() as name, \
                unittest.mock.patch.object(base.importlib.util, "module_from_spec",
                                           return_value=Recipe), \
                unittest.mock.patch.object(base.importlib.util, "spec_from_file_location"):
            self.assertEqual(base.debian_image(Path("/in"), Path(name), "http://proxy"),
                             Path("/in/linux-image.deb"))
        self.assertEqual(fetched, [(Path("/in"), "http://proxy")])

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

    def test_the_toolchain_chroot_pins_come_from_the_container_dockerfile(self):
        chroot = base.toolchain_module()
        text = base.CONTAINER_DOCKERFILE.read_text()
        stamp, versions = chroot.parse_pins(text)
        self.assertRegex(stamp, r"^\d{8}T\d{6}Z$")
        self.assertEqual(set(versions), set(chroot.PACKAGES))
        self.assertEqual((versions["gcc-14"], versions["binutils"]), ("14.2.0-19", "2.44-3"))
        self.assertEqual(versions["bison"], "2:3.8.2+dfsg-1+b2")
        # The version Debian's banner names is the pinned one.
        self.assertIn(f"Debian {versions['gcc-14']})", base.debian_toolchain()["cc"])
        with self.assertRaisesRegex(RuntimeError, "snapshot stamp"):
            chroot.parse_pins("RUN true")
        with self.assertRaisesRegex(RuntimeError, "does not pin"):
            chroot.parse_pins("stamp=20260101T000000Z; \\\n    bc=1.0 \\\n")
        command = chroot.bootstrap_command(stamp, versions, Path("/t/root.tar"))
        self.assertEqual(command[:4], ["mmdebstrap", "--mode=unshare", "--variant=minbase",
                                       "--format=tar"])
        self.assertIn("--include=" + ",".join(f"{n}={v}" for n, v in versions.items()), command)
        self.assertEqual(sum(f"/{stamp}/" in word for word in command), 3)
        self.assertTrue(all("snapshot.debian.org" in word and "signed-by=" in word
                            for word in command[-3:]))

    def test_a_toolchain_chroot_is_ready_only_for_the_dockerfile_it_was_made_from(self):
        chroot = base.toolchain_module()
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            self.assertFalse(chroot.ready(directory, base.CONTAINER_DOCKERFILE))
            gcc = directory / "root/usr/bin/x86_64-linux-gnu-gcc-14"
            gcc.parent.mkdir(parents=True)
            gcc.write_text("")
            (directory / chroot.MARKER).write_text(json.dumps(
                {"dockerfile_sha256": chroot.sha256(base.CONTAINER_DOCKERFILE)}))
            self.assertTrue(chroot.ready(directory, base.CONTAINER_DOCKERFILE))
            changed = directory / "Dockerfile"
            changed.write_text(base.CONTAINER_DOCKERFILE.read_text() + "# changed\n")
            self.assertFalse(chroot.ready(directory, changed))
            # A complete chroot is reused without touching the network.
            with unittest.mock.patch.object(chroot.subprocess, "run") as run:
                self.assertEqual(chroot.ensure(directory, base.CONTAINER_DOCKERFILE),
                                 directory / "root")
                run.assert_not_called()

    def test_the_chroot_binds_the_builds_folders_at_the_containers_paths(self):
        chroot = base.toolchain_module()
        with tempfile.TemporaryDirectory() as name:
            work, kit = Path(name, "w").resolve(), Path(name, "k").resolve()
            work.mkdir()
            kit.mkdir()
            sandbox = chroot.Chroot(Path(name, "root"), [(kit, "/kit", False), (work, "/work", True)])
            self.assertEqual(sandbox.translate(work / "source/linux"), "/work/source/linux")
            self.assertEqual(sandbox.translate(kit), "/kit")
            self.assertEqual(sandbox.translate(str(work) + "-other"), str(work) + "-other")
            command = sandbox.command(["bash", kit / "scripts/x.sh", "minimal"],
                                      {"ANTINOMIE_BUILD_TREE": work / "kernel", "JOBS": "12"})
            self.assertEqual(command[:7], ["unshare", "--user", "--map-root-user", "--mount",
                                           "--pid", "--fork", "--kill-child"])
            script = command[-1]
            self.assertIn("mount --rbind /dev", script)
            self.assertIn(f"mount --rbind {kit}", script)
            self.assertIn("remount,bind,ro", script)
            self.assertEqual(script.count("remount,bind,ro"), 1)  # only /kit is read-only
            self.assertIn("exec chroot", script)
            self.assertIn("env -i", script)
            self.assertIn("ANTINOMIE_BUILD_TREE=/work/kernel", script)
            self.assertIn("JOBS=12", script)
            self.assertIn("bash /kit/scripts/x.sh minimal", script)
            # Nothing of the host's environment leaks in.
            self.assertNotIn(os.environ["PATH"], script)

    def test_a_host_without_debians_toolchain_compiles_in_the_chroot_or_is_refused(self):
        trixie = base.debian_toolchain()
        newer = dict(trixie, cc="gcc (Ubuntu 15.2.0-4ubuntu4) 15.2.0")
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fake = unittest.mock.Mock()
            fake.ensure.return_value = root / "chroot/root"
            fake.Chroot.side_effect = lambda *args: ("chroot", args)
            try:
                # Debian 13's own toolchain compiles on the host; no chroot is made.
                with unittest.mock.patch.object(base, "toolchain", return_value=trixie), \
                        unittest.mock.patch.object(base, "toolchain_module", return_value=fake):
                    base.require_debian_toolchain("minimal", root / "chroot", root / "w", root / "i")
                self.assertIsNone(base.SANDBOX)
                fake.ensure.assert_not_called()
                # Another toolchain: refused without a chroot, naming the way out.
                with unittest.mock.patch.object(base, "toolchain", return_value=newer), \
                        self.assertRaisesRegex(RuntimeError, "Ubuntu.*--toolchain-chroot"):
                    base.require_debian_toolchain("minimal")
                # With one, the chroot is made and must then answer with Debian's.
                answers = iter([newer, trixie])
                with unittest.mock.patch.object(base, "toolchain", side_effect=lambda _: next(answers)), \
                        unittest.mock.patch.object(base, "toolchain_module", return_value=fake):
                    base.require_debian_toolchain("minimal", root / "chroot", root / "w",
                                                  root / "i", root / "cc")
                fake.ensure.assert_called_once_with(root / "chroot", base.CONTAINER_DOCKERFILE)
                kind, (chroot_root, mounts) = base.SANDBOX
                self.assertEqual(chroot_root, root / "chroot/root")
                self.assertEqual([(inside, writable) for _, inside, writable in mounts],
                                 [("/kit", False), ("/work", True), ("/inputs", False),
                                  ("/ccache", True)])
                # A chroot that still has another toolchain is not used silently.
                base.SANDBOX = None
                answers = iter([newer, newer])
                with unittest.mock.patch.object(base, "toolchain", side_effect=lambda _: next(answers)), \
                        unittest.mock.patch.object(base, "toolchain_module", return_value=fake), \
                        self.assertRaisesRegex(RuntimeError, "toolchain chroot's kernel compiler"):
                    base.require_debian_toolchain("minimal", root / "chroot", root / "w", root / "i")
            finally:
                base.SANDBOX = None

    def test_a_chrooted_step_passes_only_its_own_environment(self):
        with unittest.mock.patch.object(base, "SANDBOX") as sandbox:
            base.run_tool("patch", "-p1", env={"JOBS": "2"})
            sandbox.run.assert_called_once_with(["patch", "-p1"], {"JOBS": "2"}, check=True)
        with unittest.mock.patch.object(base, "run") as run:
            base.run_tool("patch", "-p1")
            run.assert_called_once_with("patch", "-p1", env=None)
            run.reset_mock()
            base.run_tool("patch", env={"JOBS": "2"})
            self.assertEqual(run.call_args.kwargs["env"]["JOBS"], "2")
            self.assertIn("PATH", run.call_args.kwargs["env"])

    @unittest.skipUnless(os.environ.get("ANTINOMIE_TOOLCHAIN_CHROOT"),
                         "set ANTINOMIE_TOOLCHAIN_CHROOT to a ready chroot directory")
    def test_a_real_chroot_compiles_with_debians_toolchain(self):
        chroot = base.toolchain_module()
        directory = Path(os.environ["ANTINOMIE_TOOLCHAIN_CHROOT"])
        self.assertTrue(chroot.ready(directory, base.CONTAINER_DOCKERFILE))
        with tempfile.TemporaryDirectory() as name:
            sandbox = chroot.Chroot(directory / "root", [(base.KIT, "/kit", False),
                                                         (Path(name), "/work", True)])
            base.SANDBOX = sandbox
            try:
                found = base.toolchain("minimal")
                self.assertEqual(found, base.debian_toolchain())
                sandbox.run(["sh", "-c", "echo ok > /work/probe"], check=True)
                self.assertEqual((Path(name) / "probe").read_text(), "ok\n")
                # /kit is read-only in the chroot.
                self.assertNotEqual(sandbox.run(["touch", "/kit/x"], capture_output=True).returncode, 0)
            finally:
                base.SANDBOX = None


if __name__ == "__main__":
    unittest.main()
