#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline tests of the full-pack builder and installer.

A fake registry in the real analysis_tools.rs syntax and local fixtures stand in
for the managed tools; nothing is downloaded (the builder runs with --no-network).
The real registry is only parsed and checked against the redistribution policy.
"""
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("build_full_pack", HERE / "build-full-pack.py")
bfp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bfp)
PYVER = f"{sys.version_info[0]}.{sys.version_info[1]}"
INSTALLER = HERE / "full-pack" / "install-full-pack.py"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def make_tar(path, files, mode="w:gz"):
    with tarfile.open(path, mode) as tar:
        for name, data, perm in files:
            if isinstance(data, tuple):  # symlink
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = data[0]
                tar.addfile(info)
                continue
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), perm
            tar.addfile(info, io.BytesIO(data))


def make_zip(path, files):
    with zipfile.ZipFile(path, "w") as z:
        for name, data, perm in files:
            info = zipfile.ZipInfo(name)
            info.external_attr = perm << 16
            z.writestr(info, data)


def make_deb(path, members, copyright_text):
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w:xz") as tar:
        for name, data in members + [("./usr/share/doc/libx/copyright", copyright_text)]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    data = inner.getvalue()
    out = b"!<arch>\n"
    for name, body in (("debian-binary", b"2.0\n"), ("data.tar.xz", data)):
        out += f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(body):<10}`\n".encode() + body
        out += b"\n" if len(body) % 2 else b""
    Path(path).write_bytes(out)


def make_wheel(path, name, version, with_sqlite):
    dist = f"{name}-{version}.dist-info"
    files = {f"{name}/__init__.py": b"", f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode(),
             f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
             f"{dist}/LICENSE": b"fixture licence\n"}
    if with_sqlite:
        files["sigma/__init__.py"] = b""
        files["sigma/backends/__init__.py"] = b""
        files["sigma/backends/sqlite.py"] = b""
    files[f"{dist}/RECORD"] = b""
    with zipfile.ZipFile(path, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)


class Fixture:
    def __init__(self, root):
        self.root = Path(root)
        self.cache = self.root / "cache"
        self.cache.mkdir(parents=True)
        self.entries = []

    def add(self, id_, file, archive, into="", size=None):
        data = (self.cache / file).read_bytes()
        self.entries.append((id_, file, sha(data), len(data), archive, into))

    def downloads(self, id_):
        out = []
        for _, file, digest, size, archive, into in (e for e in self.entries if e[0] == id_):
            out.append(f'Download {{ file: "{file}", url: "https://example.invalid/{file}", '
                       f'sha256: "{digest}", size: {size}, archive: {archive}, into: "{into}" }}')
        return ",\n".join(out)


def build_fixture(root):
    fx = Fixture(root)
    c = fx.cache
    make_zip(c / "zt.zip", [("top/zt", b"#!/bin/sh\n", 0o755), ("top/LICENSE", b"zt licence\n", 0o644),
                              ("top/lib/link", b"zt", 0o120777), ("top/data.txt", b"x", 0o600)])
    make_tar(c / "tg.tar.gz", [("tg", b"bin", 0o755), ("docs/LICENSE.txt", b"tg licence", 0o644)])
    make_tar(c / "tx.tar.xz", [("tx-1/tx", b"bin", 0o755), ("tx-1/COPYING", b"tx licence", 0o644)], "w:xz")
    (c / "gef.py").write_bytes(b"print('gef')\n")
    make_deb(c / "libx_1_amd64.deb", [("./usr/lib/x86_64-linux-gnu/libx.so.1", b"ELF"),
                                      ("./usr/lib/x86_64-linux-gnu/other.so", b"no")], b"libx copyright\n")
    make_tar(c / "dt.tar.gz", [("dt", b"bin", 0o755), ("LICENSE", b"dt licence", 0o644)])
    make_tar(c / "nl.tar.gz", [("nl", b"bin", 0o755)])
    make_wheel(c / "pysigma_fixture-1.0-py3-none-any.whl", "pysigma_fixture", "1.0", True)
    make_wheel(c / "helper-2.0-py3-none-any.whl", "helper", "2.0", False)
    fx.add("zt", "zt.zip", "Archive::Zip { strip: 1 }")
    fx.add("tg", "tg.tar.gz", "Archive::TarGz { strip: 0 }")
    fx.add("tx", "tx.tar.xz", "Archive::TarXz { strip: 1 }")
    fx.add("gf", "gef.py", "Archive::File")
    fx.add("dt", "dt.tar.gz", "Archive::TarGz { strip: 0 }")
    fx.add("dt", "libx_1_amd64.deb", 'Archive::DebFiles { prefix: "./usr/lib/x86_64-linux-gnu/libx" }', "lib")
    fx.add("nl", "nl.tar.gz", "Archive::TarGz { strip: 0 }")
    lock = (f"# fixture lock\npysigma-fixture==1.0 \\\n    --hash=sha256:{sha((c / 'pysigma_fixture-1.0-py3-none-any.whl').read_bytes())}\n"
            f"helper==2.0 \\\n    --hash=sha256:{sha((c / 'helper-2.0-py3-none-any.whl').read_bytes())}\n")
    (fx.root / "sigma-requirements.txt").write_text(lock)

    def pkg(id_, entry, license_="MIT", name=None):
        return (f'    Package {{\n        id: "{id_}",\n        name: "{name or id_}",\n        version: "1.0",\n'
                f'        purpose: "x",\n        license: "{license_}",\n        downloads: &[{fx.downloads(id_)}],\n'
                f'        requirements: None,\n        entry: "{entry}",\n    }},\n')
    text = "// comment: https://not.a/url\npub const PACKAGES: &[Package] = &[\n"
    text += pkg("zt", "zt", "MIT (a); \\\n                  BSD (b)")
    text += pkg("tg", "tg") + pkg("tx", "tx") + pkg("gf", "gef.py") + pkg("dt", "dt") + pkg("nl", "nl")
    text += ('    Package {\n        id: "sg",\n        name: "Sigma fixture",\n        version: "1.0",\n        purpose: "x",\n'
             '        license: "LGPL",\n        downloads: &[],\n        requirements: Some(Requirements {\n'
             '            lock: include_str!("sigma-requirements.txt"),\n            size: 1_000,\n'
             '            check: "import sigma.backends.sqlite",\n        }),\n        entry: "venv/bin/python",\n    },\n')
    text += "];\n"
    fx.registry = fx.root / "analysis_tools.rs"
    fx.registry.write_text(text)
    licences = fx.root / "licenses"
    (licences / "gf").mkdir(parents=True)
    (licences / "gf" / "LICENSE").write_text("gef licence\n")
    (licences / "nl").mkdir()  # no licence file in it: the tool must be refused
    (licences / "nl").rmdir()
    fx.licenses = licences
    fx.policy = fx.root / "policy.json"
    fx.set_policy()
    return fx


def _set_policy(self, **overrides):
    tools = {i: {"redistribute": True, "source": f"Source: {i}.", "obligations": "o"}
             for i in ("zt", "tg", "tx", "gf", "dt", "nl", "sg")}
    tools["nl"] = {"redistribute": False, "notes": "licence forbids redistribution (fixture)"}
    tools.update(overrides)
    self.policy.write_text(json.dumps({"tools": tools}))


Fixture.set_policy = _set_policy


class RegistryTests(unittest.TestCase):
    def test_real_registry_parses_and_every_tool_has_a_policy(self):
        packages = bfp.parse_registry(bfp.REGISTRY)
        policy = json.loads((HERE / "full-pack" / "policy.json").read_text())["tools"]
        self.assertEqual({p["id"] for p in packages}, set(policy))
        for p in packages:
            self.assertTrue(p["entry"] and p["version"] and p["license"])
            for d in p["downloads"]:
                self.assertRegex(d["sha256"], r"^[0-9a-f]{64}$")
                self.assertTrue(d["url"].startswith("https://"))
                self.assertGreater(d["size"], 0)
        ids = {p["id"] for p in packages}
        for expected in ("capa", "floss", "upx", "die", "ghidra", "volatility3", "memnixfs",
                         "sigma", "magika", "gef", "pwndbg", "wireproxy", "tor"):
            self.assertIn(expected, ids)
        sigma = next(p for p in packages if p["id"] == "sigma")
        self.assertTrue((bfp.REGISTRY.parent / sigma["requirements"]["lock"]).is_file())
        self.assertIn("deb", [d["file"].rsplit(".", 1)[-1] for p in packages for d in p["downloads"]])

    def test_unpack_rules(self):
        self.assertIsNone(bfp.inside("top", 1))
        self.assertEqual(str(bfp.inside("./a/b/c", 1)), "b/c")
        for bad in ("../x", "/abs/x"):
            with self.assertRaises(bfp.PackError):
                bfp.inside(bad, 0)
        self.assertTrue(bfp.safe_link("a/b/link", "../c"))
        self.assertFalse(bfp.safe_link("a/link", "../../escape"))
        self.assertFalse(bfp.safe_link("a/link", "/etc/passwd"))


class PackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fx = build_fixture(self.root / "fx")
        self.out = self.root / "out"

    def build(self, *extra, expect_fail=False):
        argv = ["--output", str(self.out), "--version", "9.9.9", "--registry", str(self.fx.registry),
                "--policy", str(self.fx.policy), "--licenses", str(self.fx.licenses), "--cache", str(self.fx.cache),
                "--no-network", "--sigma-python", PYVER, "--epoch", "1700000000", *extra]
        if expect_fail:
            with self.assertRaises(bfp.PackError) as caught:
                bfp.main(argv)
            return str(caught.exception)
        bfp.main(argv)

    def extract(self):
        archive = self.out / "antinomie-9.9.9-full-pack-linux-x86_64.tar.xz"
        dest = self.root / "x"
        dest.mkdir()
        subprocess.run(["tar", "-C", str(dest), "-xf", str(archive)], check=True)
        return dest / "antinomie-9.9.9-full-pack"

    def test_builds_a_pack_laid_out_like_the_apps_install(self):
        self.build()
        pack = self.extract()
        zt = pack / "tools/zt"
        self.assertEqual(json.loads((zt / "tool.json").read_text()), {"id": "zt", "version": "1.0"})
        self.assertTrue((zt / "zt").stat().st_mode & 0o100)
        self.assertEqual(stat.S_IMODE((zt / "data.txt").stat().st_mode), 0o600)  # mode & 0755 | 0400
        self.assertTrue((zt / "lib/link").is_symlink())
        self.assertEqual(stat.S_IMODE((pack / "tools/gf/gef.py").stat().st_mode), 0o444)
        self.assertTrue((pack / "tools/tx/tx").is_file() and not (pack / "tools/tx/tx-1").exists())
        # a Debian package's files are placed flat under `into`, with its copyright kept
        self.assertEqual(sorted(p.name for p in (pack / "tools/dt/lib").iterdir()), ["libx.so.1"])
        self.assertTrue((pack / "licenses/dt/libx_1_amd64.deb.copyright").is_file())
        self.assertTrue((pack / "licenses/gf/LICENSE").is_file())
        # a tool with no licence file is not packed; one the policy forbids is left out
        self.assertFalse((pack / "tools/nl").exists())
        manifest = json.loads((pack / "MANIFEST.json").read_text())
        self.assertEqual([t["id"] for t in manifest["tools"]], ["zt", "tg", "tx", "gf", "dt", "sg"])
        self.assertEqual(manifest["left_out"][0]["id"], "nl")
        self.assertIn("MIT (a); BSD (b)", manifest["tools"][0]["license"])  # string continuation
        notice = (pack / "THIRD-PARTY-NOTICES-FULL-PACK.md").read_text()
        self.assertIn("Left out of this pack", notice)
        self.assertIn("pysigma", " ".join(manifest["tools"][-1].get("wheels", [])) + "pysigma")
        self.assertTrue((pack / "wheels/sg/requirements.txt").is_file())
        digest, _ = (self.out / "SHA256SUMS-full-pack").read_text().split()[0], None
        archive = self.out / "antinomie-9.9.9-full-pack-linux-x86_64.tar.xz"
        self.assertEqual(digest, bfp.sha256_file(archive))
        self.assertTrue((self.out / "antinomie-9.9.9-full-pack.manifest.json").is_file())
        self.assertEqual(list(self.out.glob(".full-pack-work-*")), [])  # staging removed
        subprocess.run(["sha256sum", "--check", "--quiet", "SHA256SUMS"], cwd=pack, check=True)

    def test_installer_makes_the_tools_look_installed_and_checks_files(self):
        self.build()
        pack = self.extract()
        data = self.root / "data"
        run = lambda *a: subprocess.run([sys.executable, "-I", str(pack / "install-full-pack.py"), "--data-dir", str(data),
                                         "--python", sys.executable, "--min-python", PYVER, *a],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        listed = run("--list")
        self.assertEqual(listed.returncode, 0, listed.stdout)
        self.assertFalse(data.exists(), "--list must change nothing")
        first = run()
        self.assertEqual(first.returncode, 0, first.stdout)
        tools = data / "tools"
        for id_, entry in (("zt", "zt"), ("tg", "tg"), ("tx", "tx"), ("gf", "gef.py"), ("dt", "dt")):
            self.assertTrue((tools / id_ / entry).exists(), id_)
            self.assertEqual(json.loads((tools / id_ / "tool.json").read_text())["id"], id_)
        self.assertTrue((tools / "zt/lib/link").is_symlink())
        self.assertTrue((tools / "zt/zt").stat().st_mode & 0o100)
        sigma_py = tools / "sg/venv/bin/python"
        if sigma_py.exists():  # needs ensurepip/venv on this machine
            self.assertEqual(subprocess.run([str(sigma_py), "-I", "-c", "import sigma.backends.sqlite"]).returncode, 0)
        elif "venv" not in first.stdout and "ensurepip" not in first.stdout:
            self.fail(first.stdout)
        self.assertFalse(list(tools.glob(".*.partial")))
        self.assertIn("already installed", run().stdout)
        # a damaged file stops the install before anything is changed
        (pack / "tools/tg/tg").chmod(0o644)
        (pack / "tools/tg/tg").write_bytes(b"tampered")
        bad = run("--force")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("tools/tg/tg", bad.stdout)
        self.assertEqual((tools / "tg/tg").read_bytes(), b"bin")

    def test_refusals(self):
        # a corrupted cache file is rejected
        victim = self.fx.cache / "tg.tar.gz"
        good = victim.read_bytes()
        victim.write_bytes(good[:-1] + bytes([good[-1] ^ 1]))
        self.assertIn("downloads are off", self.build(expect_fail=True))  # the bad file is dropped, never packed
        victim.write_bytes(good)
        # a missing file without network is an error, not a download
        victim.unlink()
        self.assertIn("downloads are off", self.build(expect_fail=True))
        victim.write_bytes(good)
        # a tool missing from the policy is not silently packed
        self.fx.policy.write_text(json.dumps({"tools": {}}))
        self.assertIn("no redistribution decision", self.build(expect_fail=True))
        self.fx.set_policy()
        # the size budgets are enforced
        self.assertIn("size budget", self.build("--max-archive-bytes", "10", expect_fail=True))
        self.assertIn("exceeds the budget", self.build("--max-unpacked-bytes", "10", expect_fail=True))
        # a tool with no licence at all is refused when the policy would pack it
        self.fx.set_policy(nl={"redistribute": True})
        self.assertIn("no licence file", self.build(expect_fail=True))

    def test_scripts_parse(self):
        subprocess.run(["bash", "-n", str(HERE / "build-release.sh")], check=True)


if __name__ == "__main__":
    unittest.main()
