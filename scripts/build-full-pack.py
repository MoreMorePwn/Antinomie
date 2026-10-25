#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build the Antinomie full pack: every managed tool, pre-downloaded.

The managed tools, their pinned URLs and SHA-256 values are read from the
registry in monitor-core/src/analysis_tools.rs (the single source of truth the
app itself installs from). Each download is fetched (or taken from --cache),
checked for size and SHA-256, and unpacked with the same rules as the app's
installer into tools/<id>/, with the tool.json the app reads as "installed".
Sigma, which the app installs into a virtual environment, is carried as
hash-checked wheels that install-full-pack.py turns into that environment.

    usage: scripts/build-full-pack.py --output DIR [--version X.Y.Z] [options]

The pack is built by the person who uses it; Antinomie does not publish one.
Nothing is uploaded. See docs/full-pack.md.
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

REPO = Path(__file__).resolve().parent.parent
REGISTRY = REPO / "src/antinomie/monitor/crates/monitor-core/src/analysis_tools.rs"
CARGO = REPO / "src/antinomie/monitor/Cargo.toml"
HERE = Path(__file__).resolve().parent / "full-pack"

# Keep the archive under 2 GiB so it fits common file-size limits.
DEFAULT_MAX_ARCHIVE = 2_000_000_000
DEFAULT_MAX_UNPACKED = 6 * 1024**3
DEFAULT_SIGMA_PYTHONS = "3.11,3.12,3.13"
LICENSE_NAME = re.compile(r"(?i)^(licen[cs]e|copying|notice|copyright|unlicense)([._-].*)?$")


class PackError(Exception):
    pass


# --------------------------------------------------------------------------
# The registry: a small reader for the Rust source of the managed tools.


def rust_string(raw):
    """Value of a Rust string literal body (escapes and line continuations)."""
    out, i = [], 0
    while i < len(raw):
        c = raw[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        n = raw[i]
        if n == "\n":
            i += 1
            while i < len(raw) and raw[i] in " \t\n":
                i += 1
            continue
        out.append({"n": "\n", "t": "\t", "\\": "\\", '"': '"'}.get(n, n))
        i += 1
    return "".join(out)


def strip_comments(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//"))


def match_close(text, start, open_ch, close_ch):
    """Index of the bracket closing the one at text[start], skipping strings."""
    depth, i = 0, start
    while i < len(text):
        c = text[i]
        if c == '"':
            i += 1
            while text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise PackError("registry: unbalanced brackets")


def blocks(text, name):
    """Bodies of every `name { ... }` at the top level of `text`."""
    found, i = [], 0
    pattern = re.compile(r"\b" + re.escape(name) + r"\s*\{")
    while True:
        m = pattern.search(text, i)
        if not m:
            return found
        end = match_close(text, m.end() - 1, "{", "}")
        found.append(text[m.end():end])
        i = end + 1


def field(text, key, kind="str", required=True):
    if kind == "str":
        m = re.search(r"\b" + key + r':\s*"((?:[^"\\]|\\.)*)"', text, re.S)
        value = rust_string(m.group(1)) if m else None
    else:
        m = re.search(r"\b" + key + r":\s*([0-9_]+)", text)
        value = int(m.group(1).replace("_", "")) if m else None
    if value is None and required:
        raise PackError(f"registry: field {key} missing")
    return value


def parse_archive(text):
    m = re.search(r"archive:\s*Archive::(\w+)", text)
    if not m:
        raise PackError("registry: download without an archive kind")
    kind = m.group(1)
    rest = text[m.end():]
    if kind in ("Zip", "TarGz", "TarXz"):
        strip = re.match(r"\s*\{\s*strip:\s*(\d+)", rest)
        return {"kind": kind, "strip": int(strip.group(1)) if strip else 0}
    if kind == "DebFiles":
        return {"kind": kind, "prefix": field(rest, "prefix")}
    if kind == "File":
        return {"kind": kind}
    raise PackError(f"registry: unknown archive kind {kind}")


def parse_registry(path):
    source = strip_comments(Path(path).read_text())
    m = re.search(r"pub const PACKAGES:\s*&\[Package\]\s*=\s*&\[", source)
    if not m:
        raise PackError("registry: PACKAGES not found")
    array = source[m.end() - 1:match_close(source, m.end() - 1, "[", "]") + 1]
    packages = []
    for body in blocks(array, "Package"):
        d = body.index("downloads:")
        open_at = body.index("[", d)
        close_at = match_close(body, open_at, "[", "]")
        downloads = []
        for block in blocks(body[open_at:close_at + 1], "Download"):
            downloads.append({
                "file": field(block, "file"), "url": field(block, "url"),
                "sha256": field(block, "sha256"), "size": field(block, "size", "int"),
                "archive": parse_archive(block), "into": field(block, "into"),
            })
        rest = body[:d] + body[close_at + 1:]
        requirements = None
        if "requirements: Some(" in rest:
            r = rest[rest.index("requirements: Some("):]
            lock = re.search(r'include_str!\(\s*"([^"]+)"\s*\)', r)
            requirements = {"lock": lock.group(1), "size": field(r, "size", "int"),
                            "check": field(r, "check")}
        package = {
            "id": field(rest, "id"), "name": field(rest, "name"),
            "version": field(rest, "version"), "license": field(rest, "license"),
            "entry": field(rest, "entry"), "downloads": downloads,
            "requirements": requirements,
        }
        for key in ("sha256",):
            for download in downloads:
                if not re.fullmatch(r"[0-9a-f]{64}", download[key]):
                    raise PackError(f"registry: {package['id']}: bad SHA-256")
        packages.append(package)
    if not packages:
        raise PackError("registry: no packages")
    ids = [p["id"] for p in packages]
    if len(set(ids)) != len(ids):
        raise PackError("registry: duplicate tool ids")
    return packages


# --------------------------------------------------------------------------
# Fetching and verifying.


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verified(path, download):
    return (path.is_file() and path.stat().st_size == download["size"]
            and sha256_file(path) == download["sha256"])


def fetch(download, cache, network):
    """The verified file for a download: from the cache, else from its URL."""
    target = cache / download["file"]
    if verified(target, download):
        return target
    if target.exists():
        target.unlink()
    if not network:
        raise PackError(f"{download['file']}: not in the cache and downloads are off")
    if not download["url"].startswith("https://"):
        raise PackError(f"{download['file']}: refusing a non-HTTPS URL")
    part = cache / (download["file"] + ".part")
    print(f"  fetching {download['file']} ({download['size']:,} octets)", flush=True)
    result = subprocess.run(
        ["curl", "--fail", "--location", "--silent", "--show-error", "--proto", "=https",
         "--tlsv1.2", "--retry", "3", "--output", str(part), download["url"]])
    if result.returncode != 0:
        part.unlink(missing_ok=True)
        raise PackError(f"download failed: {download['url']}")
    if not verified(part, download):
        got = sha256_file(part) if part.exists() else "-"
        part.unlink(missing_ok=True)
        raise PackError(f"{download['file']} failed its size/SHA-256 check "
                        f"(expected {download['sha256']}, got {got}); nothing was packed")
    part.rename(target)
    return target


# --------------------------------------------------------------------------
# Unpacking, with the app's rules (analysis_tools.rs: inside, safe_link, unpack_*).


def inside(name, strip):
    parts = []
    for part in PurePosixPath(name).parts:
        if part == "/" or part == "..":
            raise PackError(f"archive path escapes its directory: {name}")
        if part != ".":
            parts.append(part)
    if len(parts) <= strip:
        return None
    return Path(*parts[strip:])


def safe_link(link, target):
    target = Path(target)
    if target.is_absolute():
        return False
    depth = len(Path(link).parts) - 1
    for part in target.parts:
        if part == "..":
            depth -= 1
        elif part != ".":
            depth += 1
        if depth < 0:
            return False
    return True


def write_file(path, data_source, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as out:
        shutil.copyfileobj(data_source, out)
    os.chmod(path, (mode & 0o755) | 0o400)


def unpack_zip(archive, target, strip):
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            relative = inside(info.filename, strip)
            if relative is None:
                continue
            path = target / relative
            if info.is_dir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            mode = (info.external_attr >> 16) or 0o644
            if stat.S_ISLNK(mode):
                link = z.read(info).decode()
                if safe_link(relative, link):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    os.symlink(link, path)
                continue
            with z.open(info) as source:
                write_file(path, source, mode)


def unpack_tar_stream(fileobj, target, place, mode="r|*"):
    with tarfile.open(fileobj=fileobj, mode=mode) as tar:
        for member in tar:
            relative = place(member.name)
            if relative is None:
                continue
            path = target / relative
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.issym():
                if safe_link(relative, member.linkname):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if path.is_symlink() or path.exists():
                        path.unlink()
                    os.symlink(member.linkname, path)
            elif member.isreg():
                write_file(path, tar.extractfile(member), member.mode)
            # Hard links, devices and the like are skipped, as the app does.


def deb_members(path):
    """(name, bytes) for each member of a Debian package (an ar archive)."""
    data = Path(path).read_bytes()
    if data[:8] != b"!<arch>\n":
        raise PackError("not a Debian package")
    i = 8
    while i + 60 <= len(data):
        name = data[i:i + 16].decode().strip().rstrip("/")
        size = int(data[i + 48:i + 58].decode().strip())
        yield name, data[i + 60:i + 60 + size]
        i += 60 + size + size % 2


def deb_data(path):
    for name, body in deb_members(path):
        if name == "data.tar.xz":
            return body
    raise PackError("Debian package has no data.tar.xz")


def unpack(download, archive, target):
    target = target / download["into"]
    target.mkdir(parents=True, exist_ok=True)
    spec = download["archive"]
    kind = spec["kind"]
    if kind == "Zip":
        unpack_zip(archive, target, spec["strip"])
    elif kind in ("TarGz", "TarXz"):
        with open(archive, "rb") as f:
            unpack_tar_stream(f, target, lambda n: inside(n, spec["strip"]),
                              "r|gz" if kind == "TarGz" else "r|xz")
    elif kind == "File":
        path = target / download["file"]
        shutil.copyfile(archive, path)
        os.chmod(path, 0o444)
    elif kind == "DebFiles":
        prefix = spec["prefix"]

        def place(name):
            return Path(name).name if name.startswith(prefix) and Path(name).name else None
        unpack_tar_stream(io.BytesIO(deb_data(archive)), target, place, "r|xz")
    else:
        raise PackError(f"unknown archive kind {kind}")


def deb_copyright(archive):
    """The Debian copyright file of a package, or None."""
    with tarfile.open(fileobj=io.BytesIO(deb_data(archive)), mode="r|xz") as tar:
        for member in tar:
            if member.isfile() and re.search(r"(^|/)usr/share/doc/[^/]+/copyright$", member.name):
                return tar.extractfile(member).read()
    return None


# --------------------------------------------------------------------------
# Licences.


def licence_files(root):
    """Recognisable licence/notice files in an unpacked tool, relative to root."""
    found = []
    for directory, _, names in os.walk(root):
        for name in names:
            if LICENSE_NAME.match(name):
                found.append(str(Path(directory, name).relative_to(root)))
    return sorted(found)


def wheel_licences(wheel):
    with zipfile.ZipFile(wheel) as z:
        return sorted(n for n in z.namelist() if ".dist-info/" in n
                      and LICENSE_NAME.match(Path(n).name))


# --------------------------------------------------------------------------
# Sigma wheels.


def parse_lock(text):
    """{name-version: {sha256, ...}} from a hash-locked requirements file."""
    lines = [l for l in text.splitlines() if not l.lstrip().startswith("#")]
    joined = "\n".join(lines).replace("\\\n", " ")
    locked = {}
    for line in joined.splitlines():
        m = re.match(r"\s*([A-Za-z0-9_.\-]+)==(\S+)\s*(.*)", line)
        if m:
            hashes = set(re.findall(r"--hash=sha256:([0-9a-f]{64})", m.group(3)))
            if not hashes:
                raise PackError(f"lock: {m.group(1)} has no hash")
            locked[(m.group(1), m.group(2))] = hashes
    if not locked:
        raise PackError("lock: no requirements")
    return locked


def fetch_wheels(package, lock_path, out, pythons, network, find_links, pip):
    lock_text = Path(lock_path).read_text()
    locked = parse_lock(lock_text)
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(lock_path, out / "requirements.txt")
    all_hashes = set().union(*locked.values())
    for python in pythons:
        tag = "cp" + python.replace(".", "")
        command = pip + [
            "download", "--disable-pip-version-check", "--no-input", "--require-hashes",
            "--only-binary=:all:", "--no-deps", "--dest", str(out),
            "--python-version", python, "--implementation", "cp", "--abi", tag,
            "--platform", "manylinux2014_x86_64", "--platform", "manylinux_2_17_x86_64",
            "--platform", "manylinux_2_28_x86_64", "--platform", "any",
            "-r", str(out / "requirements.txt")]
        if not network:
            command += ["--no-index", "--find-links", str(find_links)]
        print(f"  sigma wheels for Python {python}", flush=True)
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if result.returncode != 0:
            raise PackError(f"pip download failed for Python {python}:\n{result.stdout[-1500:]}")
    wheels = sorted(out.glob("*.whl"))
    for wheel in wheels:
        if sha256_file(wheel) not in all_hashes:
            raise PackError(f"{wheel.name} is not a wheel the lock names")
    names = {(re.sub(r"[-_.]+", "-", n).lower(), v) for n, v in locked}
    got = set()
    for wheel in wheels:
        parts = wheel.name.split("-")
        got.add((re.sub(r"[-_.]+", "-", parts[0]).lower(), parts[1]))
    if names - got:
        raise PackError(f"sigma: wheels missing for {sorted(names - got)}")
    return wheels


# --------------------------------------------------------------------------
# The pack.


def tree_digest(root):
    """SHA-256 over sorted (path, kind, mode, content hash) entries of a tree."""
    h = hashlib.sha256()
    total = 0
    files = []
    for directory, dirs, names in os.walk(root):
        dirs.sort()
        for name in sorted(names):
            path = Path(directory, name)
            rel = str(path.relative_to(root))
            if path.is_symlink():
                h.update(f"L {rel} {os.readlink(path)}\n".encode())
                files.append((rel, None))
            else:
                digest = sha256_file(path)
                size = path.stat().st_size
                total += size
                h.update(f"F {rel} {path.stat().st_mode & 0o777:o} {digest}\n".encode())
                files.append((rel, digest))
    return h.hexdigest(), total, files


def cargo_version():
    m = re.search(r'(?ms)^\[workspace\.package\]\s*\n(.*?)(?=^\[|\Z)', CARGO.read_text())
    v = re.search(r'^version\s*=\s*"(\d+\.\d+\.\d+)"', m.group(1), re.M) if m else None
    if not v:
        raise PackError("cannot read the workspace version; pass --version")
    return v.group(1)


def git(*args):
    r = subprocess.run(["git", "-C", str(REPO), *args], stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def notices(version, rows, excluded, registry_commit):
    out = [f"# Antinomie {version} full pack: third-party notices\n",
           "This pack holds unmodified, SHA-256-pinned releases of the tools below, "
           "downloaded from their upstream hosts by the person who built it and laid "
           "out the way Antinomie installs them. Whoever passes the pack on to others "
           "redistributes these tools and must meet their licences. Each tool keeps its own "
           "licence; the licence files that arrive with a tool are inside its folder "
           "under `tools/<id>/`, and any licence text the upstream download does not "
           "carry is in `licenses/<id>/`. The application's own notices are in "
           "THIRD-PARTY-NOTICES.md of the application archive.\n",
           "Antinomie itself is GPL-3.0-only (LICENSE); the tools are separate "
           "programs, run as separate processes, and are not part of that licence.\n",
           f"Registry source: `src/antinomie/monitor/crates/monitor-core/src/analysis_tools.rs`"
           f" at {registry_commit or 'an unrecorded commit'}.\n",
           "| Tool | Version | Licence (as the registry states it) | Pinned download(s) and SHA-256 | Source and obligations |",
           "|---|---|---|---|---|"]
    for row in rows:
        downloads = "<br>".join(f"`{d['file']}` `{d['sha256']}`" for d in row["downloads"])
        if not downloads:
            downloads = "hash-locked wheels (`wheels/sigma/requirements.txt`)"
        out.append(f"| {row['name']} | {row['version']} | {row['license']} | {downloads} | "
                   f"{row['policy'].get('source', '')} {row['policy'].get('obligations', '')} |")
    out.append("")
    if excluded:
        out.append("## Left out of this pack\n")
        for e in excluded:
            out.append(f"* **{e['name']}** ({e['id']}): {e['policy'].get('notes', 'redistribution not allowed')}. "
                       "The app downloads it on request as usual.")
        out.append("")
    out.append("## Source code for copyleft components\n")
    out.append("Components licensed under the GPL, LGPL or similar (GDB inside the pwndbg "
               "portable build, UPX, the Temurin JDK, Tor, Qt and ICU in Detect It Easy, "
               "libfuse, pySigma and its backend, and others) are included unmodified. "
               "Their corresponding source is available from the upstream locations in the "
               "table above. Whoever passes this pack on must make that source available "
               "as those licences require; the Antinomie project does not distribute "
               "this pack and makes no source offer for it.\n")
    return "\n".join(out)


README = """Antinomie {version} full pack (Linux x86-64)

This archive holds every tool Antinomie can install itself ({names}),
already downloaded, SHA-256 checked and laid out for the app. Installing it
means Tools > Analysis tools finds them installed and nothing is downloaded on
first use.

    sha256sum --check SHA256SUMS-full-pack     # next to the archive
    tar -xf antinomie-{version}-full-pack-linux-x86_64.tar.{ext}
    cd antinomie-{version}-full-pack
    ./install-full-pack.sh                     # into ~/antinomie/tools
    ./install-full-pack.sh --data-dir DIR      # another data folder
    ./install-full-pack.sh --list              # what it holds, nothing changed

The installer verifies every file against SHA256SUMS first, installs each tool
beside the existing ones with a rename (a tool already installed at the same
version is left alone; --force reinstalls), and builds the Sigma environment
from the bundled wheels with the system Python 3.11 or newer (python3-venv),
offline. It never touches bases, VMs or recordings, and never downloads.

This pack does not replace the application archive: install that first.
It does not hold bases, detection-rule packs or IOC datasets, which are
downloaded on request. Licences: THIRD-PARTY-NOTICES-FULL-PACK.md, licenses/
and each tool's own folder. A tool installed on the system still takes
precedence over the pack's copy.
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--output", required=True, help="directory for the archive and manifest")
    ap.add_argument("--version", help="application version (default: the workspace version)")
    ap.add_argument("--registry", default=str(REGISTRY), help="analysis_tools.rs to read")
    ap.add_argument("--policy", default=str(HERE / "policy.json"))
    ap.add_argument("--licenses", default=str(HERE / "licenses"))
    ap.add_argument("--cache", help="download cache (default: OUTPUT/.full-pack-cache)")
    ap.add_argument("--no-network", action="store_true", help="never download; use the cache only")
    ap.add_argument("--only", help="comma-separated tool ids (testing only)")
    ap.add_argument("--sigma-python", default=DEFAULT_SIGMA_PYTHONS,
                    help="Python versions to carry Sigma wheels for")
    ap.add_argument("--pip", default=f"{sys.executable} -m pip", help="pip command")
    ap.add_argument("--compress", choices=["xz", "gz"], default="xz")
    ap.add_argument("--max-archive-bytes", type=int, default=DEFAULT_MAX_ARCHIVE)
    ap.add_argument("--max-unpacked-bytes", type=int, default=DEFAULT_MAX_UNPACKED)
    ap.add_argument("--epoch", type=int, help="member mtime (default: commit time)")
    args = ap.parse_args(argv)

    version = args.version or cargo_version()
    packages = parse_registry(args.registry)
    policy = json.loads(Path(args.policy).read_text())
    if args.only:
        wanted = set(args.only.split(","))
        packages = [p for p in packages if p["id"] in wanted]
    unknown = [p["id"] for p in packages if p["id"] not in policy["tools"]]
    if unknown:
        raise PackError(f"no redistribution decision in {args.policy} for: {', '.join(unknown)}")
    included = [p for p in packages if policy["tools"][p["id"]]["redistribute"]]
    excluded = [{"id": p["id"], "name": p["name"], "policy": policy["tools"][p["id"]]}
                for p in packages if not policy["tools"][p["id"]]["redistribute"]]

    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    cache = Path(args.cache).resolve() if args.cache else out / ".full-pack-cache"
    cache.mkdir(parents=True, exist_ok=True)
    network = not args.no_network
    name = f"antinomie-{version}-full-pack"
    expected = sum(d["size"] for p in included for d in p["downloads"]) + sum(
        p["requirements"]["size"] for p in included if p["requirements"])
    print(f"{name}: {len(included)} tools, {expected:,} octets of pinned downloads")
    for e in excluded:
        print(f"  left out: {e['id']} ({e['policy'].get('notes', '')})")
    free = shutil.disk_usage(out).free
    if free < 3 * expected + (1 << 30):
        raise PackError(f"{out} has {free:,} octets free; a build needs about {3 * expected + (1 << 30):,}")

    work = Path(tempfile.mkdtemp(prefix=".full-pack-work-", dir=out))
    try:
        stage = work / name
        tools = stage / "tools"
        tools.mkdir(parents=True)
        (stage / "licenses").mkdir()
        rows = []
        for package in included:
            print(f"* {package['id']} {package['version']}", flush=True)
            pol = policy["tools"][package["id"]]
            row = dict(package, policy=pol, licence_files=[], copyright_files=[])
            licences_out = stage / "licenses" / package["id"]
            supplied = Path(args.licenses) / package["id"]
            if supplied.is_dir():
                shutil.copytree(supplied, licences_out)
            if package["requirements"]:
                lock = Path(args.registry).parent / package["requirements"]["lock"]
                wheels = fetch_wheels(package, lock, stage / "wheels" / package["id"],
                                      args.sigma_python.split(","), network, cache, args.pip.split())
                row["wheels"] = [w.name for w in wheels]
                row["licence_files"] = sorted({f"{w.name}:{n}" for w in wheels for n in wheel_licences(w)})
                row["sigma_pythons"] = args.sigma_python.split(",")
                if not row["licence_files"] and not supplied.is_dir():
                    print(f"  warning: no licence files found in the {package['id']} wheels")
            else:
                directory = tools / package["id"]
                directory.mkdir()
                for download in package["downloads"]:
                    archive = fetch(download, cache, network)
                    unpack(download, archive, directory)
                    if download["archive"]["kind"] == "DebFiles":
                        text = deb_copyright(archive)
                        if text:
                            licences_out.mkdir(parents=True, exist_ok=True)
                            (licences_out / (download["file"] + ".copyright")).write_bytes(text)
                            row["copyright_files"].append(download["file"] + ".copyright")
                if not (directory / package["entry"]).exists():
                    raise PackError(f"{package['id']}: {package['entry']} is missing after unpacking")
                (directory / "tool.json").write_text(json.dumps(
                    {"id": package["id"], "version": package["version"]}, indent=2))
                row["licence_files"] = licence_files(directory)
                if not (row["licence_files"] or row["copyright_files"] or supplied.is_dir()):
                    raise PackError(
                        f"{package['id']}: no licence file in the download and none supplied in "
                        f"{args.licenses}/{package['id']}; refusing to redistribute it")
                digest, size, _ = tree_digest(directory)
                row["tree_sha256"], row["unpacked_bytes"] = digest, size
            rows.append(row)

        unpacked = sum(r.get("unpacked_bytes", 0) for r in rows)
        if unpacked > args.max_unpacked_bytes:
            raise PackError(f"unpacked size {unpacked:,} exceeds the budget {args.max_unpacked_bytes:,}")

        if (Path(args.licenses) / "Apache-2.0.txt").is_file():
            shutil.copyfile(Path(args.licenses) / "Apache-2.0.txt", stage / "licenses/Apache-2.0.txt")
        commit = git("rev-parse", "HEAD")
        (stage / "THIRD-PARTY-NOTICES-FULL-PACK.md").write_text(notices(version, rows, excluded, commit))
        names = ", ".join(r["name"] for r in rows)
        (stage / "README.txt").write_text(README.format(version=version, names=names, ext=args.compress))
        shutil.copyfile(HERE / "install-full-pack.py", stage / "install-full-pack.py")
        os.chmod(stage / "install-full-pack.py", 0o755)
        (stage / "install-full-pack.sh").write_text(
            '#!/usr/bin/env bash\nexec python3 -I "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/install-full-pack.py" "$@"\n')
        os.chmod(stage / "install-full-pack.sh", 0o755)

        manifest = {
            "name": name, "version": version, "source_commit": commit,
            "source_dirty": bool(git("status", "--porcelain")),
            "tools": [{
                "id": r["id"], "name": r["name"], "version": r["version"], "license": r["license"],
                "entry": r["entry"], "kind": "wheels" if r["requirements"] else "tree",
                "check": r["requirements"]["check"] if r["requirements"] else None,
                "downloads": [{k: d[k] for k in ("file", "url", "sha256", "size")} for d in r["downloads"]],
                "tree_sha256": r.get("tree_sha256"), "unpacked_bytes": r.get("unpacked_bytes"),
                "licence_files": r["licence_files"], "copyright_files": r["copyright_files"],
                "sigma_pythons": r.get("sigma_pythons"),
            } for r in rows],
            "left_out": [{"id": e["id"], "name": e["name"], "reason": e["policy"].get("notes", "")}
                         for e in excluded],
            "expected_download_bytes": expected, "unpacked_bytes": unpacked,
            "budget": {"max_archive_bytes": args.max_archive_bytes,
                       "max_unpacked_bytes": args.max_unpacked_bytes},
        }
        (stage / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

        # SHA256SUMS of every regular file, so `sha256sum --check` verifies a tree.
        sums = []
        for directory, dirs, files in os.walk(stage):
            dirs.sort()
            for f in sorted(files):
                path = Path(directory, f)
                if path.is_symlink() or f == "SHA256SUMS":
                    continue
                sums.append(f"{sha256_file(path)}  {path.relative_to(stage)}")
        (stage / "SHA256SUMS").write_text("\n".join(sorted(sums, key=lambda l: l[66:])) + "\n")

        epoch = args.epoch if args.epoch is not None else int(git("log", "-1", "--format=%ct") or 0)
        archive = out / f"{name}-linux-x86_64.tar.{args.compress}"
        compressor = ["xz", "-T0", "-6", "-c"] if args.compress == "xz" else ["gzip", "-n", "-c"]
        print(f"packing {archive.name}", flush=True)
        with open(archive, "wb") as sink:
            tar = subprocess.Popen(
                ["tar", "-C", str(work), "--sort=name", "--owner=0", "--group=0", "--numeric-owner",
                 f"--mtime=@{epoch}", "-cf", "-", name], stdout=subprocess.PIPE)
            comp = subprocess.Popen(compressor, stdin=tar.stdout, stdout=sink)
            tar.stdout.close()
            if comp.wait() != 0 or tar.wait() != 0:
                raise PackError("packing failed")
        size = archive.stat().st_size
        digest = sha256_file(archive)
        (out / "SHA256SUMS-full-pack").write_text(f"{digest}  {archive.name}\n")
        full = dict(manifest, archive={"file": archive.name, "bytes": size, "sha256": digest})
        (out / f"{name}.manifest.json").write_text(json.dumps(full, indent=2, sort_keys=True) + "\n")
        print(f"{archive.name}: {size:,} octets ({size / 2**30:.2f} GiB), "
              f"{unpacked:,} unpacked; budget {args.max_archive_bytes:,}")
        if size > args.max_archive_bytes:
            raise PackError(f"archive {size:,} exceeds the size budget {args.max_archive_bytes:,} "
                            "(the archive must stay under 2 GiB)")
        print((out / "SHA256SUMS-full-pack").read_text().strip())
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except PackError as error:
        print(f"build-full-pack: {error}", file=sys.stderr)
        sys.exit(1)
