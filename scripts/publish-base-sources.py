#!/usr/bin/env python3
"""Assemble the corresponding source of one Antinomie base for publication.

A published base holds GPL-2.0 programs (the patched Linux kernel, BusyBox, the
initrd's e2fsprogs) and Debian packages. This script gathers what a recipient
needs to rebuild or inspect them, as a directory tree that is uploaded next to
the base (hf://buckets/MoreMorePwn/antinomie-bases/sources/):

    debian/linux_<version>/        the Debian source package the kernel is built on
                                   (.dsc, .debian.tar.xz, .orig.tar.xz from snapshot.debian.org)
    kernels/linux-<version>-antinomie-r<revision>-<series>/
                                   the Antinomie patch series, the kernel build recipe
                                   and the series hash it must match
    userland/<source>_<version>/   the source package of each host program copied into the image
                                   (BusyBox, glibc, e2fsprogs, ...)
    bases/<identity>/              SOURCES.json (everything above, with SHA-256), the kernel's
                                   .config and, for a Debian base, the package inventory

    publish-base-sources.py --bundle DIR --output DIR [--repo ROOT] [--cache DIR]
                            [--packages FILE] [--identity HEX]

DIR is the base's bundle directory (bundle.json, kernel, and for Debian bases
provenance/packages.tsv). The kernel's Antinomie patch series is taken from ROOT
(default: this checkout) and must hash to the bundle's antinomie_source; to
publish an older base, check out the matching release in ROOT. --packages names
a JSON list of package records for a bundle built before bundle.json recorded
them. Downloads are checked against the SHA-256 in each package's .dsc.
--cache keeps downloaded files between runs. Existing files in --output are kept
when their hash matches. Nothing is uploaded; sync --output to the bucket.
"""
# SPDX-License-Identifier: GPL-3.0-only
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import time
import urllib.parse
import urllib.request

REPO = Path(__file__).resolve().parent.parent
SNAPSHOT = "https://snapshot.debian.org"
SCHEMA = 1
SERIES_DIR = "src/antinomie/core/6.12"
ADAPTER = "src/antinomie/packaging/debian-6.12.94-1-trixie"
# Kernel build recipe files, copied when the checkout has them.
RECIPE = ("scripts/build-monitor-kernel.sh", "scripts/build-base.py", "scripts/bootstrap.sh",
          "scripts/fetch-inputs.sh", "scripts/verify-inputs.sh", "scripts/commit.sh",
          ADAPTER + "/adapter.conf", ADAPTER + "/series.fence")
PACKAGE_FIELDS = ("package", "version", "architecture", "source_package", "source_version")
# Archives snapshot.debian.org lists; the debug mirrors hold the same files.
ARCHIVE_ORDER = ("debian", "debian-security", "debian-ports")


class SourceError(RuntimeError):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha1_file(path):
    digest = hashlib.sha1()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Snapshot:
    """snapshot.debian.org through its machine-readable API."""

    def __init__(self, base=SNAPSHOT, retries=3):
        self.base = base
        self.retries = retries

    def fetch(self, url, destination=None):
        last = None
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(url, timeout=120) as response:
                    if destination is None:
                        return response.read()
                    with Path(destination).open("wb") as target:
                        shutil.copyfileobj(response, target)
                    return None
            except OSError as error:
                last = error
                time.sleep(2 * (attempt + 1))
        raise SourceError(f"cannot fetch {url}: {last}")

    def source_files(self, source, version):
        """[(name, sha1, url, size)] of a source package version."""
        url = (f"{self.base}/mr/package/{urllib.parse.quote(source, safe='')}/"
               f"{urllib.parse.quote(version, safe='')}/srcfiles?fileinfo=1")
        data = json.loads(self.fetch(url))
        files = []
        for entry in data["result"]:
            sha1 = entry["hash"]
            choices = [item for item in data["fileinfo"][sha1] if item["archive_name"] in ARCHIVE_ORDER]
            if not choices:
                raise SourceError(f"{source} {version}: no archive copy of {sha1}")
            choices.sort(key=lambda item: (ARCHIVE_ORDER.index(item["archive_name"]), item["first_seen"]))
            item = choices[0]
            files.append((item["name"], sha1, f"{self.base}/archive/{item['archive_name']}/"
                          f"{item['first_seen']}{item['path']}/{item['name']}", item["size"]))
        if not files:
            raise SourceError(f"{source} {version} is not on snapshot.debian.org")
        return files


def dsc_checksums(text):
    """{file name: (sha256, size)} from the Checksums-Sha256 field of a .dsc."""
    block = re.search(r"^Checksums-Sha256:\s*\n((?: .*\n?)+)", text, re.M)
    if not block:
        raise SourceError(".dsc has no Checksums-Sha256 field")
    result = {}
    for line in block[1].splitlines():
        digest, size, name = line.split()
        result[name] = (digest, int(size))
    return result


def fetch_source(snapshot, source, version, cache, pins=None):
    """Download a source package into the cache; return [(name, path)].

    The .dsc comes first: every other file must match its SHA-256 (and its
    snapshot SHA-1). pins maps a file name to a SHA-256 the caller already
    trusts (the repository's adapter for the kernel)."""
    files = snapshot.source_files(source, version)
    target = Path(cache) / f"{source}_{version.split(':')[-1]}"
    target.mkdir(parents=True, exist_ok=True)
    got = {}
    for name, sha1, url, size in sorted(files, key=lambda item: not item[0].endswith(".dsc")):
        path = target / name
        if not (path.is_file() and sha1_file(path) == sha1):
            snapshot.fetch(url, path)
            if sha1_file(path) != sha1:
                path.unlink()
                raise SourceError(f"{name}: SHA-1 differs from snapshot.debian.org's listing")
        got[name] = path
    dscs = [name for name in got if name.endswith(".dsc")]
    if len(dscs) != 1:
        raise SourceError(f"{source} {version}: expected one .dsc, found {dscs}")
    expected = dsc_checksums(got[dscs[0]].read_text(errors="replace"))
    for name, path in got.items():
        if name == dscs[0]:
            continue
        if name not in expected:
            raise SourceError(f"{name} is not listed in {dscs[0]}")
        if sha256_file(path) != expected[name][0] or path.stat().st_size != expected[name][1]:
            raise SourceError(f"{name} does not match the checksum in {dscs[0]}")
        if pins and name in pins and pins[name] != expected[name][0]:
            raise SourceError(f"{name} differs from the SHA-256 pinned by the repository")
    missing = set(expected) - set(got)
    if missing:
        raise SourceError(f"{source} {version}: files listed in the .dsc are missing: {sorted(missing)}")
    return sorted(got.items())


def adapter_values(root):
    values = {}
    for line in (Path(root) / ADAPTER / "adapter.conf").read_text().splitlines():
        match = re.fullmatch(r"([A-Z_]+)=(.*)", line)
        if match:
            values[match[1]] = match[2].strip("'\"")
    return values


def series_hash(series_dir):
    """The hash CONFIG_ANTINOMIE_SOURCE_ID carries: sha256 of `sha256sum -- *.patch`."""
    lines = "".join(f"{sha256_file(path)}  {path.name}\n"
                    for path in sorted(Path(series_dir).glob("*.patch"), key=lambda p: p.name))
    return hashlib.sha256(lines.encode()).hexdigest()


def copy_file(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    if not (target.is_file() and sha256_file(target) == sha256_file(source)):
        shutil.copy2(source, target)


def load_builder():
    spec = importlib.util.spec_from_file_location("build_monitor_image",
                                                  REPO / "scripts/build-monitor-image.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def kernel_record(bundle, bundle_dir):
    """The kernel source record: bundle.json's, else read from the kernel's own IKCONFIG."""
    record = (bundle.get("guest_sources") or {}).get("kernel")
    if record:
        return record, None
    config = load_builder().embedded_config(Path(bundle_dir) / bundle.get("kernel", "kernel"))
    match = re.search(rb'^CONFIG_ANTINOMIE_SOURCE_ID="([1-9][0-9]*):([0-9a-f]{64})"$', config, re.M)
    if not match:
        raise SourceError("the kernel has no Antinomie source id (a development kernel): "
                          "its source cannot be published")
    return ({"source_package": "linux", "source_version": None,
             "antinomie_revision": int(match[1]), "antinomie_source": match[2].decode()}, config)


def file_hash(bundle, bundle_dir, name):
    known = (bundle.get("sha256") or {}).get(name)
    if known:
        return known
    path = Path(bundle_dir) / name
    if not path.is_file():
        raise SourceError(f"cannot compute the base identity without {name}; pass --identity")
    return sha256_file(path)


def bundle_identity(bundle, bundle_dir):
    builder = load_builder()
    hashes = {}
    for key in ("kernel", "base_disk", "initrd"):
        name = bundle.get(key)
        if name:
            hashes[key] = file_hash(bundle, bundle_dir, name)
    if bundle.get("symbols"):
        hashes["symbols"] = file_hash(bundle, bundle_dir, bundle["symbols"])
    return builder.bundle_identity(bundle, hashes)


def read_inventory(path):
    """Rows of provenance/packages.tsv: package, version, arch, source, source version, status."""
    rows = []
    for line in Path(path).read_text().splitlines():
        fields = line.split("\t")
        if len(fields) < 5 or (len(fields) > 5 and fields[5] not in ("installed", "ii")):
            continue
        rows.append(dict(zip(PACKAGE_FIELDS, fields[:5])))
    return rows


def source_key(record):
    return (record["source_package"], record["source_version"])


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def publish(bundle_dir, output, repo, cache, snapshot, packages_file=None, identity=None):
    bundle_dir, output, repo = Path(bundle_dir), Path(output), Path(repo)
    bundle = json.loads((bundle_dir / "bundle.json").read_text())
    identity = identity or bundle_identity(bundle, bundle_dir)
    kernel, embedded = kernel_record(bundle, bundle_dir)

    # 1. The kernel: Debian's source package plus the Antinomie series.
    series_dir = repo / SERIES_DIR
    found = series_hash(series_dir)
    if found != kernel["antinomie_source"]:
        raise SourceError(f"the checkout's patch series hashes to {found[:12]}, but the base was "
                          f"built from {kernel['antinomie_source'][:12]} (revision "
                          f"{kernel['antinomie_revision']}); check out that release in --repo")
    pins = adapter_values(repo)
    version = kernel.get("source_version") or pins["SOURCE_VERSION"]
    if version != pins["SOURCE_VERSION"]:
        raise SourceError(f"kernel is built on linux {version}, the checkout pins {pins['SOURCE_VERSION']}")
    kernel_id = f"linux-{version}-antinomie-r{kernel['antinomie_revision']}-{found[:8]}"
    debian_files = fetch_source(snapshot, "linux", version, cache, {
        Path(pins["INPUT_ORIG"]).name: pins["INPUT_SHA_ORIG"],
        Path(pins["INPUT_DEBTAR"]).name: pins["INPUT_SHA_DEBTAR"]})
    for name, path in debian_files:
        copy_file(path, output / "debian" / f"linux_{version}" / name)
    for patch in sorted(series_dir.glob("*.patch")):
        copy_file(patch, output / "kernels" / kernel_id / "patches" / patch.name)
    for relative in RECIPE:
        if (repo / relative).is_file():
            copy_file(repo / relative, output / "kernels" / kernel_id / "recipe" / relative)
    write_json(output / "kernels" / kernel_id / "SERIES.json", {
        "series_sha256": found, "patches": [p.name for p in sorted(series_dir.glob("*.patch"))],
        "debian_source": f"linux {version}", "antinomie_revision": kernel["antinomie_revision"],
        "series_hash_rule": "sha256 of the `sha256sum -- *.patch` output in name order"})

    # 2. The kernel's exact configuration.
    base_dir = output / "bases" / identity
    config = None
    for candidate in (bundle_dir / "kernel.config", bundle_dir / "provenance/kernel.config"):
        if candidate.is_file():
            config = candidate.read_bytes()
    if config is None:
        config = embedded or load_builder().embedded_config(bundle_dir / bundle.get("kernel", "kernel"))
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "kernel.config").write_bytes(config)

    # 3. Host programs copied into the image, and a Debian base's whole inventory.
    records = list((bundle.get("guest_sources") or {}).get("packages") or [])
    if packages_file:
        records = json.loads(Path(packages_file).read_text())
    unowned = [r for r in records if not r.get("package")]
    if unowned:
        raise SourceError("host files no package owns were copied into the image: "
                          + ", ".join(r.get("path", "?") for r in unowned))
    inventory = []
    inventory_file = bundle_dir / "provenance/packages.tsv"
    if inventory_file.is_file():
        inventory = read_inventory(inventory_file)
        with (base_dir / "packages.tsv").open("w") as table:
            table.write("# package\tversion\tarchitecture\tsource package\tsource version\tsnapshot.debian.org\n")
            for row in inventory:
                link = f"{SNAPSHOT}/package/{urllib.parse.quote(row['source_package'])}/" \
                       f"{urllib.parse.quote(row['source_version'])}/"
                table.write("\t".join(row[k] for k in PACKAGE_FIELDS) + "\t" + link + "\n")
    if not records and not inventory:
        raise SourceError("the bundle records no packages: pass --packages for a legacy bundle")
    userland = {}
    for record in records:
        userland[source_key(record)] = record
    sources = []
    for (name, source_version), _ in sorted(userland.items()):
        if (name, source_version) == ("linux", version):
            continue
        files = fetch_source(snapshot, name, source_version, cache)
        folder = f"{name}_{source_version.split(':')[-1]}"  # as Debian names files: no epoch
        for filename, path in files:
            copy_file(path, output / "userland" / folder / filename)
        sources.append({"source_package": name, "source_version": source_version,
                        "path": f"userland/{folder}/",
                        "binary_packages": sorted({r["package"] + " " + r["version"] for r in records
                                                  if source_key(r) == (name, source_version)})})

    # 4. The manifest, with a hash of every file this base's section holds.
    def tree(relative):
        root = output / relative
        return {str(p.relative_to(output)): sha256_file(p) for p in sorted(root.rglob("*")) if p.is_file()}
    manifest = {
        "schema": SCHEMA, "identity": identity, "name": bundle.get("name"),
        "kernel": {"id": kernel_id, "debian_source": f"linux {version}",
                   "antinomie_revision": kernel["antinomie_revision"],
                   "antinomie_source": found, "path": f"kernels/{kernel_id}/",
                   "debian_path": f"debian/linux_{version}/", "config": f"bases/{identity}/kernel.config"},
        "userland": sources,
        "inventory": f"bases/{identity}/packages.tsv" if inventory else None,
        "inventory_packages": len(inventory),
        "files": {**tree(f"debian/linux_{version}"), **tree(f"kernels/{kernel_id}"),
                  **{k: v for s in sources for k, v in tree(s["path"]).items()},
                  f"bases/{identity}/kernel.config": sha256_file(base_dir / "kernel.config"),
                  **({f"bases/{identity}/packages.tsv": sha256_file(base_dir / "packages.tsv")}
                     if inventory else {})}}
    write_json(base_dir / "SOURCES.json", manifest)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--cache", type=Path, help="keep downloaded source files here")
    parser.add_argument("--packages", type=Path, help="JSON list of package records for a legacy bundle")
    parser.add_argument("--identity", help="the base identity, when the bundle directory is not named by it")
    args = parser.parse_args(argv)
    cache = args.cache or args.output / ".cache"
    try:
        manifest = publish(args.bundle, args.output, args.repo, cache, Snapshot(),
                           args.packages, args.identity)
    except (SourceError, OSError, KeyError, ValueError) as error:
        print(f"publish-base-sources: {error}", file=sys.stderr)
        return 1
    if args.cache is None:
        shutil.rmtree(cache, ignore_errors=True)
    print(f"{manifest['identity']}: {len(manifest['files'])} files, kernel {manifest['kernel']['id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
