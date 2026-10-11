#!/usr/bin/env python3
"""Build one Antinomie base from this kit: kernel source, patched kernel, image.

The kit is the repository layout the app carries: this script, the kernel
build script, the image recipes, the core patch series and the pinned Debian
source package (the large upstream tarball comes from --inputs). It runs
natively on a Linux host or as root inside the QEMU builder VM and prints
"::stage NAME" lines for the app.

    build-base.py --job JOB.json --inputs DIR --work DIR --output DIR
                  [--kernel-cache FILE] [--image-cache FILE] [--ccache DIR]

The kernel depends only on the patch series, the kernel build script and the
profile, never on the image answers. With --kernel-cache, a matching cached
kernel (bzImage, .config and modules) is reused; otherwise the kernel is built
and the cache file is written for the next build.

With --image-cache, the Debian recipe reuses a root filesystem it bootstrapped
earlier with the same recipe and answers (and not too old): only the kernel
and its modules change, which skips installing the desktop. With --ccache, the
kernel compiler output is cached there, so a new patch series recompiles only
what it touched.

JOB.json: {"format": 1, "profile": "busybox" | "debian-xfce", "options": {...},
           "app_version": "0.1.0"}   (app_version optional: recorded as built_with)
"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

KIT = Path(__file__).resolve().parent.parent
ADAPTER = KIT / "src/antinomie/packaging/debian-6.12.94-1-trixie/adapter.conf"
SERIES = KIT / "src/antinomie/core/6.12"
# Kernel profile, image recipe, accepted options, and free space (GiB) the
# kernel build and the image build need.
PROFILES = {
    "busybox": ("minimal", "build-monitor-image.py", {"hostname", "name"}, (5, 2)),
    "debian-xfce": ("debian", "build-debian-image.py",
                    {"name", "desktop", "hostname", "locale", "keyboard_layout", "keyboard_variant",
                     "timezone", "standard", "mirror", "proxy"}, (30, 20)),
}


def stage(name):
    print(f"::stage {name}", flush=True)


def run(*args, **kwargs):
    print("$ " + " ".join(str(arg) for arg in args), flush=True)
    subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def adapter():
    values = {}
    for line in ADAPTER.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip("'\"")
    return values


def series_hash():
    """Same value as `sha256sum -- *.patch | sha256sum` in the series directory."""
    patches = sorted(SERIES.glob("*.patch"))
    if not patches:
        raise RuntimeError(f"no core patches in {SERIES}")
    listing = "".join(f"{checksum(patch)}  {patch.name}\n" for patch in patches)
    return hashlib.sha256(listing.encode()).hexdigest()


def load_job(path):
    job = json.loads(path.read_text())
    if not isinstance(job, dict) or job.get("format") != 1:
        raise RuntimeError("job must be a format 1 JSON object")
    profile = job.get("profile")
    if profile not in PROFILES:
        raise RuntimeError(f"unknown profile {profile!r}")
    values = job.get("options", {})
    if not isinstance(values, dict):
        raise RuntimeError("job options must be an object")
    unknown = set(values) - PROFILES[profile][2]
    if unknown:
        raise RuntimeError(f"options not offered for {profile}: " + ", ".join(sorted(unknown)))
    app_version = job.get("app_version")
    if app_version is not None and not isinstance(app_version, str):
        raise RuntimeError("job app_version must be a string")
    return profile, values, app_version


def require_space(work, gib):
    free = shutil.disk_usage(work).free
    if free < gib << 30:
        raise RuntimeError(f"building this base needs about {gib} GiB free in {work}; "
                           f"{free / (1 << 30):.1f} GiB available")


def prepare_source(inputs, work):
    """Unpack the pinned Debian source package and apply the core series once per series."""
    conf = adapter()
    orig = inputs / Path(conf["INPUT_ORIG"]).name
    if not orig.is_file() or checksum(orig) != conf["INPUT_SHA_ORIG"]:
        raise RuntimeError(f"{orig} is missing or does not match the pinned SHA-256")
    debtar = KIT / conf["INPUT_DEBTAR"]
    if checksum(debtar) != conf["INPUT_SHA_DEBTAR"]:
        raise RuntimeError(f"{debtar.name} does not match the pinned SHA-256")
    series = series_hash()
    # One path for every series: compiler arguments and line markers carry the
    # source path, so a path naming the series would miss the whole ccache.
    root = work / "source"
    tree = root / conf["SOURCE_DIRNAME"]
    marker = root / "prepared.json"
    if marker.is_file() and json.loads(marker.read_text()).get("series") == series:
        print(f"kernel source for series {series[:16]} already prepared", flush=True)
        return tree
    for stale in [root, *work.glob("source-*")]:
        if stale.exists():
            shutil.rmtree(stale)
    package = root / "package"
    package.mkdir(parents=True)
    for source in (KIT / conf["INPUT_DSC"], debtar, orig):
        os.symlink(source, package / source.name)
    run("dpkg-source", "--no-copy", "-x", package / Path(conf["INPUT_DSC"]).name, tree)
    shutil.rmtree(package)
    for patch in sorted(SERIES.glob("*.patch")):
        run("patch", "-p1", "--fuzz=0", "--forward", "--batch", "--no-backup-if-mismatch",
            "-s", "-d", tree, "-i", patch)
    marker.write_text(json.dumps({"series": series, "source_version": conf["SOURCE_VERSION"]}) + "\n")
    return tree


def build_kernel(kernel_profile, tree, work, jobs, ccache=None):
    build = work / f"kernel-{kernel_profile}"
    env = os.environ | ({"ANTINOMIE_CCACHE_DIR": str(ccache)} if ccache else {}) | {"ANTINOMIE_SOURCE_TREE": str(tree), "ANTINOMIE_BUILD_TREE": str(build),
                        "ANTINOMIE_DEBIAN_CONFIG": str(tree / "debian/config"),
                        "ANTINOMIE_SERIES_DIR": str(SERIES), "ANTINOMIE_SOURCE_PREPARED": "1",
                        "JOBS": str(jobs)}
    run("bash", KIT / "scripts/build-monitor-kernel.sh", kernel_profile, env=env)
    return build


def memory_kib():
    with open("/proc/meminfo") as meminfo:
        for line in meminfo:
            if line.startswith("MemTotal:"):
                return int(line.split()[1])
    return 0


def make_symbols(build, work):
    """The kernel's Volatility symbol table, from vmlinux's DWARF and System.map.

    dwarf2json holds the whole debug information in memory (several GiB for
    the Debian kernel); in the QEMU builder, a temporary swap file makes up
    for a small VM."""
    swap = None
    if (os.environ.get("ANTINOMIE_BUILDER") == "1" and os.geteuid() == 0
            and memory_kib() < 12 << 20 and shutil.which("swapon")):
        swap = work / "symbols.swap"
        try:
            run("fallocate", "-l", "10G", swap)
            swap.chmod(0o600)
            run("mkswap", swap, stdout=subprocess.DEVNULL)
            run("swapon", swap)
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"no swap for the symbol table ({error}); trying without", flush=True)
            swap.unlink(missing_ok=True)
            swap = None
    try:
        run(sys.executable, KIT / "scripts/make-kernel-symbols.py", "--vmlinux", build / "vmlinux",
            "--system-map", build / "System.map", "--output", build / "symbols.json.xz",
            "--tools", work / "tools")
    finally:
        if swap is not None:
            subprocess.run(["swapoff", swap], check=False)
            swap.unlink(missing_ok=True)


def keep_artifacts(build, work):
    """Keep only what the image needs and free the kernel object tree."""
    kept = work / "kernel-artifacts"
    if kept.exists():
        shutil.rmtree(kept)
    (kept / "arch/x86/boot").mkdir(parents=True)
    shutil.copy2(build / "arch/x86/boot/bzImage", kept / "arch/x86/boot/bzImage")
    shutil.copy2(build / ".config", kept / ".config")
    shutil.copy2(build / "symbols.json.xz", kept / "symbols.json.xz")
    if (build / "modules-install").is_dir():
        shutil.move(build / "modules-install", kept / "modules-install")
    shutil.rmtree(build)
    # In the QEMU builder the disk is attached with discard=unmap: hand the freed
    # kernel objects (about 20 GiB for Debian) back to the host before the image.
    if os.geteuid() == 0 and shutil.which("fstrim"):
        subprocess.run(["fstrim", str(work)], check=False)
    return kept


def kernel_identity(kernel_profile):
    return {"format": 1, "profile": kernel_profile, "series": series_hash(),
            "kernel_script_sha256": checksum(KIT / "scripts/build-monitor-kernel.sh"),
            "symbols_script_sha256": checksum(KIT / "scripts/make-kernel-symbols.py")}


def load_cached_kernel(cache, kernel_profile, work):
    """Unpack a cached kernel that matches this kit, or return None."""
    if cache is None or not cache.is_file():
        return None
    kept = work / "kernel-artifacts"
    if kept.exists():
        shutil.rmtree(kept)
    try:
        with tarfile.open(cache) as archive:
            manifest = json.load(archive.extractfile("kernel-cache.json"))
            if manifest != kernel_identity(kernel_profile):
                print("cached kernel is from another patch series or build script; rebuilding",
                      flush=True)
                return None
            kept.mkdir(parents=True)
            archive.extractall(kept, filter="data")
    except (tarfile.TarError, KeyError, ValueError, OSError, TypeError) as error:
        print(f"cached kernel unusable ({error}); rebuilding", flush=True)
        if kept.exists():
            shutil.rmtree(kept)
        return None
    if not all((kept / name).is_file()
               for name in ("arch/x86/boot/bzImage", ".config", "symbols.json.xz")):
        shutil.rmtree(kept)
        return None
    print(f"using the cached kernel for series {manifest['series'][:16]}", flush=True)
    return kept


def save_cached_kernel(cache, kept, kernel_profile):
    """Write the kernel artifacts to the cache file atomically."""
    partial = cache.with_name(cache.name + ".part")
    cache.parent.mkdir(parents=True, exist_ok=True)
    manifest = json.dumps(kernel_identity(kernel_profile)).encode()

    def portable(info):
        # modules_install leaves build/source links into this build tree.
        if info.issym() and (info.linkname.startswith("/") or ".." in info.linkname.split("/")):
            return None
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        return info

    with tarfile.open(partial, "w") as archive:
        entry = tarfile.TarInfo("kernel-cache.json")
        entry.size = len(manifest)
        archive.addfile(entry, io.BytesIO(manifest))
        for name in ("arch/x86/boot/bzImage", ".config", "symbols.json.xz", "modules-install"):
            if (kept / name).exists():
                archive.add(kept / name, arcname=name, filter=portable)
    os.replace(partial, cache)
    print(f"kernel cached in {cache}", flush=True)


def build_image(profile, values, build, work, output, app_version=None, image_cache=None):
    recipe = KIT / "scripts" / PROFILES[profile][1]
    command = [sys.executable, recipe, "--kernel", build / "arch/x86/boot/bzImage",
               "--kernel-config", build / ".config", "--symbols", build / "symbols.json.xz",
               "--output", output, "--work", work]
    if app_version:
        command += ["--app-version", app_version]
    if profile == "busybox":
        command += ["--hostname", values.get("hostname", "localhost"),
                    "--name", values.get("name", "")]
    else:
        answers = work / "options.json"
        answers.write_text(json.dumps(values) + "\n")
        command += ["--modules", build / "modules-install", "--options", answers]
        if image_cache is not None:
            command += ["--rootfs-cache", image_cache]
    run(*command)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    parser.add_argument("--keep-kernel-build", action="store_true",
                        help="keep the kernel build tree for a faster next build")
    parser.add_argument("--kernel-cache", type=Path,
                        help="reuse this cached kernel if it matches, else write it")
    parser.add_argument("--image-cache", type=Path,
                        help="reuse this cached root filesystem if it matches, else write it")
    parser.add_argument("--ccache", type=Path,
                        help="compiler cache directory for the kernel build")
    args = parser.parse_args()
    try:
        profile, values, app_version = load_job(args.job)
        if args.output.exists():
            raise RuntimeError(f"{args.output} already exists")
        args.work.mkdir(parents=True, exist_ok=True)
        kernel_profile = PROFILES[profile][0]
        kernel_space, image_space = PROFILES[profile][3]
        build = load_cached_kernel(args.kernel_cache, kernel_profile, args.work)
        if build is None:
            require_space(args.work, kernel_space + image_space)
            stage("source")
            tree = prepare_source(args.inputs, args.work)
            stage("kernel")
            build = build_kernel(kernel_profile, tree, args.work, args.jobs, args.ccache)
            stage("symbols")
            make_symbols(build, args.work)
            if not args.keep_kernel_build:
                build = keep_artifacts(build, args.work)
            if args.kernel_cache is not None:
                save_cached_kernel(args.kernel_cache, build, kernel_profile)
        else:
            stage("kernel")
            require_space(args.work, image_space)
        stage("image")
        build_image(profile, values, build, args.work, args.output, app_version,
                    args.image_cache)
        if not args.keep_kernel_build:
            shutil.rmtree(build)
        stage("done")
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"::error {error}", flush=True)
        sys.exit(1)
    print(args.output, flush=True)


if __name__ == "__main__":
    main()
