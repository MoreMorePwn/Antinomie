#!/usr/bin/env python3
"""Build one Antinomie base from this kit: kernel source, patched kernel, image.

The kit is the repository layout the app carries: this script, the kernel
build script, the image recipes, the core patch series and the pinned Debian
source package (the large upstream tarball comes from --inputs). It runs
natively on a Linux host, as root inside the QEMU builder VM, or in a pinned
Debian 13 container (--container) and prints "::stage NAME" lines for the app.

    build-base.py --job JOB.json --inputs DIR --work DIR --output DIR
                  [--kernel-cache FILE] [--image-cache FILE] [--ccache DIR]
                  [--container auto|podman|docker]

--container runs this same script in the container builder: the image built from
src/antinomie/packaging/container/Dockerfile (Debian 13 pinned by digest, a
package snapshot and exact versions), tagged antinomie-builder:<12 hex of that
file's SHA-256>. auto takes rootless Podman first, then Docker (whose socket
gives root-equivalent access). The container is removed when the build ends.

The kernel depends only on the patch series, the kernel build script and the
profile, never on the image answers. With --kernel-cache, a matching cached
kernel (bzImage, .config and modules) is reused; otherwise the kernel is built
and the cache file is written for the next build.

With --image-cache, the Debian recipe reuses a root filesystem it bootstrapped
earlier with the same recipe and answers (and not too old): only the kernel
and its modules change, which skips installing the desktop. With --ccache, the
kernel compiler output is cached there, so a new patch series recompiles only
what it touched.

JOB.json: {"format": 1, "profile": "busybox" | "debian-xfce" | "debian-minimal",
           "options": {...}, "app_version": "0.1.0"}
           (app_version optional: recorded as built_with)

debian-xfce is Debian 13 with the desktop its options choose; debian-minimal is
the console-only Debian 13 base (no desktop). debian-minimal shares the minimal
kernel profile with BusyBox (everything built in, no modules), so the kernel
cached for a BusyBox build serves it too.
"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile

KIT = Path(__file__).resolve().parent.parent
ADAPTER = KIT / "src/antinomie/packaging/debian-6.12.94-1-trixie/adapter.conf"
SERIES = KIT / "src/antinomie/core/6.12"
DEBIAN_ANSWERS = {"name", "hostname", "locale", "keyboard_layout", "keyboard_variant",
                  "timezone", "standard", "mirror", "proxy"}
# Kernel profile, image recipe, accepted options, and free space (GiB) the
# kernel build and the image build need.
PROFILES = {
    "busybox": ("minimal", "build-monitor-image.py", {"hostname", "name"}, (5, 2)),
    "debian-xfce": ("debian", "build-debian-image.py", DEBIAN_ANSWERS | {"desktop"}, (30, 20)),
    "debian-minimal": ("minimal", "build-debian-image.py", DEBIAN_ANSWERS, (5, 6)),
}
# The image recipe's answer that selects the console-only Debian base.
CONSOLE_DESKTOP = "none"


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


# Debian's banner: release, build user, compiler, linker and build string.
BANNER = re.compile(r"Linux version (\S+) \((\S+)\) \((.+), (GNU ld [^,]+)\) (#\d+ .+)")


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


def toolchain(kernel_profile):
    """The compiler's and linker's version lines the kernel build script would
    record in the kernel's banner, as {"cc": ..., "ld": ...}."""
    output = subprocess.run(["bash", str(KIT / "scripts/build-monitor-kernel.sh"), kernel_profile],
                            env=os.environ | {"ANTINOMIE_PRINT_TOOLCHAIN": "1"},
                            capture_output=True, text=True, check=True).stdout
    return dict(line.split(": ", 1) for line in output.splitlines() if ": " in line)


def debian_toolchain():
    """Debian's compiler and linker lines, from the pinned kernel banner."""
    match = BANNER.fullmatch(adapter()["KERNEL_BANNER"])
    if not match:
        raise RuntimeError("adapter.conf KERNEL_BANNER is not a kernel banner")
    return {"cc": match[3], "ld": match[4]}


def require_debian_toolchain(kernel_profile):
    """Debian Minimal's kernel must carry Debian's banner, which only Debian
    13's compiler and linker write: refuse another toolchain before building."""
    found, wanted = toolchain(kernel_profile), debian_toolchain()
    for tool in ("cc", "ld"):
        if found.get(tool) != wanted[tool]:
            raise RuntimeError(
                f"this host's kernel {'compiler' if tool == 'cc' else 'linker'} is "
                f"{found.get(tool) or 'missing'!r}, not Debian 13's {wanted[tool]!r}: Debian "
                "Minimal's kernel banner (/proc/version) must be Debian's own; build it in "
                "a pinned Debian 13 container (--container), in the QEMU builder, or on a "
                "Debian 13 host")


CONTAINER_DOCKERFILE = KIT / "src/antinomie/packaging/container/Dockerfile"
CONTAINER_LABEL = "org.antinomie.build"
IMAGE_LABEL = "org.antinomie.builder=1"


def container_tag():
    """The builder image's tag: antinomie-builder:<12 hex of the Dockerfile>."""
    return "antinomie-builder:" + checksum(CONTAINER_DOCKERFILE)[:12]


def container_problem(engine):
    """Why `engine` (podman or docker) cannot build here, or (None, rootless)."""
    if shutil.which(engine) is None:
        return f"{engine} is not installed", False
    if engine == "podman":
        answer = subprocess.run(["podman", "info", "--format", "{{.Host.Security.Rootless}}"],
                                capture_output=True, text=True, timeout=30)
        if answer.returncode:
            lines = [line for line in answer.stderr.splitlines() if line.strip()]
            return f"podman cannot run here: {lines[0] if lines else 'no message'}", False
        return None, answer.stdout.strip() == "true"
    answer = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                            capture_output=True, text=True, timeout=30)
    if answer.returncode:
        text = answer.stderr.lower()
        if "permission denied" in text:
            return ("no permission to use Docker (its socket needs the docker group, which gives "
                    "root-equivalent access)"), False
        if "cannot connect" in text or "is the docker daemon running" in text:
            return "Docker's daemon is not reachable (is it running?)", False
        lines = [line for line in answer.stderr.splitlines() if line.strip()]
        return f"Docker cannot run here: {lines[0] if lines else 'no message'}", False
    return None, False


def pick_container_engine(choice):
    """(engine, rootless) for --container: auto is rootless Podman, then Docker."""
    problems = []
    for engine in (["podman", "docker"] if choice == "auto" else [choice]):
        problem, rootless = container_problem(engine)
        if problem is None:
            return engine, rootless
        problems.append(problem)
    raise RuntimeError("no container engine can build here (" + "; ".join(problems) + ")")


def ensure_container_image(engine):
    """Build the pinned image unless the engine has it; returns its tag."""
    tag = container_tag()
    have = subprocess.run([engine, "image", "inspect", "--format", "{{.Id}}", tag],
                          capture_output=True).returncode == 0
    if not have:
        print(f"building the builder image {tag} (a pinned Debian 13; needs the network once)",
              flush=True)
        run(engine, "build", "--label", IMAGE_LABEL, "-t", tag, "-f", CONTAINER_DOCKERFILE,
            CONTAINER_DOCKERFILE.parent)
    return tag


def run_in_container(args, choice):
    """Run this script in the container builder; the container is always removed."""
    engine, rootless = pick_container_engine(choice)
    tag = ensure_container_image(engine)
    # Containers of builds whose owner died (a crash) go; a running build's stay.
    listing = subprocess.run([engine, "ps", "-a", "--filter", f"label={CONTAINER_LABEL}",
                              "--format", '{{.ID}} {{index .Labels "' + CONTAINER_LABEL + '"}}'],
                             capture_output=True, text=True).stdout.splitlines()
    stale = [line.split()[0] for line in listing if line.split()
             and not (len(line.split()) > 1 and line.split()[1].isdigit()
                      and Path(f"/proc/{line.split()[1]}").exists())]
    if stale:
        subprocess.run([engine, "rm", "-f", *stale], capture_output=True)
    for folder in (args.work, args.inputs, args.output.parent):
        folder.mkdir(parents=True, exist_ok=True)
    mounts = [(KIT, "/kit", "ro"), (args.job.resolve(), "/job.json", "ro"),
              (args.inputs.resolve(), "/inputs", "rw"), (args.work.resolve(), "/work", "rw"),
              (args.output.resolve().parent, "/out", "rw")]
    inner = ["nice", "-n", os.environ["ANTINOMIE_BUILD_NICE"]] \
        if os.environ.get("ANTINOMIE_BUILD_NICE") else []
    inner += ["python3", "/kit/scripts/build-base.py", "--job", "/job.json", "--inputs", "/inputs",
             "--work", "/work", "--output", f"/out/{args.output.name}", "--jobs", str(args.jobs)]
    if args.keep_kernel_build:
        inner.append("--keep-kernel-build")
    for option, inside, cache in (("--kernel-cache", "/cache/kernels", args.kernel_cache),
                                  ("--image-cache", "/cache/images", args.image_cache)):
        if cache is not None:
            cache.parent.mkdir(parents=True, exist_ok=True)
            mounts.append((cache.resolve().parent, inside, "rw"))
            inner += [option, f"{inside}/{cache.name}"]
    if args.ccache is not None:
        args.ccache.mkdir(parents=True, exist_ok=True)
        mounts.append((args.ccache.resolve(), "/ccache", "rw"))
        inner += ["--ccache", "/ccache"]
    name = f"antinomie-build-{os.urandom(8).hex()}"
    command = [engine, "run", "--rm", "--init", "--name", name, "--label", f"{CONTAINER_LABEL}={os.getpid()}",
               "--cap-add=SYS_ADMIN", "--cap-add=MKNOD", "--security-opt", "apparmor=unconfined",
               "-e", "ANTINOMIE_BUILDER=1", "-e", f"ANTINOMIE_BUILDER_IMAGE={tag}"]
    for host, inside, mode in mounts:
        command += ["-v", f"{host}:{inside}:{mode}"]
    command.append(tag)
    if rootless:
        command += inner
    else:
        # A root-equivalent engine writes root-owned files: hand them back.
        quoted = " ".join(shlex.quote(word) for word in inner)
        command += ["sh", "-c", f"{quoted}; status=$?; chown -R {os.getuid()}:{os.getgid()} "
                    "/work /out /inputs /cache /ccache 2>/dev/null; exit $status"]
    print(f"building in a {engine} container from {tag}", flush=True)
    returncode = 1
    try:
        returncode = subprocess.run([str(word) for word in command]).returncode
        return returncode
    finally:
        subprocess.run([engine, "rm", "-f", name], capture_output=True)
        if returncode and not rootless:
            # A stopped build never reached its chown: hand the folders back.
            volumes = [word for pair in zip(["-v"] * len(mounts),
                                            [f"{host}:{inside}:{mode}" for host, inside, mode
                                             in mounts]) for word in pair]
            subprocess.run([engine, "run", "--rm", *volumes, tag, "sh", "-c",
                            f"chown -R {os.getuid()}:{os.getgid()} /work /out /inputs /cache "
                            "/ccache 2>/dev/null; true"], capture_output=True)


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
    if (build / "debian-config").is_file():
        shutil.copy2(build / "debian-config", kept / "debian-config")
    if (build / "modules-install").is_dir():
        shutil.move(build / "modules-install", kept / "modules-install")
    shutil.rmtree(build)
    # In the QEMU builder the disk is attached with discard=unmap: hand the freed
    # kernel objects (about 20 GiB for Debian) back to the host before the image.
    if os.geteuid() == 0 and shutil.which("fstrim"):
        subprocess.run(["fstrim", str(work)], check=False)
    return kept


def kernel_identity(kernel_profile):
    """What a cached kernel must have been built from: the series, the
    scripts, and the compiler and linker (their versions are in its banner)."""
    return {"format": 1, "profile": kernel_profile, "series": series_hash(),
            "kernel_script_sha256": checksum(KIT / "scripts/build-monitor-kernel.sh"),
            "symbols_script_sha256": checksum(KIT / "scripts/make-kernel-symbols.py"),
            "toolchain": toolchain(kernel_profile)}


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
            if {key: value for key, value in manifest.items() if key != "builder"} \
                    != kernel_identity(kernel_profile):
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
    manifest = kernel_identity(kernel_profile)
    # Which builder made it: informational, never compared, so a kernel built in
    # the container builder serves a native build with the same toolchain.
    if os.environ.get("ANTINOMIE_BUILDER_IMAGE"):
        manifest["builder"] = {"image": os.environ["ANTINOMIE_BUILDER_IMAGE"]}
    manifest = json.dumps(manifest).encode()

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
        for name in ("arch/x86/boot/bzImage", ".config", "symbols.json.xz", "debian-config",
                     "modules-install"):
            if (kept / name).exists():
                archive.add(kept / name, arcname=name, filter=portable)
    os.replace(partial, cache)
    print(f"kernel cached in {cache}", flush=True)


def build_image(profile, values, build, work, output, app_version=None, image_cache=None,
                inputs=None):
    recipe = KIT / "scripts" / PROFILES[profile][1]
    command = [sys.executable, recipe, "--kernel", build / "arch/x86/boot/bzImage",
               "--kernel-config", build / ".config", "--symbols", build / "symbols.json.xz",
               "--output", output, "--work", work]
    if app_version:
        command += ["--app-version", app_version]
    if profile == "busybox":
        # An answer the job leaves out takes the recipe's default, as the app's
        # own defaults (BuildOptions) and the Debian recipe do.
        for option in ("hostname", "name"):
            if option in values:
                command += [f"--{option}", values[option]]
    else:
        if profile == "debian-minimal":
            values = {**values, "desktop": CONSOLE_DESKTOP}
        answers = work / "options.json"
        answers.write_text(json.dumps(values) + "\n")
        command += ["--options", answers]
        # The minimal kernel profile builds everything in and installs no modules.
        if (build / "modules-install").is_dir() or PROFILES[profile][0] == "debian":
            command += ["--modules", build / "modules-install"]
        # The console base's /boot and module tree are Debian's own packages,
        # kept with the other Debian inputs.
        if profile == "debian-minimal" and inputs is not None:
            command += ["--kernel-package-cache", inputs]
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
    parser.add_argument("--container", choices=("auto", "podman", "docker"),
                        help="run this build in the pinned Debian 13 container builder")
    args = parser.parse_args()
    if args.container:
        try:
            sys.exit(run_in_container(args, args.container))
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            print(f"::error {error}", flush=True)
            sys.exit(1)
    try:
        profile, values, app_version = load_job(args.job)
        if args.output.exists():
            raise RuntimeError(f"{args.output} already exists")
        args.work.mkdir(parents=True, exist_ok=True)
        kernel_profile = PROFILES[profile][0]
        if profile == "debian-minimal":
            require_debian_toolchain(kernel_profile)
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
                    args.image_cache, args.inputs)
        if not args.keep_kernel_build:
            shutil.rmtree(build)
        stage("done")
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"::error {error}", flush=True)
        sys.exit(1)
    print(args.output, flush=True)


if __name__ == "__main__":
    main()
