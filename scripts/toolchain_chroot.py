#!/usr/bin/env python3
"""A rootless Debian 13 toolchain chroot for kernel builds on any Linux distro.

Debian Minimal's kernel banner, BTF and compiler-dependent options come from
Debian 13's exact gcc-14 and binutils. A host that has other versions compiles
in this chroot instead: mmdebstrap (unshare mode, needs /etc/subuid for the
user) installs the kernel build tools at the versions and package snapshot that
src/antinomie/packaging/container/Dockerfile pins, so the container builder and
this chroot compile with the same packages. No root, no container engine.

The chroot is unpacked once under DIR/root and reused while the Dockerfile's
pins are unchanged (DIR/ready.json records them). A build enters it with
`Chroot.command`: a user, mount and PID namespace in which the user is root,
the build's folders bound in at fixed paths (/kit, /work, /inputs, /ccache)
exactly as in the container, so a kernel built here and in a container carries
the same source paths.
"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

# The Dockerfile packages the kernel steps use (source unpacking, patching,
# configuring, compiling, BTF, module install, the banner check).
PACKAGES = ("bc", "binutils", "bison", "ccache", "cpio", "dpkg-dev", "dwarves", "flex", "gcc",
            "gcc-14", "kmod", "libelf-dev", "libssl-dev", "make", "openssl", "patch", "perl",
            "python3", "xz-utils", "zstd")
KEYRINGS = (Path("/usr/share/keyrings/debian-archive-keyring.pgp"),
            Path("/usr/share/keyrings/debian-archive-keyring.gpg"))
MARKER = "ready.json"
# Where the archive's signing keys sit inside the chroot (apt's Signed-By).
SIGNED_BY = "/usr/share/keyrings/debian-archive-keyring.pgp"
PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def parse_pins(text):
    """(snapshot stamp, {package: version}) from the Dockerfile's pinned install."""
    stamp = re.search(r"^\s*stamp=(\d{8}T\d{6}Z);", text, re.M)
    if not stamp:
        raise RuntimeError("the Dockerfile has no snapshot stamp")
    versions = dict(re.findall(r"^\s+([a-z0-9][a-z0-9+.-]*)=(\S+?)(?:\s*[;\\])*\s*$", text, re.M))
    missing = [name for name in PACKAGES if name not in versions]
    if missing:
        raise RuntimeError("the Dockerfile does not pin " + ", ".join(missing))
    return stamp.group(1), {name: versions[name] for name in PACKAGES}


def sources(stamp):
    """The package archives of the pinned snapshot, as mmdebstrap sources."""
    archive = f"[signed-by={SIGNED_BY}] http://snapshot.debian.org/archive"
    return [f"deb {archive}/debian/{stamp}/ trixie main",
            f"deb {archive}/debian/{stamp}/ trixie-updates main",
            f"deb {archive}/debian-security/{stamp}/ trixie-security main"]


def bootstrap_command(stamp, versions, tarball):
    return ["mmdebstrap", "--mode=unshare", "--variant=minbase", "--format=tar",
            "--aptopt=Acquire::Check-Valid-Until \"false\"", "--aptopt=Acquire::Retries \"5\"",
            "--include=" + ",".join(f"{name}={version}" for name, version in versions.items()),
            "trixie", str(tarball), *sources(stamp)]


def ready(directory, dockerfile):
    """Whether DIR holds a complete chroot of this Dockerfile's pins."""
    try:
        marker = json.loads((Path(directory) / MARKER).read_text())
    except (OSError, ValueError):
        return False
    return marker.get("dockerfile_sha256") == sha256(dockerfile) \
        and (Path(directory) / "root/usr/bin/x86_64-linux-gnu-gcc-14").exists()


def ensure(directory, dockerfile, log=print):
    """Create the chroot under `directory` unless it is already complete."""
    directory, dockerfile = Path(directory), Path(dockerfile)
    if ready(directory, dockerfile):
        return directory / "root"
    keyring = next((path for path in KEYRINGS if path.is_file()), None)
    if keyring is None:
        raise RuntimeError("the Debian archive keyring is missing (install debian-archive-keyring)")
    stamp, versions = parse_pins(dockerfile.read_text())
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True, exist_ok=True)
    root = directory / "root"
    log(f"creating the Debian 13 toolchain chroot (snapshot {stamp}): downloads about 110 MB, "
        "unpacks to about 0.5 GB; needs the network once")
    # mmdebstrap's namespace root is a subordinate UID: its work folder must be
    # reachable by that UID, which a private home folder is not.
    with tempfile.TemporaryDirectory(prefix="antinomie-toolchain-", dir="/var/tmp") as scratch:
        os.chmod(scratch, 0o711)
        tarball = Path(scratch) / "root.tar"
        subprocess.run(bootstrap_command(stamp, versions, tarball), check=True,
                       env=os.environ | {"TMPDIR": scratch, "LC_ALL": "C.UTF-8"})
        # The user becomes root in a one-ID namespace: files take the user's
        # ID, and /dev (device nodes) is bound in at each run instead.
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir()
        subprocess.run(["unshare", "--user", "--map-root-user", "tar", "-xf", str(tarball), "-C",
                        str(root), "--no-same-owner", "--exclude=./dev/*"], check=True)
    subprocess.run(["chmod", "-R", "u+rwX", str(root)], check=True)
    for folder in ("kit", "work", "inputs", "ccache", "out"):
        (root / folder).mkdir(exist_ok=True)
    chroot = Chroot(root, [])
    got = {name: chroot.query(["dpkg-query", "-W", "-f=${Version}", name]) for name in versions}
    wrong = {name: (got[name], want) for name, want in versions.items() if got[name] != want}
    if wrong:
        shutil.rmtree(root, ignore_errors=True)
        raise RuntimeError("the chroot has other package versions than pinned: " + json.dumps(wrong))
    (directory / MARKER).write_text(json.dumps({
        "format": 1, "dockerfile_sha256": sha256(dockerfile), "snapshot": stamp,
        "packages": got}, indent=1) + "\n")
    return root


class Chroot:
    """Commands inside the chroot, as root of a private user namespace.

    `mounts` is a list of (host path, path inside, writable): the folders the
    build touches, bound at the paths the container builder uses."""

    def __init__(self, root, mounts):
        self.root = Path(root)
        self.mounts = [(Path(host).resolve(), inside, writable) for host, inside, writable in mounts]

    def translate(self, text):
        """`text` with a host path under a bound folder replaced by its path inside."""
        text = str(text)
        for host, inside, _ in self.mounts:
            prefix = str(host)
            if text == prefix or text.startswith(prefix + "/"):
                return inside + text[len(prefix):]
        return text

    def command(self, argv, env=None):
        """The host command line running `argv` (paths translated) in the chroot."""
        q = shlex.quote
        lines = ["set -e", f"root={q(str(self.root))}",
                 'mount --rbind /dev "$root/dev"', 'mount -t proc proc "$root/proc"',
                 'mount -t tmpfs tmpfs "$root/tmp"']
        for host, inside, writable in self.mounts:
            target = f'"$root"{q(inside)}'
            lines.append(f"mkdir -p {target} && mount --rbind {q(str(host))} {target}")
            if not writable:
                lines.append(f"mount -o remount,bind,ro,nosuid,nodev {target}")
        values = {"PATH": PATH, "HOME": "/root", "LANG": "C.UTF-8", "TERM": "dumb"}
        values.update({key: self.translate(value) for key, value in (env or {}).items()})
        assignments = " ".join(q(f"{key}={value}") for key, value in values.items())
        words = " ".join(q(self.translate(word)) for word in argv)
        lines.append(f'exec chroot "$root" env -i {assignments} {words}')
        return ["unshare", "--user", "--map-root-user", "--mount", "--pid", "--fork",
                "--kill-child", "sh", "-c", "\n".join(lines)]

    def run(self, argv, env=None, **kwargs):
        return subprocess.run(self.command(argv, env), **kwargs)

    def query(self, argv):
        return self.run(argv, check=True, capture_output=True, text=True).stdout.strip()
