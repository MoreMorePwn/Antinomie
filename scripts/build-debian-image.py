#!/usr/bin/env python3
"""Build the Debian 13 Xfce bundle for the pinned Antinomie kernel with mmdebstrap.

The root filesystem is bootstrapped into a tarball (rootless with
--mode=unshare, or as root inside the QEMU builder) and turned into an ext4
image with mkfs.ext4 -d; no libguestfs appliance and no mounted host
filesystems are used.
"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tarfile
import tempfile

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "work/debian-xfce-base"
# The Debian installer's desktop choices: tasksel task, display manager,
# default session (an xsessions or wayland-sessions entry), label, minimum RAM.
DESKTOPS = {
    "xfce": ("task-xfce-desktop", "lightdm", "xfce", "Xfce", 2048),
    "gnome": ("task-gnome-desktop", "gdm3", "gnome", "GNOME", 4096),
    "gnome-flashback": ("task-gnome-flashback-desktop", "gdm3",
                        "gnome-flashback-metacity", "GNOME Flashback", 2048),
    "kde": ("task-kde-desktop", "sddm", "plasma", "KDE Plasma", 4096),
    "cinnamon": ("task-cinnamon-desktop", "lightdm", "cinnamon", "Cinnamon", 2048),
    "mate": ("task-mate-desktop", "lightdm", "mate", "MATE", 2048),
    "lxde": ("task-lxde-desktop", "lightdm", "LXDE", "LXDE", 2048),
    "lxqt": ("task-lxqt-desktop", "sddm", "lxqt", "LXQt", 2048),
}


def profile(desktop):
    """Guest profile of the base: one per desktop."""
    label, ram = DESKTOPS[desktop][3], DESKTOPS[desktop][4]
    return {"id": "debian-" + desktop, "label": f"Debian 13 ({label})",
            "min_ram_mib": ram, "min_disk_gib": 16,
            "requires_credentials": True, "graphical": True}


PROFILE = profile("xfce")
APPEND = "root=/dev/vda rw rootwait console=tty0 console=ttyS0 panic=-1"
SUITE = "trixie"
SECURITY_MIRROR = "http://security.debian.org/debian-security"
IMAGE_SIZE = 16 << 30
NETWORK_INTERFACES = """source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
"""
# The desktop's task plus its recommends mirrors a Debian ISO desktop install
# (for Xfce: desktop-base, xfce4-goodies, power-manager, notifyd, locker, apps,
# fonts). Guest integration packages stay excluded per the kernel-only control
# contract.
PACKAGES = ("systemd-sysv", "sudo", "dbus-x11", "dbus-user-session", "network-manager",
            "xserver-xorg-input-libinput", "iproute2", "iputils-ping",
            "procps", "psmisc", "less", "vim-tiny", "curl", "wget",
            "ca-certificates", "file", "bash-completion", "locales",
            "fonts-dejavu-core", "e2fsprogs", "keyboard-configuration",
            "console-setup", "tzdata")
# Installer-style answers. Values are checked again inside the new system
# against its locale, keyboard and time zone data.
DEFAULTS = {"desktop": "xfce", "hostname": "antinomie", "locale": "en_US.UTF-8",
            "keyboard_layout": "us",
            "keyboard_variant": "", "timezone": "Etc/UTC", "standard": False,
            "mirror": "http://deb.debian.org/debian", "proxy": ""}
PATTERNS = {"locale": r"[a-z]{2,3}(?:_[A-Z]{2})?(?:@[a-z]+)?\.UTF-8",
            "keyboard_layout": r"[a-z]{2,8}", "keyboard_variant": r"[a-z0-9_-]{0,32}",
            "timezone": r"[A-Z][A-Za-z_+-]*(?:/[A-Za-z0-9_+-]+){0,2}",
            "mirror": r"https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+",
            "proxy": r"(?:https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+)?"}
MIN_E2FSPROGS = (1, 47, 1)


def monitor_helpers():
    spec = importlib.util.spec_from_file_location(
        "monitor_image", REPO / "scripts/build-monitor-image.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def kernel_release(kernel):
    with kernel.open("rb") as source:
        header = source.read(0x210)
        if len(header) < 0x210 or header[0x202:0x206] != b"HdrS":
            raise RuntimeError("kernel must be an x86 Linux bzImage")
        source.seek(0x200 + struct.unpack_from("<H", header, 0x20e)[0])
        release = source.read(512).split(b"\0", 1)[0].decode("ascii")
    if not re.match(r"6\.12\.94(?:[- ]|$)", release):
        raise RuntimeError("kernel must retain pinned Linux 6.12.94")
    return release


def module_tree(modules, release):
    """Return the installed module directory matching the kernel release."""
    if modules is None:
        return None
    tree = modules / "lib/modules" / release.split()[0]
    if not (tree / "modules.dep").is_file():
        raise RuntimeError(f"--modules lacks lib/modules/{release.split()[0]}/modules.dep")
    return tree


def kernel_uses_modules(config):
    return config is not None and any(line.endswith("=m")
                                      for line in config.read_text().splitlines())


def initrd_provenance(root, provenance):
    notices = root / "usr/share/antinomie-initrd-provenance"
    files = {}
    packages = {}
    helpers = monitor_helpers()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path == root / "init":
            continue
        relative = str(path.relative_to(root))
        source = {"bin/busybox": Path("/usr/bin/busybox"),
                  "bin/resize2fs": Path(shutil.which("resize2fs"))}.get(
                      relative, Path("/") / relative)
        ownership = subprocess.check_output(
            ["dpkg-query", "--search", str(source.resolve())], text=True).splitlines()
        owner = ownership[0].split(": ", 1)[0]
        metadata = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n",
             owner], text=True).strip().split("\t")
        if len(metadata) != 5:
            raise RuntimeError("unexpected host package metadata for " + owner)
        packages[owner] = dict(zip(("package", "version", "architecture",
                                   "source_package", "source_version"), metadata))
        files["/" + relative] = {"package": owner, "sha256": helpers.checksum(path)}
    notices.mkdir(parents=True)
    for owner in sorted(packages):
        package = owner.split(":", 1)[0]
        target = notices / "packages" / package
        target.mkdir(parents=True)
        shutil.copy2(Path("/usr/share/doc") / package / "copyright", target / "copyright")
    shutil.copytree("/usr/share/common-licenses", notices / "common-licenses")
    shutil.copy2("/etc/os-release", notices / "host-os-release")
    shutil.copy2(REPO / "LICENSE", notices / "project-LICENSE")
    shutil.copy2(REPO / "scripts/build-monitor-image.py", notices / "bootstrap-recipe.py")
    record = {"packages": packages, "files": files,
              "origin": "Installed host packages copied into the bootstrap initrd",
              "recipe": "bootstrap-recipe.py:initrd_tree"}
    (notices / "packages.json").write_text(json.dumps(record, indent=2) + "\n")
    shutil.copytree(notices, provenance / "initrd")


def make_initrd(output, staging, provenance):
    root = staging / "initrd-tree"
    root.mkdir()
    monitor_helpers().initrd_tree(root)
    initrd_provenance(root, provenance)
    names = ["."] + [str(p.relative_to(root)) for p in sorted(root.rglob("*"))]
    cpio = subprocess.run(["cpio", "--create", "--format=newc", "--null", "--owner=0:0"],
                          cwd=root, input=b"\0".join(os.fsencode(n) for n in names) + b"\0",
                          capture_output=True, check=True)
    gzip = subprocess.run(["gzip", "-n", "-9"], input=cpio.stdout,
                          capture_output=True, check=True)
    output.write_bytes(gzip.stdout)


def options(values):
    """Validate installer answers; unknown keys are rejected."""
    unknown = set(values) - set(DEFAULTS)
    if unknown:
        raise RuntimeError("unknown image options: " + ", ".join(sorted(unknown)))
    result = {**DEFAULTS, **values}
    monitor_helpers().valid_hostname(result["hostname"])
    for key, pattern in PATTERNS.items():
        if not isinstance(result[key], str) or not re.fullmatch(pattern, result[key]):
            raise RuntimeError(f"invalid {key.replace('_', ' ')} {result[key]!r}")
    if ".." in result["timezone"]:
        raise RuntimeError("invalid time zone")
    if not isinstance(result["standard"], bool):
        raise RuntimeError("standard must be true or false")
    if result["desktop"] not in DESKTOPS:
        raise RuntimeError(f"unknown desktop {result['desktop']!r}")
    return result


def packages(desktop):
    """Packages to install: the common set plus the desktop's task."""
    task = DESKTOPS[desktop][0]
    extra = ("lightdm-gtk-greeter",) if desktop == "xfce" else ()
    return PACKAGES + (task,) + extra


def customization_script():
    """Run inside the new root: arguments hostname locale layout variant timezone
    display-manager session."""
    return """#!/bin/sh
set -eu
hostname=$1 locale=$2 layout=$3 variant=$4 zone=$5 manager=$6 session=$7
export DEBIAN_FRONTEND=noninteractive
test "$(. /etc/os-release; printf '%s' "$ID:$VERSION_ID")" = debian:13
test "$(dpkg --print-architecture)" = amd64
grep -qx "$locale UTF-8" /usr/share/i18n/SUPPORTED || { echo "unsupported locale $locale" >&2; exit 1; }
test -f "/usr/share/zoneinfo/$zone" || { echo "unknown time zone $zone" >&2; exit 1; }
test -f "/usr/share/xsessions/$session.desktop" || test -f "/usr/share/wayland-sessions/$session.desktop" || \\
    { echo "desktop session $session is not installed" >&2; exit 1; }
test "$(cat /etc/X11/default-display-manager)" = "/usr/sbin/$manager" || \\
    { echo "display manager is not $manager" >&2; exit 1; }
awk -v l="$layout" '/^! layout/ {s = 1; next} /^!/ {s = 0} s && $1 == l {f = 1} END {exit !f}' \\
    /usr/share/X11/xkb/rules/evdev.lst || { echo "unknown keyboard layout $layout" >&2; exit 1; }
if [ -n "$variant" ]; then
    awk -v v="$variant" -v l="$layout:" '/^! variant/ {s = 1; next} /^!/ {s = 0} s && $1 == v && $2 == l {f = 1} END {exit !f}' \\
        /usr/share/X11/xkb/rules/evdev.lst || { echo "unknown keyboard variant $variant for $layout" >&2; exit 1; }
fi
remove=$(dpkg-query -W -f='${binary:Package} ${db:Status-Status}\\n' | awk '$2 == "installed" && ($1 ~ /^openssh-server(:|$)/ || $1 ~ /^qemu-guest-agent(:|$)/ || $1 ~ /^spice-vdagent(:|$)/ || $1 ~ /^cloud-init/ || $1 ~ /^cloud-guest-utils(:|$)/ || $1 ~ /^linux-image-/) {print $1}')
if [ -n "$remove" ]; then
    apt-get -o APT::Get::AllowUnauthenticated=false -y purge $remove
fi
for unit in ssh.service sshd.service ssh.socket qemu-guest-agent.service spice-vdagentd.service cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service; do
    systemctl mask "$unit"
done
for name in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
    userdel -r "$name"
done
for name in $(awk -F: '$3 == 1000 {print $1}' /etc/group); do
    groupdel "$name"
done
passwd -l root
rm -f /etc/ssh/ssh_host_* /var/lib/dbus/machine-id
truncate -s 0 /etc/machine-id
mkdir -p /var/lib/antinomie-image
# No automatic or guest login; the chosen desktop is the default session.
case $manager in
lightdm)
    mkdir -p /etc/lightdm/lightdm.conf.d
    greeter=
    if [ "$session" = xfce ]; then greeter='greeter-session=lightdm-gtk-greeter\\n'; fi
    printf "[Seat:*]\\n${greeter}user-session=%s\\nautologin-user=\\nautologin-guest=false\\nallow-guest=false\\n" "$session" > /etc/lightdm/lightdm.conf.d/99-antinomie.conf
    ;;
gdm3)
    sed -i 's/^#*\\s*AutomaticLoginEnable\\s*=.*/AutomaticLoginEnable = false/' /etc/gdm3/daemon.conf
    ;;
sddm)
    mkdir -p /etc/sddm.conf.d
    printf '[Autologin]\\nUser=\\nSession=%s\\n' "$session" > /etc/sddm.conf.d/99-antinomie.conf
    ;;
esac
systemctl set-default graphical.target
printf '/dev/vda / ext4 defaults 0 1\\n' > /etc/fstab
printf '%s' """ + shlex.quote(NETWORK_INTERFACES) + """ > /etc/network/interfaces
printf '%s\\n' "$hostname" > /etc/hostname
printf '127.0.0.1\\tlocalhost\\n127.0.1.1\\t%s\\n\\n::1\\tlocalhost ip6-localhost ip6-loopback\\nff02::1\\tip6-allnodes\\nff02::2\\tip6-allrouters\\n' "$hostname" > /etc/hosts
printf '%s UTF-8\\n' "$locale" > /etc/locale.gen
locale-gen
printf 'LANG=%s\\n' "$locale" > /etc/default/locale
printf 'XKBMODEL="pc105"\\nXKBLAYOUT="%s"\\nXKBVARIANT="%s"\\nXKBOPTIONS=""\\n\\nBACKSPACE="guess"\\n' "$layout" "$variant" > /etc/default/keyboard
ln -sf "/usr/share/zoneinfo/$zone" /etc/localtime
printf '%s\\n' "$zone" > /etc/timezone
# Build-time apt settings (recommends, proxy) are not part of the image.
rm -f /etc/apt/apt.conf.d/99mmdebstrap
audit=$(dpkg --audit)
if [ -n "$audit" ]; then
    printf '%s\\n' "$audit" >&2
    exit 1
fi
apt-get -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false check
dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\t${source:Version}\\t${db:Status-Status}\\n' > /var/lib/antinomie-image/packages.tsv
apt-get clean
"""


def bootstrap_mode():
    return "root" if os.geteuid() == 0 else "unshare"


def mmdebstrap_command(values, tarball, script, provenance, modules=None):
    """The mmdebstrap invocation; hooks run as (namespace) root with "$1" the new root."""
    q = shlex.quote
    command = ["mmdebstrap", "--mode=" + bootstrap_mode(),
               "--variant=" + ("standard" if values["standard"] else "important"),
               "--architectures=amd64", "--format=tar",
               "--include=" + ",".join(packages(values["desktop"])),
               "--aptopt=APT::Install-Recommends \"true\"",
               "--aptopt=APT::Get::AllowUnauthenticated \"false\"",
               "--aptopt=Acquire::AllowInsecureRepositories \"false\"",
               "--aptopt=Acquire::Retries \"3\""]
    if values["proxy"]:
        command.append(f'--aptopt=Acquire::http::Proxy "{values["proxy"]}"')
        command.append(f'--aptopt=Acquire::https::Proxy "{values["proxy"]}"')
    command.append(f'--customize-hook=cp {q(str(script))} "$1/tmp/antinomie-customize.sh"')
    if modules is not None:
        command.append('--customize-hook=mkdir -p "$1/usr/lib/modules"')
        command.append(f'--customize-hook=cp -a {q(str(modules))} "$1/usr/lib/modules/"')
        command.append(f'--customize-hook=chown -R 0:0 "$1/usr/lib/modules/{modules.name}"')
    manager, session = DESKTOPS[values["desktop"]][1:3]
    arguments = " ".join([q(values[key]) for key in
                          ("hostname", "locale", "keyboard_layout", "keyboard_variant", "timezone")]
                         + [q(manager), q(session)])
    command.append(f'--customize-hook=chroot "$1" sh /tmp/antinomie-customize.sh {arguments}')
    command.append('--customize-hook=rm -f "$1/tmp/antinomie-customize.sh"')
    for path in ("/var/lib/antinomie-image/packages.tsv", "/etc/os-release"):
        command.append(f'--customize-hook=cp "$1{path}" {q(str(provenance / Path(path).name))}')
    for path, name in (("usr/share/doc", "package-docs.tar.gz"), ("var/lib/apt/lists", "apt-lists.tar.gz")):
        command.append(f'--customize-hook=tar -C "$1" -czf {q(str(provenance / name))} {path}')
    mirror = values["mirror"].rstrip("/")
    command += [SUITE, str(tarball),
                f"deb {mirror} {SUITE} main", f"deb {mirror} {SUITE}-updates main",
                f"deb {SECURITY_MIRROR} {SUITE}-security main"]
    return command


def e2fsprogs_version():
    output = subprocess.run(["mke2fs", "-V"], capture_output=True, text=True).stderr
    match = re.search(r"mke2fs (\d+)\.(\d+)(?:\.(\d+))?", output)
    if not match:
        raise RuntimeError("cannot read the mke2fs version")
    return tuple(int(part or 0) for part in match.groups())


def apply_xattrs(tarball, raw, staging, log):
    """mkfs.ext4 -d drops extended attributes from a tarball; set them again (capabilities)."""
    commands = []
    values = staging / "xattr-values"
    values.mkdir()
    with tarfile.open(tarball) as archive:
        for member in archive:
            for key, value in member.pax_headers.items():
                if not key.startswith("SCHILY.xattr."):
                    continue
                name = key[len("SCHILY.xattr."):]
                name_in_tar = member.name[2:] if member.name.startswith("./") else member.name
                path = "/" + name_in_tar.strip("/") if name_in_tar not in ("", ".") else "/"
                if any(c in path for c in '"\n') or any(c in name for c in '" \n'):
                    raise RuntimeError(f"unsupported extended attribute entry {path!r}")
                data = values / str(len(commands))
                data.write_bytes(value.encode("utf-8", "surrogateescape"))
                commands.append(f'ea_set -f {data} "{path}" {name}')
    if commands:
        script = staging / "xattrs.debugfs"
        script.write_text("\n".join(commands) + "\n")
        subprocess.run(["debugfs", "-w", "-f", str(script), str(raw)], check=True,
                       stdout=log, stderr=subprocess.STDOUT)
    shutil.rmtree(values)
    return len(commands)


def debugfs_cat(raw, path):
    return subprocess.run(["debugfs", "-R", f"cat {path}", str(raw)], check=True,
                          capture_output=True, text=True).stdout


def validate_image(raw):
    if debugfs_cat(raw, "/etc/fstab") != "/dev/vda / ext4 defaults 0 1\n":
        raise RuntimeError("image has unexpected fstab")
    shadow = debugfs_cat(raw, "/etc/shadow").splitlines()
    if not any(line.startswith(("root:!", "root:*")) for line in shadow):
        raise RuntimeError("base root password must be locked")
    passwd = debugfs_cat(raw, "/etc/passwd").splitlines()
    if any(1000 <= int(line.split(":")[2]) < 65534 for line in passwd):
        raise RuntimeError("base must not contain preset ordinary user accounts")
    groups = debugfs_cat(raw, "/etc/group").splitlines()
    if any(int(line.split(":")[2]) == 1000 for line in groups):
        raise RuntimeError("base must leave GID 1000 free for per-VM credentials")


def root_image(values, raw, staging, provenance, log, modules=None):
    tarball = staging / "rootfs.tar"
    script = staging / "customize.sh"
    script.write_text(customization_script())
    shutil.copy2(script, provenance / "customize.sh")
    command = mmdebstrap_command(values, tarball, script, provenance, modules)
    (provenance / "mmdebstrap.json").write_text(json.dumps(command, indent=2) + "\n")
    # mmdebstrap assembles the system in $TMPDIR; /tmp is a small tmpfs on
    # Debian 13 (and in the cloud builder), far too small for a desktop.
    subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT,
                   env=os.environ | {"TMPDIR": str(staging)})
    with raw.open("xb") as target:
        target.truncate(IMAGE_SIZE)
    subprocess.run(["mkfs.ext4", "-q", "-F", "-L", "antinomie", "-d", str(tarball), str(raw)],
                   check=True, stdout=log, stderr=subprocess.STDOUT)
    xattrs = apply_xattrs(tarball, raw, staging, log)
    tarball.unlink()
    validate_image(raw)
    return {"bootstrap": "mmdebstrap", "mode": bootstrap_mode(),
            "variant": "standard" if values["standard"] else "important",
            "suite": SUITE, "mirror": values["mirror"], "security_mirror": SECURITY_MIRROR,
            "root_filesystem": "ext4", "root_size": IMAGE_SIZE,
            "conversion": "mkfs.ext4 -d tarball; extended attributes set with debugfs",
            "extended_attributes": xattrs,
            "kernel_modules": None if modules is None else f"/usr/lib/modules/{modules.name}"}


def build(kernel, output, kernel_config=None, modules=None, allow_unversioned=False,
          values=None, work=None):
    if output.exists():
        raise RuntimeError("output already exists; choose a new unpublished bundle path")
    values = options(values or {})
    release = kernel_release(kernel)
    if kernel_uses_modules(kernel_config) and modules is None:
        raise RuntimeError("kernel config builds modules; pass --modules with its install root")
    tree = module_tree(modules, release)
    helpers = monitor_helpers()
    helpers.fixed_display_config(kernel_config, kernel)
    helpers.stamp_revision({}, kernel, allow_unversioned)
    if e2fsprogs_version() < MIN_E2FSPROGS:
        raise RuntimeError("mkfs.ext4 from e2fsprogs 1.47.1 or newer is required (tarball input)")
    output.parent.mkdir(parents=True, exist_ok=True)
    work = work or output.parent
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="debian-image-", dir=work) as name:
        staging = Path(name)
        bundle = staging / "bundle"
        provenance = bundle / "provenance"
        provenance.mkdir(parents=True)
        shutil.copy2(kernel, bundle / "kernel")
        raw = staging / "root.raw"
        log_path = staging / "bootstrap.log"
        try:
            with log_path.open("w") as log:
                root = root_image(values, raw, staging, provenance, log, tree)
        except (RuntimeError, subprocess.CalledProcessError):
            # The log dies with the staging directory; show why it failed.
            lines = log_path.read_text(errors="replace").splitlines()
            print("--- last bootstrap log lines ---", flush=True)
            print("\n".join(lines[-80:]), flush=True)
            raise
        shutil.copy2(log_path, provenance / "bootstrap.log")
        subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "qcow2",
                        str(raw), str(bundle / "base.qcow2")], check=True)
        raw.unlink()
        make_initrd(bundle / "initrd.gz", staging, provenance)
        hashes = {item: helpers.checksum(bundle / item)
                  for item in ("kernel", "initrd.gz", "base.qcow2")}
        record = {"built_at": datetime.now(timezone.utc).isoformat(),
                  "options": values, "root": root,
                  "apt_authentication": "Debian signed indexes; insecure repositories disallowed",
                  "package_install_recommends": True,
                  "requested_packages": list(packages(values["desktop"])),
                  "package_inventory": "packages.tsv",
                  "kernel_sha256": hashes["kernel"], "kernel_release": release,
                  "tools": {tool: subprocess.run([tool, "--version"], capture_output=True,
                                                 text=True).stdout.strip().splitlines()[0]
                            for tool in ("mmdebstrap", "qemu-img")}}
        record["provenance_sha256"] = {str(p.relative_to(provenance)): helpers.checksum(p)
            for p in sorted(provenance.rglob("*")) if p.is_file()}
        (provenance / "build.json").write_text(json.dumps(record, indent=2) + "\n")
        manifest = {"format": 1, "kernel_version": "6.12.94", "schema_id": 1,
                    "kernel": "kernel", "initrd": "initrd.gz", "base_disk": "base.qcow2",
                    "kernel_append": APPEND, "guest": profile(values["desktop"]),
                    "sha256": hashes}
        helpers.stamp_revision(manifest, bundle / "kernel", allow_unversioned)
        if helpers.fixed_display_config(kernel_config, bundle / "kernel"):
            manifest["fixed_display"] = True
            shutil.copy2(kernel_config, provenance / "kernel.config")
            helpers.fixed_display_config(provenance / "kernel.config", bundle / "kernel")
            manifest["kernel_config_sha256"] = helpers.checksum(provenance / "kernel.config")
            manifest["build_provenance"] = {"parent_identity": None,
                "kernel_sha256": hashes["kernel"], "base_disk_sha256": hashes["base.qcow2"],
                "initrd_sha256": hashes["initrd.gz"],
                "kernel_config_sha256": manifest["kernel_config_sha256"]}
        (bundle / "bundle.json").write_text(json.dumps(manifest, indent=2) + "\n")
        # Publish only a completed bundle, never overwrite an existing base.
        bundle.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--kernel-config", type=Path,
                        help="matching kernel .config; validates built-in fixed-display support")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--modules", type=Path,
                        help="modules_install root (INSTALL_MOD_PATH) matching the kernel")
    parser.add_argument("--allow-unversioned", action="store_true",
                        help="accept a development kernel without a source id")
    parser.add_argument("--options", type=Path,
                        help="JSON object of installer answers (hostname, locale, keyboard_layout, "
                             "keyboard_variant, timezone, standard, mirror, proxy)")
    parser.add_argument("--work", type=Path, help="directory for temporary build files")
    args = parser.parse_args()
    if not args.kernel.is_file():
        parser.error("an existing patched Linux 6.12.94 kernel is required")
    for tool in ("mmdebstrap", "mkfs.ext4", "mke2fs", "debugfs", "qemu-img", "cpio", "gzip",
                 "busybox", "resize2fs", "dpkg-query", "tar"):
        if shutil.which(tool) is None:
            parser.error("required installed tool missing: " + tool)
    try:
        values = json.loads(args.options.read_text()) if args.options else {}
        if not isinstance(values, dict):
            raise RuntimeError("options must be a JSON object")
        build(args.kernel, args.output, args.kernel_config, args.modules,
              args.allow_unversioned, values, args.work)
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, "Debian image build failed: " + str(error) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
