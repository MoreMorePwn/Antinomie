#!/usr/bin/env python3
"""Build a rootless Debian 13 Xfce bundle for the pinned Antinomie kernel."""
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
import tempfile

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "work/debian-xfce-base"
PROFILE = {"id": "debian-xfce", "label": "Debian 13 (Xfce)",
           "min_ram_mib": 2048, "min_disk_gib": 16,
           "requires_credentials": True, "graphical": True}
APPEND = "root=/dev/vda rw rootwait console=tty0 console=ttyS0 panic=-1"
NETWORK_INTERFACES = """source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
"""
# task-xfce-desktop plus its recommends mirrors a Debian ISO Xfce install
# (desktop-base, xfce4-goodies, power-manager, notifyd, locker, apps, fonts).
# Guest integration packages stay excluded per the kernel-only control contract.
PACKAGES = ("systemd-sysv", "task-xfce-desktop", "lightdm-gtk-greeter",
            "sudo", "dbus-x11", "dbus-user-session", "network-manager",
            "xserver-xorg-input-libinput", "iproute2", "iputils-ping",
            "procps", "psmisc", "less", "vim-tiny", "curl", "wget",
            "ca-certificates", "file", "bash-completion", "locales",
            "fonts-dejavu-core", "e2fsprogs")


def monitor_helpers():
    spec = importlib.util.spec_from_file_location(
        "monitor_image", REPO / "scripts/build-monitor-image.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def appliance_environment():
    env = os.environ.copy()
    env["LIBGUESTFS_BACKEND"] = "direct"
    # Honor neither inherited tracing nor a libvirt backend for this build.
    env.pop("LIBGUESTFS_DEBUG", None)
    env.pop("LIBGUESTFS_TRACE", None)
    return env


def customization_script():
    return """#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
test "$(. /etc/os-release; printf '%s' "$ID:$VERSION_ID")" = debian:13
test "$(dpkg --print-architecture)" = amd64
# The direct libguestfs backend owns this temporary slirp network namespace.
# Some host appliances omit their DHCP client; no network config is persisted.
ip link set eth0 up
ip addr replace 169.254.2.15/16 dev eth0
ip route replace default via 169.254.2.2 dev eth0
resolver_backup=/etc/resolv.conf.antinomie-build
test ! -e "$resolver_backup" && test ! -L "$resolver_backup"
if [ -e /etc/resolv.conf ] || [ -L /etc/resolv.conf ]; then
    mv /etc/resolv.conf "$resolver_backup"
fi
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        printf 'Customization failed; isolated appliance kernel diagnostics follow.\\n' >&2
        dmesg --level=err,warn | tail -n 80 >&2 || true
        cat /proc/meminfo >&2 || true
    fi
    rm -f /usr/sbin/policy-rc.d /etc/resolv.conf
    if [ -e "$resolver_backup" ] || [ -L "$resolver_backup" ]; then
        mv "$resolver_backup" /etc/resolv.conf
    fi
    exit "$status"
}
trap cleanup EXIT
printf 'nameserver 169.254.2.3\\n' > /etc/resolv.conf
printf '#!/bin/sh\\nexit 101\\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
apt-get -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false -o APT::Update::Error-Mode=any -o Acquire::Retries=1 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update
apt-get -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false -o Acquire::Retries=1 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -y install """ + " ".join(PACKAGES) + """
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
rm -rf /var/lib/cloud /var/lib/guestfs
mkdir -p /etc/lightdm/lightdm.conf.d /var/lib/antinomie-image
printf '[Seat:*]\\ngreeter-session=lightdm-gtk-greeter\\nuser-session=xfce\\nautologin-user=\\nautologin-guest=false\\nallow-guest=false\\n' > /etc/lightdm/lightdm.conf.d/99-antinomie.conf
systemctl set-default graphical.target
printf '/dev/vda / ext4 defaults 0 1\\n' > /etc/fstab
printf '%s' """ + shlex.quote(NETWORK_INTERFACES) + """ > /etc/network/interfaces
audit=$(dpkg --audit)
if [ -n "$audit" ]; then
    printf '%s\\n' "$audit" >&2
    exit 1
fi
apt-get -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false check
dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\t${source:Version}\\t${db:Status-Status}\\n' > /var/lib/antinomie-image/packages.tsv
apt-get clean
"""


def builder_command(source, customization, cache):
    return ["virt-builder", "debian-13", "--arch", "x86_64",
            "--check-signature", "--format", "raw", "--size", "16G",
            "--output", str(source), "--cache", str(cache), "--memsize", "2048",
            "--smp", "4", "--network", "--root-password", "disabled",
            "--hostname", "antinomie", "--run", str(customization), "--no-logfile"]


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


class Guestfish:
    """Own one isolated appliance; remote commands use argv, never a shell."""
    def __init__(self, images, log):
        command = ["guestfish", "--listen"]
        for image in images:
            command.extend(["--format=raw", "-a", str(image)])
        result = subprocess.run(command, env=appliance_environment(), check=True,
                                stdout=subprocess.PIPE, stderr=log, text=True)
        match = re.search(r"GUESTFISH_PID=(\d+)", result.stdout)
        if not match:
            raise RuntimeError("guestfish did not report its owned appliance PID")
        self.pid = match.group(1)
        self.log = log

    def __enter__(self):
        try:
            self.command("run")
        except BaseException:
            self.command("exit")
            raise
        return self

    def command(self, *args):
        result = subprocess.run(["guestfish", "--remote=" + self.pid, *args],
                                env=appliance_environment(), check=True,
                                stdout=subprocess.PIPE, stderr=self.log, text=True)
        return result.stdout.strip()

    def __exit__(self, kind, value, traceback):
        self.command("exit")


def validate_root(guest, root):
    if (guest.command("inspect-get-distro", root) != "debian"
            or guest.command("inspect-get-major-version", root) != "13"
            or guest.command("inspect-get-arch", root) != "x86_64"):
        raise RuntimeError("template must contain Debian 13 amd64")
    if guest.command("vfs-type", root) != "ext4":
        raise RuntimeError("template root filesystem must be ext4")


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


def convert_root(source, raw, provenance, log, modules=None):
    with raw.open("xb") as target:
        target.truncate(16 << 30)
    with Guestfish([source, raw], log) as guest:
        roots = guest.command("inspect-os").splitlines()
        if len(roots) != 1:
            raise RuntimeError("template must have exactly one inspected OS root")
        root = roots[0]
        validate_root(guest, root)
        source_size = int(guest.command("blockdev-getsize64", root))
        if source_size > 16 << 30:
            raise RuntimeError("template root exceeds the 16 GiB whole-disk layout")
        guest.command("mount-ro", root, "/")
        guest.command("download", "/var/lib/antinomie-image/packages.tsv",
                      str(provenance / "packages.tsv"))
        guest.command("download", "/etc/os-release", str(provenance / "os-release"))
        guest.command("tar-out", "/usr/share/doc", str(provenance / "package-docs.tar.gz"),
                      "compress:gzip")
        guest.command("tar-out", "/var/lib/apt/lists", str(provenance / "apt-lists.tar.gz"),
                      "compress:gzip")
        guest.command("umount-all")
        # Exact ext4 block copy preserves inode owners, ACLs, xattrs and capabilities.
        guest.command("copy-device-to-device", root, "/dev/sdb", "sparse:true")
        guest.command("e2fsck", "/dev/sdb", "correct:true")
        guest.command("resize2fs", "/dev/sdb")
        guest.command("mount", "/dev/sdb", "/")
        if guest.command("cat", "/etc/fstab") != "/dev/vda / ext4 defaults 0 1":
            raise RuntimeError("converted root has unexpected fstab")
        if modules is not None:
            # Debian 13 is merged-/usr; /lib/modules resolves to /usr/lib/modules.
            archive = raw.parent / "modules.tar"
            subprocess.run(["tar", "--create", "--file", str(archive), "--owner=0",
                            "--group=0", "--numeric-owner", "--directory",
                            str(modules.parent), modules.name], check=True)
            guest.command("mkdir-p", "/usr/lib/modules")
            guest.command("tar-in", str(archive), "/usr/lib/modules")
            archive.unlink()
            if not guest.command("exists", f"/usr/lib/modules/{modules.name}/modules.dep") == "true":
                raise RuntimeError("kernel modules did not reach the converted root")
        shadow = guest.command("cat", "/etc/shadow").splitlines()
        if not any(line.startswith(("root:!", "root:*")) for line in shadow):
            raise RuntimeError("base root password must be locked")
        passwd = guest.command("cat", "/etc/passwd").splitlines()
        if any(1000 <= int(line.split(":")[2]) < 65534 for line in passwd):
            raise RuntimeError("base must not contain preset ordinary user accounts")
        groups = guest.command("cat", "/etc/group").splitlines()
        if any(int(line.split(":")[2]) == 1000 for line in groups):
            raise RuntimeError("base must leave GID 1000 free for per-VM credentials")
        guest.command("umount-all")
    return {"root_device": root, "root_filesystem": "ext4", "root_size": source_size,
            "copy": "libguestfs copy-device-to-device; exact filesystem blocks",
            "kernel_modules": None if modules is None else f"/usr/lib/modules/{modules.name}"}


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


def assemble_bundle(kernel, output, staging, template_entry, cache, kernel_config=None,
                    modules=None):
    if output.exists():
        raise RuntimeError("output already exists; choose a new unpublished bundle path")
    helpers = monitor_helpers()
    bundle = staging / "bundle"
    provenance = bundle / "provenance"
    release = kernel_release(bundle / "kernel")
    raw = staging / "root.raw"
    conversion_log = output.parent / (output.name + "-conversion.log")
    with conversion_log.open("w") as log:
        conversion = convert_root(staging / "template.raw", raw, provenance, log,
                                  module_tree(modules, release))
    shutil.copy2(conversion_log, provenance / "conversion.log")
    subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "qcow2",
                    str(raw), str(bundle / "base.qcow2")], check=True)
    make_initrd(bundle / "initrd.gz", staging, provenance)
    hashes = {item: helpers.checksum(bundle / item)
              for item in ("kernel", "initrd.gz", "base.qcow2")}
    record = {"built_at": datetime.now(timezone.utc).isoformat(),
              "template": template_entry, "template_signatures": "required",
              "template_checksums": "virt-builder signed catalog SHA-512 verification",
              "apt_authentication": "Debian signed indexes; insecure repositories disallowed",
              "package_install_recommends": False,
              "requested_packages": list(PACKAGES), "package_inventory": "packages.tsv",
              "package_upgrade_policy": "Install explicit package closure; no blanket distro upgrade",
              "conversion": conversion,
              "kernel_input": str(kernel.resolve()), "kernel_sha256": hashes["kernel"],
              "kernel_release": release,
              "template_cache_sha256": {p.name: helpers.checksum(p)
                  for p in sorted(cache.iterdir()) if p.is_file()},
              "tools": {tool: subprocess.check_output([tool, "--version"], text=True).strip()
                        for tool in ("virt-builder", "guestfish", "qemu-img")}}
    record["provenance_sha256"] = {str(p.relative_to(provenance)): helpers.checksum(p)
        for p in sorted(provenance.rglob("*")) if p.is_file()}
    (provenance / "build.json").write_text(json.dumps(record, indent=2) + "\n")
    manifest = {"format": 1, "kernel_version": "6.12.94", "schema_id": 1,
                "kernel": "kernel", "initrd": "initrd.gz", "base_disk": "base.qcow2",
                "kernel_append": APPEND, "guest": PROFILE, "sha256": hashes}
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


def build(kernel, output, kernel_config=None, modules=None):
    if output.exists():
        raise RuntimeError("output already exists; choose a new unpublished bundle path")
    release = kernel_release(kernel)
    if kernel_uses_modules(kernel_config) and modules is None:
        raise RuntimeError("kernel config builds modules; pass --modules with its install root")
    module_tree(modules, release)
    monitor_helpers().fixed_display_config(kernel_config, kernel)
    output.parent.mkdir(parents=True, exist_ok=True)
    env = appliance_environment()
    with tempfile.TemporaryDirectory(prefix="debian-image-", dir=output.parent) as name:
        staging = Path(name)
        bundle = staging / "bundle"
        provenance = bundle / "provenance"
        provenance.mkdir(parents=True)
        shutil.copy2(kernel, bundle / "kernel")
        kernel_release(bundle / "kernel")
        script = staging / "customize.sh"
        script.write_text(customization_script())
        script.chmod(0o700)
        shutil.copy2(script, provenance / "customize.sh")
        catalog = subprocess.run(["virt-builder", "--list", "--list-format=json",
                                  "--check-signature"], env=env, capture_output=True,
                                 check=True, text=True)
        catalog_data = json.loads(catalog.stdout)
        entries = [entry for entry in catalog_data["templates"]
                   if entry["os-version"] == "debian-13" and entry["arch"] == "x86_64"]
        if len(entries) != 1:
            raise RuntimeError("authenticated catalog must list one Debian 13 amd64 template")
        (provenance / "catalog.json").write_text(catalog.stdout)
        (provenance / "catalog-verification.log").write_text(catalog.stderr)
        configs = provenance / "virt-builder-repos"
        configs.mkdir()
        for config in sorted(Path("/etc/virt-builder/repos.d").glob("*")):
            if config.is_file():
                shutil.copy2(config, configs / config.name)
        cache = REPO / "work/debian-template-cache"
        cache.mkdir(parents=True, exist_ok=True)
        source = staging / "template.raw"
        command = builder_command(source, script, cache)
        builder_log = output.parent / (output.name + "-builder.log")
        with builder_log.open("w") as log:
            subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        shutil.copy2(builder_log, provenance / "builder.log")
        assemble_bundle(kernel, output, staging, entries[0], cache, kernel_config, modules)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--kernel-config", type=Path,
                        help="matching kernel .config; validates built-in fixed-display support")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--modules", type=Path,
                        help="modules_install root (INSTALL_MOD_PATH) matching the kernel")
    args = parser.parse_args()
    if not args.kernel.is_file():
        parser.error("an existing patched Linux 6.12.94 kernel is required")
    for tool in ("virt-builder", "guestfish", "qemu-img", "cpio", "gzip", "busybox", "resize2fs", "dpkg-query"):
        if shutil.which(tool) is None:
            parser.error("required installed tool missing: " + tool)
    try:
        build(args.kernel, args.output, args.kernel_config, args.modules)
    except (RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, "Debian image build failed: " + str(error) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
