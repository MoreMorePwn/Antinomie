# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""The BusyBox camera base (profile busybox-extra): the BusyBox base as a
lived-in camera or DVR, the device IoT bots (Mirai, Gafgyt and relatives) go
for. scripts/build-monitor-image.py --profile busybox-extra builds it.

On top of the BusyBox base it has the device's services (BusyBox telnetd on 23
with the maker's default root password, the stand-in vendor program on 80, 554
and the vendor port, crond, syslogd and klogd to /var/log/messages, the DHCP
client kept running), the kernel's extra devices (softdog's /dev/watchdog,
flash in /proc/mtd and /dev/mtdN, iptables from Debian's pinned packages on the
glibc runtime), and the identity of one device profile (DEVICE_PROFILES):
model, firmware version and build date in vendor-style files, hostname and
the maker's MAC prefix.

Nothing here depends on the guest architecture except the Debian packages'
pins and the compiler that builds the vendor program (COMPILERS): the
arm32 and MIPS bases add theirs.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess

REPO = Path(__file__).resolve().parent.parent
CAMERA_SOURCE = REPO / "src/antinomie/packaging/busybox-extra/camera.c"
# The flags of a freestanding static program: no C library, no start files,
# nothing of the build host's libraries in it.
CAMERA_FLAGS = ("-std=c11", "-Os", "-static", "-nostdlib", "-ffreestanding", "-fno-builtin",
                "-fno-stack-protector", "-fno-pie", "-no-pie", "-fno-asynchronous-unwind-tables",
                "-fno-unwind-tables", "-Wall", "-Wextra", "-Werror", "-Wl,--build-id=none",
                "-Wl,-z,noexecstack", "-s")
# The compilers that build the vendor program, first found wins: Debian 13's
# names (as the kernel script uses), then the host's own for its architecture.
COMPILERS = {"x86_64": ("x86_64-linux-gnu-gcc-14", "x86_64-linux-gnu-gcc", "gcc"),
             "arm64": ("aarch64-linux-gnu-gcc-14", "aarch64-linux-gnu-gcc")}

# iptables (legacy tables, as on the devices) from Debian 13's packages of the
# guest's architecture, on the base's glibc runtime: the multi-call binary,
# libxtables, libip4tc, libip6tc and the extensions those alone serve.
PACKAGES = {
    "x86_64": (
        ("iptables", "1.8.11-2",
         "95ba166bb68a76ca1513196dd59d91e3c33b2096884c6de80406f302b18a030e"),
        ("libxtables12", "1.8.11-2",
         "4de5aa59faef5e98d6ba9f5f521a915be5641f224f597862f8d29e8319e8db16"),
        ("libip4tc2", "1.8.11-2",
         "762e4d9c7f86b3fdaefee2baf61ce40073d46d7602651433f2cb7a5eabfb47b4"),
        ("libip6tc2", "1.8.11-2",
         "d5ecaad5595dc88d08f317997beb53a4906c45ea79ee14ec89103f72573e3f99"),
    ),
    "arm64": (
        ("iptables", "1.8.11-2",
         "441a3c4b202f83cb1c2609c9eff768229ce991c2f49bea37416168028bc23e95"),
        ("libxtables12", "1.8.11-2",
         "b200a559a4ae1b4ebcee4fb0fcaef6a16ef01abbe3da8887de15e800b1a6440d"),
        ("libip4tc2", "1.8.11-2",
         "e2d86b0b1b5d06b529cf60f3876970b02c1ae1147555bfcf1c5b17bfdae992ca"),
        ("libip6tc2", "1.8.11-2",
         "3ab7581ae06d0b7109ec60907a063ef167446e492f30918dcb20faed810d172d"),
    ),
}
IPTABLES_LIBRARIES = ("libxtables.so.12", "libip4tc.so.2", "libip6tc.so.2")
# The names iptables-legacy answers to (Debian makes iptables and ip6tables
# alternatives; the devices have the legacy tool under these names).
IPTABLES_NAMES = ("iptables", "iptables-save", "iptables-restore", "ip6tables", "ip6tables-save",
                  "ip6tables-restore", "iptables-legacy", "iptables-legacy-save",
                  "iptables-legacy-restore", "ip6tables-legacy", "ip6tables-legacy-save",
                  "ip6tables-legacy-restore")

# One device profile per entry; the first is the default. A profile names the
# device (maker, model, firmware and its build date), the hostname, the
# maker's MAC prefix (IEEE registration), the vendor program and its vendor
# port, the default telnet root password (as published in device default
# credential lists), the SPI flash's driver name and partitions (KiB; the
# last takes the rest), and the kernel release the device runs (shown in
# uname only by a kernel with 0.10.0's device facade; recorded meanwhile).
DEVICE_PROFILES = {
    "dahua-xvr": {
        "kind": "dvr",
        "maker": "Dahua",
        "model": "DH-XVR5104HS-I3",
        "firmware": "V4.001.0000000.4.R",
        "build_date": "2022-06-14",
        "hostname": "xvr",
        "mac_prefix": "3c:ef:8c",
        "program": "/usr/bin/sonia",
        "vendor_port": 37777,
        "telnet_password": "vizxv",
        "flash": {"name": "hi_sfc", "size_kib": 16384, "erase_kib": 64,
                  "partitions": (("boot", 256), ("kernel", 2048), ("rootfs", 12288),
                                 ("config", None))},
        "kernel_release": "3.18.20",
    },
}
DEFAULT_DEVICE = next(iter(DEVICE_PROFILES))
# The settings partition, mounted where the devices' firmware keeps it.
SETTINGS_MOUNT = "/mnt/mtd"


def device_profile(name=None):
    name = name or DEFAULT_DEVICE
    if name not in DEVICE_PROFILES:
        raise RuntimeError(f"unknown device profile {name!r} (one of: "
                           + ", ".join(DEVICE_PROFILES) + ")")
    return name, DEVICE_PROFILES[name]


def md5_crypt(password, salt):
    """crypt(3)'s MD5 scheme ($1$), as BusyBox's login checks it."""
    alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    password, salt = password.encode(), salt.encode()[:8]
    alternate = hashlib.md5(password + salt + password).digest()
    context = hashlib.md5(password + b"$1$" + salt)
    for start in range(0, len(password), 16):
        context.update(alternate[:min(16, len(password) - start)])
    length = len(password)
    while length:
        context.update(b"\0" if length & 1 else password[:1])
        length >>= 1
    digest = context.digest()
    for round_ in range(1000):
        step = hashlib.md5()
        step.update(password if round_ & 1 else digest)
        if round_ % 3:
            step.update(salt)
        if round_ % 7:
            step.update(password)
        step.update(digest if round_ & 1 else password)
        digest = step.digest()
    text = ""
    for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
        value = digest[a] << 16 | digest[b] << 8 | digest[c]
        for _ in range(4):
            text += alphabet[value & 63]
            value >>= 6
    value = digest[11]
    for _ in range(2):
        text += alphabet[value & 63]
        value >>= 6
    return f"$1${salt.decode()}${text}"


def password_salt(device_name):
    """A fixed salt per profile (the base is reproducible), from crypt's alphabet."""
    alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    digest = hashlib.sha256(b"antinomie-busybox-extra:" + device_name.encode()).digest()
    return "".join(alphabet[byte & 63] for byte in digest[:8])


def mtdparts(flash):
    """The mtdparts= boot option of the flash layout."""
    parts = [f"{size}k({name})" if size else f"-({name})" for name, size in flash["partitions"]]
    return f"mtdparts={flash['name']}:" + ",".join(parts)


def compiler(arch):
    for name in COMPILERS[arch]:
        if shutil.which(name):
            return name
    raise RuntimeError(f"no compiler for the {arch} vendor program (one of: "
                       + ", ".join(COMPILERS[arch]) + ")")


def build_camera(arch, vendor_port, output):
    """Compile the stand-in vendor program for arch into output."""
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([compiler(arch), *CAMERA_FLAGS, f"-DCAMERA_VENDOR_PORT={int(vendor_port)}",
                    "-o", str(output), str(CAMERA_SOURCE)], check=True)
    output.chmod(0o755)
    return output


def install_iptables(root, userland, image):
    """iptables-legacy and its libraries in /lib, beside glibc's runtime (the
    loader searches /lib), and the extensions in the directory libxtables was
    built to load them from; an extension that needs a library the base does
    not have is left out."""
    tree = userland.tree
    multi = userland.program("xtables-legacy-multi")
    image.install_file(multi, root, "/usr/sbin/xtables-legacy-multi", userland)
    for name in IPTABLES_NAMES:
        (root / "usr/sbin" / name).symlink_to("xtables-legacy-multi")
    # What the base's /lib serves: glibc's runtime (an arm64 program names its
    # loader too) and the iptables libraries.
    loader = Path(image.GLIBC_LOADERS[userland.arch]).name
    have = set(image.GLIBC_LIBRARIES) | set(IPTABLES_LIBRARIES) | {loader}
    for name in IPTABLES_LIBRARIES:
        found = next((library for directory in userland.library_dirs
                      if (library := image.tree_file(tree, f"{directory}/{name}"))), None)
        if found is None:
            raise RuntimeError(f"{name} (for iptables) is not in the pinned packages")
        needed, _ = image.elf_needs(found)
        if missing := sorted(set(needed) - have):
            raise RuntimeError(f"{name} needs {', '.join(missing)}, which the base lacks")
        image.install_file(found, root, f"/lib/{name}", userland)
    needed, _ = image.elf_needs(multi)
    if missing := sorted(set(needed) - have):
        raise RuntimeError(f"xtables-legacy-multi needs {', '.join(missing)}, which the base lacks")
    extensions = tree / userland.library_dirs[0] / "xtables"
    target = root / userland.library_dirs[0] / "xtables"
    target.mkdir(parents=True, exist_ok=True)
    kept = set()
    for extension in sorted(extensions.iterdir()):
        # ebtables' and arptables' extensions serve only the nft tools.
        if extension.is_symlink() or not extension.name.endswith(".so") \
                or extension.name.startswith(("libebt_", "libarpt_")):
            continue
        needed, _ = image.elf_needs(extension)
        if set(needed) <= have:
            image.install_file(extension, root, f"/{userland.library_dirs[0]}/xtables/"
                               + extension.name, userland)
            kept.add(extension.name)
    for extension in sorted(extensions.iterdir()):
        if extension.is_symlink() and Path(extension.readlink()).name in kept:
            (target / extension.name).symlink_to(extension.readlink())
    return sorted(kept)


def edit(path, anchor, text, replace=False, after=False):
    """Insert text before (or after) the one occurrence of anchor in path, or
    put it in the anchor's place."""
    content = path.read_text()
    if content.count(anchor) != 1:
        raise RuntimeError(f"{path.name}: expected one {anchor.strip()!r}")
    new = text if replace else anchor + text if after else text + anchor
    path.write_text(content.replace(anchor, new))


def services(device):
    """The base's own services (bundle.json base_services): their processes,
    files and traffic are the base's, never a sample's (Triage base noise)."""
    return [
        {"name": "telnetd", "program": "/bin/telnetd", "user": "root", "ports": [23]},
        {"name": "vendor program", "program": device["program"], "user": "root",
         "ports": [80, 554, device["vendor_port"]]},
        {"name": "crond", "program": "/bin/crond", "user": "root", "ports": []},
        {"name": "syslogd", "program": "/bin/syslogd", "user": "root", "ports": [],
         "files": ["/var/log/messages"]},
        {"name": "klogd", "program": "/bin/klogd", "user": "root", "ports": []},
        {"name": "udhcpc", "program": "/bin/udhcpc", "user": "root", "ports": []},
    ]


def extra_tree(root, userland, image, device_name=None, work=None):
    """Turn the BusyBox base's tree in root (image.base_tree's) into the camera
    base. Returns its bundle.json additions: kernel_append (the flash layout
    and a watchdog that only logs), device, base_services and the vendor
    program's source record."""
    name, device = device_profile(device_name)
    flash = device["flash"]
    # The vendor program, built for the guest's architecture.
    work = Path(work or root.parent)
    program = build_camera(userland.arch, device["vendor_port"], work / "camera" / "program")
    target = root / device["program"].lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(program, target)
    target.chmod(0o755)
    extensions = install_iptables(root, userland, image)
    # The maker's default root password, as /etc/passwd holds it on the devices.
    passwd = root / "etc/passwd"
    lines = passwd.read_text().splitlines()
    hashed = md5_crypt(device["telnet_password"], password_salt(name))
    lines = [f"root:{hashed}:0:0:root:/root:/bin/sh" if line.startswith("root:") else line
             for line in lines]
    passwd.write_text("\n".join(lines) + "\n")
    # Vendor-style identity files.
    image.write_file(root, "/etc/version", device["firmware"] + "\n")
    image.write_file(root, "/etc/model", device["model"] + "\n")
    image.write_file(root, "/etc/build_date", device["build_date"] + "\n")
    for directory in ("var/spool/cron/crontabs", SETTINGS_MOUNT.lstrip("/")):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "var/spool/cron/crontabs").chmod(0o700)
    rcs = root / "etc/init.d/rcS"
    erase = flash["erase_kib"]
    # The erased block doubled to the largest power of two up to 1 MiB that
    # divides the flash, then copied that many times.
    doublings = 0
    while erase << (doublings + 1) <= 1024 and flash["size_kib"] % (erase << (doublings + 1)) == 0:
        doublings += 1
    copies = flash["size_kib"] // (erase << doublings)
    edit(rcs, "if ip link show eth0 >/dev/null 2>&1; then\n", f"""    # The maker's MAC prefix, as the firmware sets the address at boot.
    mac=$(cat /sys/class/net/eth0/address)
    ip link set eth0 address {device['mac_prefix']}:${{mac#*:*:*:}}
""", after=True)
    # The DHCP client stays (no -f, no -q): it goes to the background with
    # its lease and renews it, as the devices' does.
    edit(rcs, "udhcpc -i eth0 -s /etc/udhcpc/default.script -f -q -n -t 5 -T 1",
         "udhcpc -i eth0 -s /etc/udhcpc/default.script -n -t 5 -T 1 -p /run/udhcpc.eth0.pid",
         replace=True)
    edit(rcs, "echo 'BusyBox guest ready'\n", f"""# The device's services, as its firmware's start script runs them; the DHCP
# client above keeps its lease. telnetd on IPv4, as on the devices (a bot
# finds its port in /proc/net/tcp).
syslogd
klogd
crond
telnetd -b 0.0.0.0
setsid {device['program']} </dev/null >/dev/null 2>&1 &
# The device's SPI flash: a RAM disk handed to block2mtd under the flash
# driver's name, split by the command line's mtdparts=, erased (0xff) as
# delivered flash reads; the settings partition mounted as on the devices.
# The erased image is doubled up to 1 MiB first: few processes, which an
# emulated CPU starts slowly.
tr '\\000' '\\377' < /dev/zero | head -c {erase * 1024} > /run/.erased
for i in $(seq {doublings}); do cat /run/.erased /run/.erased > /run/.erased2; mv /run/.erased2 /run/.erased; done
i=0
while [ $i -lt {copies} ]; do cat /run/.erased; i=$((i + 1)); done > /dev/ram0
rm -f /run/.erased
echo /dev/ram0,{erase}KiB,{flash['name']} > /sys/module/block2mtd/parameters/block2mtd
mount -t jffs2 /dev/mtdblock{len(flash['partitions']) - 1} {SETTINGS_MOUNT} 2>/dev/null
""")
    source = CAMERA_SOURCE.relative_to(REPO).as_posix()
    return {
        "kernel_append": f"{mtdparts(flash)} softdog.soft_noboot=1",
        "device": {"profile": name, "kind": device["kind"], "maker": device["maker"],
                   "model": device["model"], "firmware": device["firmware"],
                   "build_date": device["build_date"], "mac_prefix": device["mac_prefix"],
                   "kernel_release": device["kernel_release"], "watchdog": "/dev/watchdog",
                   "flash": {"name": flash["name"], "size_kib": flash["size_kib"],
                             "erase_kib": erase,
                             "partitions": [part for part, _ in flash["partitions"]]},
                   "firewall": "iptables-legacy", "iptables_extensions": len(extensions)},
        "base_services": services(device),
        "program_source": {"path": device["program"], "source": source,
                           "source_sha256": hashlib.sha256(CAMERA_SOURCE.read_bytes()).hexdigest(),
                           "license": "GPL-3.0-only"},
    }
