# Implementation record: Bases and stealth

Guest bases, Debian module ABI, and the stealth profiles. Part of the [implementation record](../implementation.md).

## VM stealth profiles (0.6.2)

`VmConfig.stealth` (`monitor-core/src/stealth.rs`) holds the identity a VM
shows its guest. A configuration without the field is Transparent, which adds
no launch options, so VMs saved before 0.6.2 launch exactly as they did. New
VMs default to Realistic desktop.

| Entry | QEMU option | Transparent | Realistic |
| --- | --- | --- | --- |
| Machine identity | `-smbios type=1,2,4`, `-smbios file=` (type 0 BIOS, type 3 chassis and, from 0.8.0, type 17 memory device tables written to the runtime directory; the BIOS table lists real characteristics and not QEMU's "virtual machine" bit), `-machine smbios-entry-point-type=64` | QEMU strings, chassis Other | One of eight built-in vendor machines (Dell, HP, Lenovo, Supermicro; Intel and AMD) with random serials and UUID |
| ACPI OEM IDs | `-machine x-oem-id=,x-oem-table-id=` | `BOCHS` / `BXPC` | The machine's vendor IDs |
| CPU | `-cpu host,-hypervisor,kvm=off,pmu=on` (without KVM: `max,model-id=<host CPU name>,-hypervisor`); passthrough replaces the VM's CPU model setting | QEMU model, hypervisor bit, KVM signature | Passthrough, hidden hypervisor bit and KVM signature, performance counters |
| CPU caches | `-cpu host,host-cache-info=on` (passthrough only) | QEMU's cache sizes | The host's cache sizes |
| Topology | `-smp N,sockets=1,cores=N,threads=1` | `-smp N` | One socket of N cores |
| Network card | `-device e1000e\|e1000\|rtl8139\|virtio-net-pci,mac=` | virtio-net, `52:54:00:12:34:56` | e1000e with a random Intel (`3c:fd:fe`) address; a random locally administered address is offered |
| USB | `-machine usb=on` (ICH9 EHCI with UHCI companions at 00:1d) | No USB controller | Present |
| Disk and CD-ROM | `-global virtio-blk-pci.serial=`, `-global ide-cd.model=` | QEMU defaults | A Samsung-style disk serial, an LG DVD model |
| Devices | `-machine vmport=off,hpet=off` | VMware port and HPET present | No VMware port; HPET kept |
| Clock | `-rtc base=localtime` | UTC | UTC (local time is offered for Windows-like guests) |

Hiding the KVM signature makes the guest use its TSC instead of kvm-clock.
0.7.0 adds firmware, disk bus, SMT, pointer, clock, NAT and smaller entries:
see "Stealth profile, part 2" below.
The profile is validated before a VM is created, saved or launched: MAC
addresses are six hex pairs and not multicast, identity strings have no
control characters and are at most 64 bytes, ACPI IDs fit their 6 and 8
bytes, and the UUID is in 8-4-4-4-12 form.

**What a profile cannot change.** The fw_cfg device and QEMU's ACPI table
creator ID, the q35 chipset layout and its devices' Red Hat subsystem IDs,
the emulated display and VM-exit timing are outside launch options; the
Stealth profile window and the Summary list them under "Still visible". The
guest kernel's own traces are handled in the guest (see "Guest stealth"
below). A snapshot taken with other hardware may not restore after the
profile changes.

**Summary.** The VM configuration section of the Summary shows Compute,
Storage and display, and Network and transport cards, and a Stealth profile
card with the preset, the machine identity (machine, chassis, serial,
firmware, ACPI OEM), the CPU, network card and MAC, devices and clock, and
what is still visible. Configure… opens the VM dialog while the VM is
stopped.

**Verified** on QEMU 11 with KVM (AMD host): a Realistic desktop BusyBox
guest reads `LENOVO` / `11JN0047US` / chassis 35 from DMI, has no
hypervisor CPU flag, uses the `tsc` clocksource, sees an Intel 0x8086 e1000e
card with a `3c:fd:fe` address, Intel ICH9 USB controllers (8086:2934-2936,
293a), the host's 16 MiB L3 and a `LENOVO` ACPI OEM ID, and records a
guest-run without loss (3,456 packets, none dropped).

## Debian's module ABI (0.8.0)

Guest series 0020-0022, the `stock` kernel profile and Debian Minimal's image;
contract revision unchanged (the host sees no difference). Debian Minimal
installs Debian's own kernel packages, so its module tree is Debian's ~4,200
signed modules; until 0.8.0 the Antinomie kernel refused them (another
`struct module`, other CRCs) and the base hid them from modprobe, which left
`lsmod` empty and a Debian-built module (a rootkit's, a driver's) unloadable.
Now the kernel loads them as Debian's kernel does:

| Part | What it does |
| --- | --- |
| Patch 0020, side tables | No recorder field in a stock structure. Per task (cookies, monitor and run contexts, the event and packet sequence counters, the io_uring request a worker runs, the process core in writing): `struct ant_task_state` in the task's LSM security blob, at an offset `security.c`'s `ordered_lsm_init()` reserves after every LSM's part (`ant_task_state_reserve()`), read as `task->security + offset`. No LSM is registered: a registered one is printed by `report_lsm_order()` at boot, listed in `/sys/kernel/security/lsm` and by `lsm_list_modules()`, and would exceed `MAX_LSM_COUNT` (Debian's order names every LSM it builds). The blob is allocated zeroed in `security_task_alloc()`, after `dup_task_struct()` copied the parent, and freed in `security_task_free()` after `ant_monitor_release()`; `ANTINOMIE` depends on `SECURITY`. io_uring and AIO requests: the request record is found by its `io_kiocb`/`aio_kiocb` in a hashtable under the lock that already guarded every slot access; with no request alive no lock is taken, and a resubmitted object first abandons what it left. Rings: the creator (tgid, task, cookies) of each `io_ring_ctx` in an RCU hashtable, freed with the ring by `call_rcu`. A recvmsg's `msghdr` sizes live in the request record. A recorder process core's deadline and live state are the writing task's; `<linux/coredump.h>` declares only opaque accessors. The recorder's six `EXPORT_SYMBOL_GPL`s are gone (nothing modular used them), so the export table is Debian's. |
| Patch 0021, function tracer | The recorder's objects are built without `CC_FLAGS_FTRACE`; its eleven functions in stock files are `notrace`. With Debian's `FUNCTION_TRACER`/`DYNAMIC_FTRACE`, tracefs's `available_filter_functions` lists 45,775 call sites, none of the recorder's. |
| Patch 0022, BTF numbering | Debian's module BTF refers to vmlinux types by number, so it is valid only if each type has Debian's number. `kernel/configs.o` (IKCONFIG, which the image builders read) has no debug information; the recorder's exit and live core writer moved to `kernel/antinomie/core_writer.c` with its own copies of `fs/coredump.c`'s static helpers (a second caller had made `coredump_wait()`, `dump_vma_snapshot()` and others out-of-line functions, each a BTF and traceable function Debian's build lacks; forcing them inline only cascaded to their callees); `io_xattr_finish()`, `__io_setxattr_prep()` and `io_waitid_finish()`, grown by hooks, are `__always_inline` (from 0.9.0 also `tk_xtime_add()` and `pci_read_bridge_windows()`, for patches 0052 and 0053, whose `ant_timekeeping_present()` is notrace; `printk.c` includes only `antinomie_stealth.h`, as `time_namespace.h` there changed the console exports' symbol versions); recorder functions named like stock ones are renamed; the transport's per-CPU state is `alloc_percpu()`ed (a static per-CPU variable shifted Debian's `.data..percpu` offsets). |
| `stock` profile (`build-monitor-kernel.sh stock`) | Debian's resolved configuration with only `ANTINOMIE` (+ source id, and its `ANTINOMIE_FACADE` and `ANTINOMIE_BOOT_AGE` from 0.9.0), `IKCONFIG` (no `IKCONFIG_PROC`), gzip compression (the image builders read the configuration from the bzImage), `LOCALVERSION`, `BUILD_SALT` = the release (as Debian's `gencontrol.py` sets it; the build-salt note in `/sys/kernel/notes`) and `MODULE_SIG_KEY` changed; anything else fails the build. Debian signs its modules with a key its build makes and discards, and builds that key's certificate in as the only builtin key (`debian/rules.real`, `output/signing_key.pem`); the certificate, read from Debian's vmlinuz (serial 2C0CF174..., the signer Debian's modules name), is `src/antinomie/packaging/debian-6.12.94-1-trixie/module-signing.pem` and goes to the same path, so `.builtin_trusted_keys` is Debian's and nothing is signed here. Only `bzImage` is built (about 42 minutes at two jobs from scratch). |
| `scripts/check-kernel-abi.py` | After every stock build, against Debian's image (`ANTINOMIE_DEBIAN_IMAGE`; `build-base.py` fetches it into the inputs through the signed index, as the image recipe does): exported symbols, licence and modversions CRC from both kernels' `__ksymtab`/`__kcrctab` and the build's `vmlinux.symvers` (11,212, all equal); BTF byte identity, else every named structure or union whose size or members differ; traceable functions (`__mcount_loc`) of the recorder; a recorder function with a stock name. `tests/monitor/test-kernel-abi.py` tests it and the profile. |
| Debian Minimal image | No `updates/` tree, no index of our own, no initramfs rebuild: Debian's postinst made both. The bootstrap initrd loads Debian's root-disk and ext4 modules (see "Debian Minimal base"). |

Measured (stock kernel, native gcc-14 14.2.0-19, binutils 2.47; the
container builder's binutils 2.44 changes only the banner): exports and CRCs
equal to Debian's `Module.symvers` (vmlinux part) and to its vmlinuz; vmlinux
`.BTF` (4,959,816 bytes, 113,482 types) identical to Debian's; no recorder
call site among 45,775. What still differs from Debian's kernel: the code
(another binary: symbol addresses in `/proc/kallsyms` for root, the GNU build
ID in `/sys/kernel/notes`), the embedded configuration (not readable in the
guest), the banner's linker version unless built with Debian 13's binutils
(the build refuses Debian Minimal otherwise), and the recorder's own memory
and behaviour (see "Guest stealth").

### The desktop base on the same kernel

Since this change the Debian desktop base (profile `debian-xfce`, every
desktop of `DESKTOPS`) is built like Debian Minimal's kernel side; the
`debian` kernel profile is gone and `kernel_profile` maps both Debian kinds to
`stock`, so they share one cached kernel.

| Part | Desktop before | Desktop now |
| --- | --- | --- |
| Kernel | `debian` profile: Debian's configuration plus `VIRTIO_BLK`, `EXT4_FS`, `DRM`, `DRM_VIRTIO_GPU` built in (`=m` in Debian), its own module-signing key, release `6.12.94`, the host's gcc | `stock` profile, release `6.12.94+deb13-amd64`, Debian's certificate |
| Kernel packages | every `linux-image-*` purged in the customization | `DEBIAN_KERNEL_PACKAGES` installed first, as on Minimal, and kept (`dpkg --verify` empty) |
| Module tree | the kernel's own `modules_install` appended to the root tarball (`add_modules`, removed) | Debian's, from its packages; the bootstrap initrd loads Debian's virtio-blk and ext4 modules (`ROOT_MODULE_GROUPS`), udev the rest |
| Banner | whatever compiler built it | Debian's (`debian_banner()`); `require_debian_toolchain` runs for every stock-profile job and `toolchain::for_kind` gives both Debian kinds the same toolchain (the host's when it is Debian 13's, else the rootless toolchain chroot) |
| Fixed display | DRM and virtio-gpu built in | `fixed_display_config(..., modules_ok=True)`: virtio-gpu is Debian's module, loaded by udev before the display manager starts |
| `/tmp` | Debian 13's default tmpfs | on the root disk, as on Minimal and BusyBox (the `tmp.mount` drop-in is written for every Debian base): dropped files reach the VM's disk, and the conformance cases run in a disk folder; the conformance suite uses the Debian goldens for every `debian-*` guest |

The options the `debian` profile added were all ones Debian builds as
modules, so none is kept: the desktop's configuration differs from Debian's
only as the stock profile allows. Its root stays `/dev/vda` (fstab, no SATA or
NVMe root), and its root filesystem cache key now includes the kernel
packages' SHA-256.

### A base's programs from Debian's packages, whatever the build host

The BusyBox base and every Debian base's bootstrap initrd used to copy the
build host's `busybox`, `resize2fs` and `chattr` with the libraries `ldd`
named, and recorded the host packages that owned them (`dpkg-query`): a base
built on Ubuntu carried Ubuntu's BusyBox and glibc, and its published sources
had to be Ubuntu's. Now `build-monitor-image.py` takes them from Debian 13's
amd64 packages, pinned in `USERLAND` (busybox-static, e2fsprogs,
libext2fs2t64, libcom-err2, libc6, at the container builder's snapshot) and
fetched through the archive's signed index (`pinned_debs` in
`build-debian-image.py`, shared with the kernel packages and the arm64
userland), into `--package-cache` (build-base.py passes its inputs folder).

| Step | How |
| --- | --- |
| Unpack | `unpack_deb`: the package's data archive into a private tree (no maintainer scripts), its control fields as the `guest_sources` record (package, version, architecture, source package and version) and the paths it shipped |
| Copy | `install_binary`: the program, the libraries its `DT_NEEDED` names (into `/usr/lib/x86_64-linux-gnu`, Debian's multiarch directory the loader searches) and its loader at its `PT_INTERP` path; `elf_needs` reads both from the ELF file, so no host `ldd` or `readelf` is needed |
| Applets | read from BusyBox's packed applet table (`busybox_applets`), not by running it |
| Record | `bundle.json` `guest_sources.packages` lists the pinned packages; a Debian base's initrd notices (`provenance/initrd/packages.json`) map each initrd file to its package, with the package's own copyright file |

The host no longer needs `busybox`, `ldd` or `dpkg-query` for a native
build (the app's tool checks dropped them); it needs network access to the
snapshot archive once, as for Debian's kernel packages.

## Guest stealth (0.7.0)

Guest series 0046-0050; contract revision 17 unchanged, every guest change
either invisible to the host or negotiated. What a sample sees from inside the
guest, measured on a BusyBox base with the Realistic desktop profile, and
what the guest kernel and the base now keep from it.

**The check.** `examples/stealth-check.rs measure BUNDLE NEW_DATA_DIR PROBE
[desktop|laptop|server|transparent]` boots one VM (two vCPUs, 2 GiB, isolated
NAT) with that preset, uploads the static `tests/monitor/stealth-probe.c` and
launches it as a run, as root and as uid 1000, after the host's first
resource polls. The probe prints `STEALTH verdict key value` lines (pass: looks
like a real machine; fail: a giveaway; info; skip: not readable for that
user), the check turns them into `ROW` lines and `stealth.md`/`stealth.tsv` in
the data folder and fails when the root run's recording holds fewer than 100
calls (observation must not suffer). The probe reimplements
systemd-detect-virt's VM checks (CPUID leaf 1 and 0x40000000, DMI vendors, the
SMBIOS BIOS "virtual machine" bit), virt-what's (DMI, `/proc/cpuinfo`, block,
SCSI and PCI vendors, fw_cfg sysfs and its I/O port), the Linux side of
pafish (user and host names, uptime, CPU count, memory, disk size, rdtsc twice
and around cpuid, a 500 ms sleep timed by the monotonic clock and the TSC),
the MAC prefix and NAT addresses, and Antinomie's own: `/proc/cmdline`,
`/proc/version`, `uname`, `/proc/config.gz`, `/proc/kallsyms`, `/proc/modules`
and `/sys/module`, the kernel log, BTF and tracefs, `/proc/iomem` and
`/proc/ioports` names, ACPI devices, every process's comm and command line
watched for four seconds (worker names change with every work item), and the
launched program's parent, session, process group, terminal and environment.

**Before → after** (root's verdict; user's where it differs):

| Check | Before | After | How |
| --- | --- | --- | --- |
| `kernel.cmdline` | fail: `… antinomie_ring_kib=1024 antinomie_boot_gpa=0x40000000` | pass: `console=tty0 console=ttyS0 panic=-1` | 0046 |
| `dmesg.antinomie` | fail: the command line twice, readable by users (`dmesg_restrict` 0) | pass: none; root only (`dmesg_restrict` 1) | 0046, build script |
| `kernel.version` | fail: the builder's `user@machine`, build time and time zone | pass: `(debian-kernel@lists.debian.org) … Debian 6.12.94-1 (2026-06-20)` | build script |
| `kallsyms.antinomie` | fail: 365 `ant_*` of 190,666 | pass: none (854 of the recorder's symbols hidden) | 0047 |
| `proc.comm-antinomie`, `proc.kworker-names` | fail: `kworker/u8:N-antinomie-control`, `-antinomie_resources` | pass | 0048 |
| `self.parent` | fail: PPid 2 (kthreadd) | info: PPid 1 (init) | 0050, `SHELL_JOB` |
| `self.session` | fail: sid = pgid = pid (session leader) | info: own process group, foreground, in session `pid - 1` whose leader does not exist | 0050, `SHELL_JOB` |
| `acpi.devices`, `iomem.names` | fail: `QEMU0002:00` in sysfs and `/proc/ioports` | pass (sysfs); `bochs-drm` and `virtio-pci-modern` remain | 0049 |
| `smbios.vm-bit` | fail: set | pass: clear | host, `stealth.rs` |
| `base.hostname`, `base.users`, `base.fs-label` | fail: `localhost`, `analyst`, label `antinomie` | pass: `debian`, `user`, no label | image builders |
| `acpi.tables` (root) | fail: BXPC creator ID, `QEMU0002`/`FWCF` in the DSDT | unchanged | limit |
| `fwcfg.ioport` (root) | fail: signature `QEMU` at port 0x511 | unchanged | limit |
| `pci.vendors` | fail: subsystem vendor 1af4 on every q35 device, Bochs display 1234:1111 | unchanged | limit, launch options |
| `virtio.devices`, `block.devices`, `base.root-device` | fail: virtio disk `vda` | unchanged | Stealth profile, part 2 (SATA/NVMe) |
| `display.fb` | fail: `bochs-drmdrmfb` (or virtio-gpu) | unchanged | limit |
| `net.addresses` | fail: gateway 10.0.2.2, DNS 10.0.2.3 | unchanged | limit, launch options |
| `timing.rdtsc-cpuid` | fail: median about 16,000 cycles | unchanged | limit |
| `base.uptime`, `base.memory`, `block.disk-size` | fail: seconds, 2 GiB, 8 GiB | unchanged | the VM's settings and a fresh boot |
| CPUID, DMI strings, MAC, clocksource, `cpuinfo` | pass (the 0.6.2 profile) | pass | |

Totals with the Realistic desktop preset: 27 of 72 checks gave the VM or
Antinomie away before, 14 after; with this app and the new base the user's
view has no Antinomie name left.

**Command line (0046).** `setup_arch()` hands `boot_command_line` to
`ant_cmdline_take()` (`kernel/antinomie/stealth.c`) before it first prints it:
every `antinomie_*` option is cut out (quoting and the order of the others
kept) and applied at once with `parse_early_options()`, so the existing
`early_param()` handlers run as before and nothing later sees the options. The
decompressor reads the original line for its KASLR placement. The host is
unchanged.

**Symbols (0047).** `section_begin.o` and `section_end.o`, linked first and last
in `kernel/antinomie`, put labels at the start and end of its `.text`,
`.rodata`, `.data`, `.bss` and per-CPU sections (`sections.h`; the text labels
are annotated as not being call targets for objtool). `ant_symbol_hidden()`
answers for an address in one of these ranges or an `ant_*` name (the hooks
elsewhere and their `__pfx_`, `__ksymtab_`, `__setup_` and initcall entries).
`/proc/kallsyms` skips those lines for every reader, root too, and
`/proc/<pid>/wchan` shows 0 for them. The kernel's table is complete: oopses,
`%pS`, kprobes, `kallsyms_lookup_name()` and the debugger are unaffected.

**Workers (0048).** The resource refresh is queued on `system_unbound_wq`
(one work item, one refresh in flight); the control (ordered), process-core
and debug queues keep their own ordering and limits and are named
`events_unbound`, the system queue whose worker pool they share.

**ACPI (0049).** `acpi_bus_check_add()` skips devices whose `_HID` starts with
`QEMU` (fw_cfg `QEMU0002`, pvpanic `QEMU0001`). Nothing in the guest uses
fw_cfg after the firmware: SeaBIOS and the linuxboot option ROM read the
kernel, initrd, ACPI and SMBIOS tables through it before the kernel runs, the
BusyBox kernel has no fw_cfg driver, the Debian one's `qemu_fw_cfg` module
has no device left to load for (not run on a Debian base here), and the host uses no fw_cfg device (no vmcoreinfo). The device stays in
QEMU, so its I/O ports 0x510-0x51b still answer `QEMU` to root with `ioperm`.

**Launch shape (0050, negotiated).** EXEC flag `SHELL_JOB` (32), listed in
TRACER_CAPS `exec_flags`; the host asks for it on every launch when the guest
offers it (`control::with_tracer_flags`), alongside the hashing flags (which
alone are saved as the manifest's `tracer_hashing`). `execute()` allocates a
PID before the launch (`alloc_pid()` in the initial namespace, so it is lower
than the program's); in `launch_init()`, after the program took its terminal
as session leader, `launch_as_job()` moves it under tasklist_lock from
kthreadd's children to init's (`real_parent`, `parent`, `exit_signal`
SIGCHLD), moves its session to that PID (`change_pid(PIDTYPE_SID)`) and points
the terminal's session at it. Result: PPid 1, pgid = pid = the terminal's
foreground group, sid = an id no process holds, `/dev/tty` opens, a child can
`setsid()`, the program cannot (it leads a process group, as under a shell's
job control). Init reaps it at exit (BusyBox init and systemd reap any
child). The PID belongs to the session from then on and is freed with its last
member; a launch that fails before frees it like a failed fork's. A real
parent shell is not possible: it would be a process running in the guest for
Antinomie, which the design excludes, so this is the shape of a job whose
terminal shell has exited. An older host never asks and gets kthreadd as
parent; an older guest does not offer the flag.

**Build string and log.** `scripts/build-monitor-kernel.sh` sets
`KBUILD_BUILD_USER`/`HOST` from the pinned package's maintainer
(`debian-kernel`, `lists.debian.org`), `KBUILD_BUILD_VERSION=1`,
`KBUILD_BUILD_TIMESTAMP` from its changelog date and
`KBUILD_BUILD_VERSION_TIMESTAMP="Debian 6.12.94-1 (2026-06-20)"`, as Debian's
`debian/rules.real` does (values in `adapter.conf`: `SOURCE_VERSION`,
`SOURCE_DATE_EPOCH`, `SOURCE_MAINTAINER`); the build becomes reproducible in
time too. The minimal profile disables `LOCALVERSION_AUTO` and builds with
`LOCALVERSION=`, so a git author tree no longer gives `6.12.94-g<commit>`,
and enables `SECURITY_DMESG_RESTRICT` as Debian does. The compiler part of
`/proc/version` is the builder's compiler (Debian's own builder VM has
Debian 13's gcc 14; a host build shows the host's). The release stays
`6.12.94`: Debian's is `6.12.94+deb13-amd64`, and changing it would move the
Debian base's modules and the bundles' `kernel_version`.

**Container builder (0.8.0).** `BuildMode` is Automatic, Native, Podman, Docker
or Qemu. `container.rs` runs the same orchestrator (`scripts/build-base.py`) in a
container: `src/antinomie/packaging/container/Dockerfile` (carried in the kit)
starts from `debian:trixie@sha256:...`, points apt at a snapshot.debian.org
timestamp for `debian` and `debian-security`, and installs every tool as
`name=version` (gcc-14 14.2.0-19 and binutils 2.44-3 give Debian's kernel banner;
a test ties these to the adapter's `KERNEL_BANNER`). The image is tagged
`antinomie-builder:<12 hex of the Dockerfile's SHA-256>` and labelled
`org.antinomie.builder=1`, so a changed pin is a new image and the old ones stay
until removed (the Build base dialog lists them; `container::list_images`,
`remove_image` touch only that label and tag prefix). Engine calls go through
a `Runner` (a fake in tests). `probe` names the reason an engine cannot run: not
on PATH, daemon not reachable, no permission (Docker's socket: the docker group
is root-equivalent), or the engine's own error; answers are cached for 20 s
because the dialog asks every frame. `resolve_mode` walks Native (the existing
toolchain check), Podman (rootless preferred by being first), Docker and QEMU
and reports every reason when none can run; a manual choice is that mode or its
obstacle. A build mounts the kit, job, inputs, work, the output's parent, the
kernel cache folder, the image cache folder and ccache, runs the orchestrator
as the container's root with `SYS_ADMIN` and `MKNOD` and no AppArmor profile
(mmdebstrap's root mode needs mount; checked on Docker, not on rootless Podman,
which was not available on the test host), and, under Docker, chowns every mounted
folder to the user when the build ends. Containers are named and labelled
`org.antinomie.build=1`, run with `--rm`, removed with `rm -f` after every
build including a cancel, and any left by a crash are removed before the next
build starts. When Automatic chose a container and its image cannot be built or
fetched (offline), `after_preparation` falls through to the QEMU builder and the
log says why; a manual choice fails with the reason, and a cancel never falls
through. The kernel cache is shared by all builders: its identity names the
toolchain, and the image tag the container built it with is recorded beside it
(`builder` in `kernel-cache.json`, not compared). `ANTINOMIE_BUILD_JOBS` and
`ANTINOMIE_BUILD_NICE` set the build's `-j` and its priority inside the
container (the engine client's own priority does not reach it).
`scripts/build-base.py --container auto|podman|docker` is the script path (the
same mounts and image logic in Python), and the `build-base` example takes
`podman` and `docker` as modes.

**Base defaults.** BusyBox and Debian bases default to the hostname `debian`
(the Debian installer's default), the BusyBox base names uid 1000 `user`
(home `/home/user/`), the Debian account form proposes `user`, and neither
image gives the root filesystem a label (nothing mounts it by label; Debian
Minimal mounts it by UUID).

**Known limits** (what neither a launch option nor the guest kernel removes
without a cost to observation or a separate design):

* *VM-exit timing.* CPUID, I/O ports and other intercepted instructions exit
  to KVM: rdtsc around cpuid measures about 16,000 cycles on this AMD host
  (bare metal: 100-250). Plain rdtsc and sleep timing look normal.
* *Tracer overhead.* Each traced call of a run writes telemetry; a sample that
  times its own system calls against a baseline sees them slower (see the
  overhead benchmark). The debugger's parked thread shows state `D`, not the
  `t` of a ptrace stop (it waits killable).
* *Root inspection of the guest kernel.* Root can read `/proc/kcore`, place a
  kprobe on a recorder function by name, read `/proc/<pid>/stack`, iterate
  kernel symbols with BPF, or read the original boot command line from the
  boot parameters' memory; the guest kernel is modified and cannot hide that
  from its own root. The Debian kernel profile also keeps Debian's
  `FUNCTION_TRACER` (root's tracefs lists the recorder's functions): not
  changed here because the Debian kernel was not rebuilt. (Its
  `DEBUG_INFO_BTF`, which named every recorder function, no longer does since
  0.8.0: see "Kernel BTF without the recorder".)
* *q35 PCI layout.* QEMU gives every q35 device the Red Hat subsystem vendor
  1af4, and the chipset (ICH9, 8086:29c0 host bridge) is QEMU's choice of a
  2009 platform.
* *QEMU's ACPI tables and fw_cfg.* To root, every table header has the creator
  ID `BXPC`, the DSDT describes `QEMU0002`/`FWCF`, and port 0x511 answers
  `QEMU`; the kernel log (root only now) prints the table headers.
* *The emulated display.* Bochs (`bochs-drm`, 1234:1111) or virtio-gpu. The
  disk and the NAT addresses are profile entries since part 2 (below).
* *A fresh boot.* Uptime is seconds to minutes; the VM's CPU count, memory
  and disk size are its settings (pafish flags under 2 CPUs, 2 GiB, 60 GiB).
* *Environment.* A run gets exactly the environment the user set (by default
  `PATH` and `TERM`), not a login shell's `HOME`, `USER`, `SHELL`, `PWD`.
* *Older bases* keep their command line, build string, symbols, worker names
  and `QEMU0002` until rebuilt, and are launched with kthreadd as parent.


## Cloud VPS profiles (0.8.0)

`StealthPreset::CloudVps` (`monitor-core/src/stealth/cloud.rs`) makes a VM an
instance of a KVM cloud. `StealthProfile.cloud` names the provider
(`CLOUDS`: Tencent CVM, Alibaba ECS, DigitalOcean Droplet, Vultr VC2) and
`StealthProfile.machine` the QEMU machine type (`pc` for i440FX, `q35`); both
default to nothing and q35 in profiles saved before 0.8.0. A cloud profile
keeps the CPUID hypervisor flag, the KVM signature and kvm-clock visible (a
hidden flag on a cloud's DMI strings would itself be odd), writes the
provider's type 0 (with the "system is a virtual machine" bit, which a PC's
firmware never sets), 1, 2, 3, processor and one RAM-sized DIMM, and takes the
provider's MAC prefix and DHCP network. `giveaways()` lists what remains
(the base's display, Red Hat PCI subsystem IDs, DNS servers inside the DHCP
network, no agent processes). `catalog/SOURCES-cloud.md` cites the values. The profile is an independent
imitation of the strings a provider's instance reports; it carries no provider
software, logo or credential and implies no affiliation (README, Trademarks).

**i440FX.** `vm.rs` passes the profile's machine type. The guest transport maps
guest RAM through `RamLayout::q35`, which equals i440FX's layout only below
0xb0000000 bytes, so a pc profile on a VM of 2.75 GiB or more starts as q35 and
says so in the start log. `MachineType::for_ram` owns that boundary for both
the backend and the pre-launch VM dialog, which shows the fallback before
saving. Merely showing the advice never changes the stored chipset. A base that names its NIC by slot (`onboardnic`)
gets it at 00:03.0 (`ens3`, `NicSlot::Pc`); not exercised on a Debian base.

**Network choice.** The VM dialog identifies the independent simulation and
offers "Use Routed for cloud metadata" on cloud profiles whose selected network
cannot host the local service. Only clicking it changes the three network flags;
opening or repainting a saved VM keeps its policy. Routed still uses a route
per run. Its Drop route serves the simulated provider metadata locally while
blocking external connections; InetSim also serves metadata locally. NAT,
Isolated and Disconnected do not attach this service. The gateway rejects the
other providers' metadata addresses instead of sending them upstream.

**Metadata scope.** The source inventory records the provider documentation
checked for Tencent/Alibaba/DigitalOcean paths, Alibaba's MAC example and
Vultr's published JSON client. Vultr JSON includes canary user-data; additional
user-data aliases are compatibility extensions. These are partial simulated
services, without Alibaba token-hardening mode or functioning provider agents.
Unverified MAC prefixes, DHCP choices and size hints remain labeled as such;
they are not current provider inventory. The cloud qualification example now
uses Debian's login marker, minima and offline account provisioning on Debian
bases, rather than waiting for a BusyBox banner.

**Lived-in state (per VM, not per base).** The first start with a provider
writes `CloudProvider::state_files` into the VM's disk through an offline
libguestfs run (`guest_account/cloud_state.rs`, the same tool as provisioning,
on BusyBox and Debian Minimal alike): `/var/lib/cloud` data and instance
folder, cloud-init logs, the host name (`/etc/hostname`), the default user
(added to `/etc/passwd` when the base lacks it), its shell history, `auth.log`,
a `wtmp` with past logins, and the provider's agent directories as one-line
stubs (no provider binary), all with ages of hours to twelve days. `cloud-state.json`
in the VM's folder records the provider and instance id so a later start leaves
the disk alone; a failure only adds a "not applied" line to the start log. The
bases stay one reproducible image for every profile.

Checked on Debian Minimal (stock-ABI candidate, all four providers, `stealth-check
cloud`): the files are written and aged (instance id, `cloud-init.log` and the
provider configuration 12 days, `wtmp` an hour), the host name is the
provider's, the default user exists, the NIC has its slot's name (`ens3` on
the pc machine of Tencent, Alibaba and DigitalOcean, `enp0s25` on Vultr's q35)
with its DHCP address, and `systemd-detect-virt` says `kvm`. What a Debian 13 guest does not take from
them: it has no cloud-init (the cloud-init records are inert files, and
`cloud-init status` does not exist), and its `last` reads wtmpdb
(`/var/lib/wtmpdb/wtmp.db`), not `/var/log/wtmp`, so the past logins the file
holds do not show there: `last` lists only the VM's own boots. Tencent's and
DigitalOcean's host names follow their Ubuntu images (`VM-0-15-ubuntu`,
`ubuntu-s-1vcpu-1gb-nyc3-01`) also on the Debian base, and Tencent's `ubuntu`
user gets `/bin/sh`. Nothing beyond these checks is verified on Debian.

**Metadata service** (`route/metadata.rs`). In a Routed VM the gateway answers the
provider's metadata address on TCP port 80 on every route, even Drop, from a
thread over an in-process socket pair (nothing listens on the host, nothing
leaves it); the provider's metadata name resolves to it in the gateway's DNS; the
other providers' metadata addresses go unanswered. The instance id (from the
system UUID), host name and region are the VM's; the credentials (Tencent CAM
role, Alibaba RAM role, or a token in DigitalOcean's and Vultr's user data) are
canaries in the provider's own form (`AKID` and 32 characters, `STS.`,
`dop_v1_` and 64 hex digits, Vultr's 36 characters) with no marker in them, new
for each run (`Gateway::claim`); the expiry times are the request's time plus six
hours, as with real role credentials.
The gateway also looks for the run's canary values in the bytes the guest sends to
any other TCP address; TLS hides them. At the end of the run
`cloud-metadata.json` (requests, credentials handed out, canary uses) lands in the
run's folder.

**Triage.** `credential.cloud_metadata` also covers 169.254.0.23, 100.100.100.200
and `metadata.tencentyun.com` (syscalls, capture hosts and names); the report adds
a VM-wide row for the requests, `credential.cloud_credentials` and
`credential.canary_used` (all High, T1552.005), and an endpoint indicator for the
place the canary went to (`Engine::cloud_report`).

**The check.** `stealth-check cloud BUNDLE NEW_DATA_DIR tests/monitor/cloud-probe
[PROVIDER...]` boots each profile as a Routed VM, runs the static
`cloud-probe.c` on the InetSim route (DMI, PCI, MAC, gateway, DNS, the metadata
paths of every provider, then the canary sent to 203.0.113.9) and checks the
answers against the profile and the run's report. It is the `cloud` check of the
full tier of `scripts/vm-regress.py`.

## Stealth profile, part 2 (0.7.0)

Guest series 0052, contract revision 17 unchanged. New profile entries
(`monitor-core/src/stealth.rs`; launch options in `stealth/launch.rs`, SMBIOS
tables in `stealth/smbios.rs`, OVMF discovery in `stealth/firmware.rs`, NAT
addresses in `stealth/nat.rs`). Each adds a launch option only when it
differs from QEMU's default, and a profile saved without it reads as that
default, so earlier VMs launch exactly as before.

| Entry | QEMU option | Transparent | Realistic |
| --- | --- | --- | --- |
| Firmware | BIOS: none. UEFI: `-drive if=pflash,unit=0,readonly=on,file=<OVMF code>`, `-drive if=pflash,unit=1,file=<the VM's variable store>`; Secure Boot adds `-machine smm=on`, `-global driver=cfi.pflash01,property=secure,value=on` | SeaBIOS | UEFI (OVMF, no Secure Boot) |
| Disk bus | virtio: `-drive if=virtio` as before. SATA: `-drive if=none,id=osdisk` and `-device ide-hd,bus=ide.0,model=,serial=,ver=,wwn=,rotation_rate=1\|7200`. NVMe: `-device nvme,serial=,use-intel-id=on` | virtio | SATA SSD `Samsung SSD 870 EVO 500GB`, firmware `SVT02B6Q`, a random Samsung NAA WWN |
| CD-ROM | `-device ide-cd,bus=ide.1` (empty) | none | none |
| SMT | `-smp N,sockets=1,cores=N/2,threads=2`, `+topoext` on AMD hosts | `-smp N` | Two threads per core |
| Pointer | `virtio-tablet-pci`, `usb-tablet` or none (the PS/2 mouse) | virtio tablet | virtio tablet |
| SMBIOS type 11 | `-smbios type=11,value=…` | none | The machine's OEM strings (Dell `Dell System`, `1[0A61]`…, HP `FBYTE#…`, Lenovo, Supermicro) |
| SMBIOS entry point | `-machine smbios-entry-point-type=64\|32` (with an identity) | QEMU's | 64-bit |
| Named CPU model | `-cpu <model>,model-id=<brand>[,legacy-cache=off,l3-cache=on]` without passthrough | the VM's CPU setting | passthrough (unchanged) |
| kvm-clock | `-cpu …,-kvmclock` while the KVM signature is shown | on | hidden with the signature |
| SMM | `-machine smm=off` | on | on |
| RTC | `-rtc base=localtime,clock=vm,driftfix=slew` (each when chosen) | UTC, host clock | UTC, host clock |
| NIC subsystem | `-device e1000e,subsys_ven=,subsys=` | Intel's | The machine maker's (Dell 1028:0a61, HP 103c:…, Lenovo 17aa:3179, Supermicro 15d9:…) |
| NAT network | `-netdev user,net=,host=,dns=,dhcpstart=` | 10.0.2.0/24 | 192.168.1.0/24, gateway .1, DNS .10, DHCP from .100 |

**Machine catalog (0.8.0).** `stealth/catalog.rs` and `catalog/*.rs` hold 39
`MachineProfile`s: popular business desktops and laptops (Dell, HP, Lenovo),
common consumer or small-business laptops with a wired port, and small servers.
Each has the strings its real units report: BIOS vendor and a list of real
(version, date) releases, system manufacturer, version and family, and a list of
real units (product, SKU, board product, SMBIOS chassis type); OEM strings; the
ACPI OEM and table IDs of its XSDT; the CPU generations seen in its units
(`CpuGen`, `stealth/cpu.rs`, from the SMBIOS processor signature); the onboard
LAN chip and its PCI subsystem ID, and where its QEMU card goes (`NicSlot`); the
SATA disks (`parts.rs`: model, firmware, WWN OUI, rotation) and memory modules
(maker and part as the firmware names them, type, speed, rank, form factor,
width) seen in its units; its optical drive's model; and a `weight`.
`catalog/SOURCES.md` cites a public report of a real unit for every value
(linuxhw DMI, Dmesg, HWInfo and SMART, hw-probe uploads), with three classes:
seen in a unit of the model; seen in a unit of a sibling model, with the reason
(no such report of the model, or the model's reports hide it); and not possible
or not verified. The weight is the number of public dmidecode reports of the
model (a sample of Linux users' machines, not sales). Only factual identifiers
are kept: no logos, firmware images, dumped ACPI tables or real serial numbers
(serials, UUID, MAC, the disk WWN's tail and memory serials are random per VM;
their formats are not from a source, as every public dump hides them).
`StealthProfile::realistic_on(kind, &HostCpu)` picks one machine of the kind and
host vendor whose `cpus` contain the host's generation (`HostCpu::detect` reads
family and model from /proc/cpuinfo; `classify` maps them), weighted by `weight`,
or any of the vendor when none fits, and `StealthProfile::cpu_note` then says the
host's CPU could not be in it. `MachineIdentity::from_machine` also picks one BIOS
release, one unit, one of the machine's disks (a spinning one sets the profile's
disk media to HDD and its own rotation rate) and memory modules; the result is
stored in the VM's configuration, so a boot never picks again. Each run saves a
`MachineRecord` (`RunSummary::machine`: machine, BIOS, SKU, board, disk, memory,
NIC chip, host CPU generation, any CPU note; no serials) for reading its results
against the identity it was seen under. Limits: QEMU's card is an e1000e (Intel
82574L) even where the machine's chip is Realtek or Broadcom (a listed giveaway);
QEMU's NVMe controller names itself, so the disk is SATA even on laptops whose M.2
slots are NVMe-only (the ThinkPads: class C in the sources; deferred to 0.9.0);
a RAM size no module combination makes names a larger part. Not done: guest hostname, user
and locale, and importing a profile from a machine the user owns.

**No SMBIOS field left to QEMU (0.8.0).** QEMU fills some SMBIOS fields with
its own values when a launch leaves them out: type 1 and 2 manufacturer
(`QEMU`), product (`Standard PC (Q35 + ICH9, 2009)`) and version (the machine
type, `pc-q35-11.0`), type 3 manufacturer and version, type 4 socket (`CPU 0`),
manufacturer, version, family (`Other`) and speed (2000 MHz), and type 17
locator (`DIMM 0`), manufacturer and memory type (`RAM`). A machine profile
therefore also carries `SmbiosFields` (`catalog.rs`): board versions (Dell
`A00`, HP `KBC Version 09.94.00`, Lenovo `SDK0J40697 WIN 3305…` with a random
per-unit number), board location, chassis version and SKU, processor socket and
part number, the memory slots (locator and bank) of one real unit, the memory
form factor and type detail, each the most common value in the model's public
dmidecode reports. `MachineIdentity` keeps them (`board_version`,
`board_location`, `chassis_version`, `chassis_sku`, `cpu_socket`, `cpu_part`,
`memory_slots`, `memory_form`, `memory_detail`); an identity saved before
takes its machine's at launch (`MachineIdentity::with_firmware_fields`).
`launch::apply` always passes type 1 and 2 manufacturer, product and version
and type 4 socket prefix, manufacturer and version, an empty one as string 0
(dmidecode prints "Not Specified", `/sys/class/dmi/id` an empty line, as on a
real unit whose firmware leaves the field unset; HP's single space is passed as
such). Type 4 also gets the host CPU's maximum and base clock (cpufreq, else the
brand string's "@ 2.90GHz", else `/proc/cpuinfo`) and its SMBIOS family from the
brand (Core i3/i5/i7/i9, Xeon, Pentium, Celeron, Zen). The memory devices are
written whole (see below). The chassis table's version and SKU follow the
machine, its asset tag is string 0.

**Whole processor, memory and cache tables (0.8.0).** `processor.rs` writes the
processor as a PC's firmware does, in place of QEMU's `-smbios type=4` (which
numbers the socket after the designation, `U3E1 0`, and keeps a made-up voltage,
upgrade and unset cache handles): type 4 (handle 0x0400, 0x30 bytes) with the
socket from the catalog, the host CPU's CPUID leaf 1 as the ID (EAX from
/proc/cpuinfo family, model and stepping, EDX the common 0xBFEBFBFF or
0x178BFBFF), voltage and upgrade code from the machine's `SmbiosFields`
(`cpu_voltage`, `cpu_upgrade`: the most common value in its reports), external
clock 100 MHz (every report), core, enabled-core and thread counts from the VM's
topology, characteristics from the host's flags, and type 7 tables (0x0700 to
0x0702) for the L1 (instruction and data summed, times cores), L2 and L3 of the
host's cpu0 cache directory, which the type 4 points at. A VM with a socket per
vCPU (topology setting off) keeps QEMU's option. `memory.rs` writes the memory
array (type 16, 0x1000) with the number of slots and the capacity of the slots
at the largest module the machine's catalog lists (not from a source), and the
devices (type 17, from 0x1100): `module_plan` picks catalog parts whose sizes
add up to the VM's RAM, in the identity's part's family (type, form factor,
width): one module up to 8 GiB, two equal modules above, then one to four
modules of different sizes, then the largest parts that fit with the rest in a
last module of the smallest part (a total no real module combination makes,
such as 2 GiB, whose module then names a larger part); an edited identity (its
part not in the catalog) keeps its own part in modules of up to 16 GiB. Slots
the modules leave are empty devices ("No Module Installed"). Every machine lists
parts of 4, 8, 16 and 32 GiB (8 to 64 for servers; LPDDR5 soldered parts only
those of its reports); a size missing from a model's own reports is taken from
another machine's (class B in the sources). `MachineRecord::of` takes the VM's
RAM size and records the part the plan picks. `apply` takes the vCPU count.

**Network chip.** QEMU 11 emulates Intel (82574L e1000e, 82540EM, 82576 igb, i82550
to i82559, 82801), Realtek RTL8139, AMD pcnet, tulip, ne2k, vmxnet3, virtio, not
the PCIe Realtek RTL8168/8111 or Broadcom NetXtreme (tg3) the catalog's
Realtek and Broadcom machines have. The profile keeps the 82574L, which is
the e1000e driver's chip (also the I219's driver) and exists on real boards;
the RTL8139 is a 1997 100 Mbit PCI chip (10ec:8139) on none of the catalog's
machines and shows only in VMs, and has no subsystem ID to set. `MachineProfile::nic_fit`
says per machine whether the chip is the same driver (`Same`: I219), another Intel
chip (`OtherIntel`: I210, an igb part; QEMU's igb would be closer but the guest
kernel has no CONFIG_IGB) or another maker (`OtherMaker`), and `giveaways()`
lists the last two. Dell's board serial is `/<tag>/CN<12>/` (a public dmidecode
listing); no public source shows the other makers' board, chassis or disk serial
formats (reports hide them), so those keep their current formats.

**Fitting to the base and the host.** Some entries need the base or the host.
A base says what it boots with in `bundle.json` `stealth_support` (advisory,
not part of the identity), which the image builders compute:

| Value | Written when |
| --- | --- |
| `uefi` | The kernel has `EFI` and `EFI_STUB` and its bzImage holds the EFI stub's bootstrap page claim (0052, found by its warning text) |
| `sata`, `nvme` | The initrd searches that bus for the root disk and the kernel has `ATA SATA_AHCI SCSI BLK_DEV_SD`, or `BLK_DEV_NVME`, built in (BusyBox; the minimal kernel profile now builds NVMe in), or the initrd loads their modules (Debian Minimal, Debian's own, since 0.8.0) |
| `dhcp` | The guest takes its address from DHCP (BusyBox bases now; Debian desktop bases through NetworkManager, Debian Minimal through ifupdown and dhcpcd) |

The host offers OVMF when QEMU's firmware descriptors (the user's and
`/etc/qemu/firmware`, then `share/qemu/firmware` of the QEMU in use and
`/usr/share/qemu/firmware`, by file name, as QEMU and libvirt read them) name
a UEFI x86_64 q35 flash image with a raw variable store, with Microsoft's
keys enrolled for Secure Boot; each VM copies the store once
(`efi-vars.fd`, `efi-vars-secure-boot.fd` in its folder). SMT is offered on
Intel hosts and on AMD hosts whose CPU has TOPOEXT (without it QEMU warns that
the CPU has no hyperthreading; with `+topoext` the guest sees `thread_siblings
0-1`). `StealthProfile::fitted()` turns an entry the base or host lacks into
BIOS, virtio, 10.0.2.0/24 or one thread per core at launch (`fallbacks()` lists
each as a `Fallback`: setting, one summary line, reason); the Stealth profile
window shows such choices disabled with the reason, puts the summary on the
setting and at its top, and lists the fallbacks under "Still visible". The VM
list and the Summary card carry a badge, the launch keeps the lines in
`VmProcess::stealth_fallbacks` (the snapshot's `stealth_fallbacks`, warned once
in Activity, and a note on each run of the boot). A Debian base keeps virtio: its kernel
builds AHCI and NVMe as modules and its root is `/dev/vda` (APPEND, fstab);
the Debian kernel was not rebuilt here.

**UEFI and the bootstrap page (0052).** Under OVMF the kernel's EFI stub
decompresses and places the kernel itself, with KASLR at a random 2 MiB slot
among the firmware's free memory, and the host's bootstrap page is free
memory to the firmware. When the kernel landed on it, the host read the
kernel's bytes as the boot block and failed (`Protocol error`). The stub now
reads `antinomie_boot_gpa=` as the decompressor does (the last valid one
counts) and allocates that page as loader data at its address before the
kernel, the initrd and the boot data are placed; after `exit_boot()` it is
ordinary RAM and `ant_bootstrap_reserve()` takes it from memblock as before.
Measured: with `nokaslr` OVMF places the kernel at 0x1800000; with the page at
0x2000000 the old kernel failed 3 of 3 boots, the new one moved to 0x2200000
and passed 3 of 3. With KASLR and the default page: 32 of 32 UEFI boots and 6
of 6 Secure Boot boots brought the transport up, each at a different
physical address, plus 6 and 3 on the final base, and `/sys/firmware/efi`
exists in the guest.

**Secure Boot.** OVMF with Microsoft's keys rejects the unsigned kernel
("Secure boot image verification failed") and then starts it with its legacy
Linux loader ("insecure and deprecated"); the stub reports Secure Boot
enabled and the kernel logs `secureboot: Secure boot enabled`. A later OVMF
build without that fallback would refuse the boot; the kernel would then need
a shim.

**The base.** The BusyBox initrd mounts the first of `/dev/vda`, `/dev/sda`
and `/dev/nvme0n1`; init runs `udhcpc` with its own script (address, route,
`resolv.conf`). An isolated VM's NAT (`restrict=on`) answers DHCP without a
router or DNS server; the DHCP server's address then takes both roles, so a
program's lookups still leave the VM and are captured (they get no answer, as
before). The host-side capture, DNS and HTTP decoding and Triage do not assume
10.0.2.x (Triage treats every private address as the local network, which is
why a NAT network must be private). An older host ignores `stealth_support`
and the new base boots from virtio under SeaBIOS and gets 10.0.2.15 from the
NAT's DHCP server; a new host fits a profile to an older base's empty list.

**Disk size.** The disk's size is the VM's; a BusyBox base grows its
filesystem to it on the first boot. A 256 GiB disk took about 400 MiB of
image (virtio 398 MiB, SATA 411 MiB) and nearly two minutes of online
resizing. The VM dialog's fields and the Stealth window show what a real
machine has (pafish flags fewer than 2 CPUs, under 4 GiB RAM, under 60 GiB of
disk).

**What remains.** QEMU's CD-ROM answers the SCSI inquiry with `QEMU
DVD-ROM` whatever its model (so the presets leave it out); its NVMe
controller is `QEMU NVMe Ctrl` with QEMU's version as firmware and an
`nqn.2019-08.org.qemu:` subsystem name (QEMU prefixes any name it is given);
OVMF's firmware vendor (`EFI v2.7 by Debian distribution of EDK II`, root's
kernel log) and its BGRT table (OEM `INTEL`/`EDK2`, root); the ACPI creator
ID `BXPC` and fw_cfg (already listed); the chipset devices' Red Hat subsystem
IDs (only e1000e takes a subsystem); the display. efivarfs is not mounted in
the BusyBox base (its kernel builds it as a module), so OVMF's boot entries,
which name QEMU's devices, are not readable there. The RTC stays UTC by
default: Linux guests read it as UTC.

**Before → after**, with the new probe (`examples/stealth-check.rs`, which
gains `firmware=`, `disk=`, `nat=`, `cdrom=`, `smt=` and `gpa=` entries and a
`boots` mode), Realistic desktop on a BusyBox base: before is the 0.7.0 app
and base before this work, after is this app and base.

| Check | Before | After |
| --- | --- | --- |
| `firmware.type` | fail: BIOS, no `/sys/firmware/efi` | pass: UEFI |
| `firmware.vendor` (root) | (BIOS) | fail: `Debian distribution of EDK II` |
| `smbios.oem-strings` (root) | fail: no type 11 | pass: 2 strings |
| `acpi.oem-ids` (root) | pass | fail: OVMF's BGRT `INTEL`/`EDK2` |
| `virtio.devices`, `block.devices`, `base.root-device` | fail: `vda`, vendor 0x1af4 | pass: `sda`, `ATA Samsung SSD 870`, rev `2B6Q`, non-rotational, WWN `naa.5002538e…` |
| `net.addresses` | fail: 10.0.2.15, gateway 10.0.2.2, DNS 10.0.2.3 | pass: 192.168.1.100, gateway and DNS 192.168.1.1 (isolated) |
| `pci.vendors` | fail: Bochs 1234:1111, virtio 1af4:1001 | fail: Bochs 1234:1111 |
| `pci.subsystems` | fail: 10 of 11 Red Hat; e1000e 8086 | fail: 9 of 10 Red Hat; e1000e 17aa (Lenovo) |
| `cpu.threads` | one thread per core | two threads per core |
| unchanged fails | `acpi.tables`, `fwcfg.ioport`, `dmesg.vm` (root); `block.disk-size`, `display.fb`, `iomem.names`, `base.uptime`, `base.memory`, `timing.rdtsc-cpuid` | the same |

Totals: 17 of 77 checks gave the VM away before, 13 of 80 after; in the view
of uid 1000, 13 before and 8 after (the display, the chipset's subsystem IDs,
the measurement VM's 8 GiB disk and 2 GiB RAM, uptime and VM-exit timing).
With NVMe, `block.devices` and `block.nvme` fail on the controller's model;
with the CD-ROM, `scsi.models` fails on `QEMU DVD-ROM`.

### Accepted Debian Xfce fidelity update

The Debian Xfce guest did not resemble a VM installed from the Debian ISO: it
was a `virt-builder debian-13` cloud template plus a curated
`--no-install-recommends` package list missing the desktop meta-package and its
recommends. The base now targets the closest-to-ISO completeness level and
keeps guest integration purged. Install `task-xfce-desktop` with recommendations, move
networking to NetworkManager (dropping the custom `ifupdown`/`dhcpcd` setup),
and grow the immutable base to a 16 GiB whole-disk layout with 16 GiB guest
minimum. `openssh-server`, `qemu-guest-agent`, `spice-vdagent`, `cloud-init`,
`cloud-guest-utils` and `linux-image-*` remain purged; root stays locked, no
ordinary users exist in the base, `/dev/vda` remains the fstab root and the
hostname stays `antinomie`. No kernel, transport or application change; existing
bundles, VM disks and recordings are untouched.

### Accepted guest cursor update

After the absolute-pointer fix the guest showed two cursors
(the guest's software cursor plus the host pointer). The fixed-resolution path
used standard VGA (`-device VGA,edid=...`), which has no hardware cursor, so the
guest X server painted its cursor into the framebuffer. The fixed path switches
to a hardware-cursor GPU. Use
`-vga none -device virtio-gpu-pci,edid=on,xres=W,yres=H`. The connector is a
`DRM_MODE_CONNECTOR_VIRTUAL` named `Virtual-1`, so `video=Virtual-1:WxH` is
retained. This matches the Auto path's virtio-gpu device and gives a single,
VMware-like pointer. Both virtio-gpu and Bochs DRM use the `Virtual-1` virtual
connector, so existing fixed-display bundles whose kernels build
`DRM_VIRTIO_GPU=y` remain compatible. Image/bundle capability checks now require
`DRM_VIRTIO_GPU` and `DRM_VIRTIO_GPU_KMS`. No kernel, transport or user-disk
change.

### Accepted guest pointer update

The guest mouse pointer was stuck at the display center: clicks reached
the guest but motion did not move the cursor. Cause is the QEMU GTK relative
pointer grab; the launch attached only the emulated PS/2 mouse. All non-headless
launches now attach an absolute pointing device. Use
`-device virtio-tablet-pci` (a self-contained PCI device requiring no USB
controller) so the host pointer is tracked directly and never grabbed. The
existing guest kernel already binds `CONFIG_VIRTIO_INPUT`, so this is a
launch-argument change only: no kernel, transport, bundle or user-disk change.
Headless launches are unaffected.

### Debian Minimal base (0.7.1)

A third buildable base beside BusyBox and the Debian desktops: console-only
Debian 13 (profile `debian-minimal`, guest id `debian-minimal`, label
`Debian 13 (Minimal)`, 1024 MiB / 4 GiB minima, `requires_credentials` as on
the desktop bases, `graphical: false` so the VM behaves like BusyBox: QEMU's
default VGA console, no `-vga virtio`, no Run in desktop choices, Stop's configured
timeout without the desktops' 30 s floor). The same recipe builds it
(`build-debian-image.py` with the installer answer `desktop: "none"`, which
`build-base.py` sets for the profile; the job offers every Debian answer but
the desktop): what the Debian installer leaves with no desktop chosen, the
standard task (mmdebstrap's `standard` variant, the default answer for this
base) with recommends (exim4 on 127.0.0.1:25 as the local MTA, as the
installer installs it; timesyncd; the ispell dictionaries), the installer's own
additions in `CONSOLE_PACKAGES` (tasksel, installation-report, discover,
laptop-detect, eject, initramfs-tools, console-setup, sudo) and tasksel's
language task for the locale (`task-english` for English), documentation and
manual pages, the package indexes and apt's caches kept; no curl and no
systemd-resolved. Networking is the installer's: ifupdown with dhcpcd. The
base's `/etc/network/interfaces` has only the loopback (`CONSOLE_INTERFACES`); its
`stealth_support` adds `onboardnic`, and the app puts the NIC at a fixed PCI
slot of the profile's machine and writes the installer's `allow-hotplug`
stanza for the name udev gives it there. `StealthProfile::nic_slot` takes the
slot from the machine the identity copies (`MachineProfile::nic_slot`): Intel
100-series and later chipsets (OptiPlex 7090, EliteDesk 800 G6, Latitude 5420)
have their I219 at 00:1f.6, `enp0s31f6` (`NicSlot::Pch`; q35's LPC
bridge at 00:1f.0 is multifunction, so function 6 is free). The Supermicro
servers have no chipset LAN (the X11SCL-F has two Intel I210, the H12SSL-i
Broadcom BCM5720 on the board): firmware names such ports by index, so the NIC goes
to 00:19.0 with QEMU's `acpi-index=1` and Debian's udev names it `eno1`
(`NicSlot::Eno1`; checked on q35 with Debian 13: `e1000e 0000:00:19.0 eno1:
renamed from eth0`, no extra device or ID). Profiles without
an identity (Transparent), with an edited one, or copying an AMD machine (no
integrated LAN on bus 0, and a root port would be QEMU's Red Hat one) keep
00:19.0, `enp0s25`, the ICH9's place (`NicSlot::Ich`). `nic_option_for` adds
the address whatever the model, so the name does not depend on which display
or pointer devices take the first free slots (headless or not). Provisioning
writes the stanza (`interface_commands`: everything from the installer's
`# The primary network interface` comment on is replaced) and the account
record keeps the interface (`GuestAccount::interface`; a record from before
0.7.1 means `enp0s25`, which such a base wrote at build time); the launch puts
the NIC at that interface's slot, so a disk and its NIC always agree, and
both the user-mode network and the Routed gateway's `-device` use it. Saving
a profile whose slot differs rewrites the stanza on the VM's disk
(`set_interface`, VM stopped); with snapshots that is refused, since their
disks name the old interface. A reset writes the current profile's.
`/etc/resolv.conf` is a plain file dhcpcd rewrites from the lease. Packages
configured during the build that recorded
the build host's name (exim4's mail name) get the chosen hostname, and the
leak check also fails on the build host's name. `multi-user.target`,
`/tmp` on the root disk (a `tmp.mount` drop-in, unlike Debian 13's default tmpfs: dropped files reach the VM's disk, and the
conformance cases and goldens, which expect BusyBox's on-disk `/tmp`, pass
unchanged), a 4 GiB disk. Its root is found without naming a device: fstab
mounts `UUID=<root uuid>` (a fresh UUID per bootstrap, given to `mkfs.ext4
-U` and read back from a cached root filesystem's fstab; the build checks
fstab and the filesystem agree), and `kernel_append` names it the way GRUB
does (`root=UUID=`, below). A UUID,
not a label, because a Debian install mounts by UUID and a fixed label would
name the sandbox to a sample reading `/dev/disk/by-label`. Everything else
(account removal, masks for SSH and guest agents only where a package still
ships the unit, locked root, apt check, provenance, initrd) is the desktop
path; the desktops keep `/dev/vda` in fstab and `root=/dev/vda`.

Nothing in the image names Antinomie or the build host: the package inventory
is written to `/tmp` and leaves with the provenance, the network and tmpfiles
snippets and the desktops' display-manager snippets have stock-looking names,
systemd-resolved's backup of the resolv.conf it replaced (the build host's, as
mmdebstrap copied it) is removed, and the build fails (`check_image_leaks`) on
a path naming Antinomie, a `/dev/null` mask for a unit no package ships, or a
configuration or state file holding the build host's nameserver or search
domain (read from its `/etc/resolv.conf`; WSL's resolver and Tailscale
MagicDNS names always). Creating a VM provisions it offline with `guestfish`
(it was `virt-customize`): a read-only probe finds the one ext4 filesystem,
then the root filesystem gets a UUID of its own (`set-uuid` after `e2fsck -f`;
the account record keeps it as `root_uuid`), a directory hash seed of its own
(`debugfs ssv hash_seed random` and `e2fsck -fD` through `guestfish debug`,
best effort), fstab's `UUID=` root line follows, and the account is created as
before without a sudoers.d file (the `sudo` group already allows it). Reset
provisions again and records the new UUID.

The image carries the installation's own timeline. `mkfs.ext4 -d` takes only
modification times from the tarball (every change and access time was the
epoch, every birth time the moment of mkfs), so the last customize hook records
each path's access, change, birth and modification time with nanoseconds
(`find -printf`, stored as `inode-times` beside the tarball and in the root
filesystem cache), and `apply_timeline` writes them back with debugfs: changed
no earlier than modified (cleanup after the record touched some directories),
born no later than changed, accessed no earlier than born; a path added after
the record was born when the installation ended. The superblock follows an
installer's disk: created a minute or two before the first package (mkfs runs
under `E2FSPROGS_FAKE_TIME`), last mounted (once, at `/target`) just before it,
last written when the installation ended, and lifetime writes a little above
the space in use.

Its configuration files are the installer's: apt-setup's `sources.list` (the
netinst image's commented `cdrom` line named after the point release, `main
non-free-firmware`, `deb-src`, the updates comment block, the removable-media
note) with the indexes it lists fetched; fstab's commented header,
`errors=remount-ro` and the `/dev/sr0` line (`/media/cdrom0` and the `cdrom`
link exist); `/etc/hosts` with the IPv6 comment; locale, keyboard and time
zone answered through debconf (`locale.gen` the full commented list,
`default_environment_locale` set, no `/etc/timezone`); `/etc/adjtime` UTC;
D-Bus's `machine-id` link; `tasksel/first` and popcon answers; the
installation's dpkg, alternatives and apt logs (`--skip=cleanup/reproducible`).
`/tmp` stays on the root disk through a `tmp.mount.d/override.conf` condition
(`ConditionPathIsMountPoint=/tmp`), not a mask. Its command line is GRUB's:
`BOOT_IMAGE=/boot/vmlinuz-<release> root=UUID=<uuid> ro quiet` (no serial
console, no `panic=-1`); the app replaces the UUID with the one provisioning
gave the VM's disk (`vm_kernel_append`, from the account record), and the
bootstrap initrd finds it with `findfs` on any bus (falling back to the first
disk for a disk from before), mounts it, grows it, and remounts it read-only
for the boot's fsck. The conformance harness still waits for the login prompt
on the serial port: its VMs ask for a serial console
(`BackendOptions::serial_console` appends `console=tty0 console=ttyS0` to a
command line that names none; the app never sets it), since a readiness probe
run would break the suite's whole-boot packet accounting. Provisioning creates the account as the installer's
adduser does (full name `<Name>,,,`, the installer's groups where they exist,
a 0700 home) and writes a machine ID of the VM's own. The guest hashes the
password itself: provisioning runs the guest's `chpasswd` (through PAM, as
`passwd` does, so Debian 13 stores yescrypt `$y$`) with the password in a
here-document of the guestfish `sh` command, never in a file on the disk or a
command line, and the command prints the hash the guest stored
(`password_commands`, `printed_hash`). The record keeps that hash; a reset sets
it again with `chpasswd -e` and checks the guest kept it. Records written
before 0.7.1 keep their host-made SHA-512 hashes (`validate_hash` takes both).
The host needs no crypt of its own, only `guestfish` (App dependencies:
`libguestfs-tools` on Debian, Ubuntu and Kali, `libguestfs` on Fedora,
openSUSE and Arch).

The disk and kernel are an installed PC's. The base disk carries an MBR table
with one bootable root partition at 1 MiB (`console_disk`; mkfs and every
debugfs pass work at that offset, `CONSOLE_ROOT_SIZE` 3 GiB of the 4 GiB
disk). Provisioning lays the VM's disk out as partman does
(`partition_plan`): the root grown to a MiB before the swap partition, `sda5`
in an extended `sda2` starting two sectors before it, about the VM's RAM (256
MiB at least, a quarter of the disk at most), the last MiB free; the swap gets
a UUID, fstab its line, the MBR a
disk identifier of the VM's own (set last, after unmounting: sfdisk makes
the kernel read the table again and the partition nodes vanish for a moment), and GRUB is set up as the
installer's grub-installer does it (`BOOT_LOADER`): `grub-install --force
/dev/sda` writes the boot code into the MBR and the gap before the root
partition and `/boot/grub/i386-pc` (core.img finds the root by this VM's UUID,
so each VM runs it), debconf gets `grub-pc/install_devices` naming the VM's
disk as its guest sees it on the profile's bus (`guest_account::boot_disk`:
`/dev/vda` on virtio, `/dev/sda` on SATA, `/dev/nvme0n1` on NVMe; QEMU's
virtio disk has no serial, so grub-installer would have no by-id name for it
either, and the appliance's own by-id links name its disk, not the VM's) with
`install_devices_empty false`, and `update-grub` writes `grub.cfg` for the
VM's UUIDs. A sample reading the disk's first sectors finds GRUB, as on an
installed PC. QEMU still boots the Antinomie kernel directly (the GRUB steps
run from the uploaded `guest_account/boot_loader.sh`, `bios` or `uefi`, and
the disk name). A later device profile that moves the disk to another bus
rewrites that answer on the VM's active disk (`set_boot_disk`, as a moved NIC
rewrites its stanza); a snapshot's disk keeps its own answer, which only a
grub-pc upgrade inside a restored snapshot would read. Disks provisioned
before 0.8.0 named `/dev/sda` on every bus and keep it until such a change.

A VM whose stealth profile boots UEFI (OVMF, with or without Secure Boot)
gets a UEFI PC's disk instead (`uefi_disk.rs`). The Debian installer lays a
UEFI disk out differently: GPT, the EFI system partition first (trixie's
partman-auto `recipes-amd64-efi`; FAT32, mounted on `/boot/efi` with
`umask=0077`), then the root, then swap; and its grub-installer installs
os-prober, `grub-efi-amd64` (bringing `grub-efi-amd64-signed`, `shim-signed`,
`efibootmgr` and `mokutil` by recommends) and asks for `shim-signed`, instead
of grub-pc. An ext4 root cannot move, so the image recipe builds both
installations: it bootstraps the system without a boot loader
(`BOOT_LOADERS`), copies it to `/tmp/uefi-root` before the last steps, installs
the BIOS boot loader into the system and the UEFI one into the copy (each
apt transaction as grub-installer makes it, the ESP's mount point made first
as partman mounts it, `grub2/force_efi_extra_removable` answered as
grub-installer answers it for an empty ESP, fstab with the ESP's line and
`# / was on /dev/sda2`), runs the installation's finish (`FINISH`: apt's
history rewritten, the inventory, the resolver) in both, and keeps only what
differs: `scripts/debian-uefi-delta.py` writes every path of the UEFI system
that is new or differs (type, mode, owner, size, modification time, link,
device) to `uefi-root.tar.xz` and records the BIOS paths it lacks and the
delta paths' access, change, birth and modification times, with the disk's
geometry, in `uefi-layout.json` (both in the bundle, part of its identity, a
few MB). The ESP is the size partman gives the app's default 8 GiB disk
(`95small_disk`: about 680 MB, 1 MiB to 650 MiB); the root follows at 650 MiB
with the base's root size.

The first UEFI VM of a base has the app derive the base's UEFI disk once,
beside the base disk (`base-uefi.qcow2`, with `base-uefi.json` naming the base
identity, the recipe and its SHA-256): after a free-space check (the base
disk's allocated size, eight times the delta and 1 GiB more, else a clear
refusal before anything is written) one guestfish run lays GPT out on a new
qcow2 of the base disk's size (partition types set, names empty as partman
leaves them), copies the root filesystem sparsely after the ESP, removes the
recorded paths, unpacks the delta and sets the delta's times with debugfs on
the unmounted filesystem. The stages show in a progress window ("Preparing
the UEFI disk"). The VM's disk is then an overlay of that disk, and its copy
of the base record names it (`uefi_disk`, `Bundle::vm_disk`), which every
backing check, snapshot, Disks tab source, deletion, duplication and data
migration uses. A reset lays the disk out again if it is gone; a start
refuses a UEFI disk whose checksum changed. Provisioning recognises the GPT
disk (`part-get-parttype`): the root is `sda2`, swap goes to `sda3` right
after it (type Linux swap, after `part-expand-gpt` moves the backup GPT to the
end of a larger disk), the ESP gets a FAT filesystem of the VM's own, fstab
its UUID, and `grub-install --target=x86_64-efi --efi-directory=/boot/efi
--force-extra-removable --no-nvram` puts the shim and GRUB in `EFI/debian` and
`EFI/BOOT`; the disk and its partitions get GUIDs of their own last, and the
initramfs's device numbers say `8:2`. The firmware's `debian` boot entry is
written by the bootstrap initrd: on a UEFI boot (`/sys/firmware/efi`) from a
GPT disk whose first partition is an ESP, it builds the load option efibootmgr
would (`HD(1,GPT,<partition GUID>,<start>,<size>)/File(\EFI\debian\shimx64.efi)`,
description `debian`, active), writes it as the first free `Boot####` (or
replaces its own older one) through efivarfs and puts it first in
`BootOrder`, so the VM's variable store keeps it. BIOS VMs keep the base disk
unchanged, and a saved profile cannot switch an existing VM between BIOS and
UEFI (its disk was installed for one; a new VM is needed). What stays
different: OVMF boots the Antinomie kernel from QEMU's loader, so
`BootCurrent` names that entry, not `debian`.

The resume device is the installer's answer (base-installer writes
`/etc/initramfs-tools/conf.d/resume` just before it installs the kernel):
`RESUME=UUID=<swap uuid>`, or `RESUME=none` when the disk has no room for a
swap partition. Because the installer writes it first, update-initramfs copies
it into the initramfs (`conf/conf.d/resume`, no `zz-resume-auto`), so
provisioning puts it into each `/boot/initrd.img-*` as well
(`guest_account/initrd_resume.py`, uploaded with guestfish and run by the
guest's own python3 and zstd): the main archive is unpacked, the entry
inserted where mkinitramfs's sorted list puts it (`cp -p`: mode 0644, the
file's time), and the archive packed again exactly as before otherwise (members,
order, links, padding) and compressed as mkinitramfs does (`zstd -q -9 -T0`
from a pipe); uncompressed archives in front of it stay byte for byte. The
device and inode numbers the files had in mkinitramfs's directory on the
build machine become the installed root's (8:1, `/dev/sda1` as fstab's
comment says; inodes from near `/var/tmp`, relative order and hard links
kept). The file and its directory take a time a little before the kernel
image's change time (when the installer unpacked it); the image keeps its
own times. A reset provisions again and replaces the entry. Growing the disk in the VM's settings grows the root the same way
(`grow_disk`, keeping the swap's UUID and size); the bootstrap initrd grows only
whole-disk roots (BusyBox, the desktops) now. The kernel packages are
Debian's own (`debian_kernel_debs`): `linux-image-6.12.94+deb13-amd64` and
`linux-image-amd64` 6.12.94-1 exactly as linux-signed-amd64 6.12.94+1 shipped
them to trixie-security, taken from snapshot.debian.org
(`DEBIAN_KERNEL_ARCHIVE`, the day they were published). The archive's
`InRelease` must verify against the Debian archive keyring (`gpgv`, else
`sqv`), `main/binary-amd64/Packages.xz` must match its SHA-256 there, and each
`.deb` the index entry and the SHA-256 pinned in `DEBIAN_KERNEL_PACKAGES`.
build-base.py keeps them in its inputs directory (`--kernel-package-cache`);
a copy there that matches its pin is used without the network, and the root
filesystem cache knows them by the pins, so a cached root needs neither. They
are installed before the rest of the customization (apt brings apparmor by
recommends) and their maintainer scripts run as on an install (depmod,
`linux-update-symlinks` for `/vmlinuz` and `/initrd.img`, initramfs-tools
building `/boot/initrd.img-*` from Debian's modules); GRUB (`grub-pc`,
`os-prober`) is installed as the installer installs it. So `/boot` holds
Debian's signed image (0644), configuration and `System.map`, and
`/usr/lib/modules/6.12.94+deb13-amd64` Debian's module tree; the build fails
unless `dpkg --verify` reports nothing for both packages. QEMU boots the
Antinomie kernel directly (`-kernel`), so the guest never holds it. That
kernel (0.8.0, stock profile, below) has Debian's configuration, structure
layouts, export table and module-signing certificate, so Debian's modules are
its own: nothing is added to the module tree, the index is the one Debian's
postinst made, and the initramfs Debian's postinst built (from all of Debian's
modules) stays; `modprobe`, udev and `lsmod` behave as on a Debian install.
(Before 0.8.0 the kernel refused Debian's modules, its own went to `updates/`
under an index that named only them, and the initramfs was rebuilt from
Debian's index after the customization.) apt may install the image from
the trixie mirror rather than the verified copy when the mirror carries the
same version: the archive serves one file per version (the same SHA-256).

Its kernel is the **stock** profile (0.8.0; before, it shared BusyBox's
minimal profile): Debian 13's resolved configuration, unchanged but for the
recorder (see "Debian's module ABI" below). The release is Debian's
(`6.12.94+deb13-amd64`) and it is compiled with `x86_64-linux-gnu-gcc-14`.

Debian Minimal's banner is Debian's own, byte for byte. Its `/boot` holds
Debian's genuine image, whose `linux_banner` a program can unpack and compare
with `/proc/version`, so the Antinomie kernel must name the same release,
build user, compiler, linker and build string: `Linux version
6.12.94+deb13-amd64 (debian-kernel@lists.debian.org) (x86_64-linux-gnu-gcc-14
(Debian 14.2.0-19) 14.2.0, GNU ld (GNU Binutils for Debian) 2.44) #1 SMP
PREEMPT_DYNAMIC Debian 6.12.94-1 (2026-06-20)`, read from that package's
`/boot/vmlinuz` and pinned as the adapter's `KERNEL_BANNER` (a network test
reads it from the pinned package again). The release, user and build string
come from the adapter (`SOURCE_MAINTAINER`, `SOURCE_DATE_EPOCH`); the
compiler and linker versions only from Debian 13's tools: gcc-14 14.2.0-19
and binutils 2.44 (a host with a newer binutils, such as Kali's 2.47, writes
its own version). So: `build-base.py` refuses a debian-minimal job before
building when the kernel build script's compiler or linker
(`ANTINOMIE_PRINT_TOOLCHAIN=1` prints their version lines) differs from the
banner's (`require_debian_toolchain`); the app's Automatic mode builds Debian
Minimal in the container builder or the QEMU builder (both Debian 13) on such a
host, and Native says why it cannot (`native_obstacle`: `toolchain_obstacle`, the host's lines read once);
the cached kernel's identity names the toolchain, so a BusyBox kernel linked
by another binutils is never reused for it; the kernel build script logs the
banner (`kernel-banner` in the build tree) and warns when it is not Debian's;
and the image recipe refuses a console kernel whose banner (`kernel_banner`,
unpacked from the bzImage) differs from `KERNEL_BANNER`, recording the banner
in `build.json`. BusyBox keeps building natively with any toolchain.

`/boot/System.map-6.12.94+deb13-amd64` stays the file Debian ships: the
image package carries only a placeholder ("The real System.map is in the
linux-image-<version>-dbg package"), so no installed Debian system has a
symbol map to compare with `/proc/kallsyms` either, and `dpkg --verify` stays
clean. What remains different cannot be made equal by any file in the image:
the running kernel is another binary than Debian's, so its symbols and their
offsets (`/proc/kallsyms`, as root) and its GNU build ID (`/sys/kernel/notes`,
any user) differ from Debian's `-dbg` package and `/boot/vmlinuz`. Loading
Debian's modules (a module ABI of Debian's) does not change that; only
running Debian's own image would.

Debian builds the root disk's controllers and ext4 as modules, which the
bootstrap initrd cannot leave to udev: the recipe takes them from Debian's
image package (`root_modules`: virtio_blk; scsi_common, scsi_mod, libata,
libahci, ahci and sd_mod; nvme-auth, nvme-core and nvme; crc32c_generic,
crc32c-intel, crc16, mbcache, jbd2 and ext4; efivarfs for the UEFI boot entry),
decompressed (the signature Debian appended before compressing stays), with
each one's `depends` checked against the order, and the initrd's `/init` loads
each group when the VM has the controller (a virtio block device, a PCI class
0x010601 AHCI or 0x010802 NVMe controller), as Debian's initramfs would, with
BusyBox's `insmod` (`module_loading` in `build-monitor-image.py`; their hashes
and package are in the initrd's provenance). They stay loaded after
`switch_root`; udev loads the rest. So `stealth_support` still offers `uefi,
sata, nvme, dhcp` (`module_buses`), and the fixed display takes Debian's
virtio-gpu module (`fixed_display_config(modules_ok)`). The recipe refuses
`--modules` for this base and a kernel whose configuration is not Debian's
`/boot/config` (`stock_config`: only the recorder, the embedded configuration,
the release suffix, the signing-key path, what Debian's config file omits and
the toolchain's own values may differ). The root filesystem cache
is `images/rootfs-debian-minimal.tar`.

Rootless builds: mmdebstrap's hooks run as the user namespace's root, a
subordinate UID that cannot read or write the invoking user's mode-0700
staging directory, so files cross through mmdebstrap's `upload` and
`download` special hooks (run as the invoking user), and the staging directory
is made traversable (0711) in unshare mode. Builds before this ran only in the
QEMU builder (`--mode=root`).

### Accepted Debian Xfce VM base update

Full Debian userspace with Xfce (2026-10-06) adds per-VM credential creation
with password-protected sudo. Add Debian13
trixie amd64 alongside BusyBox; retain patched Linux6.12.94, V7, kernel-only
monitoring controls, disconnected default and existing disk/archive identities.

Optional bounded guest-profile bundle metadata distinguishes installed bases,
declares resource minima and credential/display requirements. Legacy bundles
without metadata preserve their old identity. Base import and creation stay
backend-owned; UI only selects values and transient credentials.

Debian New VM requires username/password/confirmation; create UID/GID1000 with
local password login and sudo, root locked, SSH disabled, no autologin. Offline
libguestfs provisioning precedes publication. Passwords must not be serialized
in configuration/preferences/recordings, displayed in Debug, or passed in argv.
A private0600 per-VM username/salted-hash provisioning record can support reset
and duplicate; no plaintext retained. The hash is the one the guest's own
chpasswd made at creation. Reset reapplies original credentials and
publishes replacement disk only after provisioning succeeds. Existing VMs are
not automatically converted or modified.

Image build uses authenticated Debian inputs and retains system account file
ownership, package provenance and licenses. This
does not complete the remaining syscall/async semantics of the native syscalls update below.

## Guest facade (0.9.0)

Guest patch 0052, contract revision 21 unchanged (boot options only). A
real-VPS comparison (a KVM cloud instance shows the hypervisor flag, SeaBIOS,
BOCHS/BXPC ACPI tables, Red Hat PCI IDs, virtio disks and a QEMU DVD-ROM)
showed that server and cloud machines legitimately look like QEMU/KVM, so the
facade applies to the **desktop and laptop machine profiles only**: a program
on a server or cloud profile still sees QEMU's devices, as it would on such a
host.

**Passing it.** `stealth::facade_options()` (`stealth/launch.rs`) turns the
profile's machine (`catalog/facade.rs`, cited in `catalog/SOURCES.md`, "Guest
facade") into `antinomie_f*` boot options, added by `vm.rs` for a base whose
`stealth_support` lists `facade` (both image builders write it when the kernel
has `CONFIG_ANTINOMIE_FACADE`); `ant_cmdline_take()` (patch 0014) takes them out
of the command line before the kernel prints it.

| Option | Value | Shown |
|---|---|---|
| `antinomie_fpci` | `VVVVDDDD=vvvvddddSSSSssss,...` | QEMU's VGA (1234:1111) as the machine's integrated GPU, QEMU's NVMe controller (8086:5845) as the laptop's drive, each with its subsystem |
| `antinomie_fsub` | `SSSSssss` | the board's subsystem (the identity's NIC subsystem) on every device with QEMU's 1af4 |
| `antinomie_fnvme` | `"model,firmware,OUI,VID,SSVID"` | Identify Controller and Namespace data, the firmware slot log |
| `antinomie_facpi` | `"CCCC:RRRRRRRR:OEMID :TABLEID "` | the ACPI creator ID and revision, the machine's OEM IDs |
| `antinomie_fdrm` | `i915` or `amdgpu` | the display driver's names |
| `antinomie_finput` | `"VVVV:PPPP:BBBB,maker,product"` | QEMU's USB HID devices as the maker's mouse |
| `antinomie_fefi` | `"vendor"` | the boot log's EFI firmware vendor |
| `antinomie_fnocd` | (flag) | a machine without an optical drive: QEMU's default CD-ROM (q35 adds `ide2-cd0` when no IDE disk is given, as with an NVMe root) is not attached |

**What the guest shows** (`kernel/antinomie/facade.c`; the kernel's own
`pci_dev`, Identify data copies, ACPI tables, drivers and the uevents it sends
keep the true identities, so drivers bind, quirks apply and udev loads the
emulated devices' modules):

| View | Hook |
|---|---|
| PCI config space read by user space (sysfs `config`, `/proc/bus/pci/BB/DD.F`; lspci reads both): bytes 0-3 and, in a type 0 header, 0x2c-0x2f | `pci_user_read_config_*()` (`drivers/pci/access.c`) |
| sysfs `vendor`, `device`, `subsystem_vendor`, `subsystem_device`, `modalias`; the `uevent` file as read (`PCI_ID`, `PCI_SUBSYS_ID`, `MODALIAS`, same width) | `pci-sysfs.c`, `uevent_show()` (`drivers/base/core.c`) |
| `/proc/bus/pci/devices`, the boot log's `[vvvv:dddd] type` line | `proc.c`, `probe.c` |
| NVMe Identify Controller (VID, SSVID, model, firmware, IEEE OUI, a subsystem NQN as `nvme_init_subnqn()` makes one), Identify Namespace and the descriptor list (QEMU's 52:54:00 EUI-64 prefix → the maker's OUI) as the driver reads them; the same data and the firmware slot log through `NVME_IOCTL_ADMIN_CMD`/`ADMIN64` (nvme-cli, smartctl) | `drivers/nvme/host/core.c`, `ioctl.c` |
| ACPI tables read through `/sys/firmware/acpi/tables` (root) and the boot log's table lines: creator `BXPC` → the maker's, OEM IDs `BOCHS`/`BXPC` and OVMF's `INTEL`/`EDK2` (BGRT) → the machine's, in the DSDT the fw_cfg device's name `FWCF` → an unused name and its `_HID "QEMU0002"` → `EisaId("PNP0C02")` padded with `Noop`; checksum recomputed | `drivers/acpi/sysfs.c`, `acpica/tbprint.c` |
| `bochs-drm`'s PCI driver name (sysfs, `lspci -k`, the log), its resource names (`/proc/iomem`, `/proc/ioports`), DRM_IOCTL_VERSION (name, description, version of i915 or amdgpu), the fbdev name (`/proc/fb`: `i915drmfb`, `amdgpudrmfb`) | `pci-driver.c`, `kernel/resource.c`, `drm_ioctl.c`, `drm_fb_helper.c` |
| QEMU's USB HID devices (vendor 0627, maker `QEMU`): IDs, release, maker and product strings, no serial, set right after the hub reads the descriptors (sysfs, the `descriptors` file, the input device's name and IDs) | `usb_new_device()` (`drivers/usb/core/hub.c`) |
| the EFI firmware vendor in the boot log | `efi_systab_report_header()` |
| QEMU's default ATAPI drive (`QEMU DVD-ROM`): disabled before it is attached, so no `sr0`, `/proc/scsi/scsi` entry or `/dev/cdrom` | `ata_dev_configure()` (`drivers/ata/libata-core.c`) |
| the DRM core's `Initialized ...` and bochs's `Found bochs VGA` log lines (root) | `drm_drv.c`, `tiny/bochs.c` |

**Profiles.** Every desktop and laptop machine has its GPU from a public report
of a unit (`catalog/SOURCES.md`); the ThinkPads, the M.2 Latitudes (5420,
5430, 5530) and the ProBook G8s boot from NVMe again with a drive seen in their
units or a sibling's, and the realistic desktop and laptop presets use the USB
tablet (on q35's ICH9 USB controllers, Intel IDs) instead of the virtio tablet,
a Red Hat PCI device. The display is renamed only where QEMU's VGA is bochs-drm:
a graphical base uses virtio-gpu, which keeps its name (a desktop session's
Mesa and Xorg pick drivers by these names).

**Measured** (laptop profile, Debian Minimal; see the task record for the run):
`pci.vendors`, `pci.subsystems`, `pci.config`, `acpi.oem-ids`, `acpi.tables`,
`display.fb`, `display.drm`, `block.nvme`, `nvme.identify`, `usb.devices`,
`input.names`, `input.ids` and `firmware.vendor` pass.

**Still visible** (`giveaways()` for a facade profile): QEMU's IDs to root
reading PCI config space through I/O ports (0xcf8/0xcfc), USB string requests
made to the device through usbfs (`lsusb -v`), the tablet's absolute axes, the
q35 chipset's ICH9 (2009) device IDs behind the board's subsystem, the Bochs
display's registers and modes behind its GPU name, the `bochs` module name in
`/sys/module`, udev's device database on Debian bases (it records the uevents'
true IDs and the hwdb's vendor names), OVMF's boot entries in efivarfs (they
name QEMU's devices) and its vendor in the system table to root reading memory;
an older base (no `facade`) shows QEMU's devices.

**Debian bases.** A stock-profile kernel loads Debian's own modules (see
"Debian's module ABI"), so only the facade's built-in hooks act there: PCI IDs
and config space, `uevent`, `/proc/bus/pci`, ACPI tables, the EFI vendor, the
PCI driver and resource names. NVMe, DRM, USB and libata are Debian's modules:
the NVMe Identify data, `DRM_IOCTL_VERSION`, the fbdev name, the DRM and bochs
log lines, the USB HID strings and QEMU's DVD-ROM stay QEMU's on Debian bases;
the BusyBox bases build them in and show the facade's.

## Aged uptime (0.9.0)

Guest patch 0053, contract revision 21 unchanged (a boot option). Each VM gets
a boot age when its preset is chosen (`StealthProfile.boot_age_s`,
`BootAge::draw`, log-uniform: desktop and laptop 3 hours to 6 days, server and
cloud 3 days to 120 days; Transparent 0), kept for the VM's life; `vm.rs` passes
`antinomie_boot_age=SECONDS:MODEL` to a base listing `uptime` (from
`CONFIG_ANTINOMIE_BOOT_AGE`); another base falls back to a fresh boot. The clock
model follows the machine (user decision 2026-11-05):

| Kind | Model | After the first launch |
|---|---|---|
| desktop, laptop | `suspend`: it booted N ago and slept for part of it | CLOCK_BOOTTIME and uptime large, CLOCK_MONOTONIC smaller |
| server, cloud | `continuous`: up without a break for N | CLOCK_MONOTONIC = CLOCK_BOOTTIME, both carrying the age |

**Mechanism** (`kernel/antinomie/uptime.c`). The guest boots the age in the
past and reaches the present at the host's first EXEC command, after the boot's
own records are written (the boot wait reads files and launches nothing):

- *While booting* the wall clock runs the age behind the time it was given:
  `timekeeping_init()` sets it back, and `do_settimeofday64()` shifts every
  setting before the first launch (the RTC at boot, timesyncd's saved time,
  hwclock). The boot's records carry that time: the utmp/wtmp boot record (the
  BusyBox base's `rcS` writes it at `btime`; systemd's `random-seed`,
  `systemd-update-utmp`, wtmpdb), the journal's first entries
  (`journalctl --list-boots`), the files the boot creates; `btime`,
  CLOCK_BOOTTIME, uptime, init's start time and the kernel log's place in wall
  time (`dmesg -T`) agree with them.
- *At the first launch* `ant_timekeeping_present()` (`kernel/time/timekeeping.c`)
  steps the wall clock to the true time (computed from CLOCK_MONOTONIC and the
  true time at `timekeeping_init()`, so a clock set while booting does not
  count twice) and CLOCK_BOOTTIME forward by the age, as a resume adds a sleep,
  then `clock_was_set()`. Suspend: CLOCK_MONOTONIC does not move, and the
  kernel log's timestamps do not count the sleep (as after a real resume).
  Continuous: programs' CLOCK_MONOTONIC runs the age ahead of the kernel's from
  then on: `clock_gettime()` (`timens_add_monotonic()`), the vDSO
  (`update_vsyscall()`), absolute timers, futexes, `clock_nanosleep` and timerfd
  (`timens_ktime_to_host()`), and the kernel log's timestamps (`printk`), so
  `dmesg -T` places later messages in the present; each CPU's idle time
  (`/proc/stat`, `/proc/uptime`) has 97 % of the age in it, as a mostly idle
  server's would (a sleep adds none, as a real one does not).
- *Never moved*: the kernel's CLOCK_MONOTONIC, jiffies and scheduler clock. The
  recorder's timestamps, the host's accounting of guest time and every kernel
  timeout run on them; `task->start_boottime` is an identity to the host only.

**Snapshots.** A memory snapshot keeps the guest's clocks and offsets; a VM
restored before its first launch steps to the present at the next one. The age
is the same at every start.

**Still visible:** suspend — CLOCK_BOOTTIME ahead of CLOCK_MONOTONIC, no
suspend in the log or `/sys/power/suspend_stats`, the journal's jump without a
sleep entry; continuous — processes started at boot see their clocks move
forward at the first launch, and timestamps the kernel hands out on its own
monotonic clock (input events, DRM vblanks) and io_uring's absolute timeouts
are on the kernel's clock, behind programs' by the age (a desktop session on a
server profile would notice).

**The check.** `stealth-probe.c`: `base.uptime`, `base.uptime-views`
(/proc/uptime, `sysinfo`, CLOCK_BOOTTIME and `now − btime`), `base.boot-record`
(utmp at `btime`), `base.boottime-timers`, `base.monotonic-timers` (absolute
timerfd on CLOCK_MONOTONIC), `base.init-start` (init started at the boot) and
`base.time-asleep` (information).
