// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Provisioning of a VM whose guest programs the host's x86-64 libguestfs
//! appliance cannot run (Debian arm64, 0.9.0). The appliance does only what
//! needs no guest program: the layout, the ESP, the root's new UUID and
//! directory hash seed, fstab, the NIC stanza, the machine ID and the GPT
//! GUIDs, plus a staging script and a oneshot unit. One boot of the VM
//! itself (the base's kernel, no NIC, a serial console, under TCG) then runs
//! the guest-program part: the account, GRUB, the initramfs's resume device
//! and the password, which reaches chpasswd over QEMU's fw_cfg from a private
//! host file and never touches the disk. The guest prints the hash it stored
//! between two markers and powers off; the appliance then removes what the
//! boot left, so the first boot the user sees is the disk's first.
use super::*;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// The fw_cfg item that carries the password (or the recorded hash) into
/// the provisioning boot; the guest reads it once, from sysfs.
const FW_CFG_NAME: &str = "opt/antinomie/provision";
/// The lines the guest prints around the hash it stored, and before the
/// step that failed.
const HASH_BEGIN: &str = "provision-hash-begin";
const HASH_END: &str = "provision-hash-end";
const FAILED: &str = "provision-failed ";
/// The provisioning boot under TCG: the measured boot takes a few minutes
/// (see docs/implementation.md); a loaded host gets several times that.
const BOOT_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// The provisioning boot's machine, whatever the VM's: enough RAM for the
/// initramfs's recompression, two vCPUs (one host thread each under TCG).
const BOOT_RAM_MIB: u32 = 1024;
const BOOT_CPUS: &str = "2";
/// The CPU of the provisioning boot: a core without pointer authentication,
/// which TCG emulates slowly.
const BOOT_CPU: &str = "cortex-a72";
/// The serial console's most bytes: a boot that floods it is stopped.
const SERIAL_LIMIT: u64 = 8 << 20;
/// What a Debian 13 boot may write that the base need not have; each is
/// removed after the provisioning boot unless the disk had it before. The
/// provisioning boot starts none of the units that write them (it isolates
/// its own target), so this only guards against a changed base.
pub(super) const BOOT_TRACES: &[&str] = &[
    "/var/lib/systemd/random-seed",
    "/var/lib/systemd/credential.secret",
    "/var/lib/systemd/timers",
    "/var/lib/systemd/timesync",
    "/var/lib/systemd/coredump",
    "/var/lib/wtmpdb/wtmp.db",
    "/var/lib/lastlog/lastlog2.db",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/log/private",
    "/etc/.updated",
    "/var/.updated",
];

/// How a VM of a foreign-architecture base boots once for its provisioning:
/// the base's kernel, initrd and command line on the machine of its
/// architecture.
#[derive(Clone, Debug)]
pub(crate) struct ProvisionBoot {
    arch: crate::api::GuestArch,
    qemu: PathBuf,
    kernel: PathBuf,
    initrd: Option<PathBuf>,
    append: String,
}

impl ProvisionBoot {
    /// None for an x86-64 base, whose account the appliance makes offline.
    pub(crate) fn for_bundle(
        options: &crate::api::BackendOptions,
        bundle: &storage::Bundle,
    ) -> Result<Option<Self>, String> {
        if bundle.arch == crate::api::GuestArch::X86_64 {
            return Ok(None);
        }
        let machine = crate::vm::Machine::of(bundle.arch)?;
        if machine != crate::vm::Machine::Virt {
            return Err(format!(
                "{} VMs cannot have their guest account made",
                bundle.arch.label()
            ));
        }
        Ok(Some(Self {
            arch: bundle.arch,
            qemu: machine.qemu(&options.qemu),
            kernel: bundle.kernel.clone(),
            initrd: bundle.initrd.clone(),
            append: bundle.kernel_append.clone(),
        }))
    }

    /// The QEMU arguments of the provisioning boot of `disk`, whose root
    /// filesystem now has `root_uuid`, booting `target`, with the secret in
    /// `secret` (a private file).
    fn args(&self, disk: &Path, root_uuid: &str, target: &str, secret: &Path) -> Vec<String> {
        let path = |path: &Path| crate::stealth::escape(&path.to_string_lossy());
        // The base's command line for this disk, its serial console, KPTI
        // off (which TCG runs slowly), no reboot after a panic, and the
        // provisioning target in place of the default one.
        let append = format!(
            "{} console={} panic=-1 antinomie_kpti=off systemd.unit={target}",
            crate::vm::vm_kernel_append(&self.append, Some(root_uuid)),
            crate::vm::Machine::Virt.console()
        );
        let mut args: Vec<String> = [
            "-machine",
            "virt,gic-version=3",
            "-accel",
            "tcg",
            "-cpu",
            BOOT_CPU,
            "-smp",
            BOOT_CPUS,
            "-m",
        ]
        .map(str::to_owned)
        .into();
        args.push(BOOT_RAM_MIB.to_string());
        args.extend(["-kernel".into(), self.kernel.to_string_lossy().into_owned()]);
        if let Some(initrd) = &self.initrd {
            args.extend(["-initrd".into(), initrd.to_string_lossy().into_owned()]);
        }
        args.extend([
            "-append".into(),
            append,
            "-drive".into(),
            format!("file={},format=qcow2,if=none,id=root", path(disk)),
            "-device".into(),
            "virtio-blk-pci,drive=root".into(),
            "-fw_cfg".into(),
            fw_cfg_option(secret),
        ]);
        args.extend(
            [
                "-nic",
                "none",
                "-display",
                "none",
                "-monitor",
                "none",
                "-serial",
                "stdio",
                "-no-reboot",
            ]
            .map(str::to_owned),
        );
        args
    }

    /// Boot `disk` once with `secret` over fw_cfg and return what its serial
    /// console printed. The secret's file is private and removed as soon as
    /// the guest prints (QEMU has read it by then), and in every case at the
    /// end.
    fn run(
        &self,
        disk: &Path,
        root_uuid: &str,
        target: &str,
        secret: &str,
    ) -> Result<Vec<u8>, String> {
        crate::dependencies::require_tool(&self.qemu, "qemu-system-arm")?;
        let staging = Staging::new("antinomie-provision-boot")?;
        let secret_path = staging.path.join("secret");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&secret_path)
            .and_then(|mut file| file.write_all(secret.as_bytes()))
            .map_err(|_| "cannot stage the provisioning secret")?;
        let serial_path = staging.path.join("serial.log");
        let serial = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&serial_path)
            .map_err(|_| "cannot create the provisioning console log")?;
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(staging.path.join("qemu.log"))
            .map_err(|_| "cannot create the provisioning QEMU log")?;
        let mut command = crate::vm::qemu_command(&self.qemu);
        command
            .args(self.args(disk, root_uuid, target, &secret_path))
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::from(serial))
            .stderr(Stdio::from(stderr));
        let mut child = command
            .spawn()
            .map_err(|_| "the provisioning boot's QEMU could not be started")?;
        let label = self.arch.label();
        let deadline = Instant::now() + BOOT_TIMEOUT;
        let mut secret_staged = true;
        let outcome = loop {
            let printed = fs::metadata(&serial_path).map_or(0, |metadata| metadata.len());
            if secret_staged && printed > 0 {
                secret_staged = fs::remove_file(&secret_path).is_err();
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {}
                Err(_) => break Err("the provisioning boot's QEMU could not be waited for".into()),
            }
            if printed > SERIAL_LIMIT {
                break Err(format!(
                    "the {label} VM's provisioning boot flooded its console"
                ));
            }
            if Instant::now() >= deadline {
                break Err(format!(
                    "the {label} VM's provisioning boot did not power off within {} minutes; \
                     unpublished disk retained for cleanup",
                    BOOT_TIMEOUT.as_secs() / 60
                ));
            }
            thread::sleep(Duration::from_millis(200));
        };
        let status = match outcome {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        if !status.success() {
            return Err(format!(
                "the {label} VM's provisioning boot failed{}",
                qemu_hint(&staging.path.join("qemu.log"))
            ));
        }
        fs::read(&serial_path).map_err(|_| "cannot read the provisioning console log".into())
    }
}

/// The `-fw_cfg` value: the item's name and the private file it is read from.
pub(super) fn fw_cfg_option(secret: &Path) -> String {
    format!(
        "name={FW_CFG_NAME},file={}",
        crate::stealth::escape(&secret.to_string_lossy())
    )
}

/// The last line QEMU wrote to its log (its reason to stop), for an error.
fn qemu_hint(log: &Path) -> String {
    let text = fs::read(log).unwrap_or_default();
    let tail = &text[text.len().saturating_sub(2048)..];
    String::from_utf8_lossy(tail)
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map_or_else(String::new, |line| format!("; QEMU said: {}", line.trim()))
}

/// A private host folder, removed when dropped.
struct Staging {
    path: PathBuf,
}
impl Staging {
    fn new(prefix: &str) -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("{prefix}-{}", storage::unique_id()));
        storage::private_dir(&path).map_err(|_| "cannot create a private provisioning folder")?;
        Ok(Self { path })
    }
    fn write(&self, name: &str, text: &str) -> Result<PathBuf, String> {
        let path = self.path.join(name);
        fs::write(&path, text).map_err(|_| "cannot stage a provisioning file")?;
        Ok(path)
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// What the provisioning boot's console reported.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Report {
    /// The hash the guest stored, between the markers.
    Hash(String),
    /// The step of the guest's script that failed.
    Failed(String),
    /// Neither.
    Nothing,
}

/// The report on `console`: the last hash between [`HASH_BEGIN`] and
/// [`HASH_END`] (exactly one line between them), else the last failed step.
pub(super) fn console_report(console: &[u8]) -> Report {
    let text = String::from_utf8_lossy(console);
    let lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.trim_matches(|c: char| c == '\r' || c == ' '))
        .collect();
    let hash = lines
        .iter()
        .rposition(|line| *line == HASH_BEGIN)
        .and_then(|begin| match lines.get(begin + 1..begin + 3) {
            Some([hash, end]) if *end == HASH_END && !hash.is_empty() => Some((*hash).to_owned()),
            _ => None,
        });
    if let Some(hash) = hash {
        return Report::Hash(hash);
    }
    lines
        .iter()
        .rev()
        .find_map(|line| line.strip_prefix(FAILED))
        .filter(|step| {
            !step.is_empty()
                && step.len() <= 32
                && step.bytes().all(|c| c.is_ascii_lowercase() || c == b'-')
        })
        .map_or(Report::Nothing, |step| Report::Failed(step.to_owned()))
}

/// fstab for this VM's disk, as the x86-64 script's sed and awk leave it:
/// the root's line names `uuid`; on a partitioned disk with a swap partition
/// (`swap`: its UUID and number) its line goes before the CD drive's, as the
/// installer writes it.
pub(super) fn fstab_text(fstab: &str, uuid: &str, swap: Option<(&str, u32)>) -> String {
    let mut out = String::with_capacity(fstab.len() + 160);
    for line in fstab.split_inclusive('\n') {
        if let Some((uuid_swap, number)) = swap
            && line.starts_with("/dev/sr0")
        {
            out.push_str(&format!(
                "# swap was on /dev/sda{number} during installation\nUUID={uuid_swap} none            swap    sw              0       0\n"
            ));
        }
        match root_line_rest(line) {
            Some(rest) => {
                out.push_str("UUID=");
                out.push_str(uuid);
                out.push_str(rest);
            }
            None => out.push_str(line),
        }
    }
    out
}

/// After the UUID of fstab's root line (`UUID=<hex and dashes>`, blanks,
/// `/`, a blank), the rest of the line; None for any other line.
fn root_line_rest(line: &str) -> Option<&str> {
    let value = line.strip_prefix("UUID=")?;
    let end = value
        .find(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .filter(|end| *end > 0)?;
    let rest = &value[end..];
    let blanks = rest.len() - rest.trim_start_matches([' ', '\t']).len();
    let after = rest[blanks..].strip_prefix('/')?;
    (blanks > 0 && after.starts_with([' ', '\t', '\n', '\x0b', '\x0c', '\r'])).then_some(rest)
}

/// /etc/network/interfaces with the installer's stanza for `interface` in
/// place of everything from the stanza's comment on, as the x86-64 script's
/// awk writes it.
pub(super) fn interfaces_text(interfaces: &str, interface: &str) -> String {
    let mut kept: Vec<&str> = interfaces
        .lines()
        .take_while(|line| *line != "# The primary network interface")
        .collect();
    while kept.last().is_some_and(|line| line.is_empty()) {
        kept.pop();
    }
    let mut out: String = kept.iter().map(|line| format!("{line}\n")).collect();
    out.push_str(&format!(
        "\n# The primary network interface\nallow-hotplug {interface}\niface {interface} inet dhcp\n# This is an autoconfigured IPv6 interface\niface {interface} inet6 auto\n"
    ));
    out
}

/// The oneshot unit that runs the staging script in the provisioning boot
/// and powers the VM off after it, whatever its result, and the target the
/// boot isolates (only this unit: no journal, utmp, random seed or timers).
pub(super) fn unit_files(staging: &str, name: &str) -> (String, String) {
    let service = format!(
        "[Unit]\nDescription=Provisioning\nDefaultDependencies=no\nConditionPathExists={staging}/provision.sh\nSuccessAction=poweroff-force\nFailureAction=poweroff-force\n\n[Service]\nType=oneshot\nExecStart=/bin/sh {staging}/provision.sh\nTimeoutStartSec=infinity\nStandardInput=null\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/{}\n",
        crate::vm::Machine::Virt.console()
    );
    let target =
        format!("[Unit]\nDescription=Provisioning\nAllowIsolate=yes\nWants={name}.service\n");
    (service, target)
}

/// What the guest's provisioning script does for this disk.
pub(super) struct GuestPart<'a> {
    pub username: &'a str,
    pub staging: &'a str,
    /// chpasswd gets a hash (`-e`) rather than the password.
    pub hashed: bool,
    /// A GPT disk: GRUB for UEFI on the ESP (the first partition).
    pub gpt: bool,
    /// A partitioned disk: the initramfs's resume line and install device.
    pub initrd: Option<(&'a str, &'a str)>,
}

/// The staging script the provisioning boot runs: the part of the x86-64
/// script that runs guest programs, in the same order, then the password from
/// fw_cfg (read once, straight into chpasswd) and the hash it stored between
/// the markers. A failing step prints its name instead.
pub(super) fn guest_script(part: &GuestPart) -> String {
    let GuestPart {
        username,
        staging,
        hashed,
        gpt,
        initrd,
    } = *part;
    let full_name: String = username
        .chars()
        .enumerate()
        .map(|(index, c)| {
            if index == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    let mut script = format!(
        "set -eu\nstep=remount\ntrap 'status=$?; if [ \"$status\" -ne 0 ]; then printf \"\\n{FAILED}%s\\n\" \"$step\"; fi' EXIT\n\
         mount -o remount,rw /\n\
         step=account\n\
         if getent passwd 1000 >/dev/null || getent group 1000 >/dev/null || getent passwd '{username}' >/dev/null || getent group '{username}' >/dev/null; then exit 1; fi\n\
         addgroup --quiet --gid 1000 '{username}'\n\
         adduser --quiet --uid 1000 --gid 1000 --comment '{full_name},,,' --disabled-password '{username}'\n\
         chmod 0700 '/home/{username}'\n\
         for group in {INSTALLER_GROUPS}; do\n\
         \tif getent group \"$group\" >/dev/null; then adduser --quiet '{username}' \"$group\"; fi\n\
         done\n\
         passwd -l root >/dev/null\n"
    );
    if gpt {
        // The ESP the appliance formatted for this VM (vda1 in this boot):
        // fstab names it, and grub-install puts the shim, GRUB and their
        // fallback copies on it, as on x86-64.
        script.push_str(
            "step=boot-loader\n\
             esp=$(blkid -s UUID -o value /dev/vda1)\n\
             sed -i -E \"s|^UUID=[0-9A-Fa-f-]+([[:space:]]+/boot/efi[[:space:]])|UUID=$esp\\1|\" /etc/fstab\n\
             mount -t vfat -o umask=0077 /dev/vda1 /boot/efi\n\
             grub-install --force --target=arm64-efi --efi-directory=/boot/efi --bootloader-id=debian --force-extra-removable --no-nvram >/dev/null 2>&1\n\
             if command -v update-grub >/dev/null; then update-grub >/dev/null 2>&1 || true; fi\n\
             umount /boot/efi\n",
        );
    }
    if let Some((resume, device)) = initrd {
        script.push_str(&format!(
            "step=initramfs\nmkdir -p /etc/initramfs-tools/conf.d\npython3 -I {staging}/initrd.py {resume} {device}\n"
        ));
    }
    let flag = if hashed { " -e" } else { "" };
    script.push_str(&format!(
        "step=password\n\
         modprobe qemu_fw_cfg\n\
         {{ printf '%s:' '{username}'; cat /sys/firmware/qemu_fw_cfg/by_name/{FW_CFG_NAME}/raw; printf '\\n'; }} | chpasswd{flag}\n\
         hash=$(getent shadow '{username}' | cut -d: -f2)\n\
         rm -rf {staging}\n\
         sync\n\
         printf '\\n{HASH_BEGIN}\\n%s\\n{HASH_END}\\n' \"$hash\"\n"
    ));
    script
}

/// The appliance's commands that remove what the provisioning boot left:
/// the staging folder, the unit, its target and link, the journal of this
/// machine ID, and each of [`BOOT_TRACES`] the disk did not have before.
pub(super) fn trace_commands(
    root: &str,
    staging: &str,
    name: &str,
    machine_id: &str,
    existed: &[bool],
) -> Vec<String> {
    let units = "/etc/systemd/system";
    let mut commands = vec![
        "run".to_owned(),
        format!("mount {root} /"),
        format!("rm-rf {staging}"),
        format!("rm-f {units}/{name}.service"),
        format!("rm-f {units}/{name}.target"),
        format!("rm-rf {units}/{name}.target.wants"),
        format!("rm-rf /var/log/journal/{machine_id}"),
    ];
    for (path, existed) in BOOT_TRACES.iter().zip(existed) {
        if !existed {
            commands.push(format!("rm-rf {path}"));
        }
    }
    commands.extend(["umount-all".to_owned(), String::new()]);
    commands
}

/// Which of [`BOOT_TRACES`] the read pass found (its `exists` answers).
pub(super) fn parse_existing(output: &[u8]) -> Result<Vec<bool>, String> {
    let answers: Vec<bool> = String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| match line.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
        .collect();
    if answers.len() != BOOT_TRACES.len() {
        return Err("the VM disk could not be checked before its provisioning boot".into());
    }
    Ok(answers)
}

impl GuestAccount {
    /// Provision a disk of a foreign-architecture base: the appliance's
    /// offline part, the provisioning boot, then the appliance again to
    /// remove the boot's traces (see the module's comment).
    pub(super) fn provision_foreign(
        &mut self,
        disk: &Path,
        executable: &Path,
        ram_mib: u32,
        password: &Password,
        interface: Option<&str>,
        boot: &ProvisionBoot,
    ) -> Result<(), String> {
        validate_guest_username(&self.username)?;
        let (secret, hashed) = match password {
            Password::Plain(password) => (*password, false),
            Password::Hashed(hash) => {
                validate_hash(hash)?;
                (*hash, true)
            }
        };
        if interface.is_some_and(|name| !valid_interface(name)) {
            return Err("invalid network interface name".into());
        }
        if !valid_boot_disk(self.boot_disk()) {
            return Err("invalid boot disk name".into());
        }
        let probe = run_private(&mut guestfish(executable, disk, false), PROBE, true)?;
        let layout = parse_probe(&String::from_utf8_lossy(&probe))?;
        let host = Staging::new("antinomie-provision")?;
        // The files the appliance edits on the host, and which boot traces
        // the disk has already.
        let mut read = vec![
            "run".to_owned(),
            format!("mount-ro {} /", layout.root),
            format!(
                "download /etc/fstab {}",
                fish_quote(&host.path.join("fstab").to_string_lossy())
            ),
        ];
        if interface.is_some() {
            read.push(format!(
                "download /etc/network/interfaces {}",
                fish_quote(&host.path.join("interfaces").to_string_lossy())
            ));
        }
        read.extend(BOOT_TRACES.iter().map(|path| format!("exists {path}")));
        read.push(String::new());
        let output = run_private(
            &mut guestfish(executable, disk, false),
            read.join("\n").as_bytes(),
            true,
        )?;
        let existed = parse_existing(&output)?;
        let fstab = fs::read_to_string(host.path.join("fstab"))
            .map_err(|_| "the VM disk's fstab could not be read")?;
        let interfaces = interface
            .map(|name| {
                fs::read_to_string(host.path.join("interfaces"))
                    .map(|text| interfaces_text(&text, name))
                    .map_err(|_| "the VM disk's network configuration could not be read")
            })
            .transpose()?;
        let uuid = random_uuid()?;
        let swap_uuid = random_uuid()?;
        let machine_id = random_hex()?;
        let gpt_guids = [
            random_uuid()?,
            random_uuid()?,
            random_uuid()?,
            random_uuid()?,
        ];
        let plan = layout.root_last.map(|root_last| {
            partition_plan(layout.size / 512, root_last, ram_mib, None, layout.gpt)
        });
        let swap = plan.as_ref().is_some_and(|plan| plan.swap.is_some());
        let id = storage::unique_id();
        let staging = format!("/root/.provision-{id}");
        let name = format!("provision-{id}");
        let resume = if swap {
            format!("RESUME=UUID={swap_uuid}")
        } else {
            "RESUME=none".to_owned()
        };
        let device = format!("{INSTALL_MAJOR}:{}", layout.root_number());
        let script = guest_script(&GuestPart {
            username: &self.username,
            staging: &staging,
            hashed,
            gpt: layout.gpt,
            initrd: plan.is_some().then_some((resume.as_str(), device.as_str())),
        });
        let (service, target) = unit_files(&staging, &name);
        let staged = |name: &str, text: &str| {
            host.write(name, text)
                .map(|path| fish_quote(&path.to_string_lossy()))
        };
        let mut commands = vec!["run".to_owned()];
        if let Some(plan) = &plan {
            commands.extend(layout_commands(&layout, plan, &swap_uuid));
        }
        if layout.gpt {
            commands.push("mkfs vfat /dev/sda1".to_owned());
        }
        let root = &layout.root;
        let units = "/etc/systemd/system";
        commands.extend([
            format!("e2fsck-f {root}"),
            format!("set-uuid {root} {uuid}"),
            format!(
                "-debug sh {}",
                fish_quote(&format!(
                    "echo ssv hash_seed random | debugfs -w -f - {root} >/dev/null 2>&1 && e2fsck -fyD {root} >/dev/null 2>&1; test $? -lt 4"
                ))
            ),
            format!("mount {root} /"),
            format!(
                "upload {} /etc/fstab",
                staged(
                    "fstab",
                    &fstab_text(
                        &fstab,
                        &uuid,
                        swap.then_some((swap_uuid.as_str(), layout.swap_number()))
                    )
                )?
            ),
        ]);
        if let Some(text) = &interfaces {
            commands.push(format!(
                "upload {} /etc/network/interfaces",
                staged("interfaces", text)?
            ));
        }
        commands.extend([
            format!(
                "write /etc/machine-id {}",
                fish_quote(&format!("{machine_id}\n"))
            ),
            format!("mkdir {staging}"),
            format!("chmod 0700 {staging}"),
            format!(
                "upload {} {staging}/provision.sh",
                staged("provision.sh", &script)?
            ),
        ]);
        if plan.is_some() {
            commands.push(format!(
                "upload {} {staging}/initrd.py",
                staged("initrd.py", INITRD_RESUME)?
            ));
        }
        commands.extend([
            format!(
                "upload {} {units}/{name}.service",
                staged("unit.service", &service)?
            ),
            format!(
                "upload {} {units}/{name}.target",
                staged("unit.target", &target)?
            ),
            format!("mkdir {units}/{name}.target.wants"),
            format!("ln-s ../{name}.service {units}/{name}.target.wants/{name}.service"),
            "umount-all".to_owned(),
        ]);
        if layout.gpt {
            commands.push(format!("part-set-disk-guid /dev/sda {}", gpt_guids[0]));
            let partitions = if swap { 3 } else { 2 };
            for (number, guid) in gpt_guids[1..=partitions].iter().enumerate() {
                commands.push(format!("part-set-gpt-guid /dev/sda {} {guid}", number + 1));
            }
        } else if plan.is_some() {
            let id = u32::from_str_radix(&machine_id[..8], 16).unwrap_or(1);
            commands.push(format!(
                "-debug sh {}",
                fish_quote(&format!(
                    "sfdisk --disk-id /dev/sda 0x{id:08x} >/dev/null 2>&1"
                ))
            ));
        }
        commands.push(String::new());
        run_private(
            &mut guestfish(executable, disk, true),
            commands.join("\n").as_bytes(),
            false,
        )?;
        drop(host);
        let console = boot.run(disk, &uuid, &format!("{name}.target"), secret)?;
        let label = boot.arch.label();
        let hash = match console_report(&console) {
            Report::Hash(hash) => hash,
            Report::Failed(step) => {
                return Err(format!(
                    "the {label} VM's provisioning boot failed at its {step} step; \
                     unpublished disk retained for cleanup"
                ));
            }
            Report::Nothing => {
                return Err(format!(
                    "the {label} VM's provisioning boot ended without reporting the \
                     account's password hash; unpublished disk retained for cleanup"
                ));
            }
        };
        drop(console);
        validate_hash(&hash)?;
        if hashed && secret != hash {
            return Err("the guest did not keep the account's password hash".into());
        }
        run_private(
            &mut guestfish(executable, disk, true),
            trace_commands(root, &staging, &name, &machine_id, &existed)
                .join("\n")
                .as_bytes(),
            false,
        )?;
        File::open(disk)
            .and_then(|file| file.sync_all())
            .map_err(|_| "cannot sync provisioned disk".to_owned())?;
        self.password_hash = hash;
        self.root_uuid = Some(uuid);
        self.interface = interface.map(str::to_owned);
        Ok(())
    }

    /// Point the disk's network configuration at `interface` with the
    /// appliance's own operations (the guest's sed and awk are another
    /// architecture's).
    pub(super) fn set_interface_foreign(
        &mut self,
        disk: &Path,
        executable: &Path,
        interface: &str,
    ) -> Result<(), String> {
        if !valid_interface(interface) {
            return Err("invalid network interface name".into());
        }
        let probe = run_private(&mut guestfish(executable, disk, false), PROBE, true)?;
        let layout = parse_probe(&String::from_utf8_lossy(&probe))?;
        let host = Staging::new("antinomie-interfaces")?;
        let local = fish_quote(&host.path.join("interfaces").to_string_lossy());
        let read = format!(
            "run\nmount-ro {} /\ndownload /etc/network/interfaces {local}\n",
            layout.root
        );
        run_private(
            &mut guestfish(executable, disk, false),
            read.as_bytes(),
            false,
        )?;
        let text = fs::read_to_string(host.path.join("interfaces"))
            .map_err(|_| "the VM disk's network configuration could not be read")?;
        host.write("interfaces", &interfaces_text(&text, interface))?;
        let write = format!(
            "run\nmount {} /\nupload {local} /etc/network/interfaces\numount-all\n",
            layout.root
        );
        run_private(
            &mut guestfish(executable, disk, true),
            write.as_bytes(),
            false,
        )?;
        File::open(disk)
            .and_then(|file| file.sync_all())
            .map_err(|_| "cannot sync the VM disk".to_owned())?;
        self.interface = Some(interface.to_owned());
        Ok(())
    }
}

#[cfg(test)]
#[path = "foreign_tests.rs"]
mod tests;
