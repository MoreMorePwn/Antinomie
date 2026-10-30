// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
use crate::api::{GuestCredentials, validate_guest_username};
use crate::storage;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// The groups the Debian installer adds its first user to, where they exist
/// (sudo because root gets no password).
const INSTALLER_GROUPS: &str =
    "cdrom floppy sudo audio dip video plugdev users netdev bluetooth lpadmin scanner";
/// One libguestfs appliance run: the probe, or the provisioning itself
/// (filesystem check, new UUID, directory reindex, account, GRUB, the
/// initramfs). grub-install for UEFI alone takes over a minute in the
/// appliance on a loaded host.
const PROVISION_TIMEOUT: Duration = Duration::from_secs(600);
/// The interface name a disk provisioned before 0.7.1 configures: the base
/// wrote the stanza for the NIC at PCI 00:19.0 when it was built.
const LEGACY_INTERFACE: &str = "enp0s25";
/// The disk grub-pc's debconf names on a BIOS disk provisioned before 0.8.0:
/// the appliance's name for it, whatever the VM's bus.
const LEGACY_BOOT_DISK: &str = "/dev/sda";
/// What the guest prints before the account's password hash.
const HASH_MARKER: &str = "hash:";
/// GRUB as the installer's grub-installer sets it up, for a BIOS (MBR) or
/// UEFI (GPT) disk; it runs in the guest beside [`INITRD_RESUME`].
const BOOT_LOADER: &str = include_str!("guest_account/boot_loader.sh");
/// Puts the resume device into the disk's initramfs images as
/// update-initramfs does; it runs in the guest with the guest's python3 and
/// zstd (both in the Debian Minimal base).
const INITRD_RESUME: &str = include_str!("guest_account/initrd_resume.py");
/// The disk's major device number (sd): the initramfs's files were made on
/// the partition the installer installed to, as fstab's comment names it
/// (`/dev/sda1`, or `/dev/sda2` after the ESP).
const INSTALL_MAJOR: u32 = 8;

#[cfg(test)]
thread_local! {
    static FAIL_PROVISION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn fail_next_provision() {
    FAIL_PROVISION.with(|fail| fail.set(true));
}

mod cloud_state;
pub(crate) use cloud_state::ensure as ensure_cloud_state;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct GuestAccount {
    username: String,
    password_hash: String,
    /// The root filesystem UUID provisioning gave this VM's disk: every VM
    /// gets its own, as every installation does. None for disks provisioned
    /// before 0.7.1, which keep their base's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_uuid: Option<String>,
    /// The wired interface the disk's /etc/network/interfaces brings up (on
    /// a base that names its NIC by PCI slot): written at provisioning and
    /// when the device profile moves the NIC. None: [`LEGACY_INTERFACE`]
    /// on such a base, nothing on others.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    /// The VM's disk as the guest names it (`boot_disk`), which grub-pc's
    /// debconf answer names on a BIOS disk, as grub-installer leaves it:
    /// written at provisioning and when the device profile moves the disk to
    /// another bus. None: [`LEGACY_BOOT_DISK`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_disk: Option<String>,
}
impl std::fmt::Debug for GuestAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestAccount")
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("root_uuid", &self.root_uuid)
            .field("interface", &self.interface)
            .field("boot_disk", &self.boot_disk)
            .finish()
    }
}

/// The VM disk as the libguestfs appliance sees it (always `/dev/sda`).
#[derive(Debug, PartialEq, Eq)]
struct DiskLayout {
    /// The root filesystem: the whole disk (`/dev/sda`) or a partition.
    root: String,
    /// The disk's size in bytes.
    size: u64,
    /// The root partition's last sector, on a partitioned disk.
    root_last: Option<u64>,
    /// The swap partition (sda5, sda3 on GPT) a provisioned disk has: its
    /// UUID and sectors.
    swap: Option<(String, u64)>,
    /// A GPT disk (the UEFI layout: ESP sda1, root sda2, swap sda3).
    gpt: bool,
}
impl DiskLayout {
    /// The root partition's number on a partitioned disk.
    fn root_number(&self) -> u32 {
        if self.gpt { 2 } else { 1 }
    }
    /// The swap partition's number.
    fn swap_number(&self) -> u32 {
        if self.gpt { 3 } else { 5 }
    }
}

/// Sectors in a MiB, partman's alignment.
const MIB_SECTORS: u64 = 2048;
/// The probe: filesystems, the disk's size, its partitions and the swap
/// partition's UUID (absent before provisioning).
const PROBE: &[u8] = b"run\nlist-filesystems\nblockdev-getsize64 /dev/sda\n-part-list /dev/sda\n-part-get-parttype /dev/sda\n-vfs-uuid /dev/sda5\n-vfs-uuid /dev/sda3\n";

/// Where the installer's partitions go on a disk of `sectors`: the root grown
/// to the swap partition (sda5 in an extended sda2 that starts two sectors
/// before it), the last MiB left free, as partman lays them out. The swap is
/// `swap` sectors, or the VM's RAM (at least 256 MiB, at most a quarter of the
/// disk); none when the root could not keep its present size.
#[derive(Debug, PartialEq, Eq)]
struct PartitionPlan {
    root_last: u64,
    /// The swap partition's first sector and the disk's last used sector.
    swap: Option<(u64, u64)>,
}

fn partition_plan(
    sectors: u64,
    root_last: u64,
    ram_mib: u32,
    swap: Option<u64>,
    gpt: bool,
) -> PartitionPlan {
    let end = (sectors / MIB_SECTORS - 1) * MIB_SECTORS;
    let wanted = swap.unwrap_or_else(|| {
        (u64::from(ram_mib) * MIB_SECTORS)
            .min(sectors / 4 / MIB_SECTORS * MIB_SECTORS)
            .max(256 * MIB_SECTORS)
    });
    match end.checked_sub(wanted) {
        Some(start) if start > MIB_SECTORS + root_last => PartitionPlan {
            // On MBR the extended partition holding sda5 takes the MiB before
            // it; on GPT the swap partition follows the root.
            root_last: if gpt {
                start - 1
            } else {
                start - MIB_SECTORS - 1
            },
            swap: Some((start, end - 1)),
        },
        _ => PartitionPlan {
            root_last: (end - 1).max(root_last),
            swap: None,
        },
    }
}

/// Whether `text` is a lowercase RFC 4122 UUID as `blkid` prints it.
pub(crate) fn valid_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// The account's password as provisioning hands it to the guest's chpasswd,
/// always on its standard input (a here-document), never in a file or on a
/// command line.
enum Password<'a> {
    /// The password itself, for a new account: the guest hashes it with its
    /// own PAM and libcrypt, as passwd does (yescrypt on Debian 13).
    Plain(&'a str),
    /// The hash the guest made when the account was created (a reset).
    Hashed(&'a str),
}

/// Whether `name` can be a Linux network interface name in a guest file.
fn valid_interface(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// The VM's disk as its guest names it on the profile's bus (no by-id link:
/// QEMU's virtio disk has no serial, so grub-installer would name `/dev/vda`
/// too; the plain name also holds for the other buses).
pub(crate) fn boot_disk(profile: &crate::stealth::StealthProfile) -> &'static str {
    match profile.disk_bus {
        crate::stealth::DiskBus::Virtio => "/dev/vda",
        crate::stealth::DiskBus::Sata => "/dev/sda",
        crate::stealth::DiskBus::Nvme => "/dev/nvme0n1",
    }
}

/// Whether `device` is one of the names [`boot_disk`] gives.
fn valid_boot_disk(device: &str) -> bool {
    ["/dev/vda", "/dev/sda", "/dev/nvme0n1"].contains(&device)
}

/// The guest commands that point grub-pc's debconf answer at `device` on a
/// BIOS installation (nothing where GRUB for BIOS is not installed).
fn boot_disk_commands(device: &str) -> String {
    format!(
        "if [ -d /usr/lib/grub/i386-pc ]; then printf 'grub-pc grub-pc/install_devices multiselect {device}\\n' | debconf-set-selections; fi\n"
    )
}

/// Run `commands(staging)` as a shell script in the guest's root of `disk`
/// (the VM off), with a private staging directory removed afterwards, then
/// sync the disk.
fn edit_offline(
    disk: &Path,
    executable: &Path,
    commands: impl FnOnce(&str) -> String,
) -> Result<(), String> {
    let probe = run_private(&mut guestfish(executable, disk, false), PROBE, true)?;
    let layout = parse_probe(&String::from_utf8_lossy(&probe))?;
    let staging = format!("/root/.provision-{}", storage::unique_id());
    let guest = format!(
        "set -eu\ntrap 'rm -rf {staging}' EXIT\n{}",
        commands(&staging)
    );
    let script = [
        "run".to_owned(),
        format!("mount {} /", layout.root),
        format!("mkdir {staging}"),
        format!("chmod 0700 {staging}"),
        format!("write {staging}/edit.sh {}", fish_quote(&guest)),
        format!("sh {}", fish_quote(&format!("sh {staging}/edit.sh"))),
        "umount-all".to_owned(),
        String::new(),
    ]
    .join("\n");
    run_private(
        &mut guestfish(executable, disk, true),
        script.as_bytes(),
        false,
    )?;
    File::open(disk)
        .and_then(|file| file.sync_all())
        .map_err(|_| "cannot sync the VM disk".to_owned())
}

/// The guest commands that set the password (from `password`) and print the
/// hash the guest stored, after [`HASH_MARKER`].
fn password_commands(username: &str, password: &Password) -> String {
    let (flag, secret) = match password {
        Password::Plain(password) => ("", *password),
        Password::Hashed(hash) => (" -e", *hash),
    };
    format!(
        "set -eu\nchpasswd{flag} <<'ACCOUNT'\n{username}:{secret}\nACCOUNT\n\
         hash=$(getent shadow '{username}' | cut -d: -f2)\n\
         printf '{HASH_MARKER}%s\\n' \"$hash\"\n"
    )
}

/// The hash the guest printed after [`HASH_MARKER`].
fn printed_hash(output: &[u8]) -> Option<String> {
    String::from_utf8_lossy(output)
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix(HASH_MARKER).map(str::to_owned))
}

/// The installer's stanza for the VM's wired NIC (ifupdown runs dhcpcd for
/// it), in place of everything from the stanza's comment on that the base or
/// an earlier provisioning wrote.
fn interface_commands(interface: &str, staging: &str) -> String {
    format!(
        "awk '/^# The primary network interface$/ {{exit}} {{line[++n] = $0}} END {{while (n > 0 && line[n] == \"\") n--; for (i = 1; i <= n; i++) print line[i]}}' /etc/network/interfaces > {staging}/interfaces\n\
         printf '\\n# The primary network interface\\nallow-hotplug %s\\niface %s inet dhcp\\n# This is an autoconfigured IPv6 interface\\niface %s inet6 auto\\n' {interface} {interface} {interface} >> {staging}/interfaces\n\
         cat {staging}/interfaces > /etc/network/interfaces\n"
    )
}

/// A random 128-bit identifier in hex, as /etc/machine-id holds it.
fn random_hex() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| "cannot read /dev/urandom for the machine ID")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// A random (version 4) UUID.
fn random_uuid() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| "cannot read /dev/urandom for the VM's filesystem UUID")?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// A guestfish double-quoted string: backslash escapes for `\`, `"` and
/// control characters (guestfish decodes them before the call).
fn fish_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for c in text.chars() {
        match c {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            c if c.is_control() => quoted.push_str(&format!("\\x{:02x}", c as u32)),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// The interface provisioning configures for a VM with `profile` on a base
/// whose `stealth_support` names its NIC by PCI slot (`onboardnic`): the
/// profile's slot's name. None on other bases (they configure their NIC
/// themselves).
pub(crate) fn provisioned_interface(
    stealth_support: &[String],
    profile: &crate::stealth::StealthProfile,
) -> Option<&'static str> {
    crate::stealth::BaseSupport::from_list(stealth_support)
        .onboard_nic
        .then(|| profile.nic_slot().interface())
}

/// A provisioned account for tests that need a record but no disk.
#[cfg(test)]
pub(crate) fn fixture(username: &str) -> GuestAccount {
    GuestAccount {
        username: username.into(),
        password_hash: format!("$y$j9T${}${}", "s".repeat(22), "h".repeat(43)),
        root_uuid: None,
        interface: None,
        boot_disk: None,
    }
}

/// The disk from the probe's output: the ext4 root among the
/// `list-filesystems` lines, the size, `part-list` entries and the swap UUID.
fn parse_probe(output: &str) -> Result<DiskLayout, String> {
    let mut roots = Vec::new();
    let (mut size, mut swap_uuid, mut part, mut gpt) = (None, None, 0, false);
    let mut parts: std::collections::BTreeMap<u64, (u64, u64)> = Default::default();
    for line in output.lines().map(str::trim) {
        if let Some((device, kind)) = line.split_once(": ").filter(|(d, _)| d.starts_with('/')) {
            if kind.trim() == "ext4" {
                roots.push(device.trim());
            }
        } else if line == "gpt" {
            gpt = true;
        } else if let Some(value) = line.strip_prefix("part_num: ") {
            part = value.parse().unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("part_end: ") {
            parts.entry(part).or_default().1 = value.parse().unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("part_size: ") {
            parts.entry(part).or_default().0 = value.parse().unwrap_or(0);
        } else if valid_uuid(line) {
            swap_uuid = Some(line.to_owned());
        } else if size.is_none() && !line.is_empty() && line.bytes().all(|c| c.is_ascii_digit()) {
            size = line.parse::<u64>().ok();
        }
    }
    let root = match roots[..] {
        [root]
            if root
                .strip_prefix("/dev/sda")
                .is_some_and(|number| number.bytes().all(|c| c.is_ascii_digit())) =>
        {
            root.to_owned()
        }
        _ => return Err("the VM disk does not hold exactly one ext4 root filesystem".into()),
    };
    let size = size.ok_or("the VM disk's size is unknown")?;
    let (root_number, swap_number) = if gpt { (2, 3) } else { (1, 5) };
    let partitioned = root != "/dev/sda";
    if partitioned && root != format!("/dev/sda{root_number}") {
        return Err("the VM disk's root partition is not where the base put it".into());
    }
    let root_last = partitioned
        .then(|| parts.get(&root_number).map(|(_, end)| end / 512))
        .flatten();
    if partitioned && root_last.is_none() {
        return Err("the VM disk's root partition is not where the base put it".into());
    }
    let swap = swap_uuid.zip(parts.get(&swap_number).map(|(length, _)| length / 512));
    Ok(DiskLayout {
        root,
        size,
        root_last,
        swap,
        gpt,
    })
}

/// The guestfish commands that lay a partitioned disk out for `plan`: the
/// root partition grown (a provisioned disk's swap partitions removed first
/// and made again at the end), the swap partition, the root filesystem grown.
fn layout_commands(layout: &DiskLayout, plan: &PartitionPlan, swap_uuid: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let (root, swap) = (layout.root_number(), layout.swap_number());
    if layout.gpt {
        // A disk made larger keeps its backup GPT at the old end.
        commands.push("part-expand-gpt /dev/sda".into());
        if layout.swap.is_some() {
            commands.push(format!("part-del /dev/sda {swap}"));
        }
    } else if layout.swap.is_some() {
        commands.extend(["part-del /dev/sda 5".into(), "part-del /dev/sda 2".into()]);
    }
    commands.push(format!("part-resize /dev/sda {root} {}", plan.root_last));
    if let Some((start, last)) = plan.swap {
        if layout.gpt {
            commands.extend([
                format!("part-add /dev/sda p {start} {last}"),
                format!(
                    "part-set-gpt-type /dev/sda {swap} {}",
                    crate::uefi_disk::SWAP_TYPE
                ),
                // partman leaves GPT partition names empty; parted's
                // mkpart (part-add) names them "primary".
                format!(
                    "-debug sh {}",
                    fish_quote(&format!(
                        "sgdisk --change-name={swap}: /dev/sda >/dev/null 2>&1"
                    ))
                ),
            ]);
        } else {
            commands.extend([
                format!("part-add /dev/sda e {} {last}", start - 2),
                format!("part-add /dev/sda l {start} {last}"),
                "part-set-mbr-id /dev/sda 5 0x82".into(),
            ]);
        }
        commands.push(format!("mkswap /dev/sda{swap} uuid:{swap_uuid}"));
    }
    commands.extend([
        format!("e2fsck-f /dev/sda{root}"),
        format!("resize2fs /dev/sda{root}"),
    ]);
    commands
}

/// Grow a VM disk's root to a disk made larger (its VM off): the root
/// partition and filesystem, the swap partition kept at the end with its
/// UUID and size. A whole-disk root (BusyBox, the desktops) grows at boot.
pub(crate) fn grow_disk(disk: &Path) -> Result<(), String> {
    let executable = crate::dependencies::require_tool(Path::new("guestfish"), "libguestfs-tools")?;
    grow_disk_with(disk, &executable)
}

fn grow_disk_with(disk: &Path, executable: &Path) -> Result<(), String> {
    let probe = run_private(&mut guestfish(executable, disk, false), PROBE, true)?;
    let layout = parse_probe(&String::from_utf8_lossy(&probe))?;
    let Some(root_last) = layout.root_last else {
        return Ok(());
    };
    let plan = partition_plan(
        layout.size / 512,
        root_last,
        0,
        layout.swap.as_ref().map(|(_, sectors)| *sectors),
        layout.gpt,
    );
    let uuid = layout
        .swap
        .as_ref()
        .map_or_else(random_uuid, |(uuid, _)| Ok(uuid.clone()))?;
    let mut script = vec!["run".to_owned()];
    script.extend(layout_commands(&layout, &plan, &uuid));
    script.push(String::new());
    run_private(
        &mut guestfish(executable, disk, true),
        script.join("\n").as_bytes(),
        false,
    )?;
    File::open(disk)
        .and_then(|file| file.sync_all())
        .map_err(|_| "cannot sync the grown disk".to_owned())
}

fn guestfish(executable: &Path, disk: &Path, writable: bool) -> Command {
    let mut command = Command::new(executable);
    command
        .arg(if writable { "--rw" } else { "--ro" })
        .args(["--no-progress-bars", "--format=qcow2", "-a"])
        .arg(disk)
        .env("LIBGUESTFS_BACKEND", "direct")
        .env("LIBGUESTFS_DEBUG", "0")
        .env("LIBGUESTFS_TRACE", "0");
    command
}

impl GuestAccount {
    /// Create the account on a VM's new disk (see [`provision`](Self::provision)):
    /// the guest's own chpasswd hashes the password, so the hash is the one
    /// the guest's Debian makes (yescrypt on Debian 13), and the record keeps
    /// that hash for later resets.
    pub(crate) fn create(
        credentials: GuestCredentials,
        disk: &Path,
        ram_mib: u32,
        interface: Option<&str>,
        boot_disk: &str,
    ) -> Result<Self, String> {
        let mut account = Self::unprovisioned(credentials.username)?;
        account.boot_disk = Some(boot_disk.to_owned());
        let executable = Self::provision_tool()?;
        account.provision_with(
            disk,
            &executable,
            ram_mib,
            &Password::Plain(&credentials.password),
            interface,
        )?;
        Ok(account)
    }
    fn unprovisioned(username: String) -> Result<Self, String> {
        validate_guest_username(&username)?;
        Ok(Self {
            username,
            password_hash: String::new(),
            root_uuid: None,
            interface: None,
            boot_disk: None,
        })
    }
    fn provision_tool() -> Result<std::path::PathBuf, String> {
        #[cfg(test)]
        if FAIL_PROVISION.with(|fail| fail.replace(false)) {
            return Err("injected offline provisioning failure".into());
        }
        crate::dependencies::require_tool(Path::new("guestfish"), "libguestfs-tools")
    }
    fn validate(&self) -> Result<(), String> {
        validate_guest_username(&self.username)?;
        validate_hash(&self.password_hash)?;
        if self
            .root_uuid
            .as_deref()
            .is_some_and(|uuid| !valid_uuid(uuid))
        {
            return Err("invalid provisioned root filesystem UUID".into());
        }
        if self
            .interface
            .as_deref()
            .is_some_and(|name| !valid_interface(name))
        {
            return Err("invalid provisioned network interface name".into());
        }
        if self
            .boot_disk
            .as_deref()
            .is_some_and(|device| !valid_boot_disk(device))
        {
            return Err("invalid provisioned boot disk name".into());
        }
        Ok(())
    }
    /// The account's name (uid and gid 1000 in the guest).
    pub(crate) fn username(&self) -> &str {
        &self.username
    }
    /// The root filesystem UUID provisioning gave the VM's disk.
    pub(crate) fn root_uuid(&self) -> Option<&str> {
        self.root_uuid.as_deref()
    }
    /// The wired interface the disk configures, on a base that names its NIC
    /// by PCI slot: the one provisioning wrote, or the base's own for a disk
    /// provisioned before 0.7.1.
    pub(crate) fn interface(&self) -> &str {
        self.interface.as_deref().unwrap_or(LEGACY_INTERFACE)
    }
    /// The VM's disk as grub-pc's debconf answer names it on a BIOS disk:
    /// the one provisioning wrote, or the appliance's name for a disk
    /// provisioned before 0.8.0.
    pub(crate) fn boot_disk(&self) -> &str {
        self.boot_disk.as_deref().unwrap_or(LEGACY_BOOT_DISK)
    }
    pub(crate) fn save(&self, directory: &Path) -> Result<(), String> {
        self.validate()?;
        storage::atomic_json(&directory.join("guest-account.json"), self)
    }
    pub(crate) fn load(directory: &Path) -> Result<Self, String> {
        let path = directory.join("guest-account.json");
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "guest account provisioning record is unavailable")?;
        let owner = fs::metadata(directory)
            .map_err(|_| "guest account directory is unavailable")?
            .uid();
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.uid() != owner
            || metadata.len() > 4096
        {
            return Err(
                "guest account provisioning record must be an owned private regular file".into(),
            );
        }
        // Never surface serde errors: malformed sensitive fields could appear in them.
        let account: Self =
            storage::read_json(&path).map_err(|_| "invalid guest account provisioning record")?;
        account.validate()?;
        Ok(account)
    }
    /// Make the base's disk this VM's own, offline: a root filesystem UUID
    /// and directory hash seed of its own (fstab follows), the account with
    /// its recorded hash, and, on a base that names its NIC by PCI slot, the
    /// stanza for `interface`.
    pub(crate) fn provision(
        &mut self,
        disk: &Path,
        ram_mib: u32,
        interface: Option<&str>,
        boot_disk: &str,
    ) -> Result<(), String> {
        let executable = Self::provision_tool()?;
        self.boot_disk = Some(boot_disk.to_owned());
        let hash = self.password_hash.clone();
        self.provision_with(
            disk,
            &executable,
            ram_mib,
            &Password::Hashed(&hash),
            interface,
        )
    }
    fn provision_with(
        &mut self,
        disk: &Path,
        executable: &Path,
        ram_mib: u32,
        password: &Password,
        interface: Option<&str>,
    ) -> Result<(), String> {
        validate_guest_username(&self.username)?;
        if let Password::Hashed(hash) = password {
            validate_hash(hash)?;
        }
        if interface.is_some_and(|name| !valid_interface(name)) {
            return Err("invalid network interface name".into());
        }
        if !valid_boot_disk(self.boot_disk()) {
            return Err("invalid boot disk name".into());
        }
        let probe = run_private(&mut guestfish(executable, disk, false), PROBE, true)?;
        let layout = parse_probe(&String::from_utf8_lossy(&probe))?;
        let uuid = random_uuid()?;
        let plan = layout.root_last.map(|root_last| {
            partition_plan(layout.size / 512, root_last, ram_mib, None, layout.gpt)
        });
        // A partitioned disk's initramfs gets its resume device; the helper
        // reaches the appliance as a file (guestfish upload), since the
        // script on standard input has to stay small.
        let helper = plan.is_some().then(HelperFile::new).transpose()?;
        let script = self.script(
            &layout,
            plan.as_ref(),
            &Identity {
                uuid: &uuid,
                swap_uuid: &random_uuid()?,
                machine_id: &random_hex()?,
                gpt_guids: &[
                    random_uuid()?,
                    random_uuid()?,
                    random_uuid()?,
                    random_uuid()?,
                ],
            },
            password,
            interface,
            helper.as_ref().map(HelperFile::path).as_deref(),
        );
        let output = run_private(
            &mut guestfish(executable, disk, true),
            script.as_bytes(),
            true,
        );
        drop(helper);
        let output = output?;
        let hash =
            printed_hash(&output).ok_or("the guest did not report the account's password hash")?;
        validate_hash(&hash)?;
        if matches!(password, Password::Hashed(stored) if *stored != hash) {
            return Err("the guest did not keep the account's password hash".into());
        }
        File::open(disk)
            .and_then(|file| file.sync_all())
            .map_err(|_| "cannot sync provisioned disk".to_owned())?;
        self.password_hash = hash;
        self.root_uuid = Some(uuid);
        self.interface = interface.map(str::to_owned);
        Ok(())
    }
    /// Point the disk's network configuration at `interface` (the VM off):
    /// the device profile moved the NIC to another PCI slot.
    pub(crate) fn set_interface(&mut self, disk: &Path, interface: &str) -> Result<(), String> {
        let executable = Self::provision_tool()?;
        self.set_interface_with(disk, &executable, interface)
    }
    fn set_interface_with(
        &mut self,
        disk: &Path,
        executable: &Path,
        interface: &str,
    ) -> Result<(), String> {
        if !valid_interface(interface) {
            return Err("invalid network interface name".into());
        }
        edit_offline(disk, executable, |staging| {
            interface_commands(interface, staging)
        })?;
        self.interface = Some(interface.to_owned());
        Ok(())
    }
    /// Point grub-pc's debconf answer at `device` (the VM off): the device
    /// profile moved the disk to another bus. A UEFI disk has no such answer.
    pub(crate) fn set_boot_disk(&mut self, disk: &Path, device: &str) -> Result<(), String> {
        let executable = Self::provision_tool()?;
        self.set_boot_disk_with(disk, &executable, device)
    }
    fn set_boot_disk_with(
        &mut self,
        disk: &Path,
        executable: &Path,
        device: &str,
    ) -> Result<(), String> {
        if !valid_boot_disk(device) {
            return Err("invalid boot disk name".into());
        }
        edit_offline(disk, executable, |_| boot_disk_commands(device))?;
        self.boot_disk = Some(device.to_owned());
        Ok(())
    }
    /// The guestfish commands. The password reaches the guest's chpasswd as
    /// a here-document of the `sh` command, never as a file on the disk.
    fn script(
        &self,
        layout: &DiskLayout,
        plan: Option<&PartitionPlan>,
        identity: &Identity,
        password: &Password,
        interface: Option<&str>,
        initrd_helper: Option<&Path>,
    ) -> String {
        let Identity {
            uuid,
            swap_uuid,
            machine_id,
            gpt_guids,
        } = *identity;
        let username = &self.username;
        let root = &layout.root;
        let staging = format!("/root/.provision-{}", storage::unique_id());
        // The installer asks for a full name; the account name stands in.
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
        // fstab names the root by UUID on the console base (the desktops
        // name /dev/vda and keep their line).
        let guest = format!(
            "set -eu\ntrap 'rm -rf {staging}' EXIT\n\
             sed -i -E 's|^UUID=[0-9A-Fa-f-]+([[:space:]]+/[[:space:]])|UUID={uuid}\\1|' /etc/fstab\n\
             if getent passwd 1000 >/dev/null || getent group 1000 >/dev/null || getent passwd '{username}' >/dev/null || getent group '{username}' >/dev/null; then exit 1; fi\n\
             addgroup --quiet --gid 1000 '{username}'\n\
             adduser --quiet --uid 1000 --gid 1000 --comment '{full_name},,,' --disabled-password '{username}'\n\
             chmod 0700 '/home/{username}'\n\
             for group in {INSTALLER_GROUPS}; do\n\
             \tif getent group \"$group\" >/dev/null; then adduser --quiet '{username}' \"$group\"; fi\n\
             done\n\
             passwd -l root >/dev/null\n{}",
            interface.map_or_else(String::new, |name| interface_commands(name, &staging))
        );
        // A partitioned disk: its swap partition in fstab, as the installer
        // leaves it, and GRUB's configuration for this disk's UUIDs. The
        // resume device (the swap partition, or none) goes into
        // initramfs-tools' configuration and the initramfs below.
        let swap = plan.is_some_and(|plan| plan.swap.is_some());
        let guest = if plan.is_some() {
            let swap_lines = if swap {
                format!(
                    "awk -v u={swap_uuid} '/^\\/dev\\/sr0/ {{print \"# swap was on /dev/sda{} during installation\"; printf \"UUID=%s none            swap    sw              0       0\\n\", u}} {{print}}' /etc/fstab > {staging}/fstab\n\
                     cat {staging}/fstab > /etc/fstab\n",
                    layout.swap_number()
                )
            } else {
                String::new()
            };
            format!("{guest}{swap_lines}")
        } else {
            guest
        };
        // The directory hash seed has no tune2fs option: debugfs sets it and
        // e2fsck -D reindexes every directory under it. Through the
        // appliance's own tools (guestfish debug, which joins its words
        // without their quotes); a disk keeps its base's seed where that is
        // unavailable.
        let reseed = format!(
            "echo ssv hash_seed random | debugfs -w -f - {root} >/dev/null 2>&1 && e2fsck -fyD {root} >/dev/null 2>&1; test $? -lt 4"
        );
        let mut commands = vec!["run".to_owned()];
        if let Some(plan) = plan {
            commands.extend(layout_commands(layout, plan, swap_uuid));
        }
        if layout.gpt {
            // The VM's own EFI system partition, as partman formats it.
            commands.push("mkfs vfat /dev/sda1".to_owned());
        }
        commands.extend([
            format!("e2fsck-f {root}"),
            format!("set-uuid {root} {uuid}"),
            format!("-debug sh {}", fish_quote(&reseed)),
            format!("mount {root} /"),
            format!("mkdir {staging}"),
            format!("chmod 0700 {staging}"),
            format!("write {staging}/provision.sh {}", fish_quote(&guest)),
            format!("sh {}", fish_quote(&format!("sh {staging}/provision.sh"))),
        ]);
        if layout.gpt {
            commands.push("mount /dev/sda1 /boot/efi".to_owned());
        }
        if let Some(helper) = initrd_helper {
            // The installer's resume answer: the swap partition, or none.
            let resume = if swap {
                format!("RESUME=UUID={swap_uuid}")
            } else {
                "RESUME=none".to_owned()
            };
            // Beside the staging directory, which provision.sh removed: GRUB
            // for the disk's firmware, then the initramfs's resume device.
            let (initrd, loader) = (format!("{staging}.initrd.py"), format!("{staging}.grub.sh"));
            let firmware = if layout.gpt { "uefi" } else { "bios" };
            // grub-pc's debconf answer: the VM's disk as its guest names it.
            let boot_disk = self.boot_disk();
            let device = format!("{INSTALL_MAJOR}:{}", layout.root_number());
            commands.extend([
                format!(
                    "upload {} {initrd}",
                    fish_quote(&helper.join(HelperFile::INITRD).to_string_lossy())
                ),
                format!(
                    "upload {} {loader}",
                    fish_quote(&helper.join(HelperFile::BOOT_LOADER).to_string_lossy())
                ),
                format!(
                    "sh {}",
                    fish_quote(&format!(
                        "set -eu\ntrap 'rm -f {initrd} {loader}' EXIT\nsh {loader} {firmware} {boot_disk}\nmkdir -p /etc/initramfs-tools/conf.d\npython3 -I {initrd} {resume} {device}\n"
                    ))
                ),
            ]);
        }
        commands.extend([
            // The password, set and hashed by the guest itself; it prints
            // the hash it stored.
            format!("sh {}", fish_quote(&password_commands(username, password))),
            // The installation's machine ID, its own per VM.
            format!(
                "write /etc/machine-id {}",
                fish_quote(&format!("{machine_id}\n"))
            ),
            "umount-all".to_owned(),
        ]);
        if layout.gpt {
            // The disk's and the partitions' GUIDs of its own, last (the
            // partition table is read again).
            commands.push(format!("part-set-disk-guid /dev/sda {}", gpt_guids[0]));
            let partitions = if swap { 3 } else { 2 };
            for (number, guid) in gpt_guids[1..=partitions].iter().enumerate() {
                commands.push(format!("part-set-gpt-guid /dev/sda {} {guid}", number + 1));
            }
        } else if plan.is_some() {
            // The disk identifier (PARTUUIDs) of its own as well, last:
            // sfdisk makes the kernel read the partition table again, and
            // the partitions' device nodes are gone for a moment.
            let id = u32::from_str_radix(&machine_id[..8], 16).unwrap_or(1);
            commands.push(format!(
                "-debug sh {}",
                fish_quote(&format!(
                    "sfdisk --disk-id /dev/sda 0x{id:08x} >/dev/null 2>&1"
                ))
            ));
        }
        commands.push(String::new());
        commands.join("\n")
    }
}

/// [`INITRD_RESUME`] and [`BOOT_LOADER`] in a private host folder for the
/// appliance's upload, removed when dropped.
struct HelperFile {
    directory: std::path::PathBuf,
}
impl HelperFile {
    const INITRD: &str = "initrd.py";
    const BOOT_LOADER: &str = "boot-loader.sh";
    fn new() -> Result<Self, String> {
        let directory =
            std::env::temp_dir().join(format!("antinomie-provision-{}", storage::unique_id()));
        let helper = Self { directory };
        storage::private_dir(&helper.directory)
            .and_then(|()| fs::write(helper.directory.join(Self::INITRD), INITRD_RESUME))
            .and_then(|()| fs::write(helper.directory.join(Self::BOOT_LOADER), BOOT_LOADER))
            .map_err(|_| "cannot stage the provisioning helpers")?;
        Ok(helper)
    }
    fn path(&self) -> std::path::PathBuf {
        self.directory.clone()
    }
}
impl Drop for HelperFile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// The identifiers provisioning gives a disk.
#[derive(Clone, Copy)]
struct Identity<'a> {
    uuid: &'a str,
    swap_uuid: &'a str,
    /// A GPT disk's GUID and its partitions' (ESP, root, swap).
    gpt_guids: &'a [String; 4],
    machine_id: &'a str,
}

/// A password hash as crypt(3) writes it to /etc/shadow: yescrypt
/// (`$y$j9T$salt$hash`, Debian 11 on) or salted SHA-512 (`$6$`, the hash
/// Antinomie made on the host before 0.7.1).
fn validate_hash(hash: &str) -> Result<(), String> {
    let parts: Vec<_> = hash.split('$').collect();
    let crypt64 = |part: &&str| {
        part.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'/')
    };
    let sha512 = parts.len() == 4
        && parts[1] == "6"
        && (1..=16).contains(&parts[2].len())
        && parts[3].len() == 86;
    let yescrypt = parts.len() == 5
        && parts[1] == "y"
        && parts[2] == "j9T"
        && (1..=86).contains(&parts[3].len())
        && parts[4].len() == 43;
    if !parts[0].is_empty() || !(sha512 || yescrypt) || !parts[2..].iter().all(crypt64) {
        return Err("invalid salted yescrypt or SHA-512 password hash".into());
    }
    Ok(())
}

/// Run an offline tool with `input` on its standard input, its output
/// discarded or (`capture`) returned, within one appliance run's time.
fn run_private(command: &mut Command, input: &[u8], capture: bool) -> Result<Vec<u8>, String> {
    run_private_with_timeout(command, input, capture, PROVISION_TIMEOUT)
}

fn terminate_owned_group(child: &mut Child) -> Result<(), String> {
    let group = format!("-{}", child.id());
    let group_killed = Command::new("/bin/kill")
        .args(["--signal", "KILL", "--", &group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !group_killed && child.try_wait().ok().flatten().is_none() {
        child
            .kill()
            .map_err(|_| "offline credential tool cleanup failed")?;
    }
    child
        .wait()
        .map_err(|_| "offline credential tool cleanup failed")?;
    Ok(())
}

fn run_private_with_timeout(
    command: &mut Command,
    input: &[u8],
    capture_hash: bool,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    // This fits a fresh Linux pipe even if the tool never reads its stdin.
    if input.len() > 4096 {
        return Err("offline credential tool input exceeds limit".into());
    }
    let deadline = Instant::now() + timeout;
    let mut captured_stdout = if capture_hash {
        let (reader, writer) =
            UnixStream::pair().map_err(|_| "password hash output channel failed")?;
        reader
            .set_nonblocking(true)
            .map_err(|_| "password hash output channel failed")?;
        command.stdout(Stdio::from(OwnedFd::from(writer)));
        Some(reader)
    } else {
        command.stdout(Stdio::null());
        None
    };
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| "offline credential tool could not be started")?;
    // Drop the parent's configured writer so EOF reflects owned child writers.
    command.stdout(Stdio::null());
    let write_result = child
        .stdin
        .take()
        .ok_or("offline credential tool input is unavailable")
        .and_then(|mut stdin| {
            stdin
                .write_all(input)
                .map_err(|_| "offline credential tool input failed")
        });
    let result = (|| -> Result<Vec<u8>, String> {
        write_result?;
        let mut output = Vec::new();
        let mut output_complete = !capture_hash;
        let mut status = None;
        loop {
            if let Some(reader) = captured_stdout.as_mut().filter(|_| !output_complete) {
                let mut chunk = [0; 512];
                loop {
                    let capacity = chunk.len().min(4097 - output.len());
                    match reader.read(&mut chunk[..capacity]) {
                        Ok(0) => {
                            output_complete = true;
                            break;
                        }
                        Ok(len) => {
                            output.extend_from_slice(&chunk[..len]);
                            if output.len() > 4096 {
                                return Err("password hash output exceeded limit".into());
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return Err("password hash output failed".into()),
                    }
                }
            }
            if status.is_none() {
                status = child
                    .try_wait()
                    .map_err(|_| "offline credential tool wait failed")?;
            }
            if let Some(status) = status {
                if !status.success() {
                    return Err("offline credential provisioning failed; unpublished disk retained for cleanup".into());
                }
                if output_complete {
                    return Ok(output);
                }
            }
            if Instant::now() >= deadline {
                return Err(
                    "offline credential tool timed out; unpublished disk retained for cleanup"
                        .into(),
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        terminate_owned_group(&mut child)?;
    }
    result
}

#[cfg(test)]
mod tests;
