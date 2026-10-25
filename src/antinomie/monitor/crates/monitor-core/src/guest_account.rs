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
/// (filesystem check, new UUID, directory reindex, account).
const PROVISION_TIMEOUT: Duration = Duration::from_secs(240);
/// What the guest prints before the account's password hash.
const HASH_MARKER: &str = "hash:";

#[cfg(test)]
thread_local! {
    static FAIL_PROVISION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn fail_next_provision() {
    FAIL_PROVISION.with(|fail| fail.set(true));
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct GuestAccount {
    username: String,
    password_hash: String,
    /// The root filesystem UUID provisioning gave this VM's disk: every VM
    /// gets its own, as every installation does. None for disks provisioned
    /// before 0.7.1, which keep their base's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_uuid: Option<String>,
}
impl std::fmt::Debug for GuestAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestAccount")
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("root_uuid", &self.root_uuid)
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
    /// The swap partition (sda5) a provisioned disk has: its UUID and sectors.
    swap: Option<(String, u64)>,
}

/// Sectors in a MiB, partman's alignment.
const MIB_SECTORS: u64 = 2048;
/// The probe: filesystems, the disk's size, its partitions and the swap
/// partition's UUID (absent before provisioning).
const PROBE: &[u8] =
    b"run\nlist-filesystems\nblockdev-getsize64 /dev/sda\n-part-list /dev/sda\n-vfs-uuid /dev/sda5\n";

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

fn partition_plan(sectors: u64, root_last: u64, ram_mib: u32, swap: Option<u64>) -> PartitionPlan {
    let end = (sectors / MIB_SECTORS - 1) * MIB_SECTORS;
    let wanted = swap.unwrap_or_else(|| {
        (u64::from(ram_mib) * MIB_SECTORS)
            .min(sectors / 4 / MIB_SECTORS * MIB_SECTORS)
            .max(256 * MIB_SECTORS)
    });
    match end.checked_sub(wanted) {
        Some(start) if start > MIB_SECTORS + root_last => PartitionPlan {
            root_last: start - MIB_SECTORS - 1,
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

/// A provisioned account for tests that need a record but no disk.
#[cfg(test)]
pub(crate) fn fixture(username: &str) -> GuestAccount {
    GuestAccount {
        username: username.into(),
        password_hash: format!("$y$j9T${}${}", "s".repeat(22), "h".repeat(43)),
        root_uuid: None,
    }
}

/// The disk from the probe's output: the ext4 root among the
/// `list-filesystems` lines, the size, `part-list` entries and the swap UUID.
fn parse_probe(output: &str) -> Result<DiskLayout, String> {
    let mut roots = Vec::new();
    let (mut size, mut swap_uuid, mut part) = (None, None, 0);
    let mut parts: std::collections::BTreeMap<u64, (u64, u64)> = Default::default();
    for line in output.lines().map(str::trim) {
        if let Some((device, kind)) = line.split_once(": ").filter(|(d, _)| d.starts_with('/')) {
            if kind.trim() == "ext4" {
                roots.push(device.trim());
            }
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
    let root_last = (root == "/dev/sda1")
        .then(|| parts.get(&1).map(|(_, end)| end / 512))
        .flatten();
    if root == "/dev/sda1" && root_last.is_none() {
        return Err("the VM disk's root partition is not where the base put it".into());
    }
    let swap = swap_uuid.zip(parts.get(&5).map(|(length, _)| length / 512));
    Ok(DiskLayout {
        root,
        size,
        root_last,
        swap,
    })
}

/// The guestfish commands that lay a partitioned disk out for `plan`: the
/// root partition grown (a provisioned disk's swap partitions removed first
/// and made again at the end), the swap partition, the root filesystem grown.
fn layout_commands(layout: &DiskLayout, plan: &PartitionPlan, swap_uuid: &str) -> Vec<String> {
    let mut commands = Vec::new();
    if layout.swap.is_some() {
        commands.extend(["part-del /dev/sda 5".into(), "part-del /dev/sda 2".into()]);
    }
    commands.push(format!("part-resize /dev/sda 1 {}", plan.root_last));
    if let Some((start, last)) = plan.swap {
        commands.extend([
            format!("part-add /dev/sda e {} {last}", start - 2),
            format!("part-add /dev/sda l {start} {last}"),
            "part-set-mbr-id /dev/sda 5 0x82".into(),
            format!("mkswap /dev/sda5 uuid:{swap_uuid}"),
        ]);
    }
    commands.extend(["e2fsck-f /dev/sda1".into(), "resize2fs /dev/sda1".into()]);
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
    ) -> Result<Self, String> {
        let mut account = Self::unprovisioned(credentials.username)?;
        let executable = Self::provision_tool()?;
        account.provision_with(
            disk,
            &executable,
            ram_mib,
            &Password::Plain(&credentials.password),
        )?;
        Ok(account)
    }
    fn unprovisioned(username: String) -> Result<Self, String> {
        validate_guest_username(&username)?;
        Ok(Self {
            username,
            password_hash: String::new(),
            root_uuid: None,
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
    /// and directory hash seed of its own (fstab follows), and the account
    /// with its recorded hash.
    pub(crate) fn provision(&mut self, disk: &Path, ram_mib: u32) -> Result<(), String> {
        let executable = Self::provision_tool()?;
        let hash = self.password_hash.clone();
        self.provision_with(disk, &executable, ram_mib, &Password::Hashed(&hash))
    }
    fn provision_with(
        &mut self,
        disk: &Path,
        executable: &Path,
        ram_mib: u32,
        password: &Password,
    ) -> Result<(), String> {
        validate_guest_username(&self.username)?;
        if let Password::Hashed(hash) = password {
            validate_hash(hash)?;
        }
        let probe = run_private(&mut guestfish(executable, disk, false), PROBE, true)?;
        let layout = parse_probe(&String::from_utf8_lossy(&probe))?;
        let uuid = random_uuid()?;
        let plan = layout
            .root_last
            .map(|root_last| partition_plan(layout.size / 512, root_last, ram_mib, None));
        let script = self.script(
            &layout,
            plan.as_ref(),
            &Identity {
                uuid: &uuid,
                swap_uuid: &random_uuid()?,
                machine_id: &random_hex()?,
            },
            password,
        );
        let output = run_private(
            &mut guestfish(executable, disk, true),
            script.as_bytes(),
            true,
        )?;
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
    ) -> String {
        let Identity {
            uuid,
            swap_uuid,
            machine_id,
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
             passwd -l root >/dev/null\n"
        );
        // A partitioned disk: its swap partition in fstab and as the resume
        // device, as the installer leaves them, and GRUB's configuration for
        // this disk's UUIDs.
        let swap = plan.is_some_and(|plan| plan.swap.is_some());
        let guest = if plan.is_some() {
            let swap_lines = if swap {
                format!(
                    "awk -v u={swap_uuid} '/^\\/dev\\/sr0/ {{print \"# swap was on /dev/sda5 during installation\"; printf \"UUID=%s none            swap    sw              0       0\\n\", u}} {{print}}' /etc/fstab > {staging}/fstab\n\
                     cat {staging}/fstab > /etc/fstab\n\
                     mkdir -p /etc/initramfs-tools/conf.d\n\
                     printf 'RESUME=UUID=%s\\n' {swap_uuid} > /etc/initramfs-tools/conf.d/resume\n"
                )
            } else {
                String::new()
            };
            format!(
                "{guest}{swap_lines}if command -v update-grub >/dev/null; then update-grub >/dev/null 2>&1 || true; fi\n"
            )
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
            // The disk identifier (PARTUUIDs) of its own as well.
            let id = u32::from_str_radix(&machine_id[..8], 16).unwrap_or(1);
            commands.push(format!(
                "-debug sh {}",
                fish_quote(&format!(
                    "sfdisk --disk-id /dev/sda 0x{id:08x} >/dev/null 2>&1"
                ))
            ));
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
            // The password, set and hashed by the guest itself; it prints
            // the hash it stored.
            format!("sh {}", fish_quote(&password_commands(username, password))),
            // The installation's machine ID, its own per VM.
            format!(
                "write /etc/machine-id {}",
                fish_quote(&format!("{machine_id}\n"))
            ),
            "umount-all".to_owned(),
            String::new(),
        ]);
        commands.join("\n")
    }
}

/// The identifiers provisioning gives a disk.
#[derive(Clone, Copy)]
struct Identity<'a> {
    uuid: &'a str,
    swap_uuid: &'a str,
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
mod tests {
    use super::*;
    #[test]
    fn tool_deadline_reaps_owned_child_and_preserves_unrelated_process() {
        let root =
            std::env::temp_dir().join(format!("ant-account-timeout-{}", storage::unique_id()));
        storage::private_dir(&root).unwrap();
        let tool = root.join("hung-tool");
        fs::write(
            &tool,
            "#!/bin/sh\nroot=$(dirname \"$0\")\nprintf '%s\\n' \"$$\" > \"$root/tool-pid\"\ncat >/dev/null\nsleep 60 &\nprintf '%s\\n' \"$!\" > \"$root/descendant-pid\"\nif test \"$1\" = exit-parent; then exit 0; fi\nwait\n",
        )
        .unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        let mut unrelated = Command::new("sleep").arg("60").spawn().unwrap();
        let secret = "private-timeout-password";
        // The pid of a process the tool started, once it wrote one whole.
        let written = |name: &str| {
            fs::read_to_string(root.join(name))
                .ok()
                .filter(|text| text.ends_with('\n'))
        };
        for (capture_hash, exit_parent) in [(false, false), (true, false), (true, true)] {
            // The deadline is what the tool is made to miss, so it has to be
            // long enough for a loaded host to start the tool and let it
            // start its descendant first. A deadline that fired before then
            // proves nothing about the descendant: the run is repeated with
            // twice the time, up to ten seconds.
            let mut timeout = Duration::from_millis(500);
            let (pid, descendant) = loop {
                for name in ["tool-pid", "descendant-pid"] {
                    let _ = fs::remove_file(root.join(name));
                }
                let started = Instant::now();
                let mut command = Command::new(&tool);
                if exit_parent {
                    command.arg("exit-parent");
                }
                let error = run_private_with_timeout(
                    &mut command,
                    secret.as_bytes(),
                    capture_hash,
                    timeout,
                )
                .unwrap_err();
                assert!(error.contains("timed out"));
                assert!(!error.contains(secret));
                // Killing the group is prompt: far from the tool's 60 s sleep.
                assert!(started.elapsed() < timeout + Duration::from_secs(20));
                if let (Some(pid), Some(descendant)) =
                    (written("tool-pid"), written("descendant-pid"))
                {
                    break (pid, descendant);
                }
                assert!(
                    timeout < Duration::from_secs(10),
                    "the tool never started its descendant within {timeout:?}"
                );
                timeout *= 2;
            };
            assert!(!Path::new("/proc").join(pid.trim()).exists());
            let stopped_deadline = Instant::now() + Duration::from_secs(60);
            while let Ok(stat) =
                fs::read_to_string(Path::new("/proc").join(descendant.trim()).join("stat"))
            {
                if stat.split_once(") ").unwrap().1.starts_with('Z') {
                    break;
                }
                assert!(Instant::now() < stopped_deadline);
                thread::sleep(Duration::from_millis(10));
            }
            assert!(unrelated.try_wait().unwrap().is_none());
        }
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn oversized_tool_input_and_output_are_rejected_without_exposing_content() {
        let error = run_private_with_timeout(
            &mut Command::new("missing-tool"),
            &[0; 4097],
            true,
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(error.contains("input exceeds limit"));
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "cat >/dev/null; head -c 8192 /dev/zero"]);
        let error = run_private_with_timeout(
            &mut command,
            b"private-output-password",
            true,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("output exceeded limit"));
        assert!(!error.contains("private-output-password"));
    }
    /// The probe's answer for a whole-disk root (a desktop base) of 6 GiB.
    const WHOLE_DISK: &str = "/dev/sda: ext4\\n6442450944\\n";
    /// The console base's disk on a 6 GiB VM disk, before provisioning.
    const PARTITIONED: &str = "/dev/sda1: ext4\\n6442450944\\n[0] = {\\n  part_num: 1\\n  part_start: 1048576\\n  part_end: 3222274047\\n  part_size: 3221225472\\n}\\n";
    fn input_of(root: &Path) -> String {
        fs::read_to_string(root.join("input")).unwrap()
    }
    /// The hash the fake guest reports, as Debian 13's chpasswd makes one.
    fn guest_hash() -> String {
        format!("$y$j9T${}${}", "s".repeat(22), "h".repeat(43))
    }
    fn account() -> GuestAccount {
        GuestAccount {
            username: "analyst".into(),
            password_hash: guest_hash(),
            root_uuid: None,
        }
    }
    /// A guestfish stand-in: the read-only probe lists `filesystems`, the
    /// writable run records its argv and commands and prints the hash the
    /// guest stored, as the provisioning script's last `sh` does.
    fn fake_tool(directory: &Path, fail: bool, filesystems: &str) -> std::path::PathBuf {
        let path = directory.join("fake-tool");
        fs::write(&path, format!("#!/bin/sh\nroot=$(dirname \"$0\")\nif [ \"$1\" = --ro ]; then cat > \"$root/probe\"; printf '{filesystems}'; exit 0; fi\nprintf '%s\\n' \"$@\" > \"$root/argv\"\ncat > \"$root/input\"\ncat \"$root/input\" >&2\nprintf 'hash:%s\\n' '{}'\nexit {}\n", guest_hash(), if fail { 1 } else { 0 })).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn offline_tool_uses_stdin_and_never_exposes_sensitive_output() {
        let root = std::env::temp_dir().join(format!("ant-account-{}", storage::unique_id()));
        storage::private_dir(&root).unwrap();
        let disk = root.join("disk.qcow2");
        fs::write(&disk, b"unchanged disk fixture").unwrap();
        // A new account: the guest hashes the password itself.
        let secret = "private-provision-password";
        let mut account = GuestAccount::unprovisioned("analyst".into()).unwrap();
        account
            .provision_with(
                &disk,
                &fake_tool(&root, false, WHOLE_DISK),
                1024,
                &Password::Plain(secret),
            )
            .unwrap();
        assert_eq!(account.password_hash, guest_hash());
        let uuid = account.root_uuid().unwrap().to_owned();
        assert!(valid_uuid(&uuid), "{uuid}");
        assert_eq!(
            fs::read_to_string(root.join("probe")).unwrap().as_bytes(),
            PROBE
        );
        // A whole-disk root keeps its disk as it is (it grows at boot).
        assert!(!input_of(&root).contains("part-"));
        let argv = fs::read_to_string(root.join("argv")).unwrap();
        assert!(argv.starts_with("--rw\n--no-progress-bars\n--format=qcow2\n-a\n"));
        assert!(!argv.contains(secret));
        assert!(!argv.contains(&account.username));
        let input = input_of(&root);
        // The password reaches only the guest's chpasswd, on its standard
        // input: never in a file written to the disk.
        let carrying: Vec<_> = input.lines().filter(|line| line.contains(secret)).collect();
        assert_eq!(carrying.len(), 1, "{input}");
        assert!(
            carrying[0].starts_with("sh \"set -eu\\nchpasswd <<'ACCOUNT'\\nanalyst:private-provision-password\\nACCOUNT\\n"),
            "{}",
            carrying[0]
        );
        assert!(!input.contains("/password"));
        assert!(!input.contains("chpasswd -e"));
        // A new identity before the root is mounted, then the account.
        let position = |text: &str| input.find(text).unwrap_or_else(|| panic!("{text}"));
        assert!(position("e2fsck-f /dev/sda\n") < position(&format!("set-uuid /dev/sda {uuid}")));
        assert!(
            position("-debug sh \"echo ssv hash_seed random | debugfs -w -f - /dev/sda")
                < position("mount /dev/sda /")
        );
        assert!(position("provision.sh\"\n") < position("chpasswd"));
        assert!(input.contains(&format!("UUID={uuid}\\\\1|' /etc/fstab")));
        // The installer's adduser: the full name, its groups (where they
        // exist), a private home; the installation's own machine ID.
        assert!(input.contains("addgroup --quiet --gid 1000 'analyst'"));
        assert!(input.contains(
            "adduser --quiet --uid 1000 --gid 1000 --comment 'Analyst,,,' --disabled-password 'analyst'"
        ));
        assert!(input.contains(&format!("for group in {INSTALLER_GROUPS}; do")));
        assert!(input.contains("chmod 0700 '/home/analyst'"));
        let machine_id = input
            .lines()
            .find_map(|line| line.strip_prefix("write /etc/machine-id \""))
            .unwrap();
        assert!(
            machine_id.len() == 32 + 3 && machine_id.ends_with("\\n\""),
            "{machine_id}"
        );
        assert!(!input.contains("NOPASSWD"));
        assert!(!input.contains("sudoers"));
        assert!(!input.to_lowercase().contains("antinomie"));
        // A reset sets the recorded hash again, and gets a new identity.
        let mut again = account.clone();
        again
            .provision_with(
                &disk,
                &fake_tool(&root, false, WHOLE_DISK),
                1024,
                &Password::Hashed(&guest_hash()),
            )
            .unwrap();
        assert_ne!(again.root_uuid(), Some(uuid.as_str()));
        let input = input_of(&root);
        assert!(input.contains(&format!(
            "chpasswd -e <<'ACCOUNT'\\nanalyst:{}\\nACCOUNT",
            guest_hash()
        )));
        assert!(!input.contains(secret));
        // The guest keeping another hash than the recorded one is an error.
        let other = format!("$6$fixturesalt${}", "a".repeat(86));
        assert!(
            account
                .provision_with(
                    &disk,
                    &fake_tool(&root, false, WHOLE_DISK),
                    1024,
                    &Password::Hashed(&other),
                )
                .unwrap_err()
                .contains("did not keep")
        );
        let error = account
            .provision_with(
                &disk,
                &fake_tool(&root, true, WHOLE_DISK),
                1024,
                &Password::Plain(secret),
            )
            .unwrap_err();
        assert!(!error.contains(secret));
        assert!(!error.contains(&account.password_hash));
        assert!(!format!("{account:?}").contains(&account.password_hash));
        assert!(
            account
                .provision_with(&disk, &root.join("missing"), 1024, &Password::Plain(secret),)
                .is_err()
        );
        // No single ext4 root: nothing is written.
        fs::remove_file(root.join("input")).unwrap();
        for listing in [
            "/dev/sda: xfs\\n",
            "/dev/sda1: ext4\\n/dev/sda2: ext4\\n",
            "/dev/sdb1: ext4\\n",
        ] {
            assert!(
                account
                    .provision_with(
                        &disk,
                        &fake_tool(&root, false, listing),
                        1024,
                        &Password::Plain(secret),
                    )
                    .is_err()
            );
            assert!(!root.join("input").exists());
        }
        assert_eq!(fs::read(&disk).unwrap(), b"unchanged disk fixture");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn partitions_follow_the_installer_and_the_vm() {
        // A 6 GiB disk (12582912 sectors), a 3 GiB root, 1 GiB of RAM: the
        // swap partition ends a MiB before the disk, the root a MiB before it.
        let plan = partition_plan(12_582_912, 6_293_503, 1024, None);
        assert_eq!(plan.swap, Some((10_483_712, 12_580_863)));
        assert_eq!(plan.root_last, 10_481_663);
        // A quarter of the disk at most; the root never shrinks.
        assert_eq!(
            partition_plan(12_582_912, 6_293_503, 8192, None).swap,
            Some((9_435_136, 12_580_863))
        );
        let tight = partition_plan(8_388_608, 8_380_000, 1024, None);
        assert_eq!((tight.root_last, tight.swap), (8_386_559, None));
        let layout = parse_probe(
            "/dev/sda1: ext4\n/dev/sda2: unknown\n/dev/sda5: swap\n6442450944\n[0] = {\n  part_num: 1\n  part_end: 5366611967\n}\n[1] = {\n  part_num: 5\n  part_end: 6441402367\n  part_size: 1073741824\n}\n0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d\n",
        )
        .unwrap();
        assert_eq!(layout.root_last, Some(10_481_663));
        assert_eq!(
            layout.swap,
            Some(("0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d".into(), 2_097_152))
        );
        let root = std::env::temp_dir().join(format!("ant-account-parts-{}", storage::unique_id()));
        storage::private_dir(&root).unwrap();
        let disk = root.join("disk.qcow2");
        fs::write(&disk, b"disk").unwrap();
        let mut account = account();
        account
            .provision_with(
                &disk,
                &fake_tool(&root, false, PARTITIONED),
                1024,
                &Password::Hashed(&guest_hash()),
            )
            .unwrap();
        let input = input_of(&root);
        let position = |text: &str| input.find(text).unwrap_or_else(|| panic!("{text}"));
        assert!(
            position("part-resize /dev/sda 1 10481663\n")
                < position("part-add /dev/sda e 10483710 12580863\n")
        );
        assert!(
            position("part-add /dev/sda l 10483712 12580863\n")
                < position("mkswap /dev/sda5 uuid:")
        );
        assert!(position("resize2fs /dev/sda1\n") < position("mount /dev/sda1 /\n"));
        assert!(input.contains("set-uuid /dev/sda1 "));
        assert!(input.contains("sfdisk --disk-id /dev/sda 0x"));
        assert!(input.contains("# swap was on /dev/sda5 during installation"));
        assert!(input.contains("/etc/initramfs-tools/conf.d/resume"));
        assert!(input.contains("update-grub"));
        // Growing it later keeps the swap partition's UUID and size.
        let grown = "/dev/sda1: ext4\n/dev/sda5: swap\n10737418240\n[0] = {\n  part_num: 1\n  part_end: 5366611967\n}\n[1] = {\n  part_num: 5\n  part_end: 6441402367\n  part_size: 1073741824\n}\n0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d\n";
        grow_disk_with(&disk, &fake_tool(&root, false, &grown.replace('\n', "\\n"))).unwrap();
        let input = input_of(&root);
        assert!(
            input.starts_with(
                "run\npart-del /dev/sda 5\npart-del /dev/sda 2\npart-resize /dev/sda 1 18870271\n"
            ),
            "{input}"
        );
        assert!(input.contains("mkswap /dev/sda5 uuid:0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d\n"));
        assert!(!input.contains("chpasswd"));
        // A whole-disk root is left to the initrd.
        fs::remove_file(root.join("input")).unwrap();
        grow_disk_with(&disk, &fake_tool(&root, false, WHOLE_DISK)).unwrap();
        assert!(!root.join("input").exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn the_guest_reports_the_hash_it_stored() {
        // The guest's chpasswd hashes (yescrypt on Debian 13); the record
        // also takes the SHA-512 hashes of disks provisioned before 0.7.1.
        validate_hash(&guest_hash()).unwrap();
        validate_hash(&format!("$6$fixturesalt${}", "a".repeat(86))).unwrap();
        for bad in [
            format!("$y$j9T${}${}", "a".repeat(22), "b".repeat(42)),
            format!("$y$jFT${}${}", "a".repeat(22), "b".repeat(43)),
            format!("$y$j9T${}${}", "a:".repeat(11), "b".repeat(43)),
            format!("$5$salt${}", "a".repeat(43)),
            "!".into(),
            String::new(),
        ] {
            assert!(validate_hash(&bad).is_err(), "{bad}");
        }
        assert_eq!(
            printed_hash(format!("noise\nhash:{}\n", guest_hash()).as_bytes()),
            Some(guest_hash())
        );
        assert_eq!(printed_hash(b"no marker\n"), None);
        // A password with shell and here-document characters stays one
        // line of chpasswd's input; the hash goes in with -e.
        let commands = password_commands("analyst", &Password::Plain("a'b\"$(x)`ACCOUNT"));
        assert!(commands.contains("chpasswd <<'ACCOUNT'\nanalyst:a'b\"$(x)`ACCOUNT\nACCOUNT\n"));
        let commands = password_commands("analyst", &Password::Hashed(&guest_hash()));
        assert!(commands.contains(&format!(
            "chpasswd -e <<'ACCOUNT'\nanalyst:{}\n",
            guest_hash()
        )));
        assert!(GuestAccount::unprovisioned("root".into()).is_err());
    }
    #[test]
    fn probe_finds_the_root_on_a_whole_disk_or_a_partition() {
        let whole = parse_probe("/dev/sda: ext4\n6442450944\n").unwrap();
        assert_eq!(
            (whole.root.as_str(), whole.size),
            ("/dev/sda", 6_442_450_944)
        );
        assert_eq!((whole.root_last, whole.swap), (None, None));
        assert_eq!(
            parse_probe("/dev/sda1: ext4\n/dev/sda2: unknown\n6442450944\n[0] = {\n  part_num: 1\n  part_end: 3222274047\n}\n")
                .unwrap()
                .root_last,
            Some(6_293_503)
        );
        // No size, or a root partition the probe did not list.
        assert!(parse_probe("/dev/sda: ext4\n").is_err());
        assert!(parse_probe("/dev/sda1: ext4\n6442450944\n").is_err());
        assert!(parse_probe("").is_err());
        assert!(parse_probe("/dev/sda1; rm -rf /: ext4\n").is_err());
        assert_eq!(fish_quote("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert!(valid_uuid("0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"));
        for bad in [
            "0B1C2D3E-4F50-4A6B-8C7D-9E0F1A2B3C4D",
            "0b1c2d3e4f504a6b8c7d9e0f1a2b3c4d",
            "",
        ] {
            assert!(!valid_uuid(bad));
        }
        let mut record = account();
        record.root_uuid = Some("not-a-uuid".into());
        assert!(record.validate().is_err());
    }
    #[test]
    fn account_record_is_private_and_malformed_hashes_are_redacted() {
        let root =
            std::env::temp_dir().join(format!("ant-account-record-{}", storage::unique_id()));
        storage::private_dir(&root).unwrap();
        let account = account();
        account.save(&root).unwrap();
        assert_eq!(
            fs::metadata(root.join("guest-account.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            GuestAccount::load(&root).unwrap().password_hash,
            account.password_hash
        );
        fs::set_permissions(
            root.join("guest-account.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(GuestAccount::load(&root).is_err());
        fs::set_permissions(
            root.join("guest-account.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(
            root.join("guest-account.json"),
            br#"{"username":"analyst","password_hash":123456789}"#,
        )
        .unwrap();
        assert!(!GuestAccount::load(&root).unwrap_err().contains("123456789"));
        fs::remove_dir_all(root).unwrap();
    }
}
