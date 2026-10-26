// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The UEFI disk of a Debian Minimal base, laid out once per base.
//!
//! A Debian installer on a UEFI PC makes a GPT disk with an EFI system
//! partition first, then the root and swap, and installs grub-efi-amd64 and
//! the shim instead of grub-pc. The base's disk is the BIOS installation (an
//! MBR with the root at 1 MiB), and an ext4 filesystem cannot move. So the
//! first VM of the base whose stealth profile boots UEFI has the app derive
//! a second base disk beside it (`base-uefi.qcow2`): the same root filesystem
//! copied after an ESP, with the paths the UEFI installation differs in (the
//! base's `uefi-root.tar.xz`, built by `scripts/debian-uefi-delta.py`) put in
//! place and their times set, as `uefi-layout.json` records them. Every UEFI
//! VM of the base is then an overlay of that disk; provisioning formats the
//! ESP and runs grub-install for the VM, and the bootstrap initrd writes the
//! firmware's `debian` boot entry. BIOS VMs keep the base disk unchanged.

use crate::storage::{self, Bundle};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    os::unix::fs::{MetadataExt, PermissionsExt},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

/// The derived disk and its record, beside the base disk.
pub(crate) const DISK_FILE: &str = "base-uefi.qcow2";
const RECORD_FILE: &str = "base-uefi.json";
/// What the derived disk was laid out by; another value derives it again.
const RECIPE: u32 = 1;
/// The base's UEFI files as the image recipe names them (UEFI_FILES).
pub(crate) const ROOT_FILE: &str = "uefi-root.tar.xz";
pub(crate) const LAYOUT_FILE: &str = "uefi-layout.json";
/// Largest layout record accepted (removed paths and times).
const LAYOUT_MAX_SIZE: u64 = 16 << 20;
/// The whole derivation: a filesystem copy and a package delta.
const DERIVE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Free space kept beyond the derived disk's estimated size.
const SPACE_MARGIN: u64 = 1 << 30;
/// GPT partition types, as partman sets them.
const ESP_TYPE: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
const LINUX_TYPE: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
pub(crate) const SWAP_TYPE: &str = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F";

/// The UEFI files a base carries and, in a VM's copy of its base record, the
/// derived disk its own disk is an overlay of.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UefiFiles {
    /// The UEFI installation's differing paths (xz tar); bases built before
    /// 0.8.0 have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uefi_root: Option<PathBuf>,
    /// The disk's geometry, the BIOS paths to remove and the delta's times.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uefi_layout: Option<PathBuf>,
    /// The derived disk (`base-uefi.qcow2`) a UEFI VM's disk is an overlay of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uefi_disk: Option<PathBuf>,
}

/// One partition of the layout, in 512-byte sectors.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
struct Extent {
    first_sector: u64,
    sectors: u64,
}

#[derive(Debug, Deserialize)]
struct Layout {
    format: u32,
    label: String,
    esp: Extent,
    root: Extent,
    /// Paths of the BIOS installation the UEFI one lacks, deepest first.
    removed: Vec<String>,
    /// Per delta path: access, change, birth and modification time, each
    /// (seconds, nanoseconds).
    times: std::collections::BTreeMap<String, [[u64; 2]; 4]>,
}

/// What a derived disk was made from and its checksum, with the stamp of
/// the file when it was last checked.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    format: u32,
    recipe: u32,
    base_identity: String,
    sha256: String,
    size: u64,
    mtime_ns: i128,
    inode: u64,
}

/// Whether a VM of `bundle` with `profile` gets the UEFI disk: the base
/// carries the UEFI layout and boots UEFI, and the profile asks for it.
pub(crate) fn wanted(bundle: &Bundle, profile: &crate::stealth::StealthProfile) -> bool {
    bundle.uefi.uefi_root.is_some()
        && bundle.uefi.uefi_layout.is_some()
        && crate::stealth::BaseSupport::from_list(&bundle.stealth_support).uefi
        && profile.firmware.is_uefi()
}

/// The firmware a disk of `bundle` was installed for, as words for messages.
pub(crate) fn installed_for(bundle: &Bundle) -> &'static str {
    if bundle.uefi.uefi_disk.is_some() {
        "UEFI (GPT with an EFI system partition)"
    } else {
        "BIOS (MBR, GRUB in the boot sector)"
    }
}

fn record_path(bundle: &Bundle) -> Result<PathBuf, String> {
    Ok(bundle
        .base_disk
        .parent()
        .ok_or("base disk has no folder")?
        .join(RECORD_FILE))
}

fn sha256_hex(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let digest = storage::sha256_uncached(file)?;
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn stamp(path: &Path) -> Result<(u64, i128, u64), String> {
    let metadata = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mtime = i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec());
    Ok((metadata.len(), mtime, metadata.ino()))
}

/// The base's derived UEFI disk if it is there, made from this base by this
/// recipe and unchanged since (its checksum is read again when the file's
/// size, time or inode moved).
pub(crate) fn existing(bundle: &Bundle) -> Result<Option<PathBuf>, String> {
    let identity = bundle
        .base_identity
        .as_ref()
        .ok_or("the base has no installed identity")?;
    let disk = bundle.base_disk.with_file_name(DISK_FILE);
    let path = record_path(bundle)?;
    if !disk.is_file() || !path.is_file() {
        return Ok(None);
    }
    let Ok(mut record) = storage::read_json::<Record>(&path) else {
        return Ok(None);
    };
    if record.format != 1 || record.recipe != RECIPE || &record.base_identity != identity {
        return Ok(None);
    }
    let (size, mtime_ns, inode) = stamp(&disk)?;
    if (size, mtime_ns, inode) != (record.size, record.mtime_ns, record.inode) {
        if sha256_hex(&disk)? != record.sha256 {
            return Err(format!(
                "{} differs from the disk laid out for this base; delete it to lay it out again",
                disk.display()
            ));
        }
        (record.size, record.mtime_ns, record.inode) = (size, mtime_ns, inode);
        storage::atomic_json(&path, &record)?;
    }
    Ok(Some(disk))
}

/// The base's UEFI disk: the one laid out before, or a new one (`progress`
/// gets each stage). Refused, with nothing written, when the base's folder
/// lacks the room for it.
pub(crate) fn derive(
    qemu_img: &Path,
    bundle: &Bundle,
    progress: &mut dyn FnMut(&str),
) -> Result<PathBuf, String> {
    if let Some(disk) = existing(bundle)? {
        return Ok(disk);
    }
    let (Some(root), Some(layout_path)) = (&bundle.uefi.uefi_root, &bundle.uefi.uefi_layout) else {
        return Err("this base carries no UEFI layout".into());
    };
    let guestfish = crate::dependencies::require_tool(Path::new("guestfish"), "libguestfs-tools")?;
    let qemu_img = crate::dependencies::require_tool(qemu_img, "qemu-utils")?;
    let layout = read_layout(layout_path)?;
    let directory = bundle.base_disk.parent().ok_or("base disk has no folder")?;
    progress("checking free space");
    let (virtual_size, allocated) = disk_sizes(&qemu_img, &bundle.base_disk)?;
    if (layout.root.first_sector + layout.root.sectors) * 512 > virtual_size {
        return Err("the base disk is smaller than its UEFI layout".into());
    }
    let needed = allocated + fs::metadata(root).map_err(|e| e.to_string())?.len() * 8;
    require_space(directory, needed + SPACE_MARGIN)?;
    let disk = directory.join(DISK_FILE);
    let partial = directory.join(format!(".{DISK_FILE}.partial"));
    let scratch = std::env::temp_dir().join(format!("antinomie-uefi-{}", storage::unique_id()));
    let _ = fs::remove_file(&partial);
    let result = (|| -> Result<(), String> {
        storage::private_dir(&scratch).map_err(|e| e.to_string())?;
        let output = Command::new(&qemu_img)
            .args(["create", "-q", "-f", "qcow2"])
            .arg(&partial)
            .arg(virtual_size.to_string())
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "qemu-img: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let times = scratch.join("times.debugfs");
        fs::write(&times, timeline_commands(&layout)?).map_err(|e| e.to_string())?;
        let script = scratch.join("derive.fish");
        fs::write(
            &script,
            script_text(&bundle.base_disk, &partial, root, &times, &layout)?,
        )
        .map_err(|e| e.to_string())?;
        run_stages(&guestfish, &script, progress)?;
        File::open(&partial)
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())?;
        progress("recording the UEFI disk");
        let sha256 = sha256_hex(&partial)?;
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o444))
            .map_err(|e| e.to_string())?;
        fs::rename(&partial, &disk).map_err(|e| e.to_string())?;
        let (size, mtime_ns, inode) = stamp(&disk)?;
        storage::atomic_json(
            &record_path(bundle)?,
            &Record {
                format: 1,
                recipe: RECIPE,
                base_identity: bundle.base_identity.clone().unwrap_or_default(),
                sha256,
                size,
                mtime_ns,
                inode,
            },
        )?;
        storage::sync_directory_parent(&disk)
    })();
    let _ = fs::remove_dir_all(&scratch);
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result.map(|()| disk)
}

fn read_layout(path: &Path) -> Result<Layout, String> {
    let size = fs::metadata(path).map_err(|e| e.to_string())?.len();
    if size > LAYOUT_MAX_SIZE {
        return Err("the base's UEFI layout record is too large".into());
    }
    let layout: Layout = storage::read_json(path)?;
    if layout.format != 1 || layout.label != "gpt" {
        return Err("unsupported UEFI layout record".into());
    }
    let esp_end = layout.esp.first_sector + layout.esp.sectors;
    if layout.esp.first_sector < 34
        || layout.esp.sectors == 0
        || layout.root.first_sector < esp_end
        || layout.root.sectors == 0
    {
        return Err("the base's UEFI layout record has an invalid geometry".into());
    }
    for path in layout.removed.iter().chain(layout.times.keys()) {
        valid_path(path)?;
    }
    Ok(layout)
}

/// A relative path from the layout record, safe in guestfish and debugfs
/// commands (no quotes, no control characters, no `..`).
fn valid_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\')
    {
        return Err(format!("invalid path in the base's UEFI layout: {path:?}"));
    }
    Ok(())
}

/// The base disk's virtual size and the space its file takes, in bytes.
fn disk_sizes(qemu_img: &Path, disk: &Path) -> Result<(u64, u64), String> {
    let output = Command::new(qemu_img)
        .args(["info", "-f", "qcow2", "--output=json"])
        .arg(disk)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() || output.stdout.len() > 1 << 20 {
        return Err("cannot inspect the base disk".into());
    }
    let info: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    let field = |name: &str| {
        info.get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("base disk info lacks {name}"))
    };
    Ok((field("virtual-size")?, field("actual-size")?))
}

fn require_space(directory: &Path, needed: u64) -> Result<(), String> {
    let space = rustix::fs::statvfs(directory).map_err(|e| e.to_string())?;
    let free = space.f_bavail.saturating_mul(space.f_frsize);
    if free < needed {
        return Err(format!(
            "laying out this base's UEFI disk (once) needs about {} free in {}; {} available",
            crate::byte_size::file_size(needed),
            directory.display(),
            crate::byte_size::file_size(free)
        ));
    }
    Ok(())
}

/// A guestfish double-quoted string.
fn quoted(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(quoted)
        .ok_or_else(|| format!("{} is not UTF-8", path.display()))
}

/// The guestfish script: the base disk read-only as /dev/sda, the new disk
/// as /dev/sdb; `echo stage:` lines report progress.
fn script_text(
    base: &Path,
    disk: &Path,
    root: &Path,
    times: &Path,
    layout: &Layout,
) -> Result<String, String> {
    let esp_last = layout.esp.first_sector + layout.esp.sectors - 1;
    let root_last = layout.root.first_sector + layout.root.sectors - 1;
    let mut lines = vec![
        format!("add {} readonly:true format:qcow2", path_text(base)?),
        format!("add {} format:qcow2", path_text(disk)?),
        "run".to_owned(),
        "echo stage:laying out the partitions".to_owned(),
        "part-init /dev/sdb gpt".to_owned(),
        format!("part-add /dev/sdb p {} {esp_last}", layout.esp.first_sector),
        format!(
            "part-add /dev/sdb p {} {root_last}",
            layout.root.first_sector
        ),
        format!("part-set-gpt-type /dev/sdb 1 {ESP_TYPE}"),
        format!("part-set-gpt-type /dev/sdb 2 {LINUX_TYPE}"),
        "echo stage:copying the root filesystem".to_owned(),
        "copy-device-to-device /dev/sda1 /dev/sdb2 sparse:true".to_owned(),
        "echo stage:installing the UEFI boot loader's files".to_owned(),
        "mount /dev/sdb2 /".to_owned(),
    ];
    lines.extend(
        layout
            .removed
            .iter()
            .map(|path| format!("rm-rf {}", quoted(&format!("/{path}")))),
    );
    lines.extend([
        format!(
            "tar-in {} / compress:xz xattrs:true acls:true",
            path_text(root)?
        ),
        // The times, for debugfs once the filesystem is unmounted.
        format!("upload {} /tmp/.times", path_text(times)?),
        "debug sh \"cp /sysroot/tmp/.times /tmp/.times\"".to_owned(),
        "rm /tmp/.times".to_owned(),
        "umount-all".to_owned(),
        "echo stage:setting the installation's times".to_owned(),
        "debug sh \"debugfs -w -f /tmp/.times /dev/sdb2 >/dev/null 2>&1\"".to_owned(),
        // partman leaves GPT partition names empty; parted's mkpart (which
        // part-add runs) names them "primary". Last: sgdisk has the kernel
        // read the table again.
        "debug sh \"sgdisk --change-name=1: --change-name=2: /dev/sdb\"".to_owned(),
        "echo stage:done".to_owned(),
        String::new(),
    ]);
    Ok(lines.join("\n"))
}

/// debugfs commands that set each delta path's times (the image recipe's
/// apply_timeline for these paths).
fn timeline_commands(layout: &Layout) -> Result<String, String> {
    let mut text = String::new();
    for (path, times) in &layout.times {
        for (field, [seconds, nanoseconds]) in
            ["atime", "ctime", "crtime", "mtime"].iter().zip(times)
        {
            if *nanoseconds >= 1_000_000_000 {
                return Err("invalid time in the base's UEFI layout".into());
            }
            text.push_str(&format!(
                "set_inode_field \"/{path}\" {field} @{seconds}\nset_inode_field \"/{path}\" {field}_extra {}\n",
                nanoseconds << 2
            ));
        }
    }
    Ok(text)
}

/// Run guestfish on `script`, reporting its `stage:` lines, within
/// [`DERIVE_TIMEOUT`]; the tool's process group is killed on a timeout.
fn run_stages(
    guestfish: &Path,
    script: &Path,
    progress: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let mut child = Command::new(guestfish)
        .args(["--no-progress-bars", "-f"])
        .arg(script)
        .env("LIBGUESTFS_BACKEND", "direct")
        .env("LIBGUESTFS_DEBUG", "0")
        .env("LIBGUESTFS_TRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("guestfish: {e}"))?;
    let (sender, receiver) = mpsc::channel();
    let stdout = child.stdout.take().ok_or("guestfish output unavailable")?;
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let mut stderr = child.stderr.take().ok_or("guestfish output unavailable")?;
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stderr).take(64 * 1024).read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + DERIVE_TIMEOUT;
    let status = loop {
        while let Ok(line) = receiver.try_recv() {
            if let Some(stage) = line.strip_prefix("stage:") {
                progress(stage);
            }
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = Command::new("/bin/kill")
                .args(["--signal", "KILL", "--", &format!("-{}", child.id())])
                .status();
            let _ = child.wait();
            return Err("laying out the UEFI disk timed out".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = reader.join();
    while let Ok(line) = receiver.try_recv() {
        if let Some(stage) = line.strip_prefix("stage:") {
            progress(stage);
        }
    }
    let errors = errors.join().unwrap_or_default();
    if !status.success() {
        let last = errors.lines().rev().find(|line| !line.trim().is_empty());
        return Err(format!(
            "laying out the UEFI disk failed: {}",
            last.unwrap_or("guestfish failed")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
