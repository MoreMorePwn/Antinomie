// SPDX-License-Identifier: GPL-3.0-only
//! Who owns a data directory (design 2.3).
//!
//! The lock on `.app-owner.lock` stays the authority: one process owns the
//! directory at a time. Whoever takes the lock also writes `run/owner.json`
//! (atomically, mode 0600) so another process can say who that is, and removes
//! it on a clean exit. A record whose process is gone, or that no lock backs, is
//! stale and ignored: the file is only ever a description, never a lock.
use crate::storage;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// The start of the error text when the directory is owned by another process.
/// Front ends match on it to pick their own wording and exit code.
pub const IN_USE: &str = "data folder is already in use";

const LOCK_FILE: &str = ".app-owner.lock";
const RECORD_MAX: u64 = 16 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnerKind {
    /// The window (`antinomie-monitor`).
    #[default]
    Gui,
    /// `antinomie-cli auto daemon`.
    Daemon,
    /// A one-shot `antinomie-cli` command running the engine in direct mode.
    Cli,
}

/// What a front end says about itself when it takes the directory; part of
/// `BackendOptions`. The default is the window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnerClaim {
    pub kind: OwnerKind,
    /// The socket a daemon serves, recorded for clients.
    pub socket: Option<PathBuf>,
}

/// The content of `run/owner.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerRecord {
    pub pid: u32,
    pub kind: OwnerKind,
    pub started_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    pub app_version: String,
}

/// The current owner of a directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataOwner {
    /// The record of the process that holds the lock; `None` when the lock is
    /// held but no usable record backs it (an older app, or a record of a
    /// process that is gone).
    pub record: Option<OwnerRecord>,
}

impl DataOwner {
    /// One line naming the owner, for messages.
    pub fn describe(&self) -> String {
        let Some(record) = &self.record else {
            return "another process (it left no owner record)".into();
        };
        let what = match record.kind {
            OwnerKind::Gui => "the Antinomie window",
            OwnerKind::Daemon => "the Antinomie daemon",
            OwnerKind::Cli => "an antinomie-cli command",
        };
        let mut text = format!(
            "{what} (pid {}, started {} UTC",
            record.pid,
            crate::date::date_time_text((record.started_ms / 1000) as i64)
        );
        if let Some(socket) = &record.socket {
            text.push_str(&format!(", socket {socket}"));
        }
        text.push(')');
        text
    }
}

pub fn record_path(data_dir: &Path) -> PathBuf {
    data_dir.join("run").join("owner.json")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn process_alive(pid: u32) -> bool {
    pid != 0 && Path::new(&format!("/proc/{pid}")).exists()
}

/// The record for this process.
pub fn record_for(claim: &OwnerClaim) -> OwnerRecord {
    OwnerRecord {
        pid: std::process::id(),
        kind: claim.kind,
        started_ms: now_ms(),
        socket: claim
            .socket
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        app_version: crate::api::APP_VERSION.to_owned(),
    }
}

/// Publish `record` as `run/owner.json`: a private `run` folder, then a
/// temporary file renamed over the old record, mode 0600.
pub fn write_record(data_dir: &Path, record: &OwnerRecord) -> Result<(), String> {
    let path = record_path(data_dir);
    storage::private_dir(path.parent().ok_or("owner record has no folder")?)
        .map_err(|error| error.to_string())?;
    let mut bytes = serde_json::to_vec_pretty(record).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    storage::atomic_bytes(&path, &bytes)
}

/// The record on disk, without any check that it is current. A missing,
/// oversized, symlinked or unreadable file reads as no record.
pub fn read_record(data_dir: &Path) -> Option<OwnerRecord> {
    let path = record_path(data_dir);
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > RECORD_MAX {
        return None;
    }
    serde_json::from_slice(&fs::read(&path).ok()?).ok()
}

/// Remove the record, but only the one this process wrote: a record of another
/// pid belongs to whoever took the lock after us.
pub fn remove_record(data_dir: &Path) {
    if read_record(data_dir).is_some_and(|record| record.pid == std::process::id()) {
        let _ = fs::remove_file(record_path(data_dir));
    }
}

/// Whether another process holds the lock of `data_dir`, and who it says it is.
///
/// The lock is probed without waiting and released at once. A directory with
/// no lock file is free. A record is reported only when its process is alive;
/// otherwise the lock holder is "unknown". `Ok(None)` means free: a stale record
/// is ignored.
pub fn current_owner(data_dir: &Path) -> Result<Option<DataOwner>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let lock = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(data_dir.join(LOCK_FILE))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", data_dir.join(LOCK_FILE).display())),
    };
    match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(None),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(Some(DataOwner {
            record: read_record(data_dir).filter(|record| process_alive(record.pid)),
        })),
        Err(error) => Err(format!("cannot probe the data folder lock: {error}")),
    }
}

/// The error text for a directory that is in use.
pub fn in_use_message(owner: &DataOwner) -> String {
    format!("{IN_USE} by {}", owner.describe())
}

/// Take the lock of `data_dir` and write the owner record without starting the
/// engine, for a command that edits data the engine reads (the rules registry)
/// and must not race a window or a daemon. The directory must exist. Fails with
/// [`IN_USE`] text when another process owns it.
pub fn lock_data_dir(data_dir: &Path, claim: &OwnerClaim) -> Result<OwnerGuard, String> {
    if let Some(owner) = current_owner(data_dir)? {
        return Err(in_use_message(&owner));
    }
    crate::backend::acquire_data_owner(data_dir, claim)
}

/// Held by the process that owns the directory: the lock file, plus the duty to
/// remove the record. Dropping it removes the record first, then releases the
/// lock, so a new owner never sees the old record.
pub struct OwnerGuard {
    data_dir: PathBuf,
    lock: Option<fs::File>,
}

impl OwnerGuard {
    pub(crate) fn new(data_dir: PathBuf, lock: fs::File) -> Self {
        Self {
            data_dir,
            lock: Some(lock),
        }
    }
}

impl Drop for OwnerGuard {
    fn drop(&mut self) {
        remove_record(&self.data_dir);
        self.lock.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("ant-owner-{name}-{}", storage::unique_id()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn claim(kind: OwnerKind) -> OwnerClaim {
        OwnerClaim { kind, socket: None }
    }

    #[test]
    fn the_record_is_written_private_and_read_back() {
        let root = scratch("write");
        let mut record = record_for(&claim(OwnerKind::Daemon));
        record.socket = Some("/run/x.sock".into());
        write_record(&root, &record).unwrap();
        let path = record_path(&root);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(read_record(&root), Some(record));
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"kind\": \"daemon\"") && text.contains("\"app_version\""));
        // No temporary file is left beside it.
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_damaged_or_oversized_record_reads_as_none() {
        let root = scratch("damaged");
        fs::create_dir_all(root.join("run")).unwrap();
        fs::write(record_path(&root), b"{not json").unwrap();
        assert_eq!(read_record(&root), None);
        fs::write(record_path(&root), vec![b' '; 20_000]).unwrap();
        assert_eq!(read_record(&root), None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn removal_only_takes_the_record_of_this_process() {
        let root = scratch("remove");
        let mut other = record_for(&claim(OwnerKind::Gui));
        other.pid = std::process::id().wrapping_add(1);
        write_record(&root, &other).unwrap();
        remove_record(&root);
        assert!(record_path(&root).exists());
        write_record(&root, &record_for(&claim(OwnerKind::Cli))).unwrap();
        remove_record(&root);
        assert!(!record_path(&root).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_stale_record_without_a_lock_is_ignored() {
        let root = scratch("stale");
        let mut record = record_for(&claim(OwnerKind::Gui));
        record.pid = 4_000_000_000;
        write_record(&root, &record).unwrap();
        // No lock file at all, then a lock file nobody holds.
        assert_eq!(current_owner(&root).unwrap(), None);
        fs::write(root.join(LOCK_FILE), b"").unwrap();
        assert_eq!(current_owner(&root).unwrap(), None);
        fs::remove_dir_all(root).unwrap();
    }

    fn hold_lock(root: &Path) -> fs::File {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(LOCK_FILE))
            .unwrap();
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        file
    }

    #[test]
    fn a_held_lock_reports_the_live_record_and_ignores_a_dead_one() {
        let root = scratch("held");
        let _lock = hold_lock(&root);
        // Held, no record: an owner without a name.
        assert_eq!(
            current_owner(&root).unwrap(),
            Some(DataOwner { record: None })
        );
        let mut record = record_for(&claim(OwnerKind::Daemon));
        write_record(&root, &record).unwrap();
        let owner = current_owner(&root).unwrap().unwrap();
        assert_eq!(owner.record.as_ref().unwrap().pid, std::process::id());
        let message = in_use_message(&owner);
        assert!(message.starts_with(IN_USE));
        assert!(message.contains("daemon") && message.contains(&std::process::id().to_string()));
        // The recorded process is gone: the lock is still held, the name is not trusted.
        record.pid = 4_000_000_000;
        write_record(&root, &record).unwrap();
        assert_eq!(
            current_owner(&root).unwrap(),
            Some(DataOwner { record: None })
        );
        assert!(in_use_message(&DataOwner { record: None }).contains("no owner record"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_guard_removes_its_record_and_frees_the_lock() {
        let root = scratch("guard");
        let lock = hold_lock(&root);
        write_record(&root, &record_for(&claim(OwnerKind::Gui))).unwrap();
        assert!(current_owner(&root).unwrap().is_some());
        drop(OwnerGuard::new(root.clone(), lock));
        assert!(!record_path(&root).exists());
        assert_eq!(current_owner(&root).unwrap(), None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lock_data_dir_excludes_a_second_owner_and_names_the_first() {
        let root = scratch("lock");
        let first = lock_data_dir(&root, &claim(OwnerKind::Cli)).unwrap();
        let error = lock_data_dir(&root, &claim(OwnerKind::Gui)).err().unwrap();
        assert!(
            error.starts_with(IN_USE) && error.contains("antinomie-cli"),
            "{error}"
        );
        drop(first);
        assert!(lock_data_dir(&root, &claim(OwnerKind::Gui)).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_description_names_kind_pid_time_and_socket() {
        let record = OwnerRecord {
            pid: 42,
            kind: OwnerKind::Daemon,
            started_ms: 1_793_448_000_000,
            socket: Some("/d/run/antinomie.sock".into()),
            app_version: "0.9.0".into(),
        };
        assert_eq!(
            DataOwner {
                record: Some(record)
            }
            .describe(),
            "the Antinomie daemon (pid 42, started 2026-10-31 12:00:00 UTC, socket /d/run/antinomie.sock)"
        );
    }
}
