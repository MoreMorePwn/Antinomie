// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Credential and file-hash records the guest kernel tracer writes (contract
//! revision 17).
//!
//! Both are ordinary phase-3 lifecycle events with one fixed-structure field,
//! so a recording from before they existed has none and a recording read by an
//! older application only shows an unknown lifecycle field. Nothing here
//! guesses: a value the kernel did not record, or recorded as unavailable,
//! stays `None`.
//!
//! * `lifecycle.creds` (layout `antinomie.creds/1`, 72 bytes) is the task's
//!   credentials at its first traced call and after every change.
//! * `lifecycle.file_hash` (layout `antinomie.hash/1`, 80 bytes) is the SHA-256
//!   of an executed image or of a file about to be deleted, or the reason it
//!   was not computed. A worker publishes it after the call returned, still
//!   under that call's identity.
//!
//! The byte layouts are in `protocol/control.h`.
use crate::api::EventSummary;

pub const CREDS_KEY: &str = "lifecycle.creds";
pub const HASH_KEY: &str = "lifecycle.file_hash";
const CREDS_LAYOUT: &str = "antinomie.creds/1";
const HASH_LAYOUT: &str = "antinomie.hash/1";
pub(crate) const CREDS_SIZE: usize = 72;
pub(crate) const HASH_SIZE: usize = 80;
/// "Unmapped" for a user or group id, "unset" for the login uid and session.
pub const UNSET: u32 = u32::MAX;
/// Most records kept for one call: a call changes credentials a few times at
/// most, and one hash follows an exec or a delete.
pub(crate) const NOTES_PER_CALL: usize = 32;

/// Whether `event` carries one of the records above, so call pairing keeps it.
pub fn is_note(event: &EventSummary) -> bool {
    event.phase == 3
        && event
            .fields
            .iter()
            .any(|field| field.key == CREDS_KEY || field.key == HASH_KEY)
}

fn payload<'a>(event: &'a EventSummary, key: &str, layout: &str, size: usize) -> Option<&'a [u8]> {
    if event.phase != 3 {
        return None;
    }
    let field = event.fields.iter().find(|field| field.key == key)?;
    (field.complete && field.layout == layout && field.preview.len() >= size)
        .then(|| &field.preview[..size])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap_or_default())
}
fn u64_at(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap_or_default())
}

/// Why the kernel wrote a credentials record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialChange {
    /// First traced call of the task: the credentials it already had.
    Start,
    SetUid,
    SetGid,
    SetRes,
    SetFs,
    CapSet,
    /// A setuid or setgid image was executed.
    ExecSetId,
    /// An exec changed the capability sets without changing any id.
    ExecCaps,
    LoginUid,
    Other,
    Unknown(u32),
}

impl CredentialChange {
    fn from_code(code: u32) -> Self {
        match code {
            1 => Self::Start,
            2 => Self::SetUid,
            3 => Self::SetGid,
            4 => Self::SetRes,
            5 => Self::SetFs,
            6 => Self::CapSet,
            7 => Self::ExecSetId,
            8 => Self::ExecCaps,
            9 => Self::LoginUid,
            10 => Self::Other,
            other => Self::Unknown(other),
        }
    }
}

/// A task's credentials as the kernel saw them, in the initial user namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    /// Login uid; `None` when the kernel does not track it or it was never set.
    pub auid: Option<u32>,
    pub session: Option<u32>,
    /// The kernel tracks the login uid (audit support compiled in), so an unset
    /// `auid` is a real value and not a missing one.
    pub audit: bool,
    pub change: CredentialChange,
    pub cap_effective: u64,
    pub cap_permitted: u64,
    pub cap_inheritable: u64,
}

/// The credentials record of `event`, when it is a complete one.
pub fn credentials(event: &EventSummary) -> Option<Credentials> {
    let data = payload(event, CREDS_KEY, CREDS_LAYOUT, CREDS_SIZE)?;
    let audit = u32_at(data, 44) & 1 != 0;
    let set = |value: u32| (audit && value != UNSET).then_some(value);
    Some(Credentials {
        uid: u32_at(data, 0),
        euid: u32_at(data, 4),
        suid: u32_at(data, 8),
        fsuid: u32_at(data, 12),
        gid: u32_at(data, 16),
        egid: u32_at(data, 20),
        sgid: u32_at(data, 24),
        fsgid: u32_at(data, 28),
        auid: set(u32_at(data, 32)),
        session: set(u32_at(data, 36)),
        audit,
        change: CredentialChange::from_code(u32_at(data, 40)),
        cap_effective: u64_at(data, 48),
        cap_permitted: u64_at(data, 56),
        cap_inheritable: u64_at(data, 64),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashKind {
    /// The image an exec committed.
    Exec,
    /// A file about to be deleted.
    Delete,
}

/// What became of one hashing request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashStatus {
    Ok,
    /// Over the guest's size limit; the file was not read.
    TooLarge,
    /// A filesystem the tracer never opens (it could block on a remote peer).
    UnsupportedFilesystem,
    NotRegular,
    /// The bounded queue was full: the request was dropped.
    QueueFull,
    ReadError,
    NoMemory,
    /// Too many bytes were already waiting: the request was dropped.
    Budget,
    Unknown(u8),
}

/// A file hash record of one call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHash {
    pub kind: HashKind,
    pub status: HashStatus,
    pub sha256: Option<[u8; 32]>,
    /// Size of the file when the call ran.
    pub size: u64,
    pub hashed: u64,
    pub limit: u64,
    pub error: i32,
    /// The image was the interpreter of a script, not the script itself.
    pub interpreter: bool,
    /// The file changed while it was read, so the hash may not match what the
    /// call saw.
    pub changed: bool,
    /// The digest came from one computed earlier for the same, unchanged file.
    pub cached: bool,
    pub queue_us: u32,
    pub hash_us: u32,
    /// Records the guest has lost since boot (queue, budget, memory, ring).
    pub lost: u32,
}

impl FileHash {
    /// SHA-256 as lowercase hex.
    pub fn sha256_hex(&self) -> Option<String> {
        let digest = self.sha256?;
        Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    /// The Sysmon `Hashes` value (`SHA256=…`) when it describes the file the
    /// call named: a script run through its interpreter hashes the interpreter,
    /// and a file that changed while it was read may not match.
    pub fn sysmon(&self) -> Option<String> {
        if self.interpreter || self.changed {
            return None;
        }
        Some(format!("SHA256={}", self.sha256_hex()?))
    }

    /// Why no usable hash exists, in words for a person; `None` when there is
    /// one.
    pub fn skipped(&self) -> Option<String> {
        let limit = self.limit / (1024 * 1024);
        let reason = match self.status {
            HashStatus::Ok if self.interpreter => {
                "the image was a script's interpreter, not the script".to_owned()
            }
            HashStatus::Ok if self.changed => "the file changed while it was being read".to_owned(),
            HashStatus::Ok => return None,
            HashStatus::TooLarge => format!(
                "file is {} bytes, over the {limit} MiB limit",
                self.size.max(self.hashed)
            ),
            HashStatus::UnsupportedFilesystem => {
                "the filesystem is not one the tracer reads".to_owned()
            }
            HashStatus::NotRegular => "not a regular file".to_owned(),
            HashStatus::QueueFull => "dropped: the guest hashing queue was full".to_owned(),
            HashStatus::Budget => "dropped: too many bytes were waiting to be hashed".to_owned(),
            HashStatus::NoMemory => "no memory in the guest".to_owned(),
            HashStatus::ReadError => format!("read error {}", self.error),
            HashStatus::Unknown(code) => format!("unknown status {code}"),
        };
        Some(reason)
    }
}

/// How many credential and hash records the guest has lost since boot, as the
/// latest hash record of `event` reports it. Nothing else carries the count.
pub fn guest_lost(event: &EventSummary) -> Option<u64> {
    file_hash(event).map(|hash| u64::from(hash.lost))
}

/// The file hash record of `event`, when it is a complete one.
pub fn file_hash(event: &EventSummary) -> Option<FileHash> {
    let data = payload(event, HASH_KEY, HASH_LAYOUT, HASH_SIZE)?;
    let kind = match data[0] {
        1 => HashKind::Exec,
        2 => HashKind::Delete,
        _ => return None,
    };
    let status = match data[1] {
        0 => HashStatus::Ok,
        1 => HashStatus::TooLarge,
        2 => HashStatus::UnsupportedFilesystem,
        3 => HashStatus::NotRegular,
        4 => HashStatus::QueueFull,
        5 => HashStatus::ReadError,
        6 => HashStatus::NoMemory,
        7 => HashStatus::Budget,
        other => HashStatus::Unknown(other),
    };
    let sha256 = (status == HashStatus::Ok && data[2] & 1 != 0)
        .then(|| <[u8; 32]>::try_from(&data[32..64]).ok())
        .flatten();
    Some(FileHash {
        kind,
        status,
        sha256,
        size: u64_at(data, 8),
        hashed: u64_at(data, 16),
        limit: u64_at(data, 24),
        error: u32_at(data, 4) as i32,
        interpreter: data[3] & 1 != 0,
        changed: data[3] & 2 != 0,
        cached: data[3] & 4 != 0,
        queue_us: u32_at(data, 64),
        hash_us: u32_at(data, 68),
        lost: u32_at(data, 72),
    })
}

#[cfg(test)]
pub(crate) mod tests;
