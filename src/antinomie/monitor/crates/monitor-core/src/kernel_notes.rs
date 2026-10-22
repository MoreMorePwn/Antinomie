// SPDX-License-Identifier: GPL-3.0-only
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
//! * `lifecycle.creds` (layout `antinomie.creds/2`, 96 bytes; `/1`, 72 bytes,
//!   from earlier builds is still read) is the task's credentials at its first
//!   traced call and after every change, with all five capability sets and the
//!   securebits in `/2`.
//! * `lifecycle.file_hash` (layout `antinomie.hash/1`, 80 bytes) is the SHA-256
//!   of an executed image or of a file about to be deleted, or the reason it
//!   was not computed. A worker publishes it after the call returned, still
//!   under that call's identity. A guest that offers it (`TRACER_CAPS`) also
//!   hashes, on request, the launched program's own image (under the launch's
//!   identity, call id 0) and each regular file the run wrote when its last
//!   writer closed it: layout `antinomie.hash/2`, 112 bytes, the same record
//!   followed by the file's device, inode, generation, mode and link count,
//!   because the call it belongs to (the closing task's last) need not name
//!   the file.
//!
//! * `lifecycle.file_id` (layout `antinomie.fileid/1`, 32 bytes) is the device
//!   and inode of a file a call opened, renamed, linked or removed, or that an
//!   io_uring or AIO request used. An io_uring request carries the same record
//!   as its operand `async.operand.file_id`. It lets one file be followed
//!   across names; a guest from before it records none, and then a file is
//!   known only by its names.
//! * `lifecycle.exec_image` (layout `antinomie.execimg/1`) is published once per
//!   exec: the image that was loaded and, for a script, the interpreter its
//!   `#!` line named.
//!
//! The byte layouts are in `protocol/control.h`.
use crate::api::EventSummary;

pub const CREDS_KEY: &str = "lifecycle.creds";
pub const HASH_KEY: &str = "lifecycle.file_hash";
pub const FILE_ID_KEY: &str = "lifecycle.file_id";
/// The operand an io_uring or AIO request carries instead.
pub const FILE_ID_OPERAND: &str = "async.operand.file_id";
pub const EXEC_IMAGE_KEY: &str = "lifecycle.exec_image";
const CREDS_LAYOUT: &str = "antinomie.creds/2";
const CREDS_LAYOUT_V1: &str = "antinomie.creds/1";
const HASH_LAYOUT: &str = "antinomie.hash/1";
const HASH_WRITE_LAYOUT: &str = "antinomie.hash/2";
pub const FILE_ID_LAYOUT: &str = "antinomie.fileid/1";
const EXEC_IMAGE_LAYOUT: &str = "antinomie.execimg/1";
pub const FILE_ID_SIZE: usize = 32;
const EXEC_IMAGE_HEADER: usize = 40;
pub(crate) const CREDS_SIZE: usize = 96;
const CREDS_SIZE_V1: usize = 72;
pub(crate) const HASH_SIZE: usize = 80;
const HASH_WRITE_SIZE: usize = 112;
/// "Unmapped" for a user or group id, "unset" for the login uid and session.
pub const UNSET: u32 = u32::MAX;
/// Most records kept for one call: a call changes credentials a few times at
/// most, and one hash follows an exec or a delete.
pub(crate) const NOTES_PER_CALL: usize = 32;

/// Whether `event` carries one of the records above, so call pairing keeps it.
pub fn is_note(event: &EventSummary) -> bool {
    event.phase == 3
        && event.fields.iter().any(|field| {
            matches!(
                field.key.as_str(),
                CREDS_KEY | HASH_KEY | FILE_ID_KEY | EXEC_IMAGE_KEY
            )
        })
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
    /// `prctl` changed the ambient or bounding set, the securebits or keepcaps.
    Prctl,
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
            11 => Self::Prctl,
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
    /// Bounding and ambient sets and the securebits; `None` in a `/1` record,
    /// which did not carry them.
    pub cap_bounding: Option<u64>,
    pub cap_ambient: Option<u64>,
    pub securebits: Option<u32>,
}

/// The credentials record of `event`, when it is a complete one.
pub fn credentials(event: &EventSummary) -> Option<Credentials> {
    let current = payload(event, CREDS_KEY, CREDS_LAYOUT, CREDS_SIZE);
    let data = match current {
        Some(data) => data,
        None => payload(event, CREDS_KEY, CREDS_LAYOUT_V1, CREDS_SIZE_V1)?,
    };
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
        cap_bounding: current.map(|data| u64_at(data, 72)),
        cap_ambient: current.map(|data| u64_at(data, 80)),
        securebits: current.map(|data| u32_at(data, 88)),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashKind {
    /// The image an exec committed.
    Exec,
    /// A file about to be deleted.
    Delete,
    /// A file the run wrote, when its last writer closed it.
    Write,
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
    /// [`HashKind::Write`]: the file whose last writer closed it, as it was
    /// then.
    pub file: Option<ClosedFile>,
}

/// The file a write hash describes, at its last close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosedFile {
    pub key: FileKey,
    pub mode: u32,
    /// Hard links left: 0 when every name was removed before the close.
    pub nlink: u32,
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
    let (data, file) = match payload(event, HASH_KEY, HASH_WRITE_LAYOUT, HASH_WRITE_SIZE) {
        Some(data) => (
            data,
            Some(ClosedFile {
                key: FileKey {
                    dev: u64_at(data, 80),
                    ino: u64_at(data, 88),
                    generation: u32_at(data, 96),
                },
                mode: u32_at(data, 100),
                nlink: u32_at(data, 104),
            }),
        ),
        None => (payload(event, HASH_KEY, HASH_LAYOUT, HASH_SIZE)?, None),
    };
    // Only a write record says which file it describes; the others name it
    // through their call.
    let kind = match (data[0], file.is_some()) {
        (1, false) => HashKind::Exec,
        (2, false) => HashKind::Delete,
        (3, true) => HashKind::Write,
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
        file,
    })
}

/// What a call did to the file whose identity a record carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileIdKind {
    /// The file an open returned.
    Open,
    /// The inode a rename moved.
    Rename,
    /// The inode that got a new name.
    Link,
    /// The inode whose name was removed.
    Unlink,
    /// The file an io_uring or AIO request used.
    Issue,
    /// The image an exec loaded.
    Exec,
    Unknown(u8),
}

/// The identity of a file inode: the same on every name of the file, and
/// different for a new file that took a name over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileKey {
    pub dev: u64,
    pub ino: u64,
    /// `i_generation`: tells a reused inode number from the file before it.
    pub generation: u32,
}

/// A file identity record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    pub kind: FileIdKind,
    pub key: FileKey,
    /// Hard links the inode has after the call.
    pub nlink: u32,
    pub mode: u32,
    pub directory: bool,
    pub regular: bool,
    pub symlink: bool,
}

fn file_id_from(data: &[u8]) -> FileId {
    let kind = match data[0] {
        1 => FileIdKind::Open,
        2 => FileIdKind::Rename,
        3 => FileIdKind::Link,
        4 => FileIdKind::Unlink,
        5 => FileIdKind::Issue,
        6 => FileIdKind::Exec,
        other => FileIdKind::Unknown(other),
    };
    FileId {
        kind,
        key: FileKey {
            dev: u64_at(data, 8),
            ino: u64_at(data, 16),
            generation: u32_at(data, 24),
        },
        nlink: u32_at(data, 4),
        mode: u32_at(data, 28),
        directory: data[1] & 1 != 0,
        regular: data[1] & 2 != 0,
        symlink: data[1] & 4 != 0,
    }
}

/// The file identity record of `event`, when it is a complete one.
pub fn file_id(event: &EventSummary) -> Option<FileId> {
    payload(event, FILE_ID_KEY, FILE_ID_LAYOUT, FILE_ID_SIZE).map(file_id_from)
}

/// The identity an io_uring or AIO request carried as an operand.
pub fn file_id_operand(field: &crate::api::FieldSummary) -> Option<FileId> {
    (field.key == FILE_ID_OPERAND
        && field.complete
        && field.layout == FILE_ID_LAYOUT
        && field.preview.len() >= FILE_ID_SIZE)
        .then(|| file_id_from(&field.preview[..FILE_ID_SIZE]))
}

/// The image an exec loaded and the interpreter a script named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecImage {
    /// The interpreter exactly as the script's `#!` line names it; `None` when
    /// the image is not a script's interpreter.
    pub interpreter: Option<String>,
    /// The resolved path of the loaded image: for a script, the interpreter's
    /// file. `None` when the guest could not resolve it.
    pub path: Option<String>,
    /// The interpreter name was longer than the guest records.
    pub interpreter_truncated: bool,
    /// The image path was longer than the guest records.
    pub path_truncated: bool,
    pub key: FileKey,
    pub nlink: u32,
    pub mode: u32,
}

/// The exec image record of `event`, when it is a complete one.
pub fn exec_image(event: &EventSummary) -> Option<ExecImage> {
    if event.phase != 3 {
        return None;
    }
    let field = event
        .fields
        .iter()
        .find(|field| field.key == EXEC_IMAGE_KEY)?;
    if !field.complete
        || field.layout != EXEC_IMAGE_LAYOUT
        || field.preview.len() < EXEC_IMAGE_HEADER
    {
        return None;
    }
    let data = &field.preview;
    let flags = u32_at(data, 0);
    let interp_len = u32_at(data, 4) as usize;
    let path_len = u32_at(data, 8) as usize;
    let text = |start: usize, len: usize| -> Option<String> {
        let end = start.checked_add(len)?;
        let bytes = data.get(start..end)?;
        let (last, text) = bytes.split_last()?;
        (*last == 0)
            .then(|| std::str::from_utf8(text).ok().map(str::to_owned))
            .flatten()
    };
    // A name that did not fit is not a name: it stays unknown.
    let interpreter = (interp_len != 0 && flags & 2 == 0)
        .then(|| text(EXEC_IMAGE_HEADER, interp_len))
        .flatten();
    let path = (path_len != 0 && flags & 4 == 0)
        .then(|| text(EXEC_IMAGE_HEADER + interp_len, path_len))
        .flatten();
    Some(ExecImage {
        interpreter,
        path,
        interpreter_truncated: flags & 2 != 0,
        path_truncated: flags & 4 != 0,
        key: FileKey {
            dev: u64_at(data, 16),
            ino: u64_at(data, 24),
            generation: u32_at(data, 32),
        },
        nlink: u32_at(data, 12),
        mode: u32_at(data, 36),
    })
}

#[cfg(test)]
pub(crate) mod tests;
