// SPDX-License-Identifier: MIT
//! The reader's requests and answers: one JSON object per line, one request
//! in flight at a time, each answer echoing its request id. The child knows
//! only `/image` and `/out`; every path in this protocol is a guest path.
use super::super::Ext4State;
use serde::{Deserialize, Serialize};

/// Entries of one listing page.
pub const PAGE_LEN: usize = 256;
/// Directory entries read at most from one directory.
pub const DIRECTORY_ENTRY_LIMIT: usize = 65_536;
/// Matches a find returns at most.
pub const FIND_MATCH_LIMIT: usize = 5_000;
/// Entries a find looks at at most.
pub const FIND_SCAN_LIMIT: usize = 1_000_000;
/// Wall-clock budget of one find, in seconds.
pub const FIND_SECONDS: u64 = 15;
/// Directory depth a find descends to.
pub const FIND_DEPTH_LIMIT: usize = 64;
/// Longest guest path accepted or reported, in bytes.
pub const PATH_LIMIT: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub id: u64,
    pub body: T,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindMode {
    /// Case-insensitive substring of the file name.
    Name,
    /// Case-insensitive substring of the full path.
    Path,
    /// `*`, `?` and `[...]` against the file name (the full path when the
    /// pattern contains a `/`).
    Glob,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindQuery {
    pub pattern: String,
    pub mode: FindMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskRequest {
    /// Superblock facts: state, label, UUID.
    Probe,
    /// One page of a directory.
    List { path: String, offset: usize },
    /// Details of one entry; hashes a regular file when `hash_cap` allows.
    Info { path: String, hash_cap: u64 },
    /// Search the whole tree.
    Find { query: FindQuery },
    /// Write a regular file (or a link's target) to `/out/<request id>`,
    /// at most `max_len` bytes.
    Extract { path: String, max_len: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskEntryKind {
    Dir,
    File,
    Symlink,
    CharDev,
    BlockDev,
    Fifo,
    Socket,
}

impl DiskEntryKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dir => "Directory",
            Self::File => "File",
            Self::Symlink => "Symbolic link",
            Self::CharDev => "Character device",
            Self::BlockDev => "Block device",
            Self::Fifo => "FIFO",
            Self::Socket => "Socket",
        }
    }
}

/// One row of a listing, as the inode says (never followed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskEntry {
    /// The name as text; invalid UTF-8 is replaced and `addressable` is false.
    pub name: String,
    /// The name round-trips as a path component.
    pub addressable: bool,
    pub kind: DiskEntryKind,
    pub size: u64,
    /// Permission bits (`0o7777`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub atime: i64,
    pub ctime: i64,
    /// Where a symbolic link points; text, never resolved.
    pub link_target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskListing {
    pub path: String,
    pub offset: usize,
    pub entries: Vec<DiskEntry>,
    pub more: bool,
    /// The directory holds more entries than the reader lists.
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskFileInfo {
    pub path: String,
    pub entry: DiskEntry,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    /// Why the file was not hashed.
    pub hash_note: Option<String>,
    /// The file starts with the ELF magic.
    pub elf: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskImageInfo {
    pub fs_state: Ext4State,
    pub label: String,
    pub uuid: String,
    pub image_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundEntry {
    pub path: String,
    pub kind: DiskEntryKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindResults {
    pub query: FindQuery,
    pub matches: Vec<FoundEntry>,
    /// More matches exist than the limit returned.
    pub truncated: bool,
    /// The time budget ended the search.
    pub timed_out: bool,
    pub scanned: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractReceipt {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskAnswer {
    Probed(DiskImageInfo),
    Listed(DiskListing),
    Info(DiskFileInfo),
    Found(FindResults),
    Extracted(ExtractReceipt),
}

/// Typed so the UI can tell "unsupported feature" from "damaged image" from
/// "read error".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadError {
    Unsupported(String),
    Corrupt(String),
    NotFound,
    Io(String),
    Limit(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(reason) => write!(formatter, "unsupported filesystem: {reason}"),
            Self::Corrupt(reason) => write!(formatter, "damaged filesystem: {reason}"),
            Self::NotFound => formatter.write_str("not found in the image"),
            Self::Io(reason) => write!(formatter, "read error: {reason}"),
            Self::Limit(reason) => write!(formatter, "limit reached: {reason}"),
        }
    }
}

pub type Reply = Result<DiskAnswer, ReadError>;
