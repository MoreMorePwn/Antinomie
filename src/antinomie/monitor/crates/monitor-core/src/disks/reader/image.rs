// SPDX-License-Identifier: GPL-3.0-only
//! The filesystem side of the reader: answers [`DiskRequest`]s from an ext4
//! image with the `ext4-view` crate. This runs inside the sandbox of the
//! `--disk-reader` worker, but is plain code that unit tests call directly.
//!
//! Guest paths are labels: nothing here resolves a guest link against the
//! host, symbolic links are reported (target as text) and never followed, and
//! the only host path written is `<out>/<request id>`.
use super::protocol::*;
use super::{content, diff, glob};
use crate::disks::{Ext4State, read_state};
use ext4_view::{DirEntry, Ext4, Ext4Error, FileType, Metadata};
use md5::Md5;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Bytes read from a guest file at a time.
const CHUNK: usize = 64 * 1024;

pub(super) fn map_error(error: Ext4Error) -> ReadError {
    match error {
        Ext4Error::NotFound => ReadError::NotFound,
        Ext4Error::Incompatible(reason) => ReadError::Unsupported(reason.to_string()),
        Ext4Error::Encrypted => ReadError::Unsupported("encrypted files".into()),
        Ext4Error::Corrupt(reason) => ReadError::Corrupt(reason.to_string()),
        Ext4Error::Io(reason) => ReadError::Io(reason.to_string()),
        Ext4Error::FileTooLarge => ReadError::Limit("file too large".into()),
        other => ReadError::Io(other.to_string()),
    }
}

pub(super) fn kind_of(kind: FileType) -> DiskEntryKind {
    match kind {
        FileType::Regular => DiskEntryKind::File,
        FileType::Directory => DiskEntryKind::Dir,
        FileType::Symlink => DiskEntryKind::Symlink,
        FileType::CharacterDevice => DiskEntryKind::CharDev,
        FileType::BlockDevice => DiskEntryKind::BlockDev,
        FileType::Fifo => DiskEntryKind::Fifo,
        FileType::Socket => DiskEntryKind::Socket,
    }
}

/// The filesystem of a raw ext4 image or of a standalone qcow2 image (an
/// installed base), read through the qcow2 tables without converting it.
fn load(image: &Path, lower: &[PathBuf]) -> Result<Ext4, ReadError> {
    Ext4::load(raw_disk(image, lower)?).map_err(map_error)
}

/// The bytes of the disk `image` shows, with the layers `lower` below it (a
/// qcow2 chain, top first after `image`) when there are any.
pub(super) fn raw_disk(
    image: &Path,
    lower: &[PathBuf],
) -> Result<Box<dyn ext4_view::Ext4Read>, ReadError> {
    let io = |error: std::io::Error| ReadError::Io(error.to_string());
    let mut file = std::fs::File::open(image).map_err(io)?;
    let mut magic = [0u8; 4];
    let qcow2 =
        std::io::Read::read_exact(&mut file, &mut magic).is_ok() && super::qcow2::is_qcow2(&magic);
    if !qcow2 {
        if !lower.is_empty() {
            return Err(ReadError::Unsupported(
                "a raw image has no layers below it".into(),
            ));
        }
        return Ok(Box::new(file));
    }
    if lower.is_empty() {
        return super::qcow2::Qcow2::open(file)
            .map(|disk| Box::new(disk) as Box<dyn ext4_view::Ext4Read>)
            .map_err(ReadError::Unsupported);
    }
    let mut layers = vec![file];
    for path in lower {
        layers.push(std::fs::File::open(path).map_err(io)?);
    }
    super::qcow2::Qcow2::open_chain(layers)
        .map(|disk| Box::new(disk) as Box<dyn ext4_view::Ext4Read>)
        .map_err(ReadError::Unsupported)
}

/// An opened image: the filesystem, or why it cannot be read (every request
/// then answers with that error).
pub struct Image {
    fs: Result<Ext4, ReadError>,
    /// The reference image of a diff (`/other`), when one is mounted.
    other: Option<Result<Ext4, ReadError>>,
    image: PathBuf,
    /// The layers below `image` of a qcow2 chain (the run's starting disk).
    lower: Vec<PathBuf>,
    out: PathBuf,
}

impl Image {
    pub fn open(image: &Path, out: &Path) -> Self {
        Self::open_with(image, None, out)
    }

    /// [`Self::open`] with a reference image to diff against.
    pub fn open_with(image: &Path, other: Option<&Path>, out: &Path) -> Self {
        Self {
            fs: load(image, &[]),
            other: other.map(|other| load(other, &[])),
            image: image.to_path_buf(),
            lower: Vec::new(),
            out: out.to_path_buf(),
        }
    }

    /// The disk a qcow2 chain shows: `image` on top, `lower` below it.
    pub fn open_chain(image: &Path, lower: &[PathBuf], out: &Path) -> Self {
        Self {
            fs: load(image, lower),
            other: None,
            image: image.to_path_buf(),
            lower: lower.to_vec(),
            out: out.to_path_buf(),
        }
    }

    pub fn handle(&self, id: u64, request: DiskRequest) -> Reply {
        let fs = self.fs.as_ref().map_err(Clone::clone)?;
        match request {
            DiskRequest::Probe => self.probe(fs).map(DiskAnswer::Probed),
            DiskRequest::List { path, offset } => list(fs, &path, offset).map(DiskAnswer::Listed),
            DiskRequest::Info { path, hash_cap } => info(fs, &path, hash_cap).map(DiskAnswer::Info),
            DiskRequest::Find { query } => {
                find(fs, query, content::Limits::default()).map(DiskAnswer::Found)
            }
            DiskRequest::Diff => {
                let before = match &self.other {
                    Some(other) => other
                        .as_ref()
                        .map_err(|error| ReadError::Io(format!("the reference image: {error}")))?,
                    None => return Err(ReadError::Io("no reference image is mounted".into())),
                };
                Ok(DiskAnswer::Diffed(diff::diff(
                    before,
                    fs,
                    diff::Limits::default(),
                )))
            }
            DiskRequest::Locate {
                path,
                ino,
                generation,
            } => self
                .locate(fs, &path, ino, generation)
                .map(DiskAnswer::Located),
            DiskRequest::ReadRange { path, offset, len } => {
                read_range(fs, &path, offset, len, &self.out.join(id.to_string()))
                    .map(DiskAnswer::Ranged)
            }
            DiskRequest::Extract { path, max_len } => {
                extract(fs, &path, max_len, &self.out.join(id.to_string()))
                    .map(DiskAnswer::Extracted)
            }
        }
    }

    /// A search with smaller bounds (tests).
    #[cfg(test)]
    pub(super) fn find_limited(
        &self,
        query: FindQuery,
        limits: content::Limits,
    ) -> Result<FindResults, ReadError> {
        find(self.fs.as_ref().map_err(Clone::clone)?, query, limits)
    }

    /// A comparison with smaller bounds (tests).
    #[cfg(test)]
    pub(super) fn diff_limited(&self, limits: diff::Limits) -> Result<DiffResults, ReadError> {
        let before = self
            .other
            .as_ref()
            .ok_or(ReadError::Io("no reference image".into()))?
            .as_ref()
            .map_err(Clone::clone)?;
        Ok(diff::diff(
            before,
            self.fs.as_ref().map_err(Clone::clone)?,
            limits,
        ))
    }

    /// Whether the regular file at `path` is the inode `ino` of generation
    /// `generation`, read raw from the disk (see [`super::inode`]).
    fn locate(
        &self,
        fs: &Ext4,
        path: &str,
        ino: Option<u64>,
        generation: Option<u32>,
    ) -> Result<DiskLocation, ReadError> {
        let path = checked_path(fs, path, Leaf::Any)?;
        let metadata = fs.symlink_metadata(path.as_str()).map_err(map_error)?;
        let located = |size, matched| DiskLocation {
            path: path.clone(),
            size,
            matched,
        };
        let different = |why: &str| {
            Ok(located(
                metadata.len(),
                LocationMatch::Different(why.to_owned()),
            ))
        };
        if metadata.file_type() != FileType::Regular {
            return different("the path is not a regular file on the starting disk");
        }
        let Some(ino) = ino else {
            return Ok(located(metadata.len(), LocationMatch::PathOnly));
        };
        let mut disk = raw_disk(&self.image, &self.lower)?;
        let raw = match super::inode::read_inode(disk.as_mut(), ino) {
            Ok(raw) => raw,
            Err(reason) => return different(&format!("the inode could not be read: {reason}")),
        };
        if raw.links == 0 || raw.mode & 0o170_000 != 0o100_000 {
            return different("that inode is not a file in use on the starting disk");
        }
        if generation.is_some_and(|generation| generation != raw.generation) {
            return different("that inode number held another file on the starting disk");
        }
        let same = raw.size == metadata.len()
            && u32::from(raw.mode & 0o7777) == u32::from(metadata.mode())
            && raw.uid == metadata.uid()
            && raw.gid == metadata.gid()
            && i64::from(raw.mtime) == metadata.modified().seconds() & 0xffff_ffff;
        if !same {
            return different("the path led to a different file on the starting disk");
        }
        Ok(located(metadata.len(), LocationMatch::Inode))
    }

    fn probe(&self, fs: &Ext4) -> Result<DiskImageInfo, ReadError> {
        Ok(DiskImageInfo {
            fs_state: read_state(&self.image).unwrap_or(Ext4State::Unknown),
            label: fs.label().display().to_string(),
            uuid: fs.uuid().to_string(),
            image_size: std::fs::metadata(&self.image).map_or(0, |metadata| metadata.len()),
        })
    }
}

/// What the leaf of a path must be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Leaf {
    Directory,
    Any,
}

/// A normalized absolute guest path whose parents are all real directories:
/// a path through a symbolic link is refused, not followed.
fn checked_path(fs: &Ext4, path: &str, leaf: Leaf) -> Result<String, ReadError> {
    if path.len() > PATH_LIMIT || path.contains('\0') || !path.starts_with('/') {
        return Err(ReadError::Io("not an absolute guest path".into()));
    }
    let mut normalized = String::new();
    for component in path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
    {
        if component == ".." {
            return Err(ReadError::Io("`..` is not accepted in a guest path".into()));
        }
        let parent = if normalized.is_empty() {
            "/"
        } else {
            &normalized
        };
        if !fs.symlink_metadata(parent).map_err(map_error)?.is_dir() {
            return Err(ReadError::Io(
                "the path crosses a symbolic link or a non-directory; links are never followed"
                    .into(),
            ));
        }
        normalized.push('/');
        normalized.push_str(component);
    }
    if normalized.is_empty() {
        normalized.push('/');
    }
    if leaf == Leaf::Directory {
        let metadata = fs.symlink_metadata(&normalized).map_err(map_error)?;
        if !metadata.is_dir() {
            return Err(ReadError::Io("not a directory".into()));
        }
    }
    Ok(normalized)
}

pub(super) fn entry_of(name: &[u8], metadata: &Metadata, link_target: Option<String>) -> DiskEntry {
    let kind = kind_of(metadata.file_type());
    DiskEntry {
        name: String::from_utf8_lossy(name).into_owned(),
        addressable: std::str::from_utf8(name).is_ok_and(|name| !name.contains(['/', '\0'])),
        kind,
        size: if matches!(kind, DiskEntryKind::File | DiskEntryKind::Symlink) {
            metadata.len()
        } else {
            0
        },
        mode: u32::from(metadata.mode()),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mtime: metadata.modified().seconds(),
        atime: metadata.accessed().seconds(),
        ctime: metadata.created().map_or(0, |time| time.seconds()),
        link_target,
    }
}

pub(super) fn link_target(fs: &Ext4, path: &ext4_view::PathBuf) -> Option<String> {
    fs.read_link(path)
        .ok()
        .map(|target| String::from_utf8_lossy(target.as_ref()).into_owned())
}

pub(super) fn is_dot(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

/// One page of a directory: directories first, then by name.
fn list(fs: &Ext4, path: &str, offset: usize) -> Result<DiskListing, ReadError> {
    let path = checked_path(fs, path, Leaf::Directory)?;
    let mut truncated = false;
    let mut names: Vec<(bool, Vec<u8>, DirEntry)> = Vec::new();
    for entry in fs.read_dir(path.as_str()).map_err(map_error)? {
        let entry = entry.map_err(map_error)?;
        let name = entry.file_name().as_ref().to_vec();
        if is_dot(&name) {
            continue;
        }
        if names.len() >= DIRECTORY_ENTRY_LIMIT {
            truncated = true;
            break;
        }
        let directory = entry.file_type().is_ok_and(FileType::is_dir);
        names.push((directory, name, entry));
    }
    names.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let more = names.len() > offset.saturating_add(PAGE_LEN);
    let mut entries = Vec::new();
    for (_, name, entry) in names.iter().skip(offset).take(PAGE_LEN) {
        let metadata = entry.metadata().map_err(map_error)?;
        let target = metadata
            .is_symlink()
            .then(|| link_target(fs, &entry.path()))
            .flatten();
        entries.push(entry_of(name, &metadata, target));
    }
    Ok(DiskListing {
        path,
        offset,
        entries,
        more,
        truncated,
    })
}

fn leaf_name(path: &str) -> &[u8] {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or("/")
        .as_bytes()
}

fn info(fs: &Ext4, path: &str, hash_cap: u64) -> Result<DiskFileInfo, ReadError> {
    let path = checked_path(fs, path, Leaf::Any)?;
    let metadata = fs.symlink_metadata(path.as_str()).map_err(map_error)?;
    let target = metadata
        .is_symlink()
        .then(|| {
            ext4_view::PathBuf::try_from(path.as_str())
                .ok()
                .and_then(|path| link_target(fs, &path))
        })
        .flatten();
    let entry = entry_of(leaf_name(&path), &metadata, target);
    let mut details = DiskFileInfo {
        path: path.clone(),
        entry,
        sha256: None,
        md5: None,
        hash_note: None,
        elf: false,
    };
    if metadata.file_type() != FileType::Regular {
        return Ok(details);
    }
    // A file whose block map is damaged (or absurd) is still described.
    let mut file = match fs.open(path.as_str()) {
        Ok(file) => file,
        Err(error) => {
            details.hash_note = Some(format!("not hashed: {}", map_error(error)));
            return Ok(details);
        }
    };
    let mut magic = [0u8; 4];
    details.elf = file.read_bytes(&mut magic).is_ok_and(|count| count == 4) && &magic == b"\x7fELF";
    if metadata.len() > hash_cap {
        details.hash_note = Some(format!(
            "not hashed: {} bytes exceed the {hash_cap}-byte limit",
            metadata.len()
        ));
        return Ok(details);
    }
    file.seek_to(0).map_err(map_error)?;
    let (mut sha, mut md5) = (Sha256::new(), Md5::new());
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let count = file.read_bytes(&mut buffer).map_err(map_error)?;
        if count == 0 {
            break;
        }
        sha.update(&buffer[..count]);
        md5.update(&buffer[..count]);
    }
    details.sha256 = Some(format!("{:x}", sha.finalize()));
    details.md5 = Some(format!("{:x}", md5.finalize()));
    Ok(details)
}

/// Write `len` bytes of the regular file at `path`, from `offset`, to `target`
/// (created exclusively, mode 0600). Fewer are written at the end of the file.
fn read_range(
    fs: &Ext4,
    path: &str,
    offset: u64,
    len: u64,
    target: &Path,
) -> Result<RangeReceipt, ReadError> {
    if len > RANGE_LIMIT {
        return Err(ReadError::Limit(format!(
            "a range read gives at most {RANGE_LIMIT} bytes"
        )));
    }
    let path = checked_path(fs, path, Leaf::Any)?;
    let metadata = fs.symlink_metadata(path.as_str()).map_err(map_error)?;
    if metadata.file_type() != FileType::Regular {
        return Err(ReadError::Io("only regular files can be read".into()));
    }
    let io = |error: std::io::Error| ReadError::Io(error.to_string());
    let mut file = fs.open(path.as_str()).map_err(map_error)?;
    file.seek_to(offset.min(metadata.len()))
        .map_err(map_error)?;
    let want = usize::try_from(len.min(metadata.len().saturating_sub(offset))).unwrap_or(0);
    let mut data = vec![0u8; want];
    let mut filled = 0;
    while filled < want {
        let count = file.read_bytes(&mut data[filled..]).map_err(map_error)?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    data.truncate(filled);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)
        .map_err(io)?;
    if let Err(error) = output.write_all(&data).and_then(|()| output.sync_all()) {
        drop(output);
        let _ = std::fs::remove_file(target);
        return Err(io(error));
    }
    Ok(RangeReceipt {
        len: data.len() as u64,
    })
}

/// Write a regular file, or a link's target as text, to `target` (created
/// exclusively, mode 0600, never executable). The partial file is removed on
/// failure.
fn extract(
    fs: &Ext4,
    path: &str,
    max_len: u64,
    target: &Path,
) -> Result<ExtractReceipt, ReadError> {
    let path = checked_path(fs, path, Leaf::Any)?;
    let metadata = fs.symlink_metadata(path.as_str()).map_err(map_error)?;
    let io = |error: std::io::Error| ReadError::Io(error.to_string());
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)
        .map_err(io)?;
    let result = (|| -> Result<ExtractReceipt, ReadError> {
        let mut sha = Sha256::new();
        let mut size = 0u64;
        match metadata.file_type() {
            FileType::Regular => {
                if metadata.len() > max_len {
                    return Err(ReadError::Limit(format!(
                        "the file is {} bytes; the extraction limit is {max_len} bytes",
                        metadata.len()
                    )));
                }
                let mut file = fs.open(path.as_str()).map_err(map_error)?;
                let mut buffer = vec![0u8; CHUNK];
                loop {
                    let count = file.read_bytes(&mut buffer).map_err(map_error)?;
                    if count == 0 {
                        break;
                    }
                    size += count as u64;
                    if size > max_len {
                        return Err(ReadError::Limit("the file grew past the limit".into()));
                    }
                    sha.update(&buffer[..count]);
                    output.write_all(&buffer[..count]).map_err(io)?;
                }
            }
            FileType::Symlink => {
                let link =
                    ext4_view::PathBuf::try_from(path.as_str()).map_err(|_| ReadError::NotFound)?;
                let text = fs.read_link(&link).map_err(map_error)?;
                sha.update(text.as_ref());
                output.write_all(text.as_ref()).map_err(io)?;
                size = text.as_ref().len() as u64;
            }
            _ => {
                return Err(ReadError::Io(
                    "only regular files and link targets can be extracted".into(),
                ));
            }
        }
        output.sync_all().map_err(io)?;
        Ok(ExtractReceipt {
            path: path.clone(),
            size,
            sha256: format!("{:x}", sha.finalize()),
        })
    })();
    if result.is_err() {
        drop(output);
        let _ = std::fs::remove_file(target);
    }
    result
}

/// Walk the tree from `/`, bounded by matches, entries, depth and time.
/// Symbolic links are listed, never descended. A content search also reads
/// regular files, bounded per file, in total and by time.
fn find(fs: &Ext4, query: FindQuery, limits: content::Limits) -> Result<FindResults, ReadError> {
    let content = query.mode.is_content();
    let needle = if content {
        let bytes = query.pattern.as_bytes();
        if !(CONTENT_NEEDLE_MIN..=CONTENT_NEEDLE_MAX).contains(&bytes.len()) {
            return Err(ReadError::Limit(format!(
                "the text to search for must be {CONTENT_NEEDLE_MIN} to {CONTENT_NEEDLE_MAX} bytes"
            )));
        }
        if query.mode == FindMode::ContentAnyCase {
            bytes.to_ascii_lowercase()
        } else {
            bytes.to_vec()
        }
    } else {
        query.pattern.to_lowercase().into_bytes()
    };
    let any_case = query.mode == FindMode::ContentAnyCase;
    let lowered = String::from_utf8_lossy(&needle).into_owned();
    let seconds = limits.seconds.unwrap_or(if content {
        CONTENT_SECONDS
    } else {
        FIND_SECONDS
    });
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut budget = content::Budget::new(deadline, limits);
    let mut results = FindResults {
        query: query.clone(),
        matches: Vec::new(),
        truncated: false,
        timed_out: false,
        scanned: 0,
        files_read: 0,
        bytes_read: 0,
        partial_files: 0,
        byte_limit_reached: false,
    };
    let Ok(root) = ext4_view::PathBuf::try_from("/") else {
        return Ok(results);
    };
    let mut stack = vec![(root, 0usize)];
    'walk: while let Some((directory, depth)) = stack.pop() {
        let Ok(entries) = fs.read_dir(&directory) else {
            continue;
        };
        let mut children = Vec::new();
        for (index, entry) in entries.enumerate() {
            let Ok(entry) = entry else {
                continue;
            };
            if index >= DIRECTORY_ENTRY_LIMIT {
                break;
            }
            let name = entry.file_name().as_ref().to_vec();
            if is_dot(&name) {
                continue;
            }
            results.scanned += 1;
            if results.scanned > FIND_SCAN_LIMIT as u64 {
                results.truncated = true;
                break 'walk;
            }
            if results.scanned.is_multiple_of(256) && Instant::now() >= deadline {
                results.timed_out = true;
                break 'walk;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let full = entry.path();
            let full_text = String::from_utf8_lossy(full.as_ref()).into_owned();
            let name_text = String::from_utf8_lossy(&name).into_owned();
            let mut found = None;
            let hit = match query.mode {
                FindMode::Name => name_text.to_lowercase().contains(&lowered),
                FindMode::Path => full_text.to_lowercase().contains(&lowered),
                FindMode::Glob if query.pattern.contains('/') => {
                    glob::matches(&query.pattern, &full_text)
                }
                FindMode::Glob => glob::matches(&query.pattern, &name_text),
                FindMode::Content | FindMode::ContentAnyCase => {
                    if kind == FileType::Regular {
                        found = content::search_file(fs, &full, &needle, any_case, &mut budget);
                        if budget.timed_out {
                            results.timed_out = true;
                            break 'walk;
                        }
                        if budget.byte_limit {
                            results.byte_limit_reached = true;
                            break 'walk;
                        }
                    }
                    found.is_some()
                }
            };
            if hit {
                if results.matches.len() >= FIND_MATCH_LIMIT {
                    results.truncated = true;
                    break 'walk;
                }
                let mut path = full_text;
                path.truncate(PATH_LIMIT);
                let (offset, snippet) =
                    found.map_or((None, None), |hit| (Some(hit.offset), Some(hit.snippet)));
                results.matches.push(FoundEntry {
                    path,
                    kind: kind_of(kind),
                    offset,
                    snippet,
                });
            }
            if kind.is_dir() && depth < FIND_DEPTH_LIMIT {
                children.push((full, depth + 1));
            }
        }
        // Visit in name order: the stack pops the last pushed first.
        children.sort_by(|a, b| b.0.as_ref().cmp(a.0.as_ref()));
        stack.extend(children);
    }
    results.files_read = budget.files_read;
    results.bytes_read = budget.bytes_read;
    results.partial_files = budget.partial_files;
    Ok(results)
}
