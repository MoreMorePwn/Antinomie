// SPDX-License-Identifier: MIT
//! Packed object store: captured buffers of one archive in a few append-only
//! files instead of one file per buffer.
//!
//! A heavy run captures more than a hundred thousand buffers ("fields") of
//! a few dozen bytes. One file each cost hundreds of megabytes of disk for
//! a few megabytes of payload and a create storm that kept the journal busy.
//! An archive's `objects/` directory now holds
//!
//! | File | Content |
//! | --- | --- |
//! | `objects-NNNNNN.seg` | Segments of at most [`SEGMENT_SIZE`] bytes: chunk payloads, back to back, never rewritten. |
//! | `objects.idx` | Append-only index: a 16 byte header, then field and chunk records (see [`index`]). |
//!
//! Chunks keep their identity: a field is named by the same
//! `stream-task-call-phase-seq-object.raw` string the one-file layout used
//! (`FieldSummary::raw_path` still ends in it), so readers keep working from
//! a field summary alone. A reader first looks for that file (archives made
//! before packing) and otherwise resolves the name through the index.
//!
//! Identical chunks are stored once: a chunk whose SHA-256 matches one stored
//! earlier in the same archive (and still remembered, see [`DEDUP_ENTRIES`])
//! only adds an index record that points at the earlier bytes.
//!
//! [`PackWriter`] hands its buffered bytes to the recording writer thread,
//! which writes them in submission order, payload before the index records
//! that name it. [`PackWriter::sync`] makes the files durable.
mod index;

pub(crate) use index::{ChunkLocation, lookup, read_at, read_field_range};

use crate::writer::{self, ErrorSlot, Op};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Most bytes in one segment file; a chunk never spans two.
pub(crate) const SEGMENT_SIZE: u64 = 64 * 1024 * 1024;
/// Buffered payload or index bytes that are handed to the writer thread.
const FLUSH_SIZE: usize = 256 * 1024;
/// Chunk contents remembered for deduplication; later new contents are stored
/// without being remembered.
const DEDUP_ENTRIES: usize = 65_536;

/// Index file name inside an archive's `objects/` directory.
pub(crate) const INDEX_FILE: &str = "objects.idx";
const MAGIC: &[u8; 8] = b"ANTOBJ01";
const VERSION: u32 = 1;
pub(crate) const HEADER_SIZE: u64 = 16;
const FIELD_TAG: u8 = 1;
const CHUNK_TAG: u8 = 2;
/// Bytes of the record that declares a field.
pub(crate) const FIELD_RECORD_SIZE: u64 = 42;
/// Bytes of the record that places one chunk.
pub(crate) const CHUNK_RECORD_SIZE: u64 = 25;

/// Compact content fingerprint retained for duplicate transport chunks.
pub(crate) fn chunk_fingerprint(data: &[u8]) -> [u8; 16] {
    chunk_hash(data)
}

pub(crate) fn segment_name(segment: u32) -> String {
    format!("objects-{segment:06}.seg")
}

/// A captured buffer's identity within one archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FieldKey {
    pub stream: u64,
    pub task: u64,
    pub call: u64,
    pub phase: u8,
    pub seq: u64,
    pub object: u32,
}

impl FieldKey {
    /// The name a field has always had, whether or not a file carries it.
    pub fn file_name(&self) -> String {
        format!(
            "{}-{}-{}-{}-{}-{}.raw",
            self.stream, self.task, self.call, self.phase, self.seq, self.object
        )
    }
    pub fn parse(name: &str) -> Option<Self> {
        let mut parts = name.strip_suffix(".raw")?.split('-');
        let key = Self {
            stream: parts.next()?.parse().ok()?,
            task: parts.next()?.parse().ok()?,
            call: parts.next()?.parse().ok()?,
            phase: parts.next()?.parse().ok()?,
            seq: parts.next()?.parse().ok()?,
            object: parts.next()?.parse().ok()?,
        };
        parts.next().is_none().then_some(key)
    }
}

/// Why [`PackWriter::put`] stored nothing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PutError {
    /// Storing the chunk would pass the byte budget.
    Quota,
    Failed(String),
}

/// Where [`PackWriter::put`] placed a chunk and what that added to the disk.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Placed {
    pub location: ChunkLocation,
    /// Bytes this chunk added: payload (none when deduplicated) and records.
    pub added: u64,
}

struct Segment {
    number: u32,
    file: Arc<File>,
    /// Bytes handed out in this segment, buffered or written.
    len: u64,
}

/// Appends chunks to an archive's segments and index.
pub(crate) struct PackWriter {
    directory: PathBuf,
    error: ErrorSlot,
    segment: Option<Segment>,
    /// Segment bytes not yet handed to the writer thread, and where they go.
    buffer: Vec<u8>,
    buffer_offset: u64,
    /// Finished segments, kept to be synced.
    closed: Vec<Arc<File>>,
    next_segment: u32,
    index: Option<Arc<File>>,
    index_buffer: Vec<u8>,
    /// File offset the next index byte is written at.
    index_offset: u64,
    next_field: u32,
    segment_size: u64,
    seen: HashMap<[u8; 16], (ChunkLocation, u32)>,
    ticket: u64,
}

impl PackWriter {
    /// A writer for the (existing) directory `objects`; no file is created
    /// until the first chunk. Write errors of the writer thread land in `error`.
    pub fn new(objects: PathBuf, error: ErrorSlot) -> Self {
        Self {
            directory: objects,
            error,
            segment: None,
            buffer: Vec::new(),
            buffer_offset: 0,
            closed: Vec::new(),
            next_segment: 0,
            index: None,
            index_buffer: Vec::new(),
            index_offset: 0,
            next_field: 0,
            segment_size: SEGMENT_SIZE,
            seen: HashMap::new(),
            ticket: 0,
        }
    }

    #[cfg(test)]
    pub fn set_segment_size(&mut self, size: u64) {
        self.segment_size = size;
    }

    /// Store `data` as the chunk of `key` at `object_offset`. `field` is the
    /// key's number once it has one; a field is declared with its first chunk.
    /// Adds at most `budget` bytes to the disk, else stores nothing.
    pub fn put(
        &mut self,
        key: &FieldKey,
        field: &mut Option<u32>,
        object_offset: u64,
        data: &[u8],
        budget: u64,
    ) -> Result<Placed, PutError> {
        if data.len() > index::MAX_CHUNK_SIZE as usize || data.len() as u64 > self.segment_size {
            return Err(PutError::Failed("object chunk exceeds its bound".into()));
        }
        let hash = chunk_hash(data);
        let known = self
            .seen
            .get(&hash)
            .filter(|(_, len)| *len as usize == data.len())
            .map(|(location, _)| *location);
        let records = CHUNK_RECORD_SIZE
            + if field.is_none() {
                FIELD_RECORD_SIZE
            } else {
                0
            }
            + if self.index.is_none() { HEADER_SIZE } else { 0 };
        let cost = records
            + if known.is_some() {
                0
            } else {
                data.len() as u64
            };
        if cost > budget {
            return Err(PutError::Quota);
        }
        let index_growth = (if self.index.is_none() { HEADER_SIZE } else { 0 })
            + CHUNK_RECORD_SIZE
            + if field.is_none() {
                FIELD_RECORD_SIZE
            } else {
                0
            };
        let payload_growth = if known.is_some() { 0 } else { data.len() };
        if self.buffer.len().saturating_add(payload_growth) >= FLUSH_SIZE
            || self
                .index_buffer
                .len()
                .saturating_add(index_growth as usize)
                >= FLUSH_SIZE
        {
            self.flush().map_err(PutError::Failed)?;
        }
        if self.index.is_none() {
            self.create_index().map_err(PutError::Failed)?;
        }
        let location = match known {
            Some(location) => location,
            None if data.is_empty() => ChunkLocation::new(0, 0),
            None => {
                let location = self.append(data).map_err(PutError::Failed)?;
                if self.seen.len() < DEDUP_ENTRIES {
                    self.seen.insert(hash, (location, data.len() as u32));
                }
                location
            }
        };
        if data.is_empty() && self.seen.len() < DEDUP_ENTRIES {
            self.seen.insert(hash, (location, 0));
        }
        let number = *field.get_or_insert_with(|| {
            let number = self.next_field;
            self.next_field += 1;
            self.index_buffer.push(FIELD_TAG);
            self.index_buffer.extend(number.to_le_bytes());
            self.index_buffer.extend(key.stream.to_le_bytes());
            self.index_buffer.extend(key.task.to_le_bytes());
            self.index_buffer.extend(key.call.to_le_bytes());
            self.index_buffer.extend(key.seq.to_le_bytes());
            self.index_buffer.push(key.phase);
            self.index_buffer.extend(key.object.to_le_bytes());
            number
        });
        self.index_buffer.push(CHUNK_TAG);
        self.index_buffer.extend(number.to_le_bytes());
        self.index_buffer.extend(object_offset.to_le_bytes());
        self.index_buffer.extend((data.len() as u32).to_le_bytes());
        self.index_buffer.extend(location.0.to_le_bytes());
        Ok(Placed {
            location,
            added: cost,
        })
    }

    fn create_index(&mut self) -> Result<(), String> {
        let file = create(&self.directory.join(INDEX_FILE))?;
        self.index_buffer.extend(MAGIC);
        self.index_buffer.extend(VERSION.to_le_bytes());
        self.index_buffer.extend(0u32.to_le_bytes());
        self.index = Some(Arc::new(file));
        Ok(())
    }

    /// Place `data` at the end of the current segment (rolling to a new one
    /// when it does not fit) and buffer it.
    fn append(&mut self, data: &[u8]) -> Result<ChunkLocation, String> {
        if self
            .segment
            .as_ref()
            .is_some_and(|segment| segment.len + data.len() as u64 > self.segment_size)
        {
            self.flush()
                .map_err(|error| format!("object writer queue: {error}"))?;
            if let Some(full) = self.segment.take() {
                self.closed.push(full.file);
            }
        }
        if self.segment.is_none() {
            let number = self.next_segment;
            let file = create(&self.directory.join(segment_name(number)))?;
            self.next_segment += 1;
            self.segment = Some(Segment {
                number,
                file: Arc::new(file),
                len: 0,
            });
            self.buffer_offset = 0;
        }
        let segment = self.segment.as_mut().expect("segment was just opened");
        let location = ChunkLocation::new(segment.number, segment.len);
        segment.len += data.len() as u64;
        self.buffer.extend_from_slice(data);
        Ok(location)
    }

    /// Hand buffered data to the writer thread without waiting for queue room.
    /// What the full queue cannot take yet stays buffered for the next flush
    /// (the transport owner stops taking telemetry meanwhile).
    pub fn flush(&mut self) -> Result<(), String> {
        self.flush_with(false)
    }

    /// Finalization runs off the transport owner, so it may wait for queue room.
    fn flush_blocking(&mut self) -> Result<(), String> {
        self.flush_with(true)
    }

    fn flush_with(&mut self, blocking: bool) -> Result<(), String> {
        if !self.buffer.is_empty()
            && let Some(segment) = &self.segment
        {
            let data = std::mem::take(&mut self.buffer);
            let len = data.len() as u64;
            let op = Op::WriteAt {
                file: segment.file.clone(),
                offset: self.buffer_offset,
                data,
                error: self.error.clone(),
            };
            let submitted = if blocking {
                Ok(writer::submit(op))
            } else {
                writer::try_submit(op)
            };
            match submitted {
                Ok(ticket) => {
                    self.ticket = ticket;
                    self.buffer_offset += len;
                }
                Err(Op::WriteAt { data, .. }) => {
                    self.buffer = data;
                    return Ok(());
                }
                Err(Op::Append { .. }) => unreachable!("object write operation"),
            }
        }
        if !self.index_buffer.is_empty()
            && let Some(index) = &self.index
        {
            let data = std::mem::take(&mut self.index_buffer);
            let len = data.len() as u64;
            let op = Op::WriteAt {
                file: index.clone(),
                offset: self.index_offset,
                data,
                error: self.error.clone(),
            };
            let submitted = if blocking {
                Ok(writer::submit(op))
            } else {
                writer::try_submit(op)
            };
            match submitted {
                Ok(ticket) => {
                    self.ticket = ticket;
                    self.index_offset += len;
                }
                Err(Op::WriteAt { data, .. }) => {
                    self.index_buffer = data;
                    return Ok(());
                }
                Err(Op::Append { .. }) => unreachable!("object write operation"),
            }
        }
        Ok(())
    }

    /// Wait until everything stored so far is written (not synced).
    pub fn settle(&mut self) {
        let _ = self.flush_blocking();
        writer::wait_for(self.ticket);
    }

    /// Make everything stored so far durable: files, then the directory entries.
    pub fn sync(&mut self) -> Result<(), String> {
        self.settle();
        if let Some(error) = writer::error_of(&self.error) {
            return Err(error);
        }
        let files = self
            .closed
            .iter()
            .chain(self.segment.as_ref().map(|segment| &segment.file))
            .chain(self.index.as_ref());
        for file in files {
            file.sync_all()
                .map_err(|error| format!("object store sync failed: {error}"))?;
        }
        self.closed.clear();
        if self.index.is_some() {
            File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("object store directory sync failed: {error}"))?;
        }
        Ok(())
    }

    /// Whether `data` is the chunk stored at `location`, when that can be told
    /// without reading the disk.
    #[cfg(test)]
    pub fn remembers(&self, location: ChunkLocation, data: &[u8]) -> bool {
        self.seen
            .get(&chunk_hash(data))
            .is_some_and(|(known, len)| *known == location && *len as usize == data.len())
    }
}

impl Drop for PackWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn chunk_hash(data: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(data);
    let mut hash = [0; 16];
    hash.copy_from_slice(&digest[..16]);
    hash
}

fn create(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("host object persistence: {}: {error}", path.display()))
}

#[cfg(test)]
mod tests;
