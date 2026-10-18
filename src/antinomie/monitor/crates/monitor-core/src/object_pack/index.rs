// SPDX-License-Identifier: MIT
//! Reading the packed object store: the index and the segments it names.
//!
//! `objects.idx` is retained as the evidence source. A private, disposable
//! SQLite database indexes it incrementally so field/chunk metadata does not
//! grow with the size of a recording in host memory.
mod cache;
#[cfg(test)]
mod tests;

use super::segment_name;
use rusqlite::{OptionalExtension, params};
use std::{io, os::unix::fs::FileExt, path::Path};

/// Largest packed chunk payload allowed by the pinned telemetry message bound.
pub(crate) const MAX_CHUNK_SIZE: u32 = 262_112;

/// Where a chunk's bytes are: segment number and offset in that segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ChunkLocation(pub u64);

impl ChunkLocation {
    pub fn new(segment: u32, offset: u64) -> Self {
        Self(u64::from(segment) << 32 | offset)
    }
    fn segment(self) -> u32 {
        (self.0 >> 32) as u32
    }
    fn offset(self) -> u64 {
        self.0 & 0xffff_ffff
    }
}

/// Maximum number of stored chunks examined for one bounded range read.
const MAX_RANGE_CHUNKS: usize = 4096;
/// Segment files are bounded by the writer's fixed segment size.
const MAX_SEGMENT_SIZE: u64 = 64 * 1024 * 1024;

fn reader_limit(message: &'static str) -> io::Error {
    if message.contains("cache") {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("packed-object index cache data: {message}"),
        )
    } else {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }
}

fn encode_key(key: &super::FieldKey) -> [u8; 37] {
    let mut bytes = [0; 37];
    bytes[0..8].copy_from_slice(&key.stream.to_be_bytes());
    bytes[8..16].copy_from_slice(&key.task.to_be_bytes());
    bytes[16..24].copy_from_slice(&key.call.to_be_bytes());
    bytes[24..32].copy_from_slice(&key.seq.to_be_bytes());
    bytes[32] = key.phase;
    bytes[33..37].copy_from_slice(&key.object.to_be_bytes());
    bytes
}

fn decode_u64_blob(bytes: &[u8], label: &'static str) -> io::Result<u64> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| reader_limit(label))?;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_location(bytes: &[u8]) -> io::Result<ChunkLocation> {
    decode_u64_blob(bytes, "invalid packed-object location in cache").map(ChunkLocation)
}

/// The chunk of `key` stored at exactly `offset`: its length and location.
pub(crate) fn lookup(
    objects: &Path,
    key: &super::FieldKey,
    offset: u64,
) -> io::Result<Option<(u32, ChunkLocation)>> {
    Ok(cache::with_index(objects, |connection| {
        let offset_blob = offset.to_be_bytes();
        let mut statement = connection
            .prepare_cached("SELECT size, location FROM chunks WHERE key=?1 AND object_offset=?2")
            .map_err(cache::sql_error)?;
        let found: Option<(i64, Vec<u8>)> = statement
            .query_row(
                params![encode_key(key).as_slice(), offset_blob.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(cache::sql_error)?;
        found
            .map(|(size, location)| {
                let size = u32::try_from(size)
                    .map_err(|_| reader_limit("invalid packed-object chunk length in cache"))?;
                if size > MAX_CHUNK_SIZE {
                    return Err(reader_limit("packed-object chunk exceeds its wire bound"));
                }
                offset
                    .checked_add(u64::from(size))
                    .ok_or_else(|| reader_limit("object field extent overflows"))?;
                let location = decode_location(&location)?;
                validate_location(location, u64::from(size))?;
                Ok((size, location))
            })
            .transpose()
    })?
    .flatten())
}

/// `len` bytes at `location` in the segments of `objects`.
pub(crate) fn read_at(objects: &Path, location: ChunkLocation, len: usize) -> io::Result<Vec<u8>> {
    let len_u64 = u64::try_from(len).map_err(|_| reader_limit("object read length overflows"))?;
    validate_location(location, len_u64)?;
    if len == 0 {
        return Ok(Vec::new());
    }
    let file =
        crate::archive_io::open_regular(objects, Path::new(&segment_name(location.segment())))?;
    let mut data = vec![0; len];
    file.read_exact_at(&mut data, location.offset())?;
    Ok(data)
}

fn validate_location(location: ChunkLocation, len: u64) -> io::Result<()> {
    let end = location
        .offset()
        .checked_add(len)
        .ok_or_else(|| reader_limit("object read extent overflows"))?;
    if len > u64::from(MAX_CHUNK_SIZE) || end > MAX_SEGMENT_SIZE {
        return Err(reader_limit("object read exceeds its segment bounds"));
    }
    Ok(())
}

struct Chunk {
    start: u64,
    size: u32,
    location: ChunkLocation,
}

fn chunk_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Vec<u8>, i64, Vec<u8>)> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
}

fn decode_chunk(row: (Vec<u8>, i64, Vec<u8>)) -> io::Result<Chunk> {
    let (start, size, location) = row;
    let start = decode_u64_blob(&start, "invalid packed-object offset in cache")?;
    let size = u32::try_from(size)
        .map_err(|_| reader_limit("invalid packed-object chunk length in cache"))?;
    if size > MAX_CHUNK_SIZE {
        return Err(reader_limit("packed-object chunk exceeds its wire bound"));
    }
    let location = decode_location(&location)?;
    validate_location(location, u64::from(size))?;
    start
        .checked_add(u64::from(size))
        .ok_or_else(|| reader_limit("object field extent overflows"))?;
    Ok(Chunk {
        start,
        size,
        location,
    })
}

fn copy_chunk(
    objects: &Path,
    chunk: Chunk,
    offset: u64,
    end: u64,
    data: &mut [u8],
    covered: &mut u64,
) -> io::Result<bool> {
    let chunk_end = chunk
        .start
        .checked_add(u64::from(chunk.size))
        .ok_or_else(|| reader_limit("object field extent overflows"))?;
    if chunk.size == 0 || chunk_end <= *covered {
        return Ok(true);
    }
    let from = (*covered).max(chunk.start);
    if from != *covered {
        return Ok(false);
    }
    let to = end.min(chunk_end);
    if to <= from {
        return Ok(true);
    }
    let part_offset = from - chunk.start;
    let part_len =
        usize::try_from(to - from).map_err(|_| reader_limit("object read length overflows"))?;
    let location_offset = chunk
        .location
        .offset()
        .checked_add(part_offset)
        .ok_or_else(|| reader_limit("object read offset overflows"))?;
    let location = ChunkLocation((u64::from(chunk.location.segment()) << 32) | location_offset);
    let part = read_at(objects, location, part_len)?;
    let data_start = usize::try_from(from - offset)
        .map_err(|_| reader_limit("object result offset overflows"))?;
    let data_end = data_start
        .checked_add(part_len)
        .ok_or_else(|| reader_limit("object result extent overflows"))?;
    data.get_mut(data_start..data_end)
        .ok_or_else(|| reader_limit("object result exceeds the requested range"))?
        .copy_from_slice(&part);
    *covered = to;
    Ok(true)
}

/// `len` bytes of field `key` from `offset`, when the archive's index holds
/// the field: `Ok(None)` means it does not, and the caller should look for the
/// one-file-per-field layout. Bytes the index does not cover are an error.
pub(crate) fn read_field_range(
    objects: &Path,
    key: &super::FieldKey,
    offset: u64,
    len: usize,
) -> io::Result<Option<Vec<u8>>> {
    if len > 65_536 {
        return Err(reader_limit(
            "read at most 65536 packed object bytes at a time",
        ));
    }
    let len_u64 = u64::try_from(len).map_err(|_| reader_limit("object range length overflows"))?;
    let end = offset
        .checked_add(len_u64)
        .ok_or_else(|| reader_limit("object range extent overflows"))?;
    Ok(cache::with_index(objects, |connection| {
        let key = encode_key(key);
        let mut presence_statement = connection
            .prepare_cached("SELECT EXISTS(SELECT 1 FROM chunks WHERE key=?1)")
            .map_err(cache::sql_error)?;
        let present: bool = presence_statement
            .query_row(params![key.as_slice()], |row| row.get(0))
            .map_err(cache::sql_error)?;
        if !present {
            return Ok(None);
        }
        if len == 0 {
            return Ok(Some(Vec::new()));
        }
        let mut data = vec![0; len];
        let mut covered = offset;
        let mut count = 0_usize;
        let before = offset.to_be_bytes();
        let mut previous_statement = connection
            .prepare_cached(
                "SELECT object_offset, size, location FROM chunks \
                 WHERE key=?1 AND size > 0 AND object_offset < ?2 \
                 ORDER BY object_offset DESC LIMIT 1",
            )
            .map_err(cache::sql_error)?;
        let previous: Option<(Vec<u8>, i64, Vec<u8>)> = previous_statement
            .query_row(params![key.as_slice(), before.as_slice()], chunk_from_row)
            .optional()
            .map_err(cache::sql_error)?;
        if let Some(row) = previous {
            let chunk = decode_chunk(row)?;
            let chunk_end = chunk
                .start
                .checked_add(u64::from(chunk.size))
                .ok_or_else(|| reader_limit("object field extent overflows"))?;
            if chunk.size > 0 && chunk_end > offset {
                count += 1;
                copy_chunk(objects, chunk, offset, end, &mut data, &mut covered)?;
            }
        }
        let after = end.to_be_bytes();
        let mut statement = connection
            .prepare_cached(
                "SELECT object_offset, size, location FROM chunks \
                 WHERE key=?1 AND size > 0 AND object_offset >= ?2 AND object_offset < ?3 \
                 ORDER BY object_offset LIMIT ?4",
            )
            .map_err(cache::sql_error)?;
        let mut rows = statement
            .query(params![
                key.as_slice(),
                before.as_slice(),
                after.as_slice(),
                (MAX_RANGE_CHUNKS + 1) as i64,
            ])
            .map_err(cache::sql_error)?;
        while let Some(row) = rows.next().map_err(cache::sql_error)? {
            let chunk = decode_chunk(chunk_from_row(row).map_err(cache::sql_error)?)?;
            if chunk.size == 0 {
                continue;
            }
            if count == MAX_RANGE_CHUNKS {
                return Err(reader_limit("object range contains too many chunks"));
            }
            count += 1;
            if !copy_chunk(objects, chunk, offset, end, &mut data, &mut covered)? {
                break;
            }
        }
        if covered < end {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "object range is not stored",
            ));
        }
        Ok(Some(data))
    })?
    .flatten())
}
