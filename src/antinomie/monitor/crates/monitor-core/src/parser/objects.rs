// SPDX-License-Identifier: MIT
//! How the assembler stores and re-reads field chunks: the packed object
//! store for new archives, and either layout when replaying a saved one.
use crate::{
    archive_io,
    object_pack::{self, FieldKey, PackWriter, PutError},
};
use std::{
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

/// Location recorded for a chunk of a one-file-per-field archive.
pub(super) const LEGACY: u64 = u64::MAX;

pub(super) enum StoreError {
    Quota,
    Failed(String),
}

/// Store the chunk of a live assembler, or check a chunk of a saved archive
/// against what it holds. Returns the bytes it added to the disk (none when
/// checking a saved archive).
pub(super) fn store(
    pack: &mut Option<PackWriter>,
    directory: &Path,
    key: &FieldKey,
    number: &mut Option<u32>,
    offset: u64,
    data: &[u8],
    budget: u64,
) -> Result<u64, StoreError> {
    match pack {
        Some(pack) => pack
            .put(key, number, offset, data, budget)
            .map(|placed| placed.added)
            .map_err(|error| match error {
                PutError::Quota => StoreError::Quota,
                PutError::Failed(error) => StoreError::Failed(error),
            }),
        None => match verify(directory, key, offset, data) {
            Ok(Some(_)) => Ok(0),
            Ok(None) => Err(StoreError::Failed(
                "archived field differs from raw packet".into(),
            )),
            Err(error) => Err(StoreError::Failed(error.to_string())),
        },
    }
}

/// A saved archive's copy of the chunk at `offset` must equal `data`:
/// its location, or `None` when the stored bytes differ.
fn verify(directory: &Path, key: &FieldKey, offset: u64, data: &[u8]) -> io::Result<Option<u64>> {
    if let Some((len, location)) = object_pack::lookup(directory, key, offset)? {
        if len as usize != data.len() {
            return Ok(None);
        }
        let stored = object_pack::read_at(directory, location, data.len())?;
        return Ok((stored == data).then_some(location.0));
    }
    let mut file = archive_io::open_regular(directory, &directory.join(key.file_name()))?;
    let mut stored = vec![0; data.len()];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut stored)?;
    Ok((stored == data).then_some(LEGACY))
}

#[cfg(test)]
mod tests;
