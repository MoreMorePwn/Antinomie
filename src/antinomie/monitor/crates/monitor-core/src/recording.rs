//! Reopen finalized captures and inspect only byte ranges known to be received.
use crate::api::{EventSummary, FieldSummary};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum RecordingError {
    Io(std::io::Error),
    Format(serde_json::Error),
    Limit(&'static str),
    MissingRange,
}
impl std::fmt::Display for RecordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "recording I/O: {e}"),
            Self::Format(e) => write!(f, "recording format: {e}"),
            Self::Limit(e) => f.write_str(e),
            Self::MissingRange => f.write_str("requested range includes missing capture bytes"),
        }
    }
}
impl std::error::Error for RecordingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Format(e) => Some(e),
            _ => None,
        }
    }
}
impl From<std::io::Error> for RecordingError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for RecordingError {
    fn from(e: serde_json::Error) -> Self {
        Self::Format(e)
    }
}

pub struct Recording {
    pub directory: PathBuf,
    pub manifest: serde_json::Value,
    pub events: Vec<EventSummary>,
}
pub fn open_recording(directory: &Path) -> Result<Recording, RecordingError> {
    let directory = fs::canonicalize(directory)?;
    let manifest_file = File::open(directory.join("manifest.json"))?;
    if manifest_file.metadata()?.len() > 1024 * 1024 {
        return Err(RecordingError::Limit("manifest exceeds reader limit"));
    }
    let manifest = serde_json::from_reader(manifest_file)?;
    let events_file = File::open(directory.join("events.json"))?;
    if events_file.metadata()?.len() > 64 * 1024 * 1024 {
        return Err(RecordingError::Limit(
            "event summaries exceed reader limit; raw archive retained",
        ));
    }
    let events: Vec<EventSummary> = serde_json::from_reader(events_file)?;
    if events.len() > 2112
        || events.iter().any(|e| {
            e.fields.len() > 256
                || e.fields
                    .iter()
                    .any(|f| f.preview.len() > 256 || f.ranges.len() > 4096)
        })
    {
        return Err(RecordingError::Limit(
            "recording exceeds parser state limits",
        ));
    }
    Ok(Recording {
        directory,
        manifest,
        events,
    })
}
pub fn read_captured_range(
    recording: &Path,
    field: &FieldSummary,
    offset: u64,
    data_len: usize,
) -> Result<Vec<u8>, RecordingError> {
    if data_len > 65536 {
        return Err(RecordingError::Limit(
            "read at most 65536 captured bytes at a time",
        ));
    }
    let end = offset
        .checked_add(data_len as u64)
        .ok_or(RecordingError::MissingRange)?;
    let mut covered = offset;
    for &(range_offset, range_len) in &field.ranges {
        let range_end = range_offset
            .checked_add(range_len)
            .ok_or(RecordingError::MissingRange)?;
        if range_offset <= covered && range_end > covered {
            covered = range_end;
        }
        if covered >= end {
            break;
        }
    }
    if covered < end {
        return Err(RecordingError::MissingRange);
    }
    let root = fs::canonicalize(recording.join("objects"))?;
    let path = fs::canonicalize(
        field
            .raw_path
            .as_ref()
            .ok_or(RecordingError::MissingRange)?,
    )?;
    if !path.starts_with(root) {
        return Err(RecordingError::Limit(
            "field path escapes recording objects",
        ));
    }
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0; data_len];
    file.read_exact(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_to_present_a_sparse_hole_as_captured() {
        let field = FieldSummary {
            object_id: 1,
            key: "arg1".into(),
            layout: String::new(),
            logical_len: Some(10),
            captured_len: 2,
            status: Some(0),
            capture_error: 0,
            complete: false,
            preview: vec![],
            raw_path: None,
            ranges: vec![(0, 2), (8, 2)],
        };
        assert!(matches!(
            read_captured_range(Path::new("/unused"), &field, 1, 8),
            Err(RecordingError::MissingRange)
        ));
    }
}
