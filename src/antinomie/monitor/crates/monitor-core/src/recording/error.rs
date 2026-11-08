// SPDX-License-Identifier: GPL-3.0-only
//! What reading a recording can fail with.

#[derive(Debug)]
pub enum RecordingError {
    Io(std::io::Error),
    Format(serde_json::Error),
    Limit(&'static str),
    MissingRange,
    Index(rusqlite::Error),
}
impl std::fmt::Display for RecordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "recording I/O: {e}"),
            Self::Format(e) => write!(f, "recording format: {e}"),
            Self::Limit(e) => f.write_str(e),
            Self::MissingRange => f.write_str("requested range includes missing capture bytes"),
            Self::Index(e) => write!(f, "archive index: {e}; saved raw archive retained"),
        }
    }
}
impl std::error::Error for RecordingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Format(e) => Some(e),
            Self::Index(e) => Some(e),
            _ => None,
        }
    }
}
impl From<rusqlite::Error> for RecordingError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Index(e)
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
