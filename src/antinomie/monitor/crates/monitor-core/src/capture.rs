//! Persistent observation archives, independent of launched programs and PTYs.
use crate::{
    api::{BackendOptions, Health},
    archive_io,
    observation::{CaptureState, CaptureSummary},
    parser::Assembler,
    recording::RecordingError,
    storage::{self, RawCapture},
};
use std::fs;
use std::{path::Path, sync::atomic::AtomicBool};

pub(crate) struct CaptureSession {
    pub summary: CaptureSummary,
    pub capture: RawCapture,
    pub assembler: Assembler,
    pub stream_id: Option<u64>,
}

impl CaptureSession {
    pub fn new(summary: CaptureSummary, quota: u64) -> Result<Self, String> {
        let capture = RawCapture::new(summary.directory.clone(), quota)?;
        let assembler = Assembler::new(summary.directory.join("objects"), quota)
            .map_err(|error| error.to_string())?;
        let session = Self {
            summary,
            capture,
            assembler,
            stream_id: None,
        };
        session.persist_summary()?;
        Ok(session)
    }
    pub fn stored_len(&self) -> u64 {
        self.capture
            .bytes
            .saturating_add(self.assembler.stored_len())
    }
    pub fn observe_identity(&mut self, cookie: u64, stream_id: u64) -> Result<(), String> {
        if cookie == 0
            || stream_id == 0
            || (self.summary.capture_cookie != 0 && self.summary.capture_cookie != cookie)
            || self.stream_id.is_some_and(|known| known != stream_id)
        {
            return Err("capture packet conflicts with archive identity or stream".into());
        }
        self.summary.capture_cookie = cookie;
        self.stream_id = Some(stream_id);
        Ok(())
    }
    pub fn storage_error(&mut self, error: impl Into<String>) {
        let error = error.into();
        self.capture.error.get_or_insert(error.clone());
        self.summary.recording_error.get_or_insert(error);
        self.assembler.stop_saving();
    }
    pub fn persist_summary(&self) -> Result<(), String> {
        let summary =
            storage::queue_json(&self.summary.directory.join("capture.json"), &self.summary);
        let manifest = storage::queue_json(
            &self.summary.directory.join("manifest.json"),
            &self.manifest(None),
        );
        summary.and(manifest)
    }
    fn manifest(&self, health: Option<&Health>) -> serde_json::Value {
        serde_json::json!({
            "format": "ANTT observation raw LE32", "capture": self.summary,
            "stream_id": self.stream_id,
            "packets": self.capture.packets, "bytes": self.stored_len(),
            "persistence_error": self.summary.recording_error, "health": health,
            "quota_scope": "VM boot shared raw, fields, analysis and terminal artifacts",
            "complete": false,
            "tail_status": "stopping admission does not fence delivery; admitted observations may remain unresolved"
        })
    }
    pub fn finalize(&mut self, health: &Health) -> Result<(), String> {
        self.summary.state = CaptureState::Finalized;
        let sync = self.capture.sync();
        if let Err(error) = &sync {
            self.storage_error(error.clone());
        }
        storage::atomic_json(&self.summary.directory.join("capture.json"), &self.summary)?;
        storage::atomic_json(
            &self.summary.directory.join("manifest.json"),
            &self.manifest(Some(health)),
        )?;
        sync
    }
}

/// Read bounded observation history from all recording locations for one VM.
pub fn list_vm_captures(
    options: &BackendOptions,
    vm_id: &str,
) -> Result<Vec<CaptureSummary>, String> {
    list_vm_captures_inner(options, vm_id).map_err(|error| error.to_string())
}
fn list_vm_captures_inner(
    options: &BackendOptions,
    vm_id: &str,
) -> Result<Vec<CaptureSummary>, RecordingError> {
    let locations = crate::locations::locations(options, vm_id)
        .map_err(|error| RecordingError::Io(std::io::Error::other(error)))?;
    let mut captures = Vec::new();
    for directory in locations.recording_directories {
        if !directory.exists() {
            continue;
        }
        let root = fs::canonicalize(directory)?;
        let directory = root.join("captures");
        if !directory.exists() {
            continue;
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path().join("capture.json");
            if !path.exists() {
                continue;
            }
            let file = archive_io::open_regular(&root, &path)?;
            if file.metadata()?.len() > 1024 * 1024 {
                return Err(RecordingError::Limit(
                    "capture metadata exceeds reader limit",
                ));
            }
            let mut capture: CaptureSummary = serde_json::from_reader(file)?;
            if capture.vm_id != vm_id {
                continue;
            }
            capture.directory = entry.path();
            if capture.state == CaptureState::Active {
                capture.state = CaptureState::Unknown;
            }
            if !captures
                .iter()
                .any(|existing: &CaptureSummary| existing.id == capture.id)
            {
                captures.push(capture);
            }
            if captures.len() > 1024 {
                return Err(RecordingError::Limit(
                    "VM history exceeds 1024 captures; open archive directly",
                ));
            }
        }
    }
    captures.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(captures)
}

/// Validate observation archive identity before handing it to the generic reader.
pub fn open_capture_recording_cancellable(
    directory: &Path,
    cancel: &AtomicBool,
) -> Result<crate::recording::Recording, RecordingError> {
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(RecordingError::Limit("archive read cancelled"));
    }
    let root = fs::canonicalize(directory)?;
    let summary_file = archive_io::open_regular(&root, Path::new("capture.json"))?;
    if summary_file.metadata()?.len() > 1024 * 1024 {
        return Err(RecordingError::Limit(
            "capture metadata exceeds reader limit",
        ));
    }
    let summary: CaptureSummary = serde_json::from_reader(summary_file)?;
    let recording = crate::recording::open_recording_cancellable(&root, cancel)?;
    let embedded: CaptureSummary =
        serde_json::from_value(recording.manifest.get("capture").cloned().ok_or(
            RecordingError::Limit("capture manifest identity is missing"),
        )?)?;
    if summary.id != embedded.id
        || summary.vm_id != embedded.vm_id
        || summary.boot_id != embedded.boot_id
        || summary.capture_cookie != embedded.capture_cookie
        || summary.scope != embedded.scope
        || summary.id.is_empty()
        || summary.boot_id.is_empty()
    {
        return Err(RecordingError::Limit(
            "capture summary and manifest identities disagree",
        ));
    }
    Ok(recording)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::CaptureScope;
    fn summary(directory: std::path::PathBuf) -> CaptureSummary {
        CaptureSummary {
            id: "observer".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            capture_cookie: 17,
            scope: CaptureScope::AllUserspace,
            directory,
            state: CaptureState::Active,
            recording_error: None,
            start_ns: Some(10),
            stop_ns: None,
            incomplete_reason: Some("unresolved observations may remain".into()),
        }
    }
    fn packet(call: u64) -> Vec<u8> {
        let mut packet = vec![0; 264];
        packet[..4].copy_from_slice(b"ANTT");
        packet[4..6].copy_from_slice(&1u16.to_le_bytes());
        packet[6..8].copy_from_slice(&2u16.to_le_bytes());
        packet[8..10].copy_from_slice(&144u16.to_le_bytes());
        packet[10..12].copy_from_slice(&1u16.to_le_bytes());
        packet[12..16].copy_from_slice(&264u32.to_le_bytes());
        packet[20..24].copy_from_slice(&1u32.to_le_bytes());
        packet[24..32].copy_from_slice(&9u64.to_le_bytes());
        packet[32..40].copy_from_slice(&7u64.to_le_bytes());
        packet[40..48].copy_from_slice(&call.to_le_bytes());
        packet[48..56].copy_from_slice(&call.to_le_bytes());
        packet[56..64].copy_from_slice(&call.to_le_bytes());
        packet[96..98].copy_from_slice(&1u16.to_le_bytes());
        packet[98] = 1;
        packet[99] = 1;
        packet[120..124].copy_from_slice(&120u32.to_le_bytes());
        packet[128..136].copy_from_slice(&99u64.to_le_bytes());
        packet[136..144].copy_from_slice(&17u64.to_le_bytes());
        packet
    }
    #[test]
    fn stopped_archive_accepts_late_tails_without_terminal_or_fake_run() {
        let root = std::env::temp_dir().join(format!("ant-capture-tail-{}", storage::unique_id()));
        let mut capture = CaptureSession::new(summary(root.clone()), 65536).unwrap();
        capture.observe_identity(17, 9).unwrap();
        assert!(capture.observe_identity(18, 9).is_err());
        assert!(capture.observe_identity(17, 10).is_err());
        let first = packet(1);
        assert!(capture.capture.append_with_reserved(&first, 0));
        capture.assembler.ingest(&first).unwrap();
        capture.summary.state = CaptureState::Stopped;
        capture.summary.stop_ns = Some(20);
        capture.persist_summary().unwrap();
        let tail = packet(2);
        assert!(capture.capture.append_with_reserved(&tail, 0));
        capture.assembler.ingest(&tail).unwrap();
        capture.finalize(&Health::default()).unwrap();
        let recording = open_capture_recording_cancellable(&root, &AtomicBool::new(false)).unwrap();
        assert_eq!(recording.events.len(), 2);
        assert_eq!(recording.manifest["complete"], false);
        for name in [
            "run.json",
            "terminal.journal",
            "terminal-transcript.raw",
            "terminal-screen.ansi",
        ] {
            assert!(!root.join(name).exists());
        }
        let mut wrong = capture.summary.clone();
        wrong.capture_cookie = 18;
        storage::atomic_json(&root.join("capture.json"), &wrong).unwrap();
        assert!(open_capture_recording_cancellable(&root, &AtomicBool::new(false)).is_err());
        drop(capture);
        drop(recording);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn observer_copy_reserves_primary_storage_against_shared_quota() {
        let root = std::env::temp_dir().join(format!("ant-capture-quota-{}", storage::unique_id()));
        let mut primary = RawCapture::new(root.join("primary"), 600).unwrap();
        let mut observer = CaptureSession::new(summary(root.join("observer")), 600).unwrap();
        let packet = packet(1);
        assert!(primary.append_with_reserved(&packet, observer.stored_len()));
        assert!(
            observer
                .capture
                .append_with_reserved(&packet, primary.bytes)
        );
        assert_eq!(primary.bytes + observer.stored_len(), 536);
        assert!(
            !observer
                .capture
                .append_with_reserved(&packet, primary.bytes)
        );
        assert_eq!(observer.capture.bytes, 268);
        observer.storage_error(observer.capture.error.clone().unwrap());
        observer.finalize(&Health::default()).unwrap();
        assert!(
            fs::metadata(root.join("observer/telemetry.raw"))
                .unwrap()
                .len()
                <= 600
        );
        drop(primary);
        drop(observer);
        fs::remove_dir_all(root).unwrap();
    }
}
