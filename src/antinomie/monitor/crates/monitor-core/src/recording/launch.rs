// SPDX-License-Identifier: GPL-3.0-only
//! A run's launch: the records the guest wrote for the launched program before
//! its first traced call.
//!
//! The kernel starts the program itself, so its first exec is not a traced
//! call. The launch event (`lifecycle.launch` with `context.exec.path` and
//! `context.exec.argv[N]`), the exec commit and, from a guest asked for it,
//! the hash of the program's own image carry the root task's identity with
//! call id 0. No call owns them, so archive pages never show them; this reads
//! them by that identity.
use super::call_reader::CallReader;
use super::matching::indexed_boundary;
use super::*;

/// What a recording says about the launched program, outside any call.
#[derive(Clone, Debug, Default)]
pub struct LaunchRecord {
    pub pid: u32,
    pub tid: u32,
    /// Guest monotonic time of the launch event.
    pub timestamp_ns: u64,
    /// The program the kernel executed, as the launch named it.
    pub path: Option<String>,
    /// The argument vector, only when every element was recorded whole.
    pub argv: Option<Vec<String>>,
    /// Kernel notes of the launch (the hash of the program's own image), in
    /// event order.
    pub notes: Vec<EventSummary>,
}

/// A complete text field, without its terminating NUL.
fn whole_text(field: &FieldSummary) -> Option<String> {
    let logical = usize::try_from(field.logical_len?).ok()?;
    if !field.complete || field.preview.len() != logical {
        return None;
    }
    let text = field.preview.strip_suffix(b"\0").unwrap_or(&field.preview);
    String::from_utf8(text.to_vec()).ok()
}

/// Read the launch out of its events (see the module documentation).
pub(super) fn from_events(events: &[EventSummary]) -> Option<LaunchRecord> {
    let launch = events.iter().find(|event| {
        event
            .fields
            .iter()
            .any(|field| field.key == "lifecycle.launch")
    })?;
    let field = |key: &str| launch.fields.iter().find(|field| field.key == key);
    let mut argv = Vec::new();
    let mut whole = true;
    for index in 0.. {
        match field(&format!("context.exec.argv[{index}]")) {
            Some(element) => match whole_text(element) {
                Some(text) => argv.push(text),
                None => whole = false,
            },
            None => break,
        }
    }
    // The vector ends where the kernel stopped writing it: an event that lost
    // its last packets ends early, which an incomplete event says.
    let complete = whole && launch.complete && !argv.is_empty();
    Some(LaunchRecord {
        pid: launch.pid,
        tid: launch.tid,
        timestamp_ns: launch.timestamp_ns,
        path: field("context.exec.path").and_then(whole_text),
        argv: complete.then_some(argv),
        notes: events
            .iter()
            .filter(|event| crate::kernel_notes::is_note(event))
            .cloned()
            .collect(),
    })
}

impl Recording {
    /// The launch of the run whose root task is `root_cookie`, in the guest
    /// stream `stream_id` (the stream of the root's calls). `None` when the
    /// recording has no launch event for it, as for an observation capture.
    pub fn launch_record_cancellable(
        &self,
        stream_id: u64,
        root_cookie: u64,
        cancel: &AtomicBool,
    ) -> Result<Option<LaunchRecord>, RecordingError> {
        if cancel.load(Ordering::Relaxed) {
            return Err(RecordingError::Limit("archive read cancelled"));
        }
        let (connection, _) = archive_index(&self.directory, cancel)?;
        let boundary = indexed_boundary(&connection)?;
        let mut reader = CallReader::open(&self.directory, &connection, boundary)?;
        let events = reader.lifecycle(&key_blob((stream_id, root_cookie, 0)), cancel)?;
        Ok(from_events(&events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(key: &str, value: &[u8], complete: bool) -> FieldSummary {
        FieldSummary {
            arg: None,
            object_id: 1,
            key: key.into(),
            layout: String::new(),
            logical_len: Some(value.len() as u64),
            captured_len: value.len() as u64,
            status: Some(0),
            capture_error: 0,
            complete,
            preview: value.to_vec(),
            raw_path: None,
            ranges: Vec::new(),
            recapture: None,
            encoding: None,
        }
    }

    fn event(fields: Vec<FieldSummary>) -> EventSummary {
        EventSummary {
            root_task_cookie: 5,
            stream_id: 1,
            task_cookie: 5,
            call_id: 0,
            event_seq: 1,
            phase: 3,
            syscall_nr: u64::MAX,
            syscall_name: String::new(),
            pid: 7,
            tid: 7,
            cpu: 0,
            timestamp_ns: 42,
            args: None,
            result: None,
            complete: true,
            issues: Vec::new(),
            fields,
        }
    }

    #[test]
    fn the_launch_names_its_program_and_keeps_its_own_notes() {
        let launch = event(vec![
            field("lifecycle.launch", &5u64.to_le_bytes(), true),
            field("context.exec.path", b"/tmp/sample\0", true),
            field("context.exec.argv[0]", b"/tmp/sample\0", true),
            field("context.exec.argv[1]", b"-v\0", true),
        ]);
        let mut hash = event(vec![field(crate::kernel_notes::HASH_KEY, &[1; 80], true)]);
        hash.fields[0].layout = "antinomie.hash/1".into();
        let commit = event(vec![field(
            "lifecycle.exec_commit",
            &7u64.to_le_bytes(),
            true,
        )]);
        let record = from_events(&[launch.clone(), commit, hash]).unwrap();
        assert_eq!(record.path.as_deref(), Some("/tmp/sample"));
        assert_eq!(
            record.argv,
            Some(vec!["/tmp/sample".to_owned(), "-v".to_owned()])
        );
        assert_eq!((record.pid, record.timestamp_ns), (7, 42));
        assert_eq!(record.notes.len(), 1);
        assert_eq!(record.notes[0].fields[0].key, crate::kernel_notes::HASH_KEY);
        // An argument cut short leaves the command line unknown.
        let mut cut = launch.clone();
        cut.fields[3].complete = false;
        assert_eq!(from_events(&[cut]).unwrap().argv, None);
        let mut partial = launch;
        partial.complete = false;
        assert_eq!(from_events(&[partial]).unwrap().argv, None);
        // A key with no launch event has no record.
        assert!(from_events(&[]).is_none());
    }
}
