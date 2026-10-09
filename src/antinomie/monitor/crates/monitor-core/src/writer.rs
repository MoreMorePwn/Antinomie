//! Disk writes for recordings, off the transport thread.
//!
//! Raw packet blocks and object chunks are queued here and written by one
//! background thread in submission order. A busy disk (writeback throttling,
//! journal commits) then delays this thread instead of the telemetry drain.
//! The queue holds at most [`QUEUE_LIMIT`] bytes; past that, submitting
//! waits, so a disk that stays slower than the guest still pushes back.
//! Write errors land in the submitter's [`ErrorSlot`]; [`barrier`] waits
//! until everything submitted before it is on disk (not synced).
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, OnceLock},
    thread,
};

/// Bytes the queue may hold before submitters wait.
const QUEUE_LIMIT: usize = 256 * 1024 * 1024;
/// Object files kept open between chunks; an object's chunks usually arrive
/// together.
const OPEN_OBJECTS: usize = 64;

/// The first write error of one raw capture or assembler.
pub(crate) type ErrorSlot = Arc<Mutex<Option<String>>>;

pub(crate) fn error_slot() -> ErrorSlot {
    Arc::new(Mutex::new(None))
}

pub(crate) fn error_of(slot: &ErrorSlot) -> Option<String> {
    slot.lock().ok().and_then(|error| error.clone())
}

fn fail(slot: &ErrorSlot, error: String) {
    if let Ok(mut current) = slot.lock() {
        current.get_or_insert(error);
    }
}

pub(crate) enum Op {
    /// Append to an open raw file; on failure cut it back to `rollback`.
    Append {
        file: Arc<File>,
        data: Vec<u8>,
        rollback: u64,
        error: ErrorSlot,
    },
    /// Write an object chunk at `offset`, creating the file (mode 0600).
    Object {
        path: PathBuf,
        offset: u64,
        data: Vec<u8>,
        error: ErrorSlot,
    },
}
impl Op {
    fn len(&self) -> usize {
        match self {
            Op::Append { data, .. } | Op::Object { data, .. } => data.len(),
        }
    }
}

#[derive(Default)]
struct State {
    ops: VecDeque<Op>,
    bytes: usize,
    submitted: u64,
    done: u64,
}

struct Writer {
    state: Mutex<State>,
    /// Signalled when work arrives, and when work completes.
    changed: Condvar,
}

fn writer() -> &'static Writer {
    static WRITER: OnceLock<&'static Writer> = OnceLock::new();
    WRITER.get_or_init(|| {
        let writer: &'static Writer = Box::leak(Box::new(Writer {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
        }));
        thread::Builder::new()
            .name("antinomie-writer".into())
            .spawn(move || run(writer))
            .expect("start the recording writer thread");
        writer
    })
}

fn run(writer: &'static Writer) {
    let mut open: VecDeque<(PathBuf, File)> = VecDeque::new();
    loop {
        let op = {
            let mut state = writer.state.lock().unwrap_or_else(|e| e.into_inner());
            while state.ops.is_empty() {
                state = writer
                    .changed
                    .wait(state)
                    .unwrap_or_else(|e| e.into_inner());
            }
            state.ops.pop_front().expect("queue is not empty")
        };
        let len = op.len();
        match op {
            Op::Append {
                file,
                data,
                rollback,
                error,
            } => {
                if error_of(&error).is_none()
                    && let Err(e) = (&*file).write_all(&data)
                {
                    let _ = file.set_len(rollback);
                    fail(&error, format!("capture write failed: {e}"));
                }
            }
            Op::Object {
                path,
                offset,
                data,
                error,
            } => {
                if error_of(&error).is_none()
                    && let Err(e) = write_object(&mut open, path, offset, &data)
                {
                    fail(&error, format!("host object persistence: {e}"));
                }
            }
        }
        let mut state = writer.state.lock().unwrap_or_else(|e| e.into_inner());
        state.bytes -= len;
        state.done += 1;
        writer.changed.notify_all();
    }
}

fn write_object(
    open: &mut VecDeque<(PathBuf, File)>,
    path: PathBuf,
    offset: u64,
    data: &[u8],
) -> std::io::Result<()> {
    match open.iter().position(|(known, _)| *known == path) {
        Some(at) => {
            let entry = open.remove(at).expect("position is in range");
            open.push_front(entry);
        }
        None => {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&path)?;
            open.truncate(OPEN_OBJECTS - 1);
            open.push_front((path, file));
        }
    }
    open[0].1.write_all_at(data, offset)
}

/// Wait on the writer, sending transport heartbeats meanwhile so a guest in
/// never-drop mode keeps waiting for a host that is only busy with its disk.
fn wait_while<'a>(
    writer: &'static Writer,
    mut state: std::sync::MutexGuard<'a, State>,
    mut busy: impl FnMut(&State) -> bool,
) -> std::sync::MutexGuard<'a, State> {
    while busy(&state) {
        let (next, timeout) = writer
            .changed
            .wait_timeout(state, std::time::Duration::from_millis(50))
            .unwrap_or_else(|e| e.into_inner());
        state = next;
        if timeout.timed_out() {
            drop(state);
            crate::transport::heartbeat_on_this_thread();
            state = writer.state.lock().unwrap_or_else(|e| e.into_inner());
        }
    }
    state
}

/// Queue a write; waits while the queue is full.
pub(crate) fn submit(op: Op) {
    let writer = writer();
    let len = op.len();
    let state = writer.state.lock().unwrap_or_else(|e| e.into_inner());
    let mut state = wait_while(writer, state, |state| {
        state.bytes > 0 && state.bytes + len > QUEUE_LIMIT
    });
    state.bytes += len;
    state.submitted += 1;
    state.ops.push_back(op);
    writer.changed.notify_all();
}

/// Wait until every write submitted so far has been written.
pub fn barrier() {
    let writer = writer();
    let state = writer.state.lock().unwrap_or_else(|e| e.into_inner());
    let target = state.submitted;
    drop(wait_while(writer, state, |state| state.done < target));
}

/// Bytes queued and not yet written.
pub fn backlog() -> usize {
    writer()
        .state
        .lock()
        .map(|state| state.bytes)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_and_objects_land_in_order_and_errors_are_reported() {
        let root = std::env::temp_dir().join(format!("ant-writer-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&root).unwrap();
        let raw = Arc::new(File::create(root.join("raw")).unwrap());
        let slot = error_slot();
        for part in [&b"one"[..], b"two"] {
            submit(Op::Append {
                file: raw.clone(),
                data: part.to_vec(),
                rollback: 0,
                error: slot.clone(),
            });
        }
        for (offset, part) in [(3, &b"def"[..]), (0, b"abc")] {
            submit(Op::Object {
                path: root.join("object"),
                offset,
                data: part.to_vec(),
                error: slot.clone(),
            });
        }
        let bad = error_slot();
        submit(Op::Object {
            path: root.join("missing/object"),
            offset: 0,
            data: b"x".to_vec(),
            error: bad.clone(),
        });
        barrier();
        assert_eq!(std::fs::read(root.join("raw")).unwrap(), b"onetwo");
        assert_eq!(std::fs::read(root.join("object")).unwrap(), b"abcdef");
        assert!(error_of(&slot).is_none());
        assert!(error_of(&bad).is_some_and(|e| e.contains("host object persistence")));
        std::fs::remove_dir_all(root).unwrap();
    }
}
