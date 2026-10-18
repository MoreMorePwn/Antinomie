//! Disk writes for recordings, off the transport thread.
//!
//! Raw packet blocks and object chunks are queued here and written by one
//! background thread in submission order. A busy disk (writeback throttling,
//! journal commits) then delays this thread instead of the telemetry drain.
//! The queue holds at most [`QUEUE_LIMIT`] bytes; past that, submitting
//! waits, so a disk that stays slower than the guest still pushes back.
//! Write errors land in the submitter's [`ErrorSlot`]; [`barrier`] waits
//! until everything submitted before it is on disk (not synced), and
//! [`wait_for`] waits only for one submission (and so for those before it).
//!
//! Time a thread spends waiting here for queue room or a barrier is
//! counted per thread ([`blocked_on_this_thread`]), so a caller with a
//! deadline that is not about the disk (a guest shutdown) can leave that
//! time out.
use std::{
    collections::VecDeque,
    fs::File,
    io::Write,
    os::unix::fs::FileExt,
    sync::{Arc, Condvar, Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

/// Bytes the queue may hold before submitters wait.
const QUEUE_LIMIT: usize = 256 * 1024 * 1024;

/// The first write error of one raw capture or assembler.
pub(crate) type ErrorSlot = Arc<Mutex<Option<String>>>;

pub(crate) fn error_slot() -> ErrorSlot {
    Arc::new(Mutex::new(None))
}

pub(crate) fn error_of(slot: &ErrorSlot) -> Option<String> {
    slot.lock().ok().and_then(|error| error.clone())
}

#[cfg(test)]
pub(crate) fn fail_next_write_at() {
    writer()
        .fail_next_write_at
        .store(true, std::sync::atomic::Ordering::Release);
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
    /// Write `data` at `offset` of an open file (object segments and index).
    WriteAt {
        file: Arc<File>,
        offset: u64,
        data: Vec<u8>,
        error: ErrorSlot,
    },
}
impl Op {
    fn len(&self) -> usize {
        match self {
            Op::Append { data, .. } | Op::WriteAt { data, .. } => data.len(),
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
    limit: usize,
    /// Signalled when work arrives, and when work completes.
    changed: Condvar,
    /// Tests stop a private writer to stand in for a disk that does not answer.
    #[cfg(test)]
    paused: std::sync::atomic::AtomicBool,
    /// Tests fail the next positioned object write through the normal ErrorSlot path.
    #[cfg(test)]
    fail_next_write_at: std::sync::atomic::AtomicBool,
}

impl Writer {
    fn is_paused(&self) -> bool {
        #[cfg(test)]
        return self.paused.load(std::sync::atomic::Ordering::Acquire);
        #[cfg(not(test))]
        false
    }
}

fn start(name: &str) -> &'static Writer {
    start_with_limit(name, QUEUE_LIMIT)
}

fn start_with_limit(name: &str, limit: usize) -> &'static Writer {
    let writer: &'static Writer = Box::leak(Box::new(Writer {
        state: Mutex::new(State::default()),
        limit,
        changed: Condvar::new(),
        #[cfg(test)]
        paused: std::sync::atomic::AtomicBool::new(false),
        #[cfg(test)]
        fail_next_write_at: std::sync::atomic::AtomicBool::new(false),
    }));
    thread::Builder::new()
        .name(name.into())
        .spawn(move || run(writer))
        .expect("start the recording writer thread");
    writer
}

fn writer() -> &'static Writer {
    #[cfg(test)]
    if let Some(private) = held::private_writer() {
        return private;
    }
    static WRITER: OnceLock<&'static Writer> = OnceLock::new();
    WRITER.get_or_init(|| start("antinomie-writer"))
}

fn run(writer: &'static Writer) {
    loop {
        let op = {
            let mut state = writer.state.lock().unwrap_or_else(|e| e.into_inner());
            while state.ops.is_empty() || writer.is_paused() {
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
            Op::WriteAt {
                file,
                offset,
                data,
                error,
            } => {
                #[cfg(test)]
                let injected_failure = writer
                    .fail_next_write_at
                    .swap(false, std::sync::atomic::Ordering::AcqRel);
                #[cfg(not(test))]
                let injected_failure = false;
                if injected_failure {
                    fail(
                        &error,
                        "host object persistence: injected write failure".into(),
                    );
                } else if error_of(&error).is_none()
                    && let Err(e) = file.write_all_at(&data, offset)
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

thread_local! {
    static BLOCKED: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
}

/// Total time this thread has waited for the writer (queue room, barriers).
#[cfg(test)]
pub(crate) fn blocked_on_this_thread() -> Duration {
    BLOCKED.with(std::cell::Cell::get)
}

/// Wait on the writer, sending transport heartbeats meanwhile so a guest in
/// never-drop mode keeps waiting for a host that is only busy with its disk.
fn wait_while<'a>(
    writer: &'static Writer,
    mut state: std::sync::MutexGuard<'a, State>,
    mut busy: impl FnMut(&State) -> bool,
) -> std::sync::MutexGuard<'a, State> {
    if !busy(&state) {
        return state;
    }
    let started = Instant::now();
    while busy(&state) {
        let (next, timeout) = writer
            .changed
            .wait_timeout(state, Duration::from_millis(50))
            .unwrap_or_else(|e| e.into_inner());
        state = next;
        if timeout.timed_out() {
            drop(state);
            crate::transport::heartbeat_on_this_thread();
            state = writer.state.lock().unwrap_or_else(|e| e.into_inner());
        }
    }
    BLOCKED.with(|blocked| blocked.set(blocked.get() + started.elapsed()));
    state
}

/// Queue a write; waits while the queue is full. Use this only from a
/// finalizer, never from the transport owner. The result is the write's ticket
/// for [`wait_for`]; tickets increase in submission order.
pub(crate) fn submit(op: Op) -> u64 {
    let writer = writer();
    let len = op.len();
    assert!(
        len <= writer.limit,
        "recording write exceeds the queue byte limit"
    );
    let state = writer.state.lock().unwrap_or_else(|e| e.into_inner());
    let mut state = wait_while(writer, state, |state| {
        state.bytes > 0
            && state
                .bytes
                .checked_add(len)
                .is_none_or(|total| total > writer.limit)
    });
    state.bytes += len;
    state.submitted += 1;
    state.ops.push_back(op);
    writer.changed.notify_all();
    state.submitted
}

/// Try to queue a write without waiting. `Err(op)` means the bounded queue has
/// no room; the caller still owns the unchanged operation and must retain it
/// or report that persistence stopped. A single operation may not exceed the
/// queue's byte limit.
pub(crate) fn try_submit(op: Op) -> Result<u64, Op> {
    let writer = writer();
    let len = op.len();
    let mut state = writer.state.lock().unwrap_or_else(|e| e.into_inner());
    if len > writer.limit
        || state
            .bytes
            .checked_add(len)
            .is_none_or(|total| total > writer.limit)
    {
        return Err(op);
    }
    state.bytes += len;
    state.submitted += 1;
    state.ops.push_back(op);
    writer.changed.notify_all();
    Ok(state.submitted)
}

/// Wait until every write submitted so far has been written.
pub fn barrier() {
    let writer = writer();
    let state = writer.state.lock().unwrap_or_else(|e| e.into_inner());
    let target = state.submitted;
    drop(wait_while(writer, state, |state| state.done < target));
}

/// Wait until the write with `ticket` (a [`submit`] result) and every write
/// before it has been written. Ticket 0, "nothing submitted", returns at once,
/// so a recording that wrote nothing never waits for other recordings' data.
pub(crate) fn wait_for(ticket: u64) {
    if ticket == 0 {
        return;
    }
    let writer = writer();
    let state = writer.state.lock().unwrap_or_else(|e| e.into_inner());
    drop(wait_while(writer, state, |state| state.done < ticket));
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
pub(crate) mod held;
#[cfg(test)]
mod tests;
