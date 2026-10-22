// SPDX-License-Identifier: GPL-3.0-only
//! The persistence thread for small status files (`run.json`, `artifacts.json`,
//! manifests, ...).
//!
//! Publishing one is `write`, `fsync`, `rename`, `fsync` of the directory. On
//! a disk the recording writer keeps busy, that `fsync` waits for the
//! filesystem journal behind all the dirty recording data and takes seconds to
//! a minute, so the thread that drains telemetry and answers commands never
//! does it: it queues the file here and goes on.
//!
//! Guarantees:
//!
//! | Rule | How |
//! | --- | --- |
//! | A later value is never overwritten by an earlier one | One value is pending per path and a newer one replaces it; a write in progress finishes first; a synchronous write to the path drops the pending value and waits for the one in progress. |
//! | Files are published in the order they were last queued | The queue is FIFO by the time of each path's latest queueing, not sorted by path. |
//! | A file is never published before its directory exists | Callers create directories themselves (no `fsync`, cheap) before queueing into them; a missing directory is a write failure reported with the path, never an implicit `mkdir`. |
//! | A failure is not lost | It is returned by the next queueing for the same path, and through the receipt of an observed write. |
//! | A final value is durable on return | `atomic_json` and `flush_json` are the synchronous points: finalization (off the transport thread) and shutdown use them. |
//!
//! Durability of a queued value is therefore "published within the disk's
//! latency", not "on disk when the call returns".
use super::*;
use std::{
    cell::Cell,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_PENDING_PATHS: usize = 4096;
const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_TRACKED_PATH_BYTES: usize = 4096;

thread_local! {
    static TRANSPORT_THREAD: Cell<bool> = const { Cell::new(false) };
}
static TRANSPORT_SYNC_WRITES: AtomicU64 = AtomicU64::new(0);

/// The calling thread is the one that drains telemetry and serves commands.
/// Synchronous (`fsync`ing) publications on it are counted, so a test can
/// prove a code path keeps its disk waits off that thread.
pub(crate) fn mark_transport_thread() {
    TRANSPORT_THREAD.with(|flag| flag.set(true));
}

/// Publications that waited for the disk on a thread marked as the transport thread.
#[cfg(test)]
pub(crate) fn transport_sync_writes() -> u64 {
    TRANSPORT_SYNC_WRITES.load(Ordering::Relaxed)
}

pub(super) fn note_sync_write() {
    if TRANSPORT_THREAD.with(Cell::get) {
        TRANSPORT_SYNC_WRITES.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct JsonQueue {
    /// Each pending path with its latest value and its place in `order`.
    pending: std::collections::BTreeMap<PathBuf, (u64, Vec<u8>)>,
    pending_bytes: usize,
    /// Pending paths by when they were last queued.
    order: std::collections::BTreeMap<u64, PathBuf>,
    next_order: u64,
    /// Tests stop a private queue to stand in for a disk that does not answer.
    #[cfg(test)]
    paused: bool,
    /// Tests read the order in which paths were published.
    #[cfg(test)]
    published: Vec<PathBuf>,
    writing: Option<PathBuf>,
    writing_bytes: usize,
    errors: std::collections::BTreeMap<PathBuf, String>,
    observed:
        std::collections::BTreeMap<PathBuf, std::sync::Weak<std::sync::Mutex<JsonWriteStatus>>>,
}
impl JsonQueue {
    /// Replace the pending value of `path`; it now waits behind the others.
    fn insert_pending(&mut self, path: PathBuf, bytes: Vec<u8>) -> Result<(), String> {
        if bytes.len() > MAX_JSON_BYTES {
            return Err(format!("queued JSON exceeds {MAX_JSON_BYTES} bytes"));
        }
        if path.as_os_str().as_bytes().len() > MAX_TRACKED_PATH_BYTES {
            return Err("queued JSON path exceeds the writer limit".into());
        }
        let old_len = self.pending.get(&path).map_or(0, |(_, old)| old.len());
        let new_pending_path = usize::from(!self.pending.contains_key(&path));
        let tracked = self
            .pending
            .len()
            .saturating_add(self.errors.len())
            .saturating_add(usize::from(self.writing.is_some()));
        let replaces_error = usize::from(self.errors.contains_key(&path));
        if tracked
            .saturating_add(new_pending_path)
            .saturating_sub(replaces_error)
            > MAX_PENDING_PATHS
        {
            return Err("queued JSON path and failure limit reached".into());
        }
        if self.pending.len().saturating_add(new_pending_path) > MAX_PENDING_PATHS {
            return Err("queued JSON path limit reached".into());
        }
        if self
            .pending_bytes
            .saturating_sub(old_len)
            .saturating_add(bytes.len())
            .saturating_add(self.writing_bytes)
            > MAX_PENDING_BYTES
        {
            return Err("queued JSON byte limit reached".into());
        }
        if self.next_order == u64::MAX {
            return Err("queued JSON order counter exhausted".into());
        }
        self.remove_pending(&path);
        let at = self.next_order;
        self.next_order = self.next_order.checked_add(1).expect("checked above");
        self.order.insert(at, path.clone());
        self.pending_bytes += bytes.len();
        self.pending.insert(path, (at, bytes));
        Ok(())
    }
    fn remove_pending(&mut self, path: &Path) {
        if let Some((at, bytes)) = self.pending.remove(path) {
            self.order.remove(&at);
            self.pending_bytes = self.pending_bytes.saturating_sub(bytes.len());
        }
    }
    fn pop_pending(&mut self) -> Option<(PathBuf, Vec<u8>)> {
        let (_, path) = self.order.pop_first()?;
        let (_, bytes) = self.pending.remove(&path)?;
        self.pending_bytes = self.pending_bytes.saturating_sub(bytes.len());
        Some((path, bytes))
    }
}
type Queue = (std::sync::Mutex<JsonQueue>, std::sync::Condvar);
static JSON_QUEUE: std::sync::OnceLock<Result<&'static Queue, String>> = std::sync::OnceLock::new();

fn start_queue() -> Result<&'static Queue, String> {
    let queue: &'static Queue = Box::leak(Box::default());
    let spawned = std::thread::Builder::new()
        .name("antinomie-json".into())
        .spawn(move || json_writer(queue));
    spawned
        .map(|_| queue)
        .map_err(|error| format!("JSON writer thread could not start: {error}"))
}

fn json_queue() -> Result<&'static Queue, String> {
    #[cfg(test)]
    if let Some(private) = held::private_queue() {
        return Ok(private);
    }
    JSON_QUEUE.get_or_init(start_queue).clone()
}

/// The queue, when something has started it.
fn existing_queue() -> Option<&'static Queue> {
    #[cfg(test)]
    if let Some(private) = held::private_queue() {
        return Some(private);
    }
    JSON_QUEUE
        .get()
        .and_then(|queue| queue.as_ref().ok())
        .copied()
}

fn json_writer(queue: &'static Queue) {
    let (lock, ready) = queue;
    let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        #[cfg(test)]
        if queue.paused {
            queue = ready.wait(queue).unwrap_or_else(|e| e.into_inner());
            continue;
        }
        let Some((path, bytes)) = queue.pop_pending() else {
            queue = ready.wait(queue).unwrap_or_else(|e| e.into_inner());
            continue;
        };
        queue.writing = Some(path.clone());
        queue.writing_bytes = bytes.len();
        let observed = queue.observed.get(&path).and_then(std::sync::Weak::upgrade);
        drop(queue);
        let result = write_atomic(&path, &bytes);
        queue = lock.lock().unwrap_or_else(|e| e.into_inner());
        queue.writing = None;
        queue.writing_bytes = 0;
        #[cfg(test)]
        queue.published.push(path.clone());
        if let Some(observed) = observed {
            let mut status = observed.lock().unwrap_or_else(|error| error.into_inner());
            if matches!(*status, JsonWriteStatus::Pending) {
                *status = match &result {
                    Ok(()) => JsonWriteStatus::Complete,
                    Err(error) => JsonWriteStatus::Failed(error.message.clone()),
                };
            }
        }
        match result {
            Ok(()) => {
                queue.errors.remove(&path);
            }
            Err(error) => {
                queue.errors.entry(path).or_insert(error.message);
            }
        };
        ready.notify_all();
    }
}

/// Queues an atomic JSON write and returns at once. Reports the failure of an
/// earlier background write to the same path, if any.
pub(crate) fn queue_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    queue_bytes(path, encode_json(value)?)
}

/// Serialize directly into a capped buffer. `to_vec_pretty` first allocates
/// the complete output, which lets a large event preview exceed the queue's
/// memory budget before admission has a chance to reject it.
struct CappedJson {
    bytes: Vec<u8>,
    exceeded: bool,
}
impl Write for CappedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(end) = self.bytes.len().checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("queued JSON size overflow"));
        };
        if end >= MAX_JSON_BYTES {
            self.exceeded = true;
            return Err(io::Error::other("queued JSON exceeds writer limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn encode_json(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut output = CappedJson {
        bytes: Vec::new(),
        exceeded: false,
    };
    match serde_json::to_writer_pretty(&mut output, value) {
        Ok(()) => {}
        Err(_) if output.exceeded => {
            return Err(format!("queued JSON exceeds {MAX_JSON_BYTES} bytes"));
        }
        Err(error) => return Err(error.to_string()),
    }
    output.bytes.push(b'\n');
    Ok(output.bytes)
}

/// Publication state for an observed queued value. Failure remains observable
/// until the caller retries or a later same-path write supersedes that value.
#[derive(Clone, Debug)]
pub(crate) enum JsonWriteStatus {
    Pending,
    Complete,
    Failed(String),
    Superseded,
}
/// An observed value is acknowledged only after its own durable publication.
/// Any later same-path queue or synchronous write supersedes it, including
/// coalesced writes. The caller may then publish its current final value again.
/// Weak queue registrations are removed when the capture drops its receipt.
pub(crate) struct JsonReceipt {
    path: PathBuf,
    status: std::sync::Arc<std::sync::Mutex<JsonWriteStatus>>,
}
impl JsonReceipt {
    pub(crate) fn status(&self) -> JsonWriteStatus {
        self.status
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}
impl Drop for JsonReceipt {
    fn drop(&mut self) {
        if let Some((lock, _)) = existing_queue() {
            let mut queue = lock.lock().unwrap_or_else(|error| error.into_inner());
            if queue
                .observed
                .get(&self.path)
                .is_some_and(|entry| entry.ptr_eq(&std::sync::Arc::downgrade(&self.status)))
            {
                queue.observed.remove(&self.path);
            }
        }
    }
}
fn supersede_observed(queue: &JsonQueue, path: &Path) {
    if let Some(observed) = queue.observed.get(path).and_then(std::sync::Weak::upgrade) {
        *observed.lock().unwrap_or_else(|error| error.into_inner()) = JsonWriteStatus::Superseded;
    }
}
pub(crate) fn queue_json_observed(
    path: &Path,
    value: &impl Serialize,
) -> Result<JsonReceipt, String> {
    let bytes = encode_json(value)?;
    let status = std::sync::Arc::new(std::sync::Mutex::new(JsonWriteStatus::Pending));
    let (lock, ready) = json_queue()?;
    let mut queue = lock.lock().unwrap_or_else(|error| error.into_inner());
    queue
        .observed
        .retain(|_, receipt| receipt.strong_count() > 0);
    if !queue.observed.contains_key(path) && queue.observed.len() >= MAX_PENDING_PATHS {
        return Err("queued JSON receipt limit reached".into());
    }
    queue.insert_pending(path.to_path_buf(), bytes)?;
    supersede_observed(&queue, path);
    // A new receipt describes the retry rather than a previous path failure.
    // Callers observe the original receipt before explicitly queuing a retry.
    queue.errors.remove(path);
    queue
        .observed
        .insert(path.to_path_buf(), std::sync::Arc::downgrade(&status));
    ready.notify_all();
    Ok(JsonReceipt {
        path: path.to_path_buf(),
        status,
    })
}
/// Queues an atomic write of `bytes` to `path`, like `queue_json`.
pub(crate) fn queue_bytes(path: &Path, bytes: Vec<u8>) -> Result<(), String> {
    let (lock, ready) = json_queue()?;
    let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
    let earlier = queue.errors.get(path).cloned();
    queue.insert_pending(path.to_path_buf(), bytes)?;
    queue.errors.remove(path);
    supersede_observed(&queue, path);
    ready.notify_all();
    earlier.map_or(Ok(()), Err)
}

/// Drops a pending background write to `path` and waits for one in progress.
pub(super) fn settle_json(path: &Path) {
    let Some((lock, ready)) = existing_queue() else {
        return;
    };
    let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
    supersede_observed(&queue, path);
    queue.remove_pending(path);
    while queue.writing.as_deref() == Some(path) {
        queue = ready.wait(queue).unwrap_or_else(|e| e.into_inner());
    }
    queue.errors.remove(path);
}

/// Before a test removes `directory`: drops background writes queued below it
/// and waits for one in progress there, so none recreates a file meanwhile.
#[cfg(test)]
pub(crate) fn settle_json_under(directory: &Path) {
    let Some((lock, ready)) = existing_queue() else {
        return;
    };
    let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
    let doomed: Vec<_> = queue
        .pending
        .keys()
        .filter(|path| path.starts_with(directory))
        .cloned()
        .collect();
    for path in doomed {
        queue.remove_pending(&path);
    }
    while queue
        .writing
        .as_deref()
        .is_some_and(|path| path.starts_with(directory))
    {
        queue = ready.wait(queue).unwrap_or_else(|e| e.into_inner());
    }
    queue.errors.retain(|path, _| !path.starts_with(directory));
}

/// Waits until every queued JSON write has reached the disk.
pub(crate) fn flush_json() -> Result<(), String> {
    let Some((lock, ready)) = existing_queue() else {
        return Ok(());
    };
    let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !queue.pending.is_empty() || queue.writing.is_some() {
        queue = ready.wait(queue).unwrap_or_else(|e| e.into_inner());
    }
    queue.errors.iter().next().map_or(Ok(()), |(path, error)| {
        Err(format!("{}: {error}", path.display()))
    })
}

#[cfg(test)]
pub(crate) mod held;

#[cfg(test)]
mod tests;
