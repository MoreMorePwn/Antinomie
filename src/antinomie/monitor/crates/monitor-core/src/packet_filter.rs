// SPDX-License-Identifier: MIT
//! Display filters delegated to the separately installed, unmodified TShark
//! executable. Live PCAP snapshots and all disk indexes are private; no engine
//! code is linked, copied, or bundled with the monitor.
pub use self::{
    parse::PacketDetail,
    pdml::{DetailNode, PacketTree},
    rows::{ParseStatus, RowStore},
};
use crate::network::{self, NetworkPacket};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    os::{
        fd::AsFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_SNAPSHOT_SIZE: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PACKET_COUNT: u64 = 16_000_000;
const MAX_FIELDS: usize = 300_000;
const MAX_OUTPUT_LINE_SIZE: usize = 16_384;
const MAX_ERROR_SIZE: usize = 16_384;
pub const PAGE_SIZE: usize = 500;

/// Stable file identity plus the extent for which an evaluation was requested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureIdentity {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub file_size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

impl CaptureIdentity {
    pub fn read(path: &Path) -> Result<Self, String> {
        let path = fs::canonicalize(path).map_err(|e| format!("capture identity: {e}"))?;
        let metadata = fs::metadata(&path).map_err(|e| format!("capture metadata: {e}"))?;
        if !metadata.is_file() {
            return Err("capture is not a regular file".into());
        }
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            file_size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        })
    }

    /// Appending complete records is compatible with an older live snapshot.
    pub fn permits_append(&self, current: &Self) -> bool {
        self.path == current.path
            && self.device == current.device
            && self.inode == current.inode
            && (self == current || current.file_size > self.file_size)
    }
}

#[derive(Clone, Debug)]
pub struct PacketField {
    pub name: String,
    /// TShark's FT_* type, or FT_PROTOCOL for a protocol presence predicate.
    pub kind: String,
    pub description: String,
}

#[derive(Clone, Debug)]
pub enum FieldRegistry {
    Loading,
    Ready(Arc<Vec<PacketField>>),
    Unavailable(String),
}

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new() -> Result<Self, String> {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        for _ in 0..32 {
            let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "antinomie-packet-{}-{stamp}-{serial}",
                std::process::id()
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("packet snapshot directory: {e}")),
            }
        }
        Err("could not create private packet snapshot directory".into())
    }
    fn file(&self, name: &str) -> Result<File, String> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.path.join(name))
            .map_err(|e| format!("packet snapshot file: {e}"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Nothing here is user evidence. On failure the OS retains only private
        // temporary files; the original capture is never a cleanup target.
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Snapshot {
    scratch: Scratch,
    capture_path: PathBuf,
    identity: CaptureIdentity,
    complete_extent: u64,
    packet_count: u64,
    first_time_us: u64,
    live: bool,
}

impl Snapshot {
    /// File offset of frame `number`'s record in [`Self::capture_path`].
    fn offset_of(&self, number: u64) -> Result<u64, String> {
        let mut offsets =
            File::open(self.scratch.path.join("offsets")).map_err(|e| e.to_string())?;
        offsets
            .seek(SeekFrom::Start(
                number
                    .checked_sub(1)
                    .and_then(|n| n.checked_mul(8))
                    .ok_or("invalid frame number")?,
            ))
            .map_err(|e| e.to_string())?;
        read_u64(&mut offsets)
    }
}

/// A complete result: which frames match, and the rows TShark printed for them.
pub struct PacketFilterIndex {
    snapshot: Arc<Snapshot>,
    /// Frame numbers that match, ascending; `None` when every frame does.
    matches: Option<Scratch>,
    rows: Arc<RowStore>,
    pub matching_count: u64,
    pub expression: String,
}

impl PacketFilterIndex {
    pub fn identity(&self) -> &CaptureIdentity {
        &self.snapshot.identity
    }
    pub fn packet_count(&self) -> u64 {
        self.snapshot.packet_count
    }
    pub fn complete_extent(&self) -> u64 {
        self.snapshot.complete_extent
    }
    pub fn first_time_us(&self) -> u64 {
        self.snapshot.first_time_us
    }
    /// The parse that fills the packet list: its progress and outcome.
    pub fn rows(&self) -> &RowStore {
        &self.rows
    }

    pub fn frame(&self, offset: u64) -> Result<Vec<u8>, String> {
        if offset >= self.snapshot.complete_extent {
            return Err("frame is outside the evaluated capture prefix".into());
        }
        self.check_source()?;
        network::frame(&self.snapshot.capture_path, offset)
    }

    fn check_source(&self) -> Result<(), String> {
        if self.snapshot.capture_path == self.snapshot.identity.path
            && CaptureIdentity::read(&self.snapshot.identity.path)? != self.snapshot.identity
        {
            return Err("capture changed after filtering; refresh the display result".into());
        }
        Ok(())
    }

    /// Frame numbers `start..start + count` of the matching frames.
    fn numbers(&self, start: u64, count: u64) -> Result<Vec<u64>, String> {
        let Some(matches) = &self.matches else {
            return Ok((start + 1..=start + count).collect());
        };
        let mut file = File::open(matches.path.join("matches")).map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start(
            start.checked_mul(8).ok_or("packet page offset overflow")?,
        ))
        .map_err(|e| e.to_string())?;
        (0..count).map(|_| read_u64(&mut file)).collect()
    }

    /// The packet list rows of `numbers` with their capture file offsets.
    /// Rows TShark has not printed yet end the list.
    fn packets(&self, numbers: &[u64]) -> Result<Vec<NetworkPacket>, String> {
        let mut packets = self.rows.read(numbers)?;
        if !packets.is_empty() {
            let mut offsets = File::open(self.snapshot.scratch.path.join("offsets"))
                .map_err(|e| e.to_string())?;
            for packet in &mut packets {
                offsets
                    .seek(SeekFrom::Start((packet.number - 1) * 8))
                    .map_err(|e| e.to_string())?;
                packet.offset = read_u64(&mut offsets)?;
            }
        }
        Ok(packets)
    }

    fn lookup_frame(&self, number: u64) -> Result<(NetworkPacket, Option<u64>), String> {
        self.check_source()?;
        if number == 0 || number > self.packet_count() {
            return Err(format!(
                "frame {number} is outside the evaluated complete capture prefix ({} frames)",
                self.packet_count()
            ));
        }
        let packet = self
            .packets(&[number])?
            .pop()
            .ok_or_else(|| format!("TShark has not parsed frame {number} yet"))?;
        let position = match &self.matches {
            None => Some(number - 1),
            Some(matches) => {
                let mut file =
                    File::open(matches.path.join("matches")).map_err(|e| e.to_string())?;
                let (mut low, mut high) = (0, self.matching_count);
                let mut position = None;
                while low < high {
                    let middle = low + (high - low) / 2;
                    file.seek(SeekFrom::Start(middle * 8))
                        .map_err(|e| e.to_string())?;
                    let candidate = read_u64(&mut file)?;
                    match candidate.cmp(&number) {
                        std::cmp::Ordering::Less => low = middle + 1,
                        std::cmp::Ordering::Greater => high = middle,
                        std::cmp::Ordering::Equal => {
                            position = Some(middle);
                            break;
                        }
                    }
                }
                position
            }
        };
        self.check_source()?;
        Ok((packet, position))
    }

    /// A page of the packet list from the rows TShark printed. Rows past the
    /// parse's progress are left out, so a page can be short while parsing.
    pub fn read_page(&self, start: u64, limit: usize) -> Result<Vec<NetworkPacket>, String> {
        self.check_source()?;
        let count = self
            .matching_count
            .saturating_sub(start)
            .min(limit.min(PAGE_SIZE) as u64);
        let numbers = self.numbers(start, count)?;
        let packets = self.packets(&numbers)?;
        self.check_source()?;
        Ok(packets)
    }
}

fn read_u64(file: &mut File) -> Result<u64, String> {
    let mut data = [0; 8];
    file.read_exact(&mut data).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(data))
}

pub enum PacketFilterEvent {
    Evaluated {
        generation: u64,
        identity: CaptureIdentity,
        expression: String,
        result: Result<Arc<PacketFilterIndex>, String>,
    },
    Page {
        generation: u64,
        start: u64,
        /// Rows TShark had printed before the page was read: the page holds
        /// every one of its frames up to that many.
        rows_done: u64,
        result: Result<Vec<NetworkPacket>, String>,
    },
    Frame {
        generation: u64,
        number: u64,
        result: Result<(NetworkPacket, Option<u64>), String>,
    },
    /// TShark's details of one frame.
    Detail {
        generation: u64,
        number: u64,
        result: Result<Box<PacketDetail>, String>,
    },
}

enum Job {
    Evaluate {
        generation: u64,
        identity: CaptureIdentity,
        expression: String,
        live: bool,
    },
    Page {
        generation: u64,
        index: Arc<PacketFilterIndex>,
        start: u64,
    },
    Frame {
        generation: u64,
        index: Arc<PacketFilterIndex>,
        number: u64,
    },
    Detail {
        generation: u64,
        index: Arc<PacketFilterIndex>,
        number: u64,
    },
    /// Stop parsing the open capture and forget it.
    Release,
}

struct Shared {
    pending: Mutex<Option<Job>>,
    wake: Condvar,
    generation: AtomicU64,
    stop: Arc<AtomicBool>,
    result: Mutex<Option<PacketFilterEvent>>,
    fields: Mutex<FieldRegistry>,
    cleanup_error: Mutex<Option<String>>,
}

impl Shared {
    fn new(stop: Arc<AtomicBool>) -> Self {
        Self {
            pending: Mutex::new(None),
            wake: Condvar::new(),
            generation: AtomicU64::new(0),
            stop,
            result: Mutex::new(None),
            fields: Mutex::new(FieldRegistry::Loading),
            cleanup_error: Mutex::new(None),
        }
    }
}

/// The capture the worker has open: its identity, and the parse of its rows.
struct OpenCapture {
    identity: CaptureIdentity,
    rows: Arc<RowStore>,
}

/// Two latest-request-only workers. One makes the snapshot, evaluates the
/// display filter and pages rows; the other asks TShark for the details of
/// the selected frame, so a refresh never cancels it. The packet list itself
/// is parsed on a third, per-capture thread. Child processes have deadlines,
/// bounded output, cancellation, and are reaped before the next request.
pub struct PacketFilterWorker {
    shared: Arc<Shared>,
    detail: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
    detail_thread: Option<JoinHandle<()>>,
}

impl PacketFilterWorker {
    pub fn new() -> Result<Self, String> {
        Self::with_program(PathBuf::from("tshark"))
    }

    fn with_program(program: PathBuf) -> Result<Self, String> {
        let shared = Arc::new(Shared::new(Arc::new(AtomicBool::new(false))));
        let detail = Arc::new(Shared::new(Arc::new(AtomicBool::new(false))));
        let worker = Arc::clone(&shared);
        let detail_program = program.clone();
        let detail_worker = Arc::clone(&detail);
        let detail_thread = thread::Builder::new()
            .name("packet-detail".into())
            .spawn(move || detail_loop(&detail_program, &detail_worker))
            .map_err(|e| format!("packet detail worker: {e}"))?;
        let thread = thread::Builder::new()
            .name("packet-display-filter".into())
            .spawn(move || filter_loop(&program, &worker))
            .map_err(|e| format!("packet worker: {e}"))?;
        Ok(Self {
            shared,
            detail,
            thread: Some(thread),
            detail_thread: Some(detail_thread),
        })
    }

    pub fn fields(&self) -> FieldRegistry {
        if let Some(error) = self
            .shared
            .cleanup_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return FieldRegistry::Unavailable(error);
        }
        self.shared
            .fields
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn poll(&self) -> Option<PacketFilterEvent> {
        self.shared
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
    /// The finished details request, if any.
    pub fn poll_detail(&self) -> Option<PacketFilterEvent> {
        self.detail
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    pub fn request(&self, identity: CaptureIdentity, expression: String, live: bool) -> u64 {
        let generation = self.shared.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.submit(Job::Evaluate {
            generation,
            identity,
            expression,
            live,
        });
        generation
    }
    pub fn request_page(&self, index: Arc<PacketFilterIndex>, start: u64) -> u64 {
        let generation = self.shared.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.submit(Job::Page {
            generation,
            index,
            start,
        });
        generation
    }
    pub fn request_frame(&self, index: Arc<PacketFilterIndex>, number: u64) -> u64 {
        let generation = self.shared.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.submit(Job::Frame {
            generation,
            index,
            number,
        });
        generation
    }
    /// Ask TShark for frame `number`'s details. A newer request replaces an
    /// older one (its TShark is stopped).
    pub fn request_detail(&self, index: Arc<PacketFilterIndex>, number: u64) -> u64 {
        let generation = self.detail.generation.fetch_add(1, Ordering::AcqRel) + 1;
        *self.detail.result.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .detail
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Job::Detail {
            generation,
            index,
            number,
        });
        self.detail.wake.notify_one();
        generation
    }
    /// Drop a details request that is no longer wanted.
    pub fn cancel_detail(&self) {
        self.detail.generation.fetch_add(1, Ordering::AcqRel);
        *self
            .detail
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *self.detail.result.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
    /// Stop parsing the open capture (the view moved to another one or
    /// closed). A later request for the same capture starts again.
    pub fn release(&self) {
        self.cancel();
        self.cancel_detail();
        self.submit(Job::Release);
    }
    fn submit(&self, job: Job) {
        *self.shared.result.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(job);
        self.shared.wake.notify_one();
    }
    pub fn cancel(&self) {
        self.shared.generation.fetch_add(1, Ordering::AcqRel);
        *self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *self.shared.result.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

impl Drop for PacketFilterWorker {
    fn drop(&mut self) {
        for shared in [&self.shared, &self.detail] {
            shared.stop.store(true, Ordering::Release);
        }
        self.cancel();
        self.cancel_detail();
        self.shared.wake.notify_one();
        self.detail.wake.notify_one();
        // The workers retain process ownership while cancellation finishes, so
        // destroying a VM view never blocks its UI on a busy external decoder.
        drop(self.thread.take());
        drop(self.detail_thread.take());
    }
}

/// Block until a job is pending; `None` when the worker is stopping.
fn next_job(worker: &Shared) -> Option<Job> {
    let mut pending = worker.pending.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if worker.stop.load(Ordering::Acquire) {
            return None;
        }
        if let Some(job) = pending.take() {
            return Some(job);
        }
        pending = worker.wake.wait(pending).unwrap_or_else(|e| e.into_inner());
    }
}

fn publish(worker: &Shared, generation: u64, event: PacketFilterEvent) {
    if !cancelled(worker, generation) {
        *worker.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(event);
    }
}

fn detail_loop(program: &Path, worker: &Shared) {
    while let Some(job) = next_job(worker) {
        if let Job::Detail {
            generation,
            index,
            number,
        } = job
        {
            let result = parse::load_detail(program, &index.snapshot, number, worker, generation)
                .map(Box::new);
            publish(
                worker,
                generation,
                PacketFilterEvent::Detail {
                    generation,
                    number,
                    result,
                },
            );
        }
    }
}

fn filter_loop(program: &Path, worker: &Shared) {
    let fields = discover_fields(program, worker);
    *worker.fields.lock().unwrap_or_else(|e| e.into_inner()) = match fields {
        Ok(fields) => FieldRegistry::Ready(Arc::new(fields)),
        Err(error) => FieldRegistry::Unavailable(error),
    };
    let version = parse::tshark_version(program, worker).unwrap_or_default();
    let mut snapshot: Option<Arc<Snapshot>> = None;
    let mut open: Option<OpenCapture> = None;
    while let Some(job) = next_job(worker) {
        let (generation, event) = match job {
            Job::Release => {
                if let Some(open) = open.take() {
                    open.rows.cancel();
                }
                snapshot = None;
                continue;
            }
            Job::Detail { .. } => continue,
            Job::Evaluate {
                generation,
                identity,
                expression,
                live,
            } => {
                let result = (|| {
                    if snapshot
                        .as_ref()
                        .is_none_or(|s| s.identity != identity || s.live != live)
                    {
                        snapshot = Some(Arc::new(make_snapshot(
                            &identity, worker, generation, live,
                        )?));
                    }
                    let snapshot = Arc::clone(snapshot.as_ref().ok_or("missing packet snapshot")?);
                    let rows = ensure_rows(program, &version, &mut open, &snapshot);
                    evaluate(program, snapshot, rows, &expression, worker, generation).map(Arc::new)
                })();
                (
                    generation,
                    PacketFilterEvent::Evaluated {
                        generation,
                        identity,
                        expression,
                        result,
                    },
                )
            }
            Job::Page {
                generation,
                index,
                start,
            } => {
                let rows_done = index.rows().done_count();
                (
                    generation,
                    PacketFilterEvent::Page {
                        generation,
                        start,
                        rows_done,
                        result: index.read_page(start, PAGE_SIZE),
                    },
                )
            }
            Job::Frame {
                generation,
                index,
                number,
            } => (
                generation,
                PacketFilterEvent::Frame {
                    generation,
                    number,
                    result: index.lookup_frame(number),
                },
            ),
        };
        publish(worker, generation, event);
    }
    if let Some(open) = open.take() {
        open.rows.cancel();
    }
}

/// The parse of `snapshot`'s packet list: the one already running or done for
/// this capture (continued when the capture grew), a cached one, or a new one
/// started now. The call returns at once; rows appear as TShark prints them.
fn ensure_rows(
    program: &Path,
    version: &str,
    open: &mut Option<OpenCapture>,
    snapshot: &Arc<Snapshot>,
) -> Arc<RowStore> {
    let job = |rows: &Arc<RowStore>| parse::ParseJob {
        program: program.to_path_buf(),
        store: Arc::clone(rows),
        snapshot: Arc::clone(snapshot),
        version: version.to_owned(),
    };
    if let Some(current) = open.as_mut()
        && current.identity.permits_append(&snapshot.identity)
    {
        let rows = Arc::clone(&current.rows);
        current.identity = snapshot.identity.clone();
        let grown = snapshot.packet_count > rows.total_count();
        if grown && !rows.cached && !rows.running.load(Ordering::Acquire) {
            parse::spawn_parse(job(&rows));
        } else if !snapshot.live
            && !rows.cached
            && rows.status() == ParseStatus::Complete
            && rows.done_count() == snapshot.packet_count
            && !rows.cache_saved.swap(true, Ordering::AcqRel)
        {
            // A live capture just finished: keep its parse beside it.
            let _ = parse::save_cache(&rows, &snapshot.identity, version);
        }
        return rows;
    }
    if let Some(previous) = open.take() {
        previous.rows.cancel();
    }
    let rows = if snapshot.live {
        None
    } else {
        parse::load_cache(&snapshot.identity, version, snapshot.packet_count)
    };
    let rows = rows.unwrap_or_else(|| match RowStore::scratch() {
        Ok(rows) => {
            parse::spawn_parse(job(&rows));
            rows
        }
        Err(error) => RowStore::failed(error),
    });
    *open = Some(OpenCapture {
        identity: snapshot.identity.clone(),
        rows: Arc::clone(&rows),
    });
    rows
}

fn cancelled(shared: &Shared, generation: u64) -> bool {
    shared.stop.load(Ordering::Acquire) || shared.generation.load(Ordering::Acquire) != generation
}

/// Which of `names` the installed TShark knows, from its field registry
/// (read once per process). Field names an older TShark lacks would fail a
/// whole query, so callers ask first for the optional ones.
pub fn known_fields(names: &[&str], cancel: Arc<AtomicBool>) -> Result<Vec<bool>, String> {
    static REGISTRY: OnceLock<Vec<String>> = OnceLock::new();
    let registry = match REGISTRY.get() {
        Some(registry) => registry,
        None => {
            let fields = discover_fields(Path::new("tshark"), &Shared::new(cancel))?;
            REGISTRY.get_or_init(|| fields.into_iter().map(|field| field.name).collect())
        }
    };
    Ok(names
        .iter()
        .map(|name| {
            registry
                .binary_search_by(|known| known.as_str().cmp(name))
                .is_ok()
        })
        .collect())
}

/// The exact complete-record prefix processed by a streaming field query.
pub struct StreamExtent {
    pub packet_count: u64,
    pub complete_extent: u64,
    pub file_size: u64,
}

/// Owned immutable, complete-record PCAP prefix for an offline analysis engine.
pub struct AnalysisSnapshot {
    inner: Snapshot,
}
impl AnalysisSnapshot {
    pub fn path(&self) -> &Path {
        &self.inner.capture_path
    }
    pub fn packet_count(&self) -> u64 {
        self.inner.packet_count
    }
    pub fn complete_extent(&self) -> u64 {
        self.inner.complete_extent
    }
}

/// Freeze the same validated prefix used by packet filtering; no decoder runs.
pub fn snapshot_for_analysis(
    identity: &CaptureIdentity,
    live: bool,
    cancel: Arc<AtomicBool>,
) -> Result<AnalysisSnapshot, String> {
    let shared = Shared::new(cancel);
    make_snapshot(identity, &shared, 0, live).map(|inner| AnalysisSnapshot { inner })
}

/// Stream installed TShark's decoded fields with the same cancellation,
/// complete-prefix, disk-budget, two-pass, and capture-identity protections as
/// the packet view. The caller runs this blocking operation on its own worker.
/// Each callback receives a tab-separated line with double-quoted fields;
/// doubled quotes escape a literal quote. Repeated values use ASCII unit
/// separator (0x1f), which avoids ambiguity with commas in URI or DNS values.
pub fn stream_fields(
    identity: &CaptureIdentity,
    expression: &str,
    fields: &[&str],
    live: bool,
    cancel: Arc<AtomicBool>,
    mut visit: impl FnMut(&str) -> Result<(), String> + Send + 'static,
) -> Result<StreamExtent, String> {
    if fields.is_empty() || fields.len() > 128 {
        return Err("field stream requires between 1 and 128 output fields".into());
    }
    let shared = Shared::new(cancel);
    let snapshot = make_snapshot(identity, &shared, 0, live)?;
    let mut command = Command::new("tshark");
    command
        .arg("-n")
        .arg("-2")
        .arg("-r")
        .arg(&snapshot.capture_path);
    if !expression.trim().is_empty() {
        command.arg("-Y").arg(expression);
    }
    command.args([
        "-T",
        "fields",
        "-E",
        "quote=d",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=\u{1f}",
    ]);
    for field in fields {
        command.arg("-e").arg(field);
    }
    run_process(
        command,
        &shared,
        Some(0),
        Duration::from_secs(120),
        move |reader| read_lines(reader, |line| visit(line)),
    )?;
    if !live && CaptureIdentity::read(&identity.path)? != *identity {
        return Err("capture changed during field streaming".into());
    }
    Ok(StreamExtent {
        packet_count: snapshot.packet_count,
        complete_extent: snapshot.complete_extent,
        file_size: identity.file_size,
    })
}

fn make_snapshot(
    identity: &CaptureIdentity,
    shared: &Shared,
    generation: u64,
    live: bool,
) -> Result<Snapshot, String> {
    if live && identity.file_size > MAX_SNAPSHOT_SIZE {
        return Err("live capture exceeds the 16 GiB display-filter snapshot limit; stop capture or open it in Wireshark".into());
    }
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&identity.path)
        .map_err(|e| format!("capture snapshot: {e}"))?;
    let metadata = source.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.dev() != identity.device
        || metadata.ino() != identity.inode
        || metadata.len() < identity.file_size
    {
        return Err("capture changed before filtering".into());
    }
    let mut source = BufReader::new(source);
    let scratch = Scratch::new()?;
    let space = rustix::fs::statvfs(&scratch.path)
        .map_err(|e| format!("packet snapshot disk space: {e}"))?;
    let available = space.f_bavail.saturating_mul(space.f_frsize);
    // Include index worst-case and leave a 64 MiB reserve. Other applications
    // may use space concurrently; every write/flush still reports disk errors.
    let record_bound = identity
        .file_size
        .saturating_sub(24)
        .saturating_div(16)
        .min(MAX_PACKET_COUNT);
    let required = record_bound
        .saturating_mul(16)
        .saturating_add(if live { identity.file_size } else { 0 })
        .saturating_add(64 * 1024 * 1024);
    if available < required {
        return Err(format!(
            "insufficient temporary disk space for packet filtering: need {required} bytes including reserve, {available} available"
        ));
    }
    let capture_path = if live {
        scratch.path.join("capture.pcap")
    } else {
        identity.path.clone()
    };
    let mut target = if live {
        Some(BufWriter::new(scratch.file("capture.pcap")?))
    } else {
        None
    };
    let mut offsets = BufWriter::new(scratch.file("offsets")?);
    let mut header = [0; 24];
    source
        .read_exact(&mut header)
        .map_err(|e| format!("PCAP header: {e}"))?;
    let little = match header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] => false,
        _ => {
            return Err("display-filter view requires an Ethernet microsecond PCAP capture".into());
        }
    };
    let word = |data: &[u8]| {
        let data: [u8; 4] = data.try_into().expect("four-byte PCAP word");
        if little {
            u32::from_le_bytes(data)
        } else {
            u32::from_be_bytes(data)
        }
    };
    if word(&header[20..24]) != 1 {
        return Err("display-filter view requires Ethernet PCAP".into());
    }
    if let Some(target) = &mut target {
        target
            .write_all(&header)
            .map_err(|e| format!("snapshot write: {e}"))?;
    }
    let (mut complete_extent, mut packet_count, mut first_time_us) = (24u64, 0u64, 0u64);
    let mut record = [0; 16];
    let mut frame = vec![0; 65_535];
    loop {
        if cancelled(shared, generation) {
            return Err("packet filtering cancelled".into());
        }
        if identity.file_size.saturating_sub(complete_extent) < 16 {
            break;
        }
        source
            .read_exact(&mut record)
            .map_err(|e| format!("PCAP record: {e}"))?;
        let captured = word(&record[8..12]) as usize;
        if captured > frame.len() {
            return Err(format!(
                "invalid PCAP record at {complete_extent}: captured length {captured}"
            ));
        }
        let next = complete_extent
            .checked_add(16 + captured as u64)
            .ok_or("PCAP extent overflow")?;
        if next > identity.file_size {
            break;
        }
        if live {
            source
                .read_exact(&mut frame[..captured])
                .map_err(|e| format!("PCAP payload: {e}"))?;
        } else {
            source
                .seek_relative(captured as i64)
                .map_err(|e| format!("PCAP record seek: {e}"))?;
        }
        if packet_count >= MAX_PACKET_COUNT {
            return Err("capture exceeds the 16 million packet display-filter index limit; open it in Wireshark".into());
        }
        offsets
            .write_all(&complete_extent.to_le_bytes())
            .map_err(|e| format!("packet index write: {e}"))?;
        if let Some(target) = &mut target {
            target
                .write_all(&record)
                .and_then(|()| target.write_all(&frame[..captured]))
                .map_err(|e| format!("snapshot write: {e}"))?;
        }
        if packet_count == 0 {
            first_time_us =
                u64::from(word(&record[..4])) * 1_000_000 + u64::from(word(&record[4..8]));
        }
        packet_count += 1;
        complete_extent = next;
    }
    if let Some(target) = &mut target {
        target
            .flush()
            .map_err(|e| format!("packet snapshot flush: {e}"))?;
    }
    offsets
        .flush()
        .map_err(|e| format!("packet index flush: {e}"))?;
    let current = CaptureIdentity::read(&identity.path)?;
    if !identity.permits_append(&current) || (!live && identity != &current) {
        return Err("capture was replaced or changed while snapshotting".into());
    }
    if !live && complete_extent != identity.file_size {
        return Err("finished capture has an incomplete PCAP record; use live view while capture is writing".into());
    }
    Ok(Snapshot {
        scratch,
        capture_path,
        identity: identity.clone(),
        complete_extent,
        packet_count,
        first_time_us,
        live,
    })
}

fn evaluate(
    program: &Path,
    snapshot: Arc<Snapshot>,
    rows: Arc<RowStore>,
    expression: &str,
    shared: &Shared,
    generation: u64,
) -> Result<PacketFilterIndex, String> {
    if expression.trim().is_empty() {
        // Every frame matches; the packet list is TShark's own parse.
        return Ok(PacketFilterIndex {
            matching_count: snapshot.packet_count,
            snapshot,
            matches: None,
            rows,
            expression: expression.into(),
        });
    }
    let matches = Scratch::new()?;
    let output = matches.file("matches")?;
    let mut command = Command::new(program);
    command
        .arg("-n")
        .arg("-2")
        .arg("-r")
        .arg(&snapshot.capture_path);
    command.arg("-Y").arg(expression);
    command.args(["-T", "fields", "-e", "frame.number", "-E", "occurrence=f"]);
    let packet_count = snapshot.packet_count;
    let matching_count = run_process(
        command,
        shared,
        Some(generation),
        Duration::from_secs((120 + packet_count / 5_000).min(3600)),
        move |reader| {
            let mut output = BufWriter::new(output);
            let mut count = 0;
            let mut previous = 0;
            read_lines(reader, |line| {
                let number = line
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| "invalid TShark frame-number output")?;
                if number == 0 || number > packet_count || number <= previous {
                    return Err("out-of-order TShark frame-number output".into());
                }
                output
                    .write_all(&number.to_le_bytes())
                    .map_err(|e| format!("filter index write: {e}"))?;
                count += 1;
                previous = number;
                Ok(())
            })?;
            output.flush().map_err(|e| e.to_string())?;
            Ok(count)
        },
    )?;
    if snapshot.capture_path == snapshot.identity.path
        && CaptureIdentity::read(&snapshot.identity.path)? != snapshot.identity
    {
        return Err("capture changed during TShark evaluation".into());
    }
    Ok(PacketFilterIndex {
        snapshot,
        matches: Some(matches),
        rows,
        matching_count,
        expression: expression.into(),
    })
}

fn discover_fields(program: &Path, shared: &Shared) -> Result<Vec<PacketField>, String> {
    let mut command = Command::new(program);
    command.args(["-G", "fields"]);
    run_process(command, shared, None, Duration::from_secs(30), |reader| {
        let mut fields = Vec::new();
        read_lines(reader, |line| {
            let columns: Vec<_> = line.split('\t').collect();
            let field = match columns.as_slice() {
                ["P", description, name, ..] => Some(PacketField {
                    name: (*name).into(),
                    kind: "FT_PROTOCOL".into(),
                    description: (*description).into(),
                }),
                ["F", description, name, kind, ..] => Some(PacketField {
                    name: (*name).into(),
                    kind: (*kind).into(),
                    description: (*description).into(),
                }),
                _ => None,
            };
            if let Some(field) = field {
                if fields.len() >= MAX_FIELDS {
                    return Err("TShark field registry exceeds the 300000-field limit".into());
                }
                fields.push(field);
            }
            Ok(())
        })?;
        fields.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        fields.dedup_by(|a, b| a.name == b.name);
        if fields.is_empty() {
            return Err("TShark returned no display-filter fields".into());
        }
        Ok(fields)
    })
}

fn read_lines(
    reader: impl Read,
    mut visit: impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    loop {
        line.clear();
        let count = reader
            .by_ref()
            .take((MAX_OUTPUT_LINE_SIZE + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?;
        if count == 0 {
            return Ok(());
        }
        if line.len() > MAX_OUTPUT_LINE_SIZE {
            return Err("TShark output line exceeds the bounded parser limit".into());
        }
        visit(
            std::str::from_utf8(&line)
                .map_err(|_| "TShark output is not UTF-8")?
                .trim_end_matches(['\r', '\n']),
        )?;
    }
}

mod parse;
mod pdml;
mod process;
mod rows;
use process::run_process;

#[cfg(test)]
mod tests {
    use super::process::ProcessReader;
    use super::rows::ROW_FIELDS;
    use super::*;
    use std::os::unix::net::UnixStream;

    fn shared() -> Shared {
        Shared::new(Arc::new(AtomicBool::new(false)))
    }

    /// The packet list of `snapshot`, parsed by the installed TShark.
    fn parsed(snapshot: &Arc<Snapshot>) -> Arc<RowStore> {
        let mut open = None;
        let rows = ensure_rows(Path::new("tshark"), "test", &mut open, snapshot);
        wait_parsed(&rows);
        rows
    }

    fn wait_parsed(rows: &RowStore) {
        for _ in 0..1200 {
            if rows.status() != ParseStatus::Parsing {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("TShark did not finish parsing");
    }

    #[test]
    fn packet_filter_cleanup_notice_preserves_registry_and_clears_after_reap() {
        let worker = PacketFilterWorker {
            shared: Arc::new(shared()),
            detail: Arc::new(shared()),
            thread: None,
            detail_thread: None,
        };
        let registry = Arc::new(vec![PacketField {
            name: "frame.number".into(),
            kind: "FT_UINT32".into(),
            description: "Frame number".into(),
        }]);
        *worker.shared.fields.lock().unwrap() = FieldRegistry::Ready(Arc::clone(&registry));
        *worker.shared.cleanup_error.lock().unwrap() = Some("cleanup pending".into());
        assert!(
            matches!(worker.fields(), FieldRegistry::Unavailable(message) if message == "cleanup pending")
        );
        *worker.shared.cleanup_error.lock().unwrap() = None;
        assert!(
            matches!(worker.fields(), FieldRegistry::Ready(fields) if Arc::ptr_eq(&fields, &registry))
        );
        *worker.shared.cleanup_error.lock().unwrap() = Some("cleanup pending".into());
        *worker.shared.fields.lock().unwrap() =
            FieldRegistry::Unavailable("registry discovery failed".into());
        *worker.shared.cleanup_error.lock().unwrap() = None;
        assert!(
            matches!(worker.fields(), FieldRegistry::Unavailable(message) if message == "registry discovery failed")
        );
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4], transport: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = transport;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        frame.extend(ip);
        frame.extend(payload);
        frame
    }

    fn tcp(src: u16, dst: u16, sequence: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut tcp = vec![0; 20];
        tcp[..2].copy_from_slice(&src.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst.to_be_bytes());
        tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp.extend(data);
        tcp
    }

    fn fixture() -> (Scratch, PathBuf) {
        let scratch = Scratch::new().unwrap();
        let path = scratch.path.join("fixture.pcap");
        let mut file = scratch.file("fixture.pcap").unwrap();
        file.write_all(&0xa1b2c3d4u32.to_le_bytes()).unwrap();
        file.write_all(&2u16.to_le_bytes()).unwrap();
        file.write_all(&4u16.to_le_bytes()).unwrap();
        file.write_all(&[0; 8]).unwrap();
        file.write_all(&65535u32.to_le_bytes()).unwrap();
        file.write_all(&1u32.to_le_bytes()).unwrap();
        let src = [10, 0, 2, 15];
        let dst = [93, 184, 216, 34];
        let request = b"GET /Api HTTP/1.1\r\nHost: Example.COM\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut frames = vec![
            ipv4(src, dst, 6, &tcp(40000, 80, 100, 0, 2, b"")),
            ipv4(src, dst, 6, &tcp(40000, 80, 101, 200, 0x18, request)),
            ipv4(
                dst,
                src,
                6,
                &tcp(80, 40000, 200, 101 + request.len() as u32, 0x18, response),
            ),
        ];
        let dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let mut udp = vec![0; 8];
        udp[..2].copy_from_slice(&5353u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        udp.extend(dns);
        frames.push(ipv4(src, [8, 8, 8, 8], 17, &udp));
        // A second repeated ip.addr value and DNS occurrence exercise real
        // multi-value field semantics instead of comparing a summary string.
        frames.push(ipv4([8, 8, 8, 8], src, 17, &udp));
        for (i, frame) in frames.iter().enumerate() {
            file.write_all(&(1_700_000_000u32 + i as u32).to_le_bytes())
                .unwrap();
            file.write_all(&0u32.to_le_bytes()).unwrap();
            file.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
            file.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
            file.write_all(frame).unwrap();
        }
        (scratch, path)
    }

    fn installed() -> bool {
        Command::new("tshark")
            .arg("-v")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    #[test]
    fn packet_filter_matches_real_tshark_complex_expressions_if_installed() {
        if !installed() {
            return;
        }
        let (_fixture, path) = fixture();
        let state = shared();
        let identity = CaptureIdentity::read(&path).unwrap();
        let snapshot = Arc::new(make_snapshot(&identity, &state, 0, false).unwrap());
        assert_eq!(snapshot.capture_path, identity.path);
        for expression in [
            "tcp.port in {80, 443} && (ip.src == 10.0.2.15 || tcp.flags.syn == 1)",
            "http.request.method == \"GET\" && http.request.uri matches \"^/A[a-z]+$\"",
            "lower(http.host) == \"example.com\"",
            "http.response_in > 0",
            "dns.qry.name contains \"example\" && !tcp",
            "ip.addr != 10.0.2.15",
            "tcp.flags & 0x02 == 0x02",
            "frame[0:2] == 00:00 && frame.len > 40",
            "count(ip.addr) == 2 && frame.number in {2, 4, 5}",
        ] {
            let direct = Command::new("tshark")
                .args(["-n", "-2", "-r"])
                .arg(&path)
                .args(["-Y", expression, "-T", "fields", "-e", "frame.number"])
                .output()
                .unwrap();
            assert!(
                direct.status.success(),
                "{expression}: {}",
                String::from_utf8_lossy(&direct.stderr)
            );
            let expected: Vec<u64> = String::from_utf8(direct.stdout)
                .unwrap()
                .lines()
                .map(|line| line.parse().unwrap())
                .collect();
            let index = evaluate(
                Path::new("tshark"),
                Arc::clone(&snapshot),
                parsed(&snapshot),
                expression,
                &state,
                0,
            )
            .unwrap();
            let actual: Vec<_> = index
                .read_page(0, PAGE_SIZE)
                .unwrap()
                .iter()
                .map(|packet| packet.number)
                .collect();
            assert_eq!(actual, expected, "{expression}");
            if expression.starts_with("http.request.method")
                || expression.starts_with("lower")
                || expression.starts_with("http.response_in")
            {
                assert_eq!(
                    actual,
                    [2],
                    "fixture must exercise decoded HTTP field: {expression}"
                );
            }
        }
        assert!(
            evaluate(
                Path::new("tshark"),
                Arc::clone(&snapshot),
                parsed(&snapshot),
                "no.such.field == 1",
                &state,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn packet_filter_live_snapshot_ignores_partial_record_and_never_changes_source() {
        let (_fixture, path) = fixture();
        let original = fs::read(&path).unwrap();
        let captured = u32::from_le_bytes(original[32..36].try_into().unwrap()) as usize;
        let appended = &original[24..24 + 16 + captured];
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&appended[..9]).unwrap();
        let before = fs::read(&path).unwrap();
        let state = shared();
        let identity = CaptureIdentity::read(&path).unwrap();
        let snapshot = make_snapshot(&identity, &state, 0, true).unwrap();
        assert_eq!(snapshot.packet_count, 5);
        assert_eq!(snapshot.complete_extent, identity.file_size - 9);
        assert_eq!(
            fs::metadata(&snapshot.capture_path).unwrap().len(),
            snapshot.complete_extent
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(make_snapshot(&identity, &state, 0, false).is_err());
        file.write_all(&appended[9..]).unwrap();
        let grown = CaptureIdentity::read(&path).unwrap();
        assert!(identity.permits_append(&grown));
        let next = make_snapshot(&grown, &state, 0, true).unwrap();
        assert_eq!(next.packet_count, 6);
        assert_eq!(next.complete_extent, grown.file_size);
        assert_eq!(
            fs::metadata(&snapshot.capture_path).unwrap().len(),
            snapshot.complete_extent
        );
        if installed() {
            let snapshot = Arc::new(snapshot);
            let rows = parsed(&snapshot);
            let index = evaluate(Path::new("tshark"), snapshot, rows, "dns", &state, 0).unwrap();
            assert_eq!(
                index
                    .read_page(0, PAGE_SIZE)
                    .unwrap()
                    .iter()
                    .map(|p| p.number)
                    .collect::<Vec<_>>(),
                [4, 5]
            );
        }
    }

    #[test]
    fn packet_filter_rejects_bad_records_and_releases_private_snapshots() {
        let (_fixture, path) = fixture();
        let identity = CaptureIdentity::read(&path).unwrap();
        let state = shared();
        let snapshot = make_snapshot(&identity, &state, 0, true).unwrap();
        let private = snapshot.scratch.path.clone();
        assert!(private.exists());
        drop(snapshot);
        assert!(!private.exists());
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        let mut header = [0; 16];
        header[8..12].copy_from_slice(&65536u32.to_le_bytes());
        file.write_all(&header).unwrap();
        assert!(
            make_snapshot(&CaptureIdentity::read(&path).unwrap(), &state, 0, true)
                .err()
                .expect("bad record rejected")
                .contains("invalid PCAP record")
        );
    }

    #[test]
    fn packet_filter_reader_abort_is_bounded_while_another_writer_stays_open() {
        let (reader, writer) = UnixStream::pair().unwrap();
        let abort = Arc::new(AtomicBool::new(false));
        let mut reader = ProcessReader::new(reader, Arc::clone(&abort)).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let mut output = Vec::new();
            let result = reader.read_to_end(&mut output);
            sender.send(result).unwrap();
        });
        thread::sleep(Duration::from_millis(20));
        let started = Instant::now();
        abort.store(true, Ordering::Release);
        let result = receiver.recv_timeout(Duration::from_millis(500));
        // Close the writer even on failure so a failed test cannot strand a reader.
        drop(writer);
        worker.join().unwrap();
        assert!(
            result
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("process cleanup")
        );
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn packet_filter_missing_engine_and_cancelled_process_are_errors() {
        let state = shared();
        assert!(
            discover_fields(Path::new("/no-such-antinomie-tshark"), &state)
                .unwrap_err()
                .contains("Install tshark")
        );
        let stop = Arc::clone(&state.stop);
        let setter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            stop.store(true, Ordering::Release);
        });
        let mut command = Command::new("sleep");
        command.arg("30");
        let started = Instant::now();
        let result = run_process(command, &state, Some(0), Duration::from_secs(2), |reader| {
            read_lines(reader, |_| Ok(()))
        });
        let error = result.unwrap_err();
        assert!(error.contains("cancelled"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2), "{error}");
        setter.join().unwrap();
    }

    #[test]
    fn packet_filter_namespace_masks_personal_files_but_exposes_only_capture() {
        let personal = PathBuf::from(std::env::var_os("HOME").unwrap());
        let path = personal.join(format!(
            ".ant-packet-isolation-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let fixture = Scratch { path };
        let capture = fixture.path.join("capture");
        let private = fixture.path.join("private");
        fs::write(&capture, "capture").unwrap();
        fs::write(&private, "private").unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "test \"$(cat \"$2\")\" = capture && test ! -e \"$3\" && test \"$(id -u)\" = 65534 && test -w \"$WIRESHARK_CONFIG_DIR\" && printf isolated", "packet-test", "-r"])
            .arg(&capture).arg(&private);
        let output = run_process(
            command,
            &shared(),
            Some(0),
            Duration::from_secs(2),
            |mut reader| {
                let mut output = String::new();
                reader
                    .read_to_string(&mut output)
                    .map_err(|error| error.to_string())?;
                Ok(output)
            },
        )
        .unwrap();
        assert_eq!(output, "isolated");
        assert_eq!(fs::read_to_string(&capture).unwrap(), "capture");
        assert_eq!(fs::read_to_string(&private).unwrap(), "private");
    }

    #[test]
    fn packet_filter_sandbox_hides_session_sockets_and_the_data_directory() {
        // A stand-in for the data directory: another private directory next to
        // the snapshot scratch, which must not be mounted.
        let data = Scratch::new().unwrap();
        let secret = data.path.join("secret");
        fs::write(&secret, "secret").unwrap();
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "for p in /run/user /run/dbus /tmp/.X11-unix /dev/shm /var /home /mnt \"$1\"; do \
                 test ! -e \"$p\" || { echo \"visible: $p\"; exit 1; }; done; \
             test -r /usr/share/wireshark || exit 2; printf hidden",
                "packet-test",
            ])
            .arg(&secret);
        let output = run_process(
            command,
            &shared(),
            Some(0),
            Duration::from_secs(10),
            |mut reader| {
                let mut output = String::new();
                reader
                    .read_to_string(&mut output)
                    .map_err(|error| error.to_string())?;
                Ok(output)
            },
        )
        .unwrap();
        assert_eq!(output, "hidden");
    }

    #[test]
    fn packet_filter_deadline_and_bounded_output_are_errors() {
        let state = shared();
        let mut command = Command::new("sleep");
        command.arg("30");
        let result = run_process(
            command,
            &state,
            Some(0),
            Duration::from_millis(50),
            |reader| read_lines(reader, |_| Ok(())),
        );
        assert!(result.unwrap_err().contains("timed out"));
        assert!(
            read_lines(
                std::io::Cursor::new(vec![b'x'; MAX_OUTPUT_LINE_SIZE + 1]),
                |_| Ok(())
            )
            .unwrap_err()
            .contains("bounded parser limit")
        );
        assert!(
            read_lines(std::io::Cursor::new(vec![0xff, b'\n']), |_| Ok(()))
                .unwrap_err()
                .contains("UTF-8")
        );
    }

    #[test]
    fn packet_filter_registry_is_typed_and_latest_generation_wins_if_installed() {
        if !installed() {
            return;
        }
        let state = shared();
        let fields = discover_fields(Path::new("tshark"), &state).unwrap();
        assert!(
            fields
                .iter()
                .any(|f| f.name == "tcp.flags.cwr" && f.kind == "FT_BOOLEAN")
        );
        assert!(
            fields
                .iter()
                .any(|f| f.name == "http" && f.kind == "FT_PROTOCOL")
        );
        let (_fixture, path) = fixture();
        let worker = PacketFilterWorker::new().unwrap();
        let identity = CaptureIdentity::read(&path).unwrap();
        worker.request(identity.clone(), "bad.field == 1".into(), false);
        let expected_generation = worker.request(identity, "dns".into(), false);
        let started = Instant::now();
        loop {
            if let Some(event) = worker.poll() {
                match event {
                    PacketFilterEvent::Evaluated {
                        generation, result, ..
                    } => {
                        assert_eq!(generation, expected_generation);
                        let index = result.unwrap();
                        assert_eq!(index.matching_count, 2);
                        let mut generation = worker.request_page(Arc::clone(&index), 1);
                        let started = Instant::now();
                        loop {
                            if let Some(PacketFilterEvent::Page {
                                generation: returned,
                                result,
                                ..
                            }) = worker.poll()
                            {
                                assert_eq!(returned, generation);
                                let page = result.unwrap();
                                if let Some(packet) = page.first() {
                                    assert_eq!(packet.number, 5);
                                    break;
                                }
                                // TShark has not printed the row yet.
                                generation = worker.request_page(Arc::clone(&index), 1);
                            }
                            assert!(started.elapsed() < Duration::from_secs(10));
                            thread::sleep(Duration::from_millis(20));
                        }
                        break;
                    }
                    _ => panic!("unexpected page before evaluation"),
                }
            }
            assert!(started.elapsed() < Duration::from_secs(10));
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn rows_are_tshark_columns_and_the_second_open_reads_the_cache() {
        if !installed() {
            return;
        }
        let (_fixture, path) = fixture();
        let state = shared();
        let identity = CaptureIdentity::read(&path).unwrap();
        let snapshot = Arc::new(make_snapshot(&identity, &state, 0, false).unwrap());
        let rows = parsed(&snapshot);
        assert_eq!(rows.status(), ParseStatus::Complete);
        assert_eq!(rows.done_count(), 5);
        let index = evaluate(
            Path::new("tshark"),
            Arc::clone(&snapshot),
            rows,
            "",
            &state,
            0,
        )
        .unwrap();
        assert_eq!(index.matching_count, 5);
        let page = index.read_page(0, PAGE_SIZE).unwrap();
        assert_eq!(page.len(), 5);
        let request = &page[1];
        assert_eq!(request.protocol, "HTTP");
        assert!(
            request.info.contains("GET /Api HTTP/1.1"),
            "{}",
            request.info
        );
        assert_eq!(request.source, "10.0.2.15");
        assert_eq!(request.destination, "93.184.216.34");
        assert_eq!(
            (request.src_port, request.dst_port),
            (Some(40000), Some(80))
        );
        assert_eq!(request.transport, Some(crate::network::Transport::Tcp));
        assert_eq!(request.tcp_flags, Some(0x18));
        assert_eq!(request.time_us, 1_700_000_001_000_000);
        assert!(request.offset > 24);
        assert_eq!(page[3].protocol, "DNS");
        assert_eq!(page[3].transport, Some(crate::network::Transport::Udp));
        let (found, position) = index.lookup_frame(4).unwrap();
        assert_eq!((found.number, position), (4, Some(3)));
        // The finished parse was kept beside the capture, and a new open
        // reads it back without running TShark.
        let cache = cache_dir_of(&path);
        assert!(cache.join("meta.json").is_file());
        let version = "test";
        let again = parse::load_cache(&identity, version, 5).expect("cache is used");
        assert!(again.cached);
        assert_eq!(again.read(&[2, 4]).unwrap()[1].protocol, "DNS");
        // A different capture file, packet count or TShark invalidates it.
        assert!(parse::load_cache(&identity, "another TShark", 5).is_none());
        assert!(parse::load_cache(&identity, version, 4).is_none());
        fs::write(cache.join("rows.tsv"), b"damaged").unwrap();
        assert!(parse::load_cache(&identity, version, 5).is_none());
    }

    fn cache_dir_of(path: &Path) -> PathBuf {
        let mut name = path.file_name().unwrap().to_os_string();
        name.push(".view");
        path.with_file_name(name)
    }

    #[test]
    fn details_are_tshark_lines_with_byte_ranges_inside_the_frame() {
        if !installed() {
            return;
        }
        let (_fixture, path) = fixture();
        let state = shared();
        let identity = CaptureIdentity::read(&path).unwrap();
        let snapshot = Arc::new(make_snapshot(&identity, &state, 0, false).unwrap());
        let detail = parse::load_detail(Path::new("tshark"), &snapshot, 2, &state, 0).unwrap();
        assert_eq!(detail.number, 2);
        let labels: Vec<_> = detail
            .tree
            .nodes
            .iter()
            .filter(|node| node.depth == 0)
            .map(|node| node.label.clone())
            .collect();
        assert!(labels[0].starts_with("Frame 2:"), "{labels:?}");
        assert!(
            labels.iter().any(|l| l.starts_with("Ethernet II")),
            "{labels:?}"
        );
        assert!(
            labels
                .iter()
                .any(|l| l.starts_with("Transmission Control Protocol"))
        );
        assert!(
            labels
                .iter()
                .any(|l| l.starts_with("Hypertext Transfer Protocol"))
        );
        let host = detail
            .tree
            .nodes
            .iter()
            .find(|node| node.label.starts_with("Host: Example.COM"))
            .expect("HTTP host line");
        let frame = network::frame(&snapshot.capture_path, snapshot.offset_of(2).unwrap()).unwrap();
        assert_eq!(detail.frame_len, frame.len());
        let range = host.range().expect("host bytes");
        assert_eq!(&frame[range], b"Host: Example.COM\r\n");
        for node in &detail.tree.nodes {
            assert!(node.len == 0 || node.start + node.len <= frame.len());
        }
        assert!(parse::load_detail(Path::new("tshark"), &snapshot, 6, &state, 0).is_err());
    }

    #[test]
    fn a_growing_capture_appends_rows_to_the_same_store() {
        if !installed() {
            return;
        }
        let (_fixture, path) = fixture();
        let original = fs::read(&path).unwrap();
        let captured = u32::from_le_bytes(original[32..36].try_into().unwrap()) as usize;
        let first_record = original[24..24 + 16 + captured].to_vec();
        let state = shared();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&first_record[..9]).unwrap();
        let identity = CaptureIdentity::read(&path).unwrap();
        let snapshot = Arc::new(make_snapshot(&identity, &state, 0, true).unwrap());
        let mut open = None;
        let rows = ensure_rows(Path::new("tshark"), "test", &mut open, &snapshot);
        wait_parsed(&rows);
        assert_eq!(rows.done_count(), 5);
        assert!(!rows.cached);
        file.write_all(&first_record[9..]).unwrap();
        let grown = CaptureIdentity::read(&path).unwrap();
        let next = Arc::new(make_snapshot(&grown, &state, 0, true).unwrap());
        let again = ensure_rows(Path::new("tshark"), "test", &mut open, &next);
        assert!(Arc::ptr_eq(&rows, &again));
        wait_parsed(&again);
        assert_eq!(again.done_count(), 6);
        let all = again.read(&[1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(
            all.iter().map(|p| p.number).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6]
        );
        // TShark names the repeated SYN for what it is.
        assert!(
            all[5].info.contains("[TCP Retransmission]"),
            "{}",
            all[5].info
        );
        // A live capture is never cached; the finished one is, once.
        assert!(!cache_dir_of(&path).exists());
        let finished = Arc::new(make_snapshot(&grown, &state, 0, false).unwrap());
        let done = ensure_rows(Path::new("tshark"), "test", &mut open, &finished);
        assert!(Arc::ptr_eq(&rows, &done));
        assert!(cache_dir_of(&path).join("meta.json").is_file());
    }

    #[test]
    fn a_missing_tshark_fails_the_parse_without_rows() {
        let (_fixture, path) = fixture();
        let state = shared();
        let identity = CaptureIdentity::read(&path).unwrap();
        let snapshot = Arc::new(make_snapshot(&identity, &state, 0, false).unwrap());
        let mut open = None;
        let rows = ensure_rows(Path::new("/nonexistent/tshark"), "", &mut open, &snapshot);
        wait_parsed(&rows);
        assert!(matches!(rows.status(), ParseStatus::Failed(_)));
        assert_eq!(rows.done_count(), 0);
        assert!(rows.read(&[1]).unwrap().is_empty());
    }

    #[test]
    fn untrusted_rows_are_validated_sanitized_and_bounded() {
        let mut values: Vec<String> = ROW_FIELDS.iter().map(|_| String::new()).collect();
        values[0] = "7".into();
        values[1] = "1700000000.123456789".into();
        values[2] = "60".into();
        values[3] = "60".into();
        values[6] = "TLSv1.3".into();
        values[7] = format!("Client Hello\x1b[31m{}", "x".repeat(5000));
        values[8] = "10.0.0.1".into();
        values[12] = "50000".into();
        values[14] = "443".into();
        values[16] = "0x00000002".into();
        let packet = rows::from_tshark(&values).unwrap();
        assert_eq!(packet.time_us, 1_700_000_000_123_456);
        assert_eq!(packet.info.chars().count(), 1024);
        assert!(!packet.info.contains('\x1b'));
        assert_eq!(packet.tcp_flags, Some(2));
        assert_eq!(packet.src_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(packet.dst_ip, None);
        for (index, bad) in [(0, "0"), (0, "x"), (2, "-1"), (3, "99999999999")] {
            let mut broken = values.clone();
            broken[index] = bad.into();
            assert!(rows::from_tshark(&broken).is_err(), "{index} {bad}");
        }
        assert!(rows::from_tshark(&values[..16]).is_err());
        // Quoted values hold tabs, doubled quotes and line breaks.
        let record = "\"1\"\t\"a\tb\"\"c\nd\"\t\"\"";
        assert_eq!(rows::split_record(record).unwrap(), ["1", "a\tb\"c\nd", ""]);
        assert!(rows::split_record("\"open").is_err());
    }

    #[test]
    fn rows_must_arrive_in_frame_order_within_the_capture() {
        let store = RowStore::scratch().unwrap();
        let mut writer = rows::RowWriter::open(&store).unwrap();
        let mut values: Vec<String> = ROW_FIELDS.iter().map(|_| String::new()).collect();
        values[2] = "60".into();
        values[3] = "60".into();
        values[0] = "1".into();
        writer
            .push(&store, &rows::from_tshark(&values).unwrap())
            .unwrap();
        values[0] = "3".into();
        let skipped = writer.push(&store, &rows::from_tshark(&values).unwrap());
        assert!(skipped.unwrap_err().contains("expected"));
        // Nothing is readable until published.
        assert!(store.read(&[1]).unwrap().is_empty());
        writer.publish(&store).unwrap();
        assert_eq!(store.read(&[1, 2]).unwrap().len(), 1);
    }

    /// Synthetic traffic (documentation addresses, `.test` names): TLS 1.2 and
    /// 1.3 hellos, a QUIC Initial, cleartext HTTP/2, SSH, SMB, FTP, SMTP, IRC,
    /// NTP, mDNS, ARP and DNS on a second port.
    const PROTOCOLS: &[u8] = include_bytes!("packet_filter/testdata/protocols.pcap");

    #[test]
    fn tshark_labels_protocols_the_old_decoder_showed_as_tcp_or_udp() {
        if !installed() {
            return;
        }
        let scratch = Scratch::new().unwrap();
        let path = scratch.path.join("protocols.pcap");
        fs::write(&path, PROTOCOLS).unwrap();
        let state = shared();
        let identity = CaptureIdentity::read(&path).unwrap();
        let snapshot = Arc::new(make_snapshot(&identity, &state, 0, false).unwrap());
        let rows = parsed(&snapshot);
        assert_eq!(rows.status(), ParseStatus::Complete);
        let all: Vec<u64> = (1..=snapshot.packet_count).collect();
        let packets = rows.read(&all).unwrap();
        assert_eq!(packets.len() as u64, snapshot.packet_count);
        let protocols: std::collections::BTreeSet<&str> =
            packets.iter().map(|p| p.protocol.as_str()).collect();
        for expected in [
            "DNS", "TLSv1.2", "TLSv1.3", "HTTP2", "SSH", "HTTP", "SMB", "FTP", "SMTP", "NTP",
            "ARP", "QUIC",
        ] {
            assert!(protocols.contains(expected), "{expected} in {protocols:?}");
        }
        let info = |protocol: &str| {
            packets
                .iter()
                .find(|p| p.protocol == protocol)
                .map(|p| p.info.clone())
                .unwrap()
        };
        assert!(info("TLSv1.2").contains("Client Hello (SNI=secure.example.test)"));
        assert!(info("QUIC").contains("Initial"));
        assert!(info("SSH").contains("SSH-2.0"));
        // The QUIC Initial's server name and ALPN come out of TShark without keys.
        let quic = packets.iter().find(|p| p.protocol == "QUIC").unwrap();
        let detail =
            parse::load_detail(Path::new("tshark"), &snapshot, quic.number, &state, 0).unwrap();
        let lines: Vec<&str> = detail.tree.nodes.iter().map(|n| n.label.as_str()).collect();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Server Name: quic.example.test")),
            "{lines:?}"
        );
        assert!(lines.iter().any(|l| l.contains("ALPN Next Protocol: h3")));
        assert!(
            detail
                .tree
                .nodes
                .iter()
                .all(|n| n.len == 0 || n.start + n.len <= detail.frame_len)
        );
    }

    #[test]
    fn malformed_captures_are_refused_and_garbage_frames_still_parse() {
        let (_fixture, path) = fixture();
        let good = fs::read(&path).unwrap();
        let scratch = Scratch::new().unwrap();
        let state = shared();
        let open = |name: &str, bytes: &[u8], live: bool| {
            let path = scratch.path.join(name);
            fs::write(&path, bytes).unwrap();
            let identity = CaptureIdentity::read(&path).unwrap();
            (path, make_snapshot(&identity, &state, 0, live))
        };
        // A saved capture cut in the middle of a record is refused; a live
        // one is read up to its last whole record.
        let cut = &good[..good.len() - 20];
        assert!(open("cut.pcap", cut, false).1.is_err());
        assert_eq!(open("cut-live.pcap", cut, true).1.unwrap().packet_count, 4);
        assert!(open("header.pcap", &[0; 40], false).1.is_err());
        let mut huge = good[..24].to_vec();
        huge.extend([1, 0, 0, 0, 0, 0, 0, 0, 0x70, 0x11, 0, 0, 0x70, 0x11, 0, 0]);
        huge.extend([0; 64]);
        assert!(open("huge.pcap", &huge, false).1.is_err());
        if !installed() {
            return;
        }
        // Frames of pseudo-random bytes: TShark reports them as malformed or
        // unknown, and the viewer still gets a validated row and a tree each.
        let mut garbage = good[..24].to_vec();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for number in 0..24u32 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = 14 + (seed >> 40) as usize % 200;
            let mut frame: Vec<u8> = (0..len)
                .map(|at| (seed.rotate_left(at as u32 % 63) >> 7) as u8)
                .collect();
            if number % 2 == 0 {
                // Plausible Ethernet and IPv4 headers with nonsense after them.
                frame[12..14].copy_from_slice(&[8, 0]);
                frame[14] = 0x45;
            }
            garbage.extend(number.to_le_bytes());
            garbage.extend(0u32.to_le_bytes());
            garbage.extend((len as u32).to_le_bytes());
            garbage.extend((len as u32).to_le_bytes());
            garbage.extend(frame);
        }
        let (path, snapshot) = open("garbage.pcap", &garbage, false);
        let snapshot = Arc::new(snapshot.unwrap());
        let rows = parsed(&snapshot);
        assert_eq!(rows.status(), ParseStatus::Complete);
        assert_eq!(rows.done_count(), 24);
        for number in 1..=24 {
            let detail =
                parse::load_detail(Path::new("tshark"), &snapshot, number, &state, 0).unwrap();
            assert!(!detail.tree.nodes.is_empty());
            assert!(
                detail
                    .tree
                    .nodes
                    .iter()
                    .all(|n| n.len == 0 || n.start + n.len <= detail.frame_len)
            );
        }
        drop(path);
    }

    /// `ANTINOMIE_BIG_PCAP=<file> cargo test --release -p antinomie-monitor-core
    /// large_capture_probe -- --ignored --nocapture`: the time to the first
    /// page and to the whole parse of a large capture, and this process's
    /// peak memory.
    #[test]
    #[ignore = "probe; needs ANTINOMIE_BIG_PCAP"]
    fn large_capture_probe() {
        let Ok(path) = std::env::var("ANTINOMIE_BIG_PCAP") else {
            return;
        };
        let worker = PacketFilterWorker::new().unwrap();
        while matches!(worker.fields(), FieldRegistry::Loading) {
            thread::sleep(Duration::from_millis(20));
        }
        let identity = CaptureIdentity::read(Path::new(&path)).unwrap();
        let started = Instant::now();
        worker.request(identity, String::new(), false);
        let index = loop {
            if let Some(PacketFilterEvent::Evaluated { result, .. }) = worker.poll() {
                break result.unwrap();
            }
            thread::sleep(Duration::from_millis(5));
        };
        println!(
            "index ready after {:?}, {} packets",
            started.elapsed(),
            index.packet_count()
        );
        let first = loop {
            let page = index.read_page(0, PAGE_SIZE).unwrap();
            if page.len() == PAGE_SIZE {
                break started.elapsed();
            }
            thread::sleep(Duration::from_millis(5));
        };
        println!("first page of {PAGE_SIZE} rows after {first:?}");
        let slow = Instant::now();
        let mut worst = Duration::ZERO;
        while index.rows().status() == ParseStatus::Parsing {
            let call = Instant::now();
            index
                .read_page(index.rows().done_count().saturating_sub(10), 10)
                .unwrap();
            worst = worst.max(call.elapsed());
            thread::sleep(Duration::from_millis(50));
        }
        println!(
            "parse finished {:?} after start ({:?}), status {:?}, rows {}, slowest page read while parsing {worst:?}",
            started.elapsed(),
            slow.elapsed(),
            index.rows().status(),
            index.rows().done_count()
        );
        let last = index.packet_count() - 100;
        let read = Instant::now();
        let page = index.read_page(last, 100).unwrap();
        println!(
            "page near the end: {} rows in {:?}",
            page.len(),
            read.elapsed()
        );
        let status = fs::read_to_string("/proc/self/status").unwrap();
        for line in status.lines().filter(|l| l.starts_with("VmHWM")) {
            println!("this process peak: {line}");
        }
    }
}
