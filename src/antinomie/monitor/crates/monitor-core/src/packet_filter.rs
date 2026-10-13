// SPDX-License-Identifier: MIT
//! Display filters delegated to the separately installed, unmodified TShark
//! executable. Live PCAP snapshots and all disk indexes are private; no engine
//! code is linked, copied, or bundled with the monitor.
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
        Arc, Condvar, Mutex,
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

/// A complete result with disk-backed frame numbers and offsets.
pub struct PacketFilterIndex {
    snapshot: Arc<Snapshot>,
    matches: Scratch,
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

    fn lookup_frame(&self, number: u64) -> Result<(NetworkPacket, Option<u64>), String> {
        self.check_source()?;
        if number == 0 || number > self.packet_count() {
            return Err(format!(
                "frame {number} is outside the evaluated complete capture prefix ({} frames)",
                self.packet_count()
            ));
        }
        let mut offsets =
            File::open(self.snapshot.scratch.path.join("offsets")).map_err(|e| e.to_string())?;
        offsets
            .seek(SeekFrom::Start((number - 1) * 8))
            .map_err(|e| e.to_string())?;
        let offset = read_u64(&mut offsets)?;
        let packet = network::read_page(&self.snapshot.capture_path, offset, number - 1, 1)?
            .packets
            .pop()
            .ok_or("selected frame is missing from capture")?;
        let mut matches =
            File::open(self.matches.path.join("matches")).map_err(|e| e.to_string())?;
        let (mut low, mut high) = (0, self.matching_count);
        let mut position = None;
        while low < high {
            let middle = low + (high - low) / 2;
            matches
                .seek(SeekFrom::Start(middle * 8))
                .map_err(|e| e.to_string())?;
            let candidate = read_u64(&mut matches)?;
            match candidate.cmp(&number) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => {
                    position = Some(middle);
                    break;
                }
            }
        }
        self.check_source()?;
        Ok((packet, position))
    }

    /// Decode a bounded page from the same immutable snapshot used by TShark.
    /// Packet offsets and numbers remain those of the original capture.
    pub fn read_page(&self, start: u64, limit: usize) -> Result<Vec<NetworkPacket>, String> {
        self.check_source()?;
        let count = self
            .matching_count
            .saturating_sub(start)
            .min(limit.min(PAGE_SIZE) as u64);
        let mut matches =
            File::open(self.matches.path.join("matches")).map_err(|e| e.to_string())?;
        matches
            .seek(SeekFrom::Start(
                start.checked_mul(8).ok_or("packet page offset overflow")?,
            ))
            .map_err(|e| e.to_string())?;
        let mut offsets =
            File::open(self.snapshot.scratch.path.join("offsets")).map_err(|e| e.to_string())?;
        let mut packets = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let number = read_u64(&mut matches)?;
            offsets
                .seek(SeekFrom::Start(
                    number
                        .checked_sub(1)
                        .and_then(|n| n.checked_mul(8))
                        .ok_or("invalid frame number")?,
                ))
                .map_err(|e| e.to_string())?;
            let offset = read_u64(&mut offsets)?;
            let mut page = network::read_page(&self.snapshot.capture_path, offset, number - 1, 1)?;
            let packet = page
                .packets
                .pop()
                .ok_or("indexed packet is missing from snapshot")?;
            packets.push(packet);
        }
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
        result: Result<Vec<NetworkPacket>, String>,
    },
    Frame {
        generation: u64,
        number: u64,
        result: Result<(NetworkPacket, Option<u64>), String>,
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

/// One latest-request-only worker. Child processes have deadlines, bounded
/// output, cancellation, and are reaped before the next request begins.
pub struct PacketFilterWorker {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl PacketFilterWorker {
    pub fn new() -> Result<Self, String> {
        Self::with_program(PathBuf::from("tshark"))
    }

    fn with_program(program: PathBuf) -> Result<Self, String> {
        let shared = Arc::new(Shared {
            pending: Mutex::new(None),
            wake: Condvar::new(),
            generation: AtomicU64::new(0),
            stop: Arc::new(AtomicBool::new(false)),
            result: Mutex::new(None),
            fields: Mutex::new(FieldRegistry::Loading),
            cleanup_error: Mutex::new(None),
        });
        let worker = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("packet-display-filter".into())
            .spawn(move || {
                let fields = discover_fields(&program, &worker);
                *worker.fields.lock().unwrap_or_else(|e| e.into_inner()) = match fields {
                    Ok(fields) => FieldRegistry::Ready(Arc::new(fields)),
                    Err(error) => FieldRegistry::Unavailable(error),
                };
                let mut snapshot: Option<Arc<Snapshot>> = None;
                loop {
                    let job = {
                        let mut pending = worker.pending.lock().unwrap_or_else(|e| e.into_inner());
                        while pending.is_none() && !worker.stop.load(Ordering::Acquire) {
                            pending = worker.wake.wait(pending).unwrap_or_else(|e| e.into_inner());
                        }
                        if worker.stop.load(Ordering::Acquire) {
                            break;
                        }
                        pending.take()
                    };
                    let Some(job) = job else {
                        continue;
                    };
                    let (generation, event) = match job {
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
                                        &identity, &worker, generation, live,
                                    )?));
                                }
                                evaluate(
                                    &program,
                                    Arc::clone(snapshot.as_ref().ok_or("missing packet snapshot")?),
                                    &expression,
                                    &worker,
                                    generation,
                                )
                                .map(Arc::new)
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
                            let result = index.read_page(start, PAGE_SIZE);
                            (
                                generation,
                                PacketFilterEvent::Page {
                                    generation,
                                    start,
                                    result,
                                },
                            )
                        }
                        Job::Frame {
                            generation,
                            index,
                            number,
                        } => {
                            let result = index.lookup_frame(number);
                            (
                                generation,
                                PacketFilterEvent::Frame {
                                    generation,
                                    number,
                                    result,
                                },
                            )
                        }
                    };
                    if !cancelled(&worker, generation) {
                        *worker.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(event);
                    }
                }
            })
            .map_err(|e| format!("packet worker: {e}"))?;
        Ok(Self {
            shared,
            thread: Some(thread),
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
        self.shared.stop.store(true, Ordering::Release);
        self.cancel();
        self.shared.wake.notify_one();
        // The worker retains process ownership while cancellation finishes, so
        // destroying a VM view never blocks its UI on a busy external decoder.
        if let Some(worker) = self.thread.take() {
            drop(worker);
        }
    }
}

fn cancelled(shared: &Shared, generation: u64) -> bool {
    shared.stop.load(Ordering::Acquire) || shared.generation.load(Ordering::Acquire) != generation
}

/// The exact complete-record prefix processed by a streaming field query.
pub struct StreamExtent {
    pub packet_count: u64,
    pub complete_extent: u64,
    pub file_size: u64,
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
    let shared = Shared {
        pending: Mutex::new(None),
        wake: Condvar::new(),
        generation: AtomicU64::new(0),
        stop: cancel,
        result: Mutex::new(None),
        fields: Mutex::new(FieldRegistry::Loading),
        cleanup_error: Mutex::new(None),
    };
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
    expression: &str,
    shared: &Shared,
    generation: u64,
) -> Result<PacketFilterIndex, String> {
    let matches = Scratch::new()?;
    let output = matches.file("matches")?;
    let mut command = Command::new(program);
    command
        .arg("-n")
        .arg("-2")
        .arg("-r")
        .arg(&snapshot.capture_path);
    if !expression.trim().is_empty() {
        command.arg("-Y").arg(expression);
    }
    command.args(["-T", "fields", "-e", "frame.number", "-E", "occurrence=f"]);
    let packet_count = snapshot.packet_count;
    let matching_count = run_process(
        command,
        shared,
        Some(generation),
        Duration::from_secs(120),
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
        matches,
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

const CLEANUP_BUDGET: Duration = Duration::from_secs(1);

/// The parser sees ordinary blocking Read semantics, with a bounded abort check.
struct ProcessReader<R> {
    inner: R,
    abort: Arc<AtomicBool>,
}
impl<R: Read + AsFd> ProcessReader<R> {
    fn new(inner: R, abort: Arc<AtomicBool>) -> Result<Self, String> {
        let flags = rustix::fs::fcntl_getfl(&inner).map_err(|e| e.to_string())?;
        rustix::fs::fcntl_setfl(&inner, flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(|e| e.to_string())?;
        Ok(Self { inner, abort })
    }
}
impl<R: Read> Read for ProcessReader<R> {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        loop {
            if self.abort.load(Ordering::Acquire) {
                return Err(std::io::Error::other(
                    "packet output stopped for process cleanup",
                ));
            }
            match self.inner.read(data) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                result => return result,
            }
        }
    }
}

fn cleanup_process(
    process: &mut crate::sandbox_process::SandboxProcess,
    shared: &Shared,
    reason: &str,
) -> Result<(), String> {
    let started = Instant::now();
    let mut failure = None;
    loop {
        match process.cleanup_poll() {
            Ok(true) => {
                *shared
                    .cleanup_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                return failure.map_or(Ok(()), Err);
            }
            Ok(false) => {}
            Err(error) => failure = Some(error),
        }
        if failure.is_some() || started.elapsed() >= CLEANUP_BUDGET {
            let detail = failure
                .as_deref()
                .unwrap_or("termination/reaping exceeded cleanup budget");
            *shared
                .cleanup_error
                .lock()
                .unwrap_or_else(|e| e.into_inner()) =
                Some(format!("{reason}; cleanup pending: {detail}"));
            thread::sleep(Duration::from_millis(250));
        } else {
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn run_process<T: Send + 'static>(
    command: Command,
    shared: &Shared,
    generation: Option<u64>,
    deadline: Duration,
    read_output: impl FnOnce(ProcessReader<std::process::ChildStdout>) -> Result<T, String>
    + Send
    + 'static,
) -> Result<T, String> {
    crate::dependencies::require_tool(Path::new(command.get_program()), "tshark").map_err(
        |error| format!("TShark unavailable: {error}. Install tshark to enable display filters"),
    )?;
    // Linux util-linux provides a safe exec wrapper, avoiding unsafe pre_exec
    // code in the host. These limits apply to the external decoder only.
    let mut bounded = Command::new("prlimit");
    let profile = Scratch::new()?;
    let personal = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path != Path::new("/"))
        .ok_or("a non-root absolute personal directory is required for TShark isolation")?;
    bounded
        .args(["--as=2147483648", "--core=0", "--nofile=128", "--"])
        .arg("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-user",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--cap-drop",
            "ALL",
            "--die-with-parent",
            "--new-session",
            "--tmpfs",
        ])
        .arg(&personal)
        .arg("--bind")
        .arg(&profile.path)
        .arg(&profile.path);
    // The private namespace masks personal plug-ins without changing HOME.
    // A PCAP below that directory is the only personal file exposed again.
    let mut arguments = command.get_args();
    while let Some(argument) = arguments.next() {
        if argument == "-r"
            && let Some(capture) = arguments.next()
        {
            let capture = Path::new(capture);
            if capture.starts_with(&personal) {
                bounded.arg("--ro-bind").arg(capture).arg(capture);
            }
        }
    }
    let launch = crate::sandbox_process::prepare(&mut bounded)?;
    bounded
        .arg("--")
        .arg(command.get_program())
        .args(command.get_args());
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            bounded.env(name, value);
        } else {
            bounded.env_remove(name);
        }
    }
    if let Some(directory) = command.get_current_dir() {
        bounded.current_dir(directory);
    } else {
        bounded.current_dir(&profile.path);
    }
    for key in [
        "WIRESHARK_CONFIG_DIR",
        "WIRESHARK_PLUGIN_DIR",
        "WIRESHARK_EXTCAP_DIR",
        "TMPDIR",
    ] {
        bounded.env(key, &profile.path);
    }
    bounded
        .env_remove("WIRESHARK_DATA_DIR")
        .env_remove("WIRESHARK_RUN_FROM_BUILD_DIRECTORY");
    let child = bounded
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!("bounded TShark runtime is unavailable: {e}. Install tshark, bubblewrap and util-linux (prlimit) to enable display filters")
        })?;
    // Command retains configured stream descriptors; release its info writer so
    // EOF reflects only the sandbox monitor, not this owner's command builder.
    drop(bounded);
    let mut process = crate::sandbox_process::SandboxProcess::adopt(child, launch);
    let stdout = process.take_stdout().expect("piped TShark stdout");
    let stderr = process.take_stderr().expect("piped TShark stderr");
    let abort = Arc::new(AtomicBool::new(false));
    let stdout = match ProcessReader::new(stdout, Arc::clone(&abort)) {
        Ok(stdout) => stdout,
        Err(error) => {
            cleanup_process(&mut process, shared, &error)
                .map_err(|cleanup| format!("{error}; {cleanup}"))?;
            return Err(error);
        }
    };
    let stderr = match ProcessReader::new(stderr, Arc::clone(&abort)) {
        Ok(stderr) => stderr,
        Err(error) => {
            cleanup_process(&mut process, shared, &error)
                .map_err(|cleanup| format!("{error}; {cleanup}"))?;
            return Err(error);
        }
    };
    let parser_failed = Arc::new(AtomicBool::new(false));
    let failed = Arc::clone(&parser_failed);
    let output = match thread::Builder::new()
        .name("packet-filter-output".into())
        .spawn(move || {
            let result = read_output(stdout);
            failed.store(result.is_err(), Ordering::Release);
            result
        }) {
        Ok(thread) => thread,
        Err(error) => {
            let reason = format!("TShark output worker: {error}");
            abort.store(true, Ordering::Release);
            cleanup_process(&mut process, shared, &reason)
                .map_err(|cleanup| format!("{reason}; {cleanup}"))?;
            return Err(reason);
        }
    };
    let errors = match thread::Builder::new()
        .name("packet-filter-diagnostics".into())
        .spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut kept = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => kept.extend_from_slice(
                        &chunk[..count.min(MAX_ERROR_SIZE.saturating_sub(kept.len()))],
                    ),
                    Err(error) => return Err(format!("TShark diagnostic read: {error}")),
                }
            }
            Ok(String::from_utf8_lossy(&kept).trim().to_owned())
        }) {
        Ok(thread) => thread,
        Err(error) => {
            let reason = format!("TShark diagnostic worker: {error}");
            abort.store(true, Ordering::Release);
            let cleanup = cleanup_process(&mut process, shared, &reason);
            let _ = output.join();
            cleanup.map_err(|cleanup| format!("{reason}; {cleanup}"))?;
            return Err(reason);
        }
    };
    let started = Instant::now();
    let mut exit_status = None;
    let status = loop {
        let cancelled =
            shared.stop.load(Ordering::Acquire) || generation.is_some_and(|g| cancelled(shared, g));
        // Freeze the triggering reason before cleanup/drain time can pass a deadline.
        let reason = if cancelled {
            Some("packet filtering cancelled".to_string())
        } else if started.elapsed() >= deadline {
            Some("TShark evaluation timed out after its bounded deadline".to_string())
        } else if parser_failed.load(Ordering::Acquire) {
            Some("TShark output parser failed".to_string())
        } else {
            None
        };
        if let Some(reason) = reason {
            abort.store(true, Ordering::Release);
            let cleanup = cleanup_process(&mut process, shared, &reason);
            let parsed = output.join().map_err(|_| "TShark output reader stopped")?;
            let _ = errors.join();
            cleanup.map_err(|error| format!("{reason}; {error}"))?;
            return if reason == "TShark output parser failed" {
                parsed
            } else {
                Err(reason)
            };
        }
        let polled = process.poll_status();
        match polled {
            Ok(Some(status)) => exit_status = Some(status),
            Ok(None) => {}
            Err(reason) => {
                abort.store(true, Ordering::Release);
                let cleanup = cleanup_process(&mut process, shared, &reason);
                let _ = output.join();
                let _ = errors.join();
                cleanup.map_err(|error| format!("{reason}; {error}"))?;
                return Err(reason);
            }
        }
        // Continue enforcing cancellation/deadline until both readers finish,
        // even if an exited launcher left a namespace child holding its pipes.
        if let Some(status) = exit_status
            && output.is_finished()
            && errors.is_finished()
        {
            break status;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let diagnostics = errors
        .join()
        .map_err(|_| "TShark diagnostic reader stopped")??;
    let result = output.join().map_err(|_| "TShark output reader stopped")?;
    if !status.success() {
        return Err(if diagnostics.is_empty() {
            format!("TShark exited with {status}")
        } else if diagnostics.contains("failed to execute")
            || diagnostics.contains("execvp")
            || diagnostics.contains("No such file or directory")
        {
            format!(
                "{diagnostics}. Install tshark, bubblewrap and util-linux (prlimit) to enable display filters"
            )
        } else {
            format!("TShark failed (2 GiB memory limit, 128 open files): {diagnostics}")
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn shared() -> Shared {
        Shared {
            pending: Mutex::new(None),
            wake: Condvar::new(),
            generation: AtomicU64::new(0),
            stop: Arc::new(AtomicBool::new(false)),
            result: Mutex::new(None),
            fields: Mutex::new(FieldRegistry::Loading),
            cleanup_error: Mutex::new(None),
        }
    }

    #[test]
    fn packet_filter_cleanup_notice_preserves_registry_and_clears_after_reap() {
        let worker = PacketFilterWorker {
            shared: Arc::new(shared()),
            thread: None,
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
                snapshot,
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
            let index =
                evaluate(Path::new("tshark"), Arc::new(snapshot), "dns", &state, 0).unwrap();
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
                        let generation = worker.request_page(Arc::clone(&index), 1);
                        let started = Instant::now();
                        loop {
                            if let Some(PacketFilterEvent::Page {
                                generation: returned,
                                result,
                                ..
                            }) = worker.poll()
                            {
                                assert_eq!(returned, generation);
                                assert_eq!(result.unwrap()[0].number, 5);
                                break;
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
}
