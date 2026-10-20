// SPDX-License-Identifier: MIT
//! Parsing a capture with TShark into the stored packet list, the cache of
//! that list beside the capture, and TShark's details of a single frame.
use super::pdml::{self, MAX_PDML_SIZE, PacketTree};
use super::rows::*;
use super::*;
use serde::{Deserialize, Serialize};

/// Bumped when the stored row layout or the TShark fields change.
const CACHE_FORMAT: u32 = 1;
/// Folder beside `<capture>` holding its parsed rows.
const CACHE_SUFFIX: &str = "view";

/// What identifies a cached parse: the capture file as it was, and the
/// TShark that printed it.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct CacheKey {
    format: u32,
    capture_size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    tshark: String,
    packet_count: u64,
    rows_size: u64,
}

fn cache_dir(capture: &Path) -> Option<PathBuf> {
    let mut name = capture.file_name()?.to_os_string();
    name.push(format!(".{CACHE_SUFFIX}"));
    Some(capture.with_file_name(name))
}

fn cache_key(
    identity: &CaptureIdentity,
    tshark: &str,
    packet_count: u64,
    rows_size: u64,
) -> CacheKey {
    CacheKey {
        format: CACHE_FORMAT,
        capture_size: identity.file_size,
        modified_seconds: identity.modified_seconds,
        modified_nanoseconds: identity.modified_nanoseconds,
        tshark: tshark.into(),
        packet_count,
        rows_size,
    }
}

/// The cached rows of a finished capture, when they were printed from this
/// very file by this TShark.
pub(super) fn load_cache(
    identity: &CaptureIdentity,
    tshark: &str,
    packet_count: u64,
) -> Option<Arc<RowStore>> {
    let dir = cache_dir(&identity.path)?;
    if !fs::symlink_metadata(&dir).ok()?.is_dir() {
        return None;
    }
    let meta = fs::File::open(dir.join("meta.json")).ok()?;
    let stored: CacheKey = serde_json::from_reader(meta.take(4096)).ok()?;
    let (rows_size, index_size) = RowStore::disk_sizes(&dir)?;
    (stored == cache_key(identity, tshark, packet_count, rows_size)
        && index_size == packet_count * 8)
        .then(|| RowStore::from_cache(dir, packet_count))
}

/// Copy a complete store beside its capture. Best effort: the viewer works
/// without a cache, so a read-only recording or a full disk is not an error.
pub(super) fn save_cache(
    store: &RowStore,
    identity: &CaptureIdentity,
    tshark: &str,
) -> Result<(), String> {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    let dir = cache_dir(&identity.path).ok_or("capture has no file name")?;
    let temp = dir.with_extension(format!(
        "{CACHE_SUFFIX}-tmp-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&temp)
            .map_err(|e| format!("packet cache folder: {e}"))?;
        for name in ["rows.tsv", "rows.idx"] {
            fs::copy(store.dir().join(name), temp.join(name))
                .map_err(|e| format!("packet cache copy: {e}"))?;
        }
        let (rows_size, _) = RowStore::disk_sizes(&temp).ok_or("packet cache size")?;
        let key = cache_key(identity, tshark, store.done_count(), rows_size);
        let meta = serde_json::to_vec(&key).map_err(|e| e.to_string())?;
        fs::write(temp.join("meta.json"), meta).map_err(|e| format!("packet cache meta: {e}"))?;
        if fs::symlink_metadata(&dir).is_ok() {
            fs::remove_dir_all(&dir).map_err(|e| format!("packet cache replace: {e}"))?;
        }
        fs::rename(&temp, &dir).map_err(|e| format!("packet cache publish: {e}"))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temp);
    }
    result
}

/// What a parse thread needs beyond the store.
pub(super) struct ParseJob {
    pub program: PathBuf,
    pub store: Arc<RowStore>,
    pub snapshot: Arc<Snapshot>,
    /// TShark's version line, for the cache.
    pub version: String,
}

/// Run TShark over the snapshot on its own thread, appending rows from frame
/// `store.done_count() + 1` as it prints them. The caller returns at once.
pub(super) fn spawn_parse(job: ParseJob) {
    let store = Arc::clone(&job.store);
    store.running.store(true, Ordering::Release);
    store.set_status(ParseStatus::Parsing);
    store.set_total(job.snapshot.packet_count);
    let thread_store = Arc::clone(&store);
    let spawned = thread::Builder::new()
        .name("packet-parse".into())
        .spawn(move || {
            let result = parse(&job);
            let store = &job.store;
            let cancelled = store.cancel.load(Ordering::Acquire);
            match result {
                Ok(()) => {
                    if !job.snapshot.live {
                        store.cache_saved.store(true, Ordering::Release);
                        let _ = save_cache(store, &job.snapshot.identity, &job.version);
                    }
                    store.set_status(ParseStatus::Complete);
                }
                Err(_) if cancelled => store.set_status(ParseStatus::Failed("cancelled".into())),
                Err(error) => store.set_status(ParseStatus::Failed(error)),
            }
            store.running.store(false, Ordering::Release);
        });
    if let Err(error) = spawned {
        thread_store.set_status(ParseStatus::Failed(format!("packet parser: {error}")));
        thread_store.running.store(false, Ordering::Release);
    }
}

fn parse(job: &ParseJob) -> Result<(), String> {
    let store = &job.store;
    let from = store.done_count();
    let total = job.snapshot.packet_count;
    let mut command = Command::new(&job.program);
    command.arg("-n").arg("-r").arg(&job.snapshot.capture_path);
    if from > 0 {
        command.arg("-Y").arg(format!("frame.number > {from}"));
    }
    command.args([
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]);
    for field in ROW_FIELDS {
        command.arg("-e").arg(field);
    }
    let shared = Shared::new(Arc::clone(&store.cancel));
    let reader_store = Arc::clone(store);
    let deadline = Duration::from_secs((300 + total / 10_000).min(3600));
    run_process(command, &shared, None, deadline, move |reader| {
        let store = reader_store;
        let mut writer = RowWriter::open(&store)?;
        let result = read_rows(reader, &store, &mut writer, total);
        let published = writer.publish(&store);
        result.and(published)?;
        if writer.count() < total {
            return Err(format!(
                "TShark printed {} of {total} packets of this capture",
                writer.count()
            ));
        }
        Ok(())
    })
}

fn read_rows(
    reader: impl Read,
    store: &RowStore,
    writer: &mut RowWriter,
    total: u64,
) -> Result<(), String> {
    let mut reader = BufReader::new(reader);
    let mut record = Vec::new();
    loop {
        record.clear();
        // A record ends at a line break outside quotes.
        loop {
            let before = record.len();
            let count = reader
                .by_ref()
                .take((MAX_RECORD_SIZE + 1 - before.min(MAX_RECORD_SIZE)) as u64)
                .read_until(b'\n', &mut record)
                .map_err(|e| e.to_string())?;
            if count == 0 {
                if record.is_empty() {
                    return Ok(());
                }
                return Err("TShark output ended inside a packet row".into());
            }
            if record.len() > MAX_RECORD_SIZE {
                return Err("TShark printed a packet row over the 64 KiB limit".into());
            }
            if record.iter().filter(|&&byte| byte == b'"').count() % 2 == 0 {
                break;
            }
        }
        let text = std::str::from_utf8(&record).map_err(|_| "TShark output is not UTF-8")?;
        let packet = from_tshark(&split_record(text)?)?;
        if packet.number > total {
            return Err("TShark printed more packets than the capture holds".into());
        }
        writer.push(store, &packet)?;
    }
}

/// What the packet details pane shows for one frame.
#[derive(Clone, Debug)]
pub struct PacketDetail {
    pub number: u64,
    /// Length of the captured frame every byte range of the tree fits in.
    pub frame_len: usize,
    pub tree: PacketTree,
}

/// TShark's details of frame `number` of `snapshot`.
pub(super) fn load_detail(
    program: &Path,
    snapshot: &Snapshot,
    number: u64,
    shared: &Shared,
    generation: u64,
) -> Result<PacketDetail, String> {
    if number == 0 || number > snapshot.packet_count {
        return Err(format!(
            "frame {number} is outside the evaluated capture prefix ({} frames)",
            snapshot.packet_count
        ));
    }
    let offset = snapshot.offset_of(number)?;
    let frame = network::frame(&snapshot.capture_path, offset)?;
    let mut command = Command::new(program);
    command
        .arg("-n")
        .arg("-r")
        .arg(&snapshot.capture_path)
        // One pass, so the details agree with the packet list; reading stops
        // at the frame instead of the end of a large capture.
        .arg("-c")
        .arg(number.to_string())
        .arg("-Y")
        .arg(format!("frame.number == {number}"))
        .args(["-T", "pdml"]);
    let frame_len = frame.len();
    let tree = run_process(
        command,
        shared,
        Some(generation),
        Duration::from_secs(300),
        move |reader| {
            let mut xml = Vec::new();
            reader
                .take((MAX_PDML_SIZE + 1) as u64)
                .read_to_end(&mut xml)
                .map_err(|e| e.to_string())?;
            if xml.len() > MAX_PDML_SIZE {
                return Err("TShark packet details exceed the 16 MiB limit".into());
            }
            pdml::parse(&xml, frame_len)
        },
    )?;
    Ok(PacketDetail {
        number,
        frame_len,
        tree,
    })
}

/// TShark's `--version` first line (a cache key; also tells the viewer that
/// the sandboxed TShark runs).
pub(super) fn tshark_version(program: &Path, shared: &Shared) -> Result<String, String> {
    let mut command = Command::new(program);
    command.arg("--version");
    run_process(command, shared, None, Duration::from_secs(30), |reader| {
        let mut first = String::new();
        BufReader::new(reader.take(4096))
            .read_line(&mut first)
            .map_err(|e| e.to_string())?;
        Ok(clean(first.trim(), 200))
    })
}
