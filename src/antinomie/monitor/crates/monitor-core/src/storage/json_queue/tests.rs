use super::*;
use std::time::{Duration, Instant};

fn directory(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ant-json-{label}-{}", unique_id()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn published(queue: &Queue) -> Vec<PathBuf> {
    queue.0.lock().unwrap().published.clone()
}

#[test]
fn pretty_json_serialization_stops_at_the_admission_limit() {
    let oversized = "x".repeat(MAX_JSON_BYTES);
    let error = encode_json(&oversized).unwrap_err();
    assert!(error.contains("exceeds"), "{error}");
}

#[test]
fn files_are_published_in_the_order_they_were_last_queued_not_by_name() {
    let disk = held::SlowDisk::install();
    let root = directory("order");
    disk.pause();
    let (late, early, middle) = (
        root.join("z-run.json"),
        root.join("a-manifest.json"),
        root.join("m.json"),
    );
    queue_json(&late, &1).unwrap();
    queue_json(&early, &1).unwrap();
    queue_json(&middle, &1).unwrap();
    // Queueing a path again moves it behind the others, with the newer value.
    queue_json(&late, &2).unwrap();
    disk.resume();
    flush_json().unwrap();
    assert_eq!(
        published(json_queue().unwrap()),
        [early.clone(), middle, late.clone()]
    );
    assert_eq!(read_json::<u32>(&late).unwrap(), 2);
    assert_eq!(read_json::<u32>(&early).unwrap(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn queueing_never_waits_for_the_disk_and_a_later_value_is_never_overwritten() {
    let disk = held::SlowDisk::install();
    let root = directory("stalled");
    let path = root.join("run.json");
    disk.pause();
    let started = Instant::now();
    for value in 0..200u32 {
        queue_json(&path, &value).unwrap();
        queue_bytes(&root.join("screen.ansi"), vec![value as u8]).unwrap();
    }
    // Queueing returns at once whatever the disk does; the bound is loose.
    assert!(started.elapsed() < Duration::from_secs(30));
    assert!(
        published(json_queue().unwrap()).is_empty(),
        "the disk has not answered"
    );
    disk.resume();
    flush_json().unwrap();
    assert_eq!(
        read_json::<u32>(&path).unwrap(),
        199,
        "only the newest value was written"
    );
    assert_eq!(published(json_queue().unwrap()).len(), 2);
    // A synchronous publication supersedes a queued one and is not overwritten by it.
    disk.pause();
    queue_json(&path, &1000).unwrap();
    let sync = std::thread::spawn({
        let (path, inherit) = (path.clone(), held::inherit());
        move || {
            inherit();
            atomic_json(&path, &2000)
        }
    });
    std::thread::sleep(Duration::from_millis(100));
    disk.resume();
    sync.join().unwrap().unwrap();
    flush_json().unwrap();
    assert_eq!(read_json::<u32>(&path).unwrap(), 2000);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_missing_directory_is_a_reported_failure_never_an_implicit_mkdir() {
    let disk = held::SlowDisk::install();
    let root = directory("missing");
    let path = root.join("not-yet/run.json");
    queue_json(&path, &1).unwrap();
    assert!(flush_json().is_err());
    assert!(!root.join("not-yet").exists());
    let failure = queue_json(&path, &2).unwrap_err();
    assert!(
        failure.contains("run.json") || failure.contains("No such file"),
        "{failure}"
    );
    drop(disk);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn synchronous_publications_on_the_transport_thread_are_counted() {
    let root = directory("counted");
    let path = root.join("config.json");
    let before = transport_sync_writes();
    atomic_json(&path, &1).unwrap();
    queue_json(&path, &2).unwrap();
    flush_json().unwrap();
    assert_eq!(
        transport_sync_writes(),
        before,
        "an unmarked thread is not counted"
    );
    std::thread::spawn({
        let path = path.clone();
        move || {
            mark_transport_thread();
            queue_json(&path, &3).unwrap();
            assert_eq!(transport_sync_writes(), before, "queueing is not a wait");
            atomic_json(&path, &4).unwrap();
            atomic_bytes(&path, b"5").unwrap();
        }
    })
    .join()
    .unwrap();
    assert_eq!(transport_sync_writes(), before + 2);
    fs::remove_dir_all(root).unwrap();
}

/// Disk-bound (writes 3 GiB): while recording saturates the disk, a status
/// file published from the transport thread used to take 50 s or more because
/// its `fsync` waited for the filesystem journal behind the dirty recording
/// data. Queueing it returns at once, and the newest value still lands.
/// Run with `TMPDIR` on the recording disk:
/// `cargo test --release -p antinomie-monitor-core --lib -- --ignored queued_json_stays_fast`
#[test]
#[ignore]
fn queued_json_stays_fast_while_recording_saturates_the_disk() {
    let root = directory("saturated");
    let quiet = {
        let start = Instant::now();
        for n in 0..5 {
            atomic_json(&root.join("artifacts.json"), &n).unwrap();
        }
        start.elapsed() / 5
    };
    let raw = std::sync::Arc::new(File::create(root.join("telemetry.raw")).unwrap());
    let slot = crate::writer::error_slot();
    let feeder = {
        let (raw, slot) = (raw.clone(), slot.clone());
        std::thread::spawn(move || {
            // About 3 GiB in 1 MiB blocks, as RawCapture::flush hands them over.
            for _ in 0..3072 {
                crate::writer::submit(crate::writer::Op::Append {
                    file: raw.clone(),
                    data: vec![0x5a; 1024 * 1024],
                    rollback: 0,
                    error: slot.clone(),
                });
            }
        })
    };
    std::thread::sleep(Duration::from_secs(3));
    let mut worst = Duration::ZERO;
    for n in 0..10 {
        let start = Instant::now();
        queue_json(&root.join("artifacts.json"), &(100 + n)).unwrap();
        worst = worst.max(start.elapsed());
    }
    feeder.join().unwrap();
    crate::writer::barrier();
    flush_json().unwrap();
    assert_eq!(read_json::<u32>(&root.join("artifacts.json")).unwrap(), 109);
    fs::remove_dir_all(&root).unwrap();
    assert!(
        worst < Duration::from_millis(250),
        "queueing took {worst:?} under recording load (quiet disk fsync: {quiet:?})"
    );
}
