// SPDX-License-Identifier: GPL-3.0-only
//! QEMU's serial console and its own messages are guest-controlled, so they
//! go through a pipe into a file of bounded size instead of straight to disk.
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

/// Largest `serial.log`, in bytes.
pub(super) const SERIAL_LOG_BYTES: u64 = 16 * 1024 * 1024;
/// Largest `qemu.log`, in bytes.
pub(super) const QEMU_LOG_BYTES: u64 = 2 * 1024 * 1024;

/// Copy `source` into `file` until it ends, writing at most `limit` bytes and
/// then one marker line saying the rest was dropped. Reading goes on after the
/// limit so QEMU never blocks on a full pipe.
pub(super) fn copy_capped(mut source: impl Read, mut file: File, limit: u64) {
    let mut written = 0u64;
    let mut cut = false;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let read = match source.read(&mut chunk) {
            Ok(0) => return,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        if cut {
            continue;
        }
        let room = usize::try_from(limit - written).unwrap_or(usize::MAX);
        let take = read.min(room);
        if file.write_all(&chunk[..take]).is_err() {
            cut = true;
            continue;
        }
        written += take as u64;
        if take < read {
            cut = true;
            let _ = write!(
                file,
                "\n[Antinomie: output cut here at {limit} bytes; the rest was dropped]\n"
            );
        }
    }
}

/// Logs whose copy thread has not reached the end of its pipe yet.
static OPEN: Mutex<BTreeMap<PathBuf, Arc<Open>>> = Mutex::new(BTreeMap::new());

#[derive(Default)]
struct Open {
    ended: Mutex<bool>,
    changed: Condvar,
}

/// Start a thread copying a child's output pipe into `file` (at `path`),
/// capped. The thread ends when the pipe does, that is when QEMU and every
/// process holding its output are gone; each start has a pipe of its own.
pub(super) fn spawn_capped(
    source: impl Read + Send + 'static,
    file: File,
    path: &Path,
    limit: u64,
) {
    let open = Arc::new(Open::default());
    OPEN.lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(path.to_path_buf(), open.clone());
    let key = path.to_path_buf();
    let started = std::thread::Builder::new()
        .name("antinomie-qemu-log".into())
        .spawn({
            let open = open.clone();
            move || {
                copy_capped(source, file, limit);
                finish(&key, &open);
            }
        });
    if started.is_err() {
        // The closure (and with it the pipe) is dropped: QEMU sees a closed
        // pipe rather than one nobody reads.
        finish(path, &open);
    }
}

fn finish(path: &Path, open: &Arc<Open>) {
    let mut table = OPEN.lock().unwrap_or_else(|e| e.into_inner());
    if table
        .get(path)
        .is_some_and(|known| Arc::ptr_eq(known, open))
    {
        table.remove(path);
    }
    drop(table);
    *open.ended.lock().unwrap_or_else(|e| e.into_inner()) = true;
    open.changed.notify_all();
}

/// Wait (at most `limit`) until the copy thread of the log at `path` has
/// written everything QEMU sent before it ended. Call it only once QEMU has
/// exited: while it runs, the pipe does not end.
pub(super) fn settle(path: &Path, limit: Duration) {
    let open = OPEN
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(path)
        .cloned();
    let Some(open) = open else { return };
    let ended = open.ended.lock().unwrap_or_else(|e| e.into_inner());
    let _ = open
        .changed
        .wait_timeout_while(ended, limit, |ended| !*ended);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_past_the_cap_is_dropped_and_marked() {
        let path =
            std::env::temp_dir().join(format!("ant-capped-log-{}", crate::storage::unique_id()));
        let data = vec![b'x'; 100_000];
        copy_capped(&data[..], File::create(&path).unwrap(), 4096);
        let saved = std::fs::read(&path).unwrap();
        assert!(saved.len() < 4096 + 200, "{}", saved.len());
        assert!(saved[..4096].iter().all(|byte| *byte == b'x'));
        let text = String::from_utf8_lossy(&saved[4096..]);
        assert!(text.contains("output cut here at 4096 bytes"), "{text}");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn output_within_the_cap_is_kept_whole() {
        let path =
            std::env::temp_dir().join(format!("ant-capped-log-{}", crate::storage::unique_id()));
        copy_capped(&b"boot ok\n"[..], File::create(&path).unwrap(), 4096);
        assert_eq!(std::fs::read(&path).unwrap(), b"boot ok\n");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_writer_far_past_the_cap_never_blocks_and_the_file_stays_bounded() {
        let path =
            std::env::temp_dir().join(format!("ant-capped-log-{}", crate::storage::unique_id()));
        let (reader, mut writer) = std::io::pipe().unwrap();
        spawn_capped(reader, File::create(&path).unwrap(), &path, 64 * 1024);
        let (done, finished) = std::sync::mpsc::channel();
        let flood = std::thread::spawn(move || {
            let chunk = [b'z'; 64 * 1024];
            for _ in 0..512 {
                writer.write_all(&chunk).unwrap();
            }
            done.send(()).unwrap();
            // The write end closes here, as when QEMU exits.
        });
        finished
            .recv_timeout(Duration::from_secs(60))
            .expect("the writer blocked on a full pipe");
        flood.join().unwrap();
        settle(&path, Duration::from_secs(10));
        let saved = std::fs::read(&path).unwrap();
        assert!(saved.len() < 64 * 1024 + 200, "{}", saved.len());
        assert!(String::from_utf8_lossy(&saved).contains("output cut here"));
        assert!(!OPEN.lock().unwrap().contains_key(&path), "thread ended");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_log_that_cannot_be_written_still_drains_the_pipe() {
        let path =
            std::env::temp_dir().join(format!("ant-capped-log-{}", crate::storage::unique_id()));
        let (reader, mut writer) = std::io::pipe().unwrap();
        // A read-only handle: every write fails.
        File::create(&path).unwrap();
        let file = File::open(&path).unwrap();
        spawn_capped(reader, file, &path, 1024);
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            writer.write_all(&vec![b'q'; 1 << 20]).unwrap();
            done.send(()).unwrap();
        });
        finished
            .recv_timeout(Duration::from_secs(60))
            .expect("the writer blocked on a full pipe");
        settle(&path, Duration::from_secs(10));
        std::fs::remove_file(path).unwrap();
    }
}
