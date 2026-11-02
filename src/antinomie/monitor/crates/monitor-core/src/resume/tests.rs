// SPDX-License-Identifier: GPL-3.0-only
//! Resume and restart against a loopback HTTP server that understands (or
//! refuses) byte ranges.
use super::*;
use crate::cancel::CancelToken;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// How the test server answers.
#[derive(Clone)]
struct Behaviour {
    body: Vec<u8>,
    /// Answers `Range` with 206; when false the whole file comes back (200).
    ranges: bool,
    etag: String,
}

struct Server {
    port: u16,
    behaviour: Arc<Mutex<Behaviour>>,
    /// The `Range` header of every request (empty when none).
    ranges_seen: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Server {
    fn start(body: Vec<u8>, ranges: bool, etag: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let behaviour = Arc::new(Mutex::new(Behaviour {
            body,
            ranges,
            etag: etag.into(),
        }));
        let ranges_seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (shared, seen, halt) = (behaviour.clone(), ranges_seen.clone(), stop.clone());
        std::thread::spawn(move || {
            while !halt.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (shared, seen) = (shared.clone(), seen.clone());
                        std::thread::spawn(move || serve(stream, &shared, &seen));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Self {
            port,
            behaviour,
            ranges_seen,
            stop,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/file", self.port)
    }

    fn change(&self, body: Vec<u8>, etag: &str) {
        let mut guard = self.behaviour.lock().unwrap();
        guard.body = body;
        guard.etag = etag.into();
    }

    fn ranges(&self) -> Vec<String> {
        self.ranges_seen.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn serve(mut stream: TcpStream, shared: &Mutex<Behaviour>, seen: &Mutex<Vec<String>>) {
    stream.set_nonblocking(false).unwrap();
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&request).into_owned();
    let header = |name: &str| {
        text.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    };
    let behaviour = shared.lock().unwrap().clone();
    let range = header("Range");
    seen.lock().unwrap().push(range.clone().unwrap_or_default());
    let start = range
        .as_deref()
        .and_then(|r| r.strip_prefix("bytes="))
        .and_then(|r| r.strip_suffix('-'))
        .and_then(|r| r.parse::<usize>().ok());
    // If-Range: a validator that is not the current one asks for the whole file.
    let valid = header("If-Range").is_none_or(|v| v == behaviour.etag);
    let total = behaviour.body.len();
    let (status, from) = match start {
        Some(from) if behaviour.ranges && valid && from < total => ("206 Partial Content", from),
        _ => ("200 OK", 0),
    };
    let mut head = format!(
        "HTTP/1.1 {status}\r\nETag: {}\r\nContent-Length: {}\r\n",
        behaviour.etag,
        total - from
    );
    if from > 0 {
        head.push_str(&format!(
            "Content-Range: bytes {from}-{}/{total}\r\n",
            total - 1
        ));
    }
    head.push_str("\r\n");
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    // Slowly enough for the test to cancel part-way through.
    for piece in behaviour.body[from..].chunks(8192) {
        if stream.write_all(piece).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ant-resume-{tag}-{}-{}",
        std::process::id(),
        crate::storage::unique_id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Fetch `url` into `dest`, cancelling once `cancel_at` bytes are there.
fn run(
    url: &str,
    dest: &Path,
    item: &Item,
    cancel_at: Option<u64>,
) -> (Result<(), String>, Vec<String>) {
    let token = CancelToken::new();
    let mut notes = Vec::new();
    let result = fetch(
        Path::new("curl"),
        url,
        dest,
        item,
        &token,
        "download",
        Duration::from_millis(20),
        || {
            if cancel_at.is_some_and(|at| file_len(dest) >= at) {
                token.cancel();
            }
        },
        &mut |line| notes.push(line.to_owned()),
    );
    (result, notes)
}

fn item<'a>(key: &'a str, size: usize) -> Item<'a> {
    Item {
        label: "Test item",
        key,
        size: Some(size as u64),
    }
}

#[test]
fn a_cancelled_download_resumes_with_a_range_request() {
    let data = body(2_000_000, 1);
    let server = Server::start(data.clone(), true, "\"v1\"");
    let dir = scratch("resume");
    let dest = dir.join("file");
    let item = item("k1", data.len());
    let (first, notes) = run(&server.url(), &dest, &item, Some(300_000));
    assert!(first.unwrap_err().ends_with("cancelled"));
    assert!(notes.is_empty(), "a fresh start says nothing: {notes:?}");
    let kept = file_len(&dest);
    assert!(kept >= 300_000 && kept < data.len() as u64, "{kept}");
    assert_eq!(kept_size(&dest), kept);
    let (second, notes) = run(&server.url(), &dest, &item, None);
    second.unwrap();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].starts_with("Resuming Test item from "),
        "{notes:?}"
    );
    assert_eq!(fs::read(&dest).unwrap(), data);
    assert!(
        server
            .ranges()
            .iter()
            .any(|r| r.starts_with("bytes=") && r != "bytes=0-"),
        "{:?}",
        server.ranges()
    );
    assert!(!record_path(&dest).exists() && !headers_path(&dest).exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_server_without_range_support_restarts_without_an_error() {
    let data = body(1_500_000, 2);
    let server = Server::start(data.clone(), false, "\"v1\"");
    let dir = scratch("norange");
    let dest = dir.join("file");
    let item = item("k1", data.len());
    run(&server.url(), &dest, &item, Some(200_000))
        .0
        .unwrap_err();
    let (second, notes) = run(&server.url(), &dest, &item, None);
    second.unwrap();
    assert!(notes[0].starts_with("Resuming "), "{notes:?}");
    assert!(
        notes
            .last()
            .unwrap()
            .starts_with("Starting Test item again: "),
        "{notes:?}"
    );
    assert_eq!(fs::read(&dest).unwrap(), data);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_changed_etag_restarts_from_zero_and_gives_the_new_file() {
    let data = body(1_500_000, 3);
    let server = Server::start(data, true, "\"v1\"");
    let dir = scratch("etag");
    let dest = dir.join("file");
    let item = item("k1", 1_500_000);
    run(&server.url(), &dest, &item, Some(200_000))
        .0
        .unwrap_err();
    let newer = body(1_500_000, 4);
    server.change(newer.clone(), "\"v2\"");
    let (second, notes) = run(&server.url(), &dest, &item, None);
    second.unwrap();
    assert!(
        notes
            .last()
            .unwrap()
            .starts_with("Starting Test item again: "),
        "{notes:?}"
    );
    assert_eq!(fs::read(&dest).unwrap(), newer, "no bytes of the old file");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_partial_that_does_not_match_the_item_starts_again() {
    let data = body(500_000, 5);
    let server = Server::start(data.clone(), true, "\"v1\"");
    let dir = scratch("mismatch");
    let dest = dir.join("file");
    // No record at all: a stray file is never trusted.
    fs::write(&dest, b"stray bytes").unwrap();
    let (result, notes) = run(&server.url(), &dest, &item("k1", data.len()), None);
    result.unwrap();
    assert!(notes[0].contains("nothing records"), "{notes:?}");
    assert_eq!(fs::read(&dest).unwrap(), data);
    // A record for another key (the pinned hash changed).
    fs::write(&dest, b"old item").unwrap();
    write_record(
        &dest,
        &Record {
            key: "other".into(),
            ..Record::default()
        },
    );
    let (result, notes) = run(&server.url(), &dest, &item("k1", data.len()), None);
    result.unwrap();
    assert!(notes[0].contains("item changed"), "{notes:?}");
    // A partial bigger than the item.
    fs::write(&dest, body(600_000, 9)).unwrap();
    write_record(
        &dest,
        &Record {
            key: "k1".into(),
            ..Record::default()
        },
    );
    let (result, notes) = run(&server.url(), &dest, &item("k1", data.len()), None);
    result.unwrap();
    assert!(notes[0].contains("larger"), "{notes:?}");
    assert_eq!(fs::read(&dest).unwrap(), data);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancel_before_any_byte_arrived_keeps_nothing() {
    let dir = scratch("empty");
    let dest = dir.join("file");
    let token = CancelToken::new();
    token.cancel();
    let result = fetch(
        Path::new("curl"),
        "http://127.0.0.1:9/file",
        &dest,
        &item("k", 10),
        &token,
        "download",
        Duration::from_millis(20),
        || {},
        &mut |_| {},
    );
    assert!(result.unwrap_err().ends_with("cancelled"));
    assert!(fs::read_dir(&dir).unwrap().next().is_none());
    fs::remove_dir_all(dir).unwrap();
}

/// A corrupt partial that the server happily extends: the finished file fails
/// its hash, the download starts again once from zero and succeeds.
#[test]
fn a_corrupt_partial_fails_its_hash_and_one_clean_retry_follows() {
    use crate::distribution::{CatalogBase, CatalogFile, download_base};
    let data = body(900_000, 6);
    let server = Server::start(data.clone(), true, "\"v1\"");
    let dir = scratch("corrupt");
    let staging = dir.join("downloads").join("id1");
    fs::create_dir_all(&staging).unwrap();
    let sha = {
        let file = dir.join("good");
        fs::write(&file, &data).unwrap();
        crate::distribution::sha256_file(&file).unwrap()
    };
    let base = CatalogBase {
        identity: "id1".into(),
        label: "Test base".into(),
        files: vec![CatalogFile {
            name: "kernel".into(),
            size: data.len() as u64,
            sha256: sha.clone(),
        }],
        ..Default::default()
    };
    // The partial claims to be the right item but its bytes are wrong.
    let kernel = staging.join("kernel");
    fs::write(&kernel, vec![0xAAu8; 100_000]).unwrap();
    write_record(
        &kernel,
        &Record {
            key: format!("id1/kernel:{}:{sha}", data.len()),
            ..Record::default()
        },
    );
    let mut notes = Vec::new();
    // The files live at <remote>/bases/<identity>/<name>; the server answers every path.
    let remote = format!("http://127.0.0.1:{}", server.port);
    let error = download_base(
        Path::new("curl"),
        &remote,
        &base,
        &staging,
        &AtomicBool::new(false),
        |_, _| {},
        &mut |line| notes.push(line.to_owned()),
    );
    // The bundle file is missing in this fixture, which is after the check.
    assert!(error.is_err());
    assert!(notes[0].starts_with("Resuming Test base"), "{notes:?}");
    assert!(
        notes.iter().any(|n| n.contains("failed its SHA-256 check")),
        "{notes:?}"
    );
    assert_eq!(fs::read(&kernel).unwrap(), data, "the clean retry won");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancelled_build_restarts_and_only_mentions_a_kept_download() {
    let dir = scratch("build");
    assert!(cancelled_build_text(&dir).contains("starts from the beginning"));
    assert!(!cancelled_build_text(&dir).contains("kept"));
    let inputs = dir.join("build/inputs");
    fs::create_dir_all(&inputs).unwrap();
    let part = inputs.join("linux.tar.xz.part");
    fs::write(&part, vec![0u8; 3 * 1024 * 1024]).unwrap();
    // Without its record the file is not a resumable download.
    assert!(!cancelled_build_text(&dir).contains("kept"));
    write_record(&part, &Record::default());
    let text = cancelled_build_text(&dir);
    assert!(
        text.starts_with("Cancelled. A new build starts from the beginning"),
        "{text}"
    );
    assert!(
        text.contains("3.0 MiB already downloaded is kept"),
        "{text}"
    );
    fs::remove_dir_all(dir).unwrap();
}
