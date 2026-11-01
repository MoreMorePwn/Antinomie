// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::Stdio,
    sync::atomic::AtomicUsize,
    time::Instant,
};

/// A test HTTP server on a loopback port.
struct Server {
    port: u16,
    /// Connections that ended by the client closing them.
    closed: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

#[derive(Clone, Copy)]
enum Behaviour {
    /// Announce a huge body and keep sending it, a chunk every 10 ms.
    Stream,
    /// Accept, read the request and never answer.
    Silent,
}

impl Server {
    fn start(behaviour: Behaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let closed = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, halt) = (closed.clone(), stop.clone());
        std::thread::spawn(move || {
            while !halt.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (seen, halt) = (seen.clone(), halt.clone());
                        std::thread::spawn(move || serve(stream, behaviour, &seen, &halt));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Self { port, closed, stop }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/file", self.port)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn serve(mut stream: TcpStream, behaviour: Behaviour, closed: &AtomicUsize, halt: &AtomicBool) {
    stream.set_nonblocking(false).unwrap();
    let mut request = [0u8; 2048];
    let _ = stream.read(&mut request);
    match behaviour {
        Behaviour::Silent => {
            // Hold the connection until the client goes away.
            let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
            while !halt.load(Ordering::Relaxed) {
                match stream.read(&mut request) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => break,
                }
            }
            closed.fetch_add(1, Ordering::Relaxed);
        }
        Behaviour::Stream => {
            let head = "HTTP/1.1 200 OK\r\nContent-Length: 1073741824\r\n\r\n";
            if stream.write_all(head.as_bytes()).is_err() {
                return;
            }
            let chunk = [7u8; 16 * 1024];
            while !halt.load(Ordering::Relaxed) {
                if stream.write_all(&chunk).is_err() {
                    closed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ant-cancel-{tag}-{}-{}",
        std::process::id(),
        crate::storage::unique_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `curl` for the test server, started the way every download is started.
fn fetch(url: &str, output: &std::path::Path, max_time: Option<u32>) -> Child {
    crate::http_fetch::command(
        std::path::Path::new("curl"),
        &crate::http_fetch::Options {
            max_time,
            max_filesize: None,
            ..crate::http_fetch::Options::new(0, 0)
        },
    )
    .args(["--noproxy", "*", "-o"])
    .arg(output)
    .arg(url)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
    .expect("curl is needed for the download tests")
}

fn alive(pid: u32) -> bool {
    // A zombie is dead; only its parent has not collected it.
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|stat| !stat.rsplit(") ").next().unwrap_or("").starts_with('Z'))
}

fn cancel_after(token: &CancelToken, pause: Duration) {
    let token = token.clone();
    std::thread::spawn(move || {
        std::thread::sleep(pause);
        token.cancel();
    });
}

#[test]
fn a_cancel_in_the_middle_of_a_body_stops_curl_and_closes_the_connection() {
    let server = Server::start(Behaviour::Stream);
    let dir = scratch("body");
    let file = dir.join("body.bin");
    let mut child = fetch(&server.url(), &file, None);
    let pid = child.id();
    let token = CancelToken::new();
    // Cancel once some of the body has arrived.
    let watched = file.clone();
    let flag = token.clone();
    std::thread::spawn(move || {
        while std::fs::metadata(&watched).map_or(0, |m| m.len()) < 64 * 1024 {
            std::thread::sleep(Duration::from_millis(10));
        }
        flag.cancel();
    });
    let started = Instant::now();
    let outcome = wait(&mut child, &token).unwrap();
    let took = started.elapsed();
    assert!(outcome.is_none(), "reported as cancelled");
    assert!(took < Duration::from_secs(5), "{took:?}");
    assert!(!alive(pid), "curl is gone");
    assert!(std::fs::metadata(&file).unwrap().len() >= 64 * 1024);
    let waiting = Instant::now();
    while server.closed.load(Ordering::Relaxed) == 0 && waiting.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        server.closed.load(Ordering::Relaxed),
        1,
        "connection closed"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancel_does_not_wait_for_a_server_that_never_answers() {
    let server = Server::start(Behaviour::Silent);
    let dir = scratch("silent");
    // No transfer time limit and no stall limit: only the cancel can end it.
    let mut child = fetch(&server.url(), &dir.join("never"), None);
    let pid = child.id();
    let token = CancelToken::new();
    cancel_after(&token, Duration::from_millis(400));
    let started = Instant::now();
    let outcome = wait(&mut child, &token).unwrap();
    let took = started.elapsed();
    assert!(outcome.is_none());
    assert!(took < Duration::from_millis(1500), "{took:?}");
    assert!(!alive(pid));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_transfer_that_ends_by_itself_reports_its_status_and_tick_sees_progress() {
    let dir = scratch("done");
    let mut child = Command::new("sh");
    child.args(["-c", "sleep 0.3; exit 3"]);
    lead_group(&mut child);
    let mut child = child.spawn().unwrap();
    let mut ticks = 0;
    let status = wait_every(
        &mut child,
        &CancelToken::new(),
        Duration::from_millis(100),
        || ticks += 1,
    )
    .unwrap()
    .expect("not cancelled");
    assert_eq!(status.code(), Some(3));
    assert!((2..=8).contains(&ticks), "{ticks}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancel_kills_the_whole_group_not_only_the_child() {
    let dir = scratch("group");
    let pid_file = dir.join("grandchild.pid");
    let mut command = Command::new("sh");
    command.arg("-c").arg(format!(
        "sleep 60 & echo $! > '{}'; wait",
        pid_file.display()
    ));
    lead_group(&mut command);
    let mut child = command.spawn().unwrap();
    let token = CancelToken::new();
    cancel_after(&token, Duration::from_millis(500));
    assert!(wait(&mut child, &token).unwrap().is_none());
    let grandchild: u32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let waiting = Instant::now();
    while alive(grandchild) && waiting.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!alive(grandchild), "the helper the child started is gone");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn capture_keeps_a_bounded_head_and_a_cancel_returns_nothing() {
    let mut spewing = Command::new("sh");
    spewing
        .args(["-c", "yes abcdefgh | head -c 5000000; echo oops >&2"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spewing.spawn().unwrap();
    let got = capture(&mut child, &CancelToken::new(), 1000, 100)
        .unwrap()
        .expect("finished");
    assert!(got.status.success());
    assert_eq!(got.stdout.len(), 1000);
    assert_eq!(got.stderr, b"oops\n");

    let mut idle = Command::new("sh");
    idle.args(["-c", "echo hello; sleep 60"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    lead_group(&mut idle);
    let mut child = idle.spawn().unwrap();
    let token = CancelToken::new();
    cancel_after(&token, Duration::from_millis(300));
    let started = Instant::now();
    assert!(capture(&mut child, &token, 1000, 100).unwrap().is_none());
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn stopping_everything_at_exit_ends_the_children_being_waited_on() {
    let mut command = Command::new("sleep");
    command.arg("60");
    lead_group(&mut command);
    let mut child = command.spawn().unwrap();
    let pid = child.id();
    let never = CancelToken::new();
    let waiter = std::thread::spawn(move || wait(&mut child, &never));
    let waiting = Instant::now();
    while !running().as_ref().is_some_and(|set| set.contains(&pid))
        && waiting.elapsed() < Duration::from_secs(2)
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    // Only this test's child: the other tests run children of their own.
    stop_where(|candidate| candidate == pid);
    let status = waiter
        .join()
        .unwrap()
        .unwrap()
        .expect("ended, not cancelled");
    assert!(!status.success());
    assert!(!alive(pid));
    assert!(running().as_ref().is_none_or(|set| !set.contains(&pid)));
}

#[test]
fn the_token_and_the_error_word_agree() {
    let token = CancelToken::new();
    let copy = token.clone();
    assert!(!token.is_cancelled());
    copy.cancel();
    assert!(token.is_cancelled());
    assert!(token.load(Ordering::Relaxed));
    assert!(is_cancelled("tool installation cancelled"));
    assert!(!is_cancelled("download failed"));
}
