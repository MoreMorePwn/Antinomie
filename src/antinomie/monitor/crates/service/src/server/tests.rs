// SPDX-License-Identifier: GPL-3.0-only
//! The local socket over a real Unix socket (design 5.9, T9 socket cases):
//! the folder and file modes, the peer check, the hello, every limit and
//! every refusal, `cancel`, and the event stream's resume.

use super::{
    CallContext, Handler, Server, admits,
    client::{Client, ClientError, Streamed},
    frame::MAX_LINE,
    limits::Limits,
    peer_uid,
};
use crate::{
    api::{
        error::{ApiError, ErrorCode, ErrorReason},
        event::{EventBody, Hello, HelloOwner},
        ids::RunId,
        run::Outcome,
    },
    store::tests::{Fx, lane},
    store::{Eligibility, Store},
};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

/// A handler over a store: `run.get`, `echo`, and `slow` (answers when
/// cancelled, or after 10 s).
struct TestHandler {
    store: Arc<Store>,
}

impl Handler for TestHandler {
    fn hello(&self) -> Hello {
        Hello {
            api_version: crate::API_VERSION,
            app_version: "test".into(),
            owner: HelloOwner::Daemon,
            epoch: self.store.epoch().into(),
            gseq: self.store.highest_gseq().unwrap(),
            truncated: false,
        }
    }

    fn call(&self, op: &str, params: Value, ctx: &CallContext) -> Result<Value, ApiError> {
        match op {
            "echo" => Ok(json!({"params": params, "client": ctx.caller.client_id})),
            "slow" => {
                let until = Instant::now() + Duration::from_secs(10);
                while Instant::now() < until {
                    if ctx.cancel.load(Ordering::SeqCst) {
                        return Err(ApiError::new(ErrorCode::Unavailable, "cancelled")
                            .with_reason(ErrorReason::Cancelled));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(json!("late"))
            }
            "big" => Ok(json!({"blob": "x".repeat(MAX_LINE)})),
            _ => Err(ApiError::invalid_argument("op", "unknown")),
        }
    }

    fn store(&self) -> &Store {
        &self.store
    }
}

struct Sock {
    fx: Fx,
    path: PathBuf,
    handle: super::StopHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    store: Arc<Store>,
}

impl Drop for Sock {
    fn drop(&mut self) {
        self.handle.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_dir_all(&self.fx.dir);
    }
}

fn quick() -> Limits {
    Limits {
        tick: Duration::from_millis(20),
        ping_every: Duration::from_millis(300),
        ..Limits::default()
    }
}

fn serve(name: &str, limits: Limits) -> Sock {
    let fx = Fx::new(&format!("sock-{name}"));
    let store = Arc::new(Store::open(&fx.dir.join("service2")).unwrap());
    let path = fx.dir.join("run").join("antinomie.sock");
    let handler = Arc::new(TestHandler {
        store: Arc::clone(&store),
    });
    let server = Server::bind(&path, handler, limits).unwrap();
    let handle = server.stop_handle();
    let thread = std::thread::spawn(move || server.serve());
    Sock {
        fx,
        path,
        handle,
        thread: Some(thread),
        store,
    }
}

fn connect(sock: &Sock) -> Client {
    Client::connect(&sock.path, Duration::from_secs(5)).unwrap()
}

fn api_error(result: Result<Value, ClientError>) -> ApiError {
    match result {
        Err(ClientError::Api(error)) => error,
        other => panic!("expected an error reply, got {other:?}"),
    }
}

fn reason(error: &ApiError) -> Option<ErrorReason> {
    error.reason()
}

/// Read raw lines until the server closes the connection.
fn read_until_closed(stream: &mut UnixStream, limit: Duration) -> (Vec<Value>, bool) {
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let until = Instant::now() + limit;
    let mut bytes = Vec::new();
    let mut closed = false;
    while Instant::now() < until {
        let mut chunk = [0u8; 65536];
        match stream.read(&mut chunk) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                closed = true;
                break;
            }
        }
    }
    let lines = bytes
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_slice(l).ok())
        .collect();
    (lines, closed)
}

#[test]
fn the_socket_is_0600_in_a_0700_folder_and_answers_with_the_hello_first() {
    let sock = serve("modes", quick());
    let meta = std::fs::symlink_metadata(&sock.path).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let dir = std::fs::metadata(sock.path.parent().unwrap()).unwrap();
    assert_eq!(dir.permissions().mode() & 0o777, 0o700);

    // The very first line is the hello frame itself, with no request id.
    let mut raw = UnixStream::connect(&sock.path).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut first = Vec::new();
    let mut byte = [0u8; 1];
    while raw.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
        first.push(byte[0]);
    }
    let hello: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(hello["frame"], "engine.hello");
    assert_eq!(hello["data"]["api_version"], 1);
    assert_eq!(hello["data"]["owner"], "daemon");
    assert_eq!(hello["data"]["truncated"], false);
    assert!(hello.get("id").is_none());

    // The caller is the peer's own uid, whatever the request says.
    let mut client = connect(&sock);
    let echo = client
        .call("echo", json!({"client_id": "web:mallory"}))
        .unwrap();
    let uid = rustix::process::geteuid().as_raw();
    assert_eq!(echo["client"], format!("local:{uid}"));
}

#[test]
fn only_a_peer_with_the_daemons_uid_is_admitted() {
    assert!(admits(Ok(1000), 1000));
    assert!(!admits(Ok(0), 1000));
    assert!(!admits(Ok(1001), 1000));
    assert!(!admits(Err(std::io::ErrorKind::Other.into()), 1000));
    // The credentials of a real connection are this process's.
    let (a, _b) = UnixStream::pair().unwrap();
    assert_eq!(peer_uid(&a).unwrap(), rustix::process::geteuid().as_raw());
}

#[test]
fn a_folder_others_can_reach_or_a_file_in_the_sockets_place_is_refused() {
    let fx = Fx::new("sock-refuse");
    let store = Arc::new(Store::open(&fx.dir.join("svc")).unwrap());
    let handler = || {
        Arc::new(TestHandler {
            store: Arc::clone(&store),
        }) as Arc<dyn Handler>
    };
    // A group-writable folder.
    let open = fx.dir.join("open");
    std::fs::create_dir_all(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o770)).unwrap();
    let error = Server::bind(&open.join("s.sock"), handler(), quick())
        .err()
        .unwrap();
    assert!(error.to_string().contains("0700"), "{error}");
    // A symlinked folder.
    let real = fx.dir.join("real");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real, fx.dir.join("link")).unwrap();
    assert!(Server::bind(&fx.dir.join("link").join("s.sock"), handler(), quick()).is_err());
    // A regular file where the socket goes is left alone.
    let file = real.join("s.sock");
    std::fs::write(&file, b"keep me").unwrap();
    assert!(Server::bind(&file, handler(), quick()).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
    std::fs::remove_file(&file).unwrap();
    // A stale socket (no one serves it) is replaced.
    let stale = std::os::unix::net::UnixListener::bind(&file).unwrap();
    drop(stale);
    let server = Server::bind(&file, handler(), quick()).unwrap();
    assert!(UnixStream::connect(&file).is_ok());
    drop(server);
    // Dropping the server removes its own socket.
    assert!(!file.exists());
    let _ = std::fs::remove_dir_all(&fx.dir);
}

#[test]
fn a_line_above_two_mebibytes_is_refused_and_the_connection_closes() {
    let sock = serve("long", quick());
    let mut client = connect(&sock);
    let mut long = br#"{"id":1,"op":"echo","params":{"a":""#.to_vec();
    long.extend(std::iter::repeat_n(b'x', MAX_LINE));
    long.extend_from_slice(b"\"}}\n");
    // The server may close before the whole line is written.
    let _ = client.send_raw(&long);
    let line = client.read_line().unwrap();
    let reply: Value = serde_json::from_slice(&line).unwrap();
    assert_eq!(reply["error"]["code"], "payload_too_large");
    assert!(matches!(client.read_line(), Err(ClientError::Io(_))));
}

#[test]
fn an_oversized_reply_is_an_error_for_its_request_and_the_connection_lives() {
    let sock = serve("bigreply", quick());
    let mut client = connect(&sock);
    let error = api_error(client.call("big", json!({})));
    assert_eq!(error.code, ErrorCode::PayloadTooLarge);
    assert!(client.call("echo", json!({})).is_ok());
}

#[test]
fn malformed_lines_get_an_error_and_the_connection_stays_open() {
    let sock = serve("malformed", quick());
    let mut client = connect(&sock);
    for bad in [
        "not json\n",
        "{\"op\":\"echo\"}\n",
        "{\"id\":5,\"op\":\"echo\",\"x\":1}\n",
    ] {
        client.send_raw(bad.as_bytes()).unwrap();
        let reply: Value = serde_json::from_slice(&client.read_line().unwrap()).unwrap();
        assert_eq!(reply["ok"], false, "{bad}");
        assert_eq!(reply["error"]["code"], "invalid_argument");
    }
    assert!(client.call("echo", json!({"still": "here"})).is_ok());
}

#[test]
fn sixteen_requests_may_be_in_flight_and_a_cancel_ends_one() {
    let sock = serve("inflight", quick());
    let mut client = connect(&sock);
    for id in 1..=16 {
        client
            .send_raw(format!("{{\"id\":{id},\"op\":\"slow\"}}\n").as_bytes())
            .unwrap();
    }
    // Give the server a moment to register them, then one too many.
    std::thread::sleep(Duration::from_millis(200));
    client.send_raw(b"{\"id\":17,\"op\":\"slow\"}\n").unwrap();
    let reply: Value = serde_json::from_slice(&client.read_line().unwrap()).unwrap();
    assert_eq!(reply["id"], 17);
    assert_eq!(reply["error"]["code"], "quota_exceeded");
    assert_eq!(reply["error"]["details"]["reason"], "too_many_requests");
    // An id that is in flight cannot be used again.
    client.send_raw(b"{\"id\":3,\"op\":\"echo\"}\n").unwrap();
    let reply: Value = serde_json::from_slice(&client.read_line().unwrap()).unwrap();
    assert_eq!(
        (reply["id"].clone(), reply["error"]["code"].clone()),
        (json!(3), json!("conflict"))
    );
    // Cancel request 5: it answers for itself.
    client.send_raw(b"{\"id\":5,\"op\":\"cancel\"}\n").unwrap();
    let reply: Value = serde_json::from_slice(&client.read_line().unwrap()).unwrap();
    assert_eq!(reply["id"], 5);
    assert_eq!(reply["error"]["details"]["reason"], "cancelled");
    // A cancel of nothing in flight is not_found.
    client.send_raw(b"{\"id\":99,\"op\":\"cancel\"}\n").unwrap();
    let reply: Value = serde_json::from_slice(&client.read_line().unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], "not_found");
}

#[test]
fn requests_faster_than_the_rate_are_refused_with_a_retry_time() {
    let sock = serve(
        "rate",
        Limits {
            rate_per_s: 1.0,
            burst: 3.0,
            ..quick()
        },
    );
    let mut client = connect(&sock);
    for _ in 0..3 {
        client.call("echo", json!({})).unwrap();
    }
    let error = api_error(client.call("echo", json!({})));
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(reason(&error), Some(ErrorReason::RateLimited));
    assert!(error.details["retry_after_s"].as_u64().unwrap() >= 1);
}

#[test]
fn a_connection_above_the_limit_is_told_why_and_closed() {
    let sock = serve(
        "conns",
        Limits {
            connections: 2,
            ..quick()
        },
    );
    let _a = connect(&sock);
    let _b = connect(&sock);
    match Client::connect(&sock.path, Duration::from_secs(5)) {
        Err(ClientError::Api(error)) => {
            assert_eq!(error.code, ErrorCode::Unavailable);
            assert_eq!(reason(&error), Some(ErrorReason::TooManyConnections));
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
    drop(_a);
    // A slot frees once the closed connection is noticed.
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if Client::connect(&sock.path, Duration::from_secs(5)).is_ok() {
            break;
        }
        assert!(Instant::now() < until, "the slot never came back");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn an_idle_connection_and_a_line_left_unfinished_are_closed() {
    let sock = serve(
        "idle",
        Limits {
            idle: Duration::from_millis(300),
            partial_line: Duration::from_millis(300),
            ..quick()
        },
    );
    let mut idle = UnixStream::connect(&sock.path).unwrap();
    let (lines, closed) = read_until_closed(&mut idle, Duration::from_secs(5));
    assert!(closed, "the idle connection stayed open");
    assert_eq!(lines.len(), 1, "only the hello: {lines:?}");

    let mut slow = UnixStream::connect(&sock.path).unwrap();
    // Keep the connection busy with half a line: still closed, after the
    // partial-line limit (not the longer idle one).
    slow.write_all(b"{\"id\":1,\"op\":").unwrap();
    let began = Instant::now();
    let (_, closed) = read_until_closed(&mut slow, Duration::from_secs(5));
    assert!(closed && began.elapsed() < Duration::from_secs(5));
}

#[test]
fn subscriptions_are_capped_per_client() {
    let sock = serve(
        "subs",
        Limits {
            subscriptions_per_client: 1,
            ..quick()
        },
    );
    let mut first = connect(&sock);
    first
        .send_raw(b"{\"id\":1,\"op\":\"events.subscribe\",\"params\":{}}\n")
        .unwrap();
    // Its hello.
    let hello: Value = serde_json::from_slice(&first.read_line().unwrap()).unwrap();
    assert_eq!(hello["frame"], "engine.hello");
    assert_eq!(hello["id"], 1);
    let mut second = connect(&sock);
    let error = api_error(second.subscribe(json!({}), &mut |_| true));
    assert_eq!(reason(&error), Some(ErrorReason::TooManySubscriptions));
    // The first one ends on cancel; then the second may subscribe.
    first.send_raw(b"{\"id\":1,\"op\":\"cancel\"}\n").unwrap();
    let end: Value = serde_json::from_slice(&first.read_line().unwrap()).unwrap();
    assert_eq!(end["result"]["cancelled"], true);
    std::thread::sleep(Duration::from_millis(100));
    let mut seen = 0;
    let result = second.subscribe(json!({}), &mut |line| {
        seen += 1;
        !matches!(line, Streamed::Hello(_))
    });
    assert_eq!(result.unwrap()["cancelled"], true);
    assert_eq!(seen, 1);
}

fn alert(store: &Store, n: u32) {
    store
        .emit_engine(EventBody::EngineAlert {
            code: "test".into(),
            text: format!("alert {n}"),
        })
        .unwrap();
}

/// The all-jobs stream: kill the client in the middle while events keep
/// coming, resume from the last `gseq` seen, and the two halves are exactly
/// the table: no gap, no duplicate.
#[test]
fn a_client_killed_mid_stream_resumes_by_gseq_without_a_gap_or_a_duplicate() {
    let sock = serve("resume", quick());
    let store = Arc::clone(&sock.store);
    for n in 0..50 {
        alert(&store, n);
    }
    let producer = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            for n in 50..400 {
                alert(&store, n);
                if n % 25 == 0 {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        })
    };
    let mut got = Vec::new();
    {
        let mut client = connect(&sock);
        // Stop after 120 events: the connection is dropped without a cancel.
        let _ = client.subscribe(json!({"since_gseq": 0}), &mut |line| {
            if let Streamed::Event(event) = line {
                got.push(event.gseq.unwrap());
            }
            got.len() < 120
        });
    }
    let last = *got.last().unwrap();
    let mut client = connect(&sock);
    let mut hello = None;
    let target = 400;
    let _ = client.subscribe(json!({"since_gseq": last}), &mut |line| match line {
        Streamed::Hello(h) => {
            hello = Some(h);
            true
        }
        Streamed::Event(event) => {
            got.push(event.gseq.unwrap());
            got.len() < target
        }
        Streamed::Ping => true,
    });
    producer.join().unwrap();
    assert!(!hello.unwrap().truncated);
    let table: Vec<u64> = store
        .events_since(0, 10_000)
        .unwrap()
        .iter()
        .map(|e| e.gseq.unwrap())
        .collect();
    // The first stream may have read past its 120th line before closing.
    let mut dedup = got.clone();
    dedup.dedup();
    assert_eq!(dedup.len(), got.len(), "a duplicate was sent");
    assert_eq!(got, table[..got.len()].to_vec(), "a gap or a reorder");
    assert_eq!(got.len(), 400);
}

#[test]
fn a_job_stream_carries_only_that_job_from_its_resume_point_and_ends_after_it_finishes() {
    let sock = serve("jobstream", quick());
    let fx = &sock.fx;
    // Jobs in the socket's own store.
    let ctx = fx.ctx();
    let caller = crate::store::tests::caller(1000);
    let submit = |n: u8| {
        sock.store
            .submit(&caller, crate::store::tests::spec(n), &ctx)
            .unwrap()
            .run
    };
    let mine = submit(1);
    let other = submit(2);
    let claim = || {
        sock.store
            .claim_next(&lane(), &mut |_| Eligibility::Ready)
            .unwrap()
            .unwrap()
    };
    let first = claim();
    assert_eq!(first.id, mine.id);
    let (events, _) = sock.store.events_list(&mine.id, 0, 100).unwrap();
    let resume_at = events[1].seq.unwrap();

    let stream = {
        let path = sock.path.clone();
        let id = mine.id.clone();
        std::thread::spawn(move || {
            let mut client = Client::connect(&path, Duration::from_secs(5)).unwrap();
            let mut seen = Vec::new();
            let end = client
                .subscribe(json!({"run_id": id, "since_seq": resume_at}), &mut |line| {
                    if let Streamed::Event(event) = line {
                        seen.push((event.run_id.clone(), event.seq));
                    }
                    true
                })
                .unwrap();
            (seen, end)
        })
    };
    std::thread::sleep(Duration::from_millis(200));
    // The other job's events interleave; they must not be sent.
    sock.store.add_warning(&first.id, "w", "mine").unwrap();
    sock.store
        .finish(&first.id, Outcome::Succeeded, None)
        .unwrap();
    let second = claim();
    assert_eq!(second.id, other.id);
    sock.store.add_warning(&other.id, "w", "other").unwrap();
    let (seen, end) = stream.join().unwrap();
    assert_eq!(end["finished"], true);
    let (all, _) = sock.store.events_list(&mine.id, resume_at, 100).unwrap();
    let expected: Vec<(Option<RunId>, Option<u64>)> =
        all.iter().map(|e| (e.run_id.clone(), e.seq)).collect();
    assert_eq!(seen, expected);
    assert!(seen.iter().all(|(job, _)| job.as_ref() == Some(&mine.id)));
}

#[test]
fn a_resume_point_the_store_never_reached_or_no_longer_keeps_is_truncated() {
    let sock = serve("truncated", quick());
    for n in 0..5 {
        alert(&sock.store, n);
    }
    let hello_of = |params: Value| {
        let mut client = connect(&sock);
        let mut hello = None;
        let _ = client.subscribe(params, &mut |line| {
            if let Streamed::Hello(h) = line {
                hello = Some(h);
            }
            false
        });
        hello.unwrap()
    };
    assert!(!hello_of(json!({"since_gseq": 2})).truncated);
    let future = hello_of(json!({"since_gseq": 1000}));
    assert!(future.truncated);
    assert_eq!(future.gseq, 5);
    // Engine events older than the retention are pruned: a resume point
    // before them is truncated.
    // (The socket's store runs on the system clock: delete the rows.)
    sock.store
        .conn()
        .execute("DELETE FROM events WHERE gseq <= 3", [])
        .unwrap();
    assert!(hello_of(json!({"since_gseq": 1})).truncated);
    assert!(!hello_of(json!({"since_gseq": 3})).truncated);
}

#[test]
fn a_bad_subscription_is_refused_before_any_line() {
    let sock = serve("badsub", quick());
    let mut client = connect(&sock);
    let unknown = RunId::try_from("j_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()).unwrap();
    for (params, field) in [
        (json!({"since_seq": 3}), Some("since_seq")),
        (
            json!({"run_id": unknown, "since_gseq": 3}),
            Some("since_gseq"),
        ),
        (json!({"types": ["job.nope"]}), Some("types")),
        (json!({"types": []}), Some("types")),
        (json!({"surprise": 1}), None),
    ] {
        let error = api_error(client.subscribe(params.clone(), &mut |_| true));
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{params}");
        if let Some(field) = field {
            assert_eq!(error.field.as_deref(), Some(field), "{params}");
        }
    }
    let error = api_error(client.subscribe(json!({"run_id": unknown}), &mut |_| true));
    assert_eq!(error.code, ErrorCode::NotFound);
}

#[test]
fn a_quiet_subscription_is_pinged_and_types_filter_the_stream() {
    let sock = serve("ping", quick());
    let mut client = connect(&sock);
    let mut pings = 0;
    let mut kinds = Vec::new();
    let store = Arc::clone(&sock.store);
    let producer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(700));
        alert(&store, 1);
        store
            .emit_engine(EventBody::LaneState {
                lane: lane(),
                state: crate::api::event::LaneState::Idle,
                run_id: None,
                reason: None,
            })
            .unwrap();
        alert(&store, 2);
    });
    let _ = client.subscribe(json!({"types": ["engine.alert"]}), &mut |line| {
        match line {
            Streamed::Ping => pings += 1,
            Streamed::Event(event) => kinds.push(event.body.clone()),
            Streamed::Hello(_) => {}
        }
        kinds.len() < 2
    });
    producer.join().unwrap();
    assert!(pings >= 1, "no ping in 700 ms with a 300 ms period");
    assert!(
        kinds
            .iter()
            .all(|body| matches!(body, EventBody::EngineAlert { .. }))
    );
}

/// A subscriber that falls behind the store's channel loses nothing: the
/// stream reads the table again from the last event it sent.
#[test]
fn an_overflowing_subscription_is_refilled_from_the_table() {
    let sock = serve(
        "overflow",
        Limits {
            subscription_backlog: 4,
            ..quick()
        },
    );
    let mut client = connect(&sock);
    let store = Arc::clone(&sock.store);
    let producer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        for n in 0..300 {
            alert(&store, n);
        }
    });
    let mut got = Vec::new();
    let _ = client.subscribe(json!({}), &mut |line| {
        if let Streamed::Event(event) = line {
            got.push(event.gseq.unwrap());
            // A slow reader.
            if got.len() % 50 == 0 {
                std::thread::sleep(Duration::from_millis(30));
            }
        }
        got.len() < 300
    });
    producer.join().unwrap();
    assert_eq!(got, (1..=300).collect::<Vec<u64>>());
}

/// A client that stops reading is closed once a line cannot be written
/// within the write timeout; the store forgets its subscription.
#[test]
fn a_client_that_stops_reading_is_disconnected_as_a_slow_consumer() {
    let sock = serve(
        "slowconsumer",
        Limits {
            write_timeout: Duration::from_millis(200),
            ..quick()
        },
    );
    let mut raw = UnixStream::connect(&sock.path).unwrap();
    raw.write_all(b"{\"id\":1,\"op\":\"events.subscribe\",\"params\":{}}\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let base = sock.store.subscriber_count();
    assert!(base >= 1);
    // Far more than the socket buffers hold, while the client reads nothing.
    let text = "y".repeat(20_000);
    for _ in 0..600 {
        sock.store
            .emit_engine(EventBody::EngineAlert {
                code: "flood".into(),
                text: text.clone(),
            })
            .unwrap();
    }
    std::thread::sleep(Duration::from_millis(1500));
    let (lines, closed) = read_until_closed(&mut raw, Duration::from_secs(10));
    assert!(closed, "the slow consumer was not disconnected");
    let events = lines.iter().filter(|l| l.get("event").is_some()).count();
    assert!(events < 600, "every event arrived: {events}");
    // The next publish drops the dead subscription.
    alert(&sock.store, 0);
    assert!(sock.store.subscriber_count() < base);
}

/// Concurrent writers: a live subscriber sees `gseq` strictly rising (the
/// store publishes in commit order, which the resume relies on).
#[test]
fn the_store_publishes_in_commit_order_under_concurrent_writers() {
    let fx = Fx::new("order");
    let store = Arc::new(Store::open(&fx.dir.join("svc")).unwrap());
    let receiver = store.subscribe();
    let writers: Vec<_> = (0..4)
        .map(|_| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for n in 0..100 {
                    alert(&store, n);
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    let seen: Vec<u64> = receiver.try_iter().map(|e| e.gseq.unwrap()).collect();
    assert_eq!(seen, (1..=400).collect::<Vec<u64>>());
    let _ = std::fs::remove_dir_all(&fx.dir);
}

#[test]
fn stopping_the_server_ends_subscriptions_with_service_stopping() {
    let sock = serve("stop", quick());
    let mut client = connect(&sock);
    let handle = sock.handle.clone();
    let stopper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        handle.stop();
    });
    let result = client.subscribe(json!({}), &mut |_| true);
    stopper.join().unwrap();
    match result {
        Err(ClientError::Api(error)) => {
            assert_eq!(reason(&error), Some(ErrorReason::ServiceStopping))
        }
        // The connection may close before the last line is read.
        Err(ClientError::Io(_)) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn path_helper_is_inside_the_scratch_dir() {
    // Keeps the helper's paths short enough for a Unix socket (108 bytes).
    let sock = serve("pathlen", quick());
    assert!(sock.path.as_os_str().len() < 100, "{}", sock.path.display());
    assert!(Path::new(&sock.path).starts_with(&sock.fx.dir));
}
