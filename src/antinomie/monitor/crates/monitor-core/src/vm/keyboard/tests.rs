// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
};

fn serve(
    cancel_after_first: bool,
    reject: bool,
) -> (Job, JoinHandle<Vec<serde_json::Value>>, PathBuf) {
    let root = std::env::temp_dir().join(format!("ant-keys-{}", crate::storage::unique_id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("qmp.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let epoch = Arc::new(AtomicU64::new(0));
    let changed = epoch.clone();
    let server = thread::spawn(move || {
        let mut commands = Vec::new();
        for _ in 0..if cancel_after_first || reject { 1 } else { 3 } {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            socket.write_all(b"{\"QMP\":{}}\n").unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&line).unwrap()["execute"],
                "qmp_capabilities"
            );
            socket.write_all(b"{\"return\":{}}\n").unwrap();
            line.clear();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            commands.push(serde_json::from_str::<serde_json::Value>(&line).unwrap());
            if cancel_after_first {
                changed.fetch_add(2, Ordering::AcqRel);
            }
            socket
                .write_all(if reject {
                    b"{\"error\":{\"desc\":\"rejected\"}}\n"
                } else {
                    b"{\"return\":{}}\n"
                })
                .unwrap();
            line.clear();
            assert_eq!(
                reader.read_line(&mut line).unwrap(),
                0,
                "release the monitor slot between chords"
            );
        }
        commands
    });
    let job = Job::start(
        path,
        "boot".into(),
        crate::clipboard::Text::prepare("A!\n").unwrap(),
        epoch,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    (job, server, root)
}

fn finish(mut job: Job) -> Result<String, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(result) = job.poll() {
            return result;
        }
        assert!(std::time::Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn qmp_typing_sequences_shift_and_returns_completion() {
    let (job, server, root) = serve(false, false);
    assert!(finish(job).unwrap().contains("3 keys"));
    let sent = server.join().unwrap();
    assert_eq!(sent.len(), 3);
    assert_eq!(
        sent[0]["arguments"]["keys"],
        serde_json::json!([
            {"type":"qcode","data":"shift"}, {"type":"qcode","data":"a"}
        ])
    );
    assert_eq!(sent[1]["arguments"]["keys"][1]["data"], "1");
    assert_eq!(sent[2]["arguments"]["keys"][0]["data"], "ret");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn boundary_cancels_and_rejected_keys_are_not_retried() {
    for (cancel, reject, message) in [
        (true, false, "cancelled after 1"),
        (false, true, "no retry"),
    ] {
        let (job, server, root) = serve(cancel, reject);
        assert!(finish(job).unwrap_err().contains(message));
        assert_eq!(server.join().unwrap().len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}
