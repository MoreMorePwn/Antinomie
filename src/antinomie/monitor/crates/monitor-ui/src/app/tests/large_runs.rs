// SPDX-License-Identifier: MIT
//! Large-run regressions: archive paging, the process tree and per-frame
//! file lookups stay cheap as a recording grows.
use super::*;
use std::path::Path;

const SIZE: egui::Vec2 = egui::vec2(1400.0, 900.0);

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

fn running_app() -> MonitorApp {
    let mut app = app();
    observer_fixture(&mut app);
    app
}

/// (median, max) milliseconds over `count` frames after a warm-up.
fn heavy_events(pairs: u64) -> Vec<antinomie_monitor_core::EventSummary> {
    const NAMES: [&str; 8] = [
        "read", "write", "openat", "mmap", "futex", "ioctl", "close", "poll",
    ];
    (0..pairs)
        .flat_map(|index| {
            [1u8, 2].map(|phase| {
                let mut e = event(phase, (index % 4) as u32);
                e.call_id = index + 1;
                e.event_seq = index * 2 + u64::from(phase);
                e.timestamp_ns = 1_000_000 + index * 100 + u64::from(phase);
                e.syscall_name = NAMES[(index % 8) as usize].into();
                e.syscall_nr = index % 8;
                e.task_cookie = 3 + index % 5;
                e.tid = 40 + (index % 5) as u32;
                e
            })
        })
        .collect()
}

fn live_app(pairs: u64) -> MonitorApp {
    let mut app = running_app();
    app.snapshot.runs.push(run("r1"));
    app.snapshot.events = heavy_events(pairs);
    app.selected_run = Some("r1".into());
    app
}

// ---------------------------------------------------------------------------
// Confirmed logic bugs

#[test]
fn triage_pcap_lookup_is_cached_between_frames() {
    let dir = std::env::temp_dir().join(format!("bugs-ui-pcap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pcap = dir.join("net.pcap");
    std::fs::write(&pcap, test_pcap()).unwrap();
    let artifacts = antinomie_monitor_core::RunArtifacts {
        run_id: "r1".into(),
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        network_captures: vec![pcap],
        ..Default::default()
    };
    std::fs::write(
        dir.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    let mut app = live_app(0);
    app.snapshot.runs[0].directory = dir.clone();
    assert!(app.owned_triage_pcap().is_some());
    // update() calls this on every frame (and show_triage again): the answer
    // from disk is kept, so a vanished file is not noticed until it expires.
    std::fs::remove_file(dir.join("net.pcap")).unwrap();
    let started = Instant::now();
    for _ in 0..1000 {
        assert!(
            app.owned_triage_pcap().is_some(),
            "the lookup went back to disk within a frame budget"
        );
    }
    eprintln!(
        "owned_triage_pcap: {:?} per call from the cache",
        started.elapsed() / 1000
    );
    // Another selection is looked up fresh.
    let other = std::env::temp_dir().join(format!("bugs-ui-pcap-other-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&other);
    std::fs::create_dir_all(&other).unwrap();
    app.snapshot.runs[0].directory = other.clone();
    assert!(app.owned_triage_pcap().is_none());
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&other).unwrap();
}

#[test]
fn process_tree_panel_cost_is_flat_with_many_orphan_roots() {
    let ctx = context();
    // Processes whose parents were never observed (uncaptured parents,
    // reparented children): every one is a root.
    for (count, first, warm) in [(10_000u32, 150.0, 30.0), (30_000, 400.0, 30.0)] {
        let processes: Vec<_> = (1..=count).map(|pid| process(pid, 4_000_000)).collect();
        let mut times = Vec::new();
        for frame in 0..3 {
            let started = Instant::now();
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                    time: Some(f64::from(frame)),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        super::super::captures::process_tree(ui, &processes, None, 16.0);
                    });
                },
            );
            times.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        eprintln!("process tree, {count} orphan roots: {times:?} ms per frame");
        // The first frame builds the tree; later frames draw the rows in view.
        assert!(times[0] < first, "first frame took {:.0} ms", times[0]);
        assert!(
            times[2] < warm,
            "frame took {:.0} ms (the tree is rebuilt or drawn whole every frame)",
            times[2]
        );
    }
}

fn process(pid: u32, parent: u32) -> antinomie_monitor_core::capture_processes::CaptureProcess {
    antinomie_monitor_core::capture_processes::CaptureProcess {
        pid,
        parent_pid: parent,
        name: format!("proc{pid}"),
        exe: Some(format!("/usr/bin/proc{pid}")),
        at_start: false,
        first_ns: 0,
        last_ns: 1,
        calls: 10,
        packets: 20,
        exited: true,
        exit_code: Some(0),
    }
}

fn archive_fixture(name: &str, calls: u64) -> PathBuf {
    use std::io::Write;
    let directory = std::env::temp_dir().join(format!(
        "bugs-ui-archive-{name}-{}-{}",
        std::process::id(),
        calls
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(directory.join("objects")).unwrap();
    std::fs::write(directory.join("manifest.json"), b"{}").unwrap();
    let mut raw =
        std::io::BufWriter::new(std::fs::File::create(directory.join("telemetry.raw")).unwrap());
    for call in 0..calls {
        let mut packet = vec![0u8; 264];
        packet[..4].copy_from_slice(b"ANTT");
        for (offset, value) in [(4, 1_u16), (6, 2), (8, 144), (10, 1), (96, 1)] {
            packet[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        packet[12..16].copy_from_slice(&264_u32.to_le_bytes());
        packet[20..24].copy_from_slice(&1_u32.to_le_bytes());
        let pid = 100 + (call % 997) as u32;
        for (offset, value) in [
            (24, 9_u64),
            (32, u64::from(pid)),
            (40, call),
            (48, call),
            (56, call),
            (88, 9),
            (128, 99),
            (136, 17),
        ] {
            packet[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        packet[72..76].copy_from_slice(&pid.to_le_bytes());
        packet[76..80].copy_from_slice(&pid.to_le_bytes());
        packet[98] = 1;
        packet[99] = 1;
        packet[120..124].copy_from_slice(&120_u32.to_le_bytes());
        raw.write_all(&264_u32.to_le_bytes()).unwrap();
        raw.write_all(&packet).unwrap();
    }
    raw.flush().unwrap();
    directory
}

/// Answers until `want` accepts one; the others are returned in order.
fn answer_where(
    worker: &ArchiveWorker,
    mut want: impl FnMut(&Answer) -> bool,
) -> (Answer, Vec<Answer>) {
    let mut others = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        assert!(Instant::now() < deadline, "no answer");
        if let Some(answer) = worker.wait_answer(Duration::from_secs(1)) {
            if want(&answer) {
                return (answer, others);
            }
            others.push(answer);
        }
    }
}

fn page_request(directory: &Path, query: &str, offset: u64) -> Request {
    Request::Invocations {
        generation: 1,
        directory: directory.into(),
        offset,
        capture: false,
        pid: None,
        query: query.into(),
        hidden_categories: Vec::new(),
        cancel: Arc::new(AtomicBool::new(false)),
    }
}

#[test]
fn a_slow_process_tree_does_not_hold_up_the_trace_of_another_run() {
    let big = archive_fixture("big", 400_000);
    let small = archive_fixture("small", 100);
    let worker = ArchiveWorker::new(None).unwrap();
    let wait_invocations = |worker: &ArchiveWorker| {
        answer_where(worker, |answer| {
            matches!(answer, Answer::Invocations { .. })
        })
        .0
    };
    // One page of 100 calls of a 400k-call run. The first read builds the
    // recording's index (kept for later reads); the counts follow separately.
    let started = Instant::now();
    worker.request(page_request(&big, "", 0)).unwrap();
    let Answer::Invocations { total, result, .. } = wait_invocations(&worker) else {
        panic!("wrong answer")
    };
    let first_page = started.elapsed();
    eprintln!(
        "Invocations page 0 of a 400k-call run (no filter, cold index): {first_page:?}, total {total:?}"
    );
    assert!(result.is_ok());
    assert_eq!(
        total, None,
        "the counts of a big recording come apart from its page"
    );
    // Its process tree, then the user selects another run.
    let started = Instant::now();
    worker
        .request(Request::ProcessTree {
            run_id: "big".into(),
            directory: big.clone(),
            root_pid: 100,
            path: "/bin/big".into(),
        })
        .unwrap();
    std::thread::sleep(Duration::from_millis(20));
    worker.request(page_request(&small, "", 0)).unwrap();
    let mut order = Vec::new();
    while order.len() < 2 {
        match worker.wait_answer(Duration::from_secs(120)).unwrap() {
            Answer::ProcessTree { result, .. } => order.push(format!(
                "tree after {:?} ok={}",
                started.elapsed(),
                result.is_ok()
            )),
            Answer::Invocations { result, .. } => order.push(format!(
                "new selection after {:?} ok={}",
                started.elapsed(),
                result.is_ok()
            )),
            // The counts of the first run still arrive.
            _ => {}
        }
    }
    eprintln!("answers in order: {order:#?}");
    assert!(
        order[0].starts_with("new selection"),
        "the new selection waited for the process tree: {order:?}"
    );
    let _ = std::fs::remove_dir_all(big);
    let _ = std::fs::remove_dir_all(small);
}

#[test]
fn archive_pages_cost_follows_the_page_not_the_recording() {
    let big = archive_fixture("repeat", 200_000);
    let worker = ArchiveWorker::new(None).unwrap();
    let timed = |query: &str, offset: u64| {
        let started = Instant::now();
        worker.request(page_request(&big, query, offset)).unwrap();
        let (answer, _) = answer_where(&worker, |a| matches!(a, Answer::Invocations { .. }));
        let Answer::Invocations { total, result, .. } = answer else {
            unreachable!()
        };
        (started.elapsed(), total, result.unwrap())
    };
    // The first read of a recording builds its index, kept on disk for later reads.
    let (cold, total, page) = timed("", 0);
    eprintln!("200k-call run, page 0, no filter, cold index: {cold:?} (total {total:?})");
    assert_eq!(page.invocations.len(), 100);
    assert_eq!(
        total, None,
        "a page is not held up by counting the recording"
    );
    // The counts arrive on their own, once for the view.
    let key = crate::archive::totals_key(&big, false, None, "", &[]);
    let (answer, _) = answer_where(
        &worker,
        |a| matches!(a, Answer::Totals { key: k, .. } if *k == key),
    );
    let Answer::Totals { result, .. } = answer else {
        unreachable!()
    };
    assert_eq!(result, Ok((200_000, 200_000)));
    // Every later page costs a page, whichever it is, and a counted view's
    // pages come with their counts.
    let next = page.next_offset.unwrap();
    for (label, query, offset) in [
        ("page 0 again", "", 0),
        ("next page", "", next),
        ("page 0, text filter", "mmap", 0),
    ] {
        let (took, total, page) = timed(query, offset);
        eprintln!("200k-call run, {label}: {took:?} (total {total:?})");
        assert_eq!(page.invocations.len(), 100, "{label}");
        // Wall-clock bounds depend on the machine; the first read of the
        // recording builds its index, so a later page costing a fraction of
        // it shows the page no longer reads the whole recording.
        assert!(
            took * 4 < cold || took < Duration::from_millis(500),
            "{label} took {took:?} after a {cold:?} first read: it reads the whole recording again"
        );
        if query.is_empty() {
            assert_eq!(total, Some(200_000), "{label}");
        }
    }
    let _ = std::fs::remove_dir_all(big);
}
