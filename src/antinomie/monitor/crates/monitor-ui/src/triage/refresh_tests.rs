// SPDX-License-Identifier: GPL-3.0-only
//! Triage keeps the index of the selected run current without re-reading what
//! has not changed. Regression tests for the refresh loop.
use super::tests::write_rwx_calls;
use super::*;

fn input<'a>(archive: &'a Path, finished: bool) -> TriageInput<'a> {
    TriageInput {
        analysis: None,
        invocations: &[],
        vm_id: Some("vm"),
        boot_id: Some("boot"),
        run_id: Some("done"),
        archive: Some(archive),
        pcap: None,
        pcap_open: false,
        clock_anchor: None,
        started_ms: None,
        root_cookie: 0,
        run_finished: finished,
        current_boot: false,
    }
}

fn spool_with_calls(range: std::ops::Range<u64>) -> (PacketSpool, std::fs::File) {
    let spool = PacketSpool::new().unwrap();
    let mut raw = std::fs::File::create(spool.directory.join("telemetry.raw")).unwrap();
    write_rwx_calls(&mut raw, range);
    raw.sync_all().unwrap();
    (spool, raw)
}

/// How long to wait for a background index thread before giving up. It is only
/// a bound on a hang: what the tests observe is counted in ticks and moved
/// with the view's clock, never measured. Scale it up on a slow machine with
/// `ANTINOMIE_TEST_SCALE`.
fn patience() -> Duration {
    let scale = std::env::var("ANTINOMIE_TEST_SCALE")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1)
        .max(1);
    Duration::from_secs(60) * scale
}

/// Tick until the index in flight has been delivered.
fn settle(view: &mut TriageView, ctx: &egui::Context, archive: &Path, finished: bool, shown: bool) {
    let deadline = Instant::now() + patience();
    loop {
        if shown {
            view.mark_shown(ctx);
        }
        view.tick(ctx, input(archive, finished));
        if view.scan.is_some() && view.scan_rx.is_none() {
            return;
        }
        assert!(Instant::now() < deadline, "index never arrived");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Let one second of the view's own time pass and tick once, then wait for
/// whatever index thread that started: the refresh loop has seen the second
/// and finished reacting to it, however busy the machine is.
fn second(view: &mut TriageView, ctx: &egui::Context, archive: &Path, finished: bool, shown: bool) {
    view.clock.advance(Duration::from_secs(1));
    let deadline = Instant::now() + patience();
    loop {
        if shown {
            view.mark_shown(ctx);
        }
        view.tick(ctx, input(archive, finished));
        if view.scan_rx.is_none() {
            return;
        }
        assert!(Instant::now() < deadline, "index never arrived");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Names, sizes and modification times of the files in a directory.
fn listing(directory: &Path) -> Vec<(String, u64, std::time::SystemTime)> {
    let mut found: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                meta.len(),
                meta.modified().unwrap(),
            )
        })
        .collect();
    found.sort();
    found
}

#[test]
fn finished_run_is_indexed_once_while_selected() {
    let (spool, _raw) = spool_with_calls(0..50);
    let ctx = egui::Context::default();
    let mut view = TriageView::default();
    view.refresh_seconds = 1;
    settle(&mut view, &ctx, &spool.directory, true, false);
    let indexed = view.scan_generation;
    for _ in 0..5 {
        // Nothing changes on disk: the run is finished and its archive final.
        second(&mut view, &ctx, &spool.directory, true, false);
    }
    assert_eq!(
        view.scan_generation, indexed,
        "a finished, unchanged run was indexed again (every refresh_seconds, even hidden)"
    );
}

#[test]
fn live_run_is_re_read_only_when_it_grew_and_an_unchanged_one_writes_nothing() {
    let (spool, mut raw) = spool_with_calls(0..50);
    let ctx = egui::Context::default();
    let mut view = TriageView::default();
    view.refresh_seconds = 1;
    settle(&mut view, &ctx, &spool.directory, false, true);
    let calls = view.scan.as_ref().unwrap().counts.calls;
    assert_eq!(calls, 50);
    let before = listing(&spool.directory);
    let generation = view.scan_generation;
    for _ in 0..4 {
        second(&mut view, &ctx, &spool.directory, false, true);
    }
    assert_eq!(
        listing(&spool.directory),
        before,
        "a refresh that found nothing new wrote into the run directory"
    );
    assert_eq!(view.scan.as_ref().unwrap().counts.calls, calls);
    assert!(
        view.scan_generation - generation <= 4,
        "{} checks in 4 s at one per second",
        view.scan_generation - generation
    );
    // The recording grows: the next refresh reads it.
    write_rwx_calls(&mut raw, 50..80);
    raw.sync_all().unwrap();
    let mut seconds = 0;
    while view.scan.as_ref().unwrap().counts.calls != 80 {
        second(&mut view, &ctx, &spool.directory, false, true);
        seconds += 1;
        assert!(seconds <= 10, "grown recording never re-indexed");
    }
}

#[test]
fn run_that_ends_gets_one_last_index_even_when_hidden() {
    let (spool, _raw) = spool_with_calls(0..20);
    let ctx = egui::Context::default();
    let mut view = TriageView::default();
    view.refresh_seconds = 1;
    settle(&mut view, &ctx, &spool.directory, false, false);
    let live = view.scan_generation;
    // The pane is hidden and the run is live: the timer reads nothing.
    for _ in 0..3 {
        second(&mut view, &ctx, &spool.directory, false, false);
    }
    assert_eq!(view.scan_generation, live, "a hidden live run was re-read");
    // The run ends: its final index is made once, then no more.
    let deadline = Instant::now() + patience();
    while view.scan_generation == live || view.scan_rx.is_some() {
        view.tick(&ctx, input(&spool.directory, true));
        assert!(
            Instant::now() < deadline,
            "no final index after the run ended"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let last = view.scan_generation;
    for _ in 0..3 {
        second(&mut view, &ctx, &spool.directory, true, false);
    }
    assert_eq!(view.scan_generation, last);
}

/// Generations of index started in 40 s of a live run whose pane is hidden.
fn hidden_reads(toast: bool) -> u64 {
    let (spool, _raw) = spool_with_calls(0..20);
    let ctx = egui::Context::default();
    let mut view = TriageView::default();
    view.refresh_seconds = 1;
    view.set_toast_high(toast);
    settle(&mut view, &ctx, &spool.directory, false, false);
    let first = view.scan_generation;
    for _ in 0..40 {
        second(&mut view, &ctx, &spool.directory, false, false);
    }
    view.scan_generation - first
}

#[test]
fn with_the_toast_on_a_hidden_live_run_is_read_every_fifteen_seconds_and_with_it_off_never() {
    assert_eq!(hidden_reads(false), 0);
    let reads = hidden_reads(true);
    // Forty seconds: one read at once, then one each 15 s.
    assert!((2..=3).contains(&reads), "{reads} reads in 40 s");
}
