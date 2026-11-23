// SPDX-License-Identifier: GPL-3.0-only
//! The parts of `collect` timed in `run.collect` events and the daemon log
//! (ANT-T0612), against a [`FakeEngine`](crate::engine::FakeEngine) and a
//! manual clock.
use super::{
    run_tests::{collect_stage, finished_run},
    tests::{SECOND, W},
};
use crate::api::event::{CollectPart, EventBody};
use antinomie_monitor_core::{RecordingFlushStatus, VmState, disk_layers::LayerPhase};

fn parts(w: &W, job: &crate::api::run::Run) -> Vec<(CollectPart, u64, Option<String>)> {
    let events = w.fx.store.events_list(&job.id, 0, 1000).unwrap().0;
    events
        .into_iter()
        .filter_map(|event| match event.body {
            EventBody::RunCollect {
                part,
                duration_ms,
                detail,
            } => Some((part, duration_ms, detail)),
            _ => None,
        })
        .collect()
}

#[test]
fn collect_times_the_stop_the_saving_and_the_disk_layer() {
    let w = W::new("collect-parts");
    let (job, mut waiter, ready) = finished_run(&w, |fake| {
        fake.on("Stop")
            .after(SECOND)
            .then(2 * SECOND, |s| {
                s.state = VmState::Stopped;
                s.active_vm = None;
                s.recording_flush = Some(RecordingFlushStatus::default());
                s.disk_layers = vec![crate::lane::tests::layer(LayerPhase::Saving)];
            })
            .then(42 * SECOND, |s| {
                s.recording_flush = None;
                s.disk_layers = vec![crate::lane::tests::layer(LayerPhase::Finalizing)];
            })
            .then(642 * SECOND, |s| s.disk_layers.clear())
            .ok("VM stopped");
    });
    collect_stage(&w, &mut waiter, &job, &ready).unwrap();
    let parts = parts(&w, &job);
    let names: Vec<CollectPart> = parts.iter().map(|(part, _, _)| *part).collect();
    assert_eq!(
        names,
        [
            CollectPart::Evidence,
            CollectPart::Telemetry,
            CollectPart::Stop,
            CollectPart::Saving,
            CollectPart::DiskLayer
        ]
    );
    let seconds = |part: CollectPart| {
        parts
            .iter()
            .find(|(p, _, _)| *p == part)
            .map(|(_, ms, _)| ms / 1000)
            .unwrap()
    };
    // The snapshot is read every 250 ms: within a second of the script.
    assert!((2..=3).contains(&seconds(CollectPart::Stop)), "{parts:?}");
    assert!(
        (39..=41).contains(&seconds(CollectPart::Saving)),
        "{parts:?}"
    );
    assert!(
        (599..=601).contains(&seconds(CollectPart::DiskLayer)),
        "{parts:?}"
    );
    let layer = parts
        .iter()
        .find(|(p, _, _)| *p == CollectPart::DiskLayer)
        .and_then(|(_, _, detail)| detail.clone())
        .unwrap();
    assert!(layer.contains("earlier bytes"), "{layer}");
    let lines = w.log.lines();
    let line = lines
        .iter()
        .find(|line| line.contains("collect took"))
        .expect("the daemon log line");
    assert!(
        line.starts_with(&format!("run={} collect took", job.id)),
        "{line}"
    );
    for name in ["evidence", "telemetry", "stop", "saving", "disk layer"] {
        assert!(line.contains(name), "{line}");
    }
}

#[test]
fn a_vm_that_stops_with_nothing_pending_has_short_parts() {
    let w = W::new("collect-parts-short");
    let (job, mut waiter, ready) = finished_run(&w, super::run_tests::stop_ok);
    collect_stage(&w, &mut waiter, &job, &ready).unwrap();
    let parts = parts(&w, &job);
    assert_eq!(parts.len(), 5, "{parts:?}");
    for (part, ms, detail) in &parts {
        assert!(*ms <= 4000, "{part:?} {ms} {detail:?}");
    }
    let evidence = &parts[0];
    assert_eq!(
        evidence.2.as_deref(),
        Some("nothing was still being written")
    );
    let layer = &parts[4];
    assert_eq!(layer.2.as_deref(), Some("no disk layer was pending"));
}
