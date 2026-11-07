// SPDX-License-Identifier: GPL-3.0-only
use super::*;

const BOOT: &str = "boot-1";

fn record(phase: Option<LayerPhase>, pid: Option<u32>) -> Record {
    Record {
        format: 1,
        vm_id: "vm".into(),
        boot_id: BOOT.into(),
        boot_dir: "/rec/boot".into(),
        sealed: "disk.qcow2".into(),
        top: "snapshots/top.qcow2".into(),
        manifest_absent: false,
        marker: Marker {
            phase,
            phase_ms: Some(5),
            started_ms: Some(1),
            owner: Owner {
                pid,
                start_ticks: pid.map(|_| 1000),
                host_boot: Some("host-a".into()),
                pid_ns: Some("pid:[1]".into()),
            },
        },
    }
}

fn reader<'a>(
    start: &'a dyn Fn(u32) -> Option<u64>,
    lock: &'a dyn Fn() -> Option<bool>,
) -> ReaderContext<'a> {
    ReaderContext {
        host_boot: Some("host-a".into()),
        pid_ns: Some("pid:[1]".into()),
        start_ticks: start,
        finalizer_lock_free: lock,
    }
}

fn read(record: Option<&Record>, ctx: &ReaderContext<'_>) -> PhaseReading {
    recording_phase(record, BOOT, ctx)
}

#[test]
fn a_running_owner_keeps_live_and_saving_live() {
    let start = |_: u32| Some(1000);
    let lock = || None;
    for phase in [Some(LayerPhase::Live), Some(LayerPhase::Saving), None] {
        let reading = read(Some(&record(phase, Some(42))), &reader(&start, &lock));
        assert_eq!(reading.phase, RecordingPhase::Live, "{phase:?}");
        assert_eq!(reading.owner, OwnerState::Alive);
    }
}

#[test]
fn a_dead_owner_makes_a_live_or_saving_marker_interrupted() {
    let lock = || None;
    let gone = |_: u32| None;
    for phase in [LayerPhase::Live, LayerPhase::Saving] {
        let reading = read(Some(&record(Some(phase), Some(42))), &reader(&gone, &lock));
        assert_eq!(reading.phase, RecordingPhase::Interrupted);
        assert_eq!(reading.owner, OwnerState::Gone);
    }
}

#[test]
fn a_reused_pid_is_not_mistaken_for_the_owner() {
    let reused = |_: u32| Some(999_999);
    let lock = || None;
    let reading = read(
        Some(&record(Some(LayerPhase::Live), Some(42))),
        &reader(&reused, &lock),
    );
    assert_eq!(reading.owner, OwnerState::Gone);
    assert_eq!(reading.phase, RecordingPhase::Interrupted);
}

#[test]
fn another_host_boot_means_the_owner_is_gone_whatever_the_pid_says() {
    let alive = |_: u32| Some(1000);
    let lock = || None;
    let mut ctx = reader(&alive, &lock);
    ctx.host_boot = Some("host-b".into());
    let reading = read(Some(&record(Some(LayerPhase::Saving), Some(42))), &ctx);
    assert_eq!(reading.owner, OwnerState::Gone);
    assert_eq!(reading.phase, RecordingPhase::Interrupted);
}

#[test]
fn another_pid_namespace_cannot_say_and_reads_live() {
    let alive = |_: u32| panic!("a pid of another namespace means nothing here");
    let lock = || None;
    let mut ctx = reader(&alive, &lock);
    ctx.pid_ns = Some("pid:[2]".into());
    let reading = read(Some(&record(Some(LayerPhase::Live), Some(42))), &ctx);
    assert_eq!(reading.owner, OwnerState::Unknown);
    assert_eq!(reading.phase, RecordingPhase::Live);
}

#[test]
fn a_marker_from_0_8_has_no_owner_and_reads_live() {
    let alive = |_: u32| Some(1000);
    let lock = || None;
    let old: Record = serde_json::from_str(
        r#"{"format":1,"vm_id":"vm","boot_id":"boot-1","boot_dir":"/b","sealed":"d","top":"t","manifest_absent":false}"#,
    )
    .unwrap();
    assert_eq!(old.marker, Marker::default());
    let reading = read(Some(&old), &reader(&alive, &lock));
    assert_eq!(reading.phase, RecordingPhase::Live);
    assert_eq!(reading.owner, OwnerState::Unknown);
    // And it writes back the way 0.8.x wrote it.
    let value = serde_json::to_value(&old).unwrap();
    assert!(value.get("phase").is_none() && value.get("owner_pid").is_none());
}

#[test]
fn an_orphaned_finalizing_marker_stays_finalizing() {
    let alive = |_: u32| Some(1000);
    let gone = |_: u32| None;
    let free = || Some(true);
    let held = || Some(false);
    let finalizing = record(Some(LayerPhase::Finalizing), Some(42));
    let working = read(Some(&finalizing), &reader(&alive, &held));
    assert_eq!(working.phase, RecordingPhase::Finalizing);
    assert!(!working.orphaned);
    // The lock probe finds it free although the pid test cannot tell.
    let by_lock = read(Some(&finalizing), &reader(&alive, &free));
    assert!(by_lock.orphaned && by_lock.phase == RecordingPhase::Finalizing);
    let by_pid = read(Some(&finalizing), &reader(&gone, &held));
    assert!(by_pid.orphaned && by_pid.phase == RecordingPhase::Finalizing);
}

#[test]
fn no_record_or_another_boot_is_complete() {
    let alive = |_: u32| Some(1000);
    let lock = || None;
    let ctx = reader(&alive, &lock);
    assert_eq!(read(None, &ctx).phase, RecordingPhase::Complete);
    let mut later = record(Some(LayerPhase::Live), Some(42));
    later.boot_id = "boot-2".into();
    assert_eq!(read(Some(&later), &ctx).phase, RecordingPhase::Complete);
}

#[test]
fn the_start_time_is_field_22_even_when_the_name_has_spaces_and_parentheses() {
    let stat = "42 (a (b) c) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 24 25";
    assert_eq!(start_ticks_of(stat), Some(777));
    assert_eq!(start_ticks_of("garbage"), None);
    assert!(process_start_ticks(std::process::id()).is_some());
    assert_eq!(process_start_ticks(u32::MAX), None);
}

#[test]
fn this_process_describes_itself() {
    let me = Owner::current();
    assert_eq!(me.pid, Some(std::process::id()));
    assert!(me.start_ticks.is_some());
    let lock = || None;
    let ctx = ReaderContext {
        host_boot: host_boot_id(),
        pid_ns: own_pid_namespace(),
        start_ticks: &process_start_ticks,
        finalizer_lock_free: &lock,
    };
    let mut marker = record(Some(LayerPhase::Live), None);
    marker.marker.owner = me;
    assert_eq!(owner_state(&marker.marker, &ctx), OwnerState::Alive);
}
