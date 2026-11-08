// SPDX-License-Identifier: GPL-3.0-only
//! `auto init`, `lane reset`, `lane unquarantine` and `lane list` on a
//! scripted engine (card P3-5b).

use super::{
    process::{ProcessInfo, Processes},
    provision::{InitPlan, init_lane, list_lanes, reset_lane, unquarantine_lane},
    state::LaneDir,
    tests::{CLEAN, VM, checkpoint, file, healthy, vm_config},
};
use crate::{
    api::{error::ErrorCode, failure::FailureCode, ids::JobId},
    clock::ManualClock,
    engine::FakeEngine,
    store::tests::{T0, lane},
    waiter::Waiter,
};
use antinomie_monitor_core::{Command, GuestKernel, VmConfig, VmSnapshotTree, VmState};
use std::{path::PathBuf, sync::Arc, time::Duration};

const MS: Duration = Duration::from_millis(1);

struct NoProcs;

impl Processes for NoProcs {
    fn info(&self, _: u32) -> Option<ProcessInfo> {
        None
    }
    fn find_qemu(&self, _: &str) -> Vec<(u32, ProcessInfo)> {
        Vec::new()
    }
    fn kill(&self, _: u32) -> Result<(), String> {
        Ok(())
    }
}

fn dir(name: &str) -> (PathBuf, LaneDir) {
    let dir = std::env::temp_dir().join(format!("ant-prov-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let lanes = LaneDir::new(&dir);
    (dir, lanes)
}

fn kernel(revision: u32) -> GuestKernel {
    GuestKernel {
        revision: Some(revision),
        ..GuestKernel::default()
    }
}

fn plan(replace: bool) -> InitPlan {
    InitPlan {
        lane: lane(),
        create: Command::Create(VmConfig {
            name: VM.into(),
            routed: true,
            ..VmConfig::default()
        }),
        vm_name: VM.into(),
        base_identity: "busybox-r21".into(),
        snapshot: "auto-clean".into(),
        replace,
        need_revision: None,
    }
}

/// An engine that creates the VM, boots it (guest revision `revision`),
/// stops it and takes the snapshot.
fn creating_engine(revision: u32) -> Waiter<FakeEngine> {
    let clock = Arc::new(ManualClock::new(T0));
    let mut fake = FakeEngine::new(Arc::clone(&clock));
    fake.on("Create")
        .then(100 * MS, |s| {
            let mut vm = vm_config("vm-new");
            vm.name = VM.into();
            s.vms.push(vm);
        })
        .ok("VM created");
    fake.on("Start")
        .then(100 * MS, |s| {
            s.state = VmState::Running;
            s.active_vm = Some("vm-new".into());
        })
        .then(Duration::from_secs(9), move |s| {
            s.guest_kernel = Some(kernel(revision))
        })
        .ok("starting");
    fake.on("Stop")
        .then(100 * MS, |s| {
            s.state = VmState::Stopped;
            s.active_vm = None;
            s.guest_kernel = None;
        })
        .ok("stopped");
    fake.on("CreateVmSnapshot")
        .then(100 * MS, |s| {
            let mut node = checkpoint("snap-new");
            node.name = "auto-clean".into();
            s.vm_snapshot_trees.insert(
                "vm-new".into(),
                VmSnapshotTree {
                    vm_id: "vm-new".into(),
                    nodes: vec![node],
                    active_parent_id: None,
                    recovery_note: None,
                    capabilities: Default::default(),
                },
            );
        })
        .ok("snapshot taken");
    Waiter::new(fake, clock)
}

#[test]
fn init_creates_boots_stops_snapshots_and_writes_the_lane_file() {
    let (root, lanes) = dir("init");
    let mut waiter = creating_engine(21);
    let mut lines = Vec::new();
    let made = init_lane(&mut waiter, &lanes, &plan(false), &mut |t| {
        lines.push(t.to_owned())
    })
    .unwrap();
    assert_eq!(made.vm_id, "vm-new");
    assert_eq!(made.snapshot_id, "snap-new");
    assert_eq!(made.guest_revision, Some(21));
    assert!(made.boot_ms >= 9_000, "{}", made.boot_ms);
    assert_eq!(
        waiter.engine_mut().sent_names(),
        ["Create", "Start", "Stop", "CreateVmSnapshot"]
    );
    let saved = lanes.load(&lane()).unwrap().unwrap();
    assert_eq!(
        (
            saved.vm_id.as_str(),
            saved.clean_snapshot_id.as_str(),
            saved.base_identity.as_str()
        ),
        ("vm-new", "snap-new", "busybox-r21")
    );
    assert!(saved.current.is_none() && saved.quarantine.is_none());
    assert_eq!(lines.len(), 4, "{lines:?}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_existing_lane_or_vm_name_is_refused_and_nothing_is_sent() {
    let (root, lanes) = dir("refuse");
    lanes.save(&file()).unwrap();
    let mut waiter = creating_engine(21);
    let error = init_lane(&mut waiter, &lanes, &plan(false), &mut |_| {}).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.message.contains("--replace"));
    // A lane with a job is not replaced.
    let mut busy = file();
    busy.begin_work(
        JobId::try_from("j_01HZZZZZZZZZZZZZZZZZZZZZZZ".to_owned()).unwrap(),
        1,
        T0,
    );
    lanes.save(&busy).unwrap();
    let error = init_lane(&mut waiter, &lanes, &plan(true), &mut |_| {}).unwrap_err();
    assert!(error.message.contains("still has a job"));
    // A VM of that name exists already.
    std::fs::remove_file(lanes.path(&lane())).unwrap();
    let clock = Arc::new(ManualClock::new(T0));
    let mut fake = FakeEngine::new(Arc::clone(&clock));
    fake.after(MS, |s| {
        let mut vm = vm_config("other");
        vm.name = VM.into();
        s.vms.push(vm);
    });
    let mut named = Waiter::new(fake, clock);
    named.drain().unwrap();
    named.pump(10 * MS).unwrap();
    let error = init_lane(&mut named, &lanes, &plan(false), &mut |_| {}).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(named.engine_mut().sent_names().is_empty());
    assert!(waiter.engine_mut().sent_names().is_empty());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_replace_names_the_old_vm_and_keeps_it() {
    let (root, lanes) = dir("replace");
    lanes.save(&file()).unwrap();
    let mut waiter = creating_engine(21);
    let made = init_lane(&mut waiter, &lanes, &plan(true), &mut |_| {}).unwrap();
    assert_eq!(made.replaced_vm.as_deref(), Some(VM));
    assert_eq!(lanes.load(&lane()).unwrap().unwrap().vm_id, "vm-new");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_guest_too_old_for_the_policies_stops_the_init_and_names_the_vm_left() {
    let (root, lanes) = dir("old");
    let mut waiter = creating_engine(14);
    let mut too_old = plan(false);
    too_old.need_revision = Some(15);
    let error = init_lane(&mut waiter, &lanes, &too_old, &mut |_| {}).unwrap_err();
    assert_eq!(error.code, ErrorCode::PreconditionFailed);
    assert!(error.message.contains("revision 14"), "{}", error.message);
    assert!(
        error.message.contains("vm delete vm-new"),
        "{}",
        error.message
    );
    assert!(lanes.load(&lane()).unwrap().is_none());
    // The VM was stopped, no snapshot was taken.
    assert_eq!(
        waiter.engine_mut().sent_names(),
        ["Create", "Start", "Stop"]
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_guest_that_never_answers_leaves_no_lane_file() {
    let (root, lanes) = dir("silent");
    let clock = Arc::new(ManualClock::new(T0));
    let mut fake = FakeEngine::new(Arc::clone(&clock));
    fake.on("Create")
        .then(MS, |s| {
            let mut vm = vm_config("vm-new");
            vm.name = VM.into();
            s.vms.push(vm);
        })
        .ok("created");
    fake.on("Start")
        .then(MS, |s| s.state = VmState::Running)
        .ok("starting");
    let mut waiter = Waiter::new(fake, clock);
    let error = init_lane(&mut waiter, &lanes, &plan(false), &mut |_| {}).unwrap_err();
    assert!(error.message.contains("left as it is"), "{}", error.message);
    assert!(lanes.load(&lane()).unwrap().is_none());
    let _ = std::fs::remove_dir_all(root);
}

fn settled_engine() -> Waiter<FakeEngine> {
    let clock = Arc::new(ManualClock::new(T0));
    let mut fake = FakeEngine::new(Arc::clone(&clock));
    fake.after(MS, healthy);
    let mut waiter = Waiter::new(fake, clock);
    waiter.pump(10 * MS).unwrap();
    waiter
}

#[test]
fn unquarantine_runs_the_checks_and_lifts_the_flag_only_when_they_pass() {
    let (root, lanes) = dir("unq");
    let mut quarantined = file();
    quarantined.quarantine(FailureCode::GuestUnreachable, "three in a row", T0);
    lanes.save(&quarantined).unwrap();
    // The clean snapshot is gone: the flag stays. The engine is asked for
    // the VM's snapshots first.
    let clock = Arc::new(ManualClock::new(T0));
    let mut fake = FakeEngine::new(Arc::clone(&clock));
    fake.after(MS, |s| s.vms = vec![vm_config(VM)]);
    fake.on("RefreshVmSnapshots")
        .then(MS, |s| {
            s.vm_snapshot_trees.insert(
                VM.into(),
                VmSnapshotTree {
                    vm_id: VM.into(),
                    nodes: Vec::new(),
                    active_parent_id: None,
                    recovery_note: None,
                    capabilities: Default::default(),
                },
            );
        })
        .ok("refreshed");
    let mut empty = Waiter::new(fake, clock);
    let error = unquarantine_lane(&mut empty, &lanes, &lane()).unwrap_err();
    assert_eq!(error.code, ErrorCode::PreconditionFailed);
    assert!(error.message.contains(CLEAN));
    assert_eq!(empty.engine_mut().sent_names(), ["RefreshVmSnapshots"]);
    assert!(lanes.load(&lane()).unwrap().unwrap().is_quarantined());
    // All checks pass: lifted.
    let mut waiter = settled_engine();
    waiter.engine_mut().on("RefreshVmSnapshots").ok("refreshed");
    let summary = unquarantine_lane(&mut waiter, &lanes, &lane()).unwrap();
    assert!(summary.quarantine.is_none() && summary.problems.is_empty());
    assert!(!lanes.load(&lane()).unwrap().unwrap().is_quarantined());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn reset_reverts_answers_stops_settles_and_lifts_the_quarantine() {
    let (root, lanes) = dir("reset");
    let mut quarantined = file();
    quarantined.quarantine(FailureCode::RevertFailed, "failed twice", T0);
    quarantined.failures = 2;
    lanes.save(&quarantined).unwrap();
    let mut waiter = settled_engine();
    waiter
        .engine_mut()
        .on("RestoreVmSnapshot")
        .then(MS, |s| {
            s.state = VmState::Running;
            s.active_vm = Some(VM.into());
        })
        .then(5 * MS, |s| s.guest_kernel = Some(kernel(21)))
        .ok("restored");
    waiter
        .engine_mut()
        .on("Stop")
        .then(MS, |s| {
            s.state = VmState::Stopped;
            s.active_vm = None;
        })
        .ok("stopped");
    let summary = reset_lane(&mut waiter, &lanes, &lane(), &NoProcs, &mut |_| {}).unwrap();
    assert!(
        summary.quarantine.is_none() && summary.problems.is_empty(),
        "{summary:?}"
    );
    let sent = waiter.engine_mut().sent();
    let restore = sent
        .iter()
        .find(|s| s.name == "RestoreVmSnapshot")
        .expect("a restore");
    assert!(
        restore
            .detail
            .contains(&format!("snapshot_id: \"{CLEAN}\""))
            && restore.detail.contains("boot_from_disk: true")
            && restore.detail.contains("confirmed: true"),
        "{}",
        restore.detail
    );
    let after = lanes.load(&lane()).unwrap().unwrap();
    assert!(!after.is_quarantined() && after.failures == 0);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_failed_reset_keeps_the_quarantine_and_a_busy_lane_is_not_touched() {
    let (root, lanes) = dir("resetfail");
    let mut quarantined = file();
    quarantined.quarantine(FailureCode::RevertFailed, "x", T0);
    lanes.save(&quarantined).unwrap();
    let mut waiter = settled_engine();
    waiter
        .engine_mut()
        .on("RestoreVmSnapshot")
        .fail("snapshot is unusable");
    let error = reset_lane(&mut waiter, &lanes, &lane(), &NoProcs, &mut |_| {}).unwrap_err();
    assert!(error.message.contains("unusable"));
    assert!(lanes.load(&lane()).unwrap().unwrap().is_quarantined());

    let mut busy = file();
    busy.begin_work(
        JobId::try_from("j_01HZZZZZZZZZZZZZZZZZZZZZZZ".to_owned()).unwrap(),
        1,
        T0,
    );
    lanes.save(&busy).unwrap();
    let error = reset_lane(&mut waiter, &lanes, &lane(), &NoProcs, &mut |_| {}).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    let error = unquarantine_lane(&mut waiter, &lanes, &lane()).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn list_says_what_keeps_a_lane_from_a_job() {
    let (root, lanes) = dir("list");
    assert!(list_lanes(&lanes, None).unwrap().is_empty());
    lanes.save(&file()).unwrap();
    let waiter = settled_engine();
    let ready = list_lanes(&lanes, Some(waiter.snapshot())).unwrap();
    assert_eq!(ready.len(), 1);
    assert!(ready[0].problems.is_empty());
    let bare = antinomie_monitor_core::Snapshot::default();
    let broken = list_lanes(&lanes, Some(&bare)).unwrap();
    assert!(broken[0].problems[0].contains("not in the data folder"));
    let _ = std::fs::remove_dir_all(root);
}
