// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The live judge on every architecture: an arm64 run's calls, AArch64 and
//! AArch32 (compat), reach the judge as an x86-64 run's do (ANT-T0426).
use super::*;
use crate::syscalls::{Abi, id, known_name};
use std::sync::{Arc, Mutex};

/// A judge that matches every `openat` at High and remembers what it saw.
struct OpenJudge(Arc<Mutex<Vec<String>>>);

impl LiveJudge for OpenJudge {
    fn judge(&mut self, call: &InvocationSummary) -> Vec<LiveFinding> {
        let event = call.entry.as_ref().or(call.exit.as_ref()).unwrap();
        let name = known_name(event.syscall_nr).unwrap_or("?").to_owned();
        self.0.lock().unwrap().push(name.clone());
        if name != "openat" {
            return Vec::new();
        }
        vec![LiveFinding {
            rule: "persistence.systemd".into(),
            summary: "writes /etc/systemd/system/x.service".into(),
            tier: TriggerTier::High,
            pid: event.pid,
            tid: event.tid,
            task_cookie: event.task_cookie,
            stream_id: event.stream_id,
            call_id: event.call_id,
            guest_ns: event.timestamp_ns,
            syscall: name,
        }]
    }
}

fn event(call_id: u64, phase: u8, nr: u64) -> EventSummary {
    EventSummary {
        root_task_cookie: 1,
        stream_id: 1,
        task_cookie: 7,
        call_id,
        event_seq: call_id * 2 + u64::from(phase),
        phase,
        syscall_nr: nr,
        syscall_name: known_name(nr).unwrap_or("?").into(),
        pid: 7,
        tid: 7,
        cpu: 0,
        timestamp_ns: call_id * 1_000_000,
        args: (phase == 1).then_some([0; 6]),
        result: (phase == 2).then_some(3),
        complete: true,
        issues: Vec::new(),
        fields: Vec::new(),
    }
}

/// Entry and exit of each call, in order.
fn calls(ids: &[u64]) -> Vec<EventSummary> {
    ids.iter()
        .enumerate()
        .flat_map(|(at, &nr)| [event(at as u64 + 1, 1, nr), event(at as u64 + 1, 2, nr)])
        .collect()
}

/// The recorder's list, as the UI hands it over: x86-64 names.
fn keep() -> Vec<String> {
    ["execve", "openat", "mmap", "sendto", "setresuid", "connect"]
        .map(str::to_owned)
        .to_vec()
}

fn replay_ids(ids: &[u64], plan: &DumpTrigger) -> (Vec<LiveFinding>, Vec<String>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let found = replay(Box::new(OpenJudge(seen.clone())), plan, &keep(), calls(ids));
    let seen = seen.lock().unwrap().clone();
    (found, seen)
}

#[test]
fn the_call_filter_keeps_every_abis_ids_and_x86_64s_as_before() {
    let ids = crate::syscalls::ids_on_every_abi(&keep());
    // x86-64's ids are its numbers, the same set the filter always had.
    let x86: HashSet<u64> = ids.iter().copied().filter(|id| *id >> 48 == 0).collect();
    let before: HashSet<u64> = keep()
        .iter()
        .filter_map(|name| crate::syscalls::number(name))
        .collect();
    assert_eq!(x86, before);
    let table = |abi| crate::syscalls::table(abi);
    for (abi, name) in [
        (Abi::Aarch64, "openat"),
        (Abi::Aarch64, "execve"),
        (Abi::Aarch64, "mmap"),
        (Abi::Arm, "openat"),
        (Abi::Arm, "execve"),
        // AArch32 calls of an x86-64 family: kept under the family's name.
        (Abi::Arm, "send"),
        (Abi::Arm, "mmap2"),
        (Abi::Arm, "setresuid32"),
        (Abi::I386, "openat"),
        (Abi::I386, "setresuid32"),
    ] {
        let number = table(abi).number(name).expect(name);
        assert!(ids.contains(&id(abi, number)), "{abi:?} {name}");
    }
    // A call off the list is not kept on any ABI.
    for abi in [Abi::X86_64, Abi::Aarch64, Abi::Arm, Abi::I386] {
        let write = table(abi).number("write").unwrap();
        assert!(!ids.contains(&id(abi, write)), "{abi:?} write");
    }
}

#[test]
fn an_aarch64_call_reaches_the_judge_and_fires_the_trigger() {
    let aarch64 = |name| {
        id(
            Abi::Aarch64,
            crate::syscalls::table(Abi::Aarch64).number(name).unwrap(),
        )
    };
    let (found, seen) = replay_ids(
        &[aarch64("execve"), aarch64("write"), aarch64("openat")],
        &DumpTrigger::default(),
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].rule, "persistence.systemd");
    assert_eq!(found[0].syscall, "openat");
    assert_eq!(found[0].call_id, 3);
    // The bulk call is still filtered out; the kept ones are judged.
    assert_eq!(seen, ["execve", "openat"]);
}

#[test]
fn an_aarch32_compat_call_reaches_the_judge_and_fires_the_trigger() {
    let arm = |name| {
        id(
            Abi::Arm,
            crate::syscalls::table(Abi::Arm).number(name).unwrap(),
        )
    };
    let (found, seen) = replay_ids(
        &[
            arm("execve"),
            arm("send"),
            arm("mmap2"),
            arm("write"),
            arm("openat"),
        ],
        &DumpTrigger::default(),
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].call_id, 5);
    assert_eq!(seen, ["execve", "send", "mmap2", "openat"]);
}

#[test]
fn an_x86_64_run_is_judged_as_before() {
    let (found, seen) = replay_ids(&[59, 1, 257], &DumpTrigger::default());
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].call_id, 3);
    assert_eq!(seen, ["execve", "openat"]);
}

#[test]
fn an_entry_without_its_exit_is_judged_when_the_watch_is_flushed() {
    let openat = id(Abi::Aarch64, 56);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let found = replay(
        Box::new(OpenJudge(seen)),
        &DumpTrigger::default(),
        &keep(),
        [event(1, 1, openat)],
    );
    assert_eq!(found.len(), 1);
}

#[test]
fn a_finding_below_the_tier_takes_nothing() {
    let plan = DumpTrigger {
        min_tier: TriggerTier::High,
        ..DumpTrigger::default()
    };
    struct Low;
    impl LiveJudge for Low {
        fn judge(&mut self, call: &InvocationSummary) -> Vec<LiveFinding> {
            let mut row = OpenJudge(Default::default()).judge(call);
            row.iter_mut()
                .for_each(|row| row.tier = TriggerTier::Medium);
            row
        }
    }
    let found = replay(
        Box::new(Low),
        &plan,
        &keep(),
        calls(&[id(Abi::Aarch64, 56)]),
    );
    assert!(found.is_empty());
}

#[test]
fn a_trigger_that_never_matched_says_so_and_one_that_did_does_not() {
    let plan = DumpTrigger::default();
    let note = silent_note(&plan, None).unwrap();
    assert!(note.contains("armed (core at High or higher)"), "{note}");
    assert!(note.contains("no dump was taken"), "{note}");
    assert_eq!(silent_note(&plan, Some(&TriggerLog::default())), Some(note));
    let both = DumpTrigger {
        memory: true,
        min_tier: TriggerTier::Medium,
        ..plan.clone()
    };
    assert!(
        silent_note(&both, None)
            .unwrap()
            .contains("memory dump and core at Medium or higher")
    );
    let finding = OpenJudge(Default::default())
        .judge(&pair_events(&calls(&[257]))[0])
        .remove(0);
    for log in [
        TriggerLog {
            records: vec![TriggerRecord {
                at_ms: 1,
                finding: finding.clone(),
                memory: None,
                core: None,
            }],
            ..TriggerLog::default()
        },
        TriggerLog {
            missed: vec![TriggerMiss {
                at_ms: 1,
                finding,
                reason: "late".into(),
            }],
            ..TriggerLog::default()
        },
        TriggerLog {
            skipped: 1,
            ..TriggerLog::default()
        },
        TriggerLog {
            lost: 1,
            ..TriggerLog::default()
        },
    ] {
        assert_eq!(silent_note(&plan, Some(&log)), None, "{log:?}");
    }
}

fn program_run(name: &str, plan: Option<DumpTrigger>) -> (crate::run::ProgramRun, PathBuf) {
    let directory = std::env::temp_dir().join(format!(
        "ant-trigger-{name}-{}",
        crate::storage::unique_id()
    ));
    let summary = crate::api::RunSummary {
        environment: None,
        reduced: None,
        boot_wait: None,
        triggers: None,
        stopped_by_user: false,
        stopped_at_ms: None,
        persisted: None,
        started_ms: None,
        clock_anchor: None,
        id: "run".into(),
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        session_id: 1,
        root_task_cookie: 2,
        pid: 3,
        request: crate::api::ExecRequest {
            dump_trigger: plan,
            ..Default::default()
        },
        directory: directory.clone(),
        terminal_eof: true,
        state: crate::api::RunState::Finished,
        notes: Vec::new(),
        machine: None,
        route: None,
        recording_error: None,
        execution: None,
        analysis: None,
    };
    (
        crate::run::ProgramRun::new(summary, 1024 * 1024).unwrap(),
        directory,
    )
}

#[test]
fn a_run_whose_armed_trigger_never_matched_gets_one_note() {
    let plan = DumpTrigger::default();
    let (mut run, directory) = program_run("silent", Some(plan.clone()));
    run.watch = Some(Watch::with_judge(
        Box::new(OpenJudge(Default::default())),
        &plan,
        &keep(),
    ));
    let execve = id(Abi::Arm, 11);
    for event in calls(&[execve]) {
        run.watch.as_mut().unwrap().event(event);
    }
    assert!(run.settle_trigger());
    assert_eq!(run.summary.notes, [silent_note(&plan, None).unwrap()]);
    // Once only, though the VM's stop settles every run again.
    assert!(!run.settle_trigger());
    assert_eq!(run.summary.notes.len(), 1);
    drop(run);
    // Saves are written by the flush thread: wait for them before the folder goes.
    crate::storage::flush_json().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn a_match_the_recording_ended_on_is_kept_as_a_miss_not_as_silence() {
    let plan = DumpTrigger::default();
    let (mut run, directory) = program_run("late", Some(plan.clone()));
    run.watch = Some(Watch::with_judge(
        Box::new(OpenJudge(Default::default())),
        &plan,
        &keep(),
    ));
    // The entry of an AArch64 openat whose exit never came.
    run.watch
        .as_mut()
        .unwrap()
        .event(event(1, 1, id(Abi::Aarch64, 56)));
    assert!(run.settle_trigger());
    let log = run.summary.triggers.as_ref().unwrap();
    assert_eq!(log.missed.len(), 1);
    assert_eq!(log.missed[0].reason, RECORDING_ENDED);
    assert_eq!(run.summary.notes.len(), 1);
    assert!(
        run.summary.notes[0].contains("1 match came as the recording ended"),
        "{:?}",
        run.summary.notes
    );
    drop(run);
    // Saves are written by the flush thread: wait for them before the folder goes.
    crate::storage::flush_json().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn a_run_without_a_trigger_gets_no_note() {
    let (mut run, directory) = program_run("none", None);
    assert!(!run.settle_trigger());
    assert!(run.summary.notes.is_empty());
    drop(run);
    // Saves are written by the flush thread: wait for them before the folder goes.
    crate::storage::flush_json().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn whole_events_reach_the_watch_whether_live_or_held_before_the_launch_answer() {
    // `watch_event` is what both the live packet path and the replay of the
    // telemetry held before the launch was acknowledged call (a fast x86-64
    // program wrote its cron entry before the answer and was never judged).
    let plan = DumpTrigger::default();
    let (mut run, directory) = program_run("watch", Some(plan.clone()));
    let seen = Arc::new(Mutex::new(Vec::new()));
    run.watch = Some(Watch::with_judge(
        Box::new(OpenJudge(seen.clone())),
        &plan,
        &keep(),
    ));
    run.assembler.just_finished = false;
    run.watch_event(Some(&event(1, 1, 257)));
    assert!(
        seen.lock().unwrap().is_empty(),
        "a partial event is not judged"
    );
    run.assembler.just_finished = true;
    run.watch_event(Some(&event(1, 1, 257)));
    run.watch_event(Some(&event(1, 2, 257)));
    run.watch_event(None);
    assert_eq!(*seen.lock().unwrap(), ["openat"]);
    assert_eq!(run.watch.as_ref().unwrap().queue.len(), 1);
    drop(run);
    crate::storage::flush_json().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

/// Revision 22's exit hold: a held process has what of it still waits for an
/// exit judged at once, keeps its hold while a match for it is queued, and is
/// let go once the grace passes with none.
#[test]
fn a_held_process_is_judged_at_once_and_let_go_only_without_a_match() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let plan = DumpTrigger::default();
    let mut watch = Watch::with_judge(Box::new(OpenJudge(seen)), &plan, &keep());
    let openat = 257;
    // An entry with no exit yet would wait ENTRY_GRACE; the hold judges it now.
    watch.event(event(1, 1, openat));
    assert!(watch.queue.is_empty());
    watch.hold(7, 0x77);
    assert_eq!(
        watch.queue.len(),
        1,
        "the pending openat is judged at the hold"
    );
    assert!(watch.pending.is_empty());
    // A match is queued for it: no release, however long it waits.
    assert!(watch.releases(Duration::ZERO).is_empty());
    assert!(watch.held.contains_key(&7));
    // Once the worker took the match, a held process with none is let go.
    watch.queue.clear();
    assert!(
        watch.releases(Duration::from_secs(60)).is_empty(),
        "inside the grace"
    );
    assert_eq!(watch.releases(Duration::ZERO), vec![0x77]);
    assert!(watch.held.is_empty());
}
