// SPDX-License-Identifier: GPL-3.0-only
use super::tests::{event, header};
use super::*;

fn observed(
    pid: u32,
    cookie: u64,
    time: u64,
    phase: u8,
    fields: &[(&str, Vec<u8>)],
) -> EventSummary {
    let mut event = event(pid, phase, 0, fields);
    event.task_cookie = cookie;
    event.timestamp_ns = time;
    event.cpu = (cookie % 4) as u32;
    event
}

fn fork(time: u64) -> EventSummary {
    observed(
        100,
        1,
        time,
        3,
        &[("lifecycle.child_tgid", 200_u64.to_le_bytes().to_vec())],
    )
}

fn exit(cookie: u64, time: u64, code: u64) -> EventSummary {
    observed(
        200,
        cookie,
        time,
        3,
        &[("lifecycle.task_exit", code.to_le_bytes().to_vec())],
    )
}

fn ingest(tracker: &mut ProcessTracker, event: &EventSummary) {
    let mut packet = header(event.pid, event.phase, 1);
    packet.tid = event.tid;
    packet.task_cookie = event.task_cookie;
    packet.stream_id = event.stream_id;
    packet.timestamp_ns = event.timestamp_ns;
    tracker.packet(&packet);
    tracker.event(event);
}

fn child(tracker: &ProcessTracker) -> CaptureProcess {
    tracker.list().into_iter().find(|p| p.pid == 200).unwrap()
}

#[test]
fn every_cpu_delivery_order_keeps_the_childs_recorded_exit() {
    let facts = [fork(100), observed(200, 2, 110, 1, &[]), exit(2, 120, 0)];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut tracker = ProcessTracker::default();
        for index in order {
            ingest(&mut tracker, &facts[index]);
        }
        let child = child(&tracker);
        assert_eq!(child.parent_pid, 100, "{order:?}");
        assert!(child.exited, "{order:?}");
        assert_eq!(child.exit_code, Some(0));
        assert_eq!(child.calls, 1);
        assert_eq!(child.last_ns, 120);
    }
}

#[test]
fn real_pid_reuse_discards_old_lifetime_packets_and_terminal_facts() {
    let mut tracker = ProcessTracker::default();
    for event in [
        fork(100),
        exit(2, 120, 0),
        fork(200),
        observed(200, 3, 210, 1, &[]),
        exit(2, 120, 0),
        fork(100),
        observed(200, 2, 110, 1, &[]),
    ] {
        ingest(&mut tracker, &event);
    }
    assert!(!child(&tracker).exited);
    assert_eq!(child(&tracker).calls, 1);
    assert_eq!(child(&tracker).first_ns, 210);
    ingest(&mut tracker, &exit(3, 220, 9));
    assert!(child(&tracker).exited);
    assert_eq!(child(&tracker).exit_code, Some(9));
}

#[test]
fn a_new_leader_identity_after_exit_proves_reuse_even_if_its_fork_arrives_late() {
    let mut tracker = ProcessTracker::default();
    for event in [
        exit(2, 120, 0),
        observed(200, 3, 210, 1, &[]),
        fork(200),
        exit(2, 120, 0),
    ] {
        ingest(&mut tracker, &event);
    }
    assert!(!child(&tracker).exited);
    assert_eq!(child(&tracker).parent_pid, 100);
    assert_eq!(tracker.lifetimes.len(), tracker.processes.len());
}

#[test]
fn delayed_exec_records_keep_the_latest_name_and_do_not_reopen_an_exited_task() {
    let mut tracker = ProcessTracker::default();
    let entry = |time, path: &[u8]| {
        let mut entry = observed(200, 2, time, 1, &[("arg0.path", path.to_vec())]);
        entry.syscall_nr = 59;
        entry.syscall_name = "execve".into();
        entry
    };
    let commit = |time| {
        observed(
            200,
            2,
            time,
            3,
            &[("lifecycle.exec_commit", 1_u64.to_le_bytes().to_vec())],
        )
    };
    for event in [
        entry(130, b"/bin/latest\0"),
        commit(131),
        exit(2, 140, 0),
        entry(110, b"/bin/older\0"),
        commit(111),
        fork(100),
    ] {
        ingest(&mut tracker, &event);
    }
    assert!(child(&tracker).exited);
    assert_eq!(child(&tracker).exe.as_deref(), Some("/bin/latest"));
    assert!(tracker.exec_paths.is_empty());
}

#[test]
fn older_commit_does_not_consume_the_path_of_a_newer_pending_exec() {
    let mut tracker = ProcessTracker::default();
    let mut entry = observed(200, 2, 130, 1, &[("arg0.path", b"/bin/new\0".to_vec())]);
    entry.syscall_nr = 59;
    entry.syscall_name = "execve".into();
    ingest(&mut tracker, &entry);
    for time in [111, 131] {
        ingest(
            &mut tracker,
            &observed(
                200,
                2,
                time,
                3,
                &[("lifecycle.exec_commit", 1_u64.to_le_bytes().to_vec())],
            ),
        );
    }
    assert_eq!(child(&tracker).exe.as_deref(), Some("/bin/new"));
}

#[test]
fn thread_and_parent_exits_never_end_an_unobserved_child() {
    let mut tracker = ProcessTracker::default();
    ingest(&mut tracker, &fork(100));
    let mut thread = exit(9, 120, 0);
    thread.tid = 201;
    ingest(&mut tracker, &thread);
    let mut parent = exit(1, 130, 0);
    parent.pid = 100;
    parent.tid = 100;
    ingest(&mut tracker, &parent);
    assert!(!child(&tracker).exited);
    assert_eq!(child(&tracker).exit_code, None);
}

#[test]
fn unknown_timestamps_cannot_prove_pid_reuse_and_restored_exits_survive_old_forks() {
    let mut tracker = ProcessTracker::default();
    ingest(&mut tracker, &exit(2, 120, 0));
    let mut restored = ProcessTracker::default();
    restored.restore_baseline(tracker.list());
    for event in [fork(100), fork(0)] {
        ingest(&mut restored, &event);
    }
    assert!(child(&restored).exited);
    let mut unknown = ProcessTracker::default();
    ingest(&mut unknown, &exit(2, 0, 0));
    ingest(&mut unknown, &fork(200));
    assert!(
        child(&unknown).exited,
        "without an exit time reuse remains unproven"
    );
}

#[test]
fn a_nonleader_exec_keeps_its_path_when_it_becomes_the_new_leader() {
    let mut tracker = ProcessTracker::default();
    ingest(&mut tracker, &exit(2, 120, 0));
    let mut entry = observed(
        200,
        3,
        130,
        1,
        &[("arg0.path", b"/bin/thread-exec\0".to_vec())],
    );
    entry.tid = 201;
    entry.syscall_nr = 59;
    entry.syscall_name = "execve".into();
    ingest(&mut tracker, &entry);
    ingest(
        &mut tracker,
        &observed(
            200,
            3,
            131,
            3,
            &[("lifecycle.exec_commit", 1_u64.to_le_bytes().to_vec())],
        ),
    );
    assert!(!child(&tracker).exited);
    assert_eq!(child(&tracker).exe.as_deref(), Some("/bin/thread-exec"));
}
