// SPDX-License-Identifier: GPL-3.0-only
//! The process table: threads, forked children, arguments and renames.
use super::rules::tests::support::{creds, exec, exec_env, fork, sys, with_entry};
use super::tests::{call, captured, path_call};
use super::*;

const CLONE_NR: u64 = 56;
const CLONE3_NR: u64 = 435;

/// The call as made by a task of `pid` with its own `tid` and `cookie`.
fn as_task(mut row: InvocationSummary, pid: u32, tid: u32, cookie: u64) -> InvocationSummary {
    row.task_cookie = cookie;
    for event in row.entry.iter_mut().chain(row.exit.iter_mut()) {
        event.pid = pid;
        event.tid = tid;
        event.task_cookie = cookie;
    }
    row
}

fn node(nodes: &[ProcessNode], pid: u32, cookie: u64) -> &ProcessNode {
    nodes
        .iter()
        .find(|node| node.pid == pid && node.cookie == cookie)
        .unwrap_or_else(|| panic!("no node {pid}/{cookie}"))
}

#[test]
fn runtime_threads_sit_under_their_process_and_take_its_image() {
    let mut main = exec(7, "/tmp/kaiji", &["kaiji", "-x"]);
    main = as_task(main, 7, 7, 70);
    let mut calls = vec![main];
    for tid in 8u32..12 {
        calls.push(as_task(
            call(7, 202, "futex", 0),
            7,
            tid,
            70 + u64::from(tid),
        ));
    }
    let nodes = process_nodes(&calls);
    assert_eq!(nodes.len(), 5);
    assert!(nodes
        .iter()
        .all(|node| !node.parent_missing || node.pid == 7));
    for tid in 8u32..12 {
        let thread = node(&nodes, 7, 70 + u64::from(tid));
        assert!(thread.thread);
        assert_eq!(thread.parent.unwrap().cookie, 70);
        assert_eq!(thread.depth, 1);
        assert_eq!(thread.comm, "/tmp/kaiji");
        assert_eq!(thread.argv, ["kaiji", "-x"]);
        assert!(!thread.parent_missing);
        assert!(process_label(thread).contains("thread"));
    }
    assert!(!node(&nodes, 7, 70).thread);
}

#[test]
fn two_pids_with_matching_tids_are_not_threads() {
    let calls = vec![
        as_task(call(7, 1, "write", 0), 7, 7, 100),
        as_task(call(7, 1, "write", 0), 7, 7, 200),
    ];
    let nodes = process_nodes(&calls);
    assert!(nodes.iter().all(|node| !node.thread));
}

#[test]
fn a_forked_child_with_its_own_threads_is_still_linked_to_its_parent() {
    // The child's threads were recorded before the parent's fork returned.
    let calls = vec![
        as_task(call(42, 1, "write", 0), 42, 42, 420),
        as_task(call(42, 1, "write", 0), 42, 43, 430),
        as_task(call(42, 1, "write", 0), 42, 44, 440),
        as_task(fork(1, 42), 1, 1, 10),
    ];
    let nodes = process_nodes(&calls);
    let child = node(&nodes, 42, 420);
    assert_eq!(child.parent.unwrap().pid, 1);
    assert!(!child.parent_missing);
    assert!(node(&nodes, 42, 430).thread);
    assert_eq!(node(&nodes, 42, 430).parent.unwrap().cookie, 420);
}

#[test]
fn a_forked_child_without_exec_keeps_its_parents_image() {
    let calls = vec![
        as_task(exec(1, "/tmp/mirai", &["mirai", "a"]), 1, 1, 10),
        as_task(fork(1, 5), 1, 1, 10),
        as_task(call(5, 1, "write", 0), 5, 5, 50),
    ];
    let nodes = process_nodes(&calls);
    let child = node(&nodes, 5, 50);
    assert_eq!(child.parent.unwrap().pid, 1);
    assert_eq!(child.comm, "/tmp/mirai");
    assert_eq!(child.argv, ["mirai", "a"]);
}

#[test]
fn the_guests_child_record_links_a_clone3_whose_flags_were_not_captured() {
    let mut spawn = as_task(
        sys(1, CLONE3_NR, "clone3", [0, 88, 0, 0, 0, 0], 9),
        1,
        1,
        10,
    );
    spawn.async_events.push({
        let mut note = spawn.exit.clone().unwrap();
        note.phase = 3;
        note.fields = vec![captured("lifecycle.child_tgid", "u64", &9u64.to_le_bytes())];
        note
    });
    let calls = vec![
        as_task(exec(1, "/bin/root", &["root"]), 1, 1, 10),
        spawn,
        as_task(exec(9, "/bin/sh", &["sh", "-c", "id"]), 9, 9, 90),
    ];
    let nodes = process_nodes(&calls);
    let sh = node(&nodes, 9, 90);
    assert_eq!(sh.parent.unwrap().pid, 1);
    assert!(!sh.parent_missing);
    // A clone with the thread flag and no child record stays a thread.
    let thread = sys(
        1,
        CLONE_NR,
        "clone",
        [super::CLONE_THREAD, 0, 0, 0, 0, 0],
        77,
    );
    assert!(process_nodes(&[thread]).iter().all(|node| node.pid != 77));
}

#[test]
fn the_table_shows_the_arguments_the_exec_was_given() {
    let nodes = process_nodes(&[exec(3, "/bin/sh", &["sh", "-c", "echo hi"])]);
    assert_eq!(nodes[0].argv, ["sh", "-c", "echo hi"]);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    assert_eq!(rows[0][1].text, "sh -c 'echo hi'");
}

fn prctl_name(pid: u32, name: &str) -> InvocationSummary {
    let mut bytes = name.as_bytes().to_vec();
    bytes.push(0);
    with_entry(
        sys(pid, 157, "prctl", [15, 0x2000, 0, 0, 0, 0], 0),
        "arg1.name",
        &bytes,
    )
}

#[test]
fn a_rename_is_shown_for_any_process_not_only_a_daemon_look_alike() {
    let nodes = process_nodes(&[exec(3, "/tmp/x", &["x"]), prctl_name(3, "httpd")]);
    assert_eq!(nodes[0].renames, ["httpd"]);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    assert!(
        rows[0][8].text.contains("renamed to \"httpd\""),
        "{}",
        rows[0][8].text
    );
    // A new exec starts the names over.
    let nodes = process_nodes(&[prctl_name(3, "httpd"), exec(3, "/tmp/y", &["y"])]);
    assert!(nodes[0].renames.is_empty());
}

#[test]
fn a_write_to_the_comm_file_is_a_rename() {
    let open = path_call(3, 257, "openat", 5, "/proc/self/comm");
    let write = with_entry(
        sys(3, 1, "write", [5, 0x3000, 5, 0, 0, 0], 5),
        "arg1.buf",
        b"kdmtmpflush",
    );
    let other = with_entry(
        sys(3, 1, "write", [6, 0x3000, 5, 0, 0, 0], 5),
        "arg1.buf",
        b"nope",
    );
    let nodes = process_nodes(&[open, other, write]);
    assert_eq!(nodes[0].renames, ["kdmtmpflush"]);
}

fn entry_only(mut row: InvocationSummary, at: u64) -> InvocationSummary {
    row.exit = None;
    row.entry.as_mut().unwrap().timestamp_ns = at;
    row
}

#[test]
fn a_call_still_blocking_at_the_stop_is_shown_with_where_it_started() {
    let blocked = entry_only(
        sys(3, 0, "read", [0, 0x1000, 33, 0, 0, 0], 0),
        2_000_000_000,
    );
    let mut later = call(4, 1, "write", 0);
    later.entry.as_mut().unwrap().timestamp_ns = 292_000_000_000;
    let nodes = process_nodes(&[blocked, later]);
    let blocked = node(&nodes, 3, 3);
    assert_eq!(blocked.in_call.as_ref().unwrap().0, "read");
    let rows = process_rows(&nodes, None, &Suspicious::new());
    let row = rows
        .iter()
        .find(|row| files::number(&row[0].values, "process.pid") == Some(3))
        .unwrap();
    assert_eq!(row[6].text, "in read() at end");
    let state = match &row[0]
        .values
        .iter()
        .find(|(key, _)| *key == "process.state")
    {
        Some((_, RowValue::Text(state))) => state.clone(),
        _ => panic!("no state"),
    };
    assert!(
        state.contains("still in progress at the stop: read since"),
        "{state}"
    );
    assert!(state.contains("290.0 s before the last record"), "{state}");
    // The task made another call afterwards: it was not blocked.
    let moved_on = process_nodes(&[
        entry_only(sys(3, 0, "read", [0; 6], 0), 1),
        call(3, 1, "write", 0),
    ]);
    assert!(moved_on[0].in_call.is_none());
    // exit_group never returns: it is not a call in progress.
    let leaving = process_nodes(&[entry_only(sys(3, 231, "exit_group", [0; 6], 0), 1)]);
    assert!(leaving[0].in_call.is_none());
}

#[test]
fn a_task_exit_record_with_its_sender_is_kept_on_the_node() {
    let mut killed = entry_only(sys(5, 0, "read", [0; 6], 0), 1);
    let mut end = killed.entry.clone().unwrap();
    end.phase = 3;
    end.timestamp_ns = 2;
    end.fields = vec![
        captured("lifecycle.task_exit", "", &9u64.to_le_bytes()),
        captured("lifecycle.signal.signo", "", &9u64.to_le_bytes()),
        captured("lifecycle.signal.code", "", &0u64.to_le_bytes()),
        captured("lifecycle.signal.origin", "", &1u64.to_le_bytes()),
        captured("lifecycle.signal.sender_pid", "", &44u64.to_le_bytes()),
        captured("lifecycle.signal.sender_uid", "", &0u64.to_le_bytes()),
        captured("lifecycle.signal.sender_comm", "", b"pkill"),
    ];
    killed.task_exit = Some(end);
    let nodes = process_nodes(&[killed]);
    let sender = node(&nodes, 5, 5).end_sender.as_ref().unwrap();
    assert_eq!(sender.signal, 9);
    assert_eq!(sender.sender.as_ref().unwrap().pid, 44);
    assert_eq!(sender.sender.as_ref().unwrap().comm, "pkill");
    // A record for another signal than the one the wait status names is not kept.
    let mut other = entry_only(sys(6, 0, "read", [0; 6], 0), 1);
    let mut end = other.entry.clone().unwrap();
    end.phase = 3;
    end.fields = vec![
        captured("lifecycle.task_exit", "", &15u64.to_le_bytes()),
        captured("lifecycle.signal.signo", "", &9u64.to_le_bytes()),
    ];
    other.task_exit = Some(end);
    let nodes = process_nodes(&[other]);
    assert!(node(&nodes, 6, 6).end_sender.is_none());
}

#[test]
fn the_columns_are_the_process_view_in_order() {
    assert_eq!(
        PROCESS_HEADERS,
        [
            "Process",
            "Argv",
            "Findings",
            "User ID",
            "Started",
            "Lifetime",
            "Outcome",
            "Calls",
            "Exec chain"
        ]
    );
    let nodes = process_nodes(&[exec(3, "/tmp/demo-all", &["demo-all"])]);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    assert_eq!(rows[0].len(), PROCESS_HEADERS.len());
}

#[test]
fn a_process_is_named_by_its_executable_file_with_pid_and_tid() {
    let nodes = process_nodes(&[exec(412, "/tmp/demo-all", &["demo-all"])]);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    assert!(rows[0][0].text.starts_with("demo-all (412 \u{b7} 412)"));
    // The full path is the hover text.
    assert_eq!(
        cell_hover(0, &rows[0][0], &rows[0][0]).as_deref(),
        Some("/tmp/demo-all")
    );
    // The filter keys are still on the first cell.
    for key in [
        "process.pid",
        "process.tid",
        "process.cookie",
        "process.suspicious",
        "process.worst_tier",
        "process.depth",
        "process.ppid",
        "process.parent_cookie",
        "process.exe",
        "process.argv",
        "process.state",
        "process.first_ns",
        "process.last_ns",
        "event.id",
        "stream.id",
    ] {
        assert!(
            rows[0][0].values.iter().any(|(name, _)| *name == key),
            "{key}"
        );
    }
}

#[test]
fn a_fork_shows_the_parent_image_greyed_and_a_thread_its_pid_and_tid() {
    let nodes = process_nodes(&[exec(1, "/bin/sh", &["sh"]), fork(1, 42)]);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    let child = rows
        .iter()
        .find(|row| files::number(&row[0].values, "process.pid") == Some(42))
        .unwrap();
    assert_eq!(child[0].text, "sh (42 \u{b7} ?)  fork");
    assert_eq!(child[0].color(), theme::muted());
    assert!(cell_hover(0, &child[0], &child[0])
        .unwrap()
        .contains("Not exec'd yet"));
    let main = exec(7, "/tmp/kaiji", &["kaiji"]);
    let calls = [
        as_task(main, 7, 7, 70),
        as_task(call(7, 202, "futex", 0), 7, 8, 78),
    ];
    let nodes = process_nodes(&calls);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    assert!(rows.iter().any(|row| row[0].text == "(7 \u{b7} 8)  thread"));
}

#[test]
fn a_command_line_that_disagrees_with_the_image_has_no_warning_sign() {
    // The disagreement is a finding of Suspicious activity now (evasion.argv_masquerade).
    let nodes = process_nodes(&[exec(3, "/tmp/demo-all", &["ps", "aux"])]);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    assert_eq!(rows[0][1].text, "ps aux");
    assert_eq!(rows[0][1].color(), theme::text());
    // The hover numbers the arguments and carries no warning sign.
    let hover = cell_hover(1, &rows[0][1], &rows[0][0]).unwrap();
    assert_eq!(hover, "argv[0] = ps\nargv[1] = aux\n2 arguments");
    assert!(!rows[0][0].text.contains('\u{26a0}'));
    let fine = process_nodes(&[exec(3, "/bin/ls", &["ls", "-l"])]);
    let rows = process_rows(&fine, None, &Suspicious::new());
    assert_eq!(rows[0][1].text, "ls -l");
    assert_eq!(
        cell_hover(1, &rows[0][1], &rows[0][0]).unwrap(),
        "argv[0] = ls\nargv[1] = -l\n2 arguments"
    );
}

#[test]
fn the_exec_chain_the_environment_and_the_calls_are_kept_per_task() {
    let mut first = exec_env(3, "/bin/sh", &["sh"], &["PATH=/bin", "HOME=/root"]);
    first.entry.as_mut().unwrap().timestamp_ns = 1_000_000_000;
    let mut second = exec_env(
        3,
        "/tmp/demo-all",
        &["demo-all"],
        &["PATH=/tmp", "LD_PRELOAD=/x.so"],
    );
    second.entry.as_mut().unwrap().timestamp_ns = 2_204_000_000;
    let nodes = process_nodes(&[first, call(3, 1, "write", 0), second]);
    let task = node(&nodes, 3, 3);
    assert_eq!(task.record.calls, 3);
    assert_eq!(task.record.envp, ["PATH=/tmp", "LD_PRELOAD=/x.so"]);
    let images: Vec<_> = task
        .record
        .execs
        .iter()
        .map(|(image, _)| image.as_str())
        .collect();
    assert_eq!(images, ["/bin/sh", "/tmp/demo-all"]);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    assert_eq!(rows[0][8].text, "sh \u{2192} demo-all");
    assert_eq!(rows[0][7].text, "3");
    assert_eq!(rows[0][3].text, "\u{2014}");
}

#[test]
fn a_fork_that_never_exec_s_has_its_parents_environment() {
    let parent = exec_env(1, "/bin/sh", &["sh"], &["A=1"]);
    let nodes = process_nodes(&[parent, fork(1, 42)]);
    assert_eq!(node(&nodes, 42, 0).record.envp, ["A=1"]);
}

#[test]
fn a_started_time_and_a_running_lifetime_read_from_the_run_start() {
    let mut early = exec(1, "/bin/sh", &["sh"]);
    early.entry.as_mut().unwrap().timestamp_ns = 5_000_000_000;
    early.exit.as_mut().unwrap().timestamp_ns = 5_000_000_000;
    let mut late = exec(2, "/bin/ls", &["ls"]);
    late.entry.as_mut().unwrap().timestamp_ns = 6_204_000_000;
    late.exit.as_mut().unwrap().timestamp_ns = 6_204_000_000;
    let nodes = process_nodes(&[early, late]);
    let clock = Some(antinomie_monitor_core::HostClockAnchor {
        guest_ns: 0,
        host_us: 1_700_000_000_000_000,
    });
    let rows = process_rows(&nodes, clock, &Suspicious::new());
    let ls = rows
        .iter()
        .find(|row| files::number(&row[0].values, "process.pid") == Some(2))
        .unwrap();
    assert_eq!(ls[4].text, "+1.204 s");
    assert!(cell_hover(4, &ls[4], &ls[0]).unwrap().starts_with('~'));
    assert_eq!(ls[5].text, "running");
    assert_eq!(ls[6].text, "no exit recorded");
}

#[test]
fn a_fatal_signal_names_the_sender_only_when_a_kill_call_was_recorded() {
    let mut nodes = std::collections::BTreeMap::new();
    let key = |pid| TaskKey {
        pid,
        cookie: u64::from(pid),
    };
    let mut victim = TaskNode {
        end_signal: Some(9),
        tid: 9,
        ..TaskNode::default()
    };
    victim.state = "task exit, killed by SIGKILL".into();
    nodes.insert(key(9), victim);
    nodes.insert(key(5), TaskNode::default());
    process_record::match_killers(&mut nodes);
    assert_eq!(nodes[&key(9)].record.killed_by, None);
    nodes.get_mut(&key(5)).unwrap().record.sent.push((9, 9));
    process_record::match_killers(&mut nodes);
    assert_eq!(nodes[&key(9)].record.killed_by, Some(5));
    // A different signal is not the one that killed it.
    nodes.get_mut(&key(5)).unwrap().record.sent = vec![(9, 15)];
    process_record::match_killers(&mut nodes);
    assert_eq!(nodes[&key(9)].record.killed_by, None);
}

#[test]
fn the_user_is_the_uid_or_uid_to_euid_from_the_credentials_the_run_recorded() {
    let mut start = exec(3, "/bin/su", &["su"]);
    start.kernel_notes.push(creds(
        [1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000],
        0,
        1,
    ));
    let mut rows = process_rows(&process_nodes(&[start.clone()]), None, &Suspicious::new());
    assert_eq!(rows.remove(0)[3].text, "1000");
    let mut raised = call(3, 105, "setuid", 0);
    raised
        .kernel_notes
        .push(creds([1000, 0, 0, 0, 1000, 1000, 1000, 1000], 0, 7));
    let nodes = process_nodes(&[start, raised]);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    assert_eq!(rows[0][3].text, "1000 \u{2192} 0");
    assert_eq!(node(&nodes, 3, 3).record.creds.len(), 2);
}

#[test]
fn the_argv_column_quotes_each_argument_and_the_hover_numbers_them() {
    let nodes = process_nodes(&[exec(3, "/bin/sh", &["sh", "-c", "curl x | sh"])]);
    let rows = process_rows(&nodes, None, &Suspicious::new());
    let cell = &rows[0][1];
    assert_eq!(cell.text, "sh -c 'curl x | sh'");
    let hover = cell_hover(1, cell, &rows[0][0]).expect("a hover");
    assert_eq!(
        hover,
        "argv[0] = sh\nargv[1] = -c\nargv[2] = curl x | sh\n3 arguments"
    );
    // A quote inside an argument, an empty one and a gap.
    let argv: Vec<String> = ["echo", "it's", "", "\u{2026}"].map(String::from).to_vec();
    assert_eq!(
        process_cells::argv_line(&argv),
        "echo 'it'\\''s' '' \u{2026}"
    );
    let hover = process_cells::argv_hover(&argv).unwrap();
    assert!(hover.contains("argv[3] = \u{2026}") && hover.contains("4 arguments, 1 cut short"));
    assert_eq!(process_cells::argv_hover(&[]), None);
}

/// A `vfork` child that execs at once is recorded before the parent's call
/// returns, and the parent that made it is often not the process's main
/// thread (Prometei, 2026-11-07; RotaJakiro, 2026-11-07).
fn vfork_calls() -> Vec<InvocationSummary> {
    vec![
        as_task(exec(1160, "/tmp/p", &["p"]), 1160, 1160, 1),
        // Thread 1170 of process 1160 runs for a while.
        as_task(call(1160, 202, "futex", 0), 1160, 1170, 11),
        // The child execs first: its parent is not known yet.
        as_task(
            exec(1171, "/bin/sh", &["sh", "-c", "pgrep x"]),
            1171,
            1171,
            12,
        ),
        // Then the thread's vfork returns the child's pid.
        as_task(sys(1160, 58, "vfork", [0; 6], 1171), 1160, 1170, 11),
        // Its own child: the grandchild is linked to the sh.
        as_task(exec(1172, "/bin/pgrep", &["pgrep", "x"]), 1172, 1172, 13),
        as_task(sys(1171, 58, "vfork", [0; 6], 1172), 1171, 1171, 12),
    ]
}

#[test]
fn a_child_cloned_by_a_thread_hangs_under_the_process_not_the_thread() {
    let nodes = process_nodes(&vfork_calls());
    let sh = node(&nodes, 1171, 12);
    let parent = sh.parent.expect("the sh has a parent");
    assert_eq!(
        (parent.pid, parent.cookie),
        (1160, 1),
        "the main task, not thread 1170"
    );
    assert!(!sh.parent_missing);
    assert_eq!(sh.depth, 1);
    let pgrep = node(&nodes, 1172, 13);
    assert_eq!(pgrep.parent.unwrap().pid, 1171);
    assert_eq!(pgrep.depth, 2);
    assert!(node(&nodes, 1160, 11).thread);
}

#[test]
fn the_settled_parents_name_the_process_for_a_child_seen_before_its_clone_returned() {
    let mut nodes = std::collections::BTreeMap::new();
    // Only the calls before the vfork returned: the sh has no parent yet.
    observe_processes(&mut nodes, &vfork_calls()[..3]);
    let sh = TaskKey {
        pid: 1171,
        cookie: 12,
    };
    assert!(nodes[&sh].parent.is_none());
    observe_processes(&mut nodes, &vfork_calls()[3..]);
    let settled = settled_parents(&nodes);
    assert!(
        settled[&sh]
            == TaskKey {
                pid: 1160,
                cookie: 1
            }
    );
}
