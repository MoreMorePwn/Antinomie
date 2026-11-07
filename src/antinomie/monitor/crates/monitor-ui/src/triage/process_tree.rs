// SPDX-License-Identifier: GPL-3.0-only
//! The process tree rebuilt from fork, clone and exec calls.
use super::*;

/// Suspicious observations per task, as `(task cookie, pid)`: how many, and
/// the worst tier among them.
pub(super) type Suspicious = std::collections::BTreeMap<(u64, u32), (u64, rules::Tier)>;

/// Count one finding for the task it was observed in.
pub(super) fn tally(counts: &mut Suspicious, values: &[(&'static str, RowValue)]) {
    let cookie = files::number(values, "process.cookie");
    let pid = files::number(values, "process.pid");
    let tier = values.iter().find_map(|(key, value)| match value {
        RowValue::Text(text) if *key == "finding.tier" => rules::Tier::from_tag(text),
        _ => None,
    });
    if let (Some(cookie), Some(pid)) = (cookie, pid) {
        let entry = counts
            .entry((cookie, pid as u32))
            .or_insert((0, rules::Tier::Info));
        entry.0 += 1;
        entry.1 = entry.1.max(tier.unwrap_or(rules::Tier::Info));
    }
}

/// The Process tree's rows: the cells and, in the first, the values a filter reads.
pub(super) fn process_rows(
    nodes: &[ProcessNode],
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
    suspicious: &Suspicious,
) -> Vec<Vec<Cell>> {
    // The latest moment any task was recorded: how long a call had been in progress.
    let end = nodes.iter().filter_map(|node| node.last_ns).max();
    // The start of the run: when its first task was first seen.
    let start = nodes.iter().filter_map(|node| node.first_ns).min();
    nodes
        .iter()
        .map(|node| {
            let ended = node.state.starts_with("task exit");
            let mut command = cell(process_cells::argv_line(&node.argv), theme::text(), false);
            if let Some(hover) = process_cells::argv_hover(&node.argv) {
                tip(&mut command, hover);
            }
            let mut findings = cell(
                suspicious
                    .get(&(node.cookie, node.pid))
                    .map_or_else(String::new, |(count, _)| count.to_string()),
                theme::text(),
                true,
            );
            tip(
                &mut findings,
                "Triage findings in this process. Click to list them.".into(),
            );
            let mut started = cell(
                process_cells::relative(node.first_ns, start),
                theme::text(),
                true,
            );
            tip(
                &mut started,
                crate::time_format::guest_ns(clock, node.first_ns),
            );
            let mut user = cell(
                process_cells::user(node.record.creds.last()),
                theme::text(),
                true,
            );
            if let Some(step) = node.record.creds.last() {
                tip(&mut user, process_cells::user_hover(step));
            }
            let mut row = vec![
                cell(
                    process_label(node),
                    if node.forked {
                        theme::muted()
                    } else {
                        theme::value(theme::ValueKind::Pointer)
                    },
                    true,
                ),
                command,
                findings,
                user,
                started,
                cell(
                    process_cells::lifetime(node.first_ns, node.last_ns, ended),
                    theme::text(),
                    true,
                ),
                cell(
                    process_cells::outcome(
                        &node.state,
                        node.in_call.as_ref().map(|call| call.0.as_str()),
                        node.record.killed_by,
                    ),
                    theme::text(),
                    false,
                ),
                cell(node.record.calls.to_string(), theme::text(), true),
                cell(history_text(node), theme::text(), false),
            ];
            row[0].values = vec![
                (
                    "event.id",
                    node.call_id
                        .map_or(RowValue::Missing, |id| RowValue::Number(i128::from(id.2))),
                ),
                ("process.pid", RowValue::Number(i128::from(node.pid))),
                ("process.tid", RowValue::Number(i128::from(node.tid))),
                ("process.cookie", RowValue::Number(i128::from(node.cookie))),
                (
                    "process.suspicious",
                    RowValue::Number(i128::from(
                        suspicious
                            .get(&(node.cookie, node.pid))
                            .map_or(0, |(count, _)| *count),
                    )),
                ),
                (
                    "process.worst_tier",
                    suspicious
                        .get(&(node.cookie, node.pid))
                        .map_or(RowValue::Missing, |(_, tier)| {
                            RowValue::Text(tier.tag().to_owned())
                        }),
                ),
                ("process.forked", RowValue::Bool(node.forked)),
                (
                    "process.calls",
                    RowValue::Number(i128::from(node.record.calls)),
                ),
                (
                    "process.lifetime_ns",
                    match (node.first_ns, node.last_ns) {
                        (Some(first), Some(last)) if ended => {
                            RowValue::Number(i128::from(last.saturating_sub(first)))
                        }
                        _ => RowValue::Missing,
                    },
                ),
                ("process.depth", RowValue::Number(node.depth as i128)),
                (
                    "process.ppid",
                    node.parent.map_or(RowValue::Missing, |parent| {
                        RowValue::Number(i128::from(parent.pid))
                    }),
                ),
                (
                    "process.parent_cookie",
                    node.parent
                        .filter(|parent| parent.cookie != 0)
                        .map_or(RowValue::Missing, |parent| {
                            RowValue::Number(i128::from(parent.cookie))
                        }),
                ),
                (
                    "stream.id",
                    node.call_id
                        .map_or(RowValue::Missing, |key| RowValue::Number(i128::from(key.0))),
                ),
                (
                    "process.exe",
                    if node.comm == "?" {
                        RowValue::Missing
                    } else {
                        text_value(&node.comm)
                    },
                ),
                (
                    "process.argv",
                    if node.argv.is_empty() {
                        RowValue::Missing
                    } else {
                        RowValue::List(node.argv.clone())
                    },
                ),
                (
                    "process.state",
                    RowValue::Text(state_text(node, end, clock)),
                ),
                (
                    "process.first_ns",
                    node.first_ns
                        .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                ),
                (
                    "process.last_ns",
                    node.last_ns
                        .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                ),
            ];
            row
        })
        .collect::<Vec<_>>()
}

/// The Process tree's columns, in order.
pub(super) const PROCESS_HEADERS: [&str; 9] = [
    "Process",
    "Argv",
    "Findings",
    "User ID",
    "Started",
    "Lifetime",
    "Outcome",
    "Calls",
    "Exec chain",
];

/// Key of a cell's hover text among its values.
const TIP: &str = "cell.tooltip";

fn tip(cell: &mut Cell, text: String) {
    cell.values.push((TIP, RowValue::Text(text)));
}

/// The text shown when the pointer rests on a cell of the Process tree: the
/// full executable path in the first column, the cell's own note elsewhere.
pub(super) fn cell_hover(column: usize, cell: &Cell, first: &Cell) -> Option<String> {
    if column == 0 {
        let path = match first.values.iter().find(|(key, _)| *key == "process.exe") {
            Some((_, RowValue::Text(path))) => path.clone(),
            _ => return None,
        };
        let forked = first
            .values
            .iter()
            .any(|(key, value)| *key == "process.forked" && matches!(value, RowValue::Bool(true)));
        return Some(if forked {
            format!("{path}\nNot exec'd yet: still its parent's image.")
        } else {
            path
        });
    }
    cell.values.iter().find_map(|(key, value)| match value {
        RowValue::Text(text) if *key == TIP => Some(text.clone()),
        _ => None,
    })
}

/// Thread tasks from which the Process tree folds them into "+N threads".
const THREAD_FOLD: usize = 4;

pub(super) fn process_tree_nodes(
    ui: &mut egui::Ui,
    nodes: &[ProcessNode],
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
    suspicious: &Suspicious,
) {
    let mut rows = process_rows(nodes, clock, suspicious);
    // Thread tasks fold into "+N threads" on their process once there are many
    // of them; the chip lists them. The user's choice is kept for the session.
    let thread_count = nodes.iter().filter(|node| node.thread).count();
    let thread_id = egui::Id::new("triage-process-threads");
    let expanded = if thread_count == 0 {
        true
    } else {
        let stored: Option<bool> = ui.ctx().data(|data| data.get_temp(thread_id));
        let expanded = stored.unwrap_or(thread_count < THREAD_FOLD);
        ui.horizontal(|ui| {
            let label = format!("Show threads ({thread_count})");
            if crate::widgets::toggle_chip(ui, &label, expanded, None)
                .on_hover_text(
                    "Thread tasks of a process, one per recorded thread. Off, they fold into +N threads on their process.",
                )
                .clicked()
            {
                ui.ctx().data_mut(|data| data.insert_temp(thread_id, !expanded));
            }
        });
        let stored: Option<bool> = ui.ctx().data(|data| data.get_temp(thread_id));
        stored.unwrap_or(thread_count < THREAD_FOLD)
    };
    if !expanded {
        let mut folded: std::collections::BTreeMap<(u32, u64), usize> = Default::default();
        for node in nodes.iter().filter(|node| node.thread) {
            if let Some(parent) = node.parent {
                *folded.entry((parent.pid, parent.cookie)).or_default() += 1;
            }
        }
        for (row, node) in rows.iter_mut().zip(nodes) {
            if let Some(count) = folded.get(&(node.pid, node.cookie)) {
                row[0].text.push_str(&format!("  +{count} threads"));
            }
        }
        let keep: Vec<bool> = nodes.iter().map(|node| !node.thread).collect();
        let mut keep = keep.into_iter();
        rows.retain(|_| keep.next().unwrap_or(true));
    }
    ui.ctx().data_mut(|data| {
        data.insert_temp(
            egui::Id::new(("triage-filter-target", "triage-process")),
            ui.id().with(("table-filter", "triage-process")),
        )
    });
    let compiled = query::table_filter(
        ui,
        "triage-process",
        "process.exe contains bash",
        PROCESS_FIELDS,
        &[],
    );
    let total = rows.len();
    let filtered = rows
        .into_iter()
        .filter(|row| compiled.keep_table(&row[0].values))
        .collect::<Vec<_>>();
    let group = antinomie_monitor_core::analysis::detection::group_digits;
    ui.colored_label(
        theme::muted(),
        format!(
            "{} / {} rows",
            group(filtered.len() as u64),
            group(total as u64)
        ),
    );
    // The tree is of the rows that are left: a filter leaves gaps, not stale
    // branches.
    let depths = filtered
        .iter()
        .map(|row| files::number(&row[0].values, "process.depth").map_or(0, |depth| depth as usize))
        .collect::<Vec<_>>();
    table_with(
        ui,
        "triage-process",
        &PROCESS_HEADERS,
        &filtered,
        Some(&crate::tree_lines::prefixes(&depths)),
    );
}

pub(super) fn process_nodes(invocations: &[InvocationSummary]) -> Vec<ProcessNode> {
    let mut nodes = std::collections::BTreeMap::new();
    observe_processes(&mut nodes, invocations);
    finish_processes(nodes)
}

pub(super) fn observe_processes(
    nodes: &mut std::collections::BTreeMap<TaskKey, TaskNode>,
    invocations: &[InvocationSummary],
) {
    for invocation in invocations {
        let entry = invocation.entry.as_ref();
        let exit = invocation.exit.as_ref();
        let Some(event) = entry
            .or(exit)
            .or(invocation.async_events.first())
            .or(invocation.task_exit.as_ref())
        else {
            continue;
        };
        if event.pid == 0 {
            continue;
        }
        let key = adopt_task(nodes, event);
        if let Some(node) = nodes.get_mut(&key) {
            node.tid = event.tid;
            node.record.observe(invocation, event);
            if invocation.call_id != 0 {
                node.call_id.get_or_insert(trace::key(invocation));
            }
            node.root |= event.root_task_cookie != 0 && event.task_cookie == event.root_task_cookie;
            for observed in invocation
                .entry
                .iter()
                .chain(invocation.exit.iter())
                .chain(invocation.async_events.iter())
                .chain(invocation.task_exit.iter())
            {
                node.first_ns = Some(node.first_ns.map_or(observed.timestamp_ns, |time| {
                    time.min(observed.timestamp_ns)
                }));
                node.last_ns = Some(node.last_ns.map_or(observed.timestamp_ns, |time| {
                    time.max(observed.timestamp_ns)
                }));
            }
            if let Some(start) = entry {
                // A call with an entry and no exit: where the task was when the
                // recording ended, unless it is a call that does not return.
                node.in_call = (exit.is_none()
                    && invocation.task_exit.is_none()
                    && !matches!(
                        start.syscall_name.as_str(),
                        "exit" | "exit_group" | "execve" | "execveat" | "rt_sigreturn"
                    ))
                .then(|| (start.syscall_name.clone(), start.timestamp_ns));
            }
            if invocation.task_exit.is_some() {
                let status = invocation.task_exit_status();
                node.end_signal = match status {
                    Some(antinomie_monitor_core::WaitStatus::Signaled { signal, .. }) => {
                        Some(signal)
                    }
                    _ => None,
                };
                node.state = match status {
                    Some(antinomie_monitor_core::WaitStatus::Exited { code }) => {
                        format!("task exit {code}")
                    }
                    Some(status) => format!("task exit, {}", crate::values::task_end(&status)),
                    None => "task exit".to_owned(),
                };
            } else if node.state.is_empty() {
                node.state = "exit not recorded".into();
            }
        }
        if committed_exec(invocation) {
            // The name the call gave, else the image the guest says it loaded;
            // with neither, the name inherited from the parent no longer holds.
            let named = program_name(entry, exit)
                .or_else(|| {
                    invocation
                        .async_events
                        .iter()
                        .find_map(|event| program_name(Some(event), None))
                })
                .or_else(|| kernel_records::exec_image(invocation).and_then(|image| image.path));
            if let Some(node) = nodes.get_mut(&key) {
                node.forked = false;
                node.exec_unnamed = named.is_none();
            }
            if named.is_none() {
                if let Some(node) = nodes.get_mut(&key) {
                    node.comm = "?".into();
                    node.argv.clear();
                    node.command_line = None;
                    node.proctitle = None;
                    node.record.envp.clear();
                }
            }
            if let Some(comm) = named {
                let node = nodes.get_mut(&key).unwrap();
                node.comm = comm.clone();
                if node.exec_history.last() != Some(&comm) {
                    if node.exec_history.len() < 128 {
                        node.exec_history.push(comm);
                    } else if node
                        .exec_history
                        .last()
                        .is_some_and(|text| text != "further exec history omitted")
                    {
                        node.exec_history
                            .push("further exec history omitted".into());
                    }
                }
                node.argv = exec_argv(invocation, event);
                let image = node.comm.clone();
                node.record.exec(
                    Some(&image),
                    event.timestamp_ns,
                    process_record::exec_envp(invocation, &event.syscall_name),
                );
                node.renames.clear();
                node.command_line = normalized::command_line(invocation, event);
                node.proctitle = normalized::complete_argv(invocation, event);
            }
        }
        observe_rename(nodes, key, invocation, event);
        // The guest says which task a fork, vfork or clone created, also when
        // the call's own flags were not captured (a `clone3` keeps them in a
        // struct): a new process is linked, a new thread is not a child.
        match lifecycle_born(invocation, event.pid) {
            Some(Born::Process(child)) => {
                link_child(nodes, key, child);
                continue;
            }
            Some(Born::Thread) => continue,
            None => {}
        }
        let args = entry
            .and_then(|event| event.args)
            .or(exit.and_then(|event| event.args));
        if !matches!(
            spawn_kind(invocation, &event.syscall_name, args),
            Some(Spawn::Process)
        ) {
            continue;
        }
        let Some(child) = exit
            .and_then(|event| event.result)
            .or(entry.and_then(|event| event.result))
            .filter(|result| *result > 0)
            .map(|result| result as u32)
        else {
            continue;
        };
        link_child(nodes, key, child);
    }
}

pub(super) fn finish_processes(
    mut nodes: std::collections::BTreeMap<TaskKey, TaskNode>,
) -> Vec<ProcessNode> {
    inherit_fork_images(&mut nodes);
    let threads = attach_threads(&mut nodes);
    // A child cloned by one thread of a process belongs to the process: the
    // Process tree and the Relationships graph show processes, not threads.
    let leaders: Vec<(TaskKey, TaskKey)> = nodes
        .iter()
        .filter_map(|(key, node)| Some((*key, node.parent.filter(|p| threads.contains(p))?)))
        .collect();
    for (key, thread) in leaders {
        let leader = nodes.get(&thread).and_then(|node| node.parent);
        if let Some(node) = nodes.get_mut(&key) {
            node.parent = leader;
        }
    }
    process_record::match_killers(&mut nodes);
    let mut children: std::collections::BTreeMap<TaskKey, Vec<TaskKey>> =
        std::collections::BTreeMap::new();
    let mut roots = Vec::new();
    for (key, node) in &nodes {
        match node
            .parent
            .filter(|parent| nodes.contains_key(parent) && parent != key)
        {
            Some(parent) => children.entry(parent).or_default().push(*key),
            None => roots.push(*key),
        }
    }
    let mut found = Vec::new();
    fn walk(
        key: TaskKey,
        depth: usize,
        nodes: &std::collections::BTreeMap<TaskKey, TaskNode>,
        children: &std::collections::BTreeMap<TaskKey, Vec<TaskKey>>,
        found: &mut Vec<ProcessNode>,
        seen: &mut std::collections::BTreeSet<TaskKey>,
        threads: &std::collections::BTreeSet<TaskKey>,
    ) {
        let mut pending = vec![(key, depth)];
        while let Some((key, depth)) = pending.pop() {
            if !seen.insert(key) {
                continue;
            }
            let Some(node) = nodes.get(&key) else {
                continue;
            };
            found.push(ProcessNode {
                parent: node.parent,
                depth,
                call_id: node.call_id,
                pid: key.pid,
                cookie: key.cookie,
                comm: node.comm.clone(),
                parent_missing: depth == 0 && !node.root && !threads.contains(&key),
                tid: node.tid,
                argv: node.argv.clone(),
                first_ns: node.first_ns,
                last_ns: node.last_ns,
                state: node.state.clone(),
                end_signal: node.end_signal,
                exec_history: node.exec_history.clone(),
                thread: threads.contains(&key),
                renames: node.renames.clone(),
                in_call: node.in_call.clone(),
                forked: node.forked,
                record: {
                    let mut record = node.record.clone();
                    if record.envp.is_empty() && (node.forked || threads.contains(&key)) {
                        record.envp = inherited_env(nodes, key);
                    }
                    record
                },
            });
            if let Some(kids) = children.get(&key) {
                for child in kids.iter().rev() {
                    pending.push((*child, depth.saturating_add(1)));
                }
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for key in roots {
        walk(key, 0, &nodes, &children, &mut found, &mut seen, &threads);
    }
    for key in nodes.keys() {
        if !seen.contains(key) {
            walk(*key, 0, &nodes, &children, &mut found, &mut seen, &threads);
        }
    }
    found
}

/// The environment a task that never ran an exec still has: its parent's.
fn inherited_env(
    nodes: &std::collections::BTreeMap<TaskKey, TaskNode>,
    key: TaskKey,
) -> Vec<String> {
    let mut at = key;
    for _ in 0..16 {
        let Some(parent) = nodes.get(&at).and_then(|node| node.parent) else {
            break;
        };
        match nodes.get(&parent) {
            Some(node) if !node.record.envp.is_empty() => return node.record.envp.clone(),
            Some(_) if parent != at => at = parent,
            _ => break,
        }
    }
    Vec::new()
}

/// A forked child that never ran an exec of its own is still its parent's
/// program: name it after the parent image. The parent's own name can arrive
/// after the fork was seen (the launch record), so this runs once all tasks
/// are known, parents before children.
fn inherit_fork_images(nodes: &mut std::collections::BTreeMap<TaskKey, TaskNode>) {
    for _ in 0..16 {
        let todo: Vec<(TaskKey, TaskKey)> = nodes
            .iter()
            .filter(|(_, node)| node.comm == "?" && !node.exec_unnamed)
            .filter_map(|(key, node)| node.parent.map(|parent| (*key, parent)))
            .filter(|(key, parent)| {
                parent != key && nodes.get(parent).is_some_and(|node| node.comm != "?")
            })
            .collect();
        if todo.is_empty() {
            return;
        }
        for (key, parent) in todo {
            let Some(image) = nodes.get(&parent).map(|node| {
                (
                    node.comm.clone(),
                    node.argv.clone(),
                    node.command_line.clone(),
                    node.proctitle.clone(),
                )
            }) else {
                continue;
            };
            if let Some(node) = nodes.get_mut(&key) {
                (node.comm, node.argv, node.command_line, node.proctitle) = image;
                node.forked = true;
            }
        }
    }
}

/// Identity is `(task_cookie, pid)` when the cookie is non-zero. A fork child
/// seen only as a returned pid keeps cookie 0 until one of its own events
/// supplies a cookie. A real cookie-0 event is not later rewritten as some
/// other cookie.
fn adopt_task(
    nodes: &mut std::collections::BTreeMap<TaskKey, TaskNode>,
    event: &EventSummary,
) -> TaskKey {
    let key = TaskKey {
        pid: event.pid,
        cookie: event.task_cookie,
    };
    if key.cookie != 0 {
        let provisional_key = TaskKey {
            pid: key.pid,
            cookie: 0,
        };
        let migrate = nodes
            .get(&provisional_key)
            .is_some_and(|node| node.provisional)
            && !nodes.contains_key(&key);
        if migrate {
            let mut node = nodes.remove(&provisional_key).unwrap();
            node.provisional = false;
            nodes.insert(key, node);
            return key;
        }
    }
    let node = nodes.entry(key).or_insert_with(|| TaskNode {
        parent: None,
        comm: "?".into(),
        provisional: false,
        ..TaskNode::default()
    });
    if key.cookie == 0 {
        node.provisional = false;
    }
    key
}

/// Every task's parent as the whole recording settled it, with a parent that
/// is a thread of a process replaced by the process's main task. A task that
/// starts running (a `vfork` child that execs at once) is seen before the
/// call that created it returns, so this is read from a full pass and not
/// from the calls seen so far.
pub(super) fn settled_parents(
    nodes: &std::collections::BTreeMap<TaskKey, TaskNode>,
) -> std::collections::BTreeMap<TaskKey, TaskKey> {
    let mut main: std::collections::BTreeMap<u32, TaskKey> = Default::default();
    for (key, node) in nodes {
        if key.cookie != 0 && node.tid == key.pid {
            main.entry(key.pid).or_insert(*key);
        }
    }
    nodes
        .iter()
        .filter_map(|(key, node)| {
            let parent = node.parent?;
            let is_thread = nodes
                .get(&parent)
                .is_some_and(|node| node.tid != 0 && node.tid != parent.pid);
            let parent = if is_thread {
                main.get(&parent.pid).copied().unwrap_or(parent)
            } else {
                parent
            };
            Some((*key, parent))
        })
        .collect()
}

fn link_child(
    nodes: &mut std::collections::BTreeMap<TaskKey, TaskNode>,
    parent: TaskKey,
    child_pid: u32,
) {
    if child_pid == 0 || child_pid == parent.pid {
        return;
    }
    let inherited = nodes
        .get(&parent)
        .filter(|node| node.comm != "?")
        .map(|node| {
            (
                node.comm.clone(),
                node.argv.clone(),
                node.command_line.clone(),
                node.proctitle.clone(),
            )
        });
    let mut candidates: Vec<TaskKey> = nodes
        .iter()
        .filter(|(key, node)| key.pid == child_pid && **key != parent && node.parent.is_none())
        .map(|(key, _)| *key)
        .collect();
    if candidates.len() > 1 {
        // The forked process's own threads share its pid: only the task whose
        // tid is the pid is the child.
        let leaders: Vec<TaskKey> = candidates
            .iter()
            .copied()
            .filter(|key| nodes.get(key).is_some_and(|node| node.tid == child_pid))
            .collect();
        if leaders.len() == 1 {
            candidates = leaders;
        }
    }
    match candidates.as_slice() {
        [child] => {
            if let Some(node) = nodes.get_mut(child) {
                node.parent = Some(parent);
                node.provisional = false;
                if node.comm == "?" {
                    if let Some((comm, argv, line, title)) = &inherited {
                        node.comm.clone_from(comm);
                        node.argv.clone_from(argv);
                        node.command_line.clone_from(line);
                        node.proctitle.clone_from(title);
                        node.forked = !node.exec_unnamed;
                    }
                }
            }
        }
        [] => {
            let child = TaskKey {
                pid: child_pid,
                cookie: 0,
            };
            match nodes.get_mut(&child) {
                Some(node) if node.parent.is_none() => node.parent = Some(parent),
                Some(_) => {}
                None => {
                    nodes.insert(
                        child,
                        TaskNode {
                            parent: Some(parent),
                            comm: inherited
                                .as_ref()
                                .map_or_else(|| "?".into(), |image| image.0.clone()),
                            argv: inherited
                                .as_ref()
                                .map_or_else(Vec::new, |image| image.1.clone()),
                            command_line: inherited.as_ref().and_then(|image| image.2.clone()),
                            proctitle: inherited.as_ref().and_then(|image| image.3.clone()),
                            provisional: true,
                            forked: inherited.is_some(),
                            ..TaskNode::default()
                        },
                    );
                }
            }
        }
        _ => {}
    }
}

fn spawn_kind(invocation: &InvocationSummary, name: &str, args: Option<[u64; 6]>) -> Option<Spawn> {
    match name {
        "fork" | "vfork" => Some(Spawn::Process),
        "clone" => Some(
            if args.is_some_and(|args| clone_flags(&args) & CLONE_THREAD != 0) {
                Spawn::Skip
            } else {
                Spawn::Process
            },
        ),
        "clone3" => Some(match clone3_is_thread(invocation) {
            Some(true) => Spawn::Skip,
            Some(false) => Spawn::Process,
            None => Spawn::Skip,
        }),
        _ => None,
    }
}

/// `Some` when the call's flags can be read. `None` means the recording has no
/// usable flags, so the caller must not invent an edge.
fn clone3_is_thread(invocation: &InvocationSummary) -> Option<bool> {
    Some(super::descriptors::clone3_flags(invocation)? & CLONE_THREAD != 0)
}

pub(super) fn program_name(
    entry: Option<&EventSummary>,
    exit: Option<&EventSummary>,
) -> Option<String> {
    entry.into_iter().chain(exit).find_map(|event| {
        event
            .fields
            .iter()
            .filter(|field| path_key(&field.key))
            .find_map(path_text)
    })
}

pub(super) fn committed_exec(invocation: &InvocationSummary) -> bool {
    invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .chain(&invocation.async_events)
        .any(|event| {
            event.fields.iter().any(|field| {
                field.key == "lifecycle.exec_commit"
                    && field.complete
                    && trace::covered_preview(field).len() >= 8
            })
        })
        || trace::representative(invocation)
            .is_some_and(|event| matches!(event.syscall_name.as_str(), "execve" | "execveat"))
            && succeeded(invocation)
}

/// The program a call's task runs. A worker thread (tid != pid) is named by its
/// process: the thread group leader's image, whatever the thread called itself.
pub(super) fn process_image<'a>(files: &'a FdState, event: &EventSummary) -> Option<&'a str> {
    let named = |node: &'a TaskNode| {
        Some(node.comm.as_str()).filter(|image| !image.is_empty() && *image != "?")
    };
    let exact = files.process_images.get(&TaskKey {
        pid: event.pid,
        cookie: event.task_cookie,
    });
    if event.tid == event.pid || event.tid == 0 {
        return exact.and_then(named);
    }
    let pid = event.pid;
    let leader = files
        .process_images
        .range(
            TaskKey { pid, cookie: 0 }..=TaskKey {
                pid,
                cookie: u64::MAX,
            },
        )
        .map(|(_, node)| node)
        .filter(|node| node.tid == 0 || node.tid == pid)
        .find_map(named);
    leader.or_else(|| exact.and_then(named))
}

pub(super) fn process_identity(pid: u32, tid: u32, image: Option<&str>) -> String {
    let name = image
        .and_then(|image| image.rsplit('/').find(|part| !part.is_empty()))
        .unwrap_or("Unknown");
    format!("{name} (PID {pid} \u{b7} TID {tid})")
}

/// A task as the user reads it: the process and the thread, never the
/// recording's internal task cookie (that is in the details).
pub(super) fn process_label(node: &ProcessNode) -> String {
    let ids = match node.tid {
        0 => format!("({} \u{b7} ?)", node.pid),
        tid => format!("({} \u{b7} {tid})", node.pid),
    };
    let mut text = if node.thread {
        format!("{ids}  thread")
    } else {
        let name = match node.comm.as_str() {
            "?" | "" => "unknown",
            comm => process_cells::file_name(comm),
        };
        format!("{name} {ids}")
    };
    if node.forked {
        text.push_str("  fork");
    }
    if node.parent_missing {
        text.push_str("  parent not in this trace");
    }
    text
}

/// The recording's internal id of a task, for the details.
pub(super) fn task_id_text(cookie: u64) -> String {
    if cookie == 0 {
        "unknown".into()
    } else {
        cookie.to_string()
    }
}

/// The spelled-out label the tree-shape tests read.
#[cfg(test)]
fn plain_label(node: &ProcessNode) -> String {
    let mut text = format!("PID {}", node.pid);
    match node.tid {
        0 => text.push_str(" \u{b7} TID unknown"),
        tid if tid == node.pid => text.push_str(&format!(" \u{b7} TID {tid} (main)")),
        tid => text.push_str(&format!(" \u{b7} TID {tid}")),
    }
    if node.thread {
        text.push_str("  thread");
    }
    if node.parent_missing {
        text.push_str("  parent not in this trace");
    }
    text
}

#[cfg(test)]
pub(super) fn process_tree_lines(invocations: &[InvocationSummary]) -> Vec<String> {
    process_nodes(invocations)
        .into_iter()
        .map(|node| {
            format!(
                "{}{}  {}",
                "  ".repeat(node.depth),
                plain_label(&node),
                node.comm
            )
        })
        .collect()
}

/// What a fork, vfork or clone made, as the guest's own child record says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Born {
    /// A new process (its thread group id is its own id): the pid.
    Process(u32),
    /// A new thread of the caller's process.
    Thread,
}

/// The child the guest recorded for a call (`lifecycle.child_tgid`, `_pid`),
/// read without the call's flags, which `clone3` keeps in a struct that may not
/// have been captured. `caller` is the thread group id of the calling task.
pub(super) fn lifecycle_born(invocation: &InvocationSummary, caller: u32) -> Option<Born> {
    let child = antinomie_monitor_core::kernel_notes::child_task(
        invocation
            .kernel_notes
            .iter()
            .chain(invocation.async_events.iter())
            .chain(invocation.exit.iter())
            .chain(invocation.entry.iter()),
    )?;
    if child.tgid == caller {
        Some(Born::Thread)
    } else if child.tgid == child.tid.unwrap_or(child.tgid) {
        Some(Born::Process(child.tgid))
    } else {
        None
    }
}

/// The arguments the exec was given: every string that was captured whole, a
/// gap where one was not.
fn exec_argv(invocation: &InvocationSummary, event: &EventSummary) -> Vec<String> {
    if let Some(vector) = normalized::argument_vector(invocation, event) {
        if !vector.arguments.is_empty() {
            return vector
                .arguments
                .into_iter()
                .map(|argument| argument.unwrap_or_else(|| "\u{2026}".into()))
                .collect();
        }
    }
    invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .chain(invocation.async_events.iter())
        .flat_map(|event| &event.fields)
        .filter(|field| field.key.contains("argv"))
        .filter_map(path_text)
        .collect()
}

/// The text a captured buffer argument held, up to its first NUL or newline.
fn argument_text(invocation: &InvocationSummary, index: usize) -> Option<String> {
    let prefix = format!("arg{index}.");
    let field = invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| &event.fields)
        .find(|field| field.key.starts_with(&prefix) && !field.key.contains('['))?;
    let bytes = trace::covered_preview(field);
    let end = bytes
        .iter()
        .position(|byte| *byte == 0 || *byte == b'\n')
        .unwrap_or(bytes.len());
    let text = std::str::from_utf8(&bytes[..end]).ok()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// A name the task gave itself: `prctl(PR_SET_NAME)`, or a write to a `comm`
/// file it opened (`/proc/self/comm`, `/proc/<pid>/task/<tid>/comm`).
fn observe_rename(
    nodes: &mut std::collections::BTreeMap<TaskKey, TaskNode>,
    key: TaskKey,
    invocation: &InvocationSummary,
    event: &EventSummary,
) {
    let args = event.args.unwrap_or_default();
    let result = invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .or(event.result);
    let name = match event.syscall_name.as_str() {
        "prctl" if args[0] == 15 => argument_text(invocation, 1),
        "open" | "openat" | "openat2" | "creat" => {
            let comm = invocation
                .entry
                .iter()
                .chain(invocation.exit.iter())
                .flat_map(|event| &event.fields)
                .filter(|field| path_key(&field.key))
                .find_map(path_text)
                .is_some_and(|path| path.starts_with("/proc/") && path.ends_with("/comm"));
            if let (true, Some(fd @ 0..)) = (comm, result) {
                if let Some(node) = nodes.get_mut(&key) {
                    node.comm_fds.push(fd);
                }
            }
            None
        }
        "close" => {
            if let Some(node) = nodes.get_mut(&key) {
                node.comm_fds.retain(|fd| *fd as u64 != args[0]);
            }
            None
        }
        "write" | "pwrite64"
            if nodes
                .get(&key)
                .is_some_and(|node| node.comm_fds.iter().any(|fd| *fd as u64 == args[0])) =>
        {
            argument_text(invocation, 1)
        }
        _ => None,
    };
    if let (Some(name), Some(node)) = (name, nodes.get_mut(&key)) {
        if node.renames.last() != Some(&name) && node.renames.len() < 16 {
            node.renames.push(name);
        }
    }
}

/// The task's outcome, with the call it was still in at the end of the
/// recording when its exit was not recorded.
fn state_text(
    node: &ProcessNode,
    end: Option<u64>,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> String {
    let Some((name, start)) = &node.in_call else {
        return node.state.clone();
    };
    let for_how_long = end
        .filter(|end| end > start)
        .map(|end| {
            format!(
                ", {:.1} s before the last record",
                (end - start) as f64 / 1e9
            )
        })
        .unwrap_or_default();
    format!(
        "{}; still in progress at the stop: {name} since {}{for_how_long}",
        node.state,
        crate::time_format::guest_ns(clock, Some(*start))
    )
}

/// The exec history, then the names the task took after the last exec.
fn history_text(node: &ProcessNode) -> String {
    let mut text = process_cells::exec_chain(&node.exec_history);
    for name in &node.renames {
        if !text.is_empty() {
            text.push_str("; ");
        }
        text.push_str(&format!("renamed to {name:?}"));
    }
    text
}

/// A task whose tid is not its pid is a thread of that process. Threads that
/// no fork call claimed go under the process (the task with tid = pid, else
/// the earliest task of the pid) and take its image. Returns the threads.
fn attach_threads(
    nodes: &mut std::collections::BTreeMap<TaskKey, TaskNode>,
) -> std::collections::BTreeSet<TaskKey> {
    let mut by_pid: std::collections::BTreeMap<u32, Vec<TaskKey>> = Default::default();
    for key in nodes.keys() {
        if key.pid != 0 && key.cookie != 0 {
            by_pid.entry(key.pid).or_default().push(*key);
        }
    }
    let mut threads = std::collections::BTreeSet::new();
    for (pid, group) in by_pid {
        let is_thread = |nodes: &std::collections::BTreeMap<TaskKey, TaskNode>, key: &TaskKey| {
            nodes
                .get(key)
                .is_some_and(|node| node.tid != 0 && node.tid != pid)
        };
        if group.len() < 2 {
            // A lone task whose tid is not its pid is still a thread of a
            // process that is not in the trace; it stays where it is.
            continue;
        }
        let early = |nodes: &std::collections::BTreeMap<TaskKey, TaskNode>, key: &TaskKey| {
            nodes
                .get(key)
                .and_then(|node| node.first_ns)
                .unwrap_or(u64::MAX)
        };
        let leader = group
            .iter()
            .filter(|key| !is_thread(nodes, key))
            .min_by_key(|key| early(nodes, key))
            .or_else(|| group.iter().min_by_key(|key| early(nodes, key)))
            .copied();
        let Some(leader) = leader else { continue };
        let image = nodes
            .get(&leader)
            .filter(|node| node.comm != "?")
            .map(|node| {
                (
                    node.comm.clone(),
                    node.argv.clone(),
                    node.command_line.clone(),
                    node.proctitle.clone(),
                )
            });
        for key in group {
            if key == leader
                || !is_thread(nodes, &key)
                || nodes.get(&key).is_some_and(|node| node.parent.is_some())
            {
                continue;
            }
            threads.insert(key);
            if let Some(node) = nodes.get_mut(&key) {
                node.parent = Some(leader);
                if let (true, Some((comm, argv, line, title))) = (node.comm == "?", &image) {
                    node.comm.clone_from(comm);
                    node.argv.clone_from(argv);
                    node.command_line.clone_from(line);
                    node.proctitle.clone_from(title);
                }
            }
        }
    }
    threads
}
