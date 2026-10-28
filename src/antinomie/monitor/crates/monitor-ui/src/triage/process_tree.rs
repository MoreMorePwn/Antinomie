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

pub(super) fn process_tree_nodes(
    ui: &mut egui::Ui,
    nodes: &[ProcessNode],
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
    suspicious: &Suspicious,
) {
    let rows = nodes
        .iter()
        .map(|node| {
            let mut row = vec![
                cell(
                    process_label(node),
                    theme::value(theme::ValueKind::Pointer),
                    true,
                ),
                cell(
                    node.comm.clone(),
                    theme::value(theme::ValueKind::Name),
                    true,
                ),
                cell(node.tid.to_string(), theme::text(), true),
                cell(node.argv.join(" "), theme::text(), false),
                cell(
                    crate::time_format::guest_ns(clock, node.first_ns),
                    theme::text(),
                    true,
                ),
                cell(
                    crate::time_format::guest_ns(clock, node.last_ns),
                    theme::text(),
                    true,
                ),
                cell(&node.state, theme::text(), false),
                cell(node.exec_history.join(" → "), theme::text(), false),
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
                ("process.state", RowValue::Text(node.state.clone())),
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
        .collect::<Vec<_>>();
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
    let filtered = rows
        .into_iter()
        .filter(|row| compiled.keep_table(&row[0].values))
        .collect::<Vec<_>>();
    // The tree is of the rows that are left: a filter leaves gaps, not stale
    // branches.
    let depths = filtered
        .iter()
        .map(|row| files::number(&row[0].values, "process.depth").map_or(0, |depth| depth as usize))
        .collect::<Vec<_>>();
    table_with(
        ui,
        "triage-process",
        &[
            "Process",
            "Executable",
            "TID",
            "Argv",
            "First seen",
            "Last seen",
            "Task outcome",
            "Exec history",
        ],
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
            if invocation.task_exit.is_some() {
                node.state = format!("task exit {:?}", invocation.task_exit_status());
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
            if named.is_none() {
                if let Some(node) = nodes.get_mut(&key) {
                    node.comm = "?".into();
                    node.argv.clear();
                    node.command_line = None;
                    node.proctitle = None;
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
                node.argv = entry
                    .into_iter()
                    .chain(exit)
                    .chain(invocation.async_events.iter())
                    .flat_map(|event| &event.fields)
                    .filter(|field| field.key.contains("argv"))
                    .filter_map(path_text)
                    .collect();
                node.command_line = normalized::command_line(invocation, event);
                node.proctitle = normalized::complete_argv(invocation, event);
            }
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
    nodes: std::collections::BTreeMap<TaskKey, TaskNode>,
) -> Vec<ProcessNode> {
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
                parent_missing: depth == 0 && !node.root,
                tid: node.tid,
                argv: node.argv.clone(),
                first_ns: node.first_ns,
                last_ns: node.last_ns,
                state: node.state.clone(),
                exec_history: node.exec_history.clone(),
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
        walk(key, 0, &nodes, &children, &mut found, &mut seen);
    }
    for key in nodes.keys() {
        if !seen.contains(key) {
            walk(*key, 0, &nodes, &children, &mut found, &mut seen);
        }
    }
    found
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
    let candidates: Vec<TaskKey> = nodes
        .iter()
        .filter(|(key, node)| key.pid == child_pid && **key != parent && node.parent.is_none())
        .map(|(key, _)| *key)
        .collect();
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

/// `Some` when a captured field key contains both `clone_args` and `flags`
/// and its bytes are a 4- or 8-byte little-endian integer. `None` means the
/// recording has no usable flags, so the caller must not invent an edge.
fn clone3_is_thread(invocation: &InvocationSummary) -> Option<bool> {
    let field = invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .chain(invocation.async_events.iter())
        .flat_map(|event| event.fields.iter())
        .find(|field| field.key.contains("clone_args") && field.key.contains("flags"))?;
    let bytes = trace::covered_preview(field);
    let flags = match bytes.len() {
        4 => u64::from(u32::from_le_bytes(bytes.try_into().ok()?)),
        8 => u64::from_le_bytes(bytes.try_into().ok()?),
        _ => return None,
    };
    Some(flags & CLONE_THREAD != 0)
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

pub(super) fn process_image<'a>(files: &'a FdState, event: &EventSummary) -> Option<&'a str> {
    files
        .process_images
        .get(&TaskKey {
            pid: event.pid,
            cookie: event.task_cookie,
        })
        .map(|node| node.comm.as_str())
        .filter(|image| !image.is_empty() && *image != "?")
}

pub(super) fn process_identity(pid: u32, tid: u32, image: Option<&str>) -> String {
    let name = image
        .and_then(|image| image.rsplit('/').find(|part| !part.is_empty()))
        .unwrap_or("Unknown");
    format!("{name} ({pid} / {tid})")
}

pub(super) fn process_label(node: &ProcessNode) -> String {
    let cookie = if node.cookie == 0 {
        "unknown".to_string()
    } else {
        node.cookie.to_string()
    };
    let mut text = format!("pid {} cookie {cookie}", node.pid);
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
                process_label(&node),
                node.comm
            )
        })
        .collect()
}
