// SPDX-License-Identifier: MIT
//! Triage for the selected run: process activity, files, HTTP/DNS and eBPF.
//! Rows are observations from captured syscalls and packets, not a verdict.
use crate::{bpf, theme, trace};
use antinomie_monitor_core::{network::NetworkPacket, EventSummary, InvocationSummary};
use eframe::egui::{self, RichText};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Process,
    Files,
    Network,
    Bpf,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessTab {
    Tree,
    Suspicious,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileTab {
    Opened,
    Changed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NetTab {
    Http,
    Dns,
}

pub(crate) struct TriageView {
    section: Section,
    process: ProcessTab,
    files: FileTab,
    network: NetTab,
    /// Case-insensitive substring for rule, process, summary, or evidence.
    suspicious_filter: String,
    /// Invocation chosen from a Suspicious activity row.
    selected_call_id: Option<u64>,
}

impl Default for TriageView {
    fn default() -> Self {
        Self {
            section: Section::Process,
            process: ProcessTab::Tree,
            files: FileTab::Opened,
            network: NetTab::Http,
            suspicious_filter: String::new(),
            selected_call_id: None,
        }
    }
}

pub(crate) struct TriageInput<'a> {
    pub invocations: &'a [InvocationSummary],
    pub packets: &'a [NetworkPacket],
    /// Ethernet frames parallel to `packets`. Absent when the list has no payload.
    pub frames: Option<&'a [Vec<u8>]>,
    pub vm_id: Option<&'a str>,
    pub boot_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    /// What this view actually covered. Never claim a whole run from one page.
    pub coverage: &'a str,
}

impl<'a> TriageInput<'a> {
    #[cfg(test)]
    fn page(invocations: &'a [InvocationSummary], packets: &'a [NetworkPacket]) -> Self {
        Self {
            invocations,
            packets,
            frames: None,
            vm_id: None,
            boot_id: None,
            run_id: None,
            coverage: "this loaded page",
        }
    }
}

impl TriageView {
    /// `Some(call_id)` on the frame a Suspicious activity row is clicked.
    pub(crate) fn show(&mut self, ui: &mut egui::Ui, input: TriageInput<'_>) -> Option<u64> {
        ui.horizontal_wrapped(|ui| {
            for (section, label) in [
                (Section::Process, "Process"),
                (Section::Files, "Files"),
                (Section::Network, "Network activity"),
                (Section::Bpf, "eBPF"),
            ] {
                ui.selectable_value(&mut self.section, section, label);
            }
        });
        ui.separator();
        ui.colored_label(theme::muted(), format!("Coverage: {}.", input.coverage));
        let identity = [input.vm_id, input.boot_id, input.run_id]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" / ");
        if !identity.is_empty() {
            ui.colored_label(theme::muted(), identity);
        }
        match self.section {
            Section::Process => self.process(ui, &input),
            Section::Files => {
                self.files(ui, input.invocations);
                None
            }
            Section::Network => {
                self.network(ui, &input);
                None
            }
            Section::Bpf => {
                bpf_view(ui, &input);
                None
            }
        }
    }

    fn process(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) -> Option<u64> {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.process, ProcessTab::Tree, "Process tree");
            ui.selectable_value(
                &mut self.process,
                ProcessTab::Suspicious,
                "Suspicious activity",
            );
        });
        match self.process {
            ProcessTab::Tree => {
                process_tree(ui, input.invocations);
                None
            }
            ProcessTab::Suspicious => self.suspicious(ui, input.invocations),
        }
    }

    fn files(&mut self, ui: &mut egui::Ui, invocations: &[InvocationSummary]) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.files, FileTab::Opened, "Opened files");
            ui.selectable_value(&mut self.files, FileTab::Changed, "Changed files");
        });
        let wanted: &[&str] = match self.files {
            FileTab::Opened => &["open", "openat", "openat2"],
            FileTab::Changed => &[
                "write",
                "writev",
                "pwrite64",
                "mmap",
                "mmap2",
                "unlink",
                "unlinkat",
                "rename",
                "renameat",
                "renameat2",
                "truncate",
                "ftruncate",
                "mkdir",
                "mkdirat",
                "rmdir",
                "chmod",
                "fchmod",
                "fchmodat",
                "chown",
                "fchown",
                "lchown",
                "fchownat",
            ],
        };
        limited_table(
            ui,
            "triage-files",
            &["Path", "Process", "FD", "Operation", "Result", "Outcome"],
            &file_rows(invocations, wanted),
        );
    }

    fn network(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.network, NetTab::Http, "All HTTP requests");
            ui.selectable_value(&mut self.network, NetTab::Dns, "All DNS requests");
        });
        match self.network {
            NetTab::Http => {
                ui.colored_label(
                    theme::muted(),
                    if input.frames.is_none() {
                        "Request reconstruction is unavailable for this view: the loaded packet list has no payload. Supported when frames are present: HTTP/1.0 and HTTP/1.1 over TCP. Unavailable: HTTPS, HTTP/2, and HTTP/3."
                    } else {
                        "Reassembled from captured TCP payloads. Supported: HTTP/1.0 and HTTP/1.1. Unavailable: HTTPS, HTTP/2, and HTTP/3."
                    },
                );
                limited_table(
                    ui,
                    "triage-http",
                    &["Frame", "Endpoints", "Request", "Response", "Process"],
                    &http_rows(input),
                );
            }
            NetTab::Dns => {
                ui.colored_label(
                    theme::muted(),
                    if input.frames.is_none() {
                        "DNS reconstruction is unavailable for this view: the loaded packet list has no payload. Supported when frames are present: DNS over UDP and DNS over TCP. Unavailable: DNS over TLS and DNS over HTTPS."
                    } else {
                        "Decoded from captured UDP and TCP payloads. Unavailable: DNS over TLS and DNS over HTTPS."
                    },
                );
                limited_table(
                    ui,
                    "triage-dns",
                    &["Frame", "Endpoints", "Query", "Kind"],
                    &dns_rows(input),
                );
            }
        }
    }

    fn suspicious(&mut self, ui: &mut egui::Ui, invocations: &[InvocationSummary]) -> Option<u64> {
        ui.colored_label(
            theme::muted(),
            "A row is a rule match with its source. It is not a verdict that the sample is malicious.",
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.suspicious_filter)
                .hint_text("Filter rule, process, summary, or evidence")
                .desired_width(f32::INFINITY),
        );
        let rows = filter_findings(suspicious_rows(invocations), &self.suspicious_filter);
        let clicked = finding_table(
            ui,
            "triage-findings",
            &[
                "Rule",
                "Severity",
                "Process",
                "Summary",
                "Source",
                "Time",
                "Confidence",
                "Evidence",
                "Version",
            ],
            &rows,
            self.selected_call_id,
        );
        if let Some(call_id) = clicked {
            self.selected_call_id = Some(call_id);
        }
        clicked
    }
}

struct Cell {
    text: String,
    color: egui::Color32,
    mono: bool,
}

fn cell(text: impl Into<String>, color: egui::Color32, mono: bool) -> Cell {
    Cell {
        text: text.into(),
        color,
        mono,
    }
}

struct LimitedRows {
    rows: Vec<Vec<Cell>>,
    /// The loaded page is not truncated. Callers still observe this as false.
    stopped_early: bool,
}

fn push_limited(limited: &mut LimitedRows, row: Vec<Cell>) -> bool {
    limited.rows.push(row);
    true
}

fn limited_table(ui: &mut egui::Ui, id: &str, headers: &[&str], limited: &LimitedRows) {
    // Every row built from the loaded invocations and packets is shown.
    // The count is the size of this page, not of the whole recording.
    let _ = limited.stopped_early;
    ui.colored_label(
        theme::muted(),
        format!("{} rows in this loaded page.", limited.rows.len()),
    );
    table(ui, id, headers, &limited.rows);
}

fn table(ui: &mut egui::Ui, id: &str, headers: &[&str], rows: &[Vec<Cell>]) {
    use egui_extras::{Column, TableBuilder};
    if rows.is_empty() {
        ui.colored_label(theme::muted(), "Nothing recorded for this view.");
        return;
    }
    let mut builder = TableBuilder::new(ui)
        .id_salt(id)
        .striped(true)
        .resizable(true)
        .vscroll(true);
    for index in 0..headers.len() {
        builder = if index + 1 == headers.len() {
            builder.column(Column::remainder().at_least(140.0))
        } else {
            builder.column(Column::auto().at_least(64.0).resizable(true))
        };
    }
    builder
        .header(22.0, |mut header| {
            for title in headers {
                header.col(|ui| {
                    ui.strong(*title);
                });
            }
        })
        .body(|body| {
            body.rows(22.0, rows.len(), |mut row| {
                let cells = &rows[row.index()];
                for cell in cells {
                    row.col(|ui| {
                        let mut text = RichText::new(&cell.text).color(cell.color);
                        if cell.mono {
                            text = text.monospace();
                        }
                        ui.add(egui::Label::new(text).truncate());
                    });
                }
            });
        });
}

struct Finding {
    cells: Vec<Cell>,
    call_id: u64,
}

/// Suspicious-activity rows. A click returns that invocation's `call_id`.
fn finding_table(
    ui: &mut egui::Ui,
    id: &str,
    headers: &[&str],
    rows: &[Finding],
    selected: Option<u64>,
) -> Option<u64> {
    use egui_extras::{Column, TableBuilder};
    if rows.is_empty() {
        ui.colored_label(theme::muted(), "Nothing recorded for this view.");
        return None;
    }
    let mut clicked = None;
    let mut builder = TableBuilder::new(ui)
        .id_salt(id)
        .striped(true)
        .resizable(true)
        .vscroll(true)
        .sense(egui::Sense::click());
    for index in 0..headers.len() {
        builder = if index + 1 == headers.len() {
            builder.column(Column::remainder().at_least(140.0))
        } else {
            builder.column(Column::auto().at_least(64.0).resizable(true))
        };
    }
    builder
        .header(22.0, |mut header| {
            for title in headers {
                header.col(|ui| {
                    ui.strong(*title);
                });
            }
        })
        .body(|body| {
            body.rows(22.0, rows.len(), |mut row| {
                let finding = &rows[row.index()];
                row.set_selected(selected == Some(finding.call_id));
                for cell in &finding.cells {
                    row.col(|ui| {
                        let mut text = RichText::new(&cell.text).color(cell.color);
                        if cell.mono {
                            text = text.monospace();
                        }
                        ui.add(egui::Label::new(text).truncate());
                    });
                }
                if row.response().clicked() {
                    clicked = Some(finding.call_id);
                }
            });
        });
    clicked
}

fn process_tree(ui: &mut egui::Ui, invocations: &[InvocationSummary]) {
    ui.colored_label(
        theme::muted(),
        "Parent and child from fork, vfork and clone in this trace. Only pid 1 with no parent edge is a root.",
    );
    let rows = process_nodes(invocations)
        .into_iter()
        .map(|node| {
            vec![
                cell(
                    format!("{}{}", "│ ".repeat(node.depth), process_label(&node)),
                    theme::value(theme::ValueKind::Pointer),
                    true,
                ),
                cell(node.comm, theme::value(theme::ValueKind::Name), true),
            ]
        })
        .collect::<Vec<_>>();
    table(ui, "triage-process", &["Process", "Program"], &rows);
}

/// x86-64: clone, fork, vfork, clone3. `CLONE_THREAD` stays inside the parent.
/// `clone` reads that bit from `args[0]`. `clone3`'s `args[0]` is a pointer, so
/// its flags come only from a captured `clone_args` flags field.
const CLONE: u64 = 56;
const FORK: u64 = 57;
const VFORK: u64 = 58;
const CLONE3: u64 = 435;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_FILES: u64 = 0x0000_0400;
const AT_FDCWD: u64 = (-100i64) as u64;
const MAP_ANONYMOUS: u64 = 0x20;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TaskKey {
    pid: u32,
    cookie: u64,
}

struct TaskNode {
    parent: Option<TaskKey>,
    comm: String,
    /// Fork return created this pid before any event identified its cookie.
    provisional: bool,
}

enum Spawn {
    /// A new process. The returned pid is the child.
    Process,
    /// A thread, or clone3 whose flags were not captured. No parent/child edge.
    Skip,
}

fn process_nodes(invocations: &[InvocationSummary]) -> Vec<ProcessNode> {
    let mut nodes: std::collections::BTreeMap<TaskKey, TaskNode> =
        std::collections::BTreeMap::new();
    for invocation in invocations {
        let entry = invocation.entry.as_ref();
        let exit = invocation.exit.as_ref();
        let Some(event) = entry.or(exit) else {
            continue;
        };
        if event.pid == 0 {
            continue;
        }
        let key = adopt_task(&mut nodes, event);
        if matches!(event.syscall_name.as_str(), "execve" | "execveat")
            && exit
                .and_then(|exit| exit.result)
                .is_some_and(|result| result >= 0)
        {
            if let Some(comm) = program_name(entry, exit) {
                nodes.get_mut(&key).unwrap().comm = comm;
            }
        }
        let args = entry
            .and_then(|event| event.args)
            .or(exit.and_then(|event| event.args));
        if !matches!(
            spawn_kind(invocation, event.syscall_nr, args),
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
        link_child(&mut nodes, key, child);
    }
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
        if !seen.insert(key) {
            return;
        }
        let Some(node) = nodes.get(&key) else {
            return;
        };
        found.push(ProcessNode {
            depth,
            pid: key.pid,
            cookie: key.cookie,
            comm: node.comm.clone(),
            parent_missing: depth == 0 && !(node.parent.is_none() && key.pid == 1),
        });
        if let Some(kids) = children.get(&key) {
            for child in kids {
                walk(*child, depth + 1, nodes, children, found, seen);
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for key in roots {
        walk(key, 0, &nodes, &children, &mut found, &mut seen);
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
                            comm: "?".into(),
                            provisional: true,
                        },
                    );
                }
            }
        }
        _ => {}
    }
}

fn spawn_kind(invocation: &InvocationSummary, nr: u64, args: Option<[u64; 6]>) -> Option<Spawn> {
    match nr {
        FORK | VFORK => Some(Spawn::Process),
        CLONE => Some(if args.is_some_and(|args| args[0] & CLONE_THREAD != 0) {
            Spawn::Skip
        } else {
            Spawn::Process
        }),
        CLONE3 => Some(match clone3_is_thread(invocation) {
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

fn program_name(entry: Option<&EventSummary>, exit: Option<&EventSummary>) -> Option<String> {
    entry.into_iter().chain(exit).find_map(|event| {
        let comm = preview_line(event);
        (comm != event.syscall_name).then_some(comm)
    })
}

struct ProcessNode {
    depth: usize,
    pid: u32,
    cookie: u64,
    comm: String,
    parent_missing: bool,
}

fn process_label(node: &ProcessNode) -> String {
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
fn process_tree_lines(invocations: &[InvocationSummary]) -> Vec<String> {
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

fn preview_line(event: &EventSummary) -> String {
    event
        .fields
        .iter()
        .find_map(|field| {
            let text = String::from_utf8_lossy(crate::trace::covered_preview(field))
                .trim_end_matches('\0')
                .trim()
                .to_owned();
            (!text.is_empty()).then_some(text)
        })
        .unwrap_or_else(|| event.syscall_name.clone())
}

fn hit(
    rule: &str,
    severity: &str,
    process: String,
    summary: String,
    source: &str,
    event: &EventSummary,
    invocation: &InvocationSummary,
) -> Finding {
    let color = if severity == "high" {
        theme::error()
    } else {
        theme::warn()
    };
    let time = if event.timestamp_ns == 0 {
        "—".to_string()
    } else {
        event.timestamp_ns.to_string()
    };
    Finding {
        call_id: invocation.call_id,
        cells: vec![
            cell(rule, color, false),
            cell(severity, color, false),
            cell(process, theme::text(), true),
            cell(summary, theme::text(), false),
            cell(source, theme::muted(), false),
            cell(time, theme::text(), true),
            cell(confidence(invocation), theme::text(), false),
            cell(
                format!("syscall {} call {}", event.syscall_name, invocation.call_id),
                theme::text(),
                true,
            ),
            cell("1", theme::text(), true),
        ],
    }
}

fn confidence(invocation: &InvocationSummary) -> &'static str {
    match invocation.exit.as_ref().and_then(|exit| exit.result) {
        Some(result) if result >= 0 => "observed",
        Some(_) => "attempted",
        None => "exit not recorded",
    }
}

fn call_args(invocation: &InvocationSummary) -> Option<[u64; 6]> {
    invocation
        .entry
        .as_ref()
        .and_then(|event| event.args)
        .or_else(|| invocation.exit.as_ref().and_then(|event| event.args))
}

fn outcome(invocation: &InvocationSummary) -> String {
    invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .map_or("exit not recorded".to_string(), |result| {
            if result < 0 {
                format!("failed ({result})")
            } else {
                format!("returned {result}")
            }
        })
}

/// `setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER)`. Another level with optname 26 is not a match.
fn classic_socket_filter(event: &EventSummary, args: [u64; 6]) -> bool {
    (event.syscall_name == "setsockopt" || event.syscall_nr == 54) && args[1] == 1 && args[2] == 26
}

fn filter_findings(rows: Vec<Finding>, filter: &str) -> Vec<Finding> {
    if filter.is_empty() {
        return rows;
    }
    let needle = filter.to_lowercase();
    rows.into_iter()
        .filter(|row| {
            [0, 2, 3, 7].iter().any(|index| {
                row.cells
                    .get(*index)
                    .is_some_and(|cell| cell.text.to_lowercase().contains(&needle))
            })
        })
        .collect()
}

fn suspicious_rows(invocations: &[InvocationSummary]) -> Vec<Finding> {
    let mut rows = Vec::new();
    for invocation in invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        let args = event.args.or(call_args(invocation)).unwrap_or([0; 6]);
        let process = format!("pid {} tid {}", event.pid, event.tid);
        let outcome = outcome(invocation);
        if matches!(event.syscall_nr, 9 | 10) && args.get(2).is_some_and(|prot| prot & 7 == 7) {
            rows.push(hit(
                "memory.rwx",
                "high",
                process.clone(),
                format!("{} prot {:#x}; {outcome}", event.syscall_name, args[2]),
                "MITRE ATT&CK T1055",
                event,
                invocation,
            ));
        }
        if matches!(event.syscall_nr, 59 | 322) {
            rows.push(hit(
                "process.exec",
                "medium",
                process.clone(),
                format!("{} {outcome}", preview_line(event)),
                "MITRE ATT&CK T1059.004",
                event,
                invocation,
            ));
        }
        if event.syscall_nr == 101 {
            rows.push(hit(
                "process.ptrace",
                "high",
                process.clone(),
                outcome.clone(),
                "MITRE ATT&CK T1055.008",
                event,
                invocation,
            ));
        }
        if matches!(event.syscall_nr, 310 | 311) {
            rows.push(hit(
                "process.vm_rw",
                "high",
                process.clone(),
                format!("{} {outcome}", event.syscall_name),
                "MITRE ATT&CK T1055.009",
                event,
                invocation,
            ));
        }
        if event.syscall_nr == 319 {
            rows.push(hit(
                "process.memfd",
                "medium",
                process.clone(),
                outcome.clone(),
                "MITRE ATT&CK DET0508",
                event,
                invocation,
            ));
        }
        if matches!(event.syscall_nr, 175 | 313) {
            rows.push(hit(
                "persistence.module",
                "high",
                process.clone(),
                format!("{} {outcome}", event.syscall_name),
                "MITRE ATT&CK T1547.006",
                event,
                invocation,
            ));
        }
        if let Some(command) = bpf::command_name(event) {
            if matches!(
                command,
                "BPF_PROG_LOAD" | "BPF_PROG_ATTACH" | "BPF_PROG_DETACH"
            ) {
                rows.push(hit(
                    "bpf.program",
                    "medium",
                    process.clone(),
                    format!("{command}; {outcome}"),
                    "Fournier, Afchain, Baubeau, Black Hat USA 2021",
                    event,
                    invocation,
                ));
            }
        }
        if classic_socket_filter(event, args) {
            rows.push(hit(
                "bpf.socket_filter",
                "medium",
                process,
                format!("classic socket filter; {outcome}"),
                "McCanne and Jacobson, USENIX 1993",
                event,
                invocation,
            ));
        }
    }
    rows
}

fn file_rows(invocations: &[InvocationSummary], names: &[&str]) -> LimitedRows {
    let mut limited = LimitedRows {
        rows: Vec::new(),
        stopped_early: false,
    };
    // Successful opens are remembered for this slice only. A fork, vfork, or
    // process clone copies the parent's map onto the child at that call,
    // unless the recorded flags include CLONE_FILES, which shares one table.
    // Later closes change only the task that owns the table.
    let mut files = FdState::default();
    let cookies = task_cookies(invocations);
    for invocation in invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        remember_cwd(&mut files, invocation, event);
        remember_open(&mut files, invocation, event);
        apply_dup(&mut files, invocation, event);
        forget_closed(&mut files, invocation, event);
        inherit_open_fds(&mut files, invocation, event, &cookies);
        if !names.iter().any(|name| event.syscall_name == *name) {
            continue;
        }
        if matches!(event.syscall_name.as_str(), "mmap" | "mmap2")
            && !call_args(invocation).is_some_and(|args| args[2] & 2 != 0)
        {
            continue;
        }
        let path = displayed_path(invocation, event, &files);
        let fd = file_fd(invocation, event);
        let result = invocation
            .exit
            .as_ref()
            .and_then(|exit| exit.result)
            .map(|result| result.to_string())
            .unwrap_or_else(|| "—".into());
        if !push_limited(
            &mut limited,
            vec![
                cell(
                    if path.is_empty() {
                        "—".to_string()
                    } else {
                        path
                    },
                    theme::text(),
                    true,
                ),
                cell(
                    format!("pid {} tid {}", event.pid, event.tid),
                    theme::text(),
                    true,
                ),
                cell(fd, theme::value(theme::ValueKind::Number), true),
                cell(
                    event.syscall_name.clone(),
                    theme::value(theme::ValueKind::Name),
                    false,
                ),
                cell(result, theme::text(), true),
                cell(file_outcome(invocation), theme::text(), false),
            ],
        ) {
            break;
        }
    }
    limited
}

/// Successful `open`, `openat` and `openat2` return the new descriptor.
/// Every other file operation uses the argument whose schema name is `fd`.
fn file_fd(invocation: &InvocationSummary, event: &EventSummary) -> String {
    if matches!(event.syscall_name.as_str(), "open" | "openat" | "openat2") {
        return invocation
            .exit
            .as_ref()
            .and_then(|exit| exit.result)
            .filter(|result| *result >= 0)
            .map(|result| result.to_string())
            .unwrap_or_else(|| "—".into());
    }
    fd_argument(invocation, event)
        .map(|fd| fd.to_string())
        .unwrap_or_else(|| "—".into())
}

/// The `fd` argument. `mmap2` is not in the x86-64 table; its descriptor is
/// still argument 4, the same slot `mmap` names `fd`.
fn fd_argument(invocation: &InvocationSummary, event: &EventSummary) -> Option<u64> {
    let args = call_args(invocation)?;
    let index = (0..args.len())
        .find(|index| trace::argument_name(event.syscall_nr, *index) == "fd")
        .or_else(|| matches!(event.syscall_name.as_str(), "mmap" | "mmap2").then_some(4))?;
    (index < args.len()).then_some(args[index])
}

#[derive(Default)]
struct FdState {
    /// `(owner cookie, owner pid, fd)` → path text captured for that descriptor.
    opened: std::collections::BTreeMap<(u64, u32, u64), String>,
    /// Child task → the task whose descriptor table it shares (`CLONE_FILES`).
    share: std::collections::BTreeMap<(u64, u32), (u64, u32)>,
    cwd: std::collections::BTreeMap<(u64, u32), String>,
}

fn table_owner(files: &FdState, cookie: u64, pid: u32) -> (u64, u32) {
    let mut key = (cookie, pid);
    for _ in 0..8 {
        match files.share.get(&key) {
            Some(next) if *next != key => key = *next,
            _ => break,
        }
    }
    key
}

fn file_outcome(invocation: &InvocationSummary) -> String {
    match invocation.exit.as_ref().and_then(|exit| exit.result) {
        Some(result) if result >= 0 => "successful".into(),
        Some(_) => "attempted".into(),
        None => "exit not recorded".into(),
    }
}

fn succeeded(invocation: &InvocationSummary) -> bool {
    invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .is_some_and(|result| result >= 0)
}

fn remember_open(files: &mut FdState, invocation: &InvocationSummary, event: &EventSummary) {
    if !matches!(event.syscall_name.as_str(), "open" | "openat" | "openat2") {
        return;
    }
    if !succeeded(invocation) {
        return;
    }
    let Some(result) = invocation.exit.as_ref().and_then(|exit| exit.result) else {
        return;
    };
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.pid);
    let key = (cookie, pid, result as u64);
    let paths = path_list(invocation);
    if paths.is_empty() {
        files.opened.remove(&key);
    } else {
        files.opened.insert(key, paths.join(", "));
    }
}

fn remember_cwd(files: &mut FdState, invocation: &InvocationSummary, event: &EventSummary) {
    if !succeeded(invocation) {
        return;
    }
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.pid);
    let path = match event.syscall_name.as_str() {
        "getcwd" | "chdir" => path_list(invocation).into_iter().next(),
        "fchdir" => call_args(invocation).and_then(|args| {
            files
                .opened
                .get(&(cookie, pid, args[0]))
                .cloned()
                .filter(|path| path.starts_with('/'))
        }),
        _ => None,
    };
    if let Some(path) = path.filter(|path| path.starts_with('/')) {
        files.cwd.insert((cookie, pid), path);
    }
}

/// `dup` returns the new descriptor. `dup2` and `dup3` name it in argument 1.
fn apply_dup(files: &mut FdState, invocation: &InvocationSummary, event: &EventSummary) {
    let kind = match (event.syscall_nr, event.syscall_name.as_str()) {
        (32, _) | (_, "dup") => DupKind::Return,
        (33, _) | (_, "dup2") | (292, _) | (_, "dup3") => DupKind::Argument,
        _ => return,
    };
    if !succeeded(invocation) {
        return;
    }
    let Some(args) = call_args(invocation) else {
        return;
    };
    let Some(result) = invocation.exit.as_ref().and_then(|exit| exit.result) else {
        return;
    };
    let new_fd = match kind {
        DupKind::Return => result as u64,
        DupKind::Argument => args[1],
    };
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.pid);
    let Some(path) = files.opened.get(&(cookie, pid, args[0])).cloned() else {
        return;
    };
    files.opened.insert((cookie, pid, new_fd), path);
}

enum DupKind {
    Return,
    Argument,
}

/// One cookie per pid when every event for that pid shares it. Two cookies
/// for one pid are not a guess: the caller uses 0.
fn task_cookies(invocations: &[InvocationSummary]) -> std::collections::BTreeMap<u32, u64> {
    let mut sets: std::collections::BTreeMap<u32, std::collections::BTreeSet<u64>> =
        std::collections::BTreeMap::new();
    for invocation in invocations {
        for event in invocation
            .entry
            .iter()
            .chain(invocation.exit.iter())
            .chain(invocation.async_events.iter())
        {
            if event.pid == 0 {
                continue;
            }
            sets.entry(event.pid)
                .or_default()
                .insert(invocation.task_cookie);
        }
    }
    sets.into_iter()
        .filter_map(|(pid, cookies)| {
            (cookies.len() == 1).then(|| (pid, cookies.into_iter().next().unwrap()))
        })
        .collect()
}

/// A successful `close` drops that task's descriptor only.
fn forget_closed(files: &mut FdState, invocation: &InvocationSummary, event: &EventSummary) {
    if event.syscall_name != "close" && event.syscall_nr != 3 {
        return;
    }
    if !succeeded(invocation) {
        return;
    }
    let Some(fd) = fd_argument(invocation, event) else {
        return;
    };
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.pid);
    files.opened.remove(&(cookie, pid, fd));
}

/// Snapshot the parent's open descriptors onto the new process. The child
/// keeps its own entries; a later close does not edit the parent.
fn inherit_open_fds(
    files: &mut FdState,
    invocation: &InvocationSummary,
    event: &EventSummary,
    cookies: &std::collections::BTreeMap<u32, u64>,
) {
    if !matches!(
        spawn_kind(invocation, event.syscall_nr, call_args(invocation)),
        Some(Spawn::Process)
    ) {
        return;
    }
    let Some(result) = invocation.exit.as_ref().and_then(|exit| exit.result) else {
        return;
    };
    if result <= 0 {
        return;
    }
    let Some(child_pid) = u32::try_from(result).ok() else {
        return;
    };
    let child_cookie = cookies.get(&child_pid).copied().unwrap_or(0);
    if child_pid == event.pid && child_cookie == invocation.task_cookie {
        return;
    }
    let parent = table_owner(files, invocation.task_cookie, event.pid);
    if shares_files(invocation, event) {
        files.share.insert((child_cookie, child_pid), parent);
        if let Some(cwd) = files.cwd.get(&parent).cloned() {
            files.cwd.entry((child_cookie, child_pid)).or_insert(cwd);
        }
        return;
    }
    let inherited: Vec<(u64, String)> = files
        .opened
        .iter()
        .filter(|((cookie, pid, _), _)| (*cookie, *pid) == parent)
        .map(|((_, _, fd), path)| (*fd, path.clone()))
        .collect();
    for (fd, path) in inherited {
        files
            .opened
            .entry((child_cookie, child_pid, fd))
            .or_insert(path);
    }
    if let Some(cwd) = files.cwd.get(&parent).cloned() {
        files.cwd.entry((child_cookie, child_pid)).or_insert(cwd);
    }
}

fn shares_files(invocation: &InvocationSummary, event: &EventSummary) -> bool {
    match event.syscall_nr {
        CLONE => call_args(invocation).is_some_and(|args| args[0] & CLONE_FILES != 0),
        CLONE3 => clone3_flags(invocation).is_some_and(|flags| flags & CLONE_FILES != 0),
        _ => false,
    }
}

fn clone3_flags(invocation: &InvocationSummary) -> Option<u64> {
    let field = invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .chain(invocation.async_events.iter())
        .flat_map(|event| event.fields.iter())
        .find(|field| field.key.contains("clone_args") && field.key.contains("flags"))?;
    let bytes = trace::covered_preview(field);
    match bytes.len() {
        4 => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
        8 => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

fn displayed_path(invocation: &InvocationSummary, event: &EventSummary, files: &FdState) -> String {
    let own = path_list(invocation);
    if !own.is_empty() {
        return own
            .iter()
            .map(|path| resolve_path(path, invocation, event, files))
            .collect::<Vec<_>>()
            .join(", ");
    }
    if matches!(event.syscall_name.as_str(), "mmap" | "mmap2") {
        let anonymous = call_args(invocation)
            .is_some_and(|args| args.get(3).is_some_and(|flags| flags & MAP_ANONYMOUS != 0));
        if anonymous {
            return "—".into();
        }
        if let Some(fd) = fd_argument(invocation, event) {
            if fd != u64::MAX {
                let (cookie, pid) = table_owner(files, invocation.task_cookie, event.pid);
                if let Some(path) = files.opened.get(&(cookie, pid, fd)) {
                    return path.clone();
                }
            }
        }
        return "—".into();
    }
    if matches!(
        event.syscall_name.as_str(),
        "read" | "write" | "readv" | "writev" | "pwrite64"
    ) {
        if let Some(fd) = fd_argument(invocation, event) {
            let (cookie, pid) = table_owner(files, invocation.task_cookie, event.pid);
            if let Some(path) = files.opened.get(&(cookie, pid, fd)) {
                return path.clone();
            }
        }
    }
    let preview = trace::info(invocation);
    if preview.is_empty() {
        "—".into()
    } else {
        preview
    }
}

fn resolve_path(
    path: &str,
    invocation: &InvocationSummary,
    event: &EventSummary,
    files: &FdState,
) -> String {
    if path.starts_with('/') {
        return path.to_string();
    }
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.pid);
    if matches!(event.syscall_name.as_str(), "openat" | "openat2") {
        if let Some(dirfd) = dirfd_argument(invocation, event) {
            if dirfd != AT_FDCWD {
                return match files.opened.get(&(cookie, pid, dirfd)) {
                    Some(base) if base.starts_with('/') => format!("{base}/{path}"),
                    _ => format!("{path} (relative, dirfd not recorded)"),
                };
            }
        }
    }
    match files.cwd.get(&(cookie, pid)) {
        Some(cwd) => format!("{cwd}/{path}"),
        None => format!("{path} (relative, cwd not recorded)"),
    }
}

fn dirfd_argument(invocation: &InvocationSummary, event: &EventSummary) -> Option<u64> {
    let args = call_args(invocation)?;
    let index = (0..args.len()).find(|index| {
        matches!(
            trace::argument_name(event.syscall_nr, *index),
            "dfd" | "dirfd"
        )
    })?;
    (index < args.len()).then_some(args[index])
}

fn path_key(key: &str) -> bool {
    key.split(['.', '[', ']']).any(|part| {
        matches!(
            part,
            "path" | "pathname" | "filename" | "oldname" | "newname" | "old_path" | "new_path"
        )
    })
}

fn path_text(field: &antinomie_monitor_core::FieldSummary) -> Option<String> {
    let bytes = trace::covered_preview(field);
    let end = bytes.iter().rposition(|byte| *byte != 0)?;
    let text = std::str::from_utf8(&bytes[..=end]).ok()?.trim();
    if text.is_empty() || text.chars().any(char::is_control) {
        return None;
    }
    Some(text.to_string())
}

fn path_list(invocation: &InvocationSummary) -> Vec<String> {
    let mut paths = Vec::new();
    for event in invocation.entry.iter().chain(invocation.exit.iter()) {
        for field in &event.fields {
            if !path_key(&field.key) {
                continue;
            }
            if let Some(text) = path_text(field) {
                if !paths.contains(&text) {
                    paths.push(text);
                }
            }
        }
    }
    paths
}

fn flow(frame: impl Into<String>, ends: impl Into<String>, detail: impl Into<String>) -> Vec<Cell> {
    vec![
        cell(frame, theme::value(theme::ValueKind::Number), true),
        cell(ends, theme::text(), true),
        cell(detail, theme::text(), false),
    ]
}

fn http_rows(input: &TriageInput<'_>) -> LimitedRows {
    let mut limited = LimitedRows {
        rows: Vec::new(),
        stopped_early: false,
    };
    let Some(built) = reconstruct_input(input) else {
        return limited;
    };
    for request in built.http {
        let packet = request
            .request_frames
            .first()
            .and_then(|number| input.packets.iter().find(|packet| packet.number == *number));
        let ends = packet
            .map(|packet| format!("{} → {}", packet.source, packet.destination))
            .unwrap_or_else(|| "—".into());
        let mut row = flow(
            request
                .request_frames
                .first()
                .map(|number| format!("#{number}"))
                .unwrap_or_else(|| "—".into()),
            ends,
            format!("{} {} {}", request.method, request.uri, request.version),
        );
        row.push(cell(
            request
                .status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "—".into()),
            theme::text(),
            false,
        ));
        row.push(cell(
            packet
                .map(|packet| http_process(packet, input.invocations))
                .unwrap_or_else(|| "—".into()),
            theme::text(),
            true,
        ));
        if !push_limited(&mut limited, row) {
            break;
        }
    }
    limited
}

fn reconstruct_input(
    input: &TriageInput<'_>,
) -> Option<antinomie_monitor_core::network::Reconstruction> {
    let frames = input.frames?;
    if frames.is_empty() || frames.len() > input.packets.len() {
        return None;
    }
    let captured: Vec<_> = input
        .packets
        .iter()
        .zip(frames.iter())
        .map(
            |(packet, bytes)| antinomie_monitor_core::network::CapturedFrame {
                number: packet.number,
                time_us: packet.time_us,
                bytes,
            },
        )
        .collect();
    Some(antinomie_monitor_core::network::reconstruct(&captured))
}

/// Process of a connect or sendto whose path or info text contains this
/// packet's destination address and destination port. Port text alone is
/// not enough. Anything else is an em dash.
fn http_process(packet: &NetworkPacket, invocations: &[InvocationSummary]) -> String {
    let Some(port) = packet.dst_port else {
        return "—".into();
    };
    let address = packet_address(packet);
    if address.is_empty() {
        return "—".into();
    }
    let port_text = port.to_string();
    for invocation in invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        if !connects_or_sends(event) {
            continue;
        }
        if mentions_endpoint(invocation, &address, &port_text) {
            return format!("pid {} tid {}", event.pid, event.tid);
        }
    }
    "—".into()
}

fn packet_address(packet: &NetworkPacket) -> String {
    if let Some(ip) = packet.dst_ip {
        return ip.to_string();
    }
    let destination = packet.destination.trim();
    if let Some(port) = packet.dst_port {
        let suffix = format!(":{port}");
        if let Some(host) = destination.strip_suffix(&suffix) {
            let host = host
                .strip_prefix('[')
                .and_then(|text| text.strip_suffix(']'))
                .unwrap_or(host)
                .trim();
            if !host.is_empty() {
                return host.to_string();
            }
        }
    }
    destination.to_string()
}

fn connects_or_sends(event: &EventSummary) -> bool {
    matches!(event.syscall_name.as_str(), "connect" | "sendto")
        || matches!(event.syscall_nr, 42 | 44)
}

fn mentions_endpoint(invocation: &InvocationSummary, address: &str, port: &str) -> bool {
    let info = trace::info(invocation);
    path_list(invocation)
        .iter()
        .any(|path| contains_address_and_port(path, address, port))
        || contains_address_and_port(&info, address, port)
}

fn contains_address_and_port(text: &str, address: &str, port: &str) -> bool {
    text.contains(address) && text.contains(port)
}

fn dns_rows(input: &TriageInput<'_>) -> LimitedRows {
    let mut limited = LimitedRows {
        rows: Vec::new(),
        stopped_early: false,
    };
    let Some(built) = reconstruct_input(input) else {
        return limited;
    };
    for query in built.dns {
        let packet = query
            .query_frames
            .first()
            .and_then(|number| input.packets.iter().find(|packet| packet.number == *number));
        let ends = packet
            .map(|packet| format!("{} → {}", packet.source, packet.destination))
            .unwrap_or_else(|| "—".into());
        let detail = if query.answers.is_empty() {
            format!("{} {} {}", query.name, query.qtype, query.class_name)
        } else {
            format!(
                "{} {} {} → {}",
                query.name,
                query.qtype,
                query.class_name,
                query.answers.join(", ")
            )
        };
        let mut row = flow(
            query
                .query_frames
                .first()
                .map(|number| format!("#{number}"))
                .unwrap_or_else(|| "—".into()),
            ends,
            detail,
        );
        let kind = if query.retry {
            "retry"
        } else if query.rcode.is_some() {
            "response"
        } else {
            "query"
        };
        row.push(cell(
            format!("{kind} {}", query.protocol),
            theme::text(),
            false,
        ));
        if !push_limited(&mut limited, row) {
            break;
        }
    }
    limited
}

struct BpfNote {
    heading: String,
    outcome: String,
    /// Request phrase for a lifecycle step. Load, socket, and seccomp lines
    /// include `fd {result}` when the exit result is >= 0. Attach does too,
    /// unless an argument matches an earlier successful `BPF_PROG_LOAD` fd.
    lifecycle: Option<String>,
    /// Disassembly when the instruction image was identified exactly.
    translation: Option<String>,
    /// Classic socket-filter and seccomp bytes. Absent when no image was isolated.
    dump: Option<String>,
    /// Raw bytes, hash, and the identity fields that were present.
    export: Option<String>,
}

fn bpf_notes(input: &TriageInput<'_>) -> Vec<BpfNote> {
    let mut notes = Vec::new();
    // File descriptors returned by successful BPF_PROG_LOAD calls in this slice.
    let mut program_fds = Vec::new();
    for invocation in input.invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        let recorded_args = event.args.or_else(|| call_args(invocation));
        let args = recorded_args.unwrap_or([0; 6]);
        let Some(command) = bpf_command(event, args) else {
            continue;
        };
        let image = instruction_image(invocation, command);
        let (translation, dump, export) = if let Some(bytes) = image.as_deref() {
            let action = if command == "BPF_PROG_LOAD" {
                "load"
            } else if command == "BPF_PROG_ATTACH" || command == "SO_ATTACH_FILTER" {
                "attach"
            } else {
                command
            };
            let exported = bpf::export_capture(
                bytes,
                &bpf::BpfIdentity {
                    vm_id: input.vm_id.map(str::to_owned),
                    boot_id: input.boot_id.map(str::to_owned),
                    run_id: input.run_id.map(str::to_owned),
                    cookie: Some(invocation.task_cookie),
                    pid: Some(event.pid),
                    tid: Some(event.tid),
                    timestamp_ns: (event.timestamp_ns != 0).then_some(event.timestamp_ns),
                    action: action.to_owned(),
                },
            );
            let translation = if classic_image(command) {
                bpf::translate_classic(bytes)
            } else {
                bpf::translate(bytes)
            };
            let dump = classic_image(command).then(|| bpf::dump(bytes));
            (Some(translation), dump, Some(exported))
        } else {
            (None, None, None)
        };
        let result = invocation.exit.as_ref().and_then(|exit| exit.result);
        notes.push(BpfNote {
            heading: format!("{}  tid {}  {command}", event.syscall_name, event.tid),
            outcome: outcome(invocation),
            lifecycle: attach_of_loaded(command, recorded_args, &program_fds)
                .or_else(|| bpf_lifecycle(command, result)),
            translation,
            dump,
            export,
        });
        if command == "BPF_PROG_LOAD" {
            if let Some(fd) = result.filter(|result| *result >= 0) {
                program_fds.push(fd);
            }
        }
    }
    notes
}

/// `attach requested of fd N` when a recorded argument is a program fd from
/// an earlier successful load in this slice. No fd is guessed from a pointer.
fn attach_of_loaded(command: &str, args: Option<[u64; 6]>, program_fds: &[i64]) -> Option<String> {
    if command != "BPF_PROG_ATTACH" {
        return None;
    }
    let fd = args?.into_iter().find_map(|arg| {
        let fd = i64::try_from(arg).ok()?;
        program_fds.contains(&fd).then_some(fd)
    })?;
    Some(format!("attach requested of fd {fd}"))
}

fn bpf_lifecycle(command: &str, result: Option<i64>) -> Option<String> {
    let (phrase, with_fd) = match command {
        "BPF_PROG_LOAD" => ("load requested", true),
        "BPF_PROG_ATTACH" => ("attach requested", true),
        "BPF_PROG_DETACH" => ("detach requested", false),
        "SO_ATTACH_FILTER" => ("socket attach requested", true),
        "SECCOMP_SET_MODE_STRICT"
        | "SECCOMP_SET_MODE_FILTER"
        | "SECCOMP_MODE_STRICT"
        | "SECCOMP_MODE_FILTER"
        | "PR_SET_SECCOMP" => ("seccomp install requested", true),
        _ => return None,
    };
    Some(match result {
        Some(result) if with_fd && result >= 0 => format!("{phrase} fd {result}"),
        _ => phrase.to_string(),
    })
}

fn classic_image(command: &str) -> bool {
    matches!(
        command,
        "SO_ATTACH_FILTER" | "SECCOMP_SET_MODE_FILTER" | "SECCOMP_MODE_FILTER"
    )
}

fn bpf_command(event: &EventSummary, args: [u64; 6]) -> Option<&'static str> {
    if let Some(command) = bpf::command_name(event) {
        return Some(command);
    }
    if classic_socket_filter(event, args) {
        return Some("SO_ATTACH_FILTER");
    }
    if event.syscall_name == "seccomp" || event.syscall_nr == 317 {
        return match args[0] {
            0 => Some("SECCOMP_SET_MODE_STRICT"),
            1 => Some("SECCOMP_SET_MODE_FILTER"),
            _ => None,
        };
    }
    if (event.syscall_name == "prctl" || event.syscall_nr == 157) && args[0] == 22 {
        return Some(match args[1] {
            1 => "SECCOMP_MODE_STRICT",
            2 => "SECCOMP_MODE_FILTER",
            _ => "PR_SET_SECCOMP",
        });
    }
    None
}

/// Exact captured instruction arrays. A buffer whose name merely contains
/// `prog`, `buf` or `insns` is not a program image, and a short preview is
/// not padded out to the declared length.
fn instruction_image(invocation: &InvocationSummary, command: &str) -> Option<Vec<u8>> {
    let (key, layout) = match command {
        "BPF_PROG_LOAD" => ("arg1.attr.insns", "bpf_insn[]"),
        "SO_ATTACH_FILTER" => ("arg3.optval.filter", "sock_filter[]"),
        "SECCOMP_SET_MODE_FILTER" | "SECCOMP_MODE_FILTER" => {
            ("arg2.program.filter", "sock_filter[]")
        }
        _ => return None,
    };
    invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| event.fields.iter())
        .find(|field| field.key == key && layout_is(&field.layout, layout))
        .and_then(isolated_instructions)
}

fn layout_is(layout: &str, name: &str) -> bool {
    layout == name || layout.ends_with(&format!("/{name}"))
}

fn isolated_instructions(field: &antinomie_monitor_core::FieldSummary) -> Option<Vec<u8>> {
    let logical = field.logical_len?;
    if !field.complete
        || logical == 0
        || !logical.is_multiple_of(8)
        || field.captured_len != logical
    {
        return None;
    }
    if field.ranges.as_slice() != [(0, logical)] {
        return None;
    }
    let bytes = trace::covered_preview(field);
    if bytes.len() as u64 != logical {
        return None;
    }
    Some(bytes.to_vec())
}

fn bpf_view(ui: &mut egui::Ui, input: &TriageInput<'_>) {
    ui.label(
        "BPF programs, classic socket filters and seccomp installs in this loaded page. The translation reads captured instruction bytes; it does not load or run them. VM, boot, or run is null in the export when this view does not have that id.",
    );
    let notes = bpf_notes(input);
    if notes.is_empty() {
        ui.colored_label(
            theme::muted(),
            "No bpf syscall, classic socket filter, or seccomp install was recorded.",
        );
        return;
    }
    egui::ScrollArea::vertical()
        .id_salt("triage-bpf")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for note in &notes {
                ui.strong(&note.heading);
                if let Some(line) = &note.lifecycle {
                    ui.label(line);
                }
                ui.label(&note.outcome);
                if note.translation.is_none() && note.dump.is_none() {
                    ui.colored_label(theme::muted(), "The instruction image was not isolated.");
                } else {
                    if let Some(text) = &note.translation {
                        ui.add(egui::Label::new(RichText::new(text).monospace()).wrap());
                    }
                    if let Some(text) = &note.dump {
                        ui.add(egui::Label::new(RichText::new(text).monospace()).wrap());
                    }
                    if let Some(text) = &note.export {
                        ui.add(egui::Label::new(RichText::new(text).monospace()).wrap());
                    }
                }
                ui.separator();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{
        network::NetworkPacket, EventSummary, FieldSummary, InvocationSummary,
    };

    fn page_notes(invocations: &[InvocationSummary]) -> Vec<BpfNote> {
        bpf_notes(&TriageInput::page(invocations, &[]))
    }

    fn call(pid: u32, nr: u64, name: &str, result: i64) -> InvocationSummary {
        InvocationSummary {
            stream_id: 1,
            task_cookie: u64::from(pid),
            call_id: 1,
            entry: Some(EventSummary {
                root_task_cookie: 1,
                stream_id: 1,
                task_cookie: u64::from(pid),
                call_id: 1,
                event_seq: 1,
                phase: 1,
                syscall_nr: nr,
                syscall_name: name.into(),
                pid,
                tid: pid,
                cpu: 0,
                timestamp_ns: 0,
                args: Some([0; 6]),
                result: None,
                complete: true,
                issues: Vec::new(),
                fields: Vec::new(),
            }),
            exit: Some(EventSummary {
                root_task_cookie: 1,
                stream_id: 1,
                task_cookie: u64::from(pid),
                call_id: 1,
                event_seq: 2,
                phase: 2,
                syscall_nr: nr,
                syscall_name: name.into(),
                pid,
                tid: pid,
                cpu: 0,
                timestamp_ns: 1,
                args: None,
                result: Some(result),
                complete: true,
                issues: Vec::new(),
                fields: Vec::new(),
            }),
            async_events: Vec::new(),
            task_exit: None,
        }
    }

    fn captured(key: &str, layout: &str, data: &[u8]) -> FieldSummary {
        let len = data.len() as u64;
        FieldSummary {
            object_id: 1,
            key: key.into(),
            layout: layout.into(),
            logical_len: Some(len),
            captured_len: len,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: data.to_vec(),
            raw_path: None,
            ranges: vec![(0, len)],
        }
    }

    fn packet(number: u64, protocol: &str, info: &str, port: Option<u16>) -> NetworkPacket {
        NetworkPacket {
            number,
            protocol: protocol.into(),
            info: info.into(),
            source: "10.0.0.1".into(),
            destination: "10.0.0.2".into(),
            dst_port: port,
            ..NetworkPacket::default()
        }
    }

    #[test]
    fn fork_indents_the_child_under_its_parent() {
        let lines = process_tree_lines(&[call(1, FORK, "fork", 42), call(42, 59, "execve", 0)]);
        assert_eq!(
            lines,
            vec![
                "pid 1 cookie 1  ?".to_string(),
                "  pid 42 cookie 42  ?".to_string()
            ]
        );
    }

    fn with_cookie(pid: u32, cookie: u64) -> InvocationSummary {
        let mut row = call(pid, 1, "write", 0);
        row.task_cookie = cookie;
        for event in row.entry.iter_mut().chain(row.exit.iter_mut()) {
            event.task_cookie = cookie;
        }
        row
    }

    #[test]
    fn same_pid_two_cookies_are_two_process_nodes() {
        let lines = process_tree_lines(&[with_cookie(7, 100), with_cookie(7, 200)]);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines.iter().any(|line| line.contains("pid 7 cookie 100")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("pid 7 cookie 200")),
            "{lines:?}"
        );
    }

    #[test]
    fn failed_exec_does_not_replace_the_program() {
        let mut started = call(3, 59, "execve", 0);
        started
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg0.pathname", "", b"/bin/old\0"));
        let mut failed = call(3, 59, "execve", -2);
        failed
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg0.pathname", "", b"/bin/new\0"));
        let lines = process_tree_lines(&[started, failed]);
        assert!(
            lines.iter().any(|line| line.contains("/bin/old")),
            "{lines:?}"
        );
        assert!(
            lines.iter().all(|line| !line.contains("/bin/new")),
            "{lines:?}"
        );

        let mut again = call(3, 59, "execve", 0);
        again
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg0.pathname", "", b"/bin/old\0"));
        let mut pending = call(3, 322, "execveat", 0);
        pending.exit = None;
        pending.entry.as_mut().unwrap().fields.push(captured(
            "arg1.pathname",
            "",
            b"/bin/pending\0",
        ));
        let lines = process_tree_lines(&[again, pending]);
        assert!(
            lines.iter().any(|line| line.contains("/bin/old")),
            "{lines:?}"
        );
        assert!(
            lines.iter().all(|line| !line.contains("/bin/pending")),
            "{lines:?}"
        );

        let mut rejected = call(4, 59, "execve", -13);
        rejected.entry.as_mut().unwrap().fields.push(captured(
            "arg0.pathname",
            "",
            b"/bin/rejected\0",
        ));
        let lines = process_tree_lines(&[rejected]);
        assert!(
            lines.iter().all(|line| !line.contains("/bin/rejected")),
            "{lines:?}"
        );
    }

    #[test]
    fn clone3_thread_flags_create_no_child() {
        let mut threaded = call(1, CLONE3, "clone3", 99);
        threaded.entry.as_mut().unwrap().args = Some([0x1000, 88, 0, 0, 0, 0]);
        threaded.entry.as_mut().unwrap().fields.push(captured(
            "arg0.clone_args.flags",
            "u64",
            &CLONE_THREAD.to_le_bytes(),
        ));
        let lines = process_tree_lines(&[threaded]);
        assert!(
            lines.iter().all(|line| !line.contains("pid 99")),
            "{lines:?}"
        );

        let mut spawned = call(1, CLONE3, "clone3", 77);
        spawned.entry.as_mut().unwrap().args = Some([CLONE_THREAD, 88, 0, 0, 0, 0]);
        spawned.entry.as_mut().unwrap().fields.push(captured(
            "arg0.clone_args.flags",
            "u64",
            &0u64.to_le_bytes(),
        ));
        let lines = process_tree_lines(&[spawned]);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("pid 77") && line.starts_with("  ")),
            "{lines:?}"
        );

        let mut missing = call(1, CLONE3, "clone3", 66);
        missing.entry.as_mut().unwrap().args = Some([0, 88, 0, 0, 0, 0]);
        let lines = process_tree_lines(&[missing]);
        assert!(
            lines.iter().all(|line| !line.contains("pid 66")),
            "{lines:?}"
        );
    }

    #[test]
    fn child_whose_parent_pid_is_absent_contains_parent_not_in_this_trace() {
        let lines = process_tree_lines(&[call(42, 1, "write", 0)]);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("parent not in this trace"),
            "{}",
            lines[0]
        );
        assert!(lines[0].starts_with("pid 42"), "{}", lines[0]);
    }

    #[test]
    fn write_fd_argument_is_shown_not_the_return() {
        let mut write = call(9, 1, "write", 100);
        write.entry.as_mut().unwrap().args = Some([5, 0x1000, 100, 0, 0, 0]);
        let rows = file_rows(&[write], &["write"]);
        assert_eq!(rows.rows.len(), 1);
        assert!(!rows.stopped_early);
        assert_eq!(rows.rows[0][2].text, "5");
        assert_eq!(rows.rows[0][4].text, "100");
        assert_ne!(rows.rows[0][0].text, "100");

        let mut opened = call(9, 257, "openat", 7);
        opened
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.path", "", b"/etc/passwd\0"));
        let rows = file_rows(&[opened], &["openat"]);
        assert_eq!(rows.rows[0][0].text, "/etc/passwd");
        assert_eq!(rows.rows[0][2].text, "7");

        let failed = call(9, 2, "open", -2);
        assert_eq!(file_rows(&[failed], &["open"]).rows[0][2].text, "—");

        let unlinked = call(9, 87, "unlink", 0);
        assert_eq!(file_rows(&[unlinked], &["unlink"]).rows[0][2].text, "—");
    }

    #[test]
    fn dns_port_argument_does_not_create_a_row() {
        let mut write = call(3, 1, "write", 53);
        write.entry.as_mut().unwrap().args = Some([53, 0, 53, 0, 0, 0]);
        let mut send = call(3, 44, "sendto", 53);
        send.entry.as_mut().unwrap().args = Some([53, 0, 53, 0, 0, 16]);
        let packets = [
            packet(1, "ICMP", "type 8", Some(53)),
            packet(2, "DNS", "standard query A example.com", None),
            packet(3, "TCP", "53 → 40000", Some(53)),
            packet(4, "UDP", "9 → 9", Some(9)),
        ];
        let rows = dns_rows(&TriageInput::page(&[write, send], &packets));
        assert!(rows.rows.is_empty());
        assert!(!rows.stopped_early);
    }

    #[test]
    fn http_request_includes_get_and_skips_the_status_line() {
        let packets = [
            packet(1, "http", "HTTP/1.1 200 OK", Some(80)),
            packet(2, "http", "GET / HTTP/1.1", Some(80)),
            packet(3, "TCP", "GET /hidden HTTP/1.1", Some(80)),
        ];
        let mut response = call(4, 1, "write", 0);
        response.entry.as_mut().unwrap().fields.push(captured(
            "arg1.data",
            "",
            b"HTTP/1.1 200 OK\r\n",
        ));
        let mut request = call(4, 1, "write", 0);
        request.entry.as_mut().unwrap().fields.push(captured(
            "arg1.data",
            "",
            b"GET /index.html HTTP/1.1\r\n",
        ));
        let rows = http_rows(&TriageInput::page(&[response, request], &packets));
        assert!(
            rows.rows.is_empty(),
            "packet info and syscall text are not a reconstructed request"
        );
    }

    #[test]
    fn bpf_program_finding_skips_maps_and_requires_socket_level() {
        let mut load = call(1, 321, "bpf", 3);
        load.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        let mut create = call(1, 321, "bpf", -1);
        create.entry.as_mut().unwrap().args = Some([0, 0, 0, 0, 0, 0]);
        let mut attached = call(1, 54, "setsockopt", 0);
        attached.entry.as_mut().unwrap().args = Some([4, 1, 26, 0, 0, 0]);
        let mut other = call(1, 54, "setsockopt", 0);
        other.entry.as_mut().unwrap().args = Some([4, 6, 26, 0, 0, 0]);
        let rules: Vec<_> = suspicious_rows(&[load, create, attached, other])
            .into_iter()
            .map(|row| row.cells[0].text.clone())
            .collect();
        assert_eq!(rules, ["bpf.program", "bpf.socket_filter"]);

        let mut bytes = call(1, 321, "bpf", 0);
        bytes.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        bytes.entry.as_mut().unwrap().fields.push(captured(
            "buf",
            "linux-6.12.94/x86_64/bpf_insn[]",
            &[0xb7, 0, 0, 0, 0, 0, 0, 0],
        ));
        let notes = page_notes(&[bytes]);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].heading.contains("BPF_PROG_LOAD"));
        assert!(notes[0].translation.is_none());
        assert_eq!(notes[0].outcome, "returned 0");
        assert_eq!(notes[0].lifecycle.as_deref(), Some("load requested fd 0"));

        let mut image = call(1, 321, "bpf", 0);
        image.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        image.entry.as_mut().unwrap().fields.push(captured(
            "arg1.attr.insns",
            "linux-6.12.94/x86_64/bpf_insn[]",
            &[0xb7, 0, 0, 0, 0, 0, 0, 0],
        ));
        let notes = page_notes(&[image]);
        let text = notes[0].translation.as_deref().unwrap_or("");
        assert!(text.contains("mov64 r0, 0"), "{text}");

        let mut filter = call(1, 317, "seccomp", 0);
        filter.entry.as_mut().unwrap().args = Some([1, 0, 0, 0, 0, 0]);
        let notes = page_notes(&[filter]);
        assert!(notes[0].heading.contains("SECCOMP_SET_MODE_FILTER"));
        assert!(notes[0].translation.is_none());
        assert_eq!(
            notes[0].lifecycle.as_deref(),
            Some("seccomp install requested fd 0")
        );

        let mut prctl = call(1, 157, "prctl", 0);
        prctl.entry.as_mut().unwrap().args = Some([22, 2, 0, 0, 0, 0]);
        assert!(page_notes(&[prctl])[0]
            .heading
            .contains("SECCOMP_MODE_FILTER"));

        let mut lookup = call(1, 321, "bpf", 0);
        lookup.entry.as_mut().unwrap().args = Some([1, 0, 0, 0, 0, 0]);
        assert!(page_notes(&[lookup.clone()])[0]
            .heading
            .contains("BPF_MAP_LOOKUP_ELEM"));
        assert!(page_notes(&[lookup.clone()])[0].lifecycle.is_none());
        assert!(suspicious_rows(&[lookup]).is_empty());

        let mut denied = call(1, 321, "bpf", -13);
        denied.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[denied])[0].lifecycle.as_deref(),
            Some("load requested")
        );
        let mut pending = call(1, 321, "bpf", 4);
        pending.exit = None;
        pending.entry.as_mut().unwrap().args = Some([8, 0, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[pending])[0].lifecycle.as_deref(),
            Some("attach requested")
        );
        let mut attached_prog = call(1, 321, "bpf", 7);
        attached_prog.entry.as_mut().unwrap().args = Some([8, 0, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[attached_prog])[0].lifecycle.as_deref(),
            Some("attach requested fd 7")
        );
        let mut detach = call(1, 321, "bpf", 0);
        detach.entry.as_mut().unwrap().args = Some([9, 0, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[detach])[0].lifecycle.as_deref(),
            Some("detach requested")
        );
        let mut socket = call(1, 54, "setsockopt", 0);
        socket.entry.as_mut().unwrap().args = Some([4, 1, 26, 0, 0, 0]);
        assert_eq!(
            page_notes(&[socket])[0].lifecycle.as_deref(),
            Some("socket attach requested fd 0")
        );
    }

    #[test]
    fn write_fd_copied_at_fork_is_not_shared_with_parent() {
        let mut opened = call(1, 257, "openat", 7);
        opened
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.path", "", b"/etc/passwd\0"));
        let forked = call(1, FORK, "fork", 42);
        let mut child_write = call(42, 1, "write", 3);
        child_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
        let rows = file_rows(
            &[opened.clone(), forked.clone(), child_write.clone()],
            &["write"],
        );
        assert_eq!(rows.rows[0][0].text, "/etc/passwd");
        assert_eq!(rows.rows[0][2].text, "7");

        let mut child_close = call(42, 3, "close", 0);
        child_close.entry.as_mut().unwrap().args = Some([7, 0, 0, 0, 0, 0]);
        let mut parent_write = call(1, 1, "write", 3);
        parent_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
        let rows = file_rows(
            &[
                opened.clone(),
                forked,
                child_close,
                child_write,
                parent_write,
            ],
            &["write"],
        );
        assert_eq!(rows.rows.len(), 2);
        assert!(!rows.rows[0][0].text.contains("/etc/passwd"));
        assert_eq!(rows.rows[1][0].text, "/etc/passwd");

        let mut thread = call(1, CLONE, "clone", 99);
        thread.entry.as_mut().unwrap().args = Some([CLONE_THREAD, 0, 0, 0, 0, 0]);
        let mut thread_write = call(99, 1, "write", 3);
        thread_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
        let rows = file_rows(&[opened.clone(), thread, thread_write], &["write"]);
        assert!(!rows.rows[0][0].text.contains("/etc/passwd"));

        let mut missing = call(1, CLONE3, "clone3", 77);
        missing.entry.as_mut().unwrap().args = Some([0, 88, 0, 0, 0, 0]);
        let mut missing_write = call(77, 1, "write", 3);
        missing_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
        let rows = file_rows(&[opened, missing, missing_write], &["write"]);
        assert!(!rows.rows[0][0].text.contains("/etc/passwd"));
    }

    #[test]
    fn http_request_process_needs_address_and_port() {
        let packets = [packet(2, "http", "GET / HTTP/1.1", Some(80))];
        let mut port_only = call(5, 44, "sendto", 0);
        port_only
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.buf", "", b"port 80\0"));
        assert_eq!(
            http_rows(&TriageInput::page(&[port_only.clone()], &packets))
                .rows
                .len(),
            0
        );
        assert_eq!(http_process(&packets[0], &[port_only]), "—");

        let mut connect = call(4, 42, "connect", 0);
        connect
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.addr", "", b"10.0.0.2:80\0"));
        assert_eq!(http_process(&packets[0], &[connect]), "pid 4 tid 4");
    }

    #[test]
    fn bpf_program_attach_uses_the_loaded_fd() {
        let mut load = call(1, 321, "bpf", 6);
        load.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        let mut attach = call(1, 321, "bpf", 0);
        attach.entry.as_mut().unwrap().args = Some([8, 6, 0, 0, 0, 0]);
        let notes = page_notes(&[load.clone(), attach]);
        assert_eq!(notes[0].lifecycle.as_deref(), Some("load requested fd 6"));
        assert_eq!(
            notes[1].lifecycle.as_deref(),
            Some("attach requested of fd 6")
        );
        assert_eq!(suspicious_rows(&[load])[0].cells.last().unwrap().text, "1");

        let mut other = call(1, 321, "bpf", 7);
        other.entry.as_mut().unwrap().args = Some([8, 4, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[other])[0].lifecycle.as_deref(),
            Some("attach requested fd 7")
        );

        let mut denied = call(1, 321, "bpf", -13);
        denied.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        let mut attach_exit = call(1, 321, "bpf", 3);
        attach_exit.entry.as_mut().unwrap().args = Some([8, 3, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[denied, attach_exit])[1].lifecycle.as_deref(),
            Some("attach requested fd 3")
        );
    }
}
