// SPDX-License-Identifier: GPL-3.0-only
//! Details of a selected process: the image, arguments and environment of its
//! last exec, its credentials, relatives, exec chain and outcome, its
//! suspicious observations and the jumps scoped to it. Each jump reuses a
//! navigation the app already has.
use super::process_cells;
use super::process_env::{self, Change};
use super::process_record::CredStep;
use super::*;
use crate::widgets::{self, Tone};
use antinomie_monitor_core::kernel_notes::CredentialChange;

/// Temp-data key the Trace filter of a "Filter Trace to this process" jump is
/// left under for the app.
pub(super) const TRACE_SCOPE: &str = "triage-trace-scope";

/// Temp-data key a click on a process's Findings count leaves its PID under;
/// the view then opens Suspicious activity filtered to that process.
pub(super) const PROCESS_SCOPE: &str = "triage-process-scope";

/// Observations listed in Details; the rest are in Suspicious activity.
const LISTED: usize = 12;

/// The Trace filter that shows one process: its task cookie when known.
pub(super) fn trace_filter(pid: u64, cookie: u64) -> String {
    if cookie != 0 {
        format!("process.cookie == {cookie}")
    } else {
        format!("process.pid == {pid}")
    }
}

pub(super) fn show(view: &mut TriageView, ui: &mut egui::Ui, values: &[(&str, RowValue)]) {
    let Some(pid) = files::number(values, "process.pid") else {
        return;
    };
    let cookie = files::number(values, "process.cookie").unwrap_or(0);
    let mine = |values: &[(&str, RowValue)]| {
        files::number(values, "process.pid") == Some(pid)
            && files::number(values, "process.cookie").unwrap_or(0) == cookie
    };
    ui.colored_label(
        theme::muted(),
        format!(
            "Recording task id {} (internal key of this task in the recording)",
            process_tree::task_id_text(cookie)
        ),
    );
    let total = files::number(values, "process.suspicious").unwrap_or(0);
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        if ui
            .button("Show its calls")
            .on_hover_text("Open the Syscall Trace filtered to this process")
            .clicked()
        {
            ui.ctx().data_mut(|data| {
                data.insert_temp(egui::Id::new(TRACE_SCOPE), trace_filter(pid, cookie));
            });
        }
        if ui
            .button("Files it touched")
            .on_hover_text("Opened files, filtered to this PID")
            .clicked()
        {
            view.scope_to_pid(ui.ctx(), Section::Files, pid);
        }
        if ui
            .add_enabled(total > 0, egui::Button::new("Suspicious activity"))
            .on_hover_text("Suspicious activity, filtered to this PID")
            .clicked()
        {
            view.scope_to_pid(ui.ctx(), Section::Process, pid);
        }
    });
    let facts = view
        .scan
        .as_ref()
        .and_then(|scan| facts(scan, pid as u32, cookie, scan.clock_anchor));
    if let Some(facts) = &facts {
        if let Some((pid, cookie)) = facts.show(ui) {
            open_process(view, ui.ctx(), pid, cookie);
        }
    }
    let listed: Vec<Finding> = view
        .scan
        .as_ref()
        .map(|scan| {
            scan.findings
                .iter()
                .filter(|finding| mine(&finding.values))
                .take(LISTED)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    ui.separator();
    ui.label(
        RichText::new("Suspicious observations")
            .strong()
            .color(theme::text()),
    );
    if total == 0 {
        ui.weak("None recorded for this process.");
    }
    for finding in &listed {
        ui.horizontal_wrapped(|ui| {
            let tone = rules::Tier::from_tag(&finding.cells[1].text)
                .map_or(Tone::Neutral, rules::Tier::tone);
            widgets::chip(ui, finding.cells[1].text.clone(), tone);
            let rule = egui::Label::new(RichText::new(&finding.cells[0].text).monospace())
                .sense(egui::Sense::click());
            if ui
                .add(rule)
                .on_hover_text("Open the syscall in Trace")
                .clicked()
            {
                request_evidence_jump(ui.ctx(), &finding.values);
            }
            ui.colored_label(theme::muted(), &finding.cells[3].text);
        });
    }
    if total > listed.len() as u64 {
        ui.weak(format!(
            "{} more in Suspicious activity.",
            total - listed.len() as u64
        ));
    }
}

impl TriageView {
    /// Open `section`'s table (Files › Opened, or Process › Suspicious
    /// activity) filtered to one PID.
    pub(super) fn scope_to_pid(&mut self, ctx: &egui::Context, section: Section, pid: u64) {
        self.section = section;
        let slot = if section == Section::Files {
            self.files = FileTab::Opened;
            self.history_tab = false;
            self.by_file = false;
            FileTab::Opened.slot()
        } else {
            self.process = ProcessTab::Suspicious;
            0
        };
        let draft = format!("process.pid == {pid}");
        ctx.data_mut(|data| data.insert_temp(egui::Id::new(("triage-filter-draft", slot)), draft));
    }
}

/// A relative of the process, as the Details list it.
pub(super) struct Relative {
    label: String,
    pid: u32,
    cookie: u64,
}

/// One environment variable as the Details show it.
pub(super) struct EnvRow {
    line: process_env::Line,
    /// The Triage rules that flagged this variable.
    rules: Vec<String>,
}

/// Everything the Details say about a process that the tree knows.
pub(super) struct Facts {
    pub(super) exe: Option<String>,
    pub(super) argv: Vec<String>,
    pub(super) env: Vec<EnvRow>,
    /// The parent's exec had no recorded environment to compare with.
    pub(super) compared: bool,
    pub(super) cwd: Option<String>,
    pub(super) user: String,
    pub(super) credential_changes: Vec<String>,
    pub(super) parent: Option<Relative>,
    pub(super) children: Vec<Relative>,
    /// `(time from the start of the run, absolute time, image)` of each exec.
    pub(super) chain: Vec<(String, String, String)>,
    pub(super) forked: bool,
    pub(super) outcome: String,
    pub(super) thread: bool,
}

fn relative_label(node: &ProcessNode) -> Relative {
    Relative {
        label: process_tree::process_label(node),
        pid: node.pid,
        cookie: node.cookie,
    }
}

/// The Triage rules that flagged `variable` of this process's exec.
fn flagged_by(findings: &[Finding], variable: &str) -> Vec<String> {
    let mut rules: Vec<String> = Vec::new();
    for finding in findings {
        let text = |key: &str| {
            finding.values.iter().find_map(|(name, value)| match value {
                RowValue::Text(text) if *name == key => Some(text.as_str()),
                _ => None,
            })
        };
        let hit = text("finding.object") == Some(variable)
            || text("finding.summary").is_some_and(|summary| {
                summary.starts_with("program started with ") && summary.contains(variable)
            });
        let rule = &finding.cells[0].text;
        if hit && !rules.contains(rule) {
            rules.push(rule.clone());
        }
    }
    rules
}

/// What changed between two credential records, in words.
pub(super) fn credential_changes(steps: &[CredStep], start: Option<u64>) -> Vec<String> {
    steps
        .windows(2)
        .map(|pair| {
            let (from, to) = (&pair[0], &pair[1]);
            let mut parts = Vec::new();
            for (name, old, new) in [
                ("uid", from.uid, to.uid),
                ("euid", from.euid, to.euid),
                ("gid", from.gid, to.gid),
                ("egid", from.egid, to.egid),
            ] {
                if old != new {
                    parts.push(format!("{name} {old} \u{2192} {new}"));
                }
            }
            let how = match to.change {
                CredentialChange::Start => "start".to_owned(),
                CredentialChange::SetUid => "setuid".into(),
                CredentialChange::SetGid => "setgid".into(),
                CredentialChange::SetRes => "setresuid or setresgid".into(),
                CredentialChange::SetFs => "setfsuid or setfsgid".into(),
                CredentialChange::CapSet => "capset".into(),
                CredentialChange::ExecSetId => "setuid or setgid image".into(),
                CredentialChange::ExecCaps => "exec capabilities".into(),
                CredentialChange::LoginUid => "login uid".into(),
                CredentialChange::Other => "other".into(),
                CredentialChange::Prctl => "prctl".into(),
                CredentialChange::Unknown(code) => format!("record kind {code}"),
            };
            format!(
                "{}  {how}: {}",
                process_cells::relative(Some(to.ns), start),
                parts.join(", ")
            )
        })
        .collect()
}

/// The Details of the process with this pid and task cookie, when the index has it.
pub(super) fn facts(
    scan: &ArchiveScan,
    pid: u32,
    cookie: u64,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> Option<Facts> {
    let node = scan
        .process
        .iter()
        .find(|node| node.pid == pid && node.cookie == cookie)?;
    let start = scan.process.iter().filter_map(|node| node.first_ns).min();
    let parent_node = node.parent.and_then(|key| {
        scan.process
            .iter()
            .find(|other| other.pid == key.pid && other.cookie == key.cookie)
    });
    let parent_env = parent_node
        .map(|parent| parent.record.envp.as_slice())
        .filter(|env| !env.is_empty() && !node.forked && !node.thread);
    let own: Vec<_> = scan
        .findings
        .iter()
        .filter(|finding| {
            files::number(&finding.values, "process.pid") == Some(u64::from(pid))
                && files::number(&finding.values, "process.cookie").unwrap_or(0) == cookie
        })
        .collect();
    let own: Vec<Finding> = own.into_iter().cloned().collect();
    let env = process_env::diff(parent_env, &node.record.envp)
        .into_iter()
        .map(|line| EnvRow {
            rules: if line.change == Change::Removed {
                Vec::new()
            } else {
                flagged_by(&own, &line.text())
            },
            line,
        })
        .collect();
    let creds = &node.record.creds;
    let user = match creds.last() {
        None => "not recorded".to_owned(),
        Some(last) => format!(
            "uid {}, euid {}, gid {}, egid {}",
            last.uid, last.euid, last.gid, last.egid
        ),
    };
    Some(Facts {
        exe: (node.comm != "?").then(|| node.comm.clone()),
        argv: node.argv.clone(),
        env,
        compared: parent_env.is_some(),
        cwd: node.record.cwd.clone(),
        user,
        credential_changes: credential_changes(creds, start),
        parent: parent_node.map(relative_label),
        children: scan
            .process
            .iter()
            .filter(|other| {
                other
                    .parent
                    .is_some_and(|key| key.pid == pid && key.cookie == cookie)
            })
            .map(relative_label)
            .collect(),
        chain: node
            .record
            .execs
            .iter()
            .map(|(image, ns)| {
                (
                    process_cells::relative(Some(*ns), start),
                    crate::time_format::guest_ns(clock, Some(*ns)),
                    image.clone(),
                )
            })
            .collect(),
        forked: node.forked,
        outcome: process_cells::outcome(
            &node.state,
            node.in_call.as_ref().map(|call| call.0.as_str()),
            node.record.killed_by,
        ),
        thread: node.thread,
    })
}

/// Relatives listed before the rest are summarised.
const RELATIVES: usize = 40;

impl Facts {
    /// Draw the facts; the process a click on a relative asks for, if any.
    pub(super) fn show(&self, ui: &mut egui::Ui) -> Option<(u32, u64)> {
        let mut open = None;
        let heading = |ui: &mut egui::Ui, text: &str| {
            ui.add_space(4.0);
            ui.label(RichText::new(text).strong().color(theme::text()));
        };
        ui.separator();
        heading(ui, "Executable");
        match &self.exe {
            Some(exe) => {
                ui.add(egui::Label::new(RichText::new(exe).monospace()).wrap());
            }
            None => {
                ui.weak("Not recorded.");
            }
        }
        if self.forked {
            ui.weak("This task has not run an exec: it still runs its parent's image.");
        }
        if let Some(cwd) = &self.cwd {
            heading(ui, "Working directory");
            ui.add(egui::Label::new(RichText::new(cwd).monospace()).wrap());
        }
        heading(ui, "Arguments");
        if self.argv.is_empty() {
            ui.weak("Not recorded.");
        }
        for (index, argument) in self.argv.iter().enumerate() {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(theme::muted(), format!("[{index}]"));
                ui.add(egui::Label::new(RichText::new(argument).monospace()).wrap());
            });
        }
        let title = format!("Environment ({} variables)", self.env.len());
        egui::CollapsingHeader::new(RichText::new(title).strong())
            .id_salt("triage-process-env")
            .default_open(true)
            .show(ui, |ui| self.environment(ui));
        heading(ui, "User");
        ui.label(&self.user);
        for change in &self.credential_changes {
            ui.colored_label(theme::warn(), change);
        }
        heading(ui, "Parent");
        match &self.parent {
            Some(parent) => {
                if relative_link(ui, parent).clicked() {
                    open = Some((parent.pid, parent.cookie));
                }
            }
            None => {
                ui.weak("Not in this trace.");
            }
        }
        if !self.children.is_empty() {
            heading(ui, &format!("Children ({})", self.children.len()));
            for child in self.children.iter().take(RELATIVES) {
                if relative_link(ui, child).clicked() {
                    open = Some((child.pid, child.cookie));
                }
            }
            if self.children.len() > RELATIVES {
                ui.weak(format!("{} more.", self.children.len() - RELATIVES));
            }
        }
        heading(ui, "Exec chain");
        if self.chain.is_empty() {
            ui.weak(if self.thread {
                "A thread: it runs its process's image."
            } else {
                "No exec recorded."
            });
        }
        for (relative, absolute, image) in &self.chain {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(theme::muted(), relative)
                    .on_hover_text(absolute);
                ui.add(egui::Label::new(RichText::new(image).monospace()).wrap());
            });
        }
        heading(ui, "Outcome");
        ui.label(&self.outcome);
        open
    }

    fn environment(&self, ui: &mut egui::Ui) {
        if self.env.is_empty() {
            ui.weak("The environment of its last exec was not recorded.");
            return;
        }
        ui.weak(if self.compared {
            "+ added, ~ changed, \u{2212} removed, against its parent's environment."
        } else {
            "Nothing to compare with: its parent's environment was not recorded."
        });
        egui::ScrollArea::vertical()
            .id_salt("triage-process-env-list")
            .max_height(280.0)
            .show(ui, |ui| {
                for row in &self.env {
                    let color = match row.line.change {
                        Change::Same => theme::muted(),
                        Change::Added => theme::good(),
                        Change::Changed(_) => theme::warn(),
                        Change::Removed => theme::error(),
                    };
                    ui.horizontal_wrapped(|ui| {
                        let text = format!("{} {}", row.line.mark(), row.line.text());
                        let label = ui.add(
                            egui::Label::new(RichText::new(text).monospace().color(color)).wrap(),
                        );
                        if let Change::Changed(old) = &row.line.change {
                            label.on_hover_text(format!("Its parent had {}={old}", row.line.name));
                        }
                        for rule in &row.rules {
                            widgets::chip(ui, rule.clone(), Tone::Error)
                                .on_hover_text("Flagged by this Triage rule");
                        }
                    });
                }
            });
    }
}

fn relative_link(ui: &mut egui::Ui, relative: &Relative) -> egui::Response {
    let color = ui.visuals().hyperlink_color;
    ui.add(
        egui::Label::new(RichText::new(&relative.label).monospace().color(color))
            .sense(egui::Sense::click()),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
    .on_hover_text("Show this process")
}

/// Select a process in the tree and open its Details.
pub(super) fn open_process(view: &TriageView, ctx: &egui::Context, pid: u32, cookie: u64) {
    let Some(scan) = &view.scan else { return };
    let rows = process_tree::process_rows(&scan.process, scan.clock_anchor, &scan.suspicious);
    let Some(row) = rows.into_iter().find(|row| {
        files::number(&row[0].values, "process.pid") == Some(u64::from(pid))
            && files::number(&row[0].values, "process.cookie").unwrap_or(0) == cookie
    }) else {
        return;
    };
    details::select(ctx, "triage-process", &process_tree::PROCESS_HEADERS, &row);
    ctx.data_mut(|data| {
        data.insert_temp(
            egui::Id::new(("triage-selected-row", "triage-process")),
            evidence_key(&row),
        )
    });
}
