// SPDX-License-Identifier: GPL-3.0-only
//! Triage's Summary box "Run artifacts": the selected run's cores, memory
//! dumps, capture segments and trigger log. It draws the sample page's
//! Artifacts rows (same columns, same Open buttons), read for one run, with
//! the run's time window and the packet count of each capture segment.
use super::{
    output_files::{self, Act, Availability, Kind, Output, Table},
    parts, *,
};
use antinomie_monitor_core::{
    dump_trigger::TriggerLog, network::count_packets, RunArtifactState, RunSummary,
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

/// How long a live run's artifacts are trusted before they are read again.
const LIVE_REREAD: Duration = Duration::from_secs(2);

/// An artifact of the run the user asked to open, with the run it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Open {
    Core(String),
    Memory(String),
    Capture(PathBuf),
}

/// Everything the box shows, read once and again while the run is live.
struct Built {
    run_id: String,
    outputs: Vec<Output>,
    triggers: Option<TriggerLog>,
    started_ms: Option<u64>,
    ended_ms: Option<u64>,
    live: bool,
    read: Instant,
}

/// The box's state: what was read for the selected run.
#[derive(Default)]
pub(crate) struct RunBoxState {
    built: Option<Built>,
}

type Counts = HashMap<PathBuf, (u64, Instant)>;
static PACKETS: Mutex<Option<(Counts, HashSet<PathBuf>)>> = Mutex::new(None);

/// The packets a capture segment holds, once counted on a thread; a segment
/// still being written is counted again after a few seconds.
fn packets(ctx: &egui::Context, path: &std::path::Path, live: bool) -> Option<u64> {
    let mut guard = PACKETS.lock().ok()?;
    let (known, pending) = guard.get_or_insert_with(Default::default);
    let found = known.get(path).copied();
    let stale = found.is_some_and(|(_, at)| live && at.elapsed() > Duration::from_secs(4));
    if (found.is_none() || stale) && !pending.contains(path) {
        pending.insert(path.to_path_buf());
        let (path, wake) = (path.to_path_buf(), ctx.clone());
        let _ = std::thread::Builder::new()
            .name("run-box-packets".into())
            .spawn(move || {
                let counted = count_packets(&path).map(|(count, _)| count).ok();
                if let Ok(mut guard) = PACKETS.lock() {
                    if let Some((known, pending)) = guard.as_mut() {
                        pending.remove(&path);
                        if let Some(count) = counted {
                            known.insert(path, (count, Instant::now()));
                        }
                    }
                }
                wake.request_repaint();
            });
    }
    found.map(|(count, _)| count)
}

impl RunBoxState {
    /// Read the run's artifacts when the run changed, or again while it is
    /// live; a finished run is read once. `ended_ms` is when its program
    /// tree ended, if it did.
    pub(crate) fn refresh(&mut self, run: &RunSummary, live: bool, ended_ms: Option<u64>) {
        let due = match &self.built {
            Some(built) if built.run_id == run.id => {
                live != built.live
                    || ended_ms != built.ended_ms
                    || (live && built.read.elapsed() > LIVE_REREAD)
            }
            _ => true,
        };
        if !due {
            return;
        }
        let artifacts = antinomie_monitor_core::RunArtifacts::load(&run.directory)
            .ok()
            .flatten();
        let entry = RunEntry {
            number: 1,
            run: super::super::super::history::listed(run),
            folder: true,
            artifacts,
            digest: None,
        };
        let mut outputs = output_files::read(std::slice::from_ref(&entry), &[]);
        for output in &mut outputs {
            output.run_id.clone_from(&run.id);
        }
        self.built = Some(Built {
            run_id: run.id.clone(),
            outputs,
            triggers: run.triggers.clone(),
            started_ms: run.started_ms,
            ended_ms,
            live,
            read: Instant::now(),
        });
    }

    /// Whether the run has anything to show.
    pub(crate) fn is_empty(&self) -> bool {
        self.built.as_ref().is_none_or(|built| {
            built.outputs.is_empty()
                && built
                    .triggers
                    .as_ref()
                    .is_none_or(|log| log.records.is_empty() && log.missed.is_empty())
        })
    }

    /// How many artifacts are listed, for the heading.
    pub(crate) fn count(&self) -> usize {
        self.built.as_ref().map_or(0, |built| built.outputs.len())
    }
}

/// The run's window in words: "17:38:02 to 17:44:10 (6 min 8 s)", or
/// "since 17:38:02 (running)".
pub(crate) fn window_text(started_ms: Option<u64>, ended_ms: Option<u64>, live: bool) -> String {
    let at = |ms: u64| parts::second(ms);
    match (started_ms, ended_ms) {
        (Some(from), Some(to)) => format!(
            "{} to {} ({})",
            at(from),
            at(to),
            crate::time_format::duration_ms(to.saturating_sub(from))
        ),
        (Some(from), None) if live => format!("since {} (running)", at(from)),
        (Some(from), None) => format!("from {}", at(from)),
        (None, _) => "not recorded".into(),
    }
}

/// Draw the box's content: the window, the artifact rows, the trigger log.
/// Returns the artifact to open, if a button was pressed.
pub(crate) fn show(
    ui: &mut egui::Ui,
    state: &RunBoxState,
    data_dir: &std::path::Path,
    font: f32,
) -> Option<Open> {
    let built = state.built.as_ref()?;
    ui.add(
        egui::Label::new(
            RichText::new(format!(
                "Run window {}",
                window_text(built.started_ms, built.ended_ms, built.live)
            ))
            .small()
            .color(theme::muted()),
        )
        .wrap(),
    );
    let mut rows: Vec<Output> = built.outputs.clone();
    let captures = rows.iter().filter(|o| o.kind == Kind::Capture).count();
    let mut segment = 0;
    for output in &mut rows {
        if output.kind != Kind::Capture || output.path.as_os_str().is_empty() {
            continue;
        }
        segment += 1;
        let count = match packets(ui.ctx(), &output.path, built.live) {
            Some(count) => format!("{count} packets"),
            None => "counting packets…".to_owned(),
        };
        output.saved_because =
            format!("Network capture, segment {segment} of {captures} · {count}");
    }
    let mut act = None;
    if rows.is_empty() {
        parts::muted_line(ui, "This run saved no cores, memory dumps or captures.");
    } else {
        let label = built.run_id.chars().take(8).collect::<String>();
        let present = |_: &Output| true;
        output_files::table(
            ui,
            &rows,
            &Table {
                id: "run_artifacts_box",
                data_dir,
                font,
                run_present: &present,
                go_to_run: false,
                run_label: Some(&label),
            },
            &mut act,
        );
    }
    trigger_log(ui, built.triggers.as_ref());
    match act {
        Some(Act::Open(_, kind)) => {
            let first = |wanted: Kind| {
                rows.iter()
                    .find(|o| o.kind == wanted && o.availability == Availability::InRun)
                    .map(|o| o.path.clone())
            };
            match kind {
                Kind::Core => Some(Open::Core(built.run_id.clone())),
                Kind::Memory => Some(Open::Memory(built.run_id.clone())),
                Kind::Capture => first(Kind::Capture).map(Open::Capture),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The trigger log: each match that took a dump, each that came too late, and
/// how many more the budget and the cooldown held back.
fn trigger_log(ui: &mut egui::Ui, log: Option<&TriggerLog>) {
    let Some(log) = log else { return };
    if log.records.is_empty() && log.missed.is_empty() && log.skipped == 0 && log.lost == 0 {
        return;
    }
    ui.add_space(6.0);
    ui.label(
        RichText::new("Trigger log")
            .strong()
            .color(theme::heading()),
    );
    let state = |dump: &Option<antinomie_monitor_core::dump_trigger::TriggerDump>| match dump {
        None => "not asked".to_owned(),
        Some(dump) => match (&dump.error, dump.state) {
            (Some(error), RunArtifactState::Failed) => format!("failed ({error})"),
            (_, other) => crate::app::core_capture_status(other).to_owned(),
        },
    };
    for record in &log.records {
        ui.add(
            egui::Label::new(format!(
                "{}  {} ({}) in process {}: core {}, memory {}",
                parts::second(record.at_ms),
                record.finding.rule,
                record.finding.tier.label(),
                record.finding.pid,
                state(&record.core),
                state(&record.memory),
            ))
            .wrap(),
        );
    }
    for miss in &log.missed {
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "{}  {} ({}): no dump. {}",
                    parts::second(miss.at_ms),
                    miss.finding.rule,
                    miss.finding.tier.label(),
                    miss.reason
                ))
                .color(theme::muted()),
            )
            .wrap(),
        );
    }
    if log.skipped > 0 || log.lost > 0 {
        parts::muted_line(
            ui,
            &format!(
                "{} more matches took no dump (over the budget or inside the cooldown); {} were lost.",
                log.skipped, log.lost
            ),
        );
    }
}

/// A run folder for tests and screenshots: one trigger core, one capture
/// segment of two packets and a trigger log with three skipped matches.
#[cfg(test)]
pub(crate) fn fixture_run(dir: &std::path::Path) -> RunSummary {
    /// A pcap with two packets.
    fn pcap(path: &std::path::Path) {
        let mut bytes = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ];
        for _ in 0..2 {
            bytes.extend([0u8; 8]);
            bytes.extend(4u32.to_le_bytes());
            bytes.extend(4u32.to_le_bytes());
            bytes.extend([1, 2, 3, 4]);
        }
        std::fs::write(path, bytes).unwrap();
    }

    std::fs::create_dir_all(dir.join("core-captures/c1")).unwrap();
    std::fs::write(dir.join("core-captures/c1/process.elf"), b"\x7fELF").unwrap();
    pcap(&dir.join("a.pcap"));
    let artifacts: antinomie_monitor_core::RunArtifacts =
        serde_json::from_value(serde_json::json!({
            "run_id": "f9c3d854547992ccfc7f6670b3cc7866", "vm_id": "vm", "boot_id": "b",
            "network_captures": [dir.join("a.pcap")], "network_state": "complete",
            "core_state": "disabled",
            "trigger_dumps": [{"at_ms": 5000, "finding": {"rule": "c2.bpf_backdoor",
                "summary": "", "tier": "high", "pid": 1352, "tid": 1352, "task_cookie": 2,
                "stream_id": 1, "call_id": 1, "guest_ns": 1, "syscall": "setsockopt"},
                "core": {"state": "partial", "path": dir.join("core-captures/c1/process.elf"),
                    "capture_id": "c1", "size": 4}}]
        }))
        .unwrap();
    std::fs::write(
        dir.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    let mut run = crate::run_link::test_run("f9c3d854547992ccfc7f6670b3cc7866", "/tmp/x");
    run.vm_id = "vm".into();
    run.directory = dir.to_path_buf();
    run.started_ms = Some(1_794_047_000_000);
    run.triggers = Some(TriggerLog {
        records: artifacts.trigger_dumps.clone(),
        skipped: 3,
        ..TriggerLog::default()
    });
    run
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(output: &egui::FullOutput) -> String {
        fn collect(shape: &egui::epaint::Shape, out: &mut String) {
            match shape {
                egui::epaint::Shape::Text(text) => {
                    out.push_str(text.galley.text());
                    out.push('\n');
                }
                egui::epaint::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, out)),
                _ => {}
            }
        }
        let mut out = String::new();
        for shape in &output.shapes {
            collect(&shape.shape, &mut out);
        }
        out
    }

    #[test]
    fn the_box_lists_cores_captures_the_window_and_the_trigger_log() {
        let dir = std::env::temp_dir().join(format!("antinomie-run-box-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let run = fixture_run(&dir);
        let mut state = RunBoxState::default();
        assert!(state.is_empty(), "nothing is read yet");
        state.refresh(&run, false, Some(1_794_047_368_000));
        assert!(!state.is_empty());
        assert_eq!(state.count(), 2, "one core and one capture segment");
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let mut opened = None;
        let mut all = String::new();
        for _ in 0..4 {
            let output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1200.0, 700.0),
                    )),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        opened = show(ui, &state, &dir, 14.0).or(opened.take());
                    });
                },
            );
            all = texts(&output);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        for wanted in [
            "Run window",
            "6 min 8 s",
            "Core dump",
            "Network capture",
            "segment 1 of 1",
            "2 packets",
            "Triggered by c2.bpf_backdoor (High, pid 1352)",
            "Trigger log",
            "3 more matches took no dump",
            "f9c3d854",
        ] {
            assert!(all.contains(wanted), "{wanted:?} in:\n{all}");
        }
        assert!(opened.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_window_reads_running_finished_and_unrecorded() {
        assert!(window_text(Some(1_000_000), None, true).contains("(running)"));
        assert!(window_text(Some(1_000_000), Some(1_065_000), false).contains("1 min 5 s"));
        assert_eq!(window_text(None, None, false), "not recorded");
    }
}
