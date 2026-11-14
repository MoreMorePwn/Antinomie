// SPDX-License-Identifier: GPL-3.0-only
//! How a core or a memory dump is named in its list and above its page: the
//! process, the rule that took it and the time (`PID 1352 (bpfdoor.elf) ·
//! c2.bpf_backdoor · 2026-11-14 12:03:44`), and where it came from (`Run
//! f9c3d854 (bpfdoor.elf) · dump trigger, c2.bpf_backdoor (High)`). An
//! imported file keeps its file name. A long path is shown middle-elided,
//! whole on hover.
use crate::run_link::RunNames;
use antinomie_monitor_core::provenance::{Origin, Provenance};
use eframe::egui;

/// Which kind of dump a name is for: the words of its origin differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DumpKind {
    Core,
    Memory,
}

/// A dump's time as its list shows it: `2026-11-14 12:03:44`, UTC.
pub(crate) fn dump_time(ms: u64) -> String {
    crate::time_format::utc_seconds(ms / 1000)
        .trim_end_matches(" UTC")
        .to_owned()
}

/// `PID <pid> (<program>) · <rule> · <time>`: the parts that are known, in
/// that order; the program is left out when it is not known.
pub(crate) fn core_name(
    pid: u32,
    program: Option<&str>,
    rule: Option<&str>,
    time_ms: Option<u64>,
) -> String {
    let mut name = match program.filter(|program| !program.is_empty()) {
        Some(program) => format!("PID {pid} ({program})"),
        None => format!("PID {pid}"),
    };
    if let Some(rule) = rule.filter(|rule| !rule.is_empty()) {
        name.push_str(" \u{b7} ");
        name.push_str(rule);
    }
    if let Some(ms) = time_ms.filter(|ms| *ms > 0) {
        name.push_str(" \u{b7} ");
        name.push_str(&dump_time(ms));
    }
    name
}

/// A memory dump's name: `<rule> · <time>` for one a trigger took, else its time.
pub(crate) fn memory_name(rule: Option<&str>, time_ms: u64) -> String {
    match rule.filter(|rule| !rule.is_empty()) {
        Some(rule) => format!("{rule} \u{b7} {}", dump_time(time_ms)),
        None => dump_time(time_ms),
    }
}

/// The time a record says the dump was taken: when it was written, else when
/// it was asked for.
pub(crate) fn provenance_time(provenance: &Provenance) -> Option<u64> {
    provenance
        .to_ms
        .filter(|ms| *ms > 0)
        .or(Some(provenance.from_ms).filter(|ms| *ms > 0))
}

/// The program a run executed, as the Run column names it.
pub(crate) fn run_program<'a>(names: &'a RunNames, run_id: Option<&str>) -> Option<&'a str> {
    names
        .get(run_id?)
        .map(|run| run.sample.as_str())
        .filter(|sample| !sample.is_empty())
}

/// Where a dump came from: which run, and how it was taken (dump trigger with
/// its rule, Dump core or Dump memory by hand, on exit), or "Imported".
pub(crate) fn origin(provenance: Option<&Provenance>, names: &RunNames, kind: DumpKind) -> String {
    let Some(provenance) = provenance else {
        return "Origin not recorded".into();
    };
    let how = match provenance.origin {
        Origin::Imported => return "Imported".into(),
        Origin::Trigger => Some(match &provenance.finding {
            Some(finding) => format!("dump trigger, {}", finding.text()),
            None => "dump trigger".into(),
        }),
        Origin::ByHand => Some(
            match kind {
                DumpKind::Core => "Dump core",
                DumpKind::Memory => "Dump memory",
            }
            .into(),
        ),
        Origin::RunExit => Some(
            match kind {
                DumpKind::Core => "core dump on exit",
                DumpKind::Memory => "memory dump on exit",
            }
            .into(),
        ),
        Origin::Unknown | Origin::RunCapture => None,
    };
    let run = provenance.run_id.as_deref().map(|id| match names.get(id) {
        Some(run) if !run.sample.is_empty() => format!("Run {} ({})", run.short, run.sample),
        Some(run) => format!("Run {}", run.short),
        None => format!("Run {}", crate::run_link::short(id)),
    });
    match (run, how) {
        (Some(run), Some(how)) => format!("{run} \u{b7} {how}"),
        (Some(run), None) => run,
        (None, Some(how)) => format!("Not in a run \u{b7} {how}"),
        (None, None) => "Origin not recorded".into(),
    }
}

/// `prefix…suffix` of at most `max_chars` characters; the whole text when it fits.
pub(crate) fn middle_elide(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars || max_chars < 3 {
        return text.to_owned();
    }
    let keep = max_chars - 1;
    let tail = keep / 2;
    let head = keep - tail;
    let mut elided: String = text.chars().take(head).collect();
    elided.push('\u{2026}');
    elided.extend(text.chars().skip(count - tail));
    elided
}

/// A path as one line that fits the width: middle-elided, whole on hover,
/// with Copy path on right click.
pub(crate) fn path_line(ui: &mut egui::Ui, path: &str, copy_label: &str) -> egui::Response {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let glyph = ui.fonts_mut(|fonts| fonts.glyph_width(&font, 'n')).max(1.0);
    let fits = (ui.available_width() / glyph).floor().max(8.0) as usize;
    let shown = middle_elide(path, fits);
    let response = ui
        .add(egui::Label::new(shown).sense(egui::Sense::click()))
        .on_hover_text(path);
    response.context_menu(|ui| {
        if ui.button(copy_label).clicked() {
            ui.ctx().copy_text(path.to_owned());
            ui.close();
        }
    });
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::dump_trigger::TriggerTier;
    use antinomie_monitor_core::provenance::FoundBy;

    const RUN: &str = "f9c3d854547992ccfc7f6670b3cc7866";

    fn names() -> RunNames {
        RunNames::of(&[crate::run_link::test_run(RUN, "/tmp/bpfdoor.elf")])
    }

    fn trigger() -> Provenance {
        Provenance {
            run_id: Some(RUN.into()),
            origin: Origin::Trigger,
            pid: Some(1352),
            finding: Some(FoundBy {
                rule: "c2.bpf_backdoor".into(),
                tier: TriggerTier::High,
            }),
            from_ms: 1_763_121_824_000,
            ..Provenance::default()
        }
    }

    #[test]
    fn a_core_is_named_by_its_process_rule_and_time() {
        let at = provenance_time(&trigger());
        assert_eq!(
            core_name(1352, Some("bpfdoor.elf"), Some("c2.bpf_backdoor"), at),
            "PID 1352 (bpfdoor.elf) \u{b7} c2.bpf_backdoor \u{b7} 2025-11-14 12:03:44"
        );
        // Not taken by a rule: no rule part; unknown program and time: left out.
        assert_eq!(
            core_name(7, Some("demo"), None, at),
            "PID 7 (demo) \u{b7} 2025-11-14 12:03:44"
        );
        assert_eq!(core_name(7, None, None, None), "PID 7");
        assert_eq!(
            memory_name(Some("c2.bpf_backdoor"), 1_763_121_824_000),
            "c2.bpf_backdoor \u{b7} 2025-11-14 12:03:44"
        );
        assert_eq!(memory_name(None, 1_763_121_824_000), "2025-11-14 12:03:44");
    }

    #[test]
    fn the_origin_says_which_run_and_how_the_dump_was_taken() {
        let names = names();
        assert_eq!(
            origin(Some(&trigger()), &names, DumpKind::Core),
            "Run f9c3d854 (bpfdoor.elf) \u{b7} dump trigger, c2.bpf_backdoor (High)"
        );
        let exit = Provenance::run_exit("vm", "boot", RUN, 0);
        assert_eq!(
            origin(Some(&exit), &names, DumpKind::Core),
            "Run f9c3d854 (bpfdoor.elf) \u{b7} core dump on exit"
        );
        assert_eq!(
            origin(Some(&exit), &names, DumpKind::Memory),
            "Run f9c3d854 (bpfdoor.elf) \u{b7} memory dump on exit"
        );
        let by_hand = Provenance::by_hand("vm", "boot", None, Vec::new(), 1);
        assert_eq!(
            origin(Some(&by_hand), &names, DumpKind::Core),
            "Not in a run \u{b7} Dump core"
        );
        let unlisted = Provenance::by_hand("vm", "boot", Some("0123456789abcdef"), Vec::new(), 1);
        assert_eq!(
            origin(Some(&unlisted), &names, DumpKind::Core),
            "Run 01234567 \u{b7} Dump core"
        );
        let imported = Provenance::imported("vm", 1);
        assert_eq!(
            origin(Some(&imported), &names, DumpKind::Memory),
            "Imported"
        );
        assert_eq!(origin(None, &names, DumpKind::Core), "Origin not recorded");
    }

    #[test]
    fn a_long_path_keeps_its_start_and_its_end() {
        let path =
            "/home/user/.local/share/antinomie/vms/abc/boots/def/core-captures/0179/process.elf";
        let shown = middle_elide(path, 32);
        assert_eq!(shown.chars().count(), 32);
        assert!(shown.starts_with("/home/user/.loca"), "{shown}");
        assert!(shown.ends_with("179/process.elf"), "{shown}");
        assert!(shown.contains('\u{2026}'));
        assert_eq!(middle_elide("/short/path", 32), "/short/path");
    }
}
