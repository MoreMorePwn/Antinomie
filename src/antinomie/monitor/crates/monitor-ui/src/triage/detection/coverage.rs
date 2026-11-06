// SPDX-License-Identifier: GPL-3.0-only
//! Detection > rule coverage: how many IDS rules loaded or Sigma rules were
//! evaluated, how many did not apply and why. These are coverage limits of the
//! engine and the run; they are not a partial scan.
use super::*;
use antinomie_monitor_core::analysis::detection::{
    Coverage, CoverageReason, IDS_REASONS, SIGMA_REASONS,
};

fn plural(count: u64, one: &str, many: &str) -> String {
    format!(
        "{} {}",
        engine::group_digits(count),
        if count == 1 { one } else { many }
    )
}

/// "(TLS fingerprint 2, dataset 1)": the reasons that apply, in a fixed order.
fn reasons(coverage: &Coverage, wanted: &[CoverageReason]) -> String {
    wanted
        .iter()
        .filter(|reason| coverage.count_of(**reason) > 0)
        .map(|reason| {
            format!(
                "{} {}",
                reason.label(),
                engine::group_digits(coverage.count_of(*reason))
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// "2,094 rules loaded · 5 not loadable (TLS fingerprint 3, dataset 2)" for IDS,
/// "12 rules evaluated · 40 not applicable (no matching events 30, ...)" for Sigma.
/// None for YARA and for results saved before the counts were kept.
#[cfg(test)]
pub(super) fn summary(engine: Engine, coverage: &Coverage) -> Option<String> {
    summary_of(engine, coverage, None)
}

/// [`summary`], with the rules of the enabled packs when the Rule packs line
/// above counts more than the engine loaded: "370 rules loaded (of 386 in the
/// enabled packs)".
pub(super) fn summary_of(
    engine: Engine,
    coverage: &Coverage,
    offered: Option<u64>,
) -> Option<String> {
    let (done, other, wanted, total) = match engine {
        Engine::Ids => (
            "loaded",
            "not loadable",
            &IDS_REASONS,
            coverage.not_loadable(),
        ),
        Engine::Sigma => (
            "evaluated",
            "not applicable",
            &SIGMA_REASONS,
            coverage.not_applicable(),
        ),
        Engine::Yara => return None,
    };
    let mut text = format!("{} {done}", plural(coverage.evaluated, "rule", "rules"));
    if let Some(offered) = offered.filter(|offered| *offered != coverage.evaluated) {
        text.push_str(&format!(
            " (of {} in the enabled packs)",
            engine::group_digits(offered)
        ));
    }
    if total > 0 {
        text.push_str(&format!(
            " · {} {other} ({})",
            engine::group_digits(total),
            reasons(coverage, wanted)
        ));
    }
    Some(text)
}

/// Why the Rule packs line and the loaded count differ, for the tooltip.
pub(super) fn difference_note(engine: Engine, coverage: &Coverage, offered: u64) -> Option<String> {
    if engine != Engine::Ids || offered == coverage.evaluated {
        return None;
    }
    let digits = engine::group_digits;
    let refused = coverage.not_loadable();
    let rest = offered.saturating_sub(coverage.evaluated + refused);
    let mut text = format!(
        "The Rule packs line counts every rule in the enabled packs ({}). Suricata loaded {} of them for this scan.",
        digits(offered),
        digits(coverage.evaluated)
    );
    if refused > 0 {
        text.push_str(&format!(
            " {} were refused before the scan (the list below names each one and why).",
            digits(refused)
        ));
    }
    if rest > 0 {
        text.push_str(&format!(
            " {} more were switched off one by one, belong to a pack the scan could not use, or were left out by Suricata itself (an unsupported keyword, a rule it could not parse, a protocol the capture does not have).",
            digits(rest)
        ));
    }
    Some(text)
}

/// The note for a capped evidence preview; the match counts are complete.
pub(super) fn preview_note(engine: Engine, coverage: &Coverage) -> Option<String> {
    let limit = engine::group_digits(coverage.evidence_preview_limit?);
    Some(match engine {
        Engine::Sigma => format!(
            "Evidence preview limited to {limit} locations in total; match counts are complete."
        ),
        _ => format!("Evidence preview limited to {limit} per rule; match counts are complete."),
    })
}

fn item_text(item: &antinomie_monitor_core::analysis::detection::CoverageItem) -> String {
    if item.detail.is_empty() {
        format!("{}: {}", item.reason.label(), item.rule)
    } else {
        format!("{}: {} — {}", item.reason.label(), item.rule, item.detail)
    }
}

impl View {
    /// The IDS's "2,094 rules loaded · 7 not loadable" line and its hover note.
    /// It rides at the right end of the Rule packs line.
    pub(super) fn loaded_line(&self, index: usize) -> Option<(String, Option<String>)> {
        let Some(Ok(report)) = self.results[index].as_ref() else {
            return None;
        };
        if report.engine != Engine::Ids {
            return None;
        }
        let coverage = report.coverage.as_ref()?;
        let offered: u64 = self.sets[index]
            .iter()
            .filter(|set| set.enabled)
            .map(|set| set.rules)
            .sum();
        let offered = (offered > 0).then_some(offered);
        let line = summary_of(report.engine, coverage, offered)?;
        let note = offered.and_then(|offered| difference_note(report.engine, coverage, offered));
        Some((line, note))
    }

    /// The collapsible list of the rules that did not apply, headed by its
    /// toggle; Sigma's rule counts sit under the toggle, and the preview note
    /// last. The IDS's loaded line is on the Rule packs line.
    pub(super) fn coverage_section(&self, ui: &mut egui::Ui, index: usize) {
        let Some(Ok(report)) = self.results[index].as_ref() else {
            return;
        };
        let Some(coverage) = report.coverage.as_ref() else {
            return;
        };
        let listed = !coverage.listed.is_empty();
        let open_id = ui.id().with(("detection-coverage-open", index));
        let mut open = listed
            && ui
                .data(|data| data.get_temp::<bool>(open_id))
                .unwrap_or(false);
        if listed {
            let count = coverage.listed.len() as u64 + coverage.unlisted;
            let title = if report.engine == Engine::Ids {
                format!("Show the {} rules not loaded", engine::group_digits(count))
            } else {
                format!(
                    "Show the {} rules not applicable to this run",
                    engine::group_digits(count)
                )
            };
            let caret = if open {
                egui_phosphor::regular::CARET_DOWN
            } else {
                egui_phosphor::regular::CARET_RIGHT
            };
            if ui
                .add(
                    egui::Button::new(RichText::new(format!("{caret} {title}")).small())
                        .frame(false),
                )
                .clicked()
            {
                open = !open;
                ui.data_mut(|data| data.insert_temp(open_id, open));
            }
        }
        if report.engine != Engine::Ids {
            if let Some(line) = summary_of(report.engine, coverage, None) {
                ui.label(RichText::new(line).small().color(theme::muted()));
            }
        }
        if open {
            ui.indent(("detection-coverage", index), |ui| {
                for item in &coverage.listed {
                    ui.add(
                        egui::Label::new(
                            RichText::new(item_text(item)).small().color(theme::muted()),
                        )
                        .wrap(),
                    );
                }
                if coverage.unlisted > 0 {
                    ui.label(
                        RichText::new(format!(
                            "…and {} more not listed; the counts above include them",
                            engine::group_digits(coverage.unlisted)
                        ))
                        .small()
                        .color(theme::muted()),
                    );
                }
            });
        }
        if let Some(note) = preview_note(report.engine, coverage) {
            ui.label(RichText::new(note).small().color(theme::muted()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> Coverage {
        let mut coverage = Coverage {
            evaluated: 2094,
            ..Coverage::default()
        };
        for (reason, count) in [
            (CoverageReason::TlsFingerprint, 3),
            (CoverageReason::Dataset, 2),
            (CoverageReason::DuplicateSid, 1),
            (CoverageReason::NoSid, 1),
        ] {
            for index in 0..count {
                coverage.add(reason, format!("sid {index}"), "reason text");
            }
        }
        coverage
    }

    #[test]
    fn ids_counts_read_as_loaded_and_not_loadable_with_reasons() {
        assert_eq!(
            summary(Engine::Ids, &ids()).unwrap(),
            "2,094 rules loaded · 7 not loadable (TLS fingerprint 3, dataset 2, duplicate 1, no SID 1)"
        );
        let clean = Coverage {
            evaluated: 1,
            ..Coverage::default()
        };
        assert_eq!(summary(Engine::Ids, &clean).unwrap(), "1 rule loaded");
        assert!(summary(Engine::Yara, &clean).is_none());
    }

    #[test]
    fn the_rule_packs_count_and_the_loaded_count_are_told_apart() {
        let coverage = ids();
        // 2,094 loaded + 7 refused of 2,110 offered leaves 9 unexplained by us.
        assert_eq!(
            summary_of(Engine::Ids, &coverage, Some(2110)).unwrap(),
            "2,094 rules loaded (of 2,110 in the enabled packs) · 7 not loadable (TLS fingerprint 3, dataset 2, duplicate 1, no SID 1)"
        );
        let note = difference_note(Engine::Ids, &coverage, 2110).unwrap();
        assert!(
            note.contains("every rule in the enabled packs (2,110)"),
            "{note}"
        );
        assert!(note.contains("Suricata loaded 2,094"), "{note}");
        assert!(note.contains("7 were refused"), "{note}");
        assert!(note.contains("9 more were switched off"), "{note}");
        // Equal counts need no explanation.
        assert_eq!(
            summary_of(Engine::Ids, &coverage, Some(2094)).unwrap(),
            summary(Engine::Ids, &coverage).unwrap()
        );
        assert!(difference_note(Engine::Ids, &coverage, 2094).is_none());
    }

    #[test]
    fn sigma_counts_read_as_evaluated_and_not_applicable_with_reasons() {
        let mut coverage = Coverage {
            evaluated: 12,
            ..Coverage::default()
        };
        for (reason, count) in [
            (CoverageReason::NoMatchingEvents, 30),
            (CoverageReason::Backend, 2),
            (CoverageReason::Syntax, 1),
        ] {
            for _ in 0..count {
                coverage.add(reason, "rule", "");
            }
        }
        assert_eq!(
            summary(Engine::Sigma, &coverage).unwrap(),
            "12 rules evaluated · 33 not applicable (no matching events 30, backend 2, syntax 1)"
        );
    }

    #[test]
    fn the_preview_cap_is_a_note_that_says_counts_are_complete() {
        let mut coverage = Coverage::default();
        assert!(preview_note(Engine::Ids, &coverage).is_none());
        coverage.evidence_preview_limit = Some(16);
        assert_eq!(
            preview_note(Engine::Ids, &coverage).unwrap(),
            "Evidence preview limited to 16 per rule; match counts are complete."
        );
        coverage.evidence_preview_limit = Some(10_000);
        assert!(preview_note(Engine::Sigma, &coverage)
            .unwrap()
            .contains("10,000 locations in total; match counts are complete"));
    }

    #[test]
    fn the_section_lists_rules_behind_a_collapsed_header_and_stays_complete() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut view = View::default();
        let mut report = super::super::tests::report(Vec::new());
        report.engine = Engine::Ids;
        let mut coverage = ids();
        coverage.evidence_preview_limit = Some(16);
        report.coverage = Some(coverage);
        view.results[1] = Some(Ok(report));
        let draw = |view: &View| {
            super::super::tests::rendered_text(&super::super::tests::frames(&ctx, 2, |root| {
                egui::CentralPanel::default().show(root, |ui| view.coverage_section(ui, 1));
            }))
        };
        let text = draw(&view);
        // The loaded line moved to the Rule packs line.
        assert!(!text.contains("rules loaded"), "{text}");
        assert!(text.contains("Show the 7 rules not loaded"), "{text}");
        assert!(text.contains("match counts are complete"), "{text}");
        assert!(
            !text.contains("reason text"),
            "collapsed by default: {text}"
        );
        let lower = text.to_lowercase();
        assert!(
            !lower.contains("partial") && !lower.contains("complete)"),
            "{text}"
        );
        let state = &view.results[1].as_ref().unwrap().as_ref().unwrap().state;
        assert_eq!(super::super::header::state(state), "Complete");
    }

    #[test]
    fn an_old_report_without_counts_shows_no_coverage_line() {
        let ctx = egui::Context::default();
        let mut view = View::default();
        let mut report = super::super::tests::report(Vec::new());
        report.engine = Engine::Sigma;
        view.results[2] = Some(Ok(report));
        let text =
            super::super::tests::rendered_text(&super::super::tests::frames(&ctx, 1, |root| {
                egui::CentralPanel::default().show(root, |ui| view.coverage_section(ui, 2));
            }));
        assert!(!text.contains("rules"), "{text}");
    }

    fn sigma_view() -> View {
        let mut view = View::default();
        let mut report = super::super::tests::report(Vec::new());
        report.engine = Engine::Sigma;
        let mut coverage = Coverage {
            evaluated: 12,
            ..Coverage::default()
        };
        coverage.add(CoverageReason::NoMatchingEvents, "rule one", "no events");
        report.coverage = Some(coverage);
        view.results[2] = Some(Ok(report));
        view
    }

    fn pane(view: &mut View) -> Vec<(String, egui::Rect)> {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut texts = Vec::new();
        for shape in super::super::tests::frames(&ctx, 2, |root| {
            egui::CentralPanel::default().show(root, |ui| view.coverage_section(ui, 2));
        }) {
            super::super::tests::each_galley_rect(&shape.shape, &mut |text, rect| {
                texts.push((text.to_owned(), rect));
            });
        }
        texts
    }

    #[test]
    fn the_not_applicable_toggle_is_the_line_above_the_counts() {
        let mut view = sigma_view();
        let texts = pane(&mut view);
        let find = |needle: &str| {
            texts
                .iter()
                .find(|(text, _)| text.contains(needle))
                .unwrap_or_else(|| panic!("{needle} missing: {texts:?}"))
                .1
        };
        let toggle = find("Show the 1 rules not applicable");
        let counts = find("12 rules evaluated");
        assert!(toggle.max.y <= counts.min.y + 1.0, "{toggle:?} {counts:?}");
        // The list stays folded until the toggle is opened.
        assert!(!texts.iter().any(|(text, _)| text.contains("no events")));
    }
}
