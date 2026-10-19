// SPDX-License-Identifier: MIT
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
pub(super) fn summary(engine: Engine, coverage: &Coverage) -> Option<String> {
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
    if total > 0 {
        text.push_str(&format!(
            " · {} {other} ({})",
            engine::group_digits(total),
            reasons(coverage, wanted)
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
    /// The rule counts of the selected engine, the collapsible list of the rules
    /// that did not apply, and the preview note.
    pub(super) fn coverage_section(&self, ui: &mut egui::Ui, index: usize) {
        let Some(Ok(report)) = self.results[index].as_ref() else {
            return;
        };
        let Some(coverage) = report.coverage.as_ref() else {
            return;
        };
        let Some(line) = summary(report.engine, coverage) else {
            return;
        };
        ui.label(RichText::new(line).small().color(theme::muted()));
        if !coverage.listed.is_empty() {
            let title = if report.engine == Engine::Ids {
                "Rules not loaded"
            } else {
                "Rules not applicable to this run"
            };
            egui::CollapsingHeader::new(RichText::new(title).small())
                .id_salt(("detection-coverage", index))
                .show(ui, |ui| {
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
            super::super::tests::rendered_text(&super::super::tests::frames(&ctx, 2, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| view.coverage_section(ui, 1));
            }))
        };
        let text = draw(&view);
        assert!(
            text.contains("2,094 rules loaded · 7 not loadable"),
            "{text}"
        );
        assert!(text.contains("Rules not loaded"), "{text}");
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
            super::super::tests::rendered_text(&super::super::tests::frames(&ctx, 1, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| view.coverage_section(ui, 2));
            }));
        assert!(!text.contains("rules"), "{text}");
    }
}
