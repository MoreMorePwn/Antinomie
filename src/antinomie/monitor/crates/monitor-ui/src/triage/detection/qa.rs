// SPDX-License-Identifier: GPL-3.0-only
//! Screenshot fixture: the Detection page with results for all three engines.
//! `ANTINOMIE_TRIAGE_QA_SCENE=detection` (and `ANTINOMIE_QA_ENGINE` = yara,
//! ids or sigma) under Xvfb; see `triage::tests`.
use super::tests::{finding, report};
use super::*;
use antinomie_monitor_core::analysis::detection::{
    Coverage, CoverageReason, InputKind, InputOutcome, ScannedInput, SIGMA_COVERAGE_WARNING,
};
use antinomie_monitor_core::ruleset::EngineSet;

impl View {
    pub(in crate::triage) fn qa_scene(&mut self) {
        self.selected = match std::env::var("ANTINOMIE_QA_ENGINE").as_deref() {
            Ok("ids") => Engine::Ids,
            Ok("sigma") => Engine::Sigma,
            _ => Engine::Yara,
        };
        for (index, (engine, matches)) in
            [(Engine::Yara, 3), (Engine::Ids, 120), (Engine::Sigma, 2)]
                .into_iter()
                .enumerate()
        {
            self.sets[index] = vec![EngineSet {
                name: "YARA-Forge Core".into(),
                revision: "20261004".into(),
                enabled: true,
                rules: 2094,
                source: String::new(),
            }];
            let findings = (0..matches)
                .map(|at| {
                    finding(
                        &format!("rule{at}"),
                        &format!("Matched rule {at}"),
                        Vec::new(),
                    )
                })
                .collect();
            let mut result = report(findings);
            result.engine = engine;
            result.scanned_objects = 1;
            result.scanned_rules = Some(2094);
            result.inputs = Some(vec![ScannedInput {
                kind: InputKind::Executable,
                path: PathBuf::from("/runs/r/sample"),
                name: "sample".into(),
                outcome: InputOutcome::Succeeded,
                warning: if engine == Engine::Sigma {
                    SIGMA_COVERAGE_WARNING.into()
                } else {
                    String::new()
                },
                ..ScannedInput::default()
            }]);
            let mut coverage = Coverage {
                evaluated: 2094,
                ..Coverage::default()
            };
            for at in 0..4 {
                coverage.add(
                    CoverageReason::NoMatchingEvents,
                    format!("rule {at}"),
                    "no events",
                );
            }
            result.coverage = Some(coverage);
            self.results[index] = Some(Ok(result));
            self.rows(index);
        }
    }
}
