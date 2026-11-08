// SPDX-License-Identifier: GPL-3.0-only
//! Detection (YARA, IDS and Sigma) for one run, without a window: the names
//! the results are stored and shown under. The engines themselves run in the
//! core (`antinomie_monitor_core::analysis::detection`); the Detection tab
//! that schedules and draws them is the GUI's.
use antinomie_monitor_core::analysis::detection::{Engine, Finding, Report};

/// The engines in the order the Detection tab and the digest list them.
pub const ENGINES: [Engine; 3] = [Engine::Yara, Engine::Ids, Engine::Sigma];

/// The engine's name in the digest, the report and on screen.
pub fn name(engine: Engine) -> &'static str {
    match engine {
        Engine::Yara => "YARA",
        Engine::Ids => "IDS",
        Engine::Sigma => "Sigma",
    }
}

/// The name the rules' folder and the managed selection use for `engine`.
pub fn engine_key(engine: Engine) -> &'static str {
    match engine {
        Engine::Yara => "yara",
        Engine::Ids => "ids",
        Engine::Sigma => "sigma",
    }
}

/// The rule pack a finding came from: the report's source it points at
/// (`s0`), else its own source without the digest (`Pack sha256:...`).
pub fn pack_name(report: &Report, finding: &Finding) -> String {
    let index = finding
        .source
        .strip_prefix('s')
        .and_then(|index| index.parse::<usize>().ok());
    if let Some(source) = index.and_then(|index| report.sources.get(index)) {
        return source.name.clone();
    }
    finding
        .source
        .split_once(" sha256:")
        .map_or(finding.source.as_str(), |(name, _)| name)
        .to_owned()
}
