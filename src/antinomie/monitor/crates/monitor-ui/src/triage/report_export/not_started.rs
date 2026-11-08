// SPDX-License-Identifier: GPL-3.0-only
//! The report of a run that never started (the guest refused the launch, the
//! Tor route did not come up): no recording, so no Triage; the request, why it
//! did not start, the static analysis there is and the sample's identity.
//!
//! This is the one entry point beside `build::build` that turns what the app
//! knows into a [`report::Report`]; it fills only fields the report already
//! has (the run, the sample and the overview notes), so every format writes it.
use super::*;
use antinomie_monitor_core::RunSummary;

/// What the report says of a run that did not start.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NotStartedRun {
    pub run: report::RunInfo,
    pub sample: Option<report::SampleInfo>,
    /// Why it did not start, without host paths.
    pub reason: String,
    /// The program, its arguments and where it was to run.
    pub request: String,
    /// The network route, when the run named one.
    pub route: String,
    /// The base image and kernel the run was to boot.
    pub environment: String,
    /// The static analysis: (check, what it found).
    pub static_analysis: Vec<(String, String)>,
    /// The run's folder (the report goes to its `report` folder).
    pub directory: PathBuf,
}

/// `text` with every absolute host path cut to its last component: a report
/// is shared, and the analyst's folders are not for others.
pub(crate) fn without_host_paths(text: &str) -> String {
    text.split(' ')
        .map(|word| {
            let bare = word.trim_start_matches(['(', '"', '\'']);
            let lead = &word[..word.len() - bare.len()];
            if bare.starts_with('/') && bare.matches('/').count() >= 2 {
                let last = bare.rsplit('/').next().unwrap_or(bare);
                format!("{lead}{last}")
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl NotStartedRun {
    pub(crate) fn of(run: &RunSummary) -> Self {
        let sample = run
            .request
            .sample
            .as_ref()
            .map(|sample| report::SampleInfo {
                name: sample.name.clone(),
                sha256: sample.sha256.clone(),
                size: run.analysis.as_ref().and_then(|a| a.specimen_len),
                ..report::SampleInfo::default()
            })
            .or_else(|| {
                let analysis = run.analysis.as_ref()?;
                Some(report::SampleInfo {
                    name: Path::new(&analysis.source_path)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    sha256: analysis.specimen_sha256.clone()?,
                    size: analysis.specimen_len,
                    ..report::SampleInfo::default()
                })
            });
        let mut reason = without_host_paths(
            run.recording_error
                .as_deref()
                .unwrap_or("the run did not start, and no reason was recorded"),
        );
        if reason.chars().count() > 1200 {
            reason = reason.chars().take(1199).collect::<String>() + "…";
        }
        let request = {
            let mut text = run.request.path.clone();
            for arg in &run.request.args {
                text.push(' ');
                text.push_str(arg);
            }
            if !run.request.cwd.is_empty() {
                text.push_str(&format!(" (in {})", run.request.cwd));
            }
            without_host_paths(&text)
        };
        let route = run
            .route
            .as_ref()
            .map(|route| route.label.clone())
            .unwrap_or_default();
        let environment = run
            .environment
            .as_ref()
            .map(|e| {
                let mut parts = vec![e.base_name.clone()];
                if !e.kernel_release.is_empty() {
                    parts.push(format!("kernel {}", e.kernel_release));
                }
                parts.retain(|p| !p.is_empty());
                parts.join(", ")
            })
            .unwrap_or_default();
        let static_analysis = run
            .analysis
            .as_ref()
            .map(|analysis| {
                analysis
                    .sections
                    .iter()
                    .map(|s| (s.kind.label().to_owned(), without_host_paths(&s.summary)))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            // The shared run block, so the state reads "Not started: <reason>"
            // like the run report's own wording.
            run: {
                let base = report::RunInfo {
                    vm_id: run.vm_id.clone(),
                    boot_id: run.boot_id.clone(),
                    run_id: run.id.clone(),
                    started_ms: run.started_ms,
                    finished: true,
                    ..report::RunInfo::default()
                };
                let mut info =
                    super::run_facts::run_info(&base, run, None, 0, run.started_ms.unwrap_or(0));
                info.vm_id = base.vm_id;
                info.boot_id = base.boot_id;
                info.run_id = base.run_id;
                info.finished = true;
                // The failure text can name host files (the Tor log).
                info.state = without_host_paths(&info.state);
                info
            },
            sample,
            reason,
            request,
            route,
            environment,
            static_analysis,
            directory: run.directory.clone(),
        }
    }
}

/// The report: the overview with the failure first, then the request, the
/// route, the environment and the static analysis, each as an overview note.
pub(crate) fn build(run: &NotStartedRun, now_ms: u64) -> report::Report {
    let mut report = report::Report::new(run.run.clone(), now_ms);
    report.sample = run.sample.clone();
    report.notes.push(format!(
        "This run did not start, so there is no recording and no Triage. Not started: {}",
        run.reason
    ));
    if !run.request.is_empty() {
        report.notes.push(format!("Request: {}", run.request));
    }
    if !run.route.is_empty() {
        report.notes.push(format!("Network route: {}", run.route));
    }
    if !run.environment.is_empty() {
        report
            .notes
            .push(format!("Environment: {}", run.environment));
    }
    if run.static_analysis.is_empty() {
        report
            .notes
            .push("Static analysis: none was recorded for this run.".into());
    } else {
        for (check, found) in &run.static_analysis {
            report
                .notes
                .push(format!("Static analysis, {check}: {found}"));
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_paths_are_cut_to_their_last_component() {
        assert_eq!(
            without_host_paths(
                "tor stuck at 55%. Log: /home/user/data/network/tor/ant-1/tor.log. Last log lines"
            ),
            "tor stuck at 55%. Log: tor.log. Last log lines"
        );
        assert_eq!(without_host_paths("ran (/bin/sh) /tmp"), "ran (sh) /tmp");
        assert_eq!(without_host_paths("no paths here"), "no paths here");
    }

    #[test]
    fn the_report_names_the_failure_the_request_and_the_sample() {
        let run = NotStartedRun {
            run: report::RunInfo {
                run_id: "9c861d41".into(),
                finished: true,
                ..Default::default()
            },
            sample: Some(report::SampleInfo {
                name: "elf-6168f5d053f4".into(),
                sha256: "6168f5d053f4c3d413327947c37b927a759b316d68ac341908695879edcda246".into(),
                size: Some(2048),
                ..Default::default()
            }),
            reason: "launch rejected by the guest, nothing was started".into(),
            request: "/tmp/x -a".into(),
            route: "Tor via 127.0.0.1:9050".into(),
            environment: "Debian 13 (Minimal), kernel 6.12.94".into(),
            static_analysis: vec![("Identification".into(), "ELF x86-64".into())],
            directory: PathBuf::from("/runs/9c861d41"),
        };
        let report = build(&run, 1_794_000_000_000);
        assert_eq!(report.sample.as_ref().unwrap().name, "elf-6168f5d053f4");
        assert!(report.notes[0].contains("Not started: launch rejected"));
        assert!(report.notes.iter().any(|n| n == "Request: /tmp/x -a"));
        assert!(report
            .notes
            .iter()
            .any(|n| n == "Static analysis, Identification: ELF x86-64"));
        let json = report.to_json().unwrap();
        assert!(json.contains("launch rejected"));
        // Every format writes it.
        for format in report::Format::ALL {
            let bytes = report::export::render(&report, format, true).unwrap();
            assert!(!bytes.is_empty(), "{format:?}");
        }
    }
}
