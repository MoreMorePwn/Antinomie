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
    /// Why it did not start, without host paths: the first part of the
    /// failure, in one sentence or two.
    pub reason: String,
    /// The rest of the failure text (the route's log and its last lines),
    /// without host paths; empty when there is none.
    pub detail: String,
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

/// Where a host path starts: the analyst's home and the usual places of
/// user data. A guest path (`/proc/net/tcp`, `/etc/shadow`, `/tmp/x`) is none.
fn host_prefixes() -> Vec<String> {
    let mut prefixes: Vec<String> = ["/home/", "/mnt/", "/media/", "/Users/", "/run/user/"]
        .map(String::from)
        .to_vec();
    if let Ok(home) = std::env::var("HOME") {
        let home = home.trim_end_matches('/');
        if home.len() > 1 && home != "/root" {
            prefixes.push(format!("{home}/"));
        }
    }
    prefixes
}

/// `text` with every absolute host path cut to its last component: a report
/// is shared, and the analyst's folders are not for others. Guest paths, the
/// ones the request names, stay whole.
pub(crate) fn without_host_paths(text: &str) -> String {
    let prefixes = host_prefixes();
    text.split(' ')
        .map(|word| {
            let bare = word.trim_start_matches(['(', '"', '\'', '=']);
            let lead = &word[..word.len() - bare.len()];
            if prefixes
                .iter()
                .any(|prefix| bare.starts_with(prefix.as_str()))
            {
                let last = bare.rsplit('/').next().unwrap_or(bare);
                format!("{lead}{last}")
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A failure text as (reason, detail): without a leading "Not started: "
/// (the report adds its own), the reason up to the route's log, the log
/// name and its last lines as the detail.
pub(crate) fn split_failure(text: &str) -> (String, String) {
    let mut text = text.trim();
    while let Some(rest) = text.strip_prefix("Not started:") {
        text = rest.trim_start();
    }
    let cut = [" Log: ", " Last log lines", "\nLog: ", "\nLast log lines"]
        .iter()
        .filter_map(|marker| text.find(marker))
        .min();
    match cut {
        Some(at) => (text[..at].trim().to_owned(), text[at..].trim().to_owned()),
        None => (text.to_owned(), String::new()),
    }
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
        let (reason, detail) = split_failure(
            run.recording_error
                .as_deref()
                .unwrap_or("the run did not start, and no reason was recorded"),
        );
        let clip = |text: String| {
            if text.chars().count() > 1200 {
                text.chars().take(1199).collect::<String>() + "…"
            } else {
                text
            }
        };
        let reason = clip(without_host_paths(&reason));
        let detail = clip(without_host_paths(&detail));
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
                // The state is the reason alone; the log is a note of its own.
                info.state = format!("Not started: {reason}");
                info
            },
            sample,
            reason: reason.clone(),
            detail,
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
    // Every format reads the state to know the run did not start.
    if !report.not_started() {
        report.run.state = format!("Not started: {}", run.reason);
    }
    report.sample = run.sample.clone();
    report.notes.push(format!(
        "This run did not start, so there is no recording and no Triage: {}",
        run.reason
    ));
    if !run.detail.is_empty() {
        report.notes.push(format!("Failure detail: {}", run.detail));
    }
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
    fn host_paths_are_cut_to_their_last_component_and_guest_paths_stay() {
        assert_eq!(
            without_host_paths(
                "tor stuck at 55%. Log: /home/user/data/network/tor/ant-1/tor.log. Last log lines"
            ),
            "tor stuck at 55%. Log: tor.log. Last log lines"
        );
        assert_eq!(
            without_host_paths("ran (/bin/sh) /tmp"),
            "ran (/bin/sh) /tmp"
        );
        // The Symbiote request: guest paths are what the run was asked to do.
        let request = "sh -c L=$(ls /tmp/f55af21f-* | head -n 1); cat /proc/net/tcp; cat /etc/passwd /etc/shadow";
        assert_eq!(without_host_paths(request), request);
        assert_eq!(without_host_paths("no paths here"), "no paths here");
    }

    #[test]
    fn a_failure_is_said_once_and_its_log_is_a_detail() {
        let (reason, detail) = split_failure(
            "Not started: Not started: the Tor route did not become ready in 120 s (bootstrap 55%). Log: /home/user/d/tor.log. Last log lines: [notice] Bootstrapped 55%",
        );
        assert_eq!(
            reason,
            "the Tor route did not become ready in 120 s (bootstrap 55%)."
        );
        assert!(
            detail.starts_with("Log: /home/user/d/tor.log. Last log lines"),
            "{detail}"
        );
        assert_eq!(
            split_failure("launch rejected by the guest: Bad address"),
            (
                "launch rejected by the guest: Bad address".into(),
                String::new()
            )
        );
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
            detail: "Log: tor.log. Last log lines: x".into(),
            request: "/tmp/x -a".into(),
            route: "Tor via 127.0.0.1:9050".into(),
            environment: "Debian 13 (Minimal), kernel 6.12.94".into(),
            static_analysis: vec![("Identification".into(), "ELF x86-64".into())],
            directory: PathBuf::from("/runs/9c861d41"),
        };
        let report = build(&run, 1_794_000_000_000);
        assert_eq!(report.sample.as_ref().unwrap().name, "elf-6168f5d053f4");
        assert!(report.notes[0].contains("no Triage: launch rejected"));
        assert!(!report.notes[0].contains("Not started: Not started"));
        assert_eq!(
            report.notes[1],
            "Failure detail: Log: tor.log. Last log lines: x"
        );
        assert!(report.notes.iter().any(|n| n == "Request: /tmp/x -a"));
        assert!(report
            .notes
            .iter()
            .any(|n| n == "Static analysis, Identification: ELF x86-64"));
        let json = report.to_json().unwrap();
        assert!(json.contains("launch rejected"));
        // Every format writes it; MISP and STIX hold no malware for it.
        for format in report::Format::ALL {
            let bytes = report::export::render(&report, format, true).unwrap();
            assert!(!bytes.is_empty(), "{format:?}");
            if let Ok(out) = std::env::var("ANTINOMIE_REPORT_OUT") {
                let folder = Path::new(&out).join("not-started");
                std::fs::create_dir_all(&folder).unwrap();
                std::fs::write(
                    folder.join(format!("not-started{}", format.suffix())),
                    &bytes,
                )
                .unwrap();
            }
        }
        let stix = String::from_utf8(
            report::export::render(&report, report::Format::Stix, false).unwrap(),
        )
        .unwrap();
        assert!(!stix.contains("\"malware\"") && !stix.contains("malware-analysis"));
        assert!(stix.contains("did not start"));
        let misp = String::from_utf8(
            report::export::render(&report, report::Format::Misp, false).unwrap(),
        )
        .unwrap();
        assert!(
            misp.contains("antinomie:assessment=\\\"not_started\\\""),
            "{misp}"
        );
        assert!(!misp.contains("\"to_ids\": true"));
    }
}
