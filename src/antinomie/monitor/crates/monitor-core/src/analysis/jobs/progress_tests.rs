// SPDX-License-Identifier: GPL-3.0-only
use super::*;

/// A deliberately slow, trusted tool fixture lets the real worker prove that
/// atomic progress survives the sandbox boundary before the final report.
#[test]
#[ignore = "requires built app in ANTINOMIE_TEST_WORKER_BINARY, bubblewrap and managed tool preference"]
fn production_sandbox_publishes_light_results_while_heavy_tool_runs() {
    assert_eq!(
        std::env::var("ANTINOMIE_ANALYSIS_TOOLS").as_deref(),
        Ok("managed")
    );
    let executable = PathBuf::from(std::env::var_os("ANTINOMIE_TEST_WORKER_BINARY").unwrap());
    let directory =
        std::env::temp_dir().join(format!("ant-live-progress-{}", storage::unique_id()));
    storage::private_dir(&directory).unwrap();
    let tools = directory.join("tools");
    fs::create_dir_all(tools.join("capa")).unwrap();
    let capa = tools.join("capa/capa");
    fs::write(
        &capa,
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo fixture; else sleep 5; echo '{}'; fi\n",
    )
    .unwrap();
    fs::set_permissions(&capa, fs::Permissions::from_mode(0o700)).unwrap();
    let specimen = fs::read("/usr/bin/true").unwrap();
    fs::write(directory.join("specimen"), &specimen).unwrap();
    // Heavy-first user order must not prevent metadata and strings finishing.
    let mut report = new_report(
        "/usr/bin/true",
        &AnalysisSelection {
            enabled: true,
            checks: vec![
                AnalysisKind::Capabilities,
                AnalysisKind::Metadata,
                AnalysisKind::Strings,
            ],
            time_limit_minutes: 0,
            limits: Default::default(),
        },
    );
    report.specimen_len = Some(specimen.len() as u64);
    report.specimen_sha256 = Some(format!("{:x}", Sha256::digest(&specimen)));
    report.state = AnalysisState::Queued;
    let job = Job {
        run_id: None,
        report,
        directory: directory.clone(),
        handle: None,
        total_len: specimen.len() as u64,
        received_len: specimen.len() as u64,
        file: None,
        deadline: Instant::now() + Duration::from_secs(30),
        child: None,
        cleanup_reason: None,
        reserved_len: 0,
        digest: Sha256::new(),
        disk_len: 0,
        worker_len: 0,
        report_len: 0,
        specimen_publication: None,
        progress: Default::default(),
        host_copy: None,
        supplement: None,
    };
    let mut child = spawn_worker_binary(&job, &executable, Some(&tools)).unwrap();
    let mut watch = progress::Watch::default();
    let mut live = job.report.clone();
    let mut saw_live = false;
    let status = loop {
        if let Some(snapshot) = watch.changed(&directory, &live) {
            if snapshot.sections[0].state == AnalysisSectionState::Running
                && snapshot.sections[0].tools == ["capa"]
            {
                assert_eq!(snapshot.sections[1].state, AnalysisSectionState::Complete);
                assert_eq!(snapshot.sections[2].state, AnalysisSectionState::Complete);
                assert!(snapshot.sections[0].summary.contains("elapsed"));
                eprintln!("live: {}", snapshot.sections[0].summary);
                saw_live = true;
            }
            progress::merge(&mut live, snapshot, false);
        }
        if let Some(status) = child.poll_status().unwrap() {
            break status;
        }
        if Instant::now() >= job.deadline {
            let mut log = SandboxLog::new(&directory).unwrap();
            cleanup_sandbox(&mut child, &mut log).unwrap();
            panic!("worker exceeded deadline: {}", directory.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "worker failed: {}", directory.display());
    assert!(
        saw_live,
        "host never saw live progress: {}",
        directory.display()
    );
    let final_report =
        read_report(&directory.join("output/report.json"), &job.report, true).unwrap();
    assert_eq!(
        final_report
            .sections
            .iter()
            .map(|s| s.kind)
            .collect::<Vec<_>>(),
        job.report
            .sections
            .iter()
            .map(|s| s.kind)
            .collect::<Vec<_>>()
    );
    assert!(
        !final_report
            .sections
            .iter()
            .any(|s| s.state == AnalysisSectionState::Running)
    );
    fs::remove_dir_all(directory).unwrap();
}

fn three_checks() -> AnalysisReport {
    let mut report = new_report(
        "/usr/bin/true",
        &AnalysisSelection {
            enabled: true,
            checks: vec![
                AnalysisKind::Metadata,
                AnalysisKind::Capabilities,
                AnalysisKind::Strings,
            ],
            time_limit_minutes: 0,
            limits: Default::default(),
        },
    );
    report.state = AnalysisState::Running;
    report.sections[0].state = AnalysisSectionState::Complete;
    report.sections[1].state = AnalysisSectionState::Running;
    report
}

#[test]
fn cancelling_or_failing_never_leaves_a_check_running() {
    for state in [
        AnalysisState::Cancelled,
        AnalysisState::Partial,
        AnalysisState::Unavailable,
    ] {
        let mut report = three_checks();
        fail(&mut report, state, "stopped");
        assert_eq!(report.sections[0].state, AnalysisSectionState::Complete);
        for section in &report.sections[1..] {
            assert_eq!(section.state, AnalysisSectionState::Unavailable);
            assert_eq!(section.summary, "stopped");
        }
        validation::validate_report(&report).unwrap();
    }
}

#[test]
fn only_one_running_check_is_valid_and_only_while_the_report_runs() {
    let mut report = three_checks();
    validation::validate_report(&report).unwrap();
    report.sections[2].state = AnalysisSectionState::Running;
    assert!(validation::validate_report(&report).is_err());
    report.sections[2].state = AnalysisSectionState::Pending;
    report.state = AnalysisState::Partial;
    assert!(validation::validate_report(&report).is_err());
}
