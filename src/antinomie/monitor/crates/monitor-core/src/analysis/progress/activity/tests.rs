use super::*;
fn fixture() -> (PathBuf, AnalysisReport) {
    let directory =
        std::env::temp_dir().join(format!("ant-activity-{}", crate::storage::unique_id()));
    fs::create_dir(&directory).unwrap();
    let mut report = crate::analysis::jobs::new_report(
        "/bin/true",
        &AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Identification],
        },
    );
    report.state = AnalysisState::Running;
    report.sections[0].state = AnalysisSectionState::Running;
    (directory, report)
}
#[test]
fn tool_switch_elapsed_identity_and_guard_cleanup() {
    let (directory, mut report) = fixture();
    {
        let _stage = Stage::begin(&directory, &report, 0);
        tool_started("/usr/bin/file", &["/input/specimen"]);
        tool_started("/usr/bin/file", &["--version"]);
        annotate(&directory, &mut report);
        assert_eq!(report.sections[0].tools, ["file"]);
        assert!(report.sections[0].summary.contains("tool 0s"));
        tool_started("/usr/bin/diec", &["-j", "/input/specimen"]);
        annotate(&directory, &mut report);
        assert_eq!(report.sections[0].tools, ["Detect It Easy"]);
    }
    let before = fs::read(directory.join("current.json")).unwrap();
    tool_started("/usr/bin/other", &[]);
    assert_eq!(before, fs::read(directory.join("current.json")).unwrap());
    report.id = "different".into();
    report.sections[0].summary = "unchanged".into();
    annotate(&directory, &mut report);
    assert_eq!(report.sections[0].summary, "unchanged");
    fs::remove_dir_all(directory).unwrap();
}
#[test]
fn unsafe_malformed_and_future_status_are_ignored() {
    use std::os::unix::fs::symlink;
    let (directory, mut report) = fixture();
    let _stage = Stage::begin(&directory, &report, 0);
    let path = directory.join("current.json");
    let mut a: Activity = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    a.tool_started_ms = u64::MAX;
    fs::write(&path, serde_json::to_vec(&a).unwrap()).unwrap();
    let original = report.sections[0].summary.clone();
    annotate(&directory, &mut report);
    assert_eq!(report.sections[0].summary, original);
    fs::write(&path, vec![b'x'; 4097]).unwrap();
    annotate(&directory, &mut report);
    assert_eq!(report.sections[0].summary, original);
    fs::remove_file(&path).unwrap();
    symlink("/etc/passwd", &path).unwrap();
    annotate(&directory, &mut report);
    assert_eq!(report.sections[0].summary, original);
    fs::remove_dir_all(directory).unwrap();
}
