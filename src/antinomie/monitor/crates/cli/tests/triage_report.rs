// SPDX-License-Identifier: GPL-3.0-only
//! `triage`, `detect` and `report` through the built binary, on a saved run
//! of a scratch data directory (design 3.4.3, card P2-4).
use antinomie_monitor_core::{ExecRequest, RunState, RunSummary, report::Choices};
use antinomie_triage::{
    SavedRun, report_export,
    tests::{http_pcap, write_rwx_calls},
};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, atomic::AtomicBool},
};

const RUN: &str = "5f3c9a10-run-fixture";

fn cli(args: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .args(args)
        .env_remove("ANTINOMIE_COPIER")
        .output()
        .expect("antinomie-cli runs");
    let value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    (output.status.code().unwrap_or(-1), value)
}

/// A data directory with one saved run of VM `vm-1`: RWX mapping calls under
/// root cookie 55 and its record.
struct Data {
    root: PathBuf,
}

impl Data {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("ant-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("data").join("vm-1").join("runs").join(RUN);
        std::fs::create_dir_all(&dir).unwrap();
        let mut raw = Vec::new();
        write_rwx_calls(&mut raw, 0..3);
        std::fs::write(dir.join("telemetry.raw"), raw).unwrap();
        let run = RunSummary {
            environment: None,
            reduced: None,
            boot_wait: None,
            triggers: None,
            stopped_by_user: false,
            stopped_at_ms: None,
            started_ms: Some(1_792_000_000_000),
            clock_anchor: None,
            id: RUN.into(),
            vm_id: "vm-1".into(),
            boot_id: "boot-1".into(),
            session_id: 1,
            root_task_cookie: 55,
            pid: 42,
            request: ExecRequest {
                path: "/tmp/sample".into(),
                ..ExecRequest::default()
            },
            directory: dir.clone(),
            terminal_eof: true,
            state: RunState::Finished,
            notes: Vec::new(),
            machine: None,
            route: None,
            recording_error: None,
            execution: None,
            analysis: None,
        };
        std::fs::write(dir.join("run.json"), serde_json::to_vec(&run).unwrap()).unwrap();
        Self { root }
    }

    /// The run of a library sample with an HTTP capture its artifact list
    /// names and one YARA match in its digest: the recording
    /// `tests/monitor/test-report-export.py` is written for.
    fn with_capture(name: &str) -> Self {
        let data = Self::new(name);
        let dir = data.run_dir();
        let mut run: RunSummary =
            serde_json::from_slice(&std::fs::read(dir.join("run.json")).unwrap()).unwrap();
        run.request.sample = Some(antinomie_monitor_core::samples::SampleRef {
            sha256: "ab".repeat(32),
            name: "fixture.elf".into(),
        });
        std::fs::write(dir.join("run.json"), serde_json::to_vec(&run).unwrap()).unwrap();
        let pcap = dir.join("network.pcap");
        std::fs::write(&pcap, http_pcap()).unwrap();
        let artifacts = antinomie_monitor_core::RunArtifacts {
            run_id: RUN.into(),
            vm_id: "vm-1".into(),
            boot_id: "boot-1".into(),
            network_captures: vec![pcap],
            network_state: antinomie_monitor_core::RunArtifactState::Complete,
            ..Default::default()
        };
        std::fs::write(
            dir.join("artifacts.json"),
            serde_json::to_vec(&artifacts).unwrap(),
        )
        .unwrap();
        antinomie_monitor_core::run_digest::RunDigest::update(&dir, |digest| {
            digest.detections = Some(vec![antinomie_monitor_core::run_digest::DetectionHit {
                engine: "YARA".into(),
                rule_id: "fixture_rule".into(),
                title: "fixture_rule".into(),
                severity: "high".into(),
                count: 2,
                author: "Jane Rule".into(),
                license: "DRL 1.1".into(),
                source: "Example Pack".into(),
                reference: "https://example.org/rule".into(),
                ..Default::default()
            }]);
        })
        .unwrap();
        data
    }

    fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    fn run_dir(&self) -> PathBuf {
        self.data().join("vm-1").join("runs").join(RUN)
    }

    fn args<'a>(&'a self, data: &'a str, tail: &[&'a str]) -> Vec<&'a str> {
        let mut all = vec!["-o", "json", "--data-dir", data];
        all.extend_from_slice(tail);
        all
    }
}

impl Drop for Data {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn triage_prints_the_summary_of_a_saved_run_found_by_id_prefix_or_triple() {
    let fixture = Data::new("triage");
    let data = fixture.data();
    let data = data.to_str().unwrap();
    let (code, value) = cli(&fixture.args(data, &["triage", "5f3c9a10"]));
    assert_eq!(code, 0, "{value}");
    let result = &value["result"];
    assert_eq!(result["run"]["run_id"], RUN);
    assert_eq!(result["run"]["vm_id"], "vm-1");
    let summary = &result["summary"];
    assert!(summary["assessment"].is_string(), "{summary}");
    assert!(summary["counts"]["processes"].as_u64().unwrap() >= 1);
    assert!(summary["counts"]["findings"].as_u64().unwrap() >= 1);
    assert!(result.get("processes").is_none());
    // The same run by vm:boot:run, with a part added.
    let (code, value) = cli(&fixture.args(
        data,
        &[
            "triage",
            "vm-1:boot-1:5f3c9a10-run-fixture",
            "--parts",
            "processes",
        ],
    ));
    assert_eq!(code, 0, "{value}");
    assert!(
        !value["result"]["processes"]["rows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // Unknown runs and parts.
    let (code, value) = cli(&fixture.args(data, &["triage", "ffffffff"]));
    assert_eq!(code, 3, "{value}");
    assert_eq!(value["error"]["code"], "not_found");
    let (code, _) = cli(&fixture.args(data, &["triage", RUN, "--parts", "bogus"]));
    assert_eq!(code, 4);
}

/// The report the command writes is the one the shared job builds: the same
/// JSON once its time of making is set aside.
#[test]
fn report_writes_the_files_the_shared_export_job_writes() {
    let fixture = Data::new("report");
    let data = fixture.data();
    let data_arg = data.to_str().unwrap();
    let out = fixture.root.join("out");
    let (code, value) = cli(&fixture.args(
        data_arg,
        &[
            "report",
            RUN,
            "--formats",
            "json,md,html",
            "--out",
            out.to_str().unwrap(),
        ],
    ));
    assert_eq!(code, 0, "{value}");
    let files = value["result"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 3, "{value}");
    let json_path = files
        .iter()
        .find(|file| file["format"] == "JSON")
        .and_then(|file| file["path"].as_str())
        .map(PathBuf::from)
        .unwrap();
    assert!(json_path.starts_with(&out));
    // Nothing went into the recording's own report folder.
    assert!(!fixture.run_dir().join("report").exists());

    // The library's job, as the GUI's dialog runs it, into another folder.
    let run: RunSummary =
        serde_json::from_slice(&std::fs::read(fixture.run_dir().join("run.json")).unwrap())
            .unwrap();
    let options = antinomie_monitor_core::BackendOptions {
        data_dir: data.clone(),
        ..Default::default()
    };
    let saved = SavedRun::open(run, &options).unwrap();
    let library = fixture.root.join("library");
    let choices = Choices {
        formats: vec![antinomie_monitor_core::report::Format::Json],
        folder: library.display().to_string(),
        ..Choices::default()
    };
    let job = report_export::Job::for_saved(&saved, choices, 1);
    let written = report_export::run_job(&job, &Arc::new(AtomicBool::new(false)), &|_| {}).unwrap();
    let theirs = &written.files[0].1;
    assert_eq!(normalised(&json_path), normalised(theirs));
}

fn normalised(path: &Path) -> Value {
    let mut value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    value["generated_ms"] = Value::Null;
    value
}

#[test]
fn detect_without_save_writes_nothing_into_the_recording() {
    let fixture = Data::new("detect");
    let data = fixture.data();
    let data = data.to_str().unwrap();
    // No static analysis of a sample and no capture: neither engine has
    // evidence, and says why.
    let (code, value) = cli(&fixture.args(data, &["detect", RUN, "--engine", "yara,ids"]));
    assert_eq!(code, 0, "{value}");
    let engines = value["result"]["engines"].as_array().unwrap();
    assert_eq!(engines.len(), 2);
    for engine in engines {
        assert_eq!(engine["outcome"], "not_scanned", "{engine}");
        assert!(!engine["reason"].as_str().unwrap().is_empty());
    }
    assert_eq!(engines[1]["evidence_key"], "missing:pcap");
    assert_eq!(value["result"]["saved"], false);
    assert!(!fixture.run_dir().join("triage-detection").exists());
    assert!(!fixture.run_dir().join("triage-digest.json").exists());
    let (code, _) = cli(&fixture.args(data, &["detect", RUN, "--engine", "clamav"]));
    assert_eq!(code, 4);
}

/// The command's files for `tests/monitor/test-report-export.py`: with
/// `ANTINOMIE_REPORT_OUT=DIR`, every format and the evidence bundle go to DIR
/// and an HTML and JSON export without the Network and Files parts to
/// DIR/limited-defanged, the exports the script checks (it is run as
/// `test-report-export.py DIR`). Without the variable the exports go to a
/// scratch folder and only their exit codes are checked.
#[test]
fn report_writes_what_the_report_checks_read() {
    let fixture = Data::with_capture("report-checks");
    let data = fixture.data();
    let data = data.to_str().unwrap();
    let out = std::env::var("ANTINOMIE_REPORT_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| fixture.root.join("checks"));
    let limited = out.join("limited-defanged");
    let (code, value) = cli(&fixture.args(
        data,
        &[
            "report",
            RUN,
            "--formats",
            "all",
            "--evidence-bundle",
            "--out",
            out.to_str().unwrap(),
        ],
    ));
    assert_eq!(code, 0, "{value}");
    assert!(
        value["result"]["files"].as_array().unwrap().len() >= 6,
        "{value}"
    );
    let (code, value) = cli(&fixture.args(
        data,
        &[
            "report",
            RUN,
            "--formats",
            "html,json",
            "--parts",
            "summary,indicators,attack,processes,findings,file_activity,detections,evidence,custody",
            "--defang",
            "--out",
            limited.to_str().unwrap(),
        ],
    ));
    assert_eq!(code, 0, "{value}");
    let json = value["result"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["format"] == "JSON")
        .and_then(|file| file["path"].as_str())
        .map(PathBuf::from)
        .unwrap();
    let doc: Value = serde_json::from_slice(&std::fs::read(json).unwrap()).unwrap();
    assert!(doc["network"].is_null() && doc["files"].is_null());
    assert_eq!(doc["detections"][0]["rule_id"], "fixture_rule");
}
