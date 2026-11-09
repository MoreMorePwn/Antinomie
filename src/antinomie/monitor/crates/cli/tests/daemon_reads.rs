// SPDX-License-Identifier: GPL-3.0-only
//! The read commands against a running daemon (card T0417): `run list`,
//! `run show`, `run export`, `triage`, `sample list/show/tag`, `custody
//! verify`, `vm list` and `base list` go to the daemon when one owns the data
//! directory and give the same answers as direct mode. The daemon here is the
//! real one (`Daemon::start`) over a scripted engine; the commands are the
//! built binary.

use antinomie_monitor_core::{
    BackendOptions, BaseSummary, ExecRequest, GuestArch, RunArtifactState, RunArtifacts, RunState,
    RunSummary, VmConfig,
    samples::{Library, NewSample},
};
use antinomie_service::{
    clock::ManualClock,
    config::ServiceConfig,
    daemon::{Daemon, Exit, NoSignals, Setup},
    engine::FakeEngine,
    server::limits::Limits,
};
use antinomie_triage::tests::{http_pcap, write_rwx_calls};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const RUN: &str = "5f3c9a10-run-fixture";
const SAMPLE: &[u8] = b"#!/bin/sh\necho benign\n";

fn cli(args: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .args(args)
        .env_remove("ANTINOMIE_COPIER")
        .output()
        .expect("antinomie-cli runs");
    let value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    if !output.status.success() && std::env::var_os("SHOW_STDERR").is_some() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    (output.status.code().unwrap_or(-1), value)
}

/// A scratch folder with a data directory that holds one saved run (RWX
/// mapping calls and an HTTP capture) and a library with the run's sample.
struct Fixture {
    root: PathBuf,
    sha256: String,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("ant-t417-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let data = root.join("data");
        let dir = data.join("vm-1").join("runs").join(RUN);
        std::fs::create_dir_all(&dir).unwrap();
        let mut library = Library::open(&data).unwrap();
        let added = library
            .add_bytes(
                SAMPLE,
                NewSample {
                    name: "benign.sh".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut raw = Vec::new();
        write_rwx_calls(&mut raw, 0..3);
        std::fs::write(dir.join("telemetry.raw"), raw).unwrap();
        let pcap = dir.join("network.pcap");
        std::fs::write(&pcap, http_pcap()).unwrap();
        let artifacts = RunArtifacts {
            run_id: RUN.into(),
            vm_id: "vm-1".into(),
            boot_id: "boot-1".into(),
            network_captures: vec![pcap],
            network_state: RunArtifactState::Complete,
            ..Default::default()
        };
        std::fs::write(
            dir.join("artifacts.json"),
            serde_json::to_vec(&artifacts).unwrap(),
        )
        .unwrap();
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
                path: "/tmp/benign.sh".into(),
                sample: Some(antinomie_monitor_core::samples::SampleRef {
                    sha256: added.sha256.clone(),
                    name: "benign.sh".into(),
                }),
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
        Self {
            root,
            sha256: added.sha256,
        }
    }

    fn data(&self) -> String {
        self.root.join("data").display().to_string()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A daemon over the fixture's data directory with a scripted engine.
struct Running {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Exit>>,
    service: Arc<antinomie_service::daemon::service::Service>,
}

impl Running {
    fn start(fixture: &Fixture) -> Self {
        let data = fixture.root.join("data");
        let mut engine = FakeEngine::new(Arc::new(ManualClock::new(1_800_000_000_000)));
        engine.start_with(|snapshot| {
            snapshot.vms = vec![VmConfig {
                id: "vm-1".into(),
                name: "Analysis".into(),
                base_identity: Some("base-sha".into()),
                ..VmConfig::default()
            }];
            snapshot.bases = vec![BaseSummary {
                id: "base-sha".into(),
                label: "BusyBox r21".into(),
                directory: "/never/shown".into(),
                guest: None,
                min_ram_mib: 128,
                min_disk_gib: 1,
                fixed_display: false,
                arch: GuestArch::default(),
                size_bytes: 1 << 20,
                revision: Some(21),
                min_app_version: None,
                built_with: None,
                stealth_support: Vec::new(),
            }];
        });
        let options = BackendOptions {
            data_dir: data.clone(),
            ..BackendOptions::default()
        };
        let setup = Setup {
            options,
            config: ServiceConfig::default(),
            socket: Some(data.join("run").join("antinomie.sock")),
            owner: antinomie_service::api::status::Owner::Daemon,
            host_grace: Duration::from_secs(5),
            limits: Limits::default(),
            log: Arc::new(|_| {}),
        };
        let mut daemon = Daemon::start(setup, engine).expect("the daemon starts");
        let service = Arc::clone(daemon.service());
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let exit = daemon.supervise(&NoSignals, &|_| flag.load(Ordering::SeqCst));
            let _ = daemon.finish();
            exit
        });
        Self {
            stop,
            thread: Some(thread),
            service,
        }
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}

fn args<'a>(data: &'a str, tail: &[&'a str]) -> Vec<&'a str> {
    let mut all = vec!["-o", "json", "--data-dir", data];
    all.extend_from_slice(tail);
    all
}

/// The same command through the daemon and in this process.
fn both(data: &str, tail: &[&str]) -> ((i32, Value), (i32, Value)) {
    let mut through = vec!["--daemon"];
    through.extend_from_slice(tail);
    let mut direct = vec!["--direct"];
    direct.extend_from_slice(tail);
    (cli(&args(data, &through)), cli(&args(data, &direct)))
}

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(base).unwrap().display().to_string(),
                    std::fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    if root.is_dir() {
        walk(root, root, &mut out);
    }
    out
}

#[test]
fn the_run_reads_and_triage_go_through_the_daemon_and_match_direct_mode() {
    let fixture = Fixture::new("runs");
    let data = fixture.data();
    let mut daemon = Running::start(&fixture);
    for tail in [
        vec!["run", "list"],
        vec!["run", "list", "--vm", "vm-1", "--state", "finished"],
        vec!["run", "show", "5f3c9a10"],
        vec![
            "run",
            "show",
            "vm-1:boot-1:5f3c9a10-run-fixture",
            "--summary",
        ],
        vec!["triage", "5f3c9a10"],
    ] {
        let (through, direct) = both(&data, &tail);
        assert_eq!(through.0, 0, "{tail:?}: {}", through.1);
        assert_eq!(direct.0, 0, "{tail:?}: {}", direct.1);
        assert_eq!(through.1["result"], direct.1["result"], "{tail:?}");
    }
    // The scan of the Triage reads lives in the daemon, not in the command.
    assert!(daemon.service.query.scans_in_memory() >= 1);
    // Unknown runs and a run folder are told the same way.
    let (through, direct) = both(&data, &["run", "show", "ffffffff"]);
    assert_eq!((through.0, direct.0), (3, 3));
    assert_eq!(through.1["error"]["code"], "not_found");
    let (through, direct) = both(&data, &["run", "show", "ab"]);
    assert_eq!((through.0, direct.0), (3, 3), "{}", through.1);
    daemon.stop();
    // Stopped: --daemon fails, the default falls back to direct mode.
    let (code, value) = cli(&args(&data, &["--daemon", "run", "list"]));
    assert_eq!(code, 21, "{value}");
    let (code, value) = cli(&args(&data, &["run", "list"]));
    assert_eq!(code, 0, "{value}");
}

#[test]
fn run_export_through_the_daemon_writes_the_same_files_and_only_into_out() {
    let fixture = Fixture::new("export");
    let data = fixture.data();
    let _daemon = Running::start(&fixture);
    let through = fixture.root.join("through");
    let direct = fixture.root.join("direct");
    let (code, value) = cli(&args(
        &data,
        &[
            "--daemon",
            "run",
            "export",
            "5f3c9a10",
            "--out",
            through.to_str().unwrap(),
        ],
    ));
    assert_eq!(code, 0, "{value}");
    let (code, value) = cli(&args(
        &data,
        &[
            "--direct",
            "run",
            "export",
            "5f3c9a10",
            "--out",
            direct.to_str().unwrap(),
        ],
    ));
    assert_eq!(code, 0, "{value}");
    let (a, b) = (tree(&through), tree(&direct));
    assert!(a.contains_key("findings.ndjson") && a.contains_key("processes.ndjson"));
    assert_eq!(a, b, "the same files with the same rows");

    // --no-triage leaves the five Triage parts out, here and there.
    let lean = fixture.root.join("lean");
    let (code, value) = cli(&args(
        &data,
        &[
            "--daemon",
            "run",
            "export",
            "5f3c9a10",
            "--no-triage",
            "--out",
            lean.to_str().unwrap(),
        ],
    ));
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["result"]["triage"], false);
    let lean_tree = tree(&lean);
    assert!(lean_tree.contains_key("trace.ndjson") && lean_tree.contains_key("processes.ndjson"));
    for skipped in ["findings", "indicators", "timeline"] {
        assert!(
            !lean_tree.contains_key(&format!("{skipped}.ndjson")),
            "{skipped} was written"
        );
    }
    assert!(
        !lean_tree
            .keys()
            .any(|k| k.starts_with("files-") || k.starts_with("network-"))
    );
    let (code, value) = cli(&args(
        &data,
        &[
            "run",
            "export",
            "5f3c9a10",
            "--no-triage",
            "--part",
            "findings",
            "--out",
            lean.to_str().unwrap(),
        ],
    ));
    assert_eq!(code, 4, "{value}");
    assert_eq!(value["error"]["field"], "part");

    // A part outside the ten, and an --out that is a file, are refused.
    let (code, _) = cli(&args(
        &data,
        &[
            "run",
            "export",
            "5f3c9a10",
            "--part",
            "../../etc",
            "--out",
            through.to_str().unwrap(),
        ],
    ));
    assert_eq!(code, 4);
    let file = fixture.root.join("afile");
    std::fs::write(&file, b"x").unwrap();
    let (code, _) = cli(&args(
        &data,
        &["run", "export", "5f3c9a10", "--out", file.to_str().unwrap()],
    ));
    assert_eq!(code, 4);
}

#[test]
fn the_library_and_custody_reads_go_through_the_daemon() {
    let fixture = Fixture::new("library");
    let data = fixture.data();
    let _daemon = Running::start(&fixture);
    let sha = fixture.sha256.clone();
    for tail in [
        vec!["sample", "list"],
        vec!["sample", "list", "--q", "BENIGN", "--limit", "1"],
        vec!["sample", "list", "--custody"],
        vec!["sample", "show", sha.as_str()],
        vec![
            "sample",
            "show",
            sha.as_str(),
            "--origins",
            "--events",
            "--runs",
        ],
        vec!["custody", "verify"],
        vec!["custody", "verify", sha.as_str()],
    ] {
        let (through, direct) = both(&data, &tail);
        assert_eq!(through.0, 0, "{tail:?}: {}", through.1);
        assert_eq!(direct.0, 0, "{tail:?}: {}", direct.1);
        assert_eq!(through.1["result"], direct.1["result"], "{tail:?}");
    }
    // A tag set through the daemon is the library's, and its custody entry
    // names the socket's caller.
    let (code, tagged) = cli(&args(
        &data,
        &[
            "--daemon",
            "sample",
            "tag",
            sha.as_str(),
            "verdict=benign",
            "lab",
        ],
    ));
    assert_eq!(code, 0, "{tagged}");
    assert_eq!(tagged["result"]["tags"].as_array().unwrap().len(), 2);
    let (_, shown) = cli(&args(
        &data,
        &["--direct", "sample", "show", sha.as_str(), "--events"],
    ));
    let uid = antinomie_service::server::own_uid();
    assert!(
        shown["result"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["by"] == format!("local:{uid}")),
        "{shown}"
    );
    let (code, removed) = cli(&args(
        &data,
        &["--daemon", "sample", "tag", sha.as_str(), "lab", "--remove"],
    ));
    assert_eq!(code, 0, "{removed}");
    assert_eq!(removed["result"]["tags"].as_array().unwrap().len(), 1);
    // Errors keep their codes.
    let (code, value) = cli(&args(
        &data,
        &["--daemon", "sample", "show", &"0".repeat(64)],
    ));
    assert_eq!(code, 3, "{value}");
    let (code, value) = cli(&args(
        &data,
        &["--daemon", "sample", "tag", sha.as_str(), "verdict=great"],
    ));
    assert_eq!(code, 4, "{value}");
    let (code, value) = cli(&args(
        &data,
        &["--daemon", "sample", "list", "--cursor", "junk"],
    ));
    assert_eq!(code, 4, "{value}");
}

#[test]
fn vms_and_bases_are_listed_by_the_daemon_that_owns_the_engine() {
    let fixture = Fixture::new("vmbase");
    let data = fixture.data();
    let mut daemon = Running::start(&fixture);
    let (code, vms) = cli(&args(&data, &["vm", "list"]));
    assert_eq!(code, 0, "{vms}");
    assert_eq!(vms["result"]["items"][0]["id"], "vm-1");
    assert_eq!(vms["result"]["items"][0]["base_identity"], "base-sha");
    let (code, bases) = cli(&args(&data, &["base", "list"]));
    assert_eq!(code, 0, "{bases}");
    assert_eq!(bases["result"]["items"][0]["identity"], "base-sha");
    assert!(!bases.to_string().contains("/never/shown"));
    // A command that changes a VM still needs the lock and is not sent.
    let (code, value) = cli(&args(&data, &["--daemon", "vm", "stop", "vm-1"]));
    assert_eq!(code, 1, "{value}");
    assert_eq!(value["error"]["code"], "unsupported");
    daemon.stop();
}
