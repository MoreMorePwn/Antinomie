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
            persisted: None,
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
        Self::start_with(fixture, ServiceConfig::default())
    }

    fn start_with(fixture: &Fixture, config: ServiceConfig) -> Self {
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
            config,
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
        vec!["recording", "list"],
        vec!["recording", "list", "--vm", "vm-1", "--state", "finished"],
        vec!["recording", "show", "5f3c9a10"],
        vec![
            "recording",
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
    let (through, direct) = both(&data, &["recording", "show", "ffffffff"]);
    assert_eq!((through.0, direct.0), (3, 3));
    assert_eq!(through.1["error"]["code"], "not_found");
    let (through, direct) = both(&data, &["recording", "show", "ab"]);
    assert_eq!((through.0, direct.0), (3, 3), "{}", through.1);
    daemon.stop();
    // Stopped: --daemon fails, the default falls back to direct mode.
    let (code, value) = cli(&args(&data, &["--daemon", "recording", "list"]));
    assert_eq!(code, 21, "{value}");
    let (code, value) = cli(&args(&data, &["recording", "list"]));
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
            "recording",
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
            "recording",
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
            "recording",
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
            "recording",
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
            "recording",
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
        &[
            "recording",
            "export",
            "5f3c9a10",
            "--out",
            file.to_str().unwrap(),
        ],
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

/// The first item of a list reply.
fn items(value: &Value) -> Vec<Value> {
    value["result"]["items"]
        .as_array()
        .or(value["result"].as_array())
        .cloned()
        .unwrap_or_else(|| panic!("no items in {value}"))
}

#[test]
fn run_list_shows_the_job_of_a_run_and_job_filters_the_same_through_the_daemon_and_directly() {
    let fixture = Fixture::new("jobs");
    let data = fixture.data();
    let _daemon = Running::start(&fixture);
    // A job record that names the fixture's run, as the pipeline writes it
    // when the lane records the run (the job index reads `run_key`).
    let job = antinomie_service::api::ids::RunId::from_parts(5, [3; 10]).to_string();
    let key = antinomie_service::query::key::RecordingKey::new("vm-1", "boot-1", RUN).unwrap();
    let store = rusqlite::Connection::open(fixture.root.join("data/service/jobs.sqlite")).unwrap();
    store
        .execute(
            "INSERT INTO jobs(id, created_ms, state, priority, wait_s, policy_name, policy_digest,
                terms_json, max_attempts, client_id, spec_json, canon_json, run_key)
             VALUES (?1, 1, 'succeeded', 0, 0, 'default', 'd', '{}', 1, 'local:1', '{}', '{}', ?2)",
            rusqlite::params![job, key.as_str()],
        )
        .unwrap();
    drop(store);

    for tail in [
        vec!["recording", "list"],
        vec!["recording", "list", "--run", job.as_str()],
        vec!["recording", "show", "5f3c9a10"],
    ] {
        let (through, direct) = both(&data, &tail);
        assert_eq!(through.0, 0, "{tail:?}: {}", through.1);
        assert_eq!(direct.0, 0, "{tail:?}: {}", direct.1);
        assert_eq!(through.1["result"], direct.1["result"], "{tail:?}");
    }
    let (_, listed) = cli(&args(&data, &["--direct", "recording", "list"]));
    assert_eq!(items(&listed)[0]["from_run"], job.as_str());
    let (_, filtered) = cli(&args(
        &data,
        &["--direct", "recording", "list", "--run", &job],
    ));
    assert_eq!(items(&filtered).len(), 1);
    let none = "j_00000000000000000000000000";
    let (_, filtered) = cli(&args(
        &data,
        &["--direct", "recording", "list", "--run", none],
    ));
    assert!(items(&filtered).is_empty());
}

#[test]
fn sample_add_goes_through_the_daemon_as_an_upload_then_sample_add() {
    use sha2::{Digest, Sha256};
    let fixture = Fixture::new("add");
    let data = fixture.data();
    let _daemon = Running::start(&fixture);
    let file = fixture.root.join("second.sh");
    let content = b"#!/bin/sh\necho second\n";
    std::fs::write(&file, content).unwrap();
    let sha: String = Sha256::digest(content)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let path = file.to_str().unwrap();

    let (code, added) = cli(&args(
        &data,
        &[
            "--daemon",
            "sample",
            "add",
            path,
            "--name",
            "two.sh",
            "--tag",
            "verdict=benign",
        ],
    ));
    assert_eq!(code, 0, "{added}");
    let item = &items(&added)[0];
    assert_eq!(item["ok"], true);
    assert_eq!(item["new"], true);
    assert_eq!(item["sha256"], sha.as_str());
    assert_eq!(item["name"], "two.sh");
    assert_eq!(item["size"], content.len());
    assert!(
        file.exists(),
        "the original stays without --delete-original"
    );
    // The same file again, direct and through the daemon, is already there,
    // with the same item.
    let (code, again) = cli(&args(
        &data,
        &["--direct", "sample", "add", path, "--name", "two.sh"],
    ));
    assert_eq!(code, 0, "{again}");
    assert_eq!(items(&again)[0]["new"], false);
    let (code, third) = cli(&args(
        &data,
        &["--daemon", "sample", "add", path, "--name", "two.sh"],
    ));
    assert_eq!(code, 0, "{third}");
    assert_eq!(items(&third)[0], items(&again)[0]);
    // The library has the tag, and the custody entry names the socket's caller.
    let (_, shown) = cli(&args(
        &data,
        &["--direct", "sample", "show", &sha, "--events"],
    ));
    assert_eq!(shown["result"]["tags"][0]["value"], "benign");
    let uid = antinomie_service::server::own_uid();
    assert!(
        shown["result"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["by"] == format!("local:{uid}")),
        "{shown}"
    );
    // --delete-original removes the file after the daemon reported the hash.
    let doomed = fixture.root.join("doomed.sh");
    std::fs::write(&doomed, b"#!/bin/sh\necho doomed\n").unwrap();
    let (code, value) = cli(&args(
        &data,
        &[
            "--daemon",
            "sample",
            "add",
            doomed.to_str().unwrap(),
            "--delete-original",
        ],
    ));
    assert_eq!(code, 0, "{value}");
    assert!(!doomed.exists());
    // A missing file fails that file only, with its code.
    let missing = fixture.root.join("missing.sh");
    let (code, value) = cli(&args(
        &data,
        &["--daemon", "sample", "add", path, missing.to_str().unwrap()],
    ));
    assert_ne!(code, 0, "{value}");
    assert_eq!(value["error"]["details"]["items"][0]["ok"], true);
    assert_eq!(value["error"]["details"]["items"][1]["ok"], false);
}

#[test]
fn run_export_with_sensitive_writes_the_recorded_packet_frames_the_same_both_ways() {
    if Command::new("tshark").arg("--version").output().is_err()
        || Command::new("bwrap").arg("--version").output().is_err()
    {
        eprintln!("skipped: tshark and bwrap are needed for the packet reads");
        return;
    }
    let fixture = Fixture::new("packets");
    let data = fixture.data();
    let _daemon = Running::start(&fixture);
    let through = fixture.root.join("through");
    let direct = fixture.root.join("direct");
    let plain = fixture.root.join("plain");
    for (mode, out, sensitive) in [
        ("--daemon", &through, true),
        ("--direct", &direct, true),
        ("--daemon", &plain, false),
    ] {
        let mut tail = vec![
            mode,
            "recording",
            "export",
            "5f3c9a10",
            "--part",
            "trace,network",
        ];
        if sensitive {
            tail.push("--sensitive");
        }
        tail.extend(["--out", out.to_str().unwrap()]);
        let (code, value) = cli(&args(&data, &tail));
        assert_eq!(code, 0, "{mode}: {value}");
    }
    let (a, b) = (tree(&through), tree(&direct));
    assert_eq!(a, b, "the same files both ways");
    let frames: Vec<&String> = a
        .keys()
        .filter(|k| k.starts_with("network-packets-"))
        .collect();
    assert_eq!(frames.len(), 1, "{:?}", a.keys());
    let text = String::from_utf8_lossy(&a[frames[0]]);
    let first: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert!(first["n"].is_number() && first["frame_len"].as_u64().unwrap() > 0);
    assert!(!first["bytes_b64"].as_str().unwrap().is_empty());
    // Without --sensitive, no frame and no captured byte is written.
    assert!(
        tree(&plain)
            .keys()
            .all(|k| !k.starts_with("network-packets-") && !k.starts_with("captured"))
    );
}

#[test]
fn service_toml_query_and_privacy_reach_the_running_daemon() {
    use antinomie_monitor_core::settings::AddressLookup;
    use std::time::Duration;
    let fixture = Fixture::new("conf");
    let (config, problems) = antinomie_service::config::validate::parse_service(
        "service.toml",
        "[query]\nlight_concurrency = 3\nheavy_concurrency = 1\nlight_timeout_s = 7\nheavy_timeout_s = 9\n[privacy]\naddress_lookup = \"off\"\n",
    );
    assert!(problems.is_empty(), "{problems:?}");
    let mut daemon = Running::start_with(&fixture, config.unwrap());
    let settings = daemon.service.query.settings();
    assert_eq!(settings.limits.light_concurrency, 3);
    assert_eq!(settings.limits.heavy_concurrency, 1);
    assert_eq!(settings.light_timeout, Duration::from_secs(7));
    assert_eq!(settings.heavy_timeout, Duration::from_secs(9));
    assert_eq!(settings.address_lookup, AddressLookup::Off);
    daemon.stop();
}

/// The fixture's run copied into lane 2's data folder (`<data>/lanes/2/`,
/// with its lane record) as run `run_id` of VM `vm-2`, as lane-2 records it.
fn lane_run(fixture: &Fixture, run_id: &str) -> PathBuf {
    let data = fixture.root.join("data");
    let lane = data.join("lanes").join("2");
    let from = data.join("vm-1").join("runs").join(RUN);
    let dir = lane.join("vm-2").join("runs").join(run_id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(lane.join("lane.json"), br#"{"schema":1,"lane":2}"#).unwrap();
    for name in ["telemetry.raw", "network.pcap"] {
        std::fs::copy(from.join(name), dir.join(name)).unwrap();
    }
    let mut artifacts: Value =
        serde_json::from_slice(&std::fs::read(from.join("artifacts.json")).unwrap()).unwrap();
    artifacts["run_id"] = run_id.into();
    artifacts["vm_id"] = "vm-2".into();
    artifacts["network_captures"] = serde_json::json!([dir.join("network.pcap")]);
    std::fs::write(
        dir.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    let mut run: Value =
        serde_json::from_slice(&std::fs::read(from.join("run.json")).unwrap()).unwrap();
    run["id"] = run_id.into();
    run["vm_id"] = "vm-2".into();
    run["started_ms"] = 1_792_000_100_000u64.into();
    run["directory"] = dir.display().to_string().into();
    std::fs::write(dir.join("run.json"), serde_json::to_vec(&run).unwrap()).unwrap();
    dir
}

#[test]
fn a_run_lane_2_recorded_is_read_from_lane_1_through_the_daemon_and_directly() {
    // ANT-T0455 card D: show, triage, report and the sample's runs find a run
    // in `<data>/lanes/2/`, the same both ways, and the run stays there.
    let fixture = Fixture::new("lanes");
    let data = fixture.data();
    let lane_run_id = "9d4e1b22-lane-two-run";
    let dir = lane_run(&fixture, lane_run_id);
    let _daemon = Running::start(&fixture);
    let (_, listed) = cli(&args(&data, &["--direct", "recording", "list"]));
    let ids: Vec<String> = items(&listed)
        .iter()
        .map(|i| i["run_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, [lane_run_id, RUN], "newest first, both lanes");
    for tail in [
        vec!["recording", "list"],
        vec!["recording", "list", "--vm", "vm-2"],
        vec!["recording", "show", "9d4e1b22"],
        vec![
            "recording",
            "show",
            "vm-2:boot-1:9d4e1b22-lane-two-run",
            "--summary",
        ],
        vec!["triage", "9d4e1b22"],
        vec!["sample", "show", fixture.sha256.as_str(), "--runs"],
    ] {
        let (through, direct) = both(&data, &tail);
        assert_eq!(through.0, 0, "{tail:?}: {}", through.1);
        assert_eq!(direct.0, 0, "{tail:?}: {}", direct.1);
        assert_eq!(through.1["result"], direct.1["result"], "{tail:?}");
    }
    let (_, shown) = cli(&args(&data, &["--direct", "recording", "show", "9d4e1b22"]));
    assert_eq!(shown["result"]["vm_id"], "vm-2", "{shown}");
    let (_, sample) = cli(&args(
        &data,
        &[
            "--direct",
            "sample",
            "show",
            fixture.sha256.as_str(),
            "--runs",
        ],
    ));
    let runs = sample["result"]["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 2, "{sample}");
    // The run's folder given by path is found too.
    let path = dir.display().to_string();
    let (code, value) = cli(&args(&data, &["--direct", "recording", "show", &path]));
    assert_eq!(code, 0, "{value}");
    // The report of the lane's run is written and names its run.
    let out = fixture.root.join("report-lane");
    let out_text = out.display().to_string();
    let (code, value) = cli(&args(
        &data,
        &[
            "report",
            "9d4e1b22",
            "--formats",
            "json",
            "--out",
            &out_text,
        ],
    ));
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["result"]["run"]["run_id"], lane_run_id, "{value}");
    assert_eq!(value["result"]["run"]["vm_id"], "vm-2");
    // Nothing moved: the run is still in lane 2's folder only.
    assert!(dir.join("run.json").is_file());
    assert!(!fixture.root.join("data/vm-2").exists());
}
