// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
use antinomie_monitor_core::{
    Backend, BackendOptions, CaptureState, CaptureSummary, Command, EventSummary, ExecRequest,
    GuestProcess, Notification, RunSummary, Snapshot, VmConfig, capture, parser,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    thread,
    time::{Duration, Instant},
};

struct Harness {
    backend: Backend,
    snapshot: Snapshot,
    results: BTreeMap<u64, Result<String, String>>,
    output: BTreeMap<String, Vec<u8>>,
}

impl Harness {
    fn receive(&mut self) -> Result<(), String> {
        while let Some(notification) = self.backend.try_recv() {
            match notification {
                Notification::Snapshot(snapshot) => {
                    check_unique(&snapshot.events)?;
                    if snapshot.capture_events.len() > 1
                        || snapshot
                            .capture_events
                            .values()
                            .map(Vec::len)
                            .sum::<usize>()
                            > 2048
                    {
                        return Err("observer preview exceeds frozen API bounds".into());
                    }
                    self.snapshot = snapshot;
                }
                Notification::RunStarted(run) => {
                    if !self.snapshot.runs.iter().any(|old| old.id == run.id) {
                        self.snapshot.runs.push(run);
                    }
                }
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.results
                        .insert(id, if success { Ok(message) } else { Err(message) });
                }
                Notification::Terminal { run_id, data, .. } => {
                    let output = self.output.entry(run_id).or_default();
                    if output.len().saturating_add(data.len()) > 1024 * 1024 {
                        return Err("probe terminal exceeded 1 MiB".into());
                    }
                    output.extend(data);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn wait(
        &mut self,
        seconds: u64,
        mut predicate: impl FnMut(&Self) -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive()?;
            if predicate(self) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "deadline: state {:?}, last error {:?}",
                    self.snapshot.state, self.snapshot.last_error
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn command(&mut self, command: Command) -> Result<(), String> {
        let id = self.backend.send(command)?;
        self.wait(60, |test| test.results.contains_key(&id))?;
        self.results.remove(&id).ok_or("missing command result")??;
        Ok(())
    }

    fn reject(&mut self, command: Command, reason: &str) -> Result<(), String> {
        match self.command(command) {
            Err(error) if error.contains(reason) => Ok(()),
            Err(error) => Err(format!("wrong rejection, expected {reason}: {error}")),
            Ok(()) => Err(format!("command accepted instead of rejecting {reason}")),
        }
    }

    fn launch(&mut self, args: Vec<String>) -> Result<String, String> {
        let before: BTreeSet<_> = self
            .snapshot
            .runs
            .iter()
            .map(|run| run.id.clone())
            .collect();
        self.command(Command::Execute(ExecRequest {
            path: "/tmp/observation-probe".into(),
            args,
            uid: 1000,
            gid: 1000,
            ..ExecRequest::default()
        }))?;
        self.wait(10, |test| {
            test.snapshot
                .runs
                .iter()
                .any(|run| !before.contains(&run.id))
        })?;
        self.snapshot
            .runs
            .iter()
            .find(|run| !before.contains(&run.id))
            .map(|run| run.id.clone())
            .ok_or("missing launched run".into())
    }

    fn run(&self, id: &str) -> Result<&RunSummary, String> {
        self.snapshot
            .runs
            .iter()
            .find(|run| run.id == id)
            .ok_or("missing run".into())
    }

    fn marker_count(&self, run: &str, marker: &str) -> usize {
        self.output.get(run).map_or(0, |data| {
            String::from_utf8_lossy(data).matches(marker).count()
        })
    }

    fn marker(&mut self, run: &str, marker: &str) -> Result<(), String> {
        self.wait(20, |test| test.marker_count(run, marker) != 0)
    }

    fn value(&self, run: &str, marker: &str, key: &str) -> Result<u64, String> {
        let output = self.output.get(run).ok_or("missing probe output")?;
        let text = String::from_utf8_lossy(output);
        text.lines()
            .rev()
            .find(|line| line.contains(marker))
            .and_then(|line| {
                line.split_whitespace().find_map(|word| {
                    word.strip_prefix(&format!("{key}="))
                        .and_then(|value| value.parse().ok())
                })
            })
            .ok_or_else(|| format!("missing {key} in {marker}"))
    }

    fn input(&mut self, run: &str, byte: u8) -> Result<(), String> {
        let marker = format!("value={byte}");
        let before = self.marker_count(run, &marker);
        self.command(Command::TerminalInput {
            run_id: run.into(),
            data: vec![byte, b'\n'],
        })?;
        self.wait(20, |test| test.marker_count(run, &marker) > before)
    }

    fn process(&mut self, pid: u32) -> Result<GuestProcess, String> {
        let mut after_pid = 0;
        for _ in 0..64 {
            self.command(Command::ListProcesses { after_pid })?;
            let page = self
                .snapshot
                .process_page
                .as_ref()
                .ok_or("missing process page")?;
            if let Some(process) = page
                .processes
                .iter()
                .find(|process| process.identity.tgid == pid)
            {
                return Ok(process.clone());
            }
            if page.next_pid == 0 || page.next_pid <= after_pid {
                break;
            }
            after_pid = page.next_pid;
        }
        Err(format!("PID {pid} not found in bounded process listing"))
    }

    fn active_capture(&mut self) -> Result<CaptureSummary, String> {
        self.wait(10, |test| {
            test.snapshot
                .captures
                .iter()
                .any(|capture| capture.state == CaptureState::Active)
        })?;
        self.snapshot
            .captures
            .iter()
            .find(|capture| capture.state == CaptureState::Active)
            .cloned()
            .ok_or("missing active capture".into())
    }
}

fn check_unique(events: &[EventSummary]) -> Result<(), String> {
    let mut identities = BTreeSet::new();
    for event in events {
        if !identities.insert((
            event.stream_id,
            event.task_cookie,
            event.call_id,
            event.event_seq,
            event.phase,
        )) {
            return Err("canonical history duplicates a launched/observer event".into());
        }
    }
    Ok(())
}

fn headers(directory: &Path) -> Result<Vec<parser::Header>, String> {
    let path = directory.join("telemetry.raw");
    if fs::metadata(&path)
        .map_err(|error| error.to_string())?
        .len()
        > 128 * 1024 * 1024
    {
        return Err("probe raw archive exceeds 128 MiB".into());
    }
    let raw = fs::read(path).map_err(|error| error.to_string())?;
    let mut offset = 0;
    let mut headers = Vec::new();
    while offset < raw.len() {
        let prefix = raw.get(offset..offset + 4).ok_or("truncated raw length")?;
        let len = u32::from_le_bytes(prefix.try_into().map_err(|_| "invalid raw length")?) as usize;
        offset += 4;
        if len > 1024 * 1024 {
            return Err("unbounded raw packet length".into());
        }
        let packet = raw
            .get(offset..offset + len)
            .ok_or("truncated raw packet")?;
        headers.push(
            parser::parse_packet(packet)
                .map_err(|error| error.to_string())?
                .0,
        );
        offset += len;
    }
    Ok(headers)
}

fn reject_changed_archive_identity(directory: &Path) -> Result<(), String> {
    let path = directory.join("capture.json");
    let original = fs::read(&path).map_err(|error| error.to_string())?;
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&original).map_err(|error| error.to_string())?;
    metadata["boot_id"] = serde_json::Value::String("deliberately-wrong-test-boot".into());
    fs::write(
        &path,
        serde_json::to_vec(&metadata).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let rejected =
        capture::open_capture_recording_cancellable(directory, &AtomicBool::new(false)).is_err();
    fs::write(path, original).map_err(|error| error.to_string())?;
    if !rejected {
        return Err("archive reader accepted mismatched capture metadata".into());
    }
    Ok(())
}

fn exercise(test: &mut Harness, options: &BackendOptions, probe: PathBuf) -> Result<(), String> {
    test.command(Command::Create(VmConfig {
        name: "Observation QA".into(),
        cpus: 4,
        ram_mib: 1024,
        disk_gib: 1,
        ..VmConfig::default()
    }))?;
    test.wait(10, |test| !test.snapshot.vms.is_empty())?;
    let vm_id = test.snapshot.vms[0].id.clone();
    test.command(Command::Start {
        vm_id: vm_id.clone(),
    })?;
    test.wait(60, |test| {
        test.snapshot
            .serial_log
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .is_some_and(|data| {
                data.windows(b"BusyBox guest ready".len())
                    .any(|part| part == b"BusyBox guest ready")
            })
    })?;
    test.wait(20, |test| {
        test.snapshot
            .guest_kernel
            .as_ref()
            .is_some_and(|kernel| kernel.revision.is_some_and(|revision| revision >= 11))
    })?;
    test.command(Command::Upload {
        source: probe,
        destination: "/tmp/observation-probe".into(),
        overwrite: false,
        executable: true,
    })?;
    let run_id = test.launch(Vec::new())?;
    test.marker(&run_id, "OBS READY")?;
    let root_cookie = test.run(&run_id)?.root_task_cookie;
    let pid = test.run(&run_id)?.pid;
    let existing_pid = u32::try_from(test.value(&run_id, "OBS READY", "value")?)
        .map_err(|error| error.to_string())?;
    let output = String::from_utf8_lossy(test.output.get(&run_id).ok_or("missing probe output")?);
    let current_threads: BTreeSet<u32> = output
        .lines()
        .filter(|line| line.contains("OBS THREAD pid="))
        .filter_map(|line| {
            line.split_whitespace().find_map(|word| {
                word.strip_prefix("tid=")
                    .and_then(|value| value.parse().ok())
            })
        })
        .collect();
    if current_threads.len() != 2 {
        return Err("probe did not report both preexisting thread identities".into());
    }
    let process = test.process(pid)?;
    if process.thread_count < 3 {
        return Err("probe's current threads are absent from process listing".into());
    }
    let mut stale = process.identity.clone();
    stale.boot_id.push_str("-stale");
    test.reject(
        Command::AttachProcess { identity: stale },
        "different VM boot",
    )?;
    let mut stale = process.identity.clone();
    stale.task_cookie = stale.task_cookie.wrapping_add(1);
    test.reject(
        Command::AttachProcess { identity: stale },
        "No such process",
    )?;
    let mut stale = process.identity.clone();
    stale.start_boot_ns = stale.start_boot_ns.wrapping_add(1);
    test.reject(
        Command::AttachProcess { identity: stale },
        "No such process",
    )?;
    test.command(Command::AttachProcess {
        identity: process.identity,
    })?;
    let attached = test.active_capture()?;
    test.reject(Command::CaptureAll, "stop the active capture")?;
    test.input(&run_id, b't')?;
    test.wait(20, |test| {
        test.marker_count(&run_id, "OBS THREAD-PULSE") >= 2
    })?;
    test.input(&run_id, b'e')?;
    test.marker(&run_id, "OBS EXISTING")?;
    test.input(&run_id, b'f')?;
    test.marker(&run_id, "OBS FUTURE")?;
    let future_pid = u32::try_from(test.value(&run_id, "OBS FUTURE", "pid")?)
        .map_err(|error| error.to_string())?;
    test.input(&run_id, b'b')?;
    test.marker(&run_id, "OBS BLOCK")?;
    let block_tid = u32::try_from(test.value(&run_id, "OBS BLOCK", "tid")?)
        .map_err(|error| error.to_string())?;
    let gate_fd = test.value(&run_id, "OBS BLOCK", "value")?;
    test.wait(20, |test| {
        test.snapshot
            .capture_events
            .get(&attached.id)
            .is_some_and(|events| {
                events.iter().any(|event| {
                    event.phase == 1
                        && event.syscall_nr == 0
                        && event.tid == block_tid
                        && event.args.is_some_and(|args| args[0] == gate_fd)
                })
            })
    })?;
    let blocked = test
        .snapshot
        .capture_events
        .get(&attached.id)
        .and_then(|events| {
            events.iter().find(|event| {
                event.phase == 1
                    && event.syscall_nr == 0
                    && event.tid == block_tid
                    && event.args.is_some_and(|args| args[0] == gate_fd)
            })
        })
        .map(|event| (event.task_cookie, event.call_id))
        .ok_or("missing admitted blocked read")?;
    test.command(Command::StopCapture {
        capture_id: attached.id.clone(),
    })?;
    test.command(Command::StopCapture {
        capture_id: attached.id.clone(),
    })?;
    test.input(&run_id, b'e')?;
    test.command(Command::CaptureAll)?;
    let global = test.active_capture()?;
    if attached.capture_cookie == global.capture_cookie {
        return Err("new observer reused stopped observer ID".into());
    }
    test.command(Command::ListProcesses { after_pid: 0 })?;
    let console_pid = test
        .snapshot
        .process_page
        .as_ref()
        .and_then(|page| {
            page.processes.iter().find(|process| {
                process.parent_tgid == 1 && process.command == "sh" && process.identity.tgid != 1
            })
        })
        .map(|process| process.identity.tgid)
        .ok_or("disposable BusyBox guest has no init-owned console shell")?;
    // Only the disposable test guest's respawning console is interrupted.
    // Its init/getty activity has no monitor launch root and exercises global admission.
    test.command(Command::Execute(ExecRequest {
        path: "/bin/busybox".into(),
        args: vec!["kill".into(), "-HUP".into(), console_pid.to_string()],
        uid: 0,
        gid: 0,
        ..ExecRequest::default()
    }))?;
    test.wait(20, |test| {
        test.snapshot
            .capture_events
            .get(&global.id)
            .is_some_and(|events| events.iter().any(|event| event.root_task_cookie == 0))
    })?;
    test.input(&run_id, b'u')?;
    test.marker(&run_id, "OBS TAIL")?;
    let existing_before = test.marker_count(&run_id, "OBS EXISTING");
    test.input(&run_id, b'e')?;
    test.wait(20, |test| {
        test.marker_count(&run_id, "OBS EXISTING") > existing_before
    })?;
    let future_run = test.launch(vec!["--child".into()])?;
    test.marker(&future_run, "OBS FUTURE")?;
    let future_root = test.run(&future_run)?.root_task_cookie;
    test.command(Command::StopCapture {
        capture_id: global.id.clone(),
    })?;
    let pulses_before = test.marker_count(&run_id, "OBS THREAD-PULSE");
    test.input(&run_id, b't')?;
    test.wait(20, |test| {
        test.marker_count(&run_id, "OBS THREAD-PULSE") >= pulses_before + 2
    })?;
    test.command(Command::TerminalInput {
        run_id: run_id.clone(),
        data: b"q\n".to_vec(),
    })?;
    test.marker(&run_id, "OBS DONE")?;
    test.command(Command::RecorderStats)?;
    test.command(Command::Stop)?;

    let attach_raw = headers(&attached.directory)?;
    let global_raw = headers(&global.directory)?;
    for (raw, summary) in [(&attach_raw, &attached), (&global_raw, &global)] {
        if raw.is_empty()
            || raw
                .iter()
                .any(|header| header.capture_cookie != summary.capture_cookie)
        {
            return Err("observer raw routing contains missing or wrong capture identity".into());
        }
        let recording = capture::open_capture_recording_cancellable(
            &summary.directory,
            &AtomicBool::new(false),
        )
        .map_err(|error| error.to_string())?;
        if recording
            .manifest
            .get("complete")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        {
            return Err("observer archive falsely claims completeness".into());
        }
        if recording
            .invocation_page(0, 256)
            .map_err(|error| error.to_string())?
            .invocations
            .is_empty()
        {
            return Err("observer archive cannot reopen invocation history".into());
        }
        reject_changed_archive_identity(&summary.directory)?;
    }
    let thread_tids: BTreeSet<_> = attach_raw
        .iter()
        .filter(|header| header.root_task_cookie == root_cookie)
        .map(|header| header.tid)
        .collect();
    if !thread_tids.contains(&pid)
        || !current_threads.is_subset(&thread_tids)
        || !thread_tids.contains(&future_pid)
        || thread_tids.contains(&existing_pid)
    {
        return Err(format!(
            "attach thread/descendant boundary failed: {thread_tids:?}, existing {existing_pid}"
        ));
    }
    let old_tail = |header: &parser::Header| {
        header.task_cookie == blocked.0 && header.call_id == blocked.1 && header.phase == 2
    };
    if !attach_raw.iter().any(old_tail) || global_raw.iter().any(old_tail) {
        return Err("blocked read tail lost or reassigned after stop/new start".into());
    }
    if !global_raw.iter().any(|header| header.tid == existing_pid)
        || !global_raw
            .iter()
            .any(|header| header.root_task_cookie == future_root)
        || !global_raw.iter().any(|header| header.root_task_cookie == 0)
    {
        return Err("Capture All missed existing child or future launch".into());
    }
    let saved = capture::list_vm_captures(options, &vm_id)?;
    if saved
        .iter()
        .filter(|summary| summary.capture_cookie != 0)
        .count()
        != 2
        || saved
            .iter()
            .any(|summary| summary.state != CaptureState::Finalized)
    {
        return Err("observer history did not retain two finalized admitted captures and finalized rejected attempts".into());
    }
    if test.snapshot.health.storage_dropped_packets != 0
        || test.snapshot.health.persistence_error.is_some()
        || test.snapshot.health.parser_errors != 0
        || test.snapshot.health.dropped != 0
    {
        return Err(format!(
            "paced acceptance workload suffered loss: {:?}",
            test.snapshot.health
        ));
    }
    println!(
        "PASS four-vCPU current threads, future fork/exec, existing-child exclusion, stable identity rejection, busy guard"
    );
    println!(
        "PASS nonterminating idempotent stop, old blocked-call tail, Capture All existing/future origins, canonical uniqueness, archive reopening"
    );
    println!(
        "Capture All non-monitor-launched packets observed: {}; console respawn is confined to this disposable BusyBox guest",
        global_raw
            .iter()
            .filter(|header| header.root_task_cookie == 0)
            .count()
    );
    println!(
        "Archives: {} and {}",
        attached.directory.display(),
        global.directory.display()
    );
    Ok(())
}

fn main() {
    if let Some(code) = antinomie_monitor_core::analysis::worker_main_if_requested() {
        std::process::exit(code);
    }
    let result = (|| -> Result<(), String> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.len() != 3 {
            return Err(
                "usage: observation-check BUNDLE NEW_QA_DIR STATIC_PTHREAD_PROBE_ELF".into(),
            );
        }
        let root = PathBuf::from(&args[1]);
        if root.exists() {
            return Err("QA directory must not already exist".into());
        }
        fs::create_dir_all(&root).map_err(|error| error.to_string())?;
        let options = BackendOptions {
            data_dir: root.join("data"),
            bundle_dir: PathBuf::from(&args[0]),
            headless: true,
            force_tcg: true,
            capture_quota_size: 128 * 1024 * 1024,
            ..BackendOptions::default()
        };
        let mut test = Harness {
            backend: Backend::new(options.clone())?,
            snapshot: Snapshot::default(),
            results: BTreeMap::new(),
            output: BTreeMap::new(),
        };
        let result = exercise(&mut test, &options, PathBuf::from(&args[2]));
        // Attempt VM stop on every error path; shutdown joins the backend owner.
        let stop = if test.snapshot.active_vm.is_some() {
            test.command(Command::Stop)
        } else {
            Ok(())
        };
        let shutdown = test.backend.shutdown();
        result.and(stop).and(shutdown)
    })();
    if let Err(error) = result {
        eprintln!("FAIL: {error}");
        std::process::exit(1);
    }
}
