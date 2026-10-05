// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
use antinomie_monitor_core::{
    recording::{list_runs, open_recording},
    Backend, BackendOptions, Command, ExecRequest, Notification, RunSummary, Snapshot, VmConfig,
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

struct Harness {
    backend: Backend,
    snapshot: Snapshot,
    runs: BTreeMap<String, RunSummary>,
    output: BTreeMap<String, Vec<u8>>,
    results: BTreeMap<u64, Result<String, String>>,
}
impl Harness {
    fn receive(&mut self) -> Result<(), String> {
        while let Some(notification) = self.backend.try_recv() {
            match notification {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::RunStarted(run) => {
                    self.runs.insert(run.id.clone(), run);
                }
                Notification::Terminal { run_id, data, .. } => {
                    let output = self.output.entry(run_id).or_default();
                    if output.len() + data.len() > 1024 * 1024 {
                        return Err("test output exceeded bound".into());
                    }
                    output.extend(data);
                }
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.results
                        .insert(id, if success { Ok(message) } else { Err(message) });
                }
                Notification::TerminalScreen { .. } => {}
            }
        }
        Ok(())
    }
    fn command(&mut self, command: Command) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            self.receive()?;
            if let Some(result) = self.results.remove(&id) {
                return result;
            }
            if Instant::now() > deadline {
                return Err(format!("command {id} timed out"));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn output_until(&mut self, run_id: &str, marker: &[u8]) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            self.receive()?;
            if self
                .output
                .get(run_id)
                .is_some_and(|data| data.windows(marker.len()).any(|part| part == marker))
            {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "missing {} for {run_id}",
                    String::from_utf8_lossy(marker)
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn launch(&mut self, script: &str) -> Result<RunSummary, String> {
        let before = self.runs.len();
        self.command(Command::Execute(ExecRequest {
            args: vec!["-c".into(), script.into()],
            ..ExecRequest::default()
        }))?;
        self.receive()?;
        if self.runs.len() != before + 1 {
            return Err("launch did not publish one run".into());
        }
        self.runs
            .values()
            .find(|run| run.request.args.get(1).is_some_and(|value| value == script))
            .cloned()
            .ok_or_else(|| "missing run identity".into())
    }
    fn captured_write_until(&mut self, root: u64, marker: &[u8]) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            self.receive()?;
            if self.snapshot.events.iter().any(|event| {
                event.root_task_cookie == root
                    && event.phase == 1
                    && event.syscall_nr == 1
                    && event.fields.iter().any(|field| {
                        field
                            .preview
                            .windows(marker.len())
                            .any(|part| part == marker)
                    })
            }) {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err("detached descendant write was not captured".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: run-history-check BUNDLE NEW_DATA_DIR".into());
    }
    let root = PathBuf::from(&args[1]);
    let mut test = Harness {
        backend: Backend::new(BackendOptions {
            data_dir: root.clone(),
            bundle_dir: PathBuf::from(&args[0]),
            headless: true,
            ..BackendOptions::default()
        })?,
        snapshot: Snapshot::default(),
        runs: BTreeMap::new(),
        output: BTreeMap::new(),
        results: BTreeMap::new(),
    };
    test.command(Command::Create(VmConfig {
        name: "Run history QA".into(),
        cpus: 4,
        ram_mib: 1024,
        disk_gib: 1,
        ..VmConfig::default()
    }))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while test.snapshot.vms.is_empty() && Instant::now() < deadline {
        test.receive()?;
        thread::sleep(Duration::from_millis(10));
    }
    let vm_id = test
        .snapshot
        .vms
        .first()
        .ok_or("missing created VM")?
        .id
        .clone();
    test.command(Command::Start { vm_id })?;
    thread::sleep(Duration::from_secs(3));
    let first = test.launch("echo RUN-A; read line; echo INPUT-A:$line; sleep 30")?;
    let second = test.launch("echo RUN-B; read line; echo INPUT-B:$line; sleep 30")?;
    if first.root_task_cookie == second.root_task_cookie || first.session_id == second.session_id {
        return Err("concurrent launches reused identity".into());
    }
    test.output_until(&first.id, b"RUN-A")?;
    test.output_until(&second.id, b"RUN-B")?;
    test.backend.send(Command::TerminalResize {
        run_id: first.id.clone(),
        rows: 17,
        cols: 71,
    })?;
    test.backend.send(Command::TerminalResize {
        run_id: second.id.clone(),
        rows: 19,
        cols: 73,
    })?;
    test.command(Command::TerminalInput {
        run_id: first.id.clone(),
        data: b"alpha\n".to_vec(),
    })?;
    test.command(Command::TerminalInput {
        run_id: second.id.clone(),
        data: b"beta\n".to_vec(),
    })?;
    test.output_until(&first.id, b"INPUT-A:alpha")?;
    test.output_until(&second.id, b"INPUT-B:beta")?;
    let detached = test.launch("setsid /bin/sh -c 'sleep 1; echo DETACHED-C; sleep 30' </dev/null >/tmp/detached-c.log 2>&1 & sleep 0.2; echo ROOT-C; exit 0")?;
    test.output_until(&detached.id, b"ROOT-C")?;
    test.captured_write_until(detached.root_task_cookie, b"DETACHED-C")?;
    // No TerminalRead commands were issued: persistence must outlive a closed view.
    test.command(Command::StopRun {
        run_id: detached.id.clone(),
    })?;
    test.command(Command::StopRun {
        run_id: first.id.clone(),
    })?;
    test.command(Command::StopRun {
        run_id: second.id.clone(),
    })?;
    thread::sleep(Duration::from_millis(500));
    test.command(Command::RecorderStats)?;
    test.command(Command::Stop)?;
    test.receive()?;
    test.backend.shutdown()?;
    let saved = list_runs(&root).map_err(|error| error.to_string())?;
    if saved.len() != 3 {
        return Err(format!("expected three saved runs, got {}", saved.len()));
    }
    let mut total_rows = 0;
    for expected in [&first, &second, &detached] {
        let recording = open_recording(&expected.directory).map_err(|error| error.to_string())?;
        let mut offset = 0;
        let mut seen = std::collections::BTreeSet::new();
        let mut paired = 0;
        loop {
            let page = recording
                .invocation_page(offset, 7)
                .map_err(|error| error.to_string())?;
            for row in page.invocations {
                if !seen.insert((row.stream_id, row.task_cookie, row.call_id)) {
                    return Err("duplicate history row".into());
                }
                if row.entry.is_some() && row.exit.is_some() {
                    paired += 1;
                }
                for phase in [row.entry, row.exit].into_iter().flatten() {
                    if phase.root_task_cookie != expected.root_task_cookie {
                        return Err("cross-run telemetry contamination".into());
                    }
                }
            }
            match page.next_offset {
                Some(next) if next > offset => offset = next,
                None => break,
                _ => return Err("non-progressing history cursor".into()),
            }
        }
        if seen.is_empty() || paired == 0 {
            return Err("archive lost paired telemetry".into());
        }
        total_rows += seen.len();
        let mut terminal = Vec::new();
        let mut offset = 0;
        loop {
            let page = recording
                .terminal_replay(offset, 3)
                .map_err(|error| error.to_string())?;
            for record in page.records {
                if let antinomie_monitor_core::TerminalRecord::Output(data) = record {
                    terminal.extend(data);
                }
            }
            match page.next_offset {
                Some(next) if next > offset => offset = next,
                None => break,
                _ => return Err("non-progressing terminal cursor".into()),
            }
        }
        let marker = if expected.id == first.id {
            "INPUT-A:alpha"
        } else if expected.id == second.id {
            "INPUT-B:beta"
        } else {
            "ROOT-C"
        };
        if !terminal
            .windows(marker.len())
            .any(|part| part == marker.as_bytes())
        {
            return Err("terminal output not retained".into());
        }
        println!(
            "run={} root={} invocations={} paired={} terminal_len={}",
            expected.id,
            expected.root_task_cookie,
            seen.len(),
            paired,
            terminal.len()
        );
    }
    println!(
        "PASS: 4 CPUs; 3 concurrent/separate runs; detached child stop; {} paged invocations; automatic terminal retention",
        total_rows
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("FAIL: {error}");
        std::process::exit(1);
    }
}
