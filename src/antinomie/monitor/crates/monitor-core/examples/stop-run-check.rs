// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM check of how a run ends without a program exit: Stop run on a run
//! whose root exited and whose child lives on, a VM stop over the same run,
//! and the dump trigger against processes that exit within milliseconds.
//!
//!   stop-run-check BUNDLE NEW_DATA_DIR [trigger|stop|vmstop...]
//!
//! One BusyBox Routed VM (Drop route, run network capture). Every program is a
//! benign `sh -c` script. The `trigger` case registers a small judge of its
//! own (a call that names a file under /etc/cron.d) in place of the app's
//! Triage rules and writes the host-side timing of each step to the table.
//! The data folder must be new and disposable.
use antinomie_monitor_core::dump_trigger::{DumpTrigger, LiveFinding, LiveJudge, TriggerTier};
use antinomie_monitor_core::route::RouteKind;
use antinomie_monitor_core::stealth::{CLOUDS, StealthProfile};
use antinomie_monitor_core::*;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

/// When the test judge matched, host clock.
static MATCHED: Mutex<Vec<(Instant, u128)>> = Mutex::new(Vec::new());

struct CronJudge;
impl LiveJudge for CronJudge {
    fn judge(&mut self, call: &InvocationSummary) -> Vec<LiveFinding> {
        let Some(event) = call.entry.as_ref().or(call.exit.as_ref()) else {
            return Vec::new();
        };
        let hit = event
            .fields
            .iter()
            .any(|field| String::from_utf8_lossy(&field.preview).contains("/etc/cron.d/"));
        if !hit {
            return Vec::new();
        }
        MATCHED.lock().unwrap().push((
            Instant::now(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_micros()),
        ));
        vec![LiveFinding {
            rule: "persistence.cron".into(),
            summary: "test judge".into(),
            tier: TriggerTier::High,
            pid: event.pid,
            tid: event.tid,
            task_cookie: event.task_cookie,
            stream_id: event.stream_id,
            call_id: event.call_id,
            guest_ns: event.timestamp_ns,
            syscall: event.syscall_name.clone(),
        }]
    }
}

struct Driver {
    backend: Backend,
    options: BackendOptions,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
    lines: Vec<String>,
}

impl Driver {
    fn receive(&mut self) {
        while let Some(message) = self.backend.try_recv() {
            match message {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.replies
                        .insert(id, if success { Ok(message) } else { Err(message) });
                }
                _ => {}
            }
        }
    }
    fn command(&mut self, command: Command, seconds: u64) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive();
            if let Some(reply) = self.replies.remove(&id) {
                return reply;
            }
            if Instant::now() >= deadline {
                return Err(format!("command {id} timed out"));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn wait(
        &mut self,
        label: &str,
        seconds: u64,
        ready: impl Fn(&Snapshot) -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive();
            if ready(&self.snapshot) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{label} timed out: {:?}", self.snapshot.last_error));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn say(&mut self, line: String) {
        println!("{line}");
        self.lines.push(line);
    }
    fn boot(&mut self, name: &str) -> Result<String, String> {
        let known: Vec<String> = self.snapshot.vms.iter().map(|v| v.id.clone()).collect();
        let profile = CLOUDS
            .iter()
            .find(|provider| provider.id == "cloud-vultr-vc2")
            .map(StealthProfile::cloud_vps)
            .ok_or("no cloud profile")?;
        self.command(
            Command::Create(VmConfig {
                name: name.into(),
                cpus: 2,
                ram_mib: 2048,
                disk_gib: 8,
                routed: true,
                stealth: profile,
                ..Default::default()
            }),
            600,
        )?;
        self.wait("VM publication", 10, |s| {
            s.vms.iter().any(|v| !known.contains(&v.id))
        })?;
        let vm_id = self
            .snapshot
            .vms
            .iter()
            .find(|v| !known.contains(&v.id))
            .ok_or("new VM missing")?
            .id
            .clone();
        self.command(
            Command::Start {
                vm_id: vm_id.clone(),
            },
            900,
        )?;
        self.wait("guest", 240, |s| {
            s.guest_kernel.as_ref().and_then(|k| k.revision).is_some()
                && s.serial_log
                    .as_ref()
                    .and_then(|p| fs::read(p).ok())
                    .is_some_and(|log| log.windows(19).any(|w| w == b"BusyBox guest ready"))
        })?;
        thread::sleep(Duration::from_secs(3));
        Ok(vm_id)
    }
    fn start(&mut self, script: &str, trigger: Option<DumpTrigger>) -> Result<String, String> {
        let known: Vec<String> = self.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        self.command(
            Command::Execute(ExecRequest {
                path: "/bin/sh".into(),
                args: vec!["-c".into(), script.into()],
                uid: 0,
                gid: 0,
                route: Some(RouteKind::Drop),
                capture_network: true,
                core_max_size: Some(64 << 20),
                dump_trigger: trigger,
                ..Default::default()
            }),
            180,
        )?;
        self.wait("run publication", 15, |s| {
            s.runs.iter().any(|r| !known.contains(&r.id))
        })?;
        Ok(self
            .snapshot
            .runs
            .iter()
            .find(|r| !known.contains(&r.id))
            .ok_or("new run missing")?
            .id
            .clone())
    }
    fn run(&self, id: &str) -> Option<RunSummary> {
        self.snapshot.runs.iter().find(|r| r.id == id).cloned()
    }
    fn saved(&self, vm_id: &str, id: &str) -> Option<RunSummary> {
        recording::list_vm_runs(&self.options, vm_id)
            .ok()?
            .into_iter()
            .find(|r| r.id == id)
    }
}

fn artifacts(run: &RunSummary) -> serde_json::Value {
    fs::read(run.directory.join("artifacts.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn describe(label: &str, run: &RunSummary) -> String {
    let a = artifacts(run);
    format!(
        "{label}: state {:?}; root_exit {:?}; live tasks {:?}; network_state {}; route stats {}; core_state {}; issues {}; notes {:?}; triggers {}",
        run.state,
        run.execution.as_ref().and_then(|e| e.root_exit.clone()),
        run.execution.as_ref().map(|e| e.live_task_count),
        a["network_state"],
        if a["route"]["stats"].is_null() {
            "null"
        } else {
            "present"
        },
        a["core_state"],
        a["issues"],
        run.notes,
        serde_json::to_string(&run.triggers).unwrap_or_default(),
    )
}

/// A root that forks a sleeping child and exits 0.
const ORPHAN: &str = "(nslookup example.com 1.1.1.1 >/dev/null 2>&1 &); sleep 600 & exit 0";

fn stop_case(d: &mut Driver, vm_id: &str) -> Result<(), String> {
    let id = d.start(ORPHAN, None)?;
    d.wait("root exit", 60, |s| {
        s.runs.iter().any(|r| {
            r.id == id
                && r.execution
                    .as_ref()
                    .is_some_and(|e| e.root_exit.is_some() && e.live_task_count >= 1)
        })
    })?;
    let run = d.run(&id).ok_or("run vanished")?;
    d.say(format!(
        "STOP: after root exit state {:?}, can_stop {}",
        run.state,
        run.state.can_stop()
    ));
    let started = Instant::now();
    let reply = d.command(Command::StopRun { run_id: id.clone() }, 30)?;
    d.say(format!("STOP: StopRun reply: {reply}"));
    d.wait("run end", 60, |s| {
        s.runs
            .iter()
            .any(|r| r.id == id && matches!(r.state, RunState::Finished | RunState::Stopped))
    })?;
    d.say(format!("STOP: run ended after {:?}", started.elapsed()));
    thread::sleep(Duration::from_secs(4));
    d.receive();
    let run = d
        .saved(vm_id, &id)
        .or_else(|| d.run(&id))
        .ok_or("run lost")?;
    d.say(describe("STOP result", &run));
    Ok(())
}

fn trigger_case(d: &mut Driver, vm_id: &str, delays: &[&str]) -> Result<(), String> {
    for delay in delays {
        let plan = DumpTrigger {
            min_tier: TriggerTier::High,
            memory: false,
            core: true,
            max_dumps: 1,
            cooldown_secs: 0,
            memory_max_mib: 0,
        };
        MATCHED.lock().unwrap().clear();
        let script = format!(
            "mkdir -p /etc/cron.d; echo '* * * * * root true' > /etc/cron.d/t{n}; sleep {delay}; exit 0",
            n = delay.replace('.', "_")
        );
        let started = Instant::now();
        let id = d.start(&script, Some(plan))?;
        d.wait("trigger run end", 60, |s| {
            s.runs
                .iter()
                .any(|r| r.id == id && matches!(r.state, RunState::Finished | RunState::Stopped))
        })?;
        thread::sleep(Duration::from_secs(8));
        d.receive();
        let run = d
            .saved(vm_id, &id)
            .or_else(|| d.run(&id))
            .ok_or("run lost")?;
        let matched = MATCHED.lock().unwrap().first().copied();
        let handled = run.triggers.as_ref().and_then(|log| {
            log.records
                .first()
                .map(|r| r.at_ms)
                .or_else(|| log.missed.first().map(|m| m.at_ms))
        });
        let latency = matched
            .zip(handled)
            .map(|((_, micros), at_ms)| at_ms as i128 - (micros / 1000) as i128);
        d.say(format!(
            "TRIGGER delay {delay}: judge matched at +{:?} from the launch, handled {latency:?} ms after the match; {}",
            matched.map(|(at, _)| at.duration_since(started)),
            describe("result", &run)
        ));
    }
    Ok(())
}

fn vmstop_case(d: &mut Driver, vm_id: &str) -> Result<(), String> {
    let id = d.start(ORPHAN, None)?;
    d.wait("root exit", 60, |s| {
        s.runs.iter().any(|r| {
            r.id == id
                && r.execution
                    .as_ref()
                    .is_some_and(|e| e.root_exit.is_some() && e.live_task_count >= 1)
        })
    })?;
    d.command(Command::Stop, 120)?;
    d.wait("VM stop", 120, |s| s.state == VmState::Stopped)?;
    thread::sleep(Duration::from_secs(5));
    let run = d.saved(vm_id, &id).ok_or("run lost")?;
    d.say(describe("VMSTOP result", &run));
    Ok(())
}

fn check(bundle: &str, data: &str, only: &[&str]) -> Result<(), String> {
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("the check needs a new disposable data folder".into());
    }
    fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    antinomie_monitor_core::dump_trigger::set_judge(|| Box::new(CronJudge));
    let options = BackendOptions {
        bundle_dir: PathBuf::from(bundle),
        data_dir: data.clone(),
        headless: true,
        serial_console: true,
        capture_quota_size: 1024 * 1024 * 1024,
        ..Default::default()
    };
    let mut d = Driver {
        backend: Backend::new(options.clone())?,
        options,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        lines: Vec::new(),
    };
    let wanted = |name: &str| only.is_empty() || only.contains(&name);
    let vm_id = d.boot("stop run check")?;
    let mut errors = Vec::new();
    if wanted("trigger")
        && let Err(e) = trigger_case(
            &mut d,
            &vm_id,
            &["0", "0.05", "0.1", "0.2", "0.5", "0.05", "0.1"],
        )
    {
        errors.push(format!("trigger: {e}"));
    }
    if wanted("stop")
        && let Err(e) = stop_case(&mut d, &vm_id)
    {
        errors.push(format!("stop: {e}"));
    }
    if wanted("vmstop")
        && let Err(e) = vmstop_case(&mut d, &vm_id)
    {
        errors.push(format!("vmstop: {e}"));
    }
    if d.snapshot.state != VmState::Stopped {
        let _ = d.command(Command::Stop, 120);
        let _ = d.wait("VM stop", 120, |s| s.state == VmState::Stopped);
    }
    let _ = d.command(Command::Close, 30);
    let table = d.lines.join("\n");
    let _ = fs::write(Path::new(&data).join("stop-run-check.txt"), table);
    if errors.is_empty() {
        println!("STOP-RUN-CHECK DONE");
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let [bundle, data, only @ ..] = args.as_slice() else {
        eprintln!("usage: stop-run-check BUNDLE NEW_DATA_DIR [trigger|stop|vmstop...]");
        std::process::exit(2);
    };
    if let Err(error) = check(bundle, data, only) {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
