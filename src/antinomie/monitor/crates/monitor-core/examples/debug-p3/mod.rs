// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Debugger phase 3 qualification: `debug-check p3 BUNDLE NEW_DATA_DIR FIXTURE_DIR [test ...]`.
//! FIXTURE_DIR holds `p3fix`, the build of `tests/monitor/debug-p3-fixture.c`
//! (and, for the gdb tests, `p2fix` of phase 2). One BusyBox VM, one vCPU.
use super::*;
use antinomie_monitor_core::debug::{ChildRef, SessionOptions, StopEvent, ThreadAction};

mod engine;
mod gdb;
mod session;

type Symbols = BTreeMap<String, u64>;
type Test = fn(&mut Context) -> Result<String, String>;

/// A running fixture with a debug session attached through the backend trait,
/// and the sessions of any children followed.
pub struct Prog {
    pub launched: Launched,
    pub sym: Symbols,
    pub dbg: KernelDebugBackend,
    pub kids: Vec<Box<dyn DebugBackend>>,
}

pub struct Context {
    pub driver: Driver,
    #[allow(dead_code)]
    pub dir: PathBuf,
    seed: u64,
}

fn parse_symbols(line: &str) -> Symbols {
    line.split_whitespace()
        .filter_map(|part| {
            let (name, value) = part.split_once('=')?;
            let value = value.strip_prefix("0x")?;
            Some((name.to_string(), u64::from_str_radix(value, 16).ok()?))
        })
        .collect()
}

pub fn follow() -> SessionOptions {
    SessionOptions {
        fork: true,
        exec: true,
        nonstop: false,
    }
}

impl Context {
    fn next_seed(&mut self) -> u64 {
        self.seed += 7;
        self.seed
    }
    /// Launch a fixture mode, attach, stop it and set the session options.
    /// With `options` the group stays stopped; the caller resumes.
    pub fn start(
        &mut self,
        mode: &str,
        rounds: u32,
        workers: u32,
        options: Option<SessionOptions>,
    ) -> Result<Prog, String> {
        let launched = launch_program(
            &mut self.driver,
            "/tmp/p3fix",
            vec![mode.into(), rounds.to_string(), workers.to_string()],
            false,
        )?;
        let sym = parse_symbols(&launched.symbols);
        let seed = self.next_seed();
        let dbg = attach_backend(&mut self.driver, &launched, seed)?;
        let mut prog = Prog {
            launched,
            sym,
            dbg,
            kids: Vec::new(),
        };
        if let Some(options) = options {
            prog.stop()?;
            prog.dbg
                .configure(options)
                .map_err(|e| format!("configure: {e}"))?;
        }
        Ok(prog)
    }
    pub fn finish(&mut self, mut prog: Prog) -> Result<(), String> {
        for kid in &mut prog.kids {
            let _ = kid.detach(DetachMode::Kill);
        }
        prog.kids.clear();
        prog.dbg
            .detach(DetachMode::Kill)
            .map_err(|e| e.to_string())?;
        run_ended(&mut self.driver, &prog.launched.run.id, 30).map(|_| ())
    }
    pub fn output(&mut self, prog: &Prog) -> String {
        self.driver.receive();
        self.driver.output(&prog.launched.run.id).to_string()
    }
    pub fn wait_output(&mut self, prog: &Prog, needle: &str, seconds: u64) -> Result<(), String> {
        self.driver
            .wait_text(&prog.launched.run.id, needle, seconds)
    }
}

impl Drop for Prog {
    /// A test that failed leaves no session behind.
    fn drop(&mut self) {
        for kid in &mut self.kids {
            let _ = kid.detach(DetachMode::Kill);
        }
        let _ = self.dbg.detach(DetachMode::Kill);
    }
}

impl Prog {
    pub fn sym(&self, name: &str) -> Result<u64, String> {
        self.sym
            .get(name)
            .copied()
            .ok_or_else(|| format!("symbol {name} missing"))
    }
    pub fn stop(&mut self) -> Result<StopEvent, String> {
        self.dbg.interrupt().map_err(|e| e.to_string())?;
        wait_state(&mut self.dbg, 10)
    }
    pub fn go(&mut self, seconds: u64) -> Result<StopEvent, String> {
        self.dbg
            .resume(ResumeAction::Continue)
            .map_err(|e| e.to_string())?;
        wait_state(&mut self.dbg, seconds)
    }
    pub fn regs(&mut self, tid: u32) -> Result<Vec<u8>, String> {
        user_regs(&mut self.dbg, tid)
    }
}

/// The next stop of any backend.
pub fn wait_for(backend: &mut dyn DebugBackend, seconds: u64) -> Result<StopEvent, String> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        match backend.state().map_err(|e| e.to_string())? {
            TargetState::Stopped(event) => return Ok(event),
            TargetState::Exited { wait_status } => {
                return Err(format!("target exited ({wait_status:#x})"));
            }
            TargetState::Replaced => return Err("target was replaced".into()),
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no stop in {seconds}s; failure {:?}",
                backend.take_failure()
            ));
        }
        thread::sleep(Duration::from_micros(500));
    }
}

pub fn wait_exit(backend: &mut dyn DebugBackend, seconds: u64) -> Result<u32, String> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        match backend.state().map_err(|e| e.to_string())? {
            TargetState::Exited { wait_status } => return Ok(wait_status),
            TargetState::Stopped(event) => {
                return Err(format!(
                    "stopped again: {:?} at {:#x}",
                    event.kind, event.pc
                ));
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(format!("no exit in {seconds}s"));
        }
        thread::sleep(Duration::from_millis(2));
    }
}

pub fn run(bundle: &str, data: &str, dir: &str, only: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(dir);
    // A long Stop grace period: the test needs the window between the debugger
    // giving up on a group that cannot stop and the guest's SIGKILL escalation.
    let mut driver = boot_with(bundle, data, Some(Duration::from_secs(12)))?;
    let source = dir.join("p3fix");
    if source.is_file() {
        driver.command(Command::Upload {
            source,
            destination: "/tmp/p3fix".into(),
            overwrite: false,
            executable: true,
        })?;
    }
    let mut context = Context {
        driver,
        dir,
        seed: 0x3000,
    };
    let tests: &[(&str, Test)] = &[
        ("fork-follow", engine::fork_follow),
        ("vfork-follow", engine::vfork_follow),
        ("exec-event", engine::exec_event),
        ("exec-legacy", engine::exec_legacy),
        ("nonstop", engine::nonstop),
        ("hwthreads", engine::hw_new_threads),
        ("sigchld", engine::sigchld),
        ("readopt", engine::readopt),
        ("stoprun-bytes", engine::stop_run_bytes),
        ("fork-stress", engine::fork_stress),
        ("reconnect", session::reconnect),
        ("gdb-follow-child", gdb::follow_child),
        ("gdb-follow-parent", gdb::follow_parent),
        ("gdb-keep-both", gdb::keep_both),
        ("gdb-vfork", gdb::vfork),
        ("gdb-exec", gdb::exec),
        ("gdb-nonstop", gdb::nonstop),
        // Restoring a snapshot changes the VM under the later tests: keep these last.
        ("snapshot", session::snapshot_with_debugger),
        ("snapshot-readopt", session::snapshot_readopt),
    ];
    let mut failed = Vec::new();
    for (name, test) in tests {
        if !only.is_empty() && !only.iter().any(|wanted| wanted == name) {
            continue;
        }
        let outcome = test(&mut context);
        match outcome {
            Ok(message) => println!("PASS {name}: {message}"),
            Err(error) => {
                println!("FAIL {name}: {error}");
                failed.push(*name);
            }
        }
        if context.driver.snapshot.debug.is_some() {
            let _ = context.driver.command(Command::DebugDetach { kill: true });
        }
    }
    context.driver.command(Command::Stop).ok();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("failed: {}", failed.join(", ")))
    }
}
