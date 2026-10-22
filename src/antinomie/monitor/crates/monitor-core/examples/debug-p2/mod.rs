// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Debugger phase 2 qualification: `debug-check p2 BUNDLE NEW_DATA_DIR FIXTURE_DIR [test ...]`.
//! FIXTURE_DIR holds the builds of `tests/monitor/debug-p2-fixture.c`:
//! `p2fix` (static), `p2pie` (static-pie) and, when the dynamic test runs,
//! `p2dyn` with `dbgroot/` (the host's ld.so and libc).
use super::*;
use antinomie_monitor_core::debug::signal_policy;

mod engine;
pub(crate) mod gdb;

type Symbols = BTreeMap<String, u64>;
type Test = fn(&mut Context) -> Result<String, String>;

/// A running fixture with a debug session attached through the backend trait.
struct Prog {
    launched: Launched,
    sym: Symbols,
    dbg: KernelDebugBackend,
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

impl Context {
    fn next_seed(&mut self) -> u64 {
        self.seed += 7;
        self.seed
    }
    /// Launch a fixture mode and attach the backend; the process keeps running.
    fn start(
        &mut self,
        binary: &str,
        mode: &str,
        rounds: u32,
        workers: u32,
    ) -> Result<Prog, String> {
        let path = format!("/tmp/{binary}");
        let launched = launch_program(
            &mut self.driver,
            &path,
            vec![mode.into(), rounds.to_string(), workers.to_string()],
            false,
        )?;
        let sym = parse_symbols(&launched.symbols);
        let seed = self.next_seed();
        let dbg = attach_backend(&mut self.driver, &launched, seed)?;
        Ok(Prog { launched, sym, dbg })
    }
    /// End the session and the run.
    fn finish(&mut self, mut prog: Prog) -> Result<(), String> {
        prog.dbg
            .detach(DetachMode::Kill)
            .map_err(|e| e.to_string())?;
        run_ended(&mut self.driver, &prog.launched.run.id, 30).map(|_| ())
    }
}

impl Drop for Prog {
    /// A test that failed leaves no session behind.
    fn drop(&mut self) {
        let _ = self.dbg.detach(DetachMode::Kill);
    }
}

impl Prog {
    fn sym(&self, name: &str) -> Result<u64, String> {
        self.sym
            .get(name)
            .copied()
            .ok_or_else(|| format!("symbol {name} missing"))
    }
    fn stop(&mut self) -> Result<antinomie_monitor_core::debug::StopEvent, String> {
        self.dbg.interrupt().map_err(|e| e.to_string())?;
        wait_state(&mut self.dbg, 10)
    }
    /// Continue to a software breakpoint at `addr` and remove it again.
    fn run_to(&mut self, addr: u64) -> Result<antinomie_monitor_core::debug::StopEvent, String> {
        self.dbg
            .set_breakpoint(addr, 1)
            .map_err(|e| e.to_string())?;
        self.dbg
            .resume(ResumeAction::Continue)
            .map_err(|e| e.to_string())?;
        let event = wait_state(&mut self.dbg, 15)?;
        self.dbg
            .clear_breakpoint(addr, 1)
            .map_err(|e| e.to_string())?;
        match event.kind {
            StopKind::Breakpoint { addr: hit } if hit == addr && event.pc == addr => Ok(event),
            other => Err(format!(
                "expected a breakpoint at {addr:#x}, stopped at {:#x}: {other:?}",
                event.pc
            )),
        }
    }
    fn step(&mut self, tid: u32) -> Result<u64, String> {
        self.dbg
            .resume(ResumeAction::Step { tid })
            .map_err(|e| e.to_string())?;
        let event = wait_state(&mut self.dbg, 15)?;
        if event.kind != StopKind::Step {
            return Err(format!(
                "a step ended as {:?} at {:#x}",
                event.kind, event.pc
            ));
        }
        let regs = user_regs(&mut self.dbg, tid)?;
        if u64_of(&regs, EFLAGS) & 0x100 != 0 {
            return Err("TF visible after a step".into());
        }
        Ok(u64_of(&regs, RIP))
    }
    fn regs(&mut self, tid: u32) -> Result<Vec<u8>, String> {
        user_regs(&mut self.dbg, tid)
    }
}

pub fn run(bundle: &str, data: &str, dir: &str, only: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(dir);
    let mut driver = boot(bundle, data)?;
    for (name, destination) in [("p2fix", "/tmp/p2fix"), ("p2pie", "/tmp/p2pie")] {
        let source = dir.join(name);
        if source.is_file() {
            driver.command(Command::Upload {
                source,
                destination: destination.into(),
                overwrite: false,
                executable: true,
            })?;
        }
    }
    // A dynamically linked build brings the host's loader and libc along.
    let root = dir.join("dbgroot");
    if root.is_dir() && dir.join("p2dyn").is_file() {
        driver.command(Command::Upload {
            source: dir.join("p2dyn"),
            destination: "/tmp/p2dyn".into(),
            overwrite: false,
            executable: true,
        })?;
        for entry in fs::read_dir(&root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            driver.command(Command::Upload {
                source: entry.path(),
                destination: format!("/tmp/{}", entry.file_name().to_string_lossy()),
                overwrite: false,
                executable: true,
            })?;
        }
    }
    let mut context = Context {
        driver,
        dir,
        seed: 0x2000,
    };
    let tests: &[(&str, Test)] = &[
        ("start", gdb::start),
        ("pie", gdb::pie),
        ("dynamic", gdb::dynamic),
        ("gdb-threads", gdb::threads),
        ("gdb-step", gdb::step),
        ("gdb-hw", gdb::hardware),
        ("gdb-signals", gdb::signals),
        ("gdb-fatal", gdb::fatal),
        ("stop-run", gdb::stop_run),
        ("core-under-stop", gdb::core_under_stop),
        ("step", engine::step),
        ("signals", engine::signals),
        ("signal-step", engine::signal_step),
        ("forkbp", engine::forkbp),
        ("hw", engine::hw),
        ("slots", engine::slots),
        ("hwthreads", engine::hwthreads),
        ("smc", engine::smc),
        ("anti", engine::anti),
        ("latency", engine::latency),
    ];
    let mut failed = Vec::new();
    for (name, test) in tests {
        if !only.is_empty() && !only.iter().any(|wanted| wanted == name) {
            continue;
        }
        let outcome = test(&mut context);
        if outcome.is_ok() && context.driver.snapshot.debug.is_some() {
            let _ = context.driver.command(Command::DebugDetach { kill: true });
        }
        match outcome {
            Ok(message) => println!("PASS {name}: {message}"),
            Err(error) => {
                println!("FAIL {name}: {error}");
                failed.push(*name);
                // Leave no debugger session or program behind for the next test.
                if context.driver.snapshot.debug.is_some() {
                    let _ = context.driver.command(Command::DebugDetach { kill: true });
                }
            }
        }
    }
    context.driver.command(Command::Stop).ok();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("failed: {}", failed.join(", ")))
    }
}
