// SPDX-License-Identifier: GPL-3.0-only
//! Opt-in check of the Debugger tab's gdb console against a real guest: the
//! app with its backend, a BusyBox VM, the phase-2 fixture, host gdb with
//! the managed GEF and the managed portable pwndbg, driven through the pane
//! the way a person types into it.
//!
//! ```text
//! install-tool DATA gef; install-tool DATA pwndbg
//! ANTINOMIE_DEBUG_LIVE_BUNDLE=BUNDLE ANTINOMIE_DEBUG_LIVE_DATA=DATA \
//! ANTINOMIE_DEBUG_LIVE_FIXTURE=p2fix \
//!     cargo test --release -p antinomie-monitor-ui debugger_console_live -- --ignored --nocapture
//! ```
//!
//! For each front end: attach to a running program (Run, Attach debugger),
//! and Debug on start. Each case shows registers and memory, sets a software
//! breakpoint and reaches it, steps, detaches, and closes the console: the
//! program then runs on to its own end. pwndbg is the managed portable copy
//! and then, when the host has one, the system pwndbg the app prefers.
//!
//! A new session's pane starts gdb by itself. Debug on start uses that gdb;
//! the attach case presses Restart while it holds the session, so the new gdb
//! connects while the old one is still leaving (it waits its turn).
use super::*;
use crate::app::debugger::{panes::Pane, GdbFlavour};
use antinomie_monitor_core::GuestProcessIdentity;
use std::time::{Duration, Instant};

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    ctx.set_visuals(egui::Visuals::dark());
    ctx
}

const SIZE: egui::Vec2 = egui::vec2(1280.0, 820.0);

/// Let the app pick a system pwndbg, as it does when one is installed.
static SYSTEM_PWNDBG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Draw frames until `ready` holds or `seconds` pass. The managed pwndbg is
/// used, not a system one, so the tool list is adjusted every frame.
fn pump(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    seconds: u64,
    ready: impl Fn(&MonitorApp) -> bool,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        // What a frame of the app does before it draws: take the backend's
        // notifications and keep the run terminals current.
        app.drain();
        app.resync_terminals();
        if !SYSTEM_PWNDBG.load(std::sync::atomic::Ordering::Relaxed) {
            for tool in &mut app.snapshot.analysis_tools {
                if tool.id == "pwndbg" {
                    tool.system = None;
                }
            }
        }
        render(app, ctx, SIZE);
        if ready(app) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}

fn guest_ready(app: &MonitorApp) -> bool {
    app.snapshot
        .guest_kernel
        .as_ref()
        .and_then(|kernel| kernel.revision)
        .is_some_and(|revision| revision >= 17)
        && app
            .snapshot
            .serial_log
            .as_ref()
            .and_then(|path| std::fs::read(path).ok())
            .is_some_and(|log| log.windows(19).any(|part| part == b"BusyBox guest ready"))
}

/// The address of `name` in the static fixture.
fn symbol(fixture: &str, name: &str) -> u64 {
    let output = std::process::Command::new("nm")
        .arg(fixture)
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let address = parts.next()?;
            let _kind = parts.next()?;
            (parts.next()? == name).then(|| u64::from_str_radix(address, 16).ok())?
        })
        .unwrap_or_else(|| panic!("{name} missing from {fixture}"))
}

/// Type `line` and wait until the transcript, after what it held before,
/// contains every needle.
fn gdb(app: &mut MonitorApp, ctx: &egui::Context, line: &str, needles: &[&str]) -> String {
    let before = app.debugger.console.transcript().len();
    app.debugger.console.type_text(&format!("{line}\n"));
    let found = pump(app, ctx, 30, |app| {
        let text = app.debugger.console.transcript();
        let new = text.get(before..).unwrap_or("");
        needles.iter().all(|needle| new.contains(needle))
    });
    let text = app.debugger.console.transcript();
    let new = text.get(before..).unwrap_or("").to_owned();
    assert!(
        found,
        "after {line:?} wanted {needles:?}; gdb printed:\n{new}\n\
         the whole console:\n{text}\nthe debug session: {:?}",
        app.snapshot.debug
    );
    println!("GDB {line:?} -> {} bytes, found {needles:?}", new.len());
    new
}

fn run_state(app: &MonitorApp, id: &str) -> Option<antinomie_monitor_core::RunState> {
    app.snapshot
        .runs
        .iter()
        .find(|run| run.id == id)
        .map(|run| run.state.clone())
}

/// Start the fixture; for a running program, also its exact identity, the
/// way the Attach debugger picker finds it.
fn launch(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    args: &[&str],
    debug_on_start: bool,
) -> (String, Option<GuestProcessIdentity>) {
    let known: Vec<String> = app.snapshot.runs.iter().map(|run| run.id.clone()).collect();
    app.send(Command::Execute(ExecRequest {
        path: "/tmp/p2fix".into(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        debug_on_start,
        ..Default::default()
    }));
    assert!(pump(app, ctx, 30, |app| app.snapshot.runs.iter().any(
        |run| !known.contains(&run.id) && run.pid != 0 && run.root_task_cookie != 0
    )));
    let run = app
        .snapshot
        .runs
        .iter()
        .find(|run| !known.contains(&run.id))
        .cloned()
        .unwrap();
    if debug_on_start {
        return (run.id, None);
    }
    app.send(Command::ListProcesses { after_pid: 0 });
    let found = |app: &MonitorApp| {
        app.snapshot.process_page.as_ref().and_then(|page| {
            page.processes
                .iter()
                .find(|process| {
                    process.identity.tgid == run.pid
                        && process.identity.task_cookie == run.root_task_cookie
                })
                .map(|process| process.identity.clone())
        })
    };
    assert!(pump(app, ctx, 20, |app| found(app).is_some()));
    (run.id.clone(), found(app))
}

/// One console session on the live debug session: registers, memory, a
/// software breakpoint at `stop`, steps, detach, close. With `restart` the
/// pane's gdb is replaced by a new one first.
fn console_session(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    flavour: GdbFlavour,
    stop: u64,
    run: &str,
    restart: bool,
) {
    if restart {
        app.debugger.console.restart();
    }
    let prompt = match flavour {
        GdbFlavour::Gef => "gef",
        GdbFlavour::Pwndbg => "pwndbg>",
    };
    let connected = pump(app, ctx, 60, |app| {
        let text = app.debugger.console.transcript();
        text.contains("Remote debugging using") && text.contains(prompt)
    });
    let transcript = app.debugger.console.transcript();
    assert!(
        connected
            && ![
                "Remote replied unexpectedly",
                "Remote connection closed",
                "packet error"
            ]
            .iter()
            .any(|error| transcript.contains(error)),
        "{flavour:?} did not connect; running={} screen={}\nit printed:\n{transcript}\nthe debug session: {:?}",
        app.debugger.console.running(),
        app.debugger.console.contents(),
        app.snapshot.debug
    );
    println!("CONSOLE {flavour:?} connected");
    // Registers and memory, as the front end shows them.
    let registers = gdb(app, ctx, "info registers rip rsp", &["rip", "rsp", "0x"]);
    assert!(!registers.contains("not available"), "{registers}");
    gdb(app, ctx, "x/4gx $rsp", &["0x"]);
    let context = match flavour {
        GdbFlavour::Gef => gdb(app, ctx, "context regs", &["$rip", "$rsp"]),
        GdbFlavour::Pwndbg => gdb(app, ctx, "context regs", &["RIP", "RSP"]),
    };
    assert!(!context.contains("Traceback"), "{context}");
    // A software breakpoint the program reaches.
    gdb(app, ctx, &format!("break *{stop:#x}"), &["Breakpoint 1 at"]);
    let hit = gdb(
        app,
        ctx,
        "continue",
        &["Breakpoint 1,", &format!("{stop:x}")],
    );
    assert!(!hit.contains("Traceback"), "{hit}");
    // Steps, one instruction at a time (stepping over a call could run a
    // call that never returns, as `main` of the fixture does).
    for _ in 0..2 {
        let stepped = gdb(app, ctx, "stepi", &["0x"]);
        assert!(
            !stepped.contains("Cannot") && !stepped.contains("exited"),
            "{stepped}"
        );
    }
    // The value gdb prints for $pc (a front end's context of an earlier stop
    // may still be arriving around it).
    // gdb was started for this session: its first value is $1.
    let printed = gdb(app, ctx, "print/x $pc", &["$1 = 0x"]);
    let pc = printed
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (name, value) = line.split_once(" = 0x")?;
            (name.starts_with('$') && name[1..].chars().all(|c| c.is_ascii_digit())).then(|| {
                value
                    .chars()
                    .take_while(char::is_ascii_hexdigit)
                    .collect::<String>()
            })
        })
        .next_back()
        .and_then(|hex| u64::from_str_radix(&hex, 16).ok());
    println!("STEPPED from {stop:#x} to {pc:#x?}");
    assert!(
        pc.is_some_and(|pc| pc != stop),
        "the steps did not move: {printed}"
    );
    gdb(app, ctx, "delete", &[prompt]);
    // Detach: the program runs on.
    let detached = gdb(app, ctx, "detach", &["Detaching from"]);
    println!(
        "DETACH {flavour:?}: {}",
        detached
            .lines()
            .filter(|line| line.contains("etach") || line.contains("nferior"))
            .collect::<Vec<_>>()
            .join(" / ")
    );
    let state = run_state(app, run);
    assert!(
        matches!(state, Some(antinomie_monitor_core::RunState::Running)),
        "{state:?}"
    );
    // Closing the console (its Stop) quits gdb and leaves the program
    // running; no other gdb takes its place.
    app.debugger.console.quit();
    assert!(!app.debugger.console.running());
    pump(app, ctx, 2, |_| false);
    assert!(
        !app.debugger.console.running(),
        "a closed console started gdb again"
    );
    let state = run_state(app, run);
    println!("CONSOLE {flavour:?} closed; run {state:?}");
    assert!(
        matches!(state, Some(antinomie_monitor_core::RunState::Running)),
        "closing the console ended the program: {state:?}"
    );
}

/// The debug session as the tab's Detach leaves it: ended, the program
/// running on. gdb's own detach may already have ended it.
fn end_session(app: &mut MonitorApp, ctx: &egui::Context) {
    if !pump(app, ctx, 3, |app| app.snapshot.debug.is_none()) {
        app.send(Command::DebugDetach { kill: false });
        assert!(pump(app, ctx, 30, |app| app.snapshot.debug.is_none()));
    }
}

#[test]
#[ignore = "boots a VM: needs ANTINOMIE_DEBUG_LIVE_BUNDLE, _DATA (gef and pwndbg installed) and _FIXTURE"]
fn debugger_console_live() {
    let bundle = std::env::var("ANTINOMIE_DEBUG_LIVE_BUNDLE").unwrap();
    let data = PathBuf::from(std::env::var("ANTINOMIE_DEBUG_LIVE_DATA").unwrap());
    let fixture = std::env::var("ANTINOMIE_DEBUG_LIVE_FIXTURE").unwrap();
    let hw_code = symbol(&fixture, "hw_code");
    let main = symbol(&fixture, "main");
    let history_before = std::path::Path::new(".gdb_history").exists();
    let ctx = context();
    let mut app = app();
    app.options = BackendOptions {
        bundle_dir: PathBuf::from(bundle),
        data_dir: data,
        headless: true,
        ..Default::default()
    };
    app.backend = Some(antinomie_monitor_core::Backend::new(app.options.clone()).unwrap());
    app.settings.debugger.toggle_pane(Pane::Console);
    app.send(Command::Create(VmConfig {
        name: "debugger console".into(),
        cpus: 1,
        ram_mib: 1024,
        disk_gib: 1,
        ..Default::default()
    }));
    // The first VM of a data folder imports the base into it (about 20 s on
    // a slow disk).
    assert!(pump(&mut app, &ctx, 120, |app| !app
        .snapshot
        .vms
        .is_empty()));
    let vm_id = app.snapshot.vms[0].id.clone();
    app.selected = Some(vm_id.clone());
    app.send(Command::Start {
        vm_id: vm_id.clone(),
    });
    assert!(
        pump(&mut app, &ctx, 180, guest_ready),
        "the guest did not boot"
    );
    app.send(Command::Upload {
        source: PathBuf::from(&fixture),
        destination: "/tmp/p2fix".into(),
        overwrite: true,
        executable: true,
    });
    pump(&mut app, &ctx, 5, |_| false);
    let system = antinomie_monitor_core::analysis_tools::statuses(&app.options.data_dir)
        .iter()
        .any(|tool| tool.id == "pwndbg" && tool.system.is_some());
    let mut passes = vec![(GdbFlavour::Gef, false), (GdbFlavour::Pwndbg, false)];
    if system {
        passes.push((GdbFlavour::Pwndbg, true));
    }
    for (flavour, system) in passes {
        SYSTEM_PWNDBG.store(system, std::sync::atomic::Ordering::Relaxed);
        app.settings.debugger.gdb_flavour = flavour;
        println!(
            "PASS {flavour:?}{}",
            if system { " (system pwndbg)" } else { "" }
        );
        // Attach to a running program.
        // A round sleeps 50 ms. Keep the attach target alive beyond the
        // 60-second connection deadline and command checks even on a cold host;
        // the test kills it explicitly after detaching.
        let (run, identity) = launch(&mut app, &ctx, &["hw", "12000"], false);
        app.send(Command::DebugAttach {
            identity: identity.unwrap(),
        });
        assert!(pump(&mut app, &ctx, 30, |app| app.snapshot.debug.is_some()));
        console_session(&mut app, &ctx, flavour, hw_code, &run, true);
        end_session(&mut app, &ctx);
        app.send(Command::Signal {
            run_id: run.clone(),
            signal: 9,
        });
        // Debug on start: the program is parked before its first instruction.
        // After detach, closing the console observes it running for two seconds.
        // Its lifetime must exceed that observation window, then finish within
        // the existing 60-second completion deadline.
        let (run, _) = launch(&mut app, &ctx, &["start", "200"], true);
        assert!(pump(&mut app, &ctx, 30, |app| app.snapshot.debug.is_some()));
        console_session(&mut app, &ctx, flavour, main, &run, false);
        // It runs on to its own end once the console is gone.
        let ended = pump(&mut app, &ctx, 60, |app| {
            matches!(
                run_state(app, &run),
                Some(antinomie_monitor_core::RunState::Finished)
            )
        });
        if !ended {
            let summary = app.snapshot.runs.iter().find(|r| r.id == run).cloned();
            panic!(
                "the program started under the debugger did not finish: state {:?} execution {:?} debug {:?}\ngdb printed:\n{}",
                summary.as_ref().map(|r| r.state.clone()),
                summary.as_ref().and_then(|r| r.execution.clone()),
                app.snapshot.debug,
                app.debugger.console.transcript()
            );
        }
        println!("CONSOLE {flavour:?} debug-on-start run finished");
        end_session(&mut app, &ctx);
    }
    app.send(Command::Stop);
    pump(&mut app, &ctx, 60, |app| {
        app.snapshot.state == VmState::Stopped
    });
    // gdb's history goes to the console's home (pwndbg) or the user's (GEF),
    // never to the app's working directory.
    assert!(
        history_before || !std::path::Path::new(".gdb_history").exists(),
        "a console saved gdb's history in the working directory"
    );
}
