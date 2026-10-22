// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Phase 2 through a real gdb: Debug on start, threads, stepping across a system
//! call and a repeated string instruction, hardware breakpoints and watchpoints,
//! signals, Stop of a debugged run. Each test drives one interactive gdb
//! process over pipes, one command group at a time, and also looks at the guest
//! (its terminal output, the app's snapshot) between the groups.
use super::*;
use std::{
    io::{Read, Write},
    process::{Child, ChildStdin, Stdio},
    sync::{Arc, Condvar, Mutex},
};

pub(crate) struct Gdb {
    child: Child,
    stdin: ChildStdin,
    output: Arc<(Mutex<String>, Condvar)>,
    mark: u32,
    transcript: String,
}

impl Gdb {
    pub(crate) fn start(directory: &std::path::Path) -> Result<Self, String> {
        let mut child = Process::new("sh")
            .arg("-c")
            .arg("exec gdb -nx -q 2>&1")
            .current_dir(directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("gdb: {e}"))?;
        let mut stdout = child.stdout.take().ok_or("gdb stdout")?;
        let stdin = child.stdin.take().ok_or("gdb stdin")?;
        let output = Arc::new((Mutex::new(String::new()), Condvar::new()));
        let shared = output.clone();
        thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(count) = stdout.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                let (lock, signal) = &*shared;
                lock.lock()
                    .expect("gdb output")
                    .push_str(&String::from_utf8_lossy(&buffer[..count]));
                signal.notify_all();
            }
            shared.1.notify_all();
        });
        let mut gdb = Self {
            child,
            stdin,
            output,
            mark: 0,
            transcript: String::new(),
        };
        if std::env::var_os("P2_GDB_REMOTE_DEBUG").is_some() {
            gdb.run("set debug remote 1", 20)?;
        }
        // gdb waits 2 s for a reply by default, then asks again and reads
        // every later reply as the answer to the request before it. A busy
        // host can make the guest take longer (a request is given 5 s), so
        // the checks give gdb as long as the app's console does.
        gdb.run(
            "set pagination off\nset confirm off\nset style enabled off\nset width 0\nset height 0\nset debuginfod enabled off\nset remotetimeout 30",
            20,
        )?;
        Ok(gdb)
    }
    /// Send commands without waiting for them; `wait` collects the output.
    pub(crate) fn send(&mut self, commands: &str) -> Result<String, String> {
        self.mark += 1;
        let marker = format!("<<<DONE-{}>>>", self.mark);
        write!(self.stdin, "{commands}\necho {marker}\\n\n")
            .map_err(|e| format!("gdb input: {e}"))?;
        self.stdin.flush().map_err(|e| e.to_string())?;
        Ok(marker)
    }
    pub(crate) fn wait(&mut self, marker: &str, seconds: u64) -> Result<String, String> {
        let until = Instant::now() + Duration::from_secs(seconds);
        let (lock, signal) = &*self.output;
        let mut text = lock.lock().expect("gdb output");
        while !text.contains(marker) {
            if Instant::now() >= until {
                if let Some(path) = std::env::var_os("P3_TRACE_FILE") {
                    use std::io::Write as _;
                    if let Ok(mut file) =
                        fs::OpenOptions::new().append(true).create(true).open(path)
                    {
                        let _ =
                            writeln!(file, "{}", text.chars().take(300_000).collect::<String>());
                    }
                }
                self.transcript.push_str(&text);
                return Err(format!(
                    "gdb did not finish a command group in {seconds} s; output so far:\n{}",
                    tail(
                        &self.transcript,
                        if std::env::var_os("P3_TRACE").is_some() {
                            60000
                        } else {
                            1500
                        }
                    )
                ));
            }
            let (guard, _) = signal
                .wait_timeout(text, Duration::from_millis(50))
                .expect("gdb output");
            text = guard;
        }
        let at = text.find(marker).expect("marker") + marker.len();
        let taken: String = text.drain(..at).collect();
        if let Some(path) = std::env::var_os("P3_TRACE_FILE") {
            use std::io::Write as _;
            if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(path) {
                let _ = writeln!(file, "{}", taken.chars().take(200_000).collect::<String>());
            }
        }
        self.transcript.push_str(&taken);
        Ok(taken)
    }
    pub(crate) fn run(&mut self, commands: &str, seconds: u64) -> Result<String, String> {
        let marker = self.send(commands)?;
        self.wait(&marker, seconds)
    }
    pub(crate) fn close(mut self, seconds: u64) -> String {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.stdin.flush();
        let until = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < until {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let text = self.output.0.lock().expect("gdb output").clone();
        self.transcript.push_str(&text);
        std::mem::take(&mut self.transcript)
    }
}

impl Drop for Gdb {
    fn drop(&mut self) {
        if let Some(path) = std::env::var_os("P2_GDB_TRANSCRIPT") {
            let text = self.output.0.lock().expect("gdb output").clone();
            let _ = fs::write(path, format!("{}{}", self.transcript, text));
        }
        let _ = self.child.kill();
    }
}

pub(crate) fn expect(text: &str, needles: &[&str], what: &str) -> Result<(), String> {
    for needle in needles {
        if !text.contains(needle) {
            return Err(format!(
                "{what}: gdb output lacks {needle:?}:\n{}",
                tail(text, 1800)
            ));
        }
    }
    Ok(())
}
pub(crate) fn refuse(text: &str, needles: &[&str], what: &str) -> Result<(), String> {
    for needle in needles {
        if text.contains(needle) {
            return Err(format!(
                "{what}: gdb output has {needle:?}:\n{}",
                tail(text, 1800)
            ));
        }
    }
    Ok(())
}

/// The ELF entry point of a program, from its header.
fn entry_point(path: &std::path::Path) -> Result<u64, String> {
    let header = fs::read(path).map_err(|e| e.to_string())?;
    header
        .get(24..32)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
        .ok_or_else(|| "short ELF header".to_string())
}

/// A program started with Debug on start, and the app's debugger session on it.
struct Started {
    run: String,
    info: DebugSessionInfo,
    target: Option<GuestProcessIdentity>,
}

impl Context {
    fn start_stopped(&mut self, binary: &str, args: &[&str]) -> Result<Started, String> {
        let launched = launch_program(
            &mut self.driver,
            &format!("/tmp/{binary}"),
            args.iter().map(|arg| arg.to_string()).collect(),
            true,
        )?;
        let info = self
            .driver
            .snapshot
            .debug
            .clone()
            .ok_or("Debug on start left no debugger session in the snapshot")?;
        Ok(Started {
            run: launched.run.id,
            info,
            target: None,
        })
    }
    /// Detach the app's debugger and wait for the run to end.
    fn end_started(&mut self, started: &Started, kill: bool) -> Result<(), String> {
        if self.driver.snapshot.debug.is_some() {
            self.driver.command(Command::DebugDetach { kill })?;
        } else if kill {
            self.driver.command(Command::StopRun {
                run_id: started.run.clone(),
            })?;
        }
        run_ended(&mut self.driver, &started.run, 40).map(|_| ())
    }
}

fn output_of(context: &mut Context, started: &Started) -> String {
    context.driver.receive();
    context.driver.output(&started.run).to_string()
}

/// Debug on start: nothing ran before the stop; the stop is at the entry point.
pub fn start(context: &mut Context) -> Result<String, String> {
    let started = context.start_stopped("p2fix", &["start", "30", "0"])?;
    let entry = entry_point(&context.dir.join("p2fix"))?;
    if !started.info.target_state.contains("stopped")
        && !started.info.target_state.contains("attached")
    {
        return Err(format!(
            "unexpected server state {:?}",
            started.info.target_state
        ));
    }
    thread::sleep(Duration::from_millis(1500));
    let early = output_of(context, &started);
    if early.contains("symbols") || early.contains("main reached") || early.contains("tick") {
        return Err(format!(
            "the program ran before the debugger continued it:\n{early}"
        ));
    }
    let mut gdb = Gdb::start(&context.dir)?;
    let port = started.info.tcp_port;
    let text = gdb.run(
        &format!(
            "file p2fix\ntarget remote 127.0.0.1:{port}\ninfo registers rip\nx/2i $pc\ninfo threads\ninfo symbol $pc\n\
             p/x *(long*)$rsp\np $_siginfo"
        ),
        30,
    )?;
    expect(
        &text,
        &[&format!("rip            0x{entry:x}"), "<_start>"],
        "stop at entry",
    )?;
    // Still nothing ran while gdb looked.
    let still = output_of(context, &started);
    if still.contains("symbols") || still.contains("main reached") {
        return Err("the program ran while the debugger inspected it".into());
    }
    // argc is on the stack: fixture mode, rounds, workers are three arguments plus the name.
    expect(&text, &["= 0x4"], "argc at the stack top")?;
    let text = gdb.run("break main\ncontinue\ninfo registers rip\nbt 1", 60)?;
    expect(
        &text,
        &["Breakpoint 1, 0x", " in main ()"],
        "stop at main after the entry",
    )?;
    let at_main = output_of(context, &started);
    if at_main.contains("main reached") {
        return Err("main printed before it was reached".into());
    }
    let text = gdb.run("delete\ndetach", 30)?;
    expect(
        &text,
        &["Detaching from program", "[Inferior 1 (process"],
        "detach",
    )?;
    let transcript = gdb.close(10);
    refuse(
        &transcript,
        &[
            "Cannot access memory",
            "Remote connection closed",
            "Ignoring packet error",
        ],
        "start",
    )?;
    context.driver.wait_text(&started.run, "main reached", 20)?;
    context.driver.wait_text(&started.run, "done ", 60)?;
    context.end_started(&started, false)?;
    Ok(format!(
        "stopped at the ELF entry {entry:#x} before any user output, gdb read the stack, ran to main and detached"
    ))
}

/// A position independent program: gdb relocates it from the auxiliary vector.
pub fn pie(context: &mut Context) -> Result<String, String> {
    let started = context.start_stopped("p2pie", &["start", "20", "0"])?;
    let mut gdb = Gdb::start(&context.dir)?;
    let port = started.info.tcp_port;
    let text = gdb.run(
        &format!("file p2pie\ntarget remote 127.0.0.1:{port}\ninfo registers rip\ninfo symbol $pc\nbreak main\ninfo breakpoints"),
        30,
    )?;
    expect(
        &text,
        &["_start in section .text"],
        "gdb relocated the position independent program",
    )?;
    let relocated = text
        .lines()
        .find(|line| line.contains("breakpoint") && line.contains("main"))
        .map(str::to_string)
        .unwrap_or_default();
    let text = gdb.run("continue\ninfo symbol $pc\nx/2i $pc", 60)?;
    expect(
        &text,
        &["Breakpoint 1, 0x", " in main ()", "main in section .text"],
        "main of the position independent program",
    )?;
    gdb.run("delete\ndetach", 30)?;
    let transcript = gdb.close(10);
    refuse(
        &transcript,
        &["Cannot access memory", "Remote connection closed"],
        "pie",
    )?;
    context.driver.wait_text(&started.run, "done ", 60)?;
    context.end_started(&started, false)?;
    Ok(format!(
        "a PIE (static-pie) stopped at its entry and gdb placed main from AT_ENTRY ({})",
        relocated.trim()
    ))
}

/// A dynamically linked program stops in the loader before the program's own
/// code, and gdb follows it into the program after the loader ran.
pub fn dynamic(context: &mut Context) -> Result<String, String> {
    if !context.dir.join("p2dyn").is_file() || !context.dir.join("dbgroot").is_dir() {
        return Ok("skipped: no p2dyn build or dbgroot directory beside the fixtures".into());
    }
    // gdb opens the loader and libc by the paths the guest uses (/tmp, the
    // program's interpreter and run path) under its sysroot: one that holds
    // the uploaded copies there. The host's own root would hand gdb whatever
    // the host has at /tmp/p2ld.so or /tmp/libc.so.6 instead. The auxiliary
    // vector (AT_BASE: where the loader is) is in the transcript of a failure.
    let sysroot = context.dir.join("sysroot");
    fs::create_dir_all(sysroot.join("tmp")).map_err(|e| e.to_string())?;
    for name in ["p2ld.so", "libc.so.6"] {
        fs::copy(
            context.dir.join("dbgroot").join(name),
            sysroot.join("tmp").join(name),
        )
        .map_err(|e| format!("{name}: {e}"))?;
    }
    let started = context.start_stopped("p2dyn", &["start", "20", "0"])?;
    let mut gdb = Gdb::start(&context.dir)?;
    let port = started.info.tcp_port;
    let text = gdb.run(
        &format!(
            "set sysroot {}\nfile p2dyn\ntarget remote 127.0.0.1:{port}\ninfo registers rip\ninfo symbol $pc\ninfo sharedlibrary\ninfo auxv",
            sysroot.display()
        ),
        40,
    )?;
    expect(
        &text,
        &["_start in section .text of"],
        "stopped at the loader's entry",
    )?;
    let early = output_of(context, &started);
    if early.contains("symbols") || early.contains("main reached") {
        return Err("the program ran before the debugger continued it".into());
    }
    let text = gdb.run("break main\ncontinue\ninfo sharedlibrary\nbt 1", 90)?;
    expect(
        &text,
        &["Breakpoint 1, 0x", " in main ()"],
        "main of the dynamic program",
    )?;
    gdb.run("delete\ndetach", 30)?;
    let transcript = gdb.close(10);
    refuse(
        &transcript,
        &["Cannot access memory", "Remote connection closed"],
        "dynamic",
    )?;
    context.driver.wait_text(&started.run, "done ", 60)?;
    context.end_started(&started, false)?;
    Ok("a dynamically linked program stopped at the loader's entry before running, then at main after the loader mapped libc".into())
}

/// A program that is already running, with the app's debugger attached (it keeps
/// running until a client connects).
fn start_running(context: &mut Context, binary: &str, args: &[&str]) -> Result<Started, String> {
    let launched = launch_program(
        &mut context.driver,
        &format!("/tmp/{binary}"),
        args.iter().map(|arg| arg.to_string()).collect(),
        false,
    )?;
    let info = attach(&mut context.driver, &launched.target)?;
    Ok(Started {
        run: launched.run.id,
        info,
        target: Some(launched.target),
    })
}

fn connect(context: &mut Context, started: &Started, binary: &str) -> Result<Gdb, String> {
    let mut gdb = Gdb::start(&context.dir)?;
    gdb.run(
        &format!(
            "file {binary}\ntarget remote 127.0.0.1:{}",
            started.info.tcp_port
        ),
        30,
    )?;
    Ok(gdb)
}

fn finish(context: &mut Context, started: &Started, gdb: Gdb) -> Result<String, String> {
    let transcript = gdb.close(10);
    refuse(
        &transcript,
        &[
            "Cannot access memory",
            "Remote connection closed",
            "Ignoring packet error",
            "Bad packet",
            "Malformed",
        ],
        "gdb session",
    )?;
    context.end_started(started, true)?;
    Ok(transcript)
}

/// `info threads` lists every thread; `stepi` moves only the selected one.
pub fn threads(context: &mut Context) -> Result<String, String> {
    let started = start_running(context, "p2fix", &["threads", "400", "4"])?;
    let mut gdb = connect(context, &started, "p2fix")?;
    let listing = gdb.run("info threads", 30)?;
    let count = listing
        .lines()
        .filter(|line| line.contains("Thread ") && line.contains(" in "))
        .count();
    if count != 5 {
        return Err(format!(
            "info threads lists {count} threads, wanted 5:\n{listing}"
        ));
    }
    let pcs = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|line| line.contains("$") && line.contains("= 0x"))
            .map(|line| line.rsplit("= ").next().unwrap_or("").trim().to_string())
            .collect()
    };
    let before = gdb.run("thread apply all p/x $pc", 30)?;
    let mut selected = None;
    for id in 2..=5 {
        let text = gdb.run(&format!("thread {id}\nstepi\nx/i $pc"), 40)?;
        if text.contains("0x") {
            selected = Some(id);
            break;
        }
    }
    let selected = selected.ok_or("stepi printed nothing")?;
    let after = gdb.run("thread apply all p/x $pc", 30)?;
    let (a, b) = (pcs(&before), pcs(&after));
    if a.len() != 5 || b.len() != 5 {
        return Err(format!("pc listings are not five long:\n{before}\n{after}"));
    }
    let changed = a.iter().zip(&b).filter(|(x, y)| x != y).count();
    if changed != 1 {
        return Err(format!(
            "{changed} threads moved on one stepi (before {a:?}, after {b:?})"
        ));
    }
    // A named thread step: the one thread asked for moved, others stayed stopped.
    gdb.run("thread 1\ncontinue &", 10)?;
    thread::sleep(Duration::from_millis(500));
    let after_run = output_of(context, &started);
    if !after_run.contains("tick ") {
        return Err("the program did not run after continue".into());
    }
    gdb.run("interrupt", 20)?;
    let text = gdb.run("info threads", 30)?;
    let total = text
        .lines()
        .filter(|line| line.contains("Thread "))
        .count()
        .max(5);
    let _ = finish(context, &started, gdb)?;
    Ok(format!(
        "info threads listed {count} threads; stepi on thread {selected} moved exactly one of them; continue and interrupt ({total} threads again)"
    ))
}

/// Stepping across a SYSCALL and a REP MOVSB under a real gdb.
pub fn step(context: &mut Context) -> Result<String, String> {
    let started = start_running(context, "p2fix", &["step", "400", "0"])?;
    let mut gdb = connect(context, &started, "p2fix")?;
    let text = gdb.run(
        "break step_syscall\ncontinue\ndelete\nstepi\ninfo symbol $pc\nstepi\ninfo symbol $pc\ninfo registers rax\nx/i $pc\nstepi 2\ninfo symbol $pc",
        60,
    )?;
    expect(
        &text,
        &[
            "step_syscall + 5 in section .text",
            "step_syscall + 7 in section .text",
        ],
        "stepi across SYSCALL stops at the next instruction",
    )?;
    let text = gdb.run(
        "break step_rep\ncontinue\ndelete\nstepi 3\ninfo symbol $pc\nx/i $pc\nstepi\ninfo symbol $pc\np $rcx",
        60,
    )?;
    expect(
        &text,
        &[
            "step_rep + 19 in section .text",
            "rep movs",
            "step_rep + 21 in section .text",
            "= 0",
        ],
        "stepi across REP MOVSB retires the whole copy",
    )?;
    finish(context, &started, gdb)?;
    Ok("stepi over SYSCALL ended on the next instruction (rax = pid), stepi over REP MOVSB on the instruction after it with rcx 0".into())
}

/// hbreak, watch, awatch, and running out of debug registers.
pub fn hardware(context: &mut Context) -> Result<String, String> {
    let started = start_running(context, "p2fix", &["hw", "400", "0"])?;
    let mut gdb = connect(context, &started, "p2fix")?;
    let text = gdb.run("hbreak hw_code\ncontinue\ninfo symbol $pc", 60)?;
    expect(
        &text,
        &[
            "Hardware assisted breakpoint 1 at",
            "Breakpoint 1, ",
            "hw_code in section .text",
        ],
        "hbreak",
    )?;
    let text = gdb.run("delete\nwatch *(long *)&watched\ncontinue\ncontinue", 60)?;
    expect(
        &text,
        &["Hardware watchpoint 2:", "Old value =", "New value ="],
        "watch",
    )?;
    let text = gdb.run("delete\nawatch *(long *)&watched\ncontinue\ncontinue", 60)?;
    expect(
        &text,
        &["Hardware access (read/write) watchpoint 3:", "Value ="],
        "awatch",
    )?;
    let text = gdb.run("delete\nrwatch *(long *)&watched", 20)?;
    // x86 has no read-only watchpoint: gdb explains, and the session goes on.
    if text.contains("Hardware read watchpoint 4") {
        gdb.run("delete", 10)?;
    }
    // Five instruction breakpoints do not fit in four debug registers.
    let text = gdb.run(
        "delete\nhbreak *(hw_code+0)\nhbreak *(hw_after_write+0)\nhbreak *(hw_after_read+0)\nhbreak *(step_syscall+0)\nhbreak *(step_rep+0)\ncontinue",
        60,
    )?;
    expect(
        &text,
        &[
            "Cannot insert hardware breakpoint",
            "Remote failure reply: 1c",
        ],
        "running out of debug registers is an error reply gdb shows",
    )?;
    refuse(
        &text,
        &["Remote connection closed", "Ignoring packet error"],
        "slot exhaustion",
    )?;
    // The session is still usable and the slots can be reused.
    let text = gdb.run("delete\nhbreak hw_code\ncontinue", 60)?;
    expect(
        &text,
        &["Breakpoint ", " in hw_code ()"],
        "after exhaustion",
    )?;
    finish(context, &started, gdb)?;
    Ok("hbreak and watch fired with gdb's own wording, awatch saw reads and writes, rwatch is explained as unsupported, five hbreaks gave a clean refusal and the session carried on".into())
}

/// Signal stops, passed and suppressed under gdb, and a fatal one.
pub fn signals(context: &mut Context) -> Result<String, String> {
    let started = context.start_stopped("p2fix", &["signal", "300", "0"])?;
    let mut gdb = connect(context, &started, "p2fix")?;
    let text = gdb.run("handle SIGUSR1 stop print pass\ncontinue", 60)?;
    expect(
        &text,
        &["Program received signal SIGUSR1, User defined signal 1."],
        "SIGUSR1 stop",
    )?;
    let text = gdb.run("continue", 60)?;
    expect(
        &text,
        &["Program received signal SIGUSR1"],
        "second SIGUSR1",
    )?;
    let text = gdb.run("signal 0", 60)?;
    expect(
        &text,
        &[
            "Continuing with no signal.",
            "Program received signal SIGUSR1",
        ],
        "signal 0",
    )?;
    // Dropped silently: the handler count stops rising while ticks go on.
    gdb.run("handle SIGUSR1 nostop noprint nopass", 10)?;
    let text = gdb.run("continue", 90)?;
    expect(
        &text,
        &["Program received signal SIGSEGV, Segmentation fault."],
        "SIGSEGV stop",
    )?;
    let text = gdb.run("p/x $pc\ncontinue", 90)?;
    refuse(&text, &["Program terminated", "exited"], "handled SIGSEGV")?;
    thread::sleep(Duration::from_millis(800));
    context.driver.wait_text(&started.run, "segv=1", 30)?;
    let dropped = output_of(context, &started);
    let usr1_of = |text: &str| -> Vec<u32> {
        text.lines()
            .filter_map(|l| {
                l.split("usr1=")
                    .nth(1)?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            })
            .collect()
    };
    let counts = usr1_of(&dropped);
    let last = *counts.last().ok_or("no tick")?;
    // 1 passed signal (the first), everything after dropped.
    if last > 2 {
        return Err(format!(
            "SIGUSR1 kept reaching the handler although dropped: {counts:?}"
        ));
    }
    gdb.run("interrupt", 20)?;
    gdb.run("handle SIGUSR1 nostop noprint pass\ncontinue &", 10)?;
    thread::sleep(Duration::from_millis(1500));
    let passed = usr1_of(&output_of(context, &started));
    if passed.last().copied().unwrap_or(0) <= last + 2 {
        return Err(format!(
            "SIGUSR1 did not reach the handler again once passed: {passed:?}"
        ));
    }
    if output_of(context, &started).contains("tf_in_frame=1") {
        return Err("a handler saw TF in its frame".into());
    }
    gdb.run("interrupt", 20)?;
    finish(context, &started, gdb)?;
    Ok("SIGUSR1 stopped and was passed, suppressed with signal 0 and dropped silently, then passed silently again; SIGSEGV stopped and passing it ran the program's handler".into())
}

pub fn fatal(context: &mut Context) -> Result<String, String> {
    let started = context.start_stopped("p2fix", &["fatal", "100", "0"])?;
    let mut gdb = connect(context, &started, "p2fix")?;
    let text = gdb.run("continue", 60)?;
    expect(
        &text,
        &["Program received signal SIGUSR2, User defined signal 2."],
        "SIGUSR2 stop",
    )?;
    let text = gdb.run("continue", 60)?;
    expect(
        &text,
        &["Program terminated with signal SIGUSR2, User defined signal 2."],
        "a passed fatal signal ends the program as the signal",
    )?;
    let transcript = gdb.close(10);
    refuse(&transcript, &["Remote connection closed"], "fatal signal")?;
    run_ended(&mut context.driver, &started.run, 30)?;
    Ok("a fatal signal stopped, passed with continue, and gdb reported 'terminated with signal SIGUSR2'".into())
}

/// Stop of a debugged run, running and stopped.
pub fn stop_run(context: &mut Context) -> Result<String, String> {
    // 1. The program runs under gdb's continue.
    let started = context.start_stopped("p2fix", &["start", "400", "0"])?;
    let mut gdb = connect(context, &started, "p2fix")?;
    let marker = gdb.send("continue")?;
    thread::sleep(Duration::from_millis(1500));
    let at = Instant::now();
    context.driver.command(Command::StopRun {
        run_id: started.run.clone(),
    })?;
    let text = gdb.wait(&marker, 30)?;
    expect(
        &text,
        &["Program terminated with signal SIGTERM"],
        "Stop of a running debugged program",
    )?;
    let ended = run_ended(&mut context.driver, &started.run, 30)?;
    let first = at.elapsed().as_secs_f64();
    gdb.close(10);
    // 2. The program is stopped at a breakpoint when Stop arrives.
    context
        .driver
        .command(Command::DebugDetach { kill: true })
        .ok();
    let started = context.start_stopped("p2fix", &["hw", "400", "0"])?;
    let mut gdb = connect(context, &started, "p2fix")?;
    let text = gdb.run("break hw_code\ncontinue", 60)?;
    expect(&text, &["Breakpoint 1, 0x"], "stopped at a breakpoint")?;
    let at = Instant::now();
    context.driver.command(Command::StopRun {
        run_id: started.run.clone(),
    })?;
    run_ended(&mut context.driver, &started.run, 30)?;
    let second = at.elapsed().as_secs_f64();
    let run = context
        .driver
        .snapshot
        .runs
        .iter()
        .find(|run| run.id == started.run)
        .cloned()
        .ok_or("run missing")?;
    let escalated = run
        .execution
        .as_ref()
        .is_some_and(|execution| execution.kill_escalated());
    if escalated {
        return Err("Stop of a debug-stopped program needed the SIGKILL escalation".into());
    }
    let text = gdb.run("continue", 30)?;
    refuse(
        &text,
        &["Remote connection closed"],
        "continue after the program ended",
    )?;
    gdb.close(10);
    if first > 3.0 || second > 3.0 {
        return Err(format!(
            "Stop took {first:.1} s and {second:.1} s; it should not wait for the grace period"
        ));
    }
    Ok(format!(
        "Stop ended a running debugged program in {first:.2} s (gdb: terminated with SIGTERM, root exit {ended:?}) and one stopped at a breakpoint in {second:.2} s, without the SIGKILL escalation"
    ))
}

/// A process core taken while the debugger holds the program stopped: it
/// completes, and the program is still stopped, at the same instructions.
pub fn core_under_stop(context: &mut Context) -> Result<String, String> {
    let started = start_running(context, "p2fix", &["threads", "600", "3"])?;
    let target = started.target.clone().ok_or("target")?;
    let mut gdb = connect(context, &started, "p2fix")?;
    let before = gdb.run("thread apply all p/x $pc", 30)?;
    let vm_id = context.driver.snapshot.vms[0].id.clone();
    let known: Vec<String> = context
        .driver
        .snapshot
        .process_cores
        .iter()
        .map(|core| core.id.clone())
        .collect();
    context.driver.command(Command::DumpProcessCore {
        request: ProcessCoreRequest {
            vm_id,
            target,
            source_run_id: Some(started.run.clone()),
            ..Default::default()
        },
    })?;
    context
        .driver
        .wait("core under a debug stop", 60, |snapshot| {
            snapshot
                .process_cores
                .iter()
                .any(|core| !known.contains(&core.id) && core.phase == ProcessCorePhase::Finished)
        })?;
    let core = context
        .driver
        .snapshot
        .process_cores
        .iter()
        .find(|core| !known.contains(&core.id))
        .cloned()
        .ok_or("core missing")?;
    if core.stored_size == 0 || core.file.as_ref().is_none_or(|file| !file.is_file()) {
        return Err(format!("the core did not complete: {core:?}"));
    }
    let after = gdb.run("thread apply all p/x $pc", 30)?;
    let values = |text: &str| -> Vec<String> {
        text.lines()
            .filter_map(|line| line.split("= ").nth(1).map(str::to_string))
            .collect()
    };
    if values(&before) != values(&after) {
        return Err(format!(
            "the program moved while the core was taken:\n{before}\n{after}"
        ));
    }
    let output_then = output_of(context, &started).len();
    thread::sleep(Duration::from_millis(600));
    if output_of(context, &started).len() != output_then {
        return Err("the stopped program printed while the core was taken".into());
    }
    finish(context, &started, gdb)?;
    Ok(format!(
        "a manual process core ({} bytes) completed while the debugger held the group stopped; no thread moved and the group stayed stopped",
        core.stored_size
    ))
}
