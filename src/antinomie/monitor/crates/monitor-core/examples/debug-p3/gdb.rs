// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Phase 3 through a real gdb: follow-fork-mode child and parent with
//! detach-on-fork, vfork, exec, and non-stop with several threads. Each test
//! drives one interactive gdb over pipes, a command group at a time, and also
//! reads the guest's terminal output between the groups.
use super::*;
use crate::p2::gdb::{Gdb, expect, refuse};

/// A fixture run with the app's debugger attached (it listens on a port) and a
/// gdb that has the fixture's symbols loaded and its own sysroot, so the program
/// a followed exec loads is found.
struct Session {
    run: String,
    gdb: Gdb,
    port: u16,
}

fn begin(context: &mut Context, mode: &str, rounds: u32, workers: u32) -> Result<Session, String> {
    let launched = launch_program(
        &mut context.driver,
        "/tmp/p3fix",
        // A lead-in keeps the program idle while gdb connects: a connect that lands
        // inside a fork is a gdb matter (it follows the fork before it returns).
        vec![
            mode.into(),
            rounds.to_string(),
            workers.to_string(),
            "5000".into(),
        ],
        false,
    )?;
    let info = attach(&mut context.driver, &launched.target)?;
    // gdb finds the program an exec loads under its sysroot.
    let sysroot = context.dir.join("sysroot");
    fs::create_dir_all(sysroot.join("tmp")).map_err(|e| e.to_string())?;
    fs::copy(context.dir.join("p3fix"), sysroot.join("tmp/p3fix")).map_err(|e| e.to_string())?;
    let gdb = Gdb::start(&context.dir)?;
    Ok(Session {
        run: launched.run.id,
        gdb,
        port: info.tcp_port,
    })
}

impl Session {
    fn finish(self, context: &mut Context) -> Result<String, String> {
        let transcript = self.gdb.close(10);
        let _ = context.driver.command(Command::DebugDetach { kill: true });
        // A program that ended by itself is not there to stop.
        let _ = context.driver.command(Command::StopRun {
            run_id: self.run.clone(),
        });
        run_ended(&mut context.driver, &self.run, 40)?;
        Ok(transcript)
    }
    fn output(&self, context: &mut Context) -> String {
        context.driver.receive();
        context.driver.output(&self.run).to_string()
    }
    /// The terminal output once it holds `needle` (a detached parent prints a
    /// moment after its child ended), or what there is after `seconds`.
    fn output_with(&self, context: &mut Context, needle: &str, seconds: u64) -> String {
        let until = Instant::now() + Duration::from_secs(seconds);
        loop {
            let output = self.output(context);
            if output.contains(needle) || Instant::now() >= until {
                return output;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn sysroot_line(context: &Context) -> String {
    let trace = if std::env::var_os("P3_TRACE").is_some() {
        "\nset debug remote 1"
    } else {
        ""
    };
    format!(
        "set sysroot {}\nset remote timeout 30{trace}",
        context.dir.join("sysroot").display()
    )
}

/// follow-fork-mode child with detach-on-fork on: gdb follows the child, the
/// parent is let go, the child's breakpoints hit.
pub fn follow_child(context: &mut Context) -> Result<String, String> {
    let mut session = begin(context, "fork", 60, 0)?;
    let port = session.port;
    let text = session.gdb.run(
        &format!(
            "file p3fix\n{}\nset follow-fork-mode child\ntarget remote 127.0.0.1:{port}\nbreak child_site\ncontinue",
            sysroot_line(context)
        ),
        60,
    )?;
    expect(
        &text,
        &[
            "Attaching after",
            "fork to child",
            "Detaching after fork from parent process",
            "Breakpoint 1,",
            "child_site",
        ],
        "following the child",
    )?;
    let text = session.gdb.run("info inferiors\ncontinue", 60)?;
    expect(&text, &["Breakpoint 1,"], "the second call in the child")?;
    refuse(&text, &["Program received signal SIGTRAP"], "no stray trap")?;
    let text = session.gdb.run("continue", 60)?;
    expect(&text, &["exited with code 07"], "the child's exit")?;
    session.gdb.run("kill", 20).ok();
    let output = session.output_with(context, "child exit=7 sig=0", 5);
    let transcript = session.finish(context)?;
    refuse(
        &transcript,
        &[
            "Remote connection closed",
            "Cannot access memory",
            "Ignoring packet error",
        ],
        "follow child",
    )?;
    if !output.contains("child exit=7 sig=0") {
        // The parent was detached and went on: it reports the child's end.
        return Err(format!(
            "the detached parent never saw the child exit:\n{}",
            tail(&output, 400)
        ));
    }
    Ok("follow-fork-mode child: gdb attached to the child at its fork (parent detached and still running), hit the child's breakpoint twice and saw it exit 7".into())
}

/// follow-fork-mode parent (the default): the child is detached at once, runs
/// clean, and the parent's breakpoints keep working.
pub fn follow_parent(context: &mut Context) -> Result<String, String> {
    let mut session = begin(context, "fork", 60, 0)?;
    let port = session.port;
    let text = session.gdb.run(
        &format!(
            "file p3fix\n{}\ntarget remote 127.0.0.1:{port}\nbreak parent_site\nbreak child_site\ncontinue",
            sysroot_line(context)
        ),
        60,
    )?;
    expect(
        &text,
        &["Breakpoint 1,", "parent_site"],
        "the parent's breakpoint",
    )?;
    let mut detached = 0;
    let mut parent_hits = 1;
    for _ in 0..12 {
        let text = session.gdb.run("continue", 60)?;
        if text.contains("Detaching after fork from child process") {
            detached += 1;
        }
        if text.contains("Breakpoint 1,") {
            parent_hits += 1;
        }
        if text.contains("Breakpoint 2,") {
            return Err(format!(
                "the parent stopped at the child's breakpoint:\n{text}"
            ));
        }
        if detached >= 2 {
            break;
        }
    }
    if detached < 2 {
        return Err(format!("{detached} forks seen in 12 stops"));
    }
    session.gdb.run("delete\ndetach", 30)?;
    let output = session.output(context);
    let transcript = session.finish(context)?;
    refuse(
        &transcript,
        &[
            "Remote connection closed",
            "Cannot access memory",
            "Program received signal SIGTRAP",
        ],
        "follow parent",
    )?;
    if output.contains("sig=5") {
        return Err("a detached child died of SIGTRAP".into());
    }
    Ok(format!(
        "follow-fork-mode parent: {detached} children detached at their forks and ran clean (their breakpoint byte repaired), {parent_hits} parent breakpoint hits"
    ))
}

/// detach-on-fork off: both processes are inferiors; the child waits where the
/// fork put it until the user switches to it.
pub fn keep_both(context: &mut Context) -> Result<String, String> {
    let mut session = begin(context, "fork", 60, 0)?;
    let port = session.port;
    let text = session.gdb.run(
        &format!(
            "file p3fix\n{}\nset detach-on-fork off\ntarget remote 127.0.0.1:{port}\nbreak parent_site\ncontinue",
            sysroot_line(context)
        ),
        60,
    )?;
    expect(&text, &["Breakpoint 1,"], "the first stop")?;
    // Run on to the fork: gdb follows a fork silently unless it is caught.
    session.gdb.run("catch fork", 30)?;
    let mut text = String::new();
    for _ in 0..6 {
        text = session.gdb.run("continue", 60)?;
        if text.contains("forked process") {
            break;
        }
    }
    expect(&text, &["forked process"], "the caught fork")?;
    // Resuming follows it: the child becomes an inferior and stays held, so the
    // parent blocks in waitpid until it is interrupted.
    session.gdb.run("continue &", 30)?;
    thread::sleep(Duration::from_millis(1500));
    session.gdb.run("interrupt", 30)?;
    thread::sleep(Duration::from_millis(500));
    let text = session.gdb.run("info inferiors", 30)?;
    expect(&text, &["1 ", "2 ", "process"], "two inferiors")?;
    // Look at the child: it is stopped at the fork, rax 0.
    let text = session
        .gdb
        .run("inferior 2\ninfo registers rax\nx/i $pc", 30)?;
    expect(
        &text,
        &["rax            0x0"],
        "the child's fork return value",
    )?;
    let output = session.output(context);
    if output.contains("child pid=") {
        return Err("the held child ran".into());
    }
    // Let it go: delete breakpoints (they are in the parent's address space too),
    // detach the child, and the parent carries on.
    session
        .gdb
        .run("delete\ndetach inferior 2\ninferior 1\ncontinue &", 30)?;
    thread::sleep(Duration::from_millis(800));
    let output = session.output(context);
    let transcript = session.finish(context)?;
    if !output.contains("child pid=") {
        return Err(format!(
            "the child never ran after it was detached:\n{}",
            tail(&output, 300)
        ));
    }
    refuse(
        &transcript,
        &["Remote connection closed", "Cannot access memory"],
        "detach-on-fork off",
    )?;
    Ok("detach-on-fork off: the child is a second inferior held at the fork (rax 0, no output), runs when detached".into())
}

/// vfork: follow the child through its exec (the parent is released when the
/// child execs), and follow the parent (child detached, vfork done reported).
pub fn vfork(context: &mut Context) -> Result<String, String> {
    let mut session = begin(context, "vfork", 60, 0)?;
    let port = session.port;
    let text = session.gdb.run(
        &format!(
            "file p3fix\n{}\nset follow-fork-mode child\ntarget remote 127.0.0.1:{port}\nbreak leaf_site\ncontinue",
            sysroot_line(context)
        ),
        60,
    )?;
    expect(
        &text,
        &[
            "vfork to child",
            "executing new program",
            "Breakpoint 1,",
            "leaf_site",
        ],
        "following a vfork child into its exec",
    )?;
    let text = session.gdb.run("delete\ncontinue", 60)?;
    expect(&text, &["exited with code 05"], "the leaf's exit")?;
    session.gdb.run("kill", 20).ok();
    let output = session.output_with(context, "vfork child exit=5", 5);
    let transcript = session.finish(context)?;
    refuse(
        &transcript,
        &["Remote connection closed", "Cannot access memory"],
        "vfork child",
    )?;
    if !output.contains("vfork child exit=5") {
        return Err(format!(
            "the parent never saw the vfork child exit:\n{}",
            tail(&output, 400)
        ));
    }

    // Follow the parent: the child is detached and the parent reports vfork done.
    let mut session = begin(context, "vfork", 60, 0)?;
    let port = session.port;
    let text = session.gdb.run(
        &format!(
            "file p3fix\n{}\ntarget remote 127.0.0.1:{port}\nbreak parent_site\ncontinue",
            sysroot_line(context)
        ),
        60,
    )?;
    expect(&text, &["Breakpoint 1,"], "the parent's breakpoint")?;
    let mut detached = false;
    for _ in 0..8 {
        let text = session.gdb.run("continue", 60)?;
        if text.contains("Detaching after vfork from child process") {
            detached = true;
            break;
        }
    }
    if !detached {
        return Err("no vfork reached gdb".into());
    }
    let text = session.gdb.run("delete\ncontinue &", 30)?;
    refuse(&text, &["Cannot access memory"], "after the vfork")?;
    thread::sleep(Duration::from_millis(1500));
    let output = session.output(context);
    let transcript = session.finish(context)?;
    refuse(
        &transcript,
        &[
            "Remote connection closed",
            "Program received signal SIGTRAP",
        ],
        "vfork parent",
    )?;
    if !output.contains("vfork child exit=5") || !output.contains("tick 3") {
        return Err(format!(
            "the parent did not go on after the vfork:\n{}",
            tail(&output, 400)
        ));
    }
    Ok("vfork: follow-fork-mode child went through the exec (executing new program, breakpoint in the leaf, exit 5); follow parent detached the child and the parent ran on after vfork done".into())
}

/// exec is reported and the session goes on in the new image.
pub fn exec(context: &mut Context) -> Result<String, String> {
    let mut session = begin(context, "exec", 6, 2)?;
    let port = session.port;
    let text = session.gdb.run(
        &format!(
            "file p3fix\n{}\ntarget remote 127.0.0.1:{port}\nbreak parent_site\ncontinue",
            sysroot_line(context)
        ),
        60,
    )?;
    expect(&text, &["Breakpoint 1,"], "the first stop")?;
    // gdb follows an exec silently unless it is caught.
    session.gdb.run("catch exec", 30)?;
    let mut text = String::new();
    for _ in 0..10 {
        text = session.gdb.run("continue", 60)?;
        if text.contains("executing new program") {
            break;
        }
    }
    expect(
        &text,
        &["executing new program", "/tmp/p3fix"],
        "the exec event",
    )?;
    let text = session.gdb.run(
        "info inferiors\ninfo threads\nbreak leaf_site\ncontinue",
        60,
    )?;
    expect(
        &text,
        &["Breakpoint 3,", "leaf_site"],
        "a breakpoint in the new image",
    )?;
    session.gdb.run("delete\ncontinue", 60)?;
    let output = session.output(context);
    let transcript = session.finish(context)?;
    refuse(
        &transcript,
        &["Remote connection closed", "Cannot access memory"],
        "exec",
    )?;
    if !output.contains("leaf pid=") {
        return Err("the new image never ran".into());
    }
    Ok("exec: gdb was told (executing new program: /tmp/p3fix), set a breakpoint in the new image and hit it".into())
}

/// Non-stop: one thread stops while the others run.
pub fn nonstop(context: &mut Context) -> Result<String, String> {
    let mut session = begin(context, "nonstop", 600, 4)?;
    let port = session.port;
    let text = session.gdb.run(
        &format!(
            "file p3fix\n{}\nset non-stop on\nset pagination off\ntarget extended-remote 127.0.0.1:{port}\ninfo threads",
            sysroot_line(context)
        ),
        60,
    )?;
    expect(&text, &["Id   Target Id"], "the thread list in non-stop")?;
    session.gdb.run("break work", 30)?;
    session.gdb.send("continue -a")?;
    thread::sleep(Duration::from_millis(1500));
    let text = session.gdb.run("info threads", 30)?;
    let stopped = text.matches("(stopped)").count();
    if stopped < 3 {
        return Err(format!("only {stopped} threads stopped:\n{text}"));
    }
    // Take the breakpoint out and run one thread on its own; the others stay
    // stopped.
    session.gdb.run("delete\nthread 2\ncontinue &", 30)?;
    thread::sleep(Duration::from_millis(500));
    let text = session.gdb.run("info threads", 30)?;
    // The main thread only ticks and never stopped; thread 2 runs alone among
    // the workers, and the other workers stay stopped.
    let line = |id: &str| {
        text.lines()
            .find(|line| line.trim_start_matches(['*', ' ']).starts_with(id))
            .unwrap_or("")
            .to_string()
    };
    let held = (3..=5)
        .filter(|id| line(&format!("{id} ")).contains("(stopped)"))
        .count();
    if !line("2 ").contains("(running)") || held != 3 {
        return Err(format!(
            "after continuing thread 2 alone ({held} others held):\n{text}"
        ));
    }
    // Interrupt it and read its registers.
    let text = session.gdb.run("interrupt\ninfo registers rip", 30)?;
    refuse(
        &text,
        &["Remote connection closed"],
        "interrupt in non-stop",
    )?;
    session.gdb.run("continue -a &", 30)?;
    // Every thread runs again; the guest takes a moment to let go of them.
    let mut text = String::new();
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(500));
        text = session.gdb.run("info threads", 30)?;
        if !text.contains("(stopped)") {
            break;
        }
    }
    if text.contains("(stopped)") {
        return Err(format!("continue -a left threads stopped:\n{text}"));
    }
    session.gdb.run("interrupt -a\ndetach", 30)?;
    let transcript = session.finish(context)?;
    // gdb in extended-remote mode expects the connection to outlive a detach and
    // says so once the detach is done; that is not a failure of the detach.
    let before_detach = transcript.split("detached]").next().unwrap_or("");
    refuse(
        before_detach,
        &["Remote connection closed", "Cannot access memory"],
        "non-stop",
    )?;
    expect(&transcript, &["detached]"], "the detach")?;
    Ok(format!(
        "non-stop: {stopped} threads stopped at the breakpoint while the others ran; one thread continued alone; interrupt and continue -a worked; detach left the program running"
    ))
}
