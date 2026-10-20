// SPDX-License-Identifier: MIT
//! Running optional local tools inside the analysis sandbox: bounded output,
//! a wall-clock timeout and an explicit environment.
use std::{
    io::Read,
    os::unix::process::{CommandExt, ExitStatusExt},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

pub(crate) struct Run {
    pub stdout: String,
    /// Diagnostics captured when the caller asked for them.
    pub stderr: String,
    /// Output reached `max_output` and was cut.
    pub truncated: bool,
    /// The tool ran out of time and was stopped.
    pub timed_out: bool,
    pub success: bool,
    /// Exit status, when the tool exited by itself.
    pub code: Option<i32>,
    /// Signal that ended the tool, when it was killed.
    pub signal: Option<i32>,
}

/// Lines of a tool's output that name an error: `Error…`/`E:` prefixes or the
/// word "error", never the Info/Notice lines a tool prints at startup. At most
/// `limit` distinct lines of 300 characters; when nothing matches, the last
/// diagnostic line stands in so a crash is never reported without a cause.
pub(crate) fn error_lines(texts: &[&str], limit: usize) -> Vec<String> {
    let lines = || texts.iter().flat_map(|text| text.lines()).map(str::trim);
    let startup = |line: &str| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("info") || lower.starts_with("notice") || lower.is_empty()
    };
    let mut found = Vec::new();
    for line in lines() {
        let lower = line.to_ascii_lowercase();
        let named = line.starts_with("Error") || line.starts_with("E:") || lower.contains("error");
        if named && !startup(line) && !lower.contains("rules successfully loaded") {
            let line: String = line.chars().take(300).collect();
            if !found.contains(&line) {
                found.push(line);
            }
        }
        if found.len() == limit {
            return found;
        }
    }
    if found.is_empty()
        && let Some(last) = texts
            .first()
            .and_then(|text| text.lines().map(str::trim).rfind(|line| !startup(line)))
    {
        found.push(last.chars().take(300).collect());
    }
    found
}

impl Run {
    /// Why the tool did not finish cleanly, or `None` when it did: "timed out
    /// after 100 s", "exited with code 1" or "was killed by signal 11".
    pub(crate) fn failure(&self, timeout: Duration) -> Option<String> {
        if self.timed_out {
            return Some(format!("timed out after {} s", timeout.as_secs().max(1)));
        }
        if self.success {
            return None;
        }
        Some(match (self.code, self.signal) {
            (Some(code), _) => format!("exited with code {code}"),
            (None, Some(signal)) => format!("was killed by signal {signal}"),
            (None, None) => "did not finish".to_owned(),
        })
    }

    /// `failure` with the tool's name and its real error lines:
    /// "Suricata exited with code 1: Error: …; Error: …".
    pub(crate) fn failure_text(&self, tool: &str, timeout: Duration) -> Option<String> {
        let failure = self.failure(timeout)?;
        let lines = error_lines(&[&self.stderr, &self.stdout], 4);
        Some(if lines.is_empty() {
            format!("{tool} {failure} without printing an error")
        } else {
            format!("{tool} {failure}: {}", lines.join("; "))
        })
    }
}

/// First existing executable among `candidates`.
pub(super) fn find(candidates: &[&'static str]) -> Option<&'static str> {
    candidates
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
}

/// A tool: the system's copy first, then the one Antinomie installed
/// (mounted at `analysis_tools::SANDBOX_DIR`).
/// `ANTINOMIE_ANALYSIS_TOOLS=managed` (passed in from the host) prefers the
/// copy Antinomie installed over the system's.
pub(super) fn find_tool(system: &[&'static str], managed: &'static str) -> Option<&'static str> {
    let managed = Path::new(managed).is_file().then_some(managed);
    if std::env::var("ANTINOMIE_ANALYSIS_TOOLS").as_deref() == Ok("managed") {
        managed.or_else(|| find(system))
    } else {
        find(system).or(managed)
    }
}

/// Run `path` with `args`; `env` adds to a cleared environment with
/// `LC_ALL=C` and a standard `PATH`.
pub(super) fn run(
    path: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
    max_output: usize,
) -> Result<Run, String> {
    run_with(path, args, env, timeout, max_output, false)
}

/// `run`, optionally passing the tool's diagnostics on to worker.log.
pub(super) fn run_with(
    path: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
    max_output: usize,
    log_stderr: bool,
) -> Result<Run, String> {
    run_cancellable(
        path,
        args,
        env,
        timeout,
        max_output,
        log_stderr,
        &AtomicBool::new(false),
    )
}

/// [`run_with`], stopping the tool when `cancel` is set.
pub(crate) fn run_cancellable(
    path: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
    max_output: usize,
    log_stderr: bool,
    cancel: &AtomicBool,
) -> Result<Run, String> {
    let mut command = Command::new(path);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        // The sandbox has no passwd database; tools that ask for the user
        // name (Python's getpass) take it from here.
        .env("USER", "analysis")
        .env("LOGNAME", "analysis")
        .current_dir("/tmp")
        // Its own process group, so a timeout stops the tool's children too
        // (capa's PyInstaller launcher forks the real interpreter).
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(if log_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().map_err(|e| format!("{path}: {e}"))?;
    let stdout = child.stdout.take().ok_or("tool stdout unavailable")?;
    let stderr = child.stderr.take();
    let reader = read_pipe(stdout, max_output);
    let error_reader = stderr.map(|stderr| read_pipe(stderr, max_output));
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait().map_err(|e| format!("{path}: {e}"))? {
            Some(status) => break status,
            None if cancel.load(Ordering::Relaxed) => {
                kill_group(&mut child);
                return Err("cancelled".into());
            }
            None if Instant::now() >= deadline => {
                timed_out = true;
                kill_group(&mut child);
                break child.wait().map_err(|e| format!("{path}: {e}"))?;
            }
            None => thread::sleep(Duration::from_millis(50)),
        }
    };
    // The tool exited; anything it left behind in its group is stopped so the
    // pipes reach end of file.
    let _ = rustix::process::kill_process_group(group(&child), rustix::process::Signal::KILL);
    let output_wait = if timed_out {
        KILLED_PIPE_WAIT
    } else {
        PIPE_WAIT
    };
    let mut output = reader.collect(output_wait);
    let stderr = error_reader.map_or_else(Vec::new, |reader| reader.collect(output_wait));
    let truncated = output.len() > max_output || stderr.len() > max_output;
    output.truncate(max_output);
    let stderr = String::from_utf8_lossy(&stderr[..stderr.len().min(max_output)]).into_owned();
    Ok(Run {
        stdout: String::from_utf8_lossy(&output).into_owned(),
        stderr,
        truncated,
        timed_out,
        success: status.success(),
        code: status.code(),
        signal: status.signal(),
    })
}

/// Longest wait for a pipe to close after the tool exited normally, and after
/// it was killed. A grandchild that escaped the group keeps a pipe open; its
/// output is abandoned rather than blocking the worker.
const PIPE_WAIT: Duration = Duration::from_secs(30);
const KILLED_PIPE_WAIT: Duration = Duration::from_secs(2);

struct PipeReader(mpsc::Receiver<Vec<u8>>);

impl PipeReader {
    fn collect(self, wait: Duration) -> Vec<u8> {
        self.0.recv_timeout(wait).unwrap_or_default()
    }
}

fn read_pipe(mut pipe: impl Read + Send + 'static, max_output: usize) -> PipeReader {
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let mut output = Vec::new();
        let _ = (&mut pipe)
            .take(max_output as u64 + 1)
            .read_to_end(&mut output);
        // Hand the output over first: draining the rest only keeps the tool
        // from blocking on a full pipe.
        let _ = send.send(output);
        let _ = std::io::copy(&mut pipe, &mut std::io::sink());
    });
    PipeReader(receive)
}

fn group(child: &Child) -> rustix::process::Pid {
    rustix::process::Pid::from_raw(child.id() as i32).expect("child pid is positive")
}

/// SIGKILL the tool's whole process group, then reap the tool.
fn kill_group(child: &mut Child) {
    let _ = rustix::process::kill_process_group(group(child), rustix::process::Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
}

/// The first line a tool prints for `args` (its version), or the tool name.
pub(super) fn version(path: &str, args: &[&str]) -> String {
    run(path, args, &[], Duration::from_secs(20), 4096)
        .ok()
        .and_then(|run| run.stdout.lines().next().map(|l| l.trim().to_owned()))
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| {
            Path::new(path)
                .file_name()
                .map_or(path.to_owned(), |n| n.to_string_lossy().into_owned())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_lines_keep_real_errors_and_drop_startup_notices() {
        let stderr = "Notice: suricata: This is Suricata version 8.0.7\nInfo: cpu: 12 cores\nWarning: detect-reference: unknown reference key \"cve\"\nError: pcap: failed to get first packet timestamp. pcap_next_ex(): -2\nError: pcap: pcap file reader thread failed to initialize\nInfo: detect: 1 rule files processed. 52662 rules successfully loaded, 0 rules failed\n";
        let lines = error_lines(
            &[
                stderr,
                "E: also an error\nError: pcap: failed to get first packet timestamp. pcap_next_ex(): -2",
            ],
            5,
        );
        assert_eq!(
            lines,
            [
                "Error: pcap: failed to get first packet timestamp. pcap_next_ex(): -2",
                "Error: pcap: pcap file reader thread failed to initialize",
                "E: also an error",
            ]
        );
        let long = format!("Error: {}", "x".repeat(900));
        assert_eq!(error_lines(&[&long], 1)[0].chars().count(), 300);
        let many = "Error: a\nError: b\nError: c\n";
        assert_eq!(error_lines(&[many], 2).len(), 2);
        // A crash without an error line still names its last diagnostic.
        assert_eq!(
            error_lines(&["Info: start\nSegmentation fault\n", ""], 4),
            ["Segmentation fault"]
        );
        assert!(error_lines(&["Info: only startup\n", "Notice: ok"], 4).is_empty());
    }

    #[test]
    fn failures_name_the_exit_code_the_signal_or_the_timeout() {
        let run = |sh: &str, timeout: Duration| {
            run_with("/bin/sh", &["-c", sh], &[], timeout, 4096, true).unwrap()
        };
        let long = Duration::from_secs(10);
        let ok = run("echo Info: fine", long);
        assert_eq!(ok.failure(long), None);
        assert_eq!(ok.failure_text("Tool", long), None);
        let failed = run(
            "echo 'Error: bad input' >&2; echo 'Info: hello'; exit 3",
            long,
        );
        assert_eq!(failed.code, Some(3));
        assert_eq!(
            failed.failure_text("Tool", long).as_deref(),
            Some("Tool exited with code 3: Error: bad input")
        );
        let killed = run("kill -SEGV $$", long);
        assert_eq!(killed.signal, Some(11));
        assert_eq!(
            killed.failure_text("Tool", long).as_deref(),
            Some("Tool was killed by signal 11 without printing an error")
        );
        let slow = Duration::from_secs(1);
        let timed = run("echo 'Error: stuck' >&2; sleep 5", slow);
        assert_eq!(
            timed.failure_text("Tool", slow).as_deref(),
            Some("Tool timed out after 1 s: Error: stuck")
        );
    }

    /// A launcher that forks a worker which keeps stdout open (capa's
    /// PyInstaller layout): the timeout must stop the worker too and return.
    #[test]
    fn a_timeout_kills_the_whole_process_group() {
        let dir = std::env::temp_dir().join(format!("ant-group-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("grandchild.pid");
        let script = format!("(sleep 300 & echo $! > {}; wait) & wait", pidfile.display());
        let timeout = Duration::from_secs(1);
        let started = Instant::now();
        let run = run_with("/bin/sh", &["-c", &script], &[], timeout, 4096, true).unwrap();
        let took = started.elapsed();
        assert!(run.timed_out, "timed_out");
        assert!(took < Duration::from_secs(4), "returned after {took:?}");
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let gone = (0..40).any(|_| {
            thread::sleep(Duration::from_millis(50));
            !Path::new(&format!("/proc/{pid}/stat")).exists()
                || std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .is_ok_and(|stat| stat.contains(") Z"))
        });
        assert!(gone, "grandchild {pid} still running");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leftover_children_of_a_finished_tool_do_not_hold_the_pipe() {
        let started = Instant::now();
        let run = run_with(
            "/bin/sh",
            &["-c", "sleep 300 & echo done"],
            &[],
            Duration::from_secs(20),
            4096,
            false,
        )
        .unwrap();
        assert_eq!(run.stdout.trim(), "done");
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
