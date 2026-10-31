// SPDX-License-Identifier: GPL-3.0-only
//! Keeping wireproxy and tor tied to the app's life.
//!
//! A helper started for a route must not outlive the app, whatever kills the
//! app (SIGKILL, a crash, the OOM killer). Two layers:
//!
//! * **Death signal.** The kernel sends SIGKILL to the helper when its
//!   parent dies (`PR_SET_PDEATHSIG`). The signal follows the parent
//!   *thread*, not the process, so every helper is started by one thread
//!   that lives as long as the app ([`spawn`] hands the command to it).
//! * **Recorded PID file.** Each helper writes `<name>-<pid>.pid` in the
//!   helpers folder of the data directory, with its start time. The next
//!   start ([`reap_stale`]) ends a helper whose file is still there and whose
//!   process has that same start time. A reused PID has another start time
//!   and is never touched. No name matching of any kind.
//!
//! Each helper also leads its own process group, so the cleanup ends its
//! children with it and a terminal's Ctrl-C does not reach it alone.
use rustix::process::{Pid, Signal, kill_process_group, set_parent_process_death_signal};
use std::{
    fs,
    io::{self, Write},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{
        Mutex, OnceLock,
        mpsc::{self, Sender},
    },
    thread,
    time::{Duration, Instant},
};

/// A command for the spawner thread and where to send the child.
type Job = (Command, Sender<io::Result<Child>>);

/// The folder of the PID files, inside the data directory.
pub(crate) fn helpers_dir(data_dir: &Path) -> PathBuf {
    super::config::network_dir(data_dir).join("helpers")
}

/// Ends the helpers an earlier session of the app left behind (see
/// [`reap_stale`]); one line per helper ended. Call it once at start, while
/// the app owns `data_dir`.
pub fn reap_stale_helpers(data_dir: &Path) -> Vec<String> {
    reap_stale(&helpers_dir(data_dir))
}

/// Field 22 of `/proc/<pid>/stat`: the process's start time in clock ticks
/// since boot. `None` when the process does not exist.
/// A process that has ended but is not yet waited for (a zombie) has none.
pub(crate) fn start_time(pid: u32) -> Option<u64> {
    parse_start_time(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

pub(super) fn parse_start_time(stat: &str) -> Option<u64> {
    // The command name (field 2) may hold spaces and parentheses: the fields
    // that follow start after the last ')'.
    let mut fields = stat[stat.rfind(')')? + 1..].split_whitespace();
    // `fields` starts at field 3 (the state); field 22 is the 20th.
    if fields.next()? == "Z" {
        return None;
    }
    fields.nth(18)?.parse().ok()
}

fn spawner() -> &'static Mutex<Sender<Job>> {
    static SPAWNER: OnceLock<Mutex<Sender<Job>>> = OnceLock::new();
    SPAWNER.get_or_init(|| {
        let (sender, jobs) = mpsc::channel::<Job>();
        // Never exits while the app runs: the death signal follows this thread.
        thread::Builder::new()
            .name("helper-spawner".into())
            .spawn(move || {
                for (mut command, reply) in jobs {
                    let _ = reply.send(command.spawn());
                }
            })
            .expect("the helper spawner thread starts");
        Mutex::new(sender)
    })
}

/// A recorded helper: removes its PID file when dropped.
pub(crate) struct Record(Option<PathBuf>);

impl Drop for Record {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

/// Starts `command` as a helper that dies with the app and is recorded in
/// `dir` (created owner-only). The child leads a new process group.
pub(crate) fn spawn(
    mut command: Command,
    dir: &Path,
    name: &str,
) -> Result<(Child, Record), String> {
    crate::storage::private_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let parent = std::process::id();
    command.process_group(0);
    // SAFETY: only async-signal-safe calls (prctl, getppid) run between fork
    // and exec; nothing allocates.
    unsafe {
        command.pre_exec(move || {
            set_parent_process_death_signal(Some(Signal::KILL))?;
            // The parent may have died before the signal was armed.
            if rustix::process::getppid().map(|p| p.as_raw_pid() as u32) != Some(parent) {
                return Err(io::Error::other("the app ended while the helper started"));
            }
            Ok(())
        });
    }
    let (reply, answer) = mpsc::channel();
    spawner()
        .lock()
        .map_err(|_| "the helper spawner is unavailable".to_owned())?
        .send((command, reply))
        .map_err(|_| "the helper spawner is unavailable".to_owned())?;
    let child = answer
        .recv()
        .map_err(|_| "the helper spawner is unavailable".to_owned())?
        .map_err(|e| e.to_string())?;
    let record = match write_record(dir, name, child.id()) {
        Ok(record) => record,
        Err(error) => {
            end_group(child.id());
            let mut child = child;
            let _ = child.wait();
            return Err(format!("cannot record the {name} process: {error}"));
        }
    };
    Ok((child, record))
}

pub(super) fn write_record(dir: &Path, name: &str, pid: u32) -> io::Result<Record> {
    // A helper that already ended has nothing to leave behind: no file, and
    // the caller finds out from the child itself.
    let Some(started) = start_time(pid) else {
        return Ok(Record(None));
    };
    let path = dir.join(format!("{name}-{pid}.pid"));
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?
        .write_all(format!("{pid} {started}\n").as_bytes())?;
    Ok(Record(Some(path)))
}

/// SIGKILL to the process group led by `pid` (the helper and its children).
pub(super) fn end_group(pid: u32) {
    if let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) {
        let _ = kill_process_group(pid, Signal::KILL);
    }
}

/// A PID file's `(pid, start time)`.
pub(super) fn parse_record(text: &str) -> Option<(u32, u64)> {
    let mut fields = text.split_whitespace();
    let pid = fields.next()?.parse().ok()?;
    let started = fields.next()?.parse().ok()?;
    fields.next().is_none().then_some((pid, started))
}

/// Ends the helpers a previous run of the app left behind and removes their
/// PID files; returns one line per helper ended. Call it only while this app
/// owns the data directory (no other instance can have live helpers there).
///
/// A file whose process is gone, or has another start time (the PID was
/// reused), is just removed. Only a process with the recorded PID *and*
/// start time is ended, as a group, and only a group it leads.
pub(crate) fn reap_stale(dir: &Path) -> Vec<String> {
    let mut ended = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return ended;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pid") {
            continue;
        }
        let record = fs::read_to_string(&path)
            .ok()
            .and_then(|text| parse_record(&text));
        if let Some((pid, started)) = record
            && start_time(pid) == Some(started)
        {
            end_group(pid);
            let deadline = Instant::now() + Duration::from_secs(3);
            while start_time(pid) == Some(started) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            ended.push(format!(
                "ended {} left running by an earlier session (process {pid})",
                entry.file_name().to_string_lossy()
            ));
        }
        let _ = fs::remove_file(&path);
    }
    ended
}
