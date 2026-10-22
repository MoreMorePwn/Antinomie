// SPDX-License-Identifier: GPL-3.0-only
//! Owned bubblewrap namespace lifecycle shared by noninteractive host tools.
//! Command builders call prepare before bwrap's target `--`, then drop Command
//! after spawning and adopt the Child infallibly. Never discard a false/error
//! cleanup owner; the caller retains it and exposes pending status.
use std::{
    fs::{self, File},
    io::Read,
    os::{
        fd::OwnedFd,
        unix::{fs::MetadataExt, net::UnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const MAX_SANDBOX_INFO_SIZE: usize = 8192;
const MAX_SANDBOX_CHILDREN: usize = 64;

/// Private metadata reader plus the launcher's host PID-namespace baseline.
pub(crate) struct LaunchInfo {
    info: UnixStream,
    namespace: u64,
    depth: usize,
}

/// | Item | Purpose |
/// |---|---|
/// | `command` | bwrap command/options, positioned before its target `--`; stdout/stderr are preserved. |
/// | Return | Opaque info reader adopted with the spawned Child; no child exists on error. |
pub(crate) fn prepare(command: &mut Command) -> Result<LaunchInfo, String> {
    let host = process_identity(std::process::id())?.ok_or("host process identity unavailable")?;
    let namespace = host
        .namespace
        .ok_or("host PID namespace identity unavailable")?;
    let (info, writer) = UnixStream::pair().map_err(|e| format!("sandbox info channel: {e}"))?;
    info.set_nonblocking(true)
        .map_err(|e| format!("sandbox info channel: {e}"))?;
    // Only these owned descriptors are inherited. bwrap closes fd0 before exec;
    // supported noninteractive tools consume file arguments, never stdin.
    command
        .args(["--info-fd", "0"])
        .process_group(0)
        .stdin(Stdio::from(OwnedFd::from(writer)));
    Ok(LaunchInfo {
        info,
        namespace,
        depth: host.namespace_pids.len(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    parent: u32,
    group: u32,
    started: u64,
    state: u8,
    namespace: Option<u64>,
    namespace_pids: Vec<u32>,
}

fn process_file(path: &Path, limit: usize) -> Result<Option<String>, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("sandbox process metadata: {error}")),
    };
    read_process_text(file, limit)
}

/// A task reaped between `open` and `read` (a fast sandbox init collected by
/// its launcher) makes the read fail with ESRCH, not the open with ENOENT; both
/// mean the process is gone.
fn read_process_text(file: File, limit: usize) -> Result<Option<String>, String> {
    let mut text = String::new();
    match file.take((limit + 1) as u64).read_to_string(&mut text) {
        Ok(_) => {}
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) => {
            return Ok(None);
        }
        Err(error) => return Err(format!("sandbox process metadata: {error}")),
    }
    if text.len() > limit {
        return Err("sandbox process metadata exceeds its bound".into());
    }
    Ok(Some(text))
}

fn process_identity(pid: u32) -> Result<Option<ProcessIdentity>, String> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let Some(stat) = process_file(&root.join("stat"), 4096)? else {
        return Ok(None);
    };
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or("invalid sandbox process stat")?;
    let fields = fields.split_whitespace().collect::<Vec<_>>();
    let field = |index: usize| fields.get(index).ok_or("short sandbox process stat");
    let number = |index: usize| -> Result<u64, String> {
        field(index)?
            .parse()
            .map_err(|_| "invalid sandbox process stat number".into())
    };
    let Some(status) = process_file(&root.join("status"), 8192)? else {
        return Ok(None);
    };
    let namespace_pids = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .ok_or("sandbox process has no namespace PID identity")?
        .split_whitespace()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| "invalid namespace PID".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if namespace_pids.is_empty() || namespace_pids.len() > 64 {
        return Err("invalid sandbox namespace PID depth".into());
    }
    let namespace = match fs::metadata(root.join("ns/pid")) {
        Ok(metadata) => Some(metadata.ino()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            None
        }
        Err(error) => return Err(format!("sandbox namespace identity: {error}")),
    };
    Ok(Some(ProcessIdentity {
        parent: u32::try_from(number(1)?).map_err(|_| "invalid process parent")?,
        group: u32::try_from(number(2)?).map_err(|_| "invalid process group")?,
        started: number(19)?,
        state: *field(0)?
            .as_bytes()
            .first()
            .ok_or("invalid process state")?,
        namespace,
        namespace_pids,
    }))
}

fn same_child_identity(before: &ProcessIdentity, after: &ProcessIdentity) -> bool {
    // setsid changes a legitimate init's process group; parent and birth time
    // remain its identity. Group-only termination separately requires STOP.
    before.parent == after.parent && before.started == after.started
}

fn pidfd_exited(fd: &OwnedFd) -> Result<bool, String> {
    let mut polls = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
    rustix::event::poll(
        &mut polls,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map_err(|e| format!("sandbox process handle poll: {e}"))?;
    Ok(polls[0].revents().contains(rustix::event::PollFlags::IN))
}

struct SandboxInit {
    fd: OwnedFd,
    /// Only a verified namespace init can be signaled individually; an early
    /// child with inaccessible namespaces is terminated through its owned group.
    namespace_init: bool,
}

/// One unreaped launcher anchors its group ID; one pidfd anchors its namespace init.
pub(crate) struct SandboxProcess {
    child: std::process::Child,
    info: UnixStream,
    info_data: Vec<u8>,
    info_eof: bool,
    init: Option<SandboxInit>,
    launcher_identity: Option<ProcessIdentity>,
    parent_namespace: u64,
    parent_depth: usize,
    stop_requested: bool,
    completed_status: Option<std::process::ExitStatus>,
    init_known_dead: bool,
    reaped: bool,
    group_killed: bool,
}
impl SandboxProcess {
    /// Adopt the spawned child before any fallible process metadata probe.
    pub(crate) fn adopt(child: std::process::Child, launch: LaunchInfo) -> Self {
        Self {
            child,
            info: launch.info,
            info_data: Vec::new(),
            info_eof: false,
            init: None,
            launcher_identity: None,
            parent_namespace: launch.namespace,
            parent_depth: launch.depth,
            stop_requested: false,
            completed_status: None,
            init_known_dead: false,
            reaped: false,
            group_killed: false,
        }
    }

    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }
    pub(crate) fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }
    pub(crate) fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.stderr.take()
    }

    fn refresh_launcher(&mut self) -> Result<(), String> {
        if self.reaped {
            return Ok(());
        }
        let mut identity =
            process_identity(self.child.id())?.ok_or("owned sandbox launcher disappeared")?;
        if self
            .launcher_identity
            .as_ref()
            .is_some_and(|previous| previous.started != identity.started)
        {
            return Err("owned launcher identity changed".into());
        }
        if let Some(previous) = &self.launcher_identity {
            identity.namespace = identity.namespace.or(previous.namespace);
        }
        identity.namespace = identity.namespace.or(Some(self.parent_namespace));
        self.launcher_identity = Some(identity);
        Ok(())
    }

    fn group(&self) -> Result<rustix::process::Pid, String> {
        i32::try_from(self.child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| "invalid owned sandbox group".into())
    }

    fn pin_init(&mut self, pid: u32, namespace: Option<u64>) -> Result<(), String> {
        if self.init.is_some() || self.init_known_dead {
            return Ok(());
        }
        let Some(before) = process_identity(pid)? else {
            self.init_known_dead = true;
            return Ok(());
        };
        let raw_pid = pid;
        let pid = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or("invalid sandbox init PID")?;
        let fd = match rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::SRCH) => {
                self.init_known_dead = true;
                return Ok(());
            }
            Err(error) => return Err(format!("sandbox init process handle: {error}")),
        };
        // A monitor can exit before its dying init is observed. Dead numeric
        // PIDs cannot still identify a live original init, even after reuse;
        // this path never signals the observed process.
        if pidfd_exited(&fd)? {
            self.init_known_dead = true;
            return Ok(());
        }
        if before.parent != self.child.id() {
            if self.launcher_exited()?
                || process_identity(self.child.id())?.is_some_and(|launcher| launcher.state == b'Z')
            {
                // The init may already be reparented while its death signal is
                // pending. Keep the launcher anchor and wait for proof of death;
                // never acquire authority to signal this unverified live PID.
                return Ok(());
            }
            return Err("sandbox child parent does not match owned launcher".into());
        }
        let Some(after) = process_identity(raw_pid)? else {
            return if pidfd_exited(&fd)? {
                self.init_known_dead = true;
                Ok(())
            } else {
                Err("sandbox init identity disappeared".into())
            };
        };
        if pidfd_exited(&fd)? {
            self.init_known_dead = true;
            return Ok(());
        }
        if !same_child_identity(&before, &after) {
            if before.started == after.started
                && after.parent != self.child.id()
                && (self.launcher_exited()?
                    || process_identity(self.child.id())?
                        .is_some_and(|launcher| launcher.state == b'Z'))
            {
                return Ok(());
            }
            return Err("sandbox init identity changed while pinning".into());
        }
        let namespace_init = before.namespace_pids.last() == Some(&1)
            && after.namespace_pids.last() == Some(&1)
            && before.namespace_pids.len() > self.parent_depth
            && after.namespace_pids.len() > self.parent_depth
            && before.namespace.is_some()
            && before.namespace != Some(self.parent_namespace)
            && before.namespace == after.namespace
            && namespace.is_none_or(|expected| before.namespace == Some(expected));
        if !namespace_init
            && (before.group != self.child.id()
                || after.group != self.child.id()
                || !matches!(after.state, b'T' | b't'))
        {
            if before.namespace.is_none() || after.namespace.is_none() {
                // exit_nsproxy can remove proc namespace links before pidfd
                // exit becomes observable. Missing metadata conveys no signal
                // authority; defer until death or a verifiable identity.
                return Ok(());
            }
            return Err("escaped sandbox child namespace ownership is unverified".into());
        }
        self.init = Some(SandboxInit { fd, namespace_init });
        Ok(())
    }

    fn refresh_init(&mut self) -> Result<(), String> {
        self.refresh_launcher()?;
        if self.init.is_some() || self.init_known_dead {
            return Ok(());
        }
        let mut chunk = [0; 1024];
        while !self.info_eof {
            match self.info.read(&mut chunk) {
                Ok(0) => {
                    self.info_eof = true;
                    break;
                }
                Ok(count) => {
                    if self.info_data.len() + count > MAX_SANDBOX_INFO_SIZE {
                        return Err("sandbox info exceeds its 8 KiB bound".into());
                    }
                    self.info_data.extend_from_slice(&chunk[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(format!("sandbox info read: {error}")),
            }
        }
        if self.info_data.is_empty() {
            return Ok(());
        }
        let info: serde_json::Value = match serde_json::from_slice(&self.info_data) {
            Ok(info) => info,
            Err(error) if error.is_eof() && !self.info_eof => return Ok(()),
            Err(error) => return Err(format!("invalid sandbox info: {error}")),
        };
        let pid = info
            .get("child-pid")
            .and_then(|value| value.as_u64())
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid != 0)
            .ok_or("invalid sandbox info child PID")?;
        let namespace = match info.get("pid-namespace") {
            None => None, // Older bwrap: independently verify the live proc namespace.
            Some(value) => Some(
                value
                    .as_u64()
                    .filter(|namespace| *namespace != 0)
                    .ok_or("invalid sandbox info PID namespace")?,
            ),
        };
        self.pin_init(pid, namespace)
    }

    fn pin_direct_children(&mut self) -> Result<(), String> {
        if self.init.is_some() {
            return Ok(());
        }
        let path = PathBuf::from(format!("/proc/{0}/task/{0}/children", self.child.id()));
        let children = process_file(&path, 4096)?.ok_or("owned launcher child list disappeared")?;
        let children = children
            .split_whitespace()
            .map(|pid| {
                pid.parse::<u32>()
                    .map_err(|_| "invalid owned launcher child PID".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if children.len() > MAX_SANDBOX_CHILDREN {
            return Err("owned launcher child list exceeds 64".into());
        }
        // This bwrap invocation has exactly one direct namespace init. A different
        // process topology is a cleanup failure, never a license to scan other PIDs.
        if children.len() > 1 {
            return Err("unexpected multiple sandbox namespace children".into());
        }
        if children.is_empty()
            && self
                .launcher_identity
                .as_ref()
                .is_some_and(|launcher| matches!(launcher.state, b'T' | b't'))
        {
            self.init_known_dead = true;
        }
        for pid in children {
            self.pin_init(pid, None)?;
        }
        Ok(())
    }

    fn launcher_exited(&self) -> Result<bool, String> {
        if self.reaped {
            return Ok(true);
        }
        rustix::process::waitid(
            rustix::process::WaitId::Pid(self.group()?),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        )
        .map(|status| status.is_some())
        .map_err(|e| format!("sandbox status: {e}"))
    }

    /// Namespace completion is independent of the launcher's exit status.
    pub(crate) fn init_exit_confirmed(&mut self) -> Result<bool, String> {
        self.refresh_init()?;
        if let Some(init) = &self.init {
            return pidfd_exited(&init.fd);
        }
        if self.init_known_dead {
            return Ok(true);
        }
        if !self.reaped {
            self.pin_direct_children()?;
        }
        self.init
            .as_ref()
            .map_or(Ok(self.init_known_dead), |init| pidfd_exited(&init.fd))
    }

    /// | Outcome | Meaning |
    /// |---|---|
    /// | `Some(status)` | Namespace death confirmed and launcher reaped; repeated calls return the same status. |
    /// | `None` | Not complete; the launcher remains unreaped and owned. |
    /// | `Err` | Ownership/status probe failed; ownership remains retained. |
    pub(crate) fn poll_status(&mut self) -> Result<Option<std::process::ExitStatus>, String> {
        if let Some(status) = self.completed_status {
            return Ok(Some(status));
        }
        self.refresh_init()?;
        if !self.launcher_exited()? || !self.init_exit_confirmed()? {
            return Ok(None);
        }
        let status = self
            .child
            .try_wait()
            .map_err(|e| format!("sandbox reap: {e}"))?;
        if let Some(status) = status {
            self.reaped = true;
            self.completed_status = Some(status);
        }
        Ok(status)
    }

    /// Advance one finite cleanup stage; never sleep or release an unresolved owner.
    /// | Outcome | Meaning |
    /// |---|---|
    /// | `true` | Exact init death confirmed and launcher reaped. |
    /// | `false` | Cleanup pending; retain this object and poll on a later tick. |
    /// | `Err` | Cleanup could not be proven/performed; retain ownership and expose the reason. |
    pub(crate) fn cleanup_poll(&mut self) -> Result<bool, String> {
        if self.completed_status.is_some() && self.init_exit_confirmed()? {
            return Ok(true);
        }
        if !self.stop_requested && !self.reaped {
            match rustix::process::kill_process_group(self.group()?, rustix::process::Signal::STOP)
            {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => return Err(format!("sandbox launcher stop: {error}")),
            }
            self.stop_requested = true;
            return Ok(false);
        }
        if !self.group_killed && !self.reaped {
            self.refresh_launcher()?;
            if !self
                .launcher_identity
                .as_ref()
                .is_some_and(|identity| matches!(identity.state, b'T' | b't' | b'Z'))
            {
                return Ok(false);
            }
            let info_result = self.refresh_init();
            if self.init.is_none() {
                self.pin_direct_children()
                    .map_err(|error| format!("{error}; info: {info_result:?}"))?;
            }
            if self.init.is_none() && !self.init_known_dead {
                return Err(
                    "sandbox namespace outcome is unverified; unreaped launcher retained".into(),
                );
            }
            if let Some(init) = &self.init
                && init.namespace_init
                && let Err(error) =
                    rustix::process::pidfd_send_signal(&init.fd, rustix::process::Signal::KILL)
                && error != rustix::io::Errno::SRCH
            {
                return Err(format!("sandbox init termination: {error}"));
            }
            match rustix::process::kill_process_group(self.group()?, rustix::process::Signal::KILL)
            {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => return Err(format!("sandbox launcher termination: {error}")),
            }
            self.group_killed = true;
            return Ok(false);
        }
        Ok(self.poll_status()?.is_some())
    }
}

#[cfg(test)]
mod tests {
    /// Bound on a hang, not a speed requirement: starting bwrap (user
    /// namespace, fork) can take several seconds on a loaded machine. Scale it
    /// with `ANTINOMIE_TEST_SCALE`.
    fn patience() -> std::time::Duration {
        let scale = std::env::var("ANTINOMIE_TEST_SCALE")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1)
            .max(1);
        std::time::Duration::from_secs(60) * scale
    }
    use super::*;
    use std::{
        thread,
        time::{Duration, Instant},
    };
    struct SandboxFixture {
        process: SandboxProcess,
        witness: OwnedFd,
        _stderr: UnixStream,
    }
    impl Drop for SandboxFixture {
        fn drop(&mut self) {
            // Test failures still terminate exactly the owned init and launcher.
            let _ =
                rustix::process::pidfd_send_signal(&self.witness, rustix::process::Signal::KILL);
            let _ = self.process.child.kill();
            let _ = self.process.child.wait();
        }
    }

    fn sandbox_fixture(info_before_exec: bool) -> SandboxFixture {
        sandbox_fixture_mode(info_before_exec, info_before_exec)
    }

    fn sandbox_fixture_mode(info_before_exec: bool, report_info: bool) -> SandboxFixture {
        let (info, writer) = UnixStream::pair().unwrap();
        info.set_nonblocking(true).unwrap();
        let (stderr, errors) = UnixStream::pair().unwrap();
        let mut command = Command::new("bwrap");
        command.args([
            "--unshare-pid",
            "--unshare-user",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
        ]);
        if report_info {
            command.args(["--info-fd", "0"]);
        }
        if info_before_exec {
            // Hold real bwrap before setsid/PID1's death-signal setup and exec.
            // No acknowledgment is written to its bidirectional stderr channel.
            command.args(["--block-fd", "2"]);
        }
        command
            .args(["--", "sleep", "30"])
            .process_group(0)
            .stdin(Stdio::from(OwnedFd::from(writer)))
            .stdout(Stdio::null())
            .stderr(Stdio::from(OwnedFd::from(errors)));
        let child = command.spawn().unwrap();
        drop(command);
        let host = process_identity(std::process::id()).unwrap().unwrap();
        let mut process = SandboxProcess::adopt(
            child,
            LaunchInfo {
                info,
                namespace: host.namespace.unwrap(),
                depth: host.namespace_pids.len(),
            },
        );
        process.refresh_launcher().unwrap();
        let deadline = Instant::now() + patience();
        let pid = loop {
            let path = PathBuf::from(format!("/proc/{0}/task/{0}/children", process.child.id()));
            let children = process_file(&path, 4096).unwrap().unwrap();
            if let Some(pid) = children
                .split_whitespace()
                .next()
                .and_then(|pid| pid.parse::<u32>().ok())
                && let Some(identity) = process_identity(pid).unwrap()
                && identity.namespace_pids.last() == Some(&1)
                && identity.namespace_pids.len()
                    > process
                        .launcher_identity
                        .as_ref()
                        .unwrap()
                        .namespace_pids
                        .len()
                && identity.state == b'S'
                && (identity.group == process.child.id()) == info_before_exec
                && (!report_info
                    || info_before_exec
                    || process_file(
                        &PathBuf::from(format!("/proc/{pid}/task/{pid}/children")),
                        4096,
                    )
                    .ok()
                    .flatten()
                    .is_some_and(|children| !children.trim().is_empty()))
            {
                break pid;
            }
            assert!(
                Instant::now() < deadline,
                "sandbox fixture did not reach required setup stage"
            );
            thread::sleep(Duration::from_millis(5));
        };
        let witness = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        SandboxFixture {
            process,
            witness,
            _stderr: stderr,
        }
    }

    #[test]
    fn sandbox_cleanup_reaps_preexec_and_unreported_new_session_inits() {
        for info_before_exec in [true, false] {
            let mut fixture = sandbox_fixture(info_before_exec);
            assert!(finish_cleanup(&mut fixture.process).unwrap());
            assert!(fixture.process.reaped);
            assert!(
                pidfd_exited(&fixture.witness).unwrap(),
                "owned namespace init survived cleanup"
            );
            if !info_before_exec {
                assert!(
                    fixture.process.info_data.is_empty(),
                    "fixture unexpectedly supplied info"
                );
            }
        }
    }

    #[test]
    fn sandbox_cleanup_rejects_foreign_pid_and_preserves_unrelated_process() {
        let mut fixture = sandbox_fixture(true);
        let mut unrelated = Command::new("sleep").arg("3").spawn().unwrap();
        let rejected = fixture.process.pin_init(unrelated.id(), None).unwrap_err();
        let cleaned = finish_cleanup(&mut fixture.process);
        let unrelated_running = unrelated.try_wait().unwrap().is_none();
        let _ = unrelated.kill();
        unrelated.wait().unwrap();
        assert!(rejected.contains("parent does not match"));
        assert!(cleaned.unwrap());
        assert!(pidfd_exited(&fixture.witness).unwrap());
        assert!(
            unrelated_running,
            "foreign process was terminated by sandbox cleanup"
        );
    }

    #[test]
    fn sandbox_late_info_waits_for_reparented_init_death_without_signaling_it() {
        let mut fixture = sandbox_fixture_mode(false, true);
        // Leave the real metadata unread until after its launcher has exited.
        fixture.process.child.kill().unwrap();
        let deadline = Instant::now() + patience();
        while !fixture.process.launcher_exited().unwrap() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let mut outcome = None;
        while Instant::now() < deadline {
            match fixture.process.poll_status() {
                Ok(Some(status)) => {
                    outcome = Some(Ok(status));
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(error) => {
                    outcome = Some(Err(error));
                    break;
                }
            }
        }
        assert!(
            pidfd_exited(&fixture.witness).unwrap(),
            "initialized init should die with launcher"
        );
        let status = outcome.expect("late metadata failed to complete").unwrap();
        assert!(!status.success());
        assert!(fixture.process.reaped);
        assert!(!fixture.process.stop_requested && !fixture.process.group_killed);
    }

    #[test]
    fn process_metadata_of_a_task_reaped_after_open_reads_as_gone() {
        for name in ["stat", "status"] {
            let mut child = Command::new("/bin/sh")
                .args(["-c", "exit 0"])
                .spawn()
                .unwrap();
            let file = File::open(format!("/proc/{}/{name}", child.id())).unwrap();
            child.wait().unwrap();
            assert_eq!(read_process_text(file, 4096), Ok(None), "{name}");
        }
    }

    #[test]
    fn sandbox_identity_guard_allows_setsid_but_rejects_reuse_or_reparenting() {
        let before = ProcessIdentity {
            parent: 42,
            group: 42,
            started: 100,
            state: b'R',
            namespace: Some(7),
            namespace_pids: vec![43, 1],
        };
        let mut after = before.clone();
        after.group = 43;
        assert!(same_child_identity(&before, &after));
        after.started = 101;
        assert!(!same_child_identity(&before, &after));
        after.started = 100;
        after.parent = 1;
        assert!(!same_child_identity(&before, &after));
    }

    #[test]
    fn sandbox_fast_success_and_failure_preserve_exact_status() {
        for code in [0, 7] {
            let mut command = Command::new("bwrap");
            command.args([
                "--unshare-pid",
                "--unshare-user",
                "--die-with-parent",
                "--new-session",
                "--ro-bind",
                "/",
                "/",
                "--proc",
                "/proc",
            ]);
            let launch = prepare(&mut command).unwrap();
            command
                .args(["--", "/bin/sh", "-c", &format!("exit {code}")])
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let child = command.spawn().unwrap();
            drop(command);
            let mut process = SandboxProcess::adopt(child, launch);
            let deadline = Instant::now() + patience();
            let status = loop {
                match process.poll_status() {
                    Ok(Some(status)) => break Ok(status),
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Ok(None) => break Err("fast child completion deadline elapsed".to_string()),
                    Err(error) => break Err(error),
                }
            };
            // Capture the original probe outcome before cleanup changes its
            // process state; a timeout and a failed ownership probe differ.
            let diagnostic = format!(
                "code={code}, info_eof={}, info_len={}, init_pinned={}, init_known_dead={}, launcher={:?}",
                process.info_eof,
                process.info_data.len(),
                process.init.is_some(),
                process.init_known_dead,
                process.launcher_identity,
            );
            let cleaned = finish_cleanup(&mut process);
            assert!(
                cleaned.as_ref().is_ok_and(|finished| *finished),
                "fast child cleanup did not finish: {cleaned:?}; status={status:?}; {diagnostic}"
            );
            let status = status.unwrap_or_else(|error| {
                panic!("fast child status was not delivered: {error}; {diagnostic}")
            });
            assert_eq!(status.code(), Some(code));
            assert_eq!(process.poll_status().unwrap(), Some(status));
            assert!(process.init_exit_confirmed().unwrap());
        }
    }

    #[test]
    fn sandbox_legacy_info_still_checks_live_namespace_ownership() {
        let mut fixture = sandbox_fixture(true);
        let deadline = Instant::now() + patience();
        let mut captured = Vec::new();
        loop {
            let mut chunk = [0; 1024];
            match fixture.process.info.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => captured.extend_from_slice(&chunk[..count]),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("info read failed: {error}"),
            }
        }
        let info: serde_json::Value = serde_json::from_slice(&captured).unwrap();
        fixture.process.info_data = serde_json::to_vec(&serde_json::json!({
            "child-pid": info["child-pid"],
        }))
        .unwrap();
        fixture.process.info_eof = true;
        let refreshed = fixture.process.refresh_init();
        let pinned = fixture
            .process
            .init
            .as_ref()
            .is_some_and(|init| init.namespace_init);
        let cleaned = finish_cleanup(&mut fixture.process);
        refreshed.unwrap();
        assert!(
            pinned,
            "legacy metadata must independently pin the live namespace"
        );
        assert!(cleaned.unwrap());
        assert!(pidfd_exited(&fixture.witness).unwrap());
    }

    #[test]
    fn sandbox_unknown_early_exit_retains_owner_instead_of_claiming_cleanup() {
        let mut command = Command::new("bwrap");
        command.arg("--deliberately-invalid-sandbox-option");
        let launch = prepare(&mut command).unwrap();
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let child = command.spawn().unwrap();
        drop(command);
        let mut process = SandboxProcess::adopt(child, launch);
        let deadline = Instant::now() + patience();
        while !process.launcher_exited().unwrap() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let status = process.poll_status();
        let first_cleanup = process.cleanup_poll();
        let second_cleanup = process.cleanup_poll();
        let still_owned = !process.reaped;
        // This fixture's invalid argument is known to fail before cloning. The
        // production owner has no such proof and must retain its anchor.
        let reaped = process.child.wait();
        assert_eq!(status.unwrap(), None);
        assert!(!first_cleanup.unwrap());
        assert!(second_cleanup.unwrap_err().contains("unverified"));
        assert!(still_owned);
        assert!(!reaped.unwrap().success());
    }

    fn finish_cleanup(process: &mut SandboxProcess) -> Result<bool, String> {
        let deadline = std::time::Instant::now() + patience();
        while std::time::Instant::now() < deadline {
            if process.cleanup_poll()? {
                return Ok(true);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(false)
    }
}
