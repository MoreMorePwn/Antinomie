// SPDX-License-Identifier: MIT
//! Running the external TShark decoder: bounded output reads, deadlines,
//! cancellation and reaping of the sandboxed child.
use super::*;

const CLEANUP_BUDGET: Duration = Duration::from_secs(1);

/// The parser sees ordinary blocking Read semantics, with a bounded abort check.
pub(super) struct ProcessReader<R> {
    inner: R,
    abort: Arc<AtomicBool>,
}
impl<R: Read + AsFd> ProcessReader<R> {
    pub(super) fn new(inner: R, abort: Arc<AtomicBool>) -> Result<Self, String> {
        let flags = rustix::fs::fcntl_getfl(&inner).map_err(|e| e.to_string())?;
        rustix::fs::fcntl_setfl(&inner, flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(|e| e.to_string())?;
        Ok(Self { inner, abort })
    }
}
impl<R: Read> Read for ProcessReader<R> {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        loop {
            if self.abort.load(Ordering::Acquire) {
                return Err(std::io::Error::other(
                    "packet output stopped for process cleanup",
                ));
            }
            match self.inner.read(data) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                result => return result,
            }
        }
    }
}

pub(super) fn cleanup_process(
    process: &mut crate::sandbox_process::SandboxProcess,
    shared: &Shared,
    reason: &str,
) -> Result<(), String> {
    let started = Instant::now();
    let mut failure = None;
    loop {
        match process.cleanup_poll() {
            Ok(true) => {
                *shared
                    .cleanup_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                return failure.map_or(Ok(()), Err);
            }
            Ok(false) => {}
            Err(error) => failure = Some(error),
        }
        if failure.is_some() || started.elapsed() >= CLEANUP_BUDGET {
            let detail = failure
                .as_deref()
                .unwrap_or("termination/reaping exceeded cleanup budget");
            *shared
                .cleanup_error
                .lock()
                .unwrap_or_else(|e| e.into_inner()) =
                Some(format!("{reason}; cleanup pending: {detail}"));
            thread::sleep(Duration::from_millis(250));
        } else {
            thread::sleep(Duration::from_millis(20));
        }
    }
}

pub(super) fn run_process<T: Send + 'static>(
    command: Command,
    shared: &Shared,
    generation: Option<u64>,
    deadline: Duration,
    read_output: impl FnOnce(ProcessReader<std::process::ChildStdout>) -> Result<T, String>
    + Send
    + 'static,
) -> Result<T, String> {
    crate::dependencies::require_tool(Path::new(command.get_program()), "tshark").map_err(
        |error| format!("TShark unavailable: {error}. Install tshark to enable display filters"),
    )?;
    // Linux util-linux provides a safe exec wrapper, avoiding unsafe pre_exec
    // code in the host. These limits apply to the external decoder only.
    let mut bounded = Command::new("prlimit");
    let profile = Scratch::new()?;
    // The analysis workers' minimal mount profile: /usr, a private /etc/passwd
    // and /tmp, no host sockets, no home or data directory, every namespace
    // (network included) unshared. Wireshark's own data, plug-ins and libraries
    // live under /usr; /etc/wireshark is the system configuration.
    let account = profile.path.join("passwd");
    fs::write(&account, "nobody:x:65534:65534::/tmp:/bin/false\n")
        .map_err(|e| format!("packet sandbox account: {e}"))?;
    bounded
        .args(["--as=2147483648", "--core=0", "--nofile=128", "--"])
        .arg("bwrap");
    crate::sandbox_profile::apply(
        &mut bounded,
        &account,
        &["/etc/wireshark", "/etc/localtime"],
        67_108_864,
    );
    bounded
        .args(["--uid", "65534", "--gid", "65534"])
        .arg("--bind")
        .arg(&profile.path)
        .arg(&profile.path);
    // The capture is the only input exposed, read-only, wherever it lives.
    let mut arguments = command.get_args();
    while let Some(argument) = arguments.next() {
        if argument == "-r"
            && let Some(capture) = arguments.next()
        {
            let capture = Path::new(capture);
            bounded.arg("--ro-bind").arg(capture).arg(capture);
        }
    }
    bounded.args(["--remount-ro", "/", "--setenv", "PATH", "/usr/bin:/bin"]);
    bounded.args(["--setenv", "LC_ALL", "C"]);
    for key in [
        "WIRESHARK_CONFIG_DIR",
        "WIRESHARK_PLUGIN_DIR",
        "WIRESHARK_EXTCAP_DIR",
        "TMPDIR",
        "HOME",
    ] {
        bounded.arg("--setenv").arg(key).arg(&profile.path);
    }
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            bounded.arg("--setenv").arg(name).arg(value);
        }
    }
    let launch = crate::sandbox_process::prepare(&mut bounded)?;
    bounded
        .arg("--")
        .arg(command.get_program())
        .args(command.get_args());
    if let Some(directory) = command.get_current_dir() {
        bounded.current_dir(directory);
    } else {
        bounded.current_dir(&profile.path);
    }
    let child = bounded
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!("bounded TShark runtime is unavailable: {e}. Install tshark, bubblewrap and util-linux (prlimit) to enable display filters")
        })?;
    // Command retains configured stream descriptors; release its info writer so
    // EOF reflects only the sandbox monitor, not this owner's command builder.
    drop(bounded);
    let mut process = crate::sandbox_process::SandboxProcess::adopt(child, launch);
    let stdout = process.take_stdout().expect("piped TShark stdout");
    let stderr = process.take_stderr().expect("piped TShark stderr");
    let abort = Arc::new(AtomicBool::new(false));
    let stdout = match ProcessReader::new(stdout, Arc::clone(&abort)) {
        Ok(stdout) => stdout,
        Err(error) => {
            cleanup_process(&mut process, shared, &error)
                .map_err(|cleanup| format!("{error}; {cleanup}"))?;
            return Err(error);
        }
    };
    let stderr = match ProcessReader::new(stderr, Arc::clone(&abort)) {
        Ok(stderr) => stderr,
        Err(error) => {
            cleanup_process(&mut process, shared, &error)
                .map_err(|cleanup| format!("{error}; {cleanup}"))?;
            return Err(error);
        }
    };
    let parser_failed = Arc::new(AtomicBool::new(false));
    let failed = Arc::clone(&parser_failed);
    let output = match thread::Builder::new()
        .name("packet-filter-output".into())
        .spawn(move || {
            let result = read_output(stdout);
            failed.store(result.is_err(), Ordering::Release);
            result
        }) {
        Ok(thread) => thread,
        Err(error) => {
            let reason = format!("TShark output worker: {error}");
            abort.store(true, Ordering::Release);
            cleanup_process(&mut process, shared, &reason)
                .map_err(|cleanup| format!("{reason}; {cleanup}"))?;
            return Err(reason);
        }
    };
    let errors = match thread::Builder::new()
        .name("packet-filter-diagnostics".into())
        .spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut kept = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => kept.extend_from_slice(
                        &chunk[..count.min(MAX_ERROR_SIZE.saturating_sub(kept.len()))],
                    ),
                    Err(error) => return Err(format!("TShark diagnostic read: {error}")),
                }
            }
            Ok(String::from_utf8_lossy(&kept).trim().to_owned())
        }) {
        Ok(thread) => thread,
        Err(error) => {
            let reason = format!("TShark diagnostic worker: {error}");
            abort.store(true, Ordering::Release);
            let cleanup = cleanup_process(&mut process, shared, &reason);
            let _ = output.join();
            cleanup.map_err(|cleanup| format!("{reason}; {cleanup}"))?;
            return Err(reason);
        }
    };
    let started = Instant::now();
    let mut exit_status = None;
    let status = loop {
        let cancelled =
            shared.stop.load(Ordering::Acquire) || generation.is_some_and(|g| cancelled(shared, g));
        // Freeze the triggering reason before cleanup/drain time can pass a deadline.
        let reason = if cancelled {
            Some("packet filtering cancelled".to_string())
        } else if started.elapsed() >= deadline {
            Some("TShark evaluation timed out after its bounded deadline".to_string())
        } else if parser_failed.load(Ordering::Acquire) {
            Some("TShark output parser failed".to_string())
        } else {
            None
        };
        if let Some(reason) = reason {
            abort.store(true, Ordering::Release);
            let cleanup = cleanup_process(&mut process, shared, &reason);
            let parsed = output.join().map_err(|_| "TShark output reader stopped")?;
            let _ = errors.join();
            cleanup.map_err(|error| format!("{reason}; {error}"))?;
            return if reason == "TShark output parser failed" {
                parsed
            } else {
                Err(reason)
            };
        }
        let polled = process.poll_status();
        match polled {
            Ok(Some(status)) => exit_status = Some(status),
            Ok(None) => {}
            Err(reason) => {
                abort.store(true, Ordering::Release);
                let cleanup = cleanup_process(&mut process, shared, &reason);
                let _ = output.join();
                let _ = errors.join();
                cleanup.map_err(|error| format!("{reason}; {error}"))?;
                return Err(reason);
            }
        }
        // Continue enforcing cancellation/deadline until both readers finish,
        // even if an exited launcher left a namespace child holding its pipes.
        if let Some(status) = exit_status
            && output.is_finished()
            && errors.is_finished()
        {
            break status;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let diagnostics = errors
        .join()
        .map_err(|_| "TShark diagnostic reader stopped")??;
    let result = output.join().map_err(|_| "TShark output reader stopped")?;
    if !status.success() {
        return Err(if diagnostics.is_empty() {
            format!("TShark exited with {status}")
        } else if diagnostics.contains("failed to execute")
            || diagnostics.contains("execvp")
            || diagnostics.contains("No such file or directory")
        {
            format!(
                "{diagnostics}. Install tshark, bubblewrap and util-linux (prlimit) to enable display filters"
            )
        } else {
            format!("TShark failed (2 GiB memory limit, 128 open files): {diagnostics}")
        });
    }
    result
}
