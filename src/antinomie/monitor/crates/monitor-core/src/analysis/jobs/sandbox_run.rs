// SPDX-License-Identifier: MIT
//! Running one external analysis tool in the worker's bubblewrap isolation.
use super::*;

/// Read-only host paths an external tool may read.
#[derive(Default)]
pub(crate) struct Mounts<'a> {
    /// Mounted at their own host path.
    pub paths: &'a [PathBuf],
    /// `<data>/tools`, mounted at `analysis_tools::SANDBOX_DIR` as in the
    /// static-analysis worker.
    pub tools: Option<&'a Path>,
}

/// Run an external analysis tool inside the same bubblewrap isolation as the
/// static-analysis worker. The host process is `bwrap`, not the tool itself.
/// A private, unique log retains at most 2 MiB, including the final output tail.
/// Limits apply to each descendant process, not aggregate process-tree RSS.
pub(crate) fn run_sandboxed(
    program: &Path,
    args: &[String],
    writable: &Path,
    extra_read_only: &[PathBuf],
    env: &[(&str, &str)],
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let mounts = Mounts {
        paths: extra_read_only,
        tools: None,
    };
    run_sandboxed_with(program, args, writable, &mounts, env, timeout, cancel)
}

/// [`run_sandboxed`] with the managed tools folder as an optional mount.
pub(crate) fn run_sandboxed_with(
    program: &Path,
    args: &[String],
    writable: &Path,
    mounts: &Mounts<'_>,
    env: &[(&str, &str)],
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<(), String> {
    crate::dependencies::require_tool(Path::new("/usr/bin/bwrap"), "bubblewrap")?;
    crate::dependencies::require_tool(Path::new("/usr/bin/prlimit"), "prlimit")?;
    let account = sandbox_passwd(writable)?;
    let mut log = SandboxLog::new(writable)?;
    let (mut reader, writer) = UnixStream::pair().map_err(|e| e.to_string())?;
    reader.set_nonblocking(true).map_err(|e| e.to_string())?;
    let stderr = writer.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = Command::new("/usr/bin/bwrap");
    cmd.args([
        "--unshare-all",
        "--hostname",
        "analysis",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
    ]);
    for path in ["/bin", "/sbin", "/lib", "/lib64"] {
        if let Ok(target) = fs::read_link(path) {
            cmd.arg("--symlink").arg(target).arg(path);
        }
    }
    for path in [
        "/lib",
        "/lib64",
        "/etc/alternatives",
        "/etc/java-17-openjdk",
        "/etc/java-21-openjdk",
        "/etc/ld.so.cache",
    ] {
        if Path::new(path).exists() && fs::read_link(path).is_err() {
            cmd.arg("--ro-bind").arg(path).arg(path);
        }
    }
    cmd.arg("--ro-bind").arg(&account).arg("/etc/passwd");
    cmd.args([
        "--proc",
        "/proc",
        "--dir",
        "/dev",
        "--dev-bind",
        "/dev/null",
        "/dev/null",
        "--dev-bind",
        "/dev/urandom",
        "/dev/urandom",
        "--dev-bind",
        "/dev/random",
        "/dev/random",
        "--symlink",
        "/proc/self/fd",
        "/dev/fd",
        "--symlink",
        "/proc/self/fd/0",
        "/dev/stdin",
        "--symlink",
        "/proc/self/fd/1",
        "/dev/stdout",
        "--symlink",
        "/proc/self/fd/2",
        "/dev/stderr",
        "--size",
        "2147483648",
        "--tmpfs",
        "/tmp",
        "--bind",
    ])
    .arg(writable)
    .arg(writable);
    for path in mounts.paths {
        if path.exists() {
            cmd.arg("--ro-bind").arg(path).arg(path);
        }
    }
    if let Some(tools) = mounts.tools.filter(|tools| tools.is_dir()) {
        cmd.arg("--ro-bind")
            .arg(tools)
            .arg(crate::analysis_tools::SANDBOX_DIR);
    }
    cmd.args(["--remount-ro", "/", "--setenv", "LC_ALL", "C"]);
    for (key, value) in env {
        cmd.arg("--setenv").arg(key).arg(value);
    }
    let launch = sandbox_process::prepare(&mut cmd)?;
    cmd.arg("--chdir")
        .arg(writable)
        .args([
            "--",
            "/usr/bin/prlimit",
            "--as=8589934592",
            "--nofile=1024",
            "--core=0",
            "--",
        ])
        .arg(program);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.env_clear()
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::from(OwnedFd::from(stderr)));
    let spawned = cmd.spawn();
    // Command owns its configured descriptors even after spawn; release them so
    // EOF reflects only the sandbox and its descendants.
    drop(cmd);
    let mut child = match spawned {
        Ok(child) => SandboxProcess::adopt(child, launch),
        Err(error) => {
            let reason = format!("mandatory bubblewrap isolation unavailable: {error}");
            let reason = match log.finish() {
                Ok(()) => reason,
                Err(persist) => format!("{reason}; diagnostics persistence failed: {persist}"),
            };
            return Err(log.error(&reason));
        }
    };
    let deadline = Instant::now().checked_add(timeout);
    let mut result = (|| {
        let deadline = deadline.ok_or("sandbox deadline overflow")?;
        loop {
            log.drain(&mut reader)?;
            if cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            if Instant::now() >= deadline {
                return Err("Isolated analysis timed out.".into());
            }
            match child
                .poll_status()
                .map_err(|e| format!("sandbox wait: {e}"))?
            {
                Some(status) if status.success() => return Ok(()),
                Some(status) => {
                    return Err(format!(
                        "sandboxed Ghidra exited with {status}. sparse-plan.txt is not a load result."
                    ));
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    })();
    if result.is_err() {
        // Retain both launcher and namespace ownership on this background
        // caller until exact cleanup is confirmed, including early setup.
        if let Err(error) = cleanup_sandbox(&mut child, &mut log) {
            result = Err(format!("sandbox cleanup failed: {error}; {result:?}"));
        }
    }
    let final_drain = log.drain_final(&mut reader);
    let persistence = log.finish();
    let diagnostics = match (final_drain, persistence) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(drain), Err(persist)) => Err(format!("{drain}; persistence failed: {persist}")),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
    };
    if let Err(error) = diagnostics {
        result = Err(format!(
            "sandbox diagnostics persistence failed: {error}; {result:?}"
        ));
    }
    result.map_err(|error| log.error(&error))
}
