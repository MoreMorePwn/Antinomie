// SPDX-License-Identifier: GPL-3.0-only
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

/// Address space of a sandboxed tool, in octets.
const ADDRESS_SPACE_SIZE: u64 = 8 * 1024 * 1024 * 1024;

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
    run_sandboxed_sized(
        program,
        args,
        writable,
        mounts,
        env,
        timeout,
        cancel,
        ADDRESS_SPACE_SIZE,
    )
}

/// [`run_sandboxed_with`] with the tool's address space (`prlimit --as`)
/// set by the caller: a tool that maps a whole memory dump needs more than
/// the default.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_sandboxed_sized(
    program: &Path,
    args: &[String],
    writable: &Path,
    mounts: &Mounts<'_>,
    env: &[(&str, &str)],
    timeout: Duration,
    cancel: &AtomicBool,
    address_space_size: u64,
) -> Result<(), String> {
    let bounds = Bounds {
        timeout,
        address_space_size,
        grace: crate::sandbox_process::host_stop_grace(),
    };
    run_bounded(program, args, writable, mounts, env, cancel, bounds)
}

/// The limits of one sandboxed tool.
pub(super) struct Bounds {
    pub(super) timeout: Duration,
    pub(super) address_space_size: u64,
    /// SIGTERM, then this long before SIGKILL, when the tool is stopped (its
    /// time limit, a cancel); zero stops it at once (ANT-T0471).
    pub(super) grace: Duration,
}

pub(super) fn run_bounded(
    program: &Path,
    args: &[String],
    writable: &Path,
    mounts: &Mounts<'_>,
    env: &[(&str, &str)],
    cancel: &AtomicBool,
    bounds: Bounds,
) -> Result<(), String> {
    let Bounds {
        timeout,
        address_space_size,
        grace,
    } = bounds;
    crate::dependencies::require_tool(Path::new("/usr/bin/bwrap"), "bubblewrap")?;
    crate::dependencies::require_tool(Path::new("/usr/bin/prlimit"), "prlimit")?;
    let account = sandbox_passwd(writable)?;
    let mut log = SandboxLog::new(writable)?;
    let (mut reader, writer) = UnixStream::pair().map_err(|e| e.to_string())?;
    reader.set_nonblocking(true).map_err(|e| e.to_string())?;
    let stderr = writer.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = Command::new("/usr/bin/bwrap");
    crate::sandbox_profile::apply(&mut cmd, &account, &[], 2147483648);
    cmd.arg("--bind").arg(writable).arg(writable);
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
        .args(["--", "/usr/bin/prlimit"])
        .arg(format!("--as={address_space_size}"))
        .args(["--nofile=1024", "--core=0", "--"])
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
                    let name = program.file_name().map_or_else(
                        || program.display().to_string(),
                        |name| name.to_string_lossy().into_owned(),
                    );
                    return Err(format!("sandboxed {name} exited with {status}."));
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    })();
    if result.is_err() {
        // A tool being stopped gets SIGTERM and the grace to end; what is
        // left is killed by the cleanup below.
        terminate_sandbox(&mut child, &mut log, &mut reader, grace);
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

/// The graceful stop of a sandboxed tool (ANT-T0471): SIGTERM to its group,
/// then up to `grace` for it to end. Nothing is sent when `grace` is zero or
/// when the tool has already ended. Returns whether it ended in the grace;
/// [`cleanup_sandbox`] kills (SIGSTOP, SIGKILL) whatever is still there.
pub(super) fn terminate_sandbox(
    process: &mut SandboxProcess,
    log: &mut SandboxLog,
    reader: &mut UnixStream,
    grace: Duration,
) -> bool {
    if grace.is_zero() || matches!(process.poll_status(), Ok(Some(_))) {
        return false;
    }
    match process.terminate() {
        Ok(true) => {}
        Ok(false) => return false,
        Err(error) => {
            let _ = log.record(format!("\n[graceful stop failed: {error}]\n").as_bytes());
            return false;
        }
    }
    let until = Instant::now() + grace;
    let ended = loop {
        let _ = log.drain(reader);
        match process.poll_status() {
            Ok(Some(_)) => break true,
            Ok(None) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => break false,
        }
    };
    let note = if ended {
        "\n[stopped: SIGTERM sent; it ended within the grace]\n".to_owned()
    } else {
        format!(
            "\n[stopped: SIGTERM sent; still running after the {} s grace, SIGKILL follows]\n",
            grace.as_secs_f64()
        )
    };
    let _ = log.record(note.as_bytes());
    ended
}
