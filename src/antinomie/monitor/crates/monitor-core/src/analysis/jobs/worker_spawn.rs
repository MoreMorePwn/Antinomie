// SPDX-License-Identifier: GPL-3.0-only
//! Spawning the sandboxed analysis worker and its log capture (moved out of `jobs`).
use super::*;

pub(super) fn spawn_worker(job: &Job, tools: Option<&Path>) -> Result<SandboxProcess, String> {
    let executable = worker_executable()?;
    spawn_worker_binary(job, &executable, tools)
}
pub(super) fn spawn_worker_binary(
    job: &Job,
    executable: &Path,
    tools: Option<&Path>,
) -> Result<SandboxProcess, String> {
    crate::dependencies::require_tool(Path::new("/usr/bin/bwrap"), "bubblewrap")?;
    if CLEANUP_PENDING.load(Ordering::Acquire) {
        return Err("a previous worker still awaits reap; isolation worker unavailable".into());
    }
    // The worker is bound to a plain file; it exists only for this run of it
    // and `finish` seals it again.
    sealed::materialize(&job.directory)?;
    let account = sandbox_passwd(&job.directory)?;
    let output = job.directory.join("output");
    fs::create_dir(&output).map_err(|e| e.to_string())?;
    let progress = output.join("progress");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&progress)
        .map_err(|e| e.to_string())?;
    let listings = output.join("listings");
    fs::create_dir(&listings).map_err(|e| e.to_string())?;
    fs::set_permissions(&listings, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let artifacts = output.join("artifacts");
    fs::create_dir(&artifacts).map_err(|e| e.to_string())?;
    fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let has = |kind| {
        job.report
            .sections
            .iter()
            .any(|s| s.kind == kind && s.state == AnalysisSectionState::Pending)
    };
    let decompiler =
        has(AnalysisKind::Decompilation) || super::decompile::listing_only(&job.report).is_some();
    // capa and FLOSS unpack themselves into /tmp before they run.
    let tmp_size = if decompiler {
        "2147483648"
    } else if has(AnalysisKind::Capabilities) || has(AnalysisKind::Floss) {
        "1073741824"
    } else {
        "33554432"
    };
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(output.join("report.json"))
        .map_err(|e| e.to_string())?;
    storage::atomic_json(&job.directory.join("request.json"), &job.report)?;
    let log = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(job.directory.join("worker.log"))
        .map_err(|e| e.to_string())?;
    let mut cmd = Command::new("/usr/bin/bwrap");
    cmd.args([
        "--unshare-all",
        // A neutral host name: tools log it, and logs are kept.
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
    // Read-only system configuration the optional tools need: the Java
    // runtime of a decompiler resolves itself through these.
    // Merged-/usr systems keep /bin, /sbin and /lib as links into /usr; tool
    // scripts start with #!/bin/sh, so recreate the links.
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
    for path in [
        "/usr/lib/bfd-plugins",
        "/usr/lib/x86_64-linux-gnu/bfd-plugins",
    ] {
        if Path::new(path).is_dir() {
            cmd.args(["--size", "4096", "--tmpfs", path, "--remount-ro", path]);
        }
    }
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
        // Shell process substitution (the decompiler's launcher) needs these.
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
    ])
    // A decompiler keeps its project database in /tmp.
    .arg(tmp_size)
    .args([
        "--tmpfs",
        "/tmp",
        "--dir",
        "/input",
        "--size",
        "33554432",
        "--tmpfs",
        "/output",
        "--ro-bind",
    ])
    .arg(executable)
    .arg("/worker")
    .arg("--ro-bind")
    .arg(job.directory.join("specimen"))
    .arg("/input/specimen");
    stage_static_rules(&job.directory)?;
    let rules = job.directory.join("rules");
    if rules.is_dir() {
        cmd.arg("--ro-bind").arg(&rules).arg("/input/rules");
    }
    cmd.arg("--ro-bind")
        .arg(job.directory.join("request.json"))
        .arg("/input/request.json")
        .arg("--bind")
        .arg(output.join("report.json"))
        .arg("/output/report.json")
        .arg("--bind")
        .arg(&listings)
        .arg("/output/listings")
        .arg("--bind")
        .arg(&artifacts)
        .arg("/output/artifacts")
        .arg("--bind")
        .arg(&progress)
        .arg("/output/progress");
    // Analysis tools Antinomie installed, read-only.
    if let Some(tools) = tools.filter(|tools| tools.is_dir()) {
        cmd.arg("--ro-bind")
            .arg(tools)
            .arg(crate::analysis_tools::SANDBOX_DIR);
    }
    if has(AnalysisKind::Capabilities) {
        super::capa::mount_cache(&mut cmd, tools);
    }
    if std::env::var("ANTINOMIE_ANALYSIS_TOOLS").as_deref() == Ok("managed") {
        cmd.args(["--setenv", "ANTINOMIE_ANALYSIS_TOOLS", "managed"]);
    }
    let launch = sandbox_process::prepare(&mut cmd)?;
    cmd.args([
        "--remount-ro",
        "/",
        "--setenv",
        "ANTINOMIE_ISOLATED_WORKER",
        "1",
        "--setenv",
        "LC_ALL",
        "C",
        "--setenv",
        "HOME",
        "/nonexistent",
        "--chdir",
        "/output",
        "--",
        "/worker",
        "--antinomie-analysis-worker",
    ])
    .env_clear()
    .stdout(Stdio::null())
    .stderr(Stdio::from(log));
    let spawned = cmd.spawn();
    drop(cmd);
    spawned
        .map(|child| SandboxProcess::adopt(child, launch))
        .map_err(|e| format!("mandatory bubblewrap isolation unavailable: {e}"))
}

pub(super) fn cleanup_sandbox(
    process: &mut SandboxProcess,
    log: &mut SandboxLog,
) -> Result<(), String> {
    let started = Instant::now();
    let mut failure = None;
    let mut noted = false;
    loop {
        match process.cleanup_poll() {
            Ok(true) => return failure.map_or(Ok(()), Err),
            Ok(false) => {}
            Err(error) => failure = Some(error),
        }
        if !noted && (failure.is_some() || started.elapsed() >= Duration::from_secs(1)) {
            let detail = failure
                .as_deref()
                .unwrap_or("namespace termination and reap are pending");
            let message =
                format!("\n[sandbox cleanup pending: {detail}; owned process retained]\n");
            if let Err(error) = log
                .record(message.as_bytes())
                .and_then(|()| log.file.flush().map_err(|e| e.to_string()))
            {
                failure = Some(format!("cleanup pending diagnostics: {error}; {detail}"));
            }
            noted = true;
        }
        std::thread::sleep(Duration::from_millis(if noted { 50 } else { 10 }));
    }
}

pub(super) const SANDBOX_LOG_MAX_SIZE: usize = 2 * 1024 * 1024;
pub(super) const SANDBOX_TAIL_MAX_SIZE: usize = 8192;
pub(super) const SANDBOX_LOG_HEAD_SIZE: usize = SANDBOX_LOG_MAX_SIZE - SANDBOX_TAIL_MAX_SIZE - 256;

pub(super) struct SandboxLog {
    file: File,
    path: PathBuf,
    head_len: usize,
    total_len: u64,
    tail: VecDeque<u8>,
}
impl SandboxLog {
    pub(super) fn new(directory: &Path) -> Result<Self, String> {
        let path = directory.join(format!("ghidra-{}.log", storage::unique_id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("sandbox diagnostics {}: {e}", path.display()))?;
        Ok(Self {
            file,
            path,
            head_len: 0,
            total_len: 0,
            tail: VecDeque::with_capacity(SANDBOX_TAIL_MAX_SIZE),
        })
    }
    /// True means the stream reached EOF or has no queued output at this instant.
    pub(super) fn drain(&mut self, reader: &mut UnixStream) -> Result<bool, String> {
        let mut chunk = [0u8; 8192];
        // Finite drain work keeps cancellation/deadline polling responsive even
        // when a malfunctioning tool produces output continuously.
        for _ in 0..32 {
            let len = match reader.read(&mut chunk) {
                Ok(0) => return Ok(true),
                Ok(len) => len,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("sandbox output: {e}")),
            };
            self.record(&chunk[..len])?;
        }
        Ok(false)
    }
    pub(super) fn record(&mut self, chunk: &[u8]) -> Result<(), String> {
        self.total_len = self.total_len.saturating_add(chunk.len() as u64);
        let keep = chunk.len().min(SANDBOX_LOG_HEAD_SIZE - self.head_len);
        self.file
            .write_all(&chunk[..keep])
            .map_err(|e| e.to_string())?;
        self.head_len += keep;
        let discard = self
            .tail
            .len()
            .saturating_add(chunk.len())
            .saturating_sub(SANDBOX_TAIL_MAX_SIZE);
        self.tail.drain(..discard);
        self.tail.extend(chunk);
        Ok(())
    }
    pub(super) fn drain_final(&mut self, reader: &mut UnixStream) -> Result<(), String> {
        // Socket send buffers can exceed the ordinary per-poll drain budget.
        // Once the sandbox has exited/been reaped, consume queued data until
        // idle, while bounding work even if a hidden writer retained a handle.
        let deadline = Instant::now() + Duration::from_secs(1);
        for _ in 0..256 {
            if Instant::now() >= deadline {
                return Err(
                    "incomplete sandbox diagnostics: final drain exceeded one second".into(),
                );
            }
            if self.drain(reader)? {
                return Ok(());
            }
        }
        Err("incomplete sandbox diagnostics: final drain exceeded 64 MiB work bound".into())
    }
    pub(super) fn finish(&mut self) -> Result<(), String> {
        if self.total_len > self.head_len as u64 {
            writeln!(
                self.file,
                "\n[output truncated; {} observed; final observed output tail follows]",
                crate::byte_size::file_size(self.total_len)
            )
            .map_err(|e| e.to_string())?;
            let (a, b) = self.tail.as_slices();
            self.file
                .write_all(a)
                .and_then(|()| self.file.write_all(b))
                .map_err(|e| e.to_string())?;
        }
        self.file.sync_all().map_err(|e| e.to_string())
    }
    pub(super) fn error(&self, reason: &str) -> String {
        let tail: Vec<u8> = self
            .tail
            .iter()
            .skip(self.tail.len().saturating_sub(2048))
            .copied()
            .collect();
        let mut text = format!(
            "{reason}\nDiagnostics: {}\n{}",
            self.path.display(),
            String::from_utf8_lossy(&tail)
        );
        if text.len() > 4096 {
            let mut end = 4096;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        text
    }
}
