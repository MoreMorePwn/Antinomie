// SPDX-License-Identifier: GPL-3.0-only
//! The parent's handle on the sandboxed reader worker.
use super::protocol::{CONTENT_SECONDS, DIFF_SECONDS, DiskRequest, Envelope, FIND_SECONDS, Reply};
use crate::disks::sandbox::Account;
use crate::process_tree::{KILLED_JOIN_WAIT, join_within, kill_tree, own_group};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

/// An answer line is at most this long (a 5,000-match find with long paths).
const ANSWER_LIMIT: u64 = 32 * 1024 * 1024;
/// Address space of the worker: the filesystem's group descriptors and
/// journal map are well under it (the TShark figure).
const ADDRESS_SPACE_SIZE: u64 = 2 * 1024 * 1024 * 1024;
/// Files the worker may open.
const OPEN_FILE_LIMIT: u32 = 64;
/// Size of the worker's `/tmp`.
const TMP_SIZE: u64 = 16 * 1024 * 1024;

struct Live {
    child: Child,
    stdin: ChildStdin,
    answers: Receiver<Result<Vec<u8>, String>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    stderr_thread: thread::JoinHandle<()>,
}

impl Live {
    /// Kill the worker and return what it said on stderr.
    fn end(mut self) -> String {
        // The whole group: bubblewrap and anything it left behind. A holder
        // that escaped it must not hang the caller on the stderr thread.
        kill_tree(&mut self.child);
        let _ = join_within(self.stderr_thread, KILLED_JOIN_WAIT);
        let tail = self
            .stderr
            .lock()
            .map(|tail| tail.clone())
            .unwrap_or_default();
        String::from_utf8_lossy(&tail).trim().to_string()
    }
}

/// One reader per open image. It owns the worker process: the worker never
/// outlives it, and a worker that dies or stalls is replaced on the next
/// request.
pub struct Reader {
    executable: PathBuf,
    image: PathBuf,
    /// The reference image of a diff, mounted at `/other`.
    other: Option<PathBuf>,
    out: PathBuf,
    account: Account,
    live: Option<Live>,
    next_id: u64,
    timeout: Option<Duration>,
    abort: Arc<AtomicBool>,
}

/// The bubblewrap command line of the reader worker.
pub(crate) fn sandbox_command(
    executable: &Path,
    image: &Path,
    other: Option<&Path>,
    out: &Path,
    account: &Path,
) -> Command {
    let mut command = sandbox_base(executable, image, other, out, account);
    command.args(["/worker", "--disk-reader"]);
    command
}

/// The shared analysis sandbox profile (`sandbox_profile`) with the image
/// mounted read-only at `/image`, the program at `/worker` and one writable
/// folder at `/out`: everything up to the program to run (tests run a shell
/// there to probe the sandbox).
pub(crate) fn sandbox_base(
    executable: &Path,
    image: &Path,
    other: Option<&Path>,
    out: &Path,
    account: &Path,
) -> Command {
    let mut command = Command::new("/usr/bin/bwrap");
    crate::sandbox_profile::apply(&mut command, account, &[], TMP_SIZE);
    command
        .arg("--ro-bind")
        .arg(executable)
        .arg("/worker")
        .arg("--ro-bind")
        .arg(image)
        .arg("/image");
    if let Some(other) = other {
        command.arg("--ro-bind").arg(other).arg("/other");
    }
    command
        .arg("--bind")
        .arg(out)
        .arg("/out")
        .args([
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
            "/out",
            "--",
            "/usr/bin/prlimit",
        ])
        .arg(format!("--as={ADDRESS_SPACE_SIZE}"))
        .arg(format!("--nofile={OPEN_FILE_LIMIT}"))
        .args(["--core=0", "--"]);
    command.env_clear();
    command
}

impl Reader {
    /// A reader of `image`, extracting into `out` (created, private). The
    /// worker starts with the first request.
    pub fn open(image: &Path, out: &Path) -> Result<Self, String> {
        Self::with_executable(crate::analysis::jobs::worker_executable()?, image, out)
    }

    /// [`Self::open`] with an explicit worker program (tests).
    pub fn with_executable(executable: PathBuf, image: &Path, out: &Path) -> Result<Self, String> {
        Self::with_executable_and_other(executable, image, None, out)
    }

    /// A reader that can also diff `image` against the reference `other`
    /// (mounted read-only at `/other`).
    pub fn open_with_other(image: &Path, other: &Path, out: &Path) -> Result<Self, String> {
        Self::with_executable_and_other(
            crate::analysis::jobs::worker_executable()?,
            image,
            Some(other),
            out,
        )
    }

    pub fn with_executable_and_other(
        executable: PathBuf,
        image: &Path,
        other: Option<&Path>,
        out: &Path,
    ) -> Result<Self, String> {
        crate::dependencies::require_tool(Path::new("/usr/bin/bwrap"), "bubblewrap")?;
        crate::dependencies::require_tool(Path::new("/usr/bin/prlimit"), "util-linux")?;
        crate::storage::private_dir(out).map_err(|error| format!("{}: {error}", out.display()))?;
        for path in std::iter::once(image).chain(other) {
            if !path.is_file() {
                return Err(format!("{} is not a disk image", path.display()));
            }
        }
        Ok(Self {
            executable,
            image: image.to_path_buf(),
            other: other.map(Path::to_path_buf),
            out: out.to_path_buf(),
            account: Account::new()?,
            live: None,
            next_id: 0,
            timeout: None,
            abort: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Use `flag`: set from another thread, it ends a request in progress
    /// quickly (the worker is killed), so closing a view does not wait for a
    /// long find.
    pub fn set_abort_flag(&mut self, flag: Arc<AtomicBool>) {
        self.abort = flag;
    }

    /// The id of the latest request: the name of its output under `out`.
    pub fn last_request_id(&self) -> u64 {
        self.next_id
    }

    /// Replace the per-request time limit (tests).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }

    /// The folder the worker writes extractions to.
    pub fn out(&self) -> &Path {
        &self.out
    }

    fn spawn(&self) -> Result<Live, String> {
        let mut command = sandbox_command(
            &self.executable,
            &self.image,
            self.other.as_deref(),
            &self.out,
            self.account.passwd(),
        );
        own_group(&mut command);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("mandatory bubblewrap isolation unavailable: {error}"))?;
        let stdin = child.stdin.take().ok_or("reader stdin unavailable")?;
        let stdout = child.stdout.take().ok_or("reader stdout unavailable")?;
        let mut stderr = child.stderr.take().ok_or("reader stderr unavailable")?;
        let tail = Arc::new(Mutex::new(Vec::new()));
        let kept = tail.clone();
        let stderr_thread = thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            while let Ok(count) = stderr.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                if let Ok(mut tail) = kept.lock() {
                    tail.extend_from_slice(&buffer[..count]);
                    let excess = tail.len().saturating_sub(4096);
                    tail.drain(..excess);
                }
            }
        });
        let (sender, answers) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                let count = (&mut reader)
                    .take(ANSWER_LIMIT + 1)
                    .read_until(b'\n', &mut line);
                match count {
                    Ok(0) | Err(_) => break,
                    Ok(_) if line.len() as u64 > ANSWER_LIMIT || line.last() != Some(&b'\n') => {
                        let _ = sender.send(Err("the reader sent an oversized answer".into()));
                        break;
                    }
                    Ok(_) => {
                        if sender.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Live {
            child,
            stdin,
            answers,
            stderr: tail,
            stderr_thread,
        })
    }

    fn stop(&mut self) -> String {
        self.live.take().map(Live::end).unwrap_or_default()
    }

    /// Send one request and wait for its answer. A worker that fails or
    /// stalls is killed and the error says so; the next request starts a new
    /// one.
    pub fn request(&mut self, request: DiskRequest) -> Result<Reply, String> {
        let timeout = self.timeout.unwrap_or_else(|| timeout_for(&request));
        if self.live.is_none() {
            self.live = Some(self.spawn()?);
        }
        self.next_id += 1;
        let id = self.next_id;
        let mut line = serde_json::to_vec(&Envelope { id, body: request })
            .map_err(|error| error.to_string())?;
        line.push(b'\n');
        let deadline = Instant::now() + timeout;
        let outcome = (|| -> Result<Reply, String> {
            let live = self.live.as_mut().ok_or("the reader is not running")?;
            live.stdin
                .write_all(&line)
                .and_then(|()| live.stdin.flush())
                .map_err(|_| "the reader stopped".to_string())?;
            loop {
                if self.abort.load(Ordering::Relaxed) {
                    return Err("cancelled".into());
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                match live
                    .answers
                    .recv_timeout(remaining.min(Duration::from_millis(100)))
                {
                    Ok(Ok(answer)) => {
                        let answer: Envelope<Reply> = serde_json::from_slice(&answer)
                            .map_err(|error| format!("the reader's answer is invalid: {error}"))?;
                        // An answer to an earlier, timed-out request is dropped.
                        if answer.id == id {
                            return Ok(answer.body);
                        }
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(RecvTimeoutError::Timeout) => {
                        if remaining <= Duration::from_millis(100) {
                            return Err("the reader did not answer in time".into());
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err("the reader stopped".into());
                    }
                }
            }
        })();
        if let Err(error) = &outcome {
            let detail = self.stop();
            return Err(if detail.is_empty() {
                error.clone()
            } else {
                format!("{error}: {detail}")
            });
        }
        outcome
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn timeout_for(request: &DiskRequest) -> Duration {
    match request {
        DiskRequest::Find { query } if query.mode.is_content() => {
            Duration::from_secs(CONTENT_SECONDS + 30)
        }
        DiskRequest::Find { .. } => Duration::from_secs(FIND_SECONDS + 30),
        DiskRequest::Diff => Duration::from_secs(DIFF_SECONDS + 60),
        DiskRequest::Extract { .. } => Duration::from_secs(15 * 60),
        _ => Duration::from_secs(60),
    }
}
