// SPDX-License-Identifier: GPL-3.0-only
//! A thread that owns one sandboxed reader and answers one request at a time,
//! so the interface never waits for the image.
use antinomie_monitor_core::disks::{
    extract,
    reader::{DiskRequest, Reader, Reply},
};
use eframe::egui;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread::{self, JoinHandle},
};

pub(super) struct Job {
    pub token: u64,
    pub request: DiskRequest,
    /// For an extraction: the guest path, to name the host file.
    pub place: Option<String>,
}

pub(super) struct Answer {
    pub token: u64,
    pub reply: Result<Reply, String>,
    /// Where the extracted file was put (after it was sanitized and sealed).
    pub placed: Option<Result<PathBuf, String>>,
}

pub(super) struct Worker {
    sender: Option<Sender<Job>>,
    answers: Receiver<Answer>,
    abort: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    /// The token of the request in flight.
    pub busy: Option<u64>,
}

impl Worker {
    /// Start the thread; the sandbox itself starts with the first request.
    /// `other` is a reference image to diff `image` against.
    pub(super) fn start(
        ctx: egui::Context,
        name: &str,
        image: PathBuf,
        other: Option<PathBuf>,
        out: PathBuf,
    ) -> Result<Self, String> {
        let (sender, jobs) = mpsc::channel::<Job>();
        let (replies, answers) = mpsc::channel::<Answer>();
        let abort = Arc::new(AtomicBool::new(false));
        let flag = abort.clone();
        let thread = thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let opened = match &other {
                    Some(other) => Reader::open_with_other(&image, other, &out),
                    None => Reader::open(&image, &out),
                };
                let mut reader = opened.map(|mut reader| {
                    reader.set_abort_flag(flag.clone());
                    reader
                });
                while let Ok(job) = jobs.recv() {
                    if flag.load(Ordering::Relaxed) {
                        break;
                    }
                    let (reply, placed) = match reader.as_mut() {
                        Ok(reader) => {
                            let reply = reader.request(job.request);
                            let placed = match (&reply, &job.place) {
                                (Ok(Ok(_)), Some(guest)) => Some(extract::place(
                                    reader.out(),
                                    reader.last_request_id(),
                                    guest,
                                )),
                                (_, Some(_)) => {
                                    // A stopped or refused extraction can leave
                                    // a partial `<out>/<request id>`.
                                    let partial =
                                        reader.out().join(reader.last_request_id().to_string());
                                    let _ = std::fs::remove_file(partial);
                                    None
                                }
                                _ => None,
                            };
                            (reply, placed)
                        }
                        Err(error) => (Err(error.clone()), None),
                    };
                    let sent = replies.send(Answer {
                        token: job.token,
                        reply,
                        placed,
                    });
                    ctx.request_repaint();
                    if sent.is_err() {
                        break;
                    }
                }
            })
            .map_err(|error| format!("disk reader thread: {error}"))?;
        Ok(Self {
            sender: Some(sender),
            answers,
            abort,
            thread: Some(thread),
            busy: None,
        })
    }

    pub(super) fn send(&mut self, job: Job) {
        self.busy = Some(job.token);
        if self
            .sender
            .as_ref()
            .is_none_or(|sender| sender.send(job).is_err())
        {
            self.busy = None;
        }
    }

    pub(super) fn poll(&mut self) -> Vec<Answer> {
        let answers: Vec<Answer> = self.answers.try_iter().collect();
        if !answers.is_empty() {
            self.busy = None;
        }
        answers
    }
}

impl Drop for Worker {
    /// End the thread and its sandbox promptly, even in the middle of a find.
    fn drop(&mut self) {
        self.abort.store(true, Ordering::Relaxed);
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
