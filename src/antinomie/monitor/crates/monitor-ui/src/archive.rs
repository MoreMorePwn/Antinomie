//! Bounded offline work, independent of rendering and the transport owner.
use antinomie_monitor_core::{
    recording, FieldSummary, InvocationPage, RunSummary, TerminalPage, TerminalRecord,
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

pub(crate) enum Request {
    List(PathBuf),
    Invocations {
        generation: u64,
        directory: PathBuf,
        offset: u64,
    },
    Terminal {
        run_id: String,
        generation: u64,
        directory: PathBuf,
        offset: u64,
    },
    Captured {
        generation: u64,
        directory: PathBuf,
        field: FieldSummary,
        offset: u64,
        data_len: usize,
    },
}

pub(crate) struct TerminalReplay {
    pub(crate) page: TerminalPage,
    pub(crate) screen_warning: Option<String>,
}

pub(crate) enum Answer {
    List(Result<Vec<RunSummary>, String>),
    Invocations {
        generation: u64,
        offset: u64,
        result: Result<InvocationPage, String>,
    },
    Terminal {
        run_id: String,
        generation: u64,
        result: Result<TerminalReplay, String>,
    },
    Captured {
        generation: u64,
        offset: u64,
        result: Result<Vec<u8>, String>,
    },
}

pub(crate) struct ArchiveWorker {
    sender: Option<mpsc::SyncSender<Request>>,
    receiver: Option<mpsc::Receiver<Answer>>,
    worker: Option<thread::JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
}

impl ArchiveWorker {
    pub(crate) fn new() -> Result<Self, String> {
        let (sender, requests) = mpsc::sync_channel(1);
        let (answers, receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let worker = thread::Builder::new()
            .name("archive-reader".into())
            .spawn(move || {
                while let Ok(request) = requests.recv() {
                    if worker_cancelled.load(Ordering::Relaxed) {
                        break;
                    }
                    let answer = match request {
                        Request::List(root) => {
                            Answer::List(recording::list_runs(&root).map_err(|e| e.to_string()))
                        }
                        Request::Invocations {
                            generation,
                            directory,
                            offset,
                        } => Answer::Invocations {
                            generation,
                            offset,
                            result: recording::open_recording_cancellable(
                                &directory,
                                &worker_cancelled,
                            )
                            .and_then(|r| {
                                r.invocation_page_cancellable(offset, 256, &worker_cancelled)
                            })
                            .map_err(|e| e.to_string()),
                        },
                        Request::Terminal {
                            run_id,
                            generation,
                            directory,
                            offset,
                        } => Answer::Terminal {
                            run_id,
                            generation,
                            result: recording::open_recording_cancellable(
                                &directory,
                                &worker_cancelled,
                            )
                            .and_then(|r| {
                                let mut page = r.terminal_replay(offset, 32)?;
                                let screen_warning = if page.next_offset.is_none() {
                                    match r.terminal_screen() {
                                        Ok(data) => {
                                            page.records.push(TerminalRecord::Output(data));
                                            None
                                        }
                                        Err(error) => Some(format!(
                                            "Final terminal screen unavailable: {error}"
                                        )),
                                    }
                                } else {
                                    None
                                };
                                Ok(TerminalReplay {
                                    page,
                                    screen_warning,
                                })
                            })
                            .map_err(|e| e.to_string()),
                        },
                        Request::Captured {
                            generation,
                            directory,
                            field,
                            offset,
                            data_len,
                        } => Answer::Captured {
                            generation,
                            offset,
                            result: recording::read_captured_range(
                                &directory, &field, offset, data_len,
                            )
                            .map_err(|e| e.to_string()),
                        },
                    };
                    if worker_cancelled.load(Ordering::Relaxed) || answers.send(answer).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            sender: Some(sender),
            receiver: Some(receiver),
            worker: Some(worker),
            cancelled,
        })
    }

    pub(crate) fn request(&self, request: Request) -> Result<(), String> {
        self.sender
            .as_ref()
            .ok_or("archive worker closed")?
            .try_send(request)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn try_request(
        &self,
        request: Request,
    ) -> Result<(), Box<mpsc::TrySendError<Request>>> {
        match &self.sender {
            Some(sender) => sender.try_send(request).map_err(Box::new),
            None => Err(Box::new(mpsc::TrySendError::Disconnected(request))),
        }
    }

    pub(crate) fn receive(&self) -> Option<Answer> {
        self.receiver.as_ref()?.try_recv().ok()
    }

    #[cfg(test)]
    pub(crate) fn wait_answer(&self, timeout: std::time::Duration) -> Option<Answer> {
        self.receiver.as_ref()?.recv_timeout(timeout).ok()
    }
}

impl Drop for ArchiveWorker {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        // Disconnect both directions before joining, including a worker blocked on answers.
        self.sender.take();
        self.receiver.take();
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                eprintln!("archive worker panicked");
            }
        }
    }
}
