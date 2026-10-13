//! Bounded offline work, independent of rendering and the transport owner.
use antinomie_monitor_core::{
    recording, BackendOptions, CaptureSummary, FieldSummary, InvocationPage, RunSummary,
    TerminalPage, TerminalRecord,
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

pub(crate) type ProcessTreeResult = Result<
    (
        Vec<antinomie_monitor_core::capture_processes::CaptureProcess>,
        Vec<String>,
    ),
    String,
>;

pub(crate) enum Request {
    ProcessTree {
        run_id: String,
        directory: PathBuf,
        root_pid: u32,
        path: String,
    },
    ListCaptures {
        options: BackendOptions,
        vm_id: String,
        generation: u64,
    },
    ListVm {
        options: BackendOptions,
        vm_id: String,
        generation: u64,
    },
    Invocations {
        generation: u64,
        directory: PathBuf,
        offset: u64,
        capture: bool,
        /// Only this guest process (thread group ID).
        pid: Option<u32>,
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
    Specimen {
        view_key: String,
        generation: u64,
        directory: PathBuf,
        report_id: String,
        offset: u64,
        data_len: usize,
    },
    Listing {
        view_key: String,
        generation: u64,
        directory: PathBuf,
        report_id: String,
        kind: antinomie_monitor_core::AnalysisKind,
        start: u64,
        query: String,
        record_context: Vec<(&'static str, crate::query::RowValue)>,
    },
}

pub(crate) struct TerminalReplay {
    pub(crate) page: TerminalPage,
    pub(crate) screen_warning: Option<String>,
}

pub(crate) enum Answer {
    ProcessTree {
        run_id: String,
        result: ProcessTreeResult,
    },
    ListCaptures {
        vm_id: String,
        generation: u64,
        result: Result<Vec<CaptureSummary>, String>,
    },
    #[cfg(test)]
    List(Result<Vec<RunSummary>, String>),
    ListVm {
        vm_id: String,
        generation: u64,
        result: Result<Vec<RunSummary>, String>,
    },
    Invocations {
        generation: u64,
        offset: u64,
        total: Option<u64>,
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
    Specimen {
        view_key: String,
        generation: u64,
        report_id: String,
        offset: u64,
        data_len: usize,
        result: Result<antinomie_monitor_core::AnalysisSpecimenPage, String>,
    },
    Listing {
        view_key: String,
        generation: u64,
        result: Result<antinomie_monitor_core::AnalysisListingPage, String>,
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
                        Request::ProcessTree {
                            run_id,
                            directory,
                            root_pid,
                            path,
                        } => Answer::ProcessTree {
                            run_id,
                            result: Ok(recording::Recording {
                                directory,
                                manifest: serde_json::Value::Null,
                                events: Vec::new(),
                            })
                            .and_then(|recording| {
                                recording.process_tree_cancellable(
                                    root_pid,
                                    &path,
                                    &worker_cancelled,
                                )
                            })
                            .map_err(|e| e.to_string()),
                        },
                        Request::ListCaptures {
                            options,
                            vm_id,
                            generation,
                        } => Answer::ListCaptures {
                            result: antinomie_monitor_core::capture::list_vm_captures(
                                &options, &vm_id,
                            )
                            .map_err(|error| error.to_string()),
                            vm_id,
                            generation,
                        },
                        Request::ListVm {
                            options,
                            vm_id,
                            generation,
                        } => Answer::ListVm {
                            result: recording::list_vm_runs(&options, &vm_id)
                                .map_err(|e| e.to_string()),
                            vm_id,
                            generation,
                        },
                        Request::Invocations {
                            generation,
                            directory,
                            offset,
                            capture,
                            pid,
                        } => {
                            let opened = if capture {
                                antinomie_monitor_core::capture::open_capture_recording_cancellable(
                                    &directory,
                                    &worker_cancelled,
                                )
                            } else {
                                recording::open_recording_cancellable(&directory, &worker_cancelled)
                            };
                            let total = opened.as_ref().ok().and_then(|r| {
                                r.invocation_count_cancellable(pid, &worker_cancelled).ok()
                            });
                            Answer::Invocations {
                                generation,
                                offset,
                                total,
                                result: opened
                                    .and_then(|r| {
                                        r.process_page_cancellable(
                                            offset,
                                            100,
                                            pid,
                                            &worker_cancelled,
                                        )
                                    })
                                    .map_err(|e| e.to_string()),
                            }
                        }
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
                        Request::Specimen {
                            view_key,
                            generation,
                            directory,
                            report_id,
                            offset,
                            data_len,
                        } => Answer::Specimen {
                            result: antinomie_monitor_core::read_specimen_range(
                                &directory, &report_id, offset, data_len,
                            ),
                            view_key,
                            generation,
                            report_id,
                            offset,
                            data_len,
                        },
                        Request::Listing {
                            view_key,
                            generation,
                            directory,
                            report_id,
                            kind,
                            start,
                            query,
                            record_context,
                        } => Answer::Listing {
                            result: {
                                let fields = crate::analysis::listing_fields(kind);
                                let filter = crate::query::compile_table(&query, &fields);
                                if let Some(error) = filter.error.clone() {
                                    Err(error)
                                } else {
                                    antinomie_monitor_core::read_listing_page_with(
                                        &directory,
                                        &report_id,
                                        kind,
                                        start,
                                        antinomie_monitor_core::LISTING_PAGE_MAX_ROWS,
                                        &query,
                                        |entry| {
                                            filter.keep_table(&crate::analysis::listing_row_with(
                                                entry,
                                                &record_context,
                                            ))
                                        },
                                    )
                                }
                            },
                            view_key,
                            generation,
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
