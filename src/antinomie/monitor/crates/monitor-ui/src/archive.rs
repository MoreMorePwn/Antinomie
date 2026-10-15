//! Bounded offline work, independent of rendering and the transport owner.
use antinomie_monitor_core::{
    recording, syscall_groups::SyscallGroup, BackendOptions, CaptureSummary, FieldSummary,
    InvocationPage, RunSummary, TerminalPage, TerminalRecord,
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
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
        query: String,
        hidden_categories: Vec<SyscallGroup>,
        cancel: Arc<AtomicBool>,
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
        source_total: Option<u64>,
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
    active_invocations: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}

impl ArchiveWorker {
    pub(crate) fn new() -> Result<Self, String> {
        let (sender, requests) = mpsc::sync_channel(1);
        let (answers, receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let active_invocations = Arc::new(Mutex::new(None::<Arc<AtomicBool>>));
        let worker_active_invocations = Arc::clone(&active_invocations);
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
                            query,
                            hidden_categories,
                            cancel,
                        } => {
                            *worker_active_invocations
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some(Arc::clone(&cancel));
                            if worker_cancelled.load(Ordering::Relaxed) {
                                cancel.store(true, Ordering::Relaxed);
                            }
                            let filter = crate::query::compile_note(&query);
                            let opened = if let Some(error) = filter.error.as_ref() {
                                Err(error.clone())
                            } else if capture {
                                antinomie_monitor_core::capture::open_capture_recording_cancellable(
                                    &directory, &cancel,
                                )
                                .map_err(|error| error.to_string())
                            } else {
                                recording::open_recording_cancellable(&directory, &cancel)
                                    .map_err(|error| error.to_string())
                            };
                            let filtered = opened.and_then(|recording| {
                                recording
                                    .filtered_page_cancellable(
                                        offset,
                                        100,
                                        pid,
                                        &cancel,
                                        |invocation| {
                                            let visible = crate::trace::representative(invocation)
                                                .is_some_and(|event| {
                                                    SyscallGroup::of(&event.syscall_name)
                                                        .is_none_or(|group| {
                                                            !hidden_categories.contains(&group)
                                                        })
                                                });
                                            visible && filter.keep(invocation)
                                        },
                                    )
                                    .map_err(|error| error.to_string())
                            });
                            let total = filtered.as_ref().ok().map(|page| page.total);
                            let source_total = filtered.as_ref().ok().map(|page| page.source_total);
                            *worker_active_invocations
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                            Answer::Invocations {
                                generation,
                                offset,
                                total,
                                source_total,
                                result: filtered.map(|filtered| filtered.page),
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
            active_invocations,
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
        if let Some(cancel) = self
            .active_invocations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            cancel.store(true, Ordering::Relaxed);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{CaptureScope, CaptureState};
    use std::{
        fs,
        io::Write,
        sync::atomic::AtomicU64,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn fixture(call_count: u64) -> Fixture {
        static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ant-global-query-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        // Creating a new directory must succeed; never reuse/remove an existing path.
        fs::create_dir(&directory).unwrap();
        let summary = CaptureSummary {
            started_ms: None,
            id: "observation".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            capture_cookie: 17,
            scope: CaptureScope::AllUserspace,
            directory: directory.clone(),
            state: CaptureState::Stopped,
            recording_error: None,
            start_ns: Some(1),
            stop_ns: Some(2),
            incomplete_reason: Some("pending tail".into()),
        };
        fs::write(
            directory.join("capture.json"),
            serde_json::to_vec(&summary).unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({"capture":summary})).unwrap(),
        )
        .unwrap();
        let mut raw = fs::File::create(directory.join("telemetry.raw")).unwrap();
        for call in 0..call_count {
            let mut packet = vec![0; 264];
            packet[..4].copy_from_slice(b"ANTT");
            for (offset, value) in [(4, 1_u16), (6, 2), (8, 144), (10, 1), (96, 1)] {
                packet[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            }
            packet[12..16].copy_from_slice(&264_u32.to_le_bytes());
            packet[20..24].copy_from_slice(&1_u32.to_le_bytes());
            let pid = if call % 2 == 0 { 41_u32 } else { 42 };
            for (offset, value) in [
                (24, 9_u64),
                (32, u64::from(pid)),
                (40, call),
                (48, call),
                (56, call),
                (88, if call < 150 { 0 } else { 9 }),
                (128, 99),
                (136, 17),
            ] {
                packet[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            packet[72..76].copy_from_slice(&pid.to_le_bytes());
            packet[76..80].copy_from_slice(&pid.to_le_bytes());
            packet[98] = 1;
            packet[99] = 1;
            packet[120..124].copy_from_slice(&120_u32.to_le_bytes());
            raw.write_all(&264_u32.to_le_bytes()).unwrap();
            raw.write_all(&packet).unwrap();
        }
        raw.write_all(&264_u32.to_le_bytes()).unwrap();
        raw.write_all(&[0; 40]).unwrap();
        raw.sync_all().unwrap();
        Fixture(directory)
    }
    fn request(
        directory: &std::path::Path,
        query: &str,
        pid: Option<u32>,
        hidden_categories: Vec<SyscallGroup>,
        cancel: Arc<AtomicBool>,
    ) -> Request {
        Request::Invocations {
            generation: 1,
            directory: directory.into(),
            offset: 0,
            capture: true,
            pid,
            query: query.into(),
            hidden_categories,
            cancel,
        }
    }
    #[test]
    fn worker_searches_late_saved_calls_with_typed_query_process_and_category() {
        let fixture = fixture(350);
        let worker = ArchiveWorker::new().unwrap();
        let query = "call.id >= 150 && syscall.num == 9";
        worker
            .request(request(
                &fixture.0,
                query,
                None,
                Vec::new(),
                Arc::new(AtomicBool::new(false)),
            ))
            .unwrap();
        let Answer::Invocations {
            total,
            source_total,
            result,
            ..
        } = worker.wait_answer(Duration::from_secs(5)).unwrap()
        else {
            panic!("wrong answer")
        };
        let page = result.unwrap();
        assert_eq!((total, source_total), (Some(200), Some(350)));
        assert_eq!(page.invocations.len(), 100);
        assert_eq!(page.invocations[0].call_id, 150);
        assert_eq!(page.invocations[99].call_id, 249);
        assert!(page.next_offset.is_some());
        worker
            .request(request(
                &fixture.0,
                query,
                Some(42),
                Vec::new(),
                Arc::new(AtomicBool::new(false)),
            ))
            .unwrap();
        let Answer::Invocations {
            total,
            source_total,
            result,
            ..
        } = worker.wait_answer(Duration::from_secs(5)).unwrap()
        else {
            panic!("wrong answer")
        };
        let page = result.unwrap();
        assert_eq!((total, source_total), (Some(100), Some(175)));
        assert!(page
            .invocations
            .iter()
            .all(|call| call.entry.as_ref().unwrap().pid == 42));
        assert!(page.next_offset.is_none());
        let memory = SyscallGroup::of("mmap").unwrap();
        worker
            .request(request(
                &fixture.0,
                query,
                Some(42),
                vec![memory],
                Arc::new(AtomicBool::new(false)),
            ))
            .unwrap();
        let Answer::Invocations {
            total,
            source_total,
            result,
            ..
        } = worker.wait_answer(Duration::from_secs(5)).unwrap()
        else {
            panic!("wrong answer")
        };
        assert_eq!((total, source_total), (Some(0), Some(175)));
        assert!(result.unwrap().invocations.is_empty());
    }
    #[test]
    fn worker_rejects_invalid_query_and_precancelled_request() {
        let fixture = fixture(350);
        let worker = ArchiveWorker::new().unwrap();
        for (query, cancel) in [("syscall.num ==", false), ("", true)] {
            worker
                .request(request(
                    &fixture.0,
                    query,
                    None,
                    Vec::new(),
                    Arc::new(AtomicBool::new(cancel)),
                ))
                .unwrap();
            let Answer::Invocations {
                total,
                source_total,
                result,
                ..
            } = worker.wait_answer(Duration::from_secs(5)).unwrap()
            else {
                panic!("wrong answer")
            };
            assert!(result.is_err());
            assert!(total.is_none() && source_total.is_none());
        }
    }
    #[test]
    fn dropping_worker_cancels_an_active_archive_scan() {
        let fixture = fixture(15_000);
        let worker = ArchiveWorker::new().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        worker
            .request(request(
                &fixture.0,
                "call.id > 20000",
                None,
                Vec::new(),
                Arc::clone(&cancel),
            ))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if worker.active_invocations.lock().unwrap().is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "archive scan never became active"
            );
            thread::yield_now();
        }
        drop(worker);
        assert!(cancel.load(Ordering::Relaxed));
    }
}
