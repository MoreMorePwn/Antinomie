//! Bounded offline work, independent of rendering and the transport owner.
use antinomie_monitor_core::{
    recording, syscall_groups::SyscallGroup, AsyncPage, BackendOptions, CaptureSummary,
    FieldSummary, InvocationPage, RunSummary, TerminalPage, TerminalRecord,
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
};

mod totals;
pub(crate) use totals::key as totals_key;

/// Async observations one continuation request reads.
pub(crate) const ASYNC_PAGE: usize = antinomie_monitor_core::ASYNC_PREVIEW_LIMIT;

pub(crate) type ProcessTreeResult = Result<
    (
        Vec<antinomie_monitor_core::capture_processes::CaptureProcess>,
        Vec<String>,
    ),
    String,
>;

pub(crate) enum Request {
    InvocationRange {
        generation: u64,
        directory: PathBuf,
        offset: u64,
        skip: u64,
        limit: usize,
        capture: bool,
        pid: Option<u32>,
        query: String,
        hidden_categories: Vec<SyscallGroup>,
        cancel: Arc<AtomicBool>,
    },
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
        carried: Vec<(String, PathBuf)>,
    },
    Invocations {
        generation: u64,
        directory: PathBuf,
        offset: u64,
        limit: usize,
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
    /// One page of the async observations a call row only previews.
    AsyncObservations {
        generation: u64,
        directory: PathBuf,
        capture: bool,
        call: (u64, u64, u64),
        /// Inclusive event sequence cursor; `0` for the first page.
        from: u64,
        cancel: Arc<AtomicBool>,
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
        sort: Option<antinomie_monitor_core::ListingSort>,
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
        checked: Vec<String>,
        retained: Vec<String>,
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
    AsyncObservations {
        generation: u64,
        call: (u64, u64, u64),
        result: Result<AsyncPage, String>,
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
    /// The match counts of a trace view whose page came without them, as
    /// `(matching, saved)`. `key` is [`totals_key`] of the view.
    Totals {
        key: String,
        result: Result<(u64, u64), String>,
    },
}

/// State the worker threads share.
struct Shared {
    cancelled: Arc<AtomicBool>,
    active_invocations: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    counts: Arc<totals::Counts>,
    answers: mpsc::SyncSender<Answer>,
    wake: Option<eframe::egui::Context>,
    #[cfg(test)]
    tree_gate: Option<TreeGate>,
}

/// Test seam: holds the process-tree lane inside a request until released.
#[cfg(test)]
pub(crate) struct TreeGate {
    pub(crate) entered: Mutex<mpsc::Sender<()>>,
    pub(crate) release: Mutex<mpsc::Receiver<()>>,
}

fn serve(requests: mpsc::Receiver<Request>, shared: &Shared) {
    while let Ok(request) = requests.recv() {
        if shared.cancelled.load(Ordering::Relaxed) {
            break;
        }
        #[cfg(test)]
        if let (Some(gate), Request::ProcessTree { .. }) = (&shared.tree_gate, &request) {
            let _ = gate.entered.lock().unwrap().send(());
            // A dropped sender (a failed test) releases it too.
            let _ = gate.release.lock().unwrap().recv();
        }
        let answer = answer(request, shared);
        if shared.cancelled.load(Ordering::Relaxed) || shared.answers.send(answer).is_err() {
            break;
        }
        if let Some(ctx) = &shared.wake {
            ctx.request_repaint_of(eframe::egui::ViewportId::ROOT);
        }
    }
}

fn invocations(
    shared: &Shared,
    view: &totals::View,
    offset: u64,
    limit: usize,
    cancel: &Arc<AtomicBool>,
) -> Result<(InvocationPage, Option<(u64, u64)>), String> {
    invocation_range(shared, view, offset, 0, limit, cancel)
}

fn invocation_range(
    shared: &Shared,
    view: &totals::View,
    offset: u64,
    skip: u64,
    limit: usize,
    cancel: &Arc<AtomicBool>,
) -> Result<(InvocationPage, Option<(u64, u64)>), String> {
    let filter = crate::query::compile_note(&view.query);
    if let Some(error) = filter.error.as_ref() {
        return Err(error.clone());
    }
    // A page seeks to its cursor; the counts come from memory, from a thread
    // of their own, or here for a small recording.
    let found = view
        .open(cancel)?
        .matching_range_cancellable(
            offset,
            skip,
            limit,
            view.pid,
            cancel,
            totals::predicate(&filter, &view.hidden_categories),
        )
        .map_err(|error| error.to_string())?;
    let counts = shared
        .counts
        .totals(view, &found.stamp, cancel, &shared.answers, &shared.wake)?;
    Ok((found.page, counts))
}

fn answer(request: Request, shared: &Shared) -> Answer {
    match request {
        Request::InvocationRange {
            generation,
            directory,
            offset,
            skip,
            limit,
            capture,
            pid,
            query,
            hidden_categories,
            cancel,
        } => {
            *shared
                .active_invocations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&cancel));
            if shared.cancelled.load(Ordering::Relaxed) {
                cancel.store(true, Ordering::Relaxed);
            }
            let view = totals::View {
                directory,
                capture,
                pid,
                query,
                hidden_categories,
            };
            let read = invocation_range(shared, &view, offset, skip, limit, &cancel);
            *shared
                .active_invocations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            let (total, source_total) = match &read {
                Ok((_, Some((total, source_total)))) => (Some(*total), Some(*source_total)),
                _ => (None, None),
            };
            Answer::Invocations {
                generation,
                offset,
                total,
                source_total,
                result: read.map(|(page, _)| page),
            }
        }
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
                recording.process_tree_cancellable(root_pid, &path, &shared.cancelled)
            })
            .map_err(|e| e.to_string()),
        },
        Request::ListCaptures {
            options,
            vm_id,
            generation,
        } => Answer::ListCaptures {
            result: antinomie_monitor_core::capture::list_vm_captures(&options, &vm_id)
                .map_err(|error| error.to_string()),
            vm_id,
            generation,
        },
        Request::ListVm {
            options,
            vm_id,
            generation,
            carried,
        } => Answer::ListVm {
            result: recording::list_vm_runs(&options, &vm_id).map_err(|e| e.to_string()),
            vm_id,
            generation,
            checked: carried.iter().map(|(id, _)| id.clone()).collect(),
            retained: retained_run_ids(carried),
        },
        Request::Invocations {
            generation,
            directory,
            offset,
            limit,
            capture,
            pid,
            query,
            hidden_categories,
            cancel,
        } => {
            *shared
                .active_invocations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&cancel));
            if shared.cancelled.load(Ordering::Relaxed) {
                cancel.store(true, Ordering::Relaxed);
            }
            let view = totals::View {
                directory,
                capture,
                pid,
                query,
                hidden_categories,
            };
            let read = invocations(shared, &view, offset, limit, &cancel);
            *shared
                .active_invocations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            let (total, source_total) = match &read {
                Ok((_, Some((total, source_total)))) => (Some(*total), Some(*source_total)),
                _ => (None, None),
            };
            Answer::Invocations {
                generation,
                offset,
                total,
                source_total,
                result: read.map(|(page, _)| page),
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
            result: recording::open_recording_cancellable(&directory, &shared.cancelled)
                .and_then(|r| {
                    let mut page = r.terminal_replay(offset, 32)?;
                    let screen_warning = if page.next_offset.is_none() {
                        match r.terminal_screen() {
                            Ok(data) => {
                                page.records.push(TerminalRecord::Output(data));
                                None
                            }
                            Err(error) => {
                                Some(format!("Final terminal screen unavailable: {error}"))
                            }
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
            result: recording::read_captured_range(&directory, &field, offset, data_len)
                .map_err(|e| e.to_string()),
        },
        Request::AsyncObservations {
            generation,
            directory,
            capture,
            call,
            from,
            cancel,
        } => {
            if shared.cancelled.load(Ordering::Relaxed) {
                cancel.store(true, Ordering::Relaxed);
            }
            let view = totals::View {
                directory,
                capture,
                pid: None,
                query: String::new(),
                hidden_categories: Vec::new(),
            };
            Answer::AsyncObservations {
                generation,
                call,
                result: view.open(&cancel).and_then(|recording| {
                    recording
                        .async_page_cancellable(call, from, ASYNC_PAGE, &cancel)
                        .map_err(|error| error.to_string())
                }),
            }
        }
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
            sort,
            record_context,
        } => Answer::Listing {
            result: {
                let fields = crate::analysis::listing_fields(kind);
                let filter = crate::query::compile_table(&query, &fields);
                if let Some(error) = filter.error.clone() {
                    Err(error)
                } else {
                    antinomie_monitor_core::read_listing_page_sorted(
                        &directory,
                        &report_id,
                        kind,
                        start,
                        antinomie_monitor_core::LISTING_PAGE_MAX_ROWS,
                        &query,
                        sort,
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
    }
}

fn retained_run_ids(carried: Vec<(String, PathBuf)>) -> Vec<String> {
    carried
        .into_iter()
        .filter_map(|(id, directory)| directory.is_dir().then_some(id))
        .collect()
}

/// Reads saved recordings off the UI thread. Interactive reads (trace pages,
/// terminal replay, history lists, evidence ranges) share one thread; the
/// whole-recording process tree has its own, and the match counts of a big
/// recording are counted by a third, so none of them waits for another.
pub(crate) struct ArchiveWorker {
    sender: Option<mpsc::SyncSender<Request>>,
    bulk_sender: Option<mpsc::SyncSender<Request>>,
    receiver: Option<mpsc::Receiver<Answer>>,
    workers: Vec<thread::JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
    active_invocations: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    counts: Arc<totals::Counts>,
}

impl ArchiveWorker {
    pub(crate) fn new(wake: Option<eframe::egui::Context>) -> Result<Self, String> {
        Self::build(
            wake,
            #[cfg(test)]
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_tree_gate(gate: TreeGate) -> Result<Self, String> {
        Self::build(None, Some(gate))
    }

    fn build(
        wake: Option<eframe::egui::Context>,
        #[cfg(test)] tree_gate: Option<TreeGate>,
    ) -> Result<Self, String> {
        let (answers, receiver) = mpsc::sync_channel(4);
        let shared = Arc::new(Shared {
            cancelled: Arc::new(AtomicBool::new(false)),
            active_invocations: Arc::new(Mutex::new(None::<Arc<AtomicBool>>)),
            counts: totals::Counts::new(),
            answers,
            wake,
            #[cfg(test)]
            tree_gate,
        });
        let mut lanes = Vec::new();
        let mut workers = Vec::new();
        for name in ["archive-reader", "archive-process-tree"] {
            let (sender, requests) = mpsc::sync_channel(1);
            let lane_shared = Arc::clone(&shared);
            let spawned = thread::Builder::new()
                .name(name.into())
                .spawn(move || serve(requests, &lane_shared));
            match spawned {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    // Stop the lane that did start; its sender is dropped here.
                    drop(lanes);
                    shared.cancelled.store(true, Ordering::Relaxed);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error.to_string());
                }
            }
            lanes.push(sender);
        }
        let bulk_sender = lanes.pop();
        let sender = lanes.pop();
        Ok(Self {
            sender,
            bulk_sender,
            receiver: Some(receiver),
            workers,
            cancelled: Arc::clone(&shared.cancelled),
            active_invocations: Arc::clone(&shared.active_invocations),
            counts: Arc::clone(&shared.counts),
        })
    }

    fn lane(&self, request: &Request) -> Option<&mpsc::SyncSender<Request>> {
        match request {
            Request::ProcessTree { .. } => self.bulk_sender.as_ref(),
            _ => self.sender.as_ref(),
        }
    }

    pub(crate) fn request(&self, request: Request) -> Result<(), String> {
        self.lane(&request)
            .ok_or("archive worker closed")?
            .try_send(request)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn try_request(
        &self,
        request: Request,
    ) -> Result<(), Box<mpsc::TrySendError<Request>>> {
        match self.lane(&request) {
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
        self.bulk_sender.take();
        self.receiver.take();
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                eprintln!("archive worker panicked");
            }
        }
        self.counts.shut_down();
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

    #[test]
    fn carried_run_paths_are_validated_by_archive_work() {
        let existing = fixture(0);
        let missing = existing.0.join("missing-run");
        assert_eq!(
            retained_run_ids(vec![
                ("existing".into(), existing.0.clone()),
                ("missing".into(), missing),
            ]),
            vec!["existing"]
        );
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
            limit: 100,
            capture: true,
            pid,
            query: query.into(),
            hidden_categories,
            cancel,
        }
    }
    #[test]
    fn direct_rank_jump_counts_only_filtered_calls() {
        let fixture = fixture(1000);
        let worker = ArchiveWorker::new(None).unwrap();
        worker
            .try_request(Request::InvocationRange {
                generation: 7,
                directory: fixture.0.clone(),
                offset: 0,
                skip: 300,
                limit: 37,
                capture: false,
                pid: None,
                query: "call.id >= 150".into(),
                hidden_categories: Vec::new(),
                cancel: Arc::new(AtomicBool::new(false)),
            })
            .unwrap_or_else(|_| panic!("request rejected"));
        let answer = worker
            .wait_answer(std::time::Duration::from_secs(20))
            .unwrap();
        let Answer::Invocations {
            generation, result, ..
        } = answer
        else {
            panic!("wrong answer")
        };
        assert_eq!(generation, 7);
        let page = result.unwrap();
        let ids: Vec<_> = page.invocations.iter().map(|call| call.call_id).collect();
        assert_eq!(ids, (450..487).collect::<Vec<_>>());
        assert!(page.next_offset.is_some());
    }

    #[test]
    fn configurable_pages_follow_raw_cursors_without_skipping_filtered_calls() {
        let fixture = fixture(350);
        let worker = ArchiveWorker::new(None).unwrap();
        for (query, expected) in [("call.id >= 150", 150..350), ("call.id > 500", 0..0)] {
            for size in [1, 37, 100, 256] {
                let mut offset = 0;
                let mut ids = Vec::new();
                loop {
                    let mut asked = request(
                        &fixture.0,
                        query,
                        None,
                        Vec::new(),
                        Arc::new(AtomicBool::new(false)),
                    );
                    if let Request::Invocations {
                        offset: at, limit, ..
                    } = &mut asked
                    {
                        *at = offset;
                        *limit = size;
                    }
                    worker.request(asked).unwrap();
                    let Answer::Invocations { result, .. } =
                        worker.wait_answer(Duration::from_secs(60)).unwrap()
                    else {
                        panic!("wrong answer")
                    };
                    let page = result.unwrap();
                    assert!(page.invocations.len() <= size);
                    ids.extend(page.invocations.iter().map(|call| call.call_id));
                    let Some(next) = page.next_offset else { break };
                    assert!(next > offset);
                    offset = next;
                }
                assert_eq!(ids, expected.clone().collect::<Vec<_>>());
            }
        }
    }

    #[test]
    fn worker_reads_async_pages_for_a_saved_call_and_reports_unknown_or_cancelled_reads() {
        let fixture = fixture(10);
        let worker = ArchiveWorker::new(None).unwrap();
        let ask = |call: (u64, u64, u64), cancel: bool| {
            worker
                .request(Request::AsyncObservations {
                    generation: 3,
                    directory: fixture.0.clone(),
                    capture: true,
                    call,
                    from: 0,
                    cancel: Arc::new(AtomicBool::new(cancel)),
                })
                .unwrap();
            let Answer::AsyncObservations {
                generation,
                call: answered,
                result,
            } = worker.wait_answer(Duration::from_secs(60)).unwrap()
            else {
                panic!("wrong answer")
            };
            assert_eq!((generation, answered), (3, call));
            result
        };
        // The fixture's calls have no async observations: an empty, final page.
        let page = ask((9, 41, 0), false).unwrap();
        assert!(page.events.is_empty() && page.next_event_seq.is_none());
        assert_eq!(page.total, 0);
        assert!(ask((9, 41, 404), false).is_err());
        assert!(ask((9, 41, 0), true).unwrap_err().contains("cancelled"));
    }

    #[test]
    fn worker_searches_late_saved_calls_with_typed_query_process_and_category() {
        let fixture = fixture(350);
        let worker = ArchiveWorker::new(None).unwrap();
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
        } = worker.wait_answer(Duration::from_secs(60)).unwrap()
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
        } = worker.wait_answer(Duration::from_secs(60)).unwrap()
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
        } = worker.wait_answer(Duration::from_secs(60)).unwrap()
        else {
            panic!("wrong answer")
        };
        assert_eq!((total, source_total), (Some(0), Some(175)));
        assert!(result.unwrap().invocations.is_empty());
    }
    #[test]
    fn worker_rejects_invalid_query_and_precancelled_request() {
        let fixture = fixture(350);
        let worker = ArchiveWorker::new(None).unwrap();
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
            } = worker.wait_answer(Duration::from_secs(60)).unwrap()
            else {
                panic!("wrong answer")
            };
            assert!(result.is_err());
            assert!(total.is_none() && source_total.is_none());
        }
    }
    #[test]
    fn a_big_recording_answers_its_page_first_and_counts_once_for_the_view() {
        // 12,000 calls are about 3 MB of raw packets: past the inline limit.
        let fixture = fixture(12_000);
        let worker = ArchiveWorker::new(None).unwrap();
        // Answers that arrive while another is awaited (the counts may beat the page).
        let held = std::cell::RefCell::new(Vec::new());
        let next = |wanted: fn(&Answer) -> bool| loop {
            let position = held.borrow().iter().position(wanted);
            if let Some(position) = position {
                return held.borrow_mut().remove(position);
            }
            held.borrow_mut()
                .push(worker.wait_answer(Duration::from_secs(20)).unwrap());
        };
        let page = |query: &str, offset: u64| {
            let mut asked = request(
                &fixture.0,
                query,
                None,
                Vec::new(),
                Arc::new(AtomicBool::new(false)),
            );
            if let Request::Invocations { offset: at, .. } = &mut asked {
                *at = offset;
            }
            worker.request(asked).unwrap();
            let Answer::Invocations {
                total,
                source_total,
                result,
                ..
            } = next(|answer| matches!(answer, Answer::Invocations { .. }))
            else {
                unreachable!()
            };
            (total, source_total, result.unwrap())
        };
        let (total, source_total, first) = page("call.id >= 150", 0);
        assert_eq!((total, source_total), (None, None));
        assert_eq!(first.invocations.len(), 100);
        let key = totals_key(&fixture.0, true, None, "call.id >= 150", &[]);
        let Answer::Totals {
            key: counted,
            result,
        } = next(|answer| matches!(answer, Answer::Totals { .. }))
        else {
            unreachable!()
        };
        assert_eq!(counted, key);
        assert_eq!(result, Ok((11_850, 12_000)));
        // The next page of the same view carries the counts from memory.
        let (total, source_total, second) = page("call.id >= 150", first.next_offset.unwrap());
        assert_eq!((total, source_total), (Some(11_850), Some(12_000)));
        assert_eq!(second.invocations[0].call_id, 250);
        // Another filter is another view: counted by itself.
        let (total, _, _) = page("call.id >= 10000", 0);
        assert_eq!(total, None);
        let Answer::Totals {
            key: counted,
            result,
        } = next(|answer| matches!(answer, Answer::Totals { .. }))
        else {
            unreachable!()
        };
        assert_eq!(
            counted,
            totals_key(&fixture.0, true, None, "call.id >= 10000", &[])
        );
        assert_eq!(result, Ok((2_000, 12_000)));
    }

    #[test]
    fn dropping_the_worker_stops_a_count_in_progress() {
        let fixture = fixture(12_000);
        let worker = ArchiveWorker::new(None).unwrap();
        worker
            .request(request(
                &fixture.0,
                "call.id >= 0",
                None,
                Vec::new(),
                Arc::new(AtomicBool::new(false)),
            ))
            .unwrap();
        let Answer::Invocations { total, .. } =
            worker.wait_answer(Duration::from_secs(20)).unwrap()
        else {
            panic!("wrong answer")
        };
        assert_eq!(total, None);
        let started = Instant::now();
        drop(worker);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn dropping_worker_cancels_an_active_archive_scan() {
        let fixture = fixture(15_000);
        let worker = ArchiveWorker::new(None).unwrap();
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
