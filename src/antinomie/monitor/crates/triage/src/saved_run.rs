// SPDX-License-Identifier: GPL-3.0-only
//! A saved run as Triage reads it (design 1.4 U3): what selecting the run in
//! the GUI gathers, from the run's record (`RunSummary`), its artifact list and
//! the settings. The GUI builds its input and its scan request with these
//! functions; a headless caller, which has a `RunSummary` and no selected row,
//! gets the same index from [`SavedRun`].
use super::*;
use antinomie_monitor_core::{
    file_writes, settings, BackendOptions, RunArtifactState, RunArtifacts, RunSummary,
};
use std::path::PathBuf;

/// Whether `path` starts with a pcap magic number (either byte order).
pub fn pcap_magic(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if std::io::Read::read_exact(&mut file, &mut magic).is_err() {
        return false;
    }
    matches!(magic, [0xd4, 0xc3, 0xb2, 0xa1] | [0xa1, 0xb2, 0xc3, 0xd4])
}

/// What a run's artifact list says of its packet capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SavedCapture {
    /// No artifact list was written (yet).
    Absent,
    /// The list belongs to another run, boot or VM.
    Mismatch,
    /// The list names no readable capture.
    NoCapture,
    Found {
        file: PathBuf,
        /// The capture was closed: nothing will add to it.
        complete: bool,
    },
}

impl SavedCapture {
    /// Read the artifact list of `run`: its first capture that is a pcap.
    pub fn of(run: &RunSummary) -> Self {
        match RunArtifacts::load(&run.directory).ok().flatten() {
            None => Self::Absent,
            Some(artifacts)
                if artifacts.run_id != run.id
                    || artifacts.vm_id != run.vm_id
                    || artifacts.boot_id != run.boot_id =>
            {
                Self::Mismatch
            }
            Some(artifacts) => artifacts
                .network_captures
                .iter()
                .find(|file| file.is_file() && pcap_magic(file))
                .map_or(Self::NoCapture, |file| Self::Found {
                    file: file.clone(),
                    complete: artifacts.network_state == RunArtifactState::Complete,
                }),
        }
    }
}

/// Whether a run's pcap can still grow. A capture its writer left unclosed
/// (the VM stopped under it) is final: nothing will add to it, so a scan takes
/// what it holds and says so, not waiting for a segment that never closes.
pub fn pcap_open(run_live: bool, complete: bool, writing: bool) -> bool {
    run_live || (!complete && writing)
}

/// The settings a scan reads: Settings in the GUI, `settings.json` headless.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriageSettings {
    /// Caps on the file write content File activity keeps.
    pub write_limits: file_writes::Limits,
    /// Caps on the bytes the Changed files rebuild keeps.
    pub retention: files::Retention,
    /// Rows one table keeps per page; 0 reads as [`STORED_ROWS`].
    pub page_rows: usize,
    pub address_lookup: AddressLookup,
    /// The data folder: where a run's base is installed (guest user names).
    pub data_dir: Option<PathBuf>,
}

impl Default for TriageSettings {
    /// The GUI's defaults.
    fn default() -> Self {
        Self {
            write_limits: settings::EngineSettings::default().write_limits(),
            retention: files::Retention::default(),
            page_rows: STORED_ROWS,
            address_lookup: AddressLookup::default(),
            data_dir: None,
        }
    }
}

impl TriageSettings {
    /// The settings of a process with no window: the data directory's
    /// `settings.json` (its defaults when there is none), and no lookup that
    /// asks another machine: `dig` and `whois` are off, TShark's installed
    /// GeoIP fields stay (design 1.4 U3, 6.3). An unreadable file is an error,
    /// never silently the defaults.
    pub fn headless(options: &BackendOptions) -> Result<Self, String> {
        let stored = settings::load(&options.data_dir)?.unwrap_or_default();
        Ok(Self {
            write_limits: stored.write_limits(),
            address_lookup: AddressLookup::Tshark,
            data_dir: Some(options.data_dir.clone()),
            ..Self::default()
        })
    }
}

impl<'a> TriageInput<'a> {
    /// The input of the saved `run`, as the GUI makes it when the run is
    /// selected: `pcap` is its capture ([`SavedCapture`]). The run counts as
    /// finished unless its record says it is live; no VM boot of it is up.
    /// The GUI changes `run_finished`, `pcap_open` and `current_boot` for a
    /// run that is still going.
    pub fn for_run(run: &'a RunSummary, pcap: Option<&'a Path>) -> Self {
        Self {
            analysis: run.analysis.as_ref(),
            invocations: &[],
            vm_id: Some(&run.vm_id),
            boot_id: Some(&run.boot_id),
            run_id: Some(&run.id),
            archive: Some(&run.directory),
            pcap,
            pcap_open: false,
            clock_anchor: run.clock_anchor,
            started_ms: run.started_ms,
            root_cookie: run.root_task_cookie,
            run_finished: !run.state.is_live(),
            current_boot: false,
        }
    }
}

impl ScanRequest {
    /// Take the run's identity, clock and state from `input` (what the GUI
    /// does every frame for the run on screen).
    pub fn apply_input(&mut self, input: &TriageInput<'_>) {
        self.clock_anchor = input.clock_anchor;
        self.started_ms = input.started_ms;
        self.root_cookie = input.root_cookie;
        self.packed = input.analysis.and_then(rules::PackedImage::of);
        self.run_finished = input.run_finished;
        self.recording_open = input.current_boot;
        self.identity = input
            .vm_id
            .zip(input.boot_id)
            .zip(input.run_id)
            .map(|((vm, boot), run)| (vm.into(), boot.into(), run.into()));
    }

    /// Take the caps, the page size, the address lookup and the data folder.
    pub fn apply_settings(&mut self, settings: &TriageSettings) {
        self.write_limits = settings.write_limits;
        self.retention = settings.retention;
        self.page_rows = settings.page_rows;
        self.address_lookup = settings.address_lookup;
        self.data_dir.clone_from(&settings.data_dir);
    }

    /// The launch `run` was asked for: the root's pid, the program and its
    /// arguments; it names the root when the recording has no launch record.
    pub fn launch_of(run: Option<&RunSummary>) -> Option<(u32, String, Vec<String>)> {
        run.filter(|run| run.pid != 0)
            .map(|run| (run.pid, run.request.path.clone(), run.request.args.clone()))
    }

    /// The kernel revision of the run's base, when the run recorded it.
    pub fn kernel_revision_of(run: &RunSummary) -> Option<u32> {
        run.environment
            .as_ref()
            .and_then(|environment| environment.kernel_revision)
    }

    /// The request the GUI's Triage holds for the saved `run` with `settings`
    /// and no filter, sort or page: the index the tables and the export read.
    pub fn for_run(input: &TriageInput<'_>, run: &RunSummary, settings: &TriageSettings) -> Self {
        let mut request = Self::default();
        request.apply_input(input);
        request.apply_settings(settings);
        request.launch = Self::launch_of(Some(run));
        request.kernel_revision = Self::kernel_revision_of(run);
        request
    }
}

/// A saved run with everything its scan needs, owned: the record, its capture
/// and the settings. What a headless caller has instead of a selected row.
#[derive(Clone, Debug)]
pub struct SavedRun {
    pub run: RunSummary,
    /// The run's capture, when its artifact list names one.
    pub pcap: Option<PathBuf>,
    pub settings: TriageSettings,
}

impl SavedRun {
    pub fn new(run: RunSummary, settings: TriageSettings) -> Self {
        let pcap = match SavedCapture::of(&run) {
            SavedCapture::Found { file, .. } => Some(file),
            _ => None,
        };
        Self {
            run,
            pcap,
            settings,
        }
    }

    /// The saved `run` with the headless settings of `options`
    /// ([`TriageSettings::headless`]).
    pub fn open(run: RunSummary, options: &BackendOptions) -> Result<Self, String> {
        Ok(Self::new(run, TriageSettings::headless(options)?))
    }

    /// The run's Triage input ([`TriageInput::for_run`]).
    pub fn input(&self) -> TriageInput<'_> {
        TriageInput::for_run(&self.run, self.pcap.as_deref())
    }

    /// The scan request ([`ScanRequest::for_run`]).
    pub fn request(&self) -> ScanRequest {
        ScanRequest::for_run(&self.input(), &self.run, &self.settings)
    }

    /// Index the whole run, as the GUI does when it is selected.
    pub fn scan(&self, cancel: &Arc<AtomicBool>) -> Result<ArchiveScan, String> {
        self.scan_with(self.request(), cancel)
    }

    /// [`scan`](Self::scan) with `request` (one made by [`request`](Self::request)
    /// and given a progress counter, say).
    pub fn scan_with(
        &self,
        request: ScanRequest,
        cancel: &Arc<AtomicBool>,
    ) -> Result<ArchiveScan, String> {
        archive_scan::scan_archive_query(
            &self.run.directory,
            self.pcap.as_deref(),
            false,
            cancel,
            &request,
        )
    }
}
