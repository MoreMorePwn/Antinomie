// SPDX-License-Identifier: GPL-3.0-only
//! How long a host work item may take (user decision 2026-11-11, section 5).
//!
//! Every item has an **expected time** and a **limit**:
//!
//! | Expected time, in this order | From |
//! |---|---|
//! | `median` | the median of the item's last runs on this host (at least [`MEDIAN_MIN`] of the last [`MEDIAN_KEEP`], kept in `<data>/service/host-times.json`), when it is not below the estimate |
//! | `estimate` | a base plus a rate per MiB of its input (the sample for a static tool, the recording for the others), times the host's load factor |
//! | `fixed` | the stage's fixed limit of design 4.1, when the input size is not known |
//!
//! The limit is `daemon.host_time_factor` (default 2) times the expected
//! time, at least [`MIN_LIMIT`]. A policy that sets
//! `analysis.static_time_limit_min` (or a job that overrides it) gives the
//! static tools that fixed limit instead (`policy`). Time an item spends in the
//! pool's queue, waiting for memory or in the engine's own analysis queue does
//! not count against its limit.
use super::{
    items::ItemKind,
    plan::{ANALYSE_WAIT, DIGEST_WAIT, HostPlan, REPORT_WAIT, TOOL_OWN_LIMIT_MIN},
};
use antinomie_monitor_core::analysis::AnalysisKind;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Runs kept per item name.
pub const MEDIAN_KEEP: usize = 9;
/// Runs needed before the median replaces the estimate.
pub const MEDIAN_MIN: usize = 3;
/// No item gets less time than this.
pub const MIN_LIMIT: u64 = 30;

/// The expected time of one item and its limit, in seconds.
#[derive(Clone, Debug, PartialEq)]
pub struct ItemTime {
    pub expected_s: u64,
    pub basis: &'static str,
    pub limit_s: u64,
}

/// What the estimate of an item reads.
#[derive(Clone, Copy, Debug, Default)]
pub struct Inputs {
    pub sample_bytes: Option<u64>,
    pub recording_bytes: Option<u64>,
    /// How much a busy host stretches work (1 when idle).
    pub load: f64,
}

/// Base seconds and seconds per MiB of a static tool at an idle host.
fn static_rate(kind: AnalysisKind) -> (f64, f64) {
    match kind {
        AnalysisKind::Metadata | AnalysisKind::Entropy | AnalysisKind::Hardening => (10.0, 1.0),
        AnalysisKind::Structures | AnalysisKind::Strings => (15.0, 3.0),
        AnalysisKind::Regex => (20.0, 5.0),
        AnalysisKind::Identification => (20.0, 2.0),
        AnalysisKind::Rules | AnalysisKind::Embedded => (30.0, 5.0),
        AnalysisKind::Unpacking => (60.0, 10.0),
        AnalysisKind::Disassembly => (60.0, 20.0),
        AnalysisKind::Capabilities | AnalysisKind::Floss => (90.0, 30.0),
        AnalysisKind::Decompilation => (180.0, 60.0),
    }
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / f64::from(1u32 << 20)
}

/// The recent run times of each item on this host.
pub struct Medians {
    file: Option<PathBuf>,
    runs: Mutex<BTreeMap<String, Vec<u64>>>,
}

impl Medians {
    /// No history (tests, direct one-shot use).
    pub fn none() -> Self {
        Self {
            file: None,
            runs: Mutex::new(BTreeMap::new()),
        }
    }

    /// The history kept in `file`; a missing or unreadable file is no history.
    pub fn load(file: &Path) -> Self {
        let runs = std::fs::read(file)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            file: Some(file.to_owned()),
            runs: Mutex::new(runs),
        }
    }

    pub fn median(&self, name: &str) -> Option<u64> {
        let runs = crate::store::lock(&self.runs);
        let mut list = runs.get(name)?.clone();
        if list.len() < MEDIAN_MIN {
            return None;
        }
        list.sort_unstable();
        Some(list[list.len() / 2])
    }

    /// Remember that `name` took `seconds` (only items that finished).
    pub fn record(&self, name: &str, seconds: u64) {
        let snapshot = {
            let mut runs = crate::store::lock(&self.runs);
            let list = runs.entry(name.to_owned()).or_default();
            list.push(seconds.max(1));
            if list.len() > MEDIAN_KEEP {
                list.remove(0);
            }
            runs.clone()
        };
        if let Some(file) = &self.file
            && let Ok(bytes) = serde_json::to_vec_pretty(&snapshot)
        {
            let _ = crate::store::mirror::write_private(file, &bytes);
        }
    }
}

/// The rules above, with the factor and the history.
pub struct Timing {
    pub factor: f64,
    pub medians: Medians,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            factor: crate::config::service::DEFAULT_HOST_TIME_FACTOR,
            medians: Medians::none(),
        }
    }
}

impl Timing {
    /// The estimate of `kind` from its input, or `None` when the input size
    /// is not known.
    fn estimate(kind: &ItemKind, plan: &HostPlan, inputs: &Inputs) -> Option<f64> {
        let recording = inputs.recording_bytes.map(mib);
        let engines = plan.engines.len().max(1) as f64;
        let seconds = match kind {
            ItemKind::Static(group) => {
                let size = mib(inputs.sample_bytes?);
                group
                    .iter()
                    .map(|k| {
                        let (base, rate) = static_rate(*k);
                        base + rate * size
                    })
                    .sum()
            }
            ItemKind::Triage => 20.0 + 10.0 * recording?,
            ItemKind::Detection => engines * (30.0 + 5.0 * recording?),
            ItemKind::Assess => 20.0 + 5.0 * recording?,
            ItemKind::Report => 30.0 + 5.0 * recording?,
        };
        Some(seconds * inputs.load.max(1.0))
    }

    /// The fixed limit of 4.1 for `kind`, in seconds.
    fn fixed(kind: &ItemKind) -> u64 {
        match kind {
            ItemKind::Static(group) => group.len() as u64 * u64::from(TOOL_OWN_LIMIT_MIN) * 60 + 60,
            ItemKind::Triage | ItemKind::Detection => ANALYSE_WAIT.as_secs(),
            ItemKind::Assess => DIGEST_WAIT.as_secs(),
            ItemKind::Report => REPORT_WAIT.as_secs(),
        }
    }

    /// The expected time and the limit of `kind` for a job.
    pub fn of(&self, kind: &ItemKind, plan: &HostPlan, inputs: &Inputs) -> ItemTime {
        // The median takes no account of the input's size: after a few small
        // jobs it would give a large one the time of a small one. It may
        // raise the estimate (a slow host), never lower it.
        let estimate = Self::estimate(kind, plan, inputs).map(|seconds| seconds.ceil() as u64);
        let (expected, basis) = match (self.medians.median(&kind.name()), estimate) {
            (Some(median), Some(estimate)) if estimate > median => (estimate, "estimate"),
            (Some(median), _) => (median, "median"),
            (None, Some(estimate)) => (estimate, "estimate"),
            (None, None) => (
                (Self::fixed(kind) as f64 * inputs.load.max(1.0)).ceil() as u64,
                "fixed",
            ),
        };
        let expected = expected.max(1);
        let limit = ((expected as f64) * self.factor.max(1.0)).ceil() as u64;
        let limit = limit.max(MIN_LIMIT);
        if let (ItemKind::Static(group), Some(minutes)) = (kind, plan.static_limit_min) {
            // A fixed limit of the policy or the job: tools x limit x 60 + 60.
            let minutes = if minutes == 0 {
                TOOL_OWN_LIMIT_MIN
            } else {
                minutes
            };
            let fixed = (group.len() as f64 * f64::from(minutes) * 60.0 * inputs.load.max(1.0))
                .ceil() as u64
                + 60;
            return ItemTime {
                expected_s: expected,
                basis: "policy",
                limit_s: fixed,
            };
        }
        ItemTime {
            expected_s: expected,
            basis,
            limit_s: limit,
        }
    }
}

/// The sizes the estimates read: the sample's, and the recording folder's.
pub fn inputs_of(job: &crate::api::job::Job, load: f64) -> Inputs {
    let recording_bytes = job
        .recording
        .as_ref()
        .and_then(|r| r.directory.as_deref())
        .map(|dir| folder_size(Path::new(dir)));
    Inputs {
        sample_bytes: job.sample.as_ref().map(|s| s.size),
        recording_bytes,
        load,
    }
}

/// Bytes under `dir`, bounded to a hundred thousand entries.
fn folder_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_owned()];
    let mut seen = 0usize;
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 100_000 {
                return total;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}
