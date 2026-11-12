// SPDX-License-Identifier: GPL-3.0-only
//! What the recording can and cannot say, from the run's manifest (design 2.2.1).
//!
//! The figures are kept apart and never summed: transport loss, storage loss,
//! screen previews, reduced recording and read gaps are different faults.
//! `health` is the VM boot's transport health at the moment the run was saved,
//! so the rows that come from it are boot-wide, not the run's alone.
use antinomie_monitor_core::api::Health;
use antinomie_monitor_core::read_gaps::ReadGapStats;
use antinomie_monitor_core::reduced::ReducedRecording;
use antinomie_monitor_core::TelemetryLoss;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Which manifest the figures came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualitySource {
    /// Written when the VM stopped: `health` and `telemetry_loss`.
    Finalized,
    /// The run was sealed before the VM stopped: `telemetry_loss` alone.
    SealedEarly,
    /// No manifest, or one without either: nothing is known.
    #[default]
    Missing,
}

/// Guest sends that found the ring full and waited (never-drop mode).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendWaits {
    pub count: u64,
    pub total_ns: u64,
}

/// The transport held back to keep the guest or the disk going.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shedding {
    pub active: bool,
    pub never_drop_slowing: bool,
    pub shed_count: u64,
    pub shed_ns: u64,
}

/// Every figure is `None` when the manifest does not say.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Quality {
    pub source: QualitySource,
    pub telemetry_lost: Option<TelemetryLoss>,
    pub transport_dropped: Option<u64>,
    pub storage_dropped: Option<u64>,
    /// Screen preview rows skipped: not a recording loss.
    pub ui_dropped: Option<u64>,
    pub guest_note_lost: Option<u64>,
    /// io_uring and similar completions the guest could not report.
    pub async_lost: Option<u64>,
    pub reduced: Option<ReducedRecording>,
    /// Boot-wide; the window keeps those inside the run's span.
    pub read_gaps: Option<ReadGapStats>,
    pub guest_send_waits: Option<SendWaits>,
    pub writer_held_ns: Option<u64>,
    pub writer_held_longest_ns: Option<u64>,
    pub shedding: Option<Shedding>,
    pub ring_size: Option<u32>,
    pub send_wait_us: Option<u32>,
    /// Packets and bytes the recorder saved.
    pub packets: Option<u64>,
    pub bytes: Option<u64>,
    /// `kvm`, `tcg`, `tcg (KVM unavailable)`; `None` when not recorded.
    pub accelerator: Option<String>,
    /// Host Unix milliseconds the run started and ended, from the manifest.
    pub started_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    pub notes: Vec<String>,
}

impl Quality {
    /// Read the figures from a parsed `manifest.json` (`Value::Null` when there is none).
    pub fn from_manifest(manifest: &Value) -> Self {
        let mut quality = Self::default();
        let loss = manifest
            .get("telemetry_loss")
            .and_then(|loss| serde_json::from_value::<TelemetryLoss>(loss.clone()).ok());
        let health = manifest
            .get("health")
            .and_then(|health| serde_json::from_value::<Health>(health.clone()).ok());
        quality.source = match (&health, &loss) {
            (Some(_), _) => QualitySource::Finalized,
            (None, Some(_)) => QualitySource::SealedEarly,
            (None, None) => QualitySource::Missing,
        };
        quality.telemetry_lost = loss;
        if let Some(health) = health {
            quality.transport_dropped = Some(health.dropped);
            quality.storage_dropped = Some(health.storage_dropped_packets);
            quality.ui_dropped = Some(health.ui_dropped);
            quality.guest_note_lost = Some(health.guest_note_lost);
            quality.guest_send_waits = Some(SendWaits {
                count: health.transport_waits,
                total_ns: health.transport_wait_ns,
            });
            quality.writer_held_ns = Some(health.writer_held_ns);
            quality.writer_held_longest_ns = Some(health.writer_held_longest_ns);
            quality.shedding = Some(Shedding {
                active: health.shedding,
                never_drop_slowing: health.never_drop_slowing,
                shed_count: health.shed_count,
                shed_ns: health.shed_ns,
            });
            quality.ring_size = Some(health.ring_size);
            quality.send_wait_us = Some(health.send_wait_us);
            quality.read_gaps = Some(health.read_gaps);
        }
        quality.started_ms = manifest.get("started_ms").and_then(Value::as_u64);
        quality.ended_ms = manifest.get("ended_ms").and_then(Value::as_u64);
        quality.packets = manifest.get("packets").and_then(Value::as_u64);
        quality.bytes = manifest.get("bytes").and_then(Value::as_u64);
        // The run summary the manifest embeds.
        let run = manifest.get("run");
        quality.reduced = run
            .and_then(|run| run.get("reduced"))
            .filter(|reduced| !reduced.is_null())
            .and_then(|reduced| serde_json::from_value(reduced.clone()).ok());
        quality.async_lost = run
            .and_then(|run| run.get("execution"))
            .and_then(|execution| execution.get("async_loss_count"))
            .and_then(Value::as_u64);
        quality.accelerator = run
            .and_then(|run| run.get("environment"))
            .and_then(|environment| environment.get("accelerator"))
            .and_then(Value::as_str)
            .filter(|accelerator| !accelerator.is_empty())
            .map(str::to_owned);
        quality.notes = run
            .and_then(|run| run.get("notes"))
            .and_then(Value::as_array)
            .map(|notes| {
                notes
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        quality
    }

    /// Whether any packet is known lost (the quality strip's "Incomplete" chip).
    pub fn incomplete(&self) -> bool {
        self.telemetry_lost
            .is_some_and(|loss| loss.lost_packets > 0)
            || self.transport_dropped.is_some_and(|n| n > 0)
            || self.storage_dropped.is_some_and(|n| n > 0)
    }
}
