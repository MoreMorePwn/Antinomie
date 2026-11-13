// SPDX-License-Identifier: GPL-3.0-only
//! The recording phase (design 5.12.2): `live`, `finalizing`, `complete` or
//! `interrupted`, the state of the writer, and whether the layer is pending.
//!
//! Where a service owns the engine, `Snapshot.disk_layers` is the truth and
//! wins. A reader without one (a CLI beside a GUI, a read-only service) applies
//! the marker `run-layer.json` and the owner test of the engine
//! (`disk_layers::read_phase`). A read of a run that is still being settled
//! answers with its phase; it never claims a final total.

use super::types::{LayerState, OwnerState};
use crate::api::run::RecordingPhase;
use antinomie_monitor_core::disk_layers::{
    self, DiskLayer, LayerPhase, OwnerState as CoreOwner, RecordingPhase as CorePhase,
};
use std::path::Path;

/// What a reader knows about the writer of a recording.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseInfo {
    pub phase: RecordingPhase,
    pub owner: OwnerState,
    pub layer: LayerState,
}

impl PhaseInfo {
    /// Pages of this recording report `total_exact: false`: it still grows.
    pub fn growing(&self) -> bool {
        self.phase == RecordingPhase::Live
    }

    /// Pages say `partial: true`: the writer is gone and the recording is as
    /// it left it.
    pub fn partial(&self) -> bool {
        self.phase == RecordingPhase::Interrupted
    }

    /// A binding may cache a page by `generation` (the ETag): only a complete
    /// recording, and never one whose owner could not be told.
    pub fn cacheable(&self) -> bool {
        self.phase == RecordingPhase::Complete && self.owner != OwnerState::Unknown
    }
}

/// The engine's own list, when the service owns the engine (`Snapshot`).
pub trait LayerSource: Send + Sync {
    fn layers(&self) -> Vec<DiskLayer>;
}

/// A fixed list, for a service that was handed one snapshot and for tests.
pub struct FixedLayers(pub Vec<DiskLayer>);

impl LayerSource for FixedLayers {
    fn layers(&self) -> Vec<DiskLayer> {
        self.0.clone()
    }
}

/// The phase of the recording of `boot_id` of the VM whose folder is
/// `disk_directory`.
///
/// `run_interrupted` is the saved run state `interrupted`: with no pending
/// layer it still makes the recording `interrupted`. `snapshot` is the
/// engine's list when there is one; it wins over the marker.
pub fn detect(
    disk_directory: &Path,
    vm_id: &str,
    boot_id: &str,
    run_interrupted: bool,
    snapshot: Option<&[DiskLayer]>,
) -> PhaseInfo {
    let boot = match snapshot {
        Some(layers) => from_snapshot(layers, vm_id, boot_id),
        None => from_marker(disk_directory, boot_id),
    };
    if boot.phase == RecordingPhase::Complete && run_interrupted {
        return PhaseInfo {
            phase: RecordingPhase::Interrupted,
            owner: OwnerState::Gone,
            layer: LayerState::None,
        };
    }
    boot
}

fn from_snapshot(layers: &[DiskLayer], vm_id: &str, boot_id: &str) -> PhaseInfo {
    match layers
        .iter()
        .find(|layer| layer.vm_id == vm_id && layer.boot_id == boot_id)
    {
        // The engine that published the list is the owner.
        Some(layer) => PhaseInfo {
            phase: match layer.phase {
                LayerPhase::Live | LayerPhase::Saving => RecordingPhase::Live,
                LayerPhase::Finalizing => RecordingPhase::Finalizing,
            },
            owner: OwnerState::Alive,
            layer: LayerState::Pending,
        },
        None => complete(),
    }
}

fn from_marker(disk_directory: &Path, boot_id: &str) -> PhaseInfo {
    let reading = disk_layers::read_phase(disk_directory, boot_id);
    let owner = match reading.owner {
        CoreOwner::Alive => OwnerState::Alive,
        CoreOwner::Gone => OwnerState::Gone,
        CoreOwner::Unknown => OwnerState::Unknown,
    };
    match reading.phase {
        CorePhase::Complete => complete(),
        CorePhase::Live => PhaseInfo {
            phase: RecordingPhase::Live,
            owner,
            layer: LayerState::Pending,
        },
        CorePhase::Interrupted => PhaseInfo {
            phase: RecordingPhase::Interrupted,
            owner,
            layer: LayerState::Pending,
        },
        CorePhase::Finalizing => PhaseInfo {
            phase: RecordingPhase::Finalizing,
            owner,
            layer: if reading.orphaned {
                LayerState::Orphaned
            } else {
                LayerState::Pending
            },
        },
    }
}

/// No layer is pending: nobody writes the recording.
fn complete() -> PhaseInfo {
    PhaseInfo {
        phase: RecordingPhase::Complete,
        owner: OwnerState::Gone,
        layer: LayerState::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{
        disk_layers::{Marker, Owner},
        snapshots::RunLayerRecord,
    };
    use std::path::PathBuf;

    struct Folder(PathBuf);

    impl Folder {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "ant-phase-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        /// A `run-layer.json` as the engine writes it.
        fn marker(&self, boot: &str, phase: Option<LayerPhase>, owner: Owner) {
            let record = RunLayerRecord {
                format: 1,
                vm_id: "vm".into(),
                boot_id: boot.into(),
                boot_dir: self.0.join("boots").join(boot),
                sealed: "a".into(),
                top: "b".into(),
                manifest_absent: false,
                marker: Marker {
                    phase,
                    phase_ms: Some(2),
                    started_ms: Some(1),
                    owner,
                },
            };
            std::fs::write(
                self.0.join("run-layer.json"),
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        }
    }

    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn gone_owner() -> Owner {
        Owner {
            pid: Some(1),
            start_ticks: Some(1),
            host_boot: Some("another-host-boot".into()),
            pid_ns: Some("pid:[1]".into()),
        }
    }

    fn at(dir: &Folder, boot: &str, interrupted: bool) -> PhaseInfo {
        detect(&dir.0, "vm", boot, interrupted, None)
    }

    #[test]
    fn no_marker_is_complete_and_a_later_boot_settles_the_earlier_one() {
        let dir = Folder::new("none");
        let info = at(&dir, "b1", false);
        assert_eq!(info.phase, RecordingPhase::Complete);
        assert_eq!(info.layer, LayerState::None);
        assert!(info.cacheable());
        // A marker that names another boot: this one is settled.
        dir.marker("b2", Some(LayerPhase::Live), Owner::current());
        assert_eq!(at(&dir, "b1", false).phase, RecordingPhase::Complete);
        assert_eq!(at(&dir, "b2", false).phase, RecordingPhase::Live);
    }

    #[test]
    fn live_and_saving_with_a_living_owner_are_live_and_grow() {
        let dir = Folder::new("live");
        for phase in [Some(LayerPhase::Live), Some(LayerPhase::Saving), None] {
            dir.marker("b1", phase, Owner::current());
            let info = at(&dir, "b1", false);
            assert_eq!(info.phase, RecordingPhase::Live, "{phase:?}");
            assert_eq!(info.owner, OwnerState::Alive);
            assert_eq!(info.layer, LayerState::Pending);
            assert!(info.growing());
            assert!(!info.cacheable());
        }
    }

    #[test]
    fn a_gone_owner_makes_live_and_saving_interrupted() {
        let dir = Folder::new("gone");
        for phase in [LayerPhase::Live, LayerPhase::Saving] {
            dir.marker("b1", Some(phase), gone_owner());
            let info = at(&dir, "b1", false);
            assert_eq!(info.phase, RecordingPhase::Interrupted, "{phase:?}");
            assert_eq!(info.owner, OwnerState::Gone);
            assert!(info.partial());
        }
        // A pid that no longer exists, in the reader's own namespace.
        let mut dead = Owner::current();
        dead.pid = Some(u32::MAX - 1);
        dir.marker("b1", Some(LayerPhase::Live), dead);
        assert_eq!(at(&dir, "b1", false).phase, RecordingPhase::Interrupted);
    }

    #[test]
    fn another_pid_namespace_is_live_with_an_unknown_owner_and_never_cached() {
        let dir = Folder::new("unknown");
        let mut elsewhere = Owner::current();
        elsewhere.pid_ns = Some("pid:[4026999999]".into());
        dir.marker("b1", Some(LayerPhase::Saving), elsewhere);
        let info = at(&dir, "b1", false);
        assert_eq!(info.phase, RecordingPhase::Live);
        assert_eq!(info.owner, OwnerState::Unknown);
        assert!(!info.cacheable());
    }

    #[test]
    fn finalizing_stays_finalizing_and_says_orphaned_when_the_finalizer_is_gone() {
        let dir = Folder::new("final");
        dir.marker("b1", Some(LayerPhase::Finalizing), Owner::current());
        let info = at(&dir, "b1", false);
        assert_eq!(info.phase, RecordingPhase::Finalizing);
        assert_eq!(info.owner, OwnerState::Alive);
        // The test process holds no run-layer.lock, so the probe finds it
        // free; that alone marks the finalizer gone (5.12.2).
        std::fs::write(dir.0.join("run-layer.lock"), b"").unwrap();
        assert_eq!(at(&dir, "b1", false).layer, LayerState::Orphaned);
        dir.marker("b1", Some(LayerPhase::Finalizing), gone_owner());
        let info = at(&dir, "b1", false);
        assert_eq!(info.phase, RecordingPhase::Finalizing);
        assert_eq!(info.layer, LayerState::Orphaned);
        assert!(!info.growing());
    }

    #[test]
    fn a_saved_interrupted_state_without_a_layer_is_interrupted() {
        let dir = Folder::new("state");
        let info = at(&dir, "b1", true);
        assert_eq!(info.phase, RecordingPhase::Interrupted);
        assert!(info.partial());
    }

    #[test]
    fn the_engines_snapshot_wins_over_the_marker() {
        let dir = Folder::new("snap");
        // The marker would say interrupted.
        dir.marker("b1", Some(LayerPhase::Live), gone_owner());
        let layer = |phase| DiskLayer {
            vm_id: "vm".into(),
            boot_id: "b1".into(),
            phase,
            started_ms: 1,
            phase_ms: 2,
        };
        let from = |layers: &[DiskLayer]| detect(&dir.0, "vm", "b1", false, Some(layers));
        assert_eq!(from(&[layer(LayerPhase::Live)]).phase, RecordingPhase::Live);
        assert_eq!(
            from(&[layer(LayerPhase::Saving)]).phase,
            RecordingPhase::Live
        );
        let finalizing = from(&[layer(LayerPhase::Finalizing)]);
        assert_eq!(finalizing.phase, RecordingPhase::Finalizing);
        assert_eq!(finalizing.layer, LayerState::Pending);
        // Absent from the list: complete, whatever the stale marker says.
        assert_eq!(from(&[]).phase, RecordingPhase::Complete);
        // Another VM's entry does not count.
        let mut other = layer(LayerPhase::Live);
        other.vm_id = "other".into();
        assert_eq!(from(&[other]).phase, RecordingPhase::Complete);
    }
}
