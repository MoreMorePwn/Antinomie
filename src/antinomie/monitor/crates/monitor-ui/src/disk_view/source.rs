// SPDX-License-Identifier: MIT
//! What the "Current disk" entry reads: the VM's current disk, the frozen
//! layer of a saved checkpoint, or the installed base image, and, for a
//! disk with a partition table, which partition. One rule for all of them:
//! the VM must be off.
use super::*;
use crate::theme;
use antinomie_monitor_core::{
    disks::{
        partition::{Partition, PartitionFs},
        DiskSourceKind, DiskSourceSpec,
    },
    VmCheckpoint, VmSnapshotConsistency, VmSnapshotMode,
};

/// A source and, for a partitioned disk, the partition the user chose
/// (`None`: the root or largest ext4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pick {
    pub source: DiskSourceSpec,
    pub partition: Option<u32>,
}

impl Pick {
    pub(super) fn of_source(source: DiskSourceSpec) -> Self {
        Self {
            source,
            partition: None,
        }
    }
}

/// The saved, not deleted, checkpoints a source can be taken from, newest
/// first.
pub(crate) fn offered(checkpoints: &[VmCheckpoint]) -> Vec<&VmCheckpoint> {
    let mut offered: Vec<_> = checkpoints
        .iter()
        .filter(|checkpoint| !checkpoint.deleted)
        .collect();
    offered.sort_by(|a, b| {
        b.created_unix_ms
            .cmp(&a.created_unix_ms)
            .then(b.id.cmp(&a.id))
    });
    offered
}

fn consistency(checkpoint: &VmCheckpoint) -> &'static str {
    match checkpoint.consistency {
        VmSnapshotConsistency::Stopped => "stopped",
        VmSnapshotConsistency::CrashConsistent => "crash-consistent",
        VmSnapshotConsistency::Paused => "paused",
    }
}

/// `before-run · 14:05 · Disk · stopped`.
pub(super) fn checkpoint_label(checkpoint: &VmCheckpoint) -> String {
    format!(
        "{} · {} · {} · {}",
        display_name(&checkpoint.name),
        clock(checkpoint.created_unix_ms / 1000),
        match checkpoint.mode {
            VmSnapshotMode::Disk => "Disk",
            VmSnapshotMode::Full => "Full",
        },
        consistency(checkpoint)
    )
}

impl DiskView {
    /// "Current disk (VM off)", "Disk at before-run (VM off)", "Base image
    /// (VM off)": the entry's name for the source being read.
    pub(super) fn source_title(&self, source: &DiskSourceSpec) -> String {
        format!("{} (VM off)", self.source_name(source))
    }

    /// "Current disk", "Disk at before-run", "Base image".
    pub(super) fn source_name(&self, source: &DiskSourceSpec) -> String {
        let kind = match source {
            DiskSourceSpec::Current => DiskSourceKind::Current,
            DiskSourceSpec::Base => DiskSourceKind::Base,
            DiskSourceSpec::Checkpoint(id) => DiskSourceKind::Checkpoint {
                id: id.clone(),
                name: self
                    .checkpoints
                    .iter()
                    .find(|checkpoint| &checkpoint.id == id)
                    .map_or_else(|| "checkpoint".to_string(), |c| display_name(&c.name)),
            },
        };
        kind.label()
    }

    /// The measurement for the source and partition picked, if the last one
    /// is it. Another source's measurement is not shown.
    pub(super) fn current_measure<'a>(&self, cx: &DiskContext<'a>) -> Option<&'a DiskMeasure> {
        cx.measure.filter(|measure| {
            measure.source.kind.spec().as_ref() == Some(&self.pick.source)
                && (self.pick.partition.is_none() || measure.partition == self.pick.partition)
        })
    }

    /// Choose another source: its measurement is asked for again.
    pub(super) fn pick_source(&mut self, source: DiskSourceSpec) {
        if self.pick.source != source {
            self.pick = Pick::of_source(source);
            self.measured_for = None;
        }
    }

    /// The source dropdown of the measure card.
    pub(super) fn source_picker(&mut self, ui: &mut egui::Ui, enabled: bool) {
        let checkpoints = offered(&self.checkpoints);
        let selected = match &self.pick.source {
            DiskSourceSpec::Current => "Current disk".to_string(),
            DiskSourceSpec::Base => "Installed base image".to_string(),
            DiskSourceSpec::Checkpoint(id) => checkpoints
                .iter()
                .find(|checkpoint| &checkpoint.id == id)
                .map_or_else(|| "A checkpoint".to_string(), |c| checkpoint_label(c)),
        };
        let mut chosen = None;
        ui.horizontal(|ui| {
            ui.label("Source");
            ui.add_enabled_ui(enabled, |ui| {
                egui::ComboBox::from_id_salt("disk_source")
                    .selected_text(selected)
                    .width(340.0)
                    .show_ui(ui, |ui| {
                        if ui
                            .selectable_label(
                                self.pick.source == DiskSourceSpec::Current,
                                "Current disk",
                            )
                            .clicked()
                        {
                            chosen = Some(DiskSourceSpec::Current);
                        }
                        for checkpoint in &checkpoints {
                            let source = DiskSourceSpec::Checkpoint(checkpoint.id.clone());
                            if ui
                                .selectable_label(
                                    self.pick.source == source,
                                    checkpoint_label(checkpoint),
                                )
                                .on_hover_text(
                                    "The disk as it was when this checkpoint was saved. A \
                                     crash-consistent checkpoint usually reads as not cleanly \
                                     unmounted.",
                                )
                                .clicked()
                            {
                                chosen = Some(source);
                            }
                        }
                        if ui
                            .selectable_label(
                                self.pick.source == DiskSourceSpec::Base,
                                "Installed base image",
                            )
                            .on_hover_text("The image this VM's disk was created from")
                            .clicked()
                        {
                            chosen = Some(DiskSourceSpec::Base);
                        }
                    });
            });
        });
        if let Some(source) = chosen {
            self.pick_source(source);
        }
    }

    /// The partitions of a partitioned disk, one radio each, with Save for
    /// the ones that are not ext2/3/4.
    pub(super) fn partition_list(&mut self, ui: &mut egui::Ui, measure: &DiskMeasure, busy: bool) {
        let Some(table) = &measure.partitions else {
            return;
        };
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(format!(
                "{} partition table · {} partition{}",
                table.kind.label(),
                table.partitions.len(),
                if table.partitions.len() == 1 { "" } else { "s" }
            ))
            .strong()
            .color(theme::heading()),
        );
        if let Some(error) = &measure.partition_error {
            crate::activity::warning(ui, error);
        }
        if table.skipped > 0 {
            crate::activity::warning(
                ui,
                format!(
                    "{} table entr{} outside the disk {} left out.",
                    table.skipped,
                    if table.skipped == 1 { "y" } else { "ies" },
                    if table.skipped == 1 { "was" } else { "were" }
                ),
            );
        }
        let mut choose = None;
        let mut save = None;
        for partition in &table.partitions {
            ui.horizontal(|ui| {
                let supported = partition.fs == PartitionFs::Ext4;
                let selected = measure.partition == Some(partition.index);
                if ui
                    .add_enabled(
                        supported && !busy,
                        egui::RadioButton::new(selected, partition.label()),
                    )
                    .on_disabled_hover_text(if supported {
                        "A request is on its way"
                    } else {
                        "Only ext2/3/4 partitions can be opened or dumped"
                    })
                    .clicked()
                {
                    choose = Some(partition.index);
                }
                ui.colored_label(
                    if supported {
                        theme::good()
                    } else {
                        theme::muted()
                    },
                    fs_text(partition),
                );
                if !supported
                    && ui
                        .add_enabled(!busy, egui::Button::new("Save partition to host…"))
                        .on_hover_text("Write this partition's bytes to a file")
                        .clicked()
                {
                    save = Some(partition.index);
                }
            });
        }
        if let Some(reason) = measure.unsupported() {
            crate::activity::warning(ui, reason);
        }
        if let Some(index) = choose.filter(|index| measure.partition != Some(*index)) {
            self.pick.partition = Some(index);
            self.measured_for = None;
        }
        if let Some(index) = save {
            self.save_partition(ui.ctx(), index);
        }
    }
}

fn fs_text(partition: &Partition) -> &'static str {
    match partition.fs {
        PartitionFs::Ext4 => "ext2/3/4",
        PartitionFs::Other => "unsupported filesystem",
        PartitionFs::Unknown => "unsupported filesystem (not read)",
    }
}
