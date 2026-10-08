use antinomie_monitor_core::{AnalysisData, AnalysisSection};
use eframe::egui;

pub(super) fn regions(
    section: &AnalysisSection,
    specimen_len: Option<u64>,
) -> Vec<(usize, u64, u64, u32)> {
    section
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let AnalysisData::Entropy { range, milli_bits } = &entry.record.as_ref()?.data else {
                return None;
            };
            let total_len = specimen_len?;
            if range.len == 0
                || *milli_bits > 8000
                || range.offset.checked_add(range.len)? > total_len
                || (range.offset == 0 && range.len == total_len)
            {
                return None;
            }
            Some((index, range.offset, range.len, *milli_bits))
        })
        .take(64)
        .collect()
}

pub(super) fn chart(
    ui: &mut egui::Ui,
    section: &AnalysisSection,
    specimen_len: Option<u64>,
) -> Option<usize> {
    let regions = regions(section, specimen_len);
    if regions.is_empty() {
        return None;
    }
    ui.label("Measured regions / bits per octet (0..8)");
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 80.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, crate::theme::BG);
    let slot_size = rect.width() / regions.len() as f32;
    let mut selected = None;
    for (ordinal, &(index, offset, len, milli_bits)) in regions.iter().enumerate() {
        let slot = egui::Rect::from_min_size(
            egui::pos2(rect.left() + ordinal as f32 * slot_size, rect.top()),
            egui::vec2(slot_size, rect.height()),
        );
        let bar = egui::Rect::from_min_max(
            egui::pos2(
                slot.left() + 1.0,
                rect.bottom() - rect.height() * milli_bits as f32 / 8000.0,
            ),
            egui::pos2((slot.right() - 1.0).max(slot.left() + 1.0), rect.bottom()),
        );
        ui.painter().rect_filled(bar, 0.0, crate::theme::BLUE);
        if ui
            .interact(
                slot,
                ui.make_persistent_id(("entropy-region", index)),
                egui::Sense::click(),
            )
            .on_hover_text(format!(
                "File 0x{offset:x} + {len} octets\n{}.{:03} bits/octet",
                milli_bits / 1000,
                milli_bits % 1000
            ))
            .clicked()
        {
            selected = Some(index);
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{
        AnalysisEntry, AnalysisKind, AnalysisRange, AnalysisRecord, AnalysisSectionState,
    };
    #[test]
    fn measured_regions_exclude_whole_file_and_invalid_extents() {
        let section = AnalysisSection {
            kind: AnalysisKind::Entropy,
            state: AnalysisSectionState::Complete,
            summary: String::new(),
            entries: [
                (0, 100, 4000),
                (0, 10, 8000),
                (90, 20, 5000),
                (10, 10, 8001),
            ]
            .into_iter()
            .enumerate()
            .map(|(id, (offset, len, milli_bits))| AnalysisEntry {
                label: String::new(),
                value: String::new(),
                offset: None,
                record: Some(AnalysisRecord {
                    revision: 1,
                    id: id as u64 + 1,
                    location: None,
                    data: AnalysisData::Entropy {
                        range: AnalysisRange { offset, len },
                        milli_bits,
                    },
                }),
            })
            .collect(),
        };
        assert_eq!(regions(&section, Some(100)), [(1, 0, 10, 8000)]);
        assert!(regions(&section, None).is_empty());
    }
}
