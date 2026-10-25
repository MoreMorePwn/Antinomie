//! The process-core budget and deadline chooser, shared by Run program and the
//! Dump core dialog. The guest says what it accepts; the choices above that are
//! shown but disabled, with the reason as their hover text.
use antinomie_monitor_core::{CoreLimits, CORE_DEFAULT_BUDGET_MIB, CORE_MAX_SUPPORTED};
use eframe::egui;

const MIB: u64 = 1024 * 1024;
const CHOICES_MIB: [u64; 5] = [64, 128, 256, 512, 1024];

/// One entry of the budget list: bytes, its label, and why it cannot be chosen.
pub(crate) struct Entry {
    pub size: u64,
    pub label: String,
    pub disabled: Option<String>,
}

/// The entries for a guest: the fixed sizes and, when the guest's own maximum is
/// not one of them, that maximum as "Guest maximum".
pub(crate) fn entries(limits: Option<&CoreLimits>) -> Vec<Entry> {
    let mut sizes: Vec<(u64, String)> = CHOICES_MIB
        .iter()
        .map(|&mib| (mib * MIB, format!("{mib} MiB")))
        .collect();
    if let Some(limits) = limits
        && limits.advertised
        && !sizes.iter().any(|(size, _)| *size == limits.max_size)
    {
        sizes.push((
            limits.max_size,
            format!("Guest maximum ({} MiB)", limits.max_size / MIB),
        ));
        sizes.sort_by_key(|(size, _)| *size);
    }
    sizes
        .into_iter()
        .map(|(size, label)| Entry {
            disabled: match limits {
                None => Some("waiting for the guest's limits".into()),
                Some(limits) => limits.check(size, 5000).err(),
            },
            size,
            label,
        })
        .collect()
}

/// The size a remembered default becomes for this guest, in bytes.
pub(crate) fn initial(limits: Option<&CoreLimits>, default_mib: u32) -> u32 {
    let wanted = default_mib.clamp(1, (CORE_MAX_SUPPORTED / MIB) as u32);
    limits.map_or(64 << 20, |limits| limits.effective_budget(wanted))
}

/// The deadline for a budget, in milliseconds.
pub(crate) fn default_timeout_ms(limits: Option<&CoreLimits>, budget: u64) -> u32 {
    limits.map_or(5000, |limits| limits.default_timeout_ms(budget))
}

/// What to tell the user about the guest's limit, and whether it is a warning.
pub(crate) fn caption(
    limits: Option<&CoreLimits>,
    available: Option<u64>,
    budget: u64,
) -> (String, bool) {
    let Some(limits) = limits else {
        return ("Waiting for the guest's limits.".into(), false);
    };
    if !limits.advertised {
        return (
            "This guest's base accepts 64 MiB (older base); rebuild it for larger cores.".into(),
            false,
        );
    }
    let ram = limits
        .guest_ram
        .map(|ram| format!(" ({} MiB RAM)", ram / MIB))
        .unwrap_or_default();
    let mut text = format!("Guest accepts up to {} MiB{ram}.", limits.max_size / MIB);
    let mut warn = false;
    if let Some(available) = available {
        text.push_str(&format!(
            " Guest memory available now {} MiB.",
            available / MIB
        ));
        if budget > available {
            text.push_str(" The budget is larger than that; the core may be cut.");
            warn = true;
        }
    }
    (text, warn)
}

/// Budget list and deadline in one row. `budget` and `timeout_ms` are the values
/// the request will carry; the return value is the size the user picked this
/// frame, which the caller remembers as the default.
pub(crate) fn show(
    ui: &mut egui::Ui,
    salt: &str,
    budget: &mut u32,
    timeout_ms: &mut u32,
    limits: Option<&CoreLimits>,
) -> Option<u32> {
    let edited_id = ui.make_persistent_id((salt, "deadline-edited"));
    let mut edited = ui
        .data(|data| data.get_temp::<bool>(edited_id))
        .unwrap_or(false);
    let mut picked = None;
    ui.horizontal_wrapped(|ui| {
        ui.label("Budget");
        let current = entries(limits)
            .into_iter()
            .find(|entry| entry.size == u64::from(*budget))
            .map_or_else(|| format!("{} MiB", u64::from(*budget) / MIB), |entry| entry.label);
        ui.add_enabled_ui(limits.is_some(), |ui| {
            egui::ComboBox::from_id_salt((salt, "budget"))
                .selected_text(current)
                .show_ui(ui, |ui| {
                    for entry in entries(limits) {
                        let enabled = entry.disabled.is_none();
                        let response = ui
                            .add_enabled(
                                enabled,
                                egui::SelectableLabel::new(
                                    u64::from(*budget) == entry.size,
                                    &entry.label,
                                ),
                            )
                            .on_disabled_hover_text(entry.disabled.clone().unwrap_or_default());
                        if response.clicked() {
                            *budget = entry.size as u32;
                            picked = Some(*budget);
                            if !edited {
                                *timeout_ms = default_timeout_ms(limits, entry.size);
                            }
                        }
                    }
                });
        });
        ui.label("Deadline");
        let max_s = limits.map_or(5.0, |limits| f64::from(limits.max_timeout_ms) / 1000.0);
        let mut seconds = f64::from(*timeout_ms) / 1000.0;
        let response = ui.add_enabled(
            limits.is_some_and(|limits| limits.advertised),
            egui::DragValue::new(&mut seconds)
                .range(1.0..=max_s)
                .speed(0.1)
                .fixed_decimals(1)
                .suffix(" s"),
        );
        if response.changed() {
            *timeout_ms = (seconds * 1000.0).round() as u32;
            edited = true;
        }
        response.on_hover_text("Serialization deadline. The guest checks it page by page; page faults and thread rendezvous can still delay the pause.");
    });
    ui.data_mut(|data| data.insert_temp(edited_id, edited));
    picked
}

/// The default budget in MiB a fresh settings file holds.
pub(crate) const fn default_mib() -> u32 {
    CORE_DEFAULT_BUDGET_MIB
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_mib: u64) -> CoreLimits {
        CoreLimits {
            advertised: true,
            max_size: max_mib * MIB,
            pool_size: 2 * max_mib * MIB,
            guest_ram: Some(1024 * MIB),
            max_timeout_ms: 60_000,
            stored_status: true,
            chunked: true,
            fast_read: true,
            ..CoreLimits::LEGACY
        }
    }

    #[test]
    fn entries_above_the_guest_maximum_are_disabled_with_a_reason() {
        let limits = limits(384);
        let list = entries(Some(&limits));
        let sizes: Vec<_> = list.iter().map(|entry| entry.size / MIB).collect();
        assert_eq!(sizes, [64, 128, 256, 384, 512, 1024]);
        assert!(list[3].label.starts_with("Guest maximum (384"));
        assert!(list[..4].iter().all(|entry| entry.disabled.is_none()));
        assert!(list[4].disabled.as_ref().unwrap().contains("up to 384 MiB"));
    }

    #[test]
    fn a_legacy_guest_offers_only_64_mib_and_says_why() {
        let legacy = CoreLimits::LEGACY;
        let list = entries(Some(&legacy));
        assert!(list[0].disabled.is_none());
        assert!(list[1..].iter().all(|entry| entry.disabled.is_some()));
        assert!(caption(Some(&legacy), None, 64 * MIB)
            .0
            .contains("older base"));
        assert!(entries(None).iter().all(|entry| entry.disabled.is_some()));
    }

    #[test]
    fn the_remembered_default_is_clamped_to_the_guest() {
        assert_eq!(initial(Some(&limits(384)), 256), (256 * MIB) as u32);
        assert_eq!(initial(Some(&limits(128)), 256), (128 * MIB) as u32);
        assert_eq!(initial(Some(&CoreLimits::LEGACY), 256), (64 * MIB) as u32);
        assert_eq!(initial(None, 256), (64 * MIB) as u32);
        assert_eq!(default_timeout_ms(Some(&limits(384)), 256 * MIB), 7560);
    }

    #[test]
    fn the_caption_warns_when_the_budget_exceeds_available_memory() {
        let limits = limits(384);
        let (_, calm) = caption(Some(&limits), Some(612 * MIB), 256 * MIB);
        assert!(!calm);
        let (text, warn) = caption(Some(&limits), Some(100 * MIB), 256 * MIB);
        assert!(warn && text.contains("may be cut"));
    }
}
