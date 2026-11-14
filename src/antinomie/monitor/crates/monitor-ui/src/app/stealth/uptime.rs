// SPDX-License-Identifier: GPL-3.0-only
//! The Device profile window's Clock section: the uptime the guest shows
//! when it starts (the boot age), typed or drawn in the recommended range,
//! and the clock model that carries it.
use super::*;
use antinomie_monitor_core::stealth::{
    boot_age_text, parse_boot_age, BootAge, ClockModel, BOOT_AGE_MAX_S,
};

/// What kind of machine the recommended range is for.
fn machine_words(profile: &StealthProfile) -> &'static str {
    match profile.preset {
        StealthPreset::Iot => "an IoT device",
        _ if profile.cloud_provider().is_some() => "a cloud machine",
        _ if BootAge::of(profile) == BootAge::Server => "a server",
        _ => "a desktop or laptop",
    }
}

/// The recommended range line: `Recommended for a server: 3 d 0 h to 120 d 0 h`.
pub(super) fn recommended(profile: &StealthProfile) -> String {
    let (low, high) = BootAge::of(profile).range();
    format!(
        "Recommended for {}: {} to {}",
        machine_words(profile),
        boot_age_text(low),
        boot_age_text(high)
    )
}

/// The help icon's text.
fn explanation(profile: &StealthProfile) -> String {
    format!(
        "How long the guest says it has been up when the VM starts, the same at every \
         start: type it (3 d 4 h, 90 min; up to {}) or press the dice for a random uptime \
         in the recommended range.\n\nThe guest boots this long ago and reaches the present \
         when the first program starts: a desktop or laptop as if it slept for part of it, a \
         server, cloud machine or IoT device as if it never stopped (see Clock model).\n\n\
         Off: a fresh boot (minutes of uptime).\n\n{}.",
        boot_age_text(BOOT_AGE_MAX_S),
        recommended(profile)
    )
}

/// The boot's age: how long the guest says it has been up when it starts.
pub(super) fn uptime(ui: &mut egui::Ui, profile: &mut StealthProfile, debian: bool) {
    let kind = BootAge::of(profile);
    // The text being typed, kept with the age it was last read as: an age
    // set elsewhere (a preset, the dice) replaces it.
    let id = ui.make_persistent_id("stealth_uptime_text");
    let mut problem = None;
    ui.horizontal(|ui| {
        let mut aged = profile.boot_age_s > 0;
        if ui.checkbox(&mut aged, "Uptime").changed() {
            profile.boot_age_s = if aged { kind.draw() } else { 0 };
        }
        if profile.boot_age_s > 0 {
            let kept: Option<(String, u64)> = ui.data(|data| data.get_temp(id));
            let mut text = match kept {
                Some((text, age)) if age == profile.boot_age_s => text,
                _ => boot_age_text(profile.boot_age_s),
            };
            let response = ui.add(
                egui::TextEdit::singleline(&mut text)
                    .desired_width(crate::theme::plain_edit_width(110.0))
                    .hint_text(crate::theme::placeholder(ui, "3 d 4 h")),
            );
            match parse_boot_age(&text) {
                Ok(age) => {
                    if response.changed() {
                        profile.boot_age_s = age;
                    }
                    if response.lost_focus() {
                        text = boot_age_text(profile.boot_age_s);
                    }
                }
                Err(error) => problem = Some(error),
            }
            ui.data_mut(|data| data.insert_temp(id, (text, profile.boot_age_s)));
            // Explained by the help icon beside it.
            if ui.button(egui_phosphor::regular::DICE_FIVE).clicked() {
                profile.boot_age_s = kind.draw();
            }
        } else {
            ui.label(RichText::new("a fresh boot").color(theme::muted()));
        }
        help(ui, explanation(profile));
    });
    let (low, high) = kind.range();
    if let Some(problem) = problem {
        ui.colored_label(theme::error(), problem);
    } else if profile.boot_age_s > 0 && !(low..=high).contains(&profile.boot_age_s) {
        ui.colored_label(
            theme::warn(),
            format!(
                "Outside the recommended range for {}",
                machine_words(profile)
            ),
        );
    }
    ui.label(
        RichText::new(recommended(profile))
            .small()
            .color(theme::muted()),
    );
    if profile.boot_age_s > 0 {
        clock_model(ui, profile, debian);
    }
}

/// The label of a clock model; Auto names what it resolves to.
pub(super) fn clock_model_label(
    model: ClockModel,
    profile: &StealthProfile,
    debian: bool,
) -> String {
    match model {
        ClockModel::Auto => format!(
            "Auto ({})",
            match profile.resolved_clock(debian) {
                ClockModel::Continuous => "Always running",
                _ => "Suspend",
            }
        ),
        ClockModel::Continuous => "Always running".into(),
        ClockModel::Suspend => "Suspend".into(),
    }
}

/// How the boot age reaches the guest's clocks.
fn clock_model(ui: &mut egui::Ui, profile: &mut StealthProfile, debian: bool) {
    ui.horizontal(|ui| {
        ui.label("Clock model");
        let shown = clock_model_label(profile.clock_model, profile, debian);
        egui::ComboBox::from_id_salt("stealth_clock_model")
            .selected_text(shown)
            .show_ui(ui, |ui| {
                for option in [
                    ClockModel::Auto,
                    ClockModel::Continuous,
                    ClockModel::Suspend,
                ] {
                    let label = clock_model_label(option, profile, debian);
                    ui.selectable_value(&mut profile.clock_model, option, label);
                }
            });
        help(
            ui,
            "Always running: the machine never stopped, so both of the guest's clocks \
             (CLOCK_MONOTONIC and CLOCK_BOOTTIME) step by the boot age.\n\nSuspend: the age \
             reads as time asleep, so only CLOCK_BOOTTIME steps.\n\nAuto: a server, cloud \
             machine or IoT device is always running and a desktop or laptop suspends, except \
             on a Debian base, where stepping CLOCK_MONOTONIC makes systemd's watchdogs kill \
             journald, udevd and logind at the first launch.",
        );
    });
}
