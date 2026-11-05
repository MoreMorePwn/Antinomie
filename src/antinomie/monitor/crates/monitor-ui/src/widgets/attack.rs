// SPDX-License-Identifier: GPL-3.0-only
//! ATT&CK techniques drawn in their tactic's colour. The colour is in the
//! shape (outline, wash, one dot per tactic); the text keeps the theme's own
//! colour so it reads in every theme, and the tactic names are always in the
//! tooltip and the legend, so colour is never the only cue.
//!
//! A technique that ATT&CK files under several tactics (T1055 is Privilege
//! Escalation and Stealth) takes the colour of the tactic of the row it is
//! drawn in when a view groups by tactic, else of its first tactic in
//! kill-chain order, and carries one dot per tactic.
use super::tone::{pill, pill_font, pill_text, PillLook};
use crate::theme;
use antinomie_monitor_core::mitre::{self, Tactic};
use eframe::egui::{self, Color32, Stroke};

/// The colour of `tactic` in the active theme.
pub fn tactic_color(tactic: Tactic) -> Color32 {
    let [r, g, b] = tactic.rgb(theme::is_light());
    Color32::from_rgb(r, g, b)
}

/// `color` as a translucent wash for a filled badge.
fn wash(color: Color32) -> Color32 {
    let [r, g, b, _] = color.to_array();
    Color32::from_rgba_unmultiplied(r, g, b, 40)
}

/// The tactics a technique badge shows: the row's tactic first when there is
/// one, then the technique's own in kill-chain order.
pub fn badge_tactics(id: &str, context: Option<Tactic>) -> Vec<Tactic> {
    let mut found = mitre::tactics(id);
    if let Some(context) = context {
        found.retain(|tactic| *tactic != context);
        found.insert(0, context);
    }
    found
}

/// The pill look of a technique whose tactics are `tactics`: the first one's
/// outline and wash, or the accent when ATT&CK files it nowhere.
pub fn technique_look(tactics: &[Tactic]) -> PillLook {
    let color = tactics
        .first()
        .map_or_else(theme::blue, |t| tactic_color(*t));
    PillLook {
        fill: wash(color),
        stroke: Stroke::new(1.0_f32, color),
        corner: 4,
        pad: 8.0,
    }
}

/// The pill text of a technique: one dot per tactic, the id in monospace,
/// then the name.
pub fn technique_job(
    ui: &egui::Ui,
    id: &str,
    name: &str,
    tactics: &[Tactic],
) -> egui::text::LayoutJob {
    let small = pill_font(ui);
    let mono = egui::FontId::monospace(small.size);
    let mut job = egui::text::LayoutJob::default();
    for tactic in tactics {
        pill_text(&mut job, "● ", small.clone(), tactic_color(*tactic));
    }
    pill_text(&mut job, id, mono, theme::text());
    if !name.is_empty() {
        pill_text(&mut job, " ", small.clone(), theme::text());
        pill_text(&mut job, name, small, theme::text());
    }
    job
}

/// "Tactics: Privilege Escalation, Stealth" for a tooltip; empty when the
/// technique has none.
pub fn tactic_names(tactics: &[Tactic]) -> String {
    if tactics.is_empty() {
        return "Tactic: not in the bundled ATT&CK table".into();
    }
    let names: Vec<&str> = tactics.iter().map(|t| t.name()).collect();
    format!(
        "{}: {}",
        if names.len() == 1 {
            "Tactic"
        } else {
            "Tactics"
        },
        names.join(", ")
    )
}

/// A technique badge: "T1059.004 Command and Scripting Interpreter: Unix
/// Shell" in its tactic's colour, the tactic names on hover. `context` is the
/// tactic of the row it sits in, for a view that groups by tactic.
pub fn technique_badge(ui: &mut egui::Ui, id: &str, context: Option<Tactic>) -> egui::Response {
    let tactics = badge_tactics(id, context);
    let name = mitre::technique_name(id).unwrap_or_default();
    let job = technique_job(ui, id, &name, &tactics);
    let response = pill(ui, technique_look(&tactics), job, 0.0);
    response.on_hover_text(format!(
        "{}\n{}",
        mitre::technique_label(id),
        tactic_names(&tactics)
    ))
}

/// A tactic as a small pill: its dot and name.
pub fn tactic_chip(ui: &mut egui::Ui, tactic: Tactic) -> egui::Response {
    let mut job = egui::text::LayoutJob::default();
    pill_text(&mut job, "● ", pill_font(ui), tactic_color(tactic));
    pill_text(&mut job, tactic.name(), pill_font(ui), theme::text());
    let look = technique_look(&[tactic]);
    pill(ui, look, job, 0.0)
}

/// The legend, folded under "Tactic colours": every tactic in kill-chain
/// order with its colour. `id` keeps the fold state apart per place.
pub fn legend(ui: &mut egui::Ui, id: &str) {
    egui::CollapsingHeader::new(
        egui::RichText::new("Tactic colours")
            .small()
            .color(theme::muted()),
    )
    .id_salt(id)
    .default_open(false)
    .show(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            for tactic in Tactic::ALL {
                tactic_chip(ui, tactic);
            }
        });
    });
}

/// A tactic heading of a grouped list: its dot and name, in the tactic's
/// colour, with how many techniques it holds. `None` is the group of
/// techniques the bundled ATT&CK table does not know.
pub fn tactic_heading(ui: &mut egui::Ui, tactic: Option<Tactic>, count: usize) {
    ui.horizontal(|ui| {
        let (dot, name) = match tactic {
            Some(tactic) => (tactic_color(tactic), tactic.name()),
            None => (theme::muted(), "Not in the ATT&CK table"),
        };
        ui.add(
            crate::widgets::dot::DotLabel::new(dot, name)
                .strong()
                .text_color(theme::text()),
        );
        ui.label(
            egui::RichText::new(format!("({count})"))
                .small()
                .color(theme::muted()),
        );
    });
}

/// A foldable technique row: the badge (in `context`'s colour) and `summary`
/// in the header, `body` when it is open. Open or closed is kept per
/// technique for the rest of the app session, under `salt` so a technique in
/// two lists folds on its own in each.
pub fn technique_row(
    ui: &mut egui::Ui,
    salt: &str,
    id: &str,
    context: Option<Tactic>,
    summary: &str,
    body: impl FnOnce(&mut egui::Ui),
) {
    let state = ui.make_persistent_id(("technique-row", salt, id));
    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), state, false)
        .show_header(ui, |ui| {
            technique_badge(ui, id, context);
            if !summary.is_empty() {
                ui.label(egui::RichText::new(summary).small().color(theme::muted()));
            }
        })
        .body(body);
}
