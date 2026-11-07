// SPDX-License-Identifier: GPL-3.0-only
//! The sort arrows of Triage tables. The sorting itself is in
//! `antinomie_triage::sorting`.
use super::*;

pub(super) use antinomie_triage::sorting::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub fn header(ui: &mut egui::Ui, table: &str, column: usize, title: &str) {
    crate::query::note_head(ui, title);
    crate::widgets::fit_table::head_bg(ui);
    let id = egui::Id::new(("triage-sort", table));
    let current = ui.ctx().data(|data| data.get_temp::<Spec>(id));
    let arrow = current
        .filter(|sort| sort.column == column)
        .map_or("", |sort| if sort.descending { " ▼" } else { " ▲" });
    let response = ui.add(
        egui::Button::new(
            RichText::new(format!("{title}{arrow}"))
                .strong()
                .color(theme::muted()),
        )
        .frame(false),
    );
    if response.clicked() {
        // Ascending, then descending, then off: the recorded order again.
        let request = match current.filter(|sort| sort.column == column) {
            Some(sort) if sort.descending => None,
            Some(_) => Some(Spec {
                column,
                descending: true,
            }),
            None => Some(Spec {
                column,
                descending: false,
            }),
        };
        ui.ctx().data_mut(|data| {
            match request {
                Some(next) => {
                    data.insert_temp(id, next);
                }
                None => {
                    data.remove::<Spec>(id);
                }
            }
            data.insert_temp(egui::Id::new(("triage-sort-request", table)), request);
        });
    }
    response.context_menu(|ui| {
        if ui.button("Recorded order").clicked() {
            ui.ctx().data_mut(|data| {
                data.remove::<Spec>(id);
                data.insert_temp(egui::Id::new(("triage-sort-request", table)), None::<Spec>);
            });
            ui.close();
        }
    });
}

/// The order a table's header clicks chose, if any.
pub fn current(ctx: &egui::Context, table: &str) -> Option<Spec> {
    ctx.data(|data| data.get_temp::<Spec>(egui::Id::new(("triage-sort", table))))
}

pub fn take_request(ctx: &egui::Context, table: &str) -> Option<Option<Spec>> {
    ctx.data_mut(|data| data.remove_temp(egui::Id::new(("triage-sort-request", table))))
}

#[derive(Clone)]
struct Order {
    spec: Spec,
    hash: u64,
    indices: Arc<Vec<usize>>,
}

pub fn order<'a>(
    ctx: &egui::Context,
    table: &str,
    headers: &[&str],
    rows: impl Iterator<Item = &'a [Cell]>,
) -> Option<Arc<Vec<usize>>> {
    let spec = ctx.data(|data| data.get_temp::<Spec>(egui::Id::new(("triage-sort", table))))?;
    let header = headers.get(spec.column)?;
    let keys: Vec<_> = rows.map(|row| atom(header, spec.column, row)).collect();
    let mut hash = DefaultHasher::new();
    keys.hash(&mut hash);
    let hash = hash.finish();
    let id = egui::Id::new(("triage-sort-order", table));
    if let Some(cached) = ctx
        .data(|data| data.get_temp::<Order>(id))
        .filter(|cached| cached.spec == spec && cached.hash == hash)
    {
        return Some(cached.indices);
    }
    let mut indices: Vec<_> = (0..keys.len()).collect();
    indices.sort_by(|a, b| compare(&keys[*a], &keys[*b], spec.descending));
    let indices = Arc::new(indices);
    ctx.data_mut(|data| {
        data.insert_temp(
            id,
            Order {
                spec,
                hash,
                indices: Arc::clone(&indices),
            },
        )
    });
    Some(indices)
}
