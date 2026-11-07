// SPDX-License-Identifier: GPL-3.0-only
//! The filter bar: the edit box, its completions and its history.
use super::*;


pub fn filter_edit(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    scope: FilterScope,
) -> egui::Response {
    filter_edit_with(ui, text, hint, width, scope, &[])
}

pub fn filter_edit_with(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    scope: FilterScope,
    known_values: &[String],
) -> egui::Response {
    #[cfg(test)]
    if let FilterScope::Table(fields) = scope {
        assert_example_compiles(hint, fields);
    }
    filter_edit_fields(ui, text, hint, width, &fields_for(scope), known_values)
}

pub fn filter_edit_fields(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    fields: &[FieldSpec<'_>],
    known_values: &[String],
) -> egui::Response {
    #[cfg(test)]
    assert_example_compiles(hint, fields);
    filter_edit_field_iter(ui, text, hint, width, fields.iter().copied(), known_values)
}


/// Borrow large external field registries without allocating a per-frame adapter vector.
pub fn filter_edit_field_iter<'a>(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    fields: impl Iterator<Item = FieldSpec<'a>> + Clone,
    known_values: &[String],
) -> egui::Response {
    filter_edit_iter(ui, text, hint, width, fields, known_values, false)
}

pub fn filter_edit_packet_field_iter<'a>(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    fields: impl Iterator<Item = FieldSpec<'a>> + Clone,
    known_values: &[String],
) -> egui::Response {
    filter_edit_iter(ui, text, hint, width, fields, known_values, true)
}

fn filter_edit_iter<'a>(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    fields: impl Iterator<Item = FieldSpec<'a>> + Clone,
    known_values: &[String],
    packet: bool,
) -> egui::Response {
    let id = ui.id().with(("filter-edit", hint));
    ui.ctx().data_mut(|data| {
        data.insert_temp(egui::Id::new("filter-history-target"), id.with("history"))
    });
    let mut dismiss = ui
        .data(|data| data.get_temp::<bool>(id.with("dismiss")))
        .unwrap_or(false);
    let mut selected = ui
        .data(|data| data.get_temp::<usize>(id.with("selected")))
        .unwrap_or(0);
    let was_focused = ui
        .data(|data| data.get_temp::<bool>(id.with("focus")))
        .unwrap_or(false);
    let pending = ui
        .data(|data| data.get_temp::<Vec<Completion>>(id.with("items")))
        .unwrap_or_default();
    let mut caret = None;
    let mut accepted = false;
    if was_focused {
        let reopen = ui.input_mut(|input| {
            input.consume_key(egui::Modifiers::CTRL, egui::Key::Space)
                || input.consume_key(egui::Modifiers::COMMAND, egui::Key::Space)
        });
        if reopen {
            dismiss = false;
        }
        if !pending.is_empty() && !dismiss {
            let accept = ui.input_mut(|input| {
                if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                    selected = selected.saturating_add(1) % pending.len();
                }
                if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                    selected = if selected == 0 {
                        pending.len() - 1
                    } else {
                        selected - 1
                    };
                }
                if input.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                    dismiss = true;
                }
                input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                    || input.consume_key(egui::Modifiers::NONE, egui::Key::Tab)
            });
            if accept && !dismiss {
                if let Some(item) = pending.get(selected.min(pending.len() - 1)).cloned() {
                    let byte = apply_completion(text, &item);
                    caret = Some(char_index(text, byte));
                    dismiss = true;
                    accepted = true;
                }
            }
        }
    }
    // A fixed id: a status label or spinner that appears before the field while
    // the filter applies would move its automatic id and drop the focus.
    let mut output = egui::TextEdit::singleline(text)
        .id(id.with("edit"))
        .hint_text(crate::theme::placeholder(ui, format!("filter e.g. {hint}")))
        .desired_width(width)
        .margin(crate::widgets::clear_margin(crate::theme::TEXT_EDIT_MARGIN))
        .show(ui);
    let cleared = crate::widgets::clear_button(ui, &output.response, text);
    if cleared {
        output.response.mark_changed();
    }
    if let Some(caret) = caret {
        let mut state = output.state.clone();
        state
            .cursor
            .set_char_range(Some(egui::text::CCursorRange::one(
                egui::text::CCursor::new(caret),
            )));
        state.store(ui.ctx(), output.response.id);
    }
    if accepted {
        output.response.mark_changed();
    }
    let cursor_chars = caret.unwrap_or_else(|| {
        output
            .cursor_range
            .map(|range| usize::from(range.primary.index))
            .unwrap_or(text.chars().count())
    });
    let cursor = byte_index(text, cursor_chars);
    let changed = output.response.changed();
    if changed && !accepted {
        dismiss = false;
        selected = 0;
    }
    let items = if output.response.has_focus() && !dismiss {
        let selection = output.cursor_range.and_then(|range| {
            let first = byte_index(text, usize::from(range.primary.index));
            let second = byte_index(text, usize::from(range.secondary.index));
            (first != second).then_some((first.min(second), first.max(second)))
        });
        completions_field_iter(
            text,
            cursor,
            fields.clone(),
            known_values,
            selection,
            packet,
        )
    } else {
        Vec::new()
    };
    let popup_id = id.with("popup");
    if items.is_empty() {
        egui::Popup::close_id(ui.ctx(), popup_id);
        ui.data_mut(|data| data.remove_temp::<Option<usize>>(id.with("scrolled")));
    } else {
        let shown = items.clone();
        let mut picked = None;
        // Keep the highlighted entry in view only when it moves (arrow keys
        // or new items); every frame would undo the wheel and scrollbar.
        let scrolled_id = id.with("scrolled");
        let scrolled = ui.data(|data| data.get_temp::<Option<usize>>(scrolled_id));
        let follow = changed || scrolled != Some(Some(selected));
        egui::Popup::from_response(&output.response)
            .id(popup_id)
            .open(true)
            .close_behavior(egui::PopupCloseBehavior::IgnoreClicks)
            .layout(egui::Layout::top_down_justified(egui::Align::Min))
            .show(|ui| {
                let popup_width = width
                    .min(ui.ctx().content_rect().width() - 24.0)
                    .clamp(80.0, 560.0);
                ui.set_min_width(popup_width);
                ui.set_max_width(popup_width);
                let scroll = egui::ScrollArea::vertical()
                    .max_height(240.0)
                    .show(ui, |ui| {
                        for (index, item) in shown.iter().enumerate() {
                            let label = format!("{}  {}", item.insert.trim(), item.detail);
                            let response =
                                ui.add(egui::Button::new(label).selected(index == selected).wrap());
                            if index == selected && follow {
                                response.scroll_to_me(Some(egui::Align::Center));
                            }
                            if response.clicked() {
                                picked = Some(item.clone());
                            }
                        }
                    });
                #[cfg(test)]
                ui.data_mut(|data| data.insert_temp(id.with("offset"), scroll.state.offset.y));
                #[cfg(not(test))]
                let _ = scroll;
            });
        ui.data_mut(|data| data.insert_temp(scrolled_id, Some(selected)));
        if let Some(item) = picked {
            let byte = apply_completion(text, &item);
            let caret = char_index(text, byte);
            let mut state = output.state.clone();
            state
                .cursor
                .set_char_range(Some(egui::text::CCursorRange::one(
                    egui::text::CCursor::new(caret),
                )));
            state.store(ui.ctx(), output.response.id);
            output.response.request_focus();
            output.response.mark_changed();
            dismiss = true;
        }
    }
    let focused = output.response.has_focus();
    ui.data_mut(|data| {
        data.insert_temp(id.with("dismiss"), dismiss);
        data.insert_temp(id.with("selected"), selected);
        data.insert_temp(id.with("focus"), focused);
        data.insert_temp(id.with("items"), items);
    });
    let mut menu_changed = false;
    output.response.context_menu(|ui| {
        let history = ui.data(|data| data.get_temp::<Vec<String>>(id.with("history"))).unwrap_or_default();
        if !history.is_empty() {
            ui.menu_button("Recent filters", |ui| {
                crate::widgets::bounded_menu(ui, |ui| {
                    for entry in &history {
                        if ui.add(egui::Button::new(entry).truncate()).on_hover_text(entry).clicked() { *text = entry.clone(); menu_changed = true; ui.close(); }
                    }
                });
            });
        }
        if ui.button("Clear filter").clicked() { text.clear(); menu_changed = true; ui.close(); }
        if ui.button("Filter fields and examples").clicked() {
            ui.ctx().data_mut(|data| data.insert_temp(egui::Id::new("filter-guide-packet"), packet));
            let rows: Vec<_> = fields.clone().map(|field| (field.name.to_owned(), field.kind.to_owned(), field.detail.to_owned())).collect();
            ui.ctx().data_mut(|data| data.insert_temp(egui::Id::new("filter-guide-fields"), std::sync::Arc::new(rows)));
            open_guide(ui.ctx());
            ui.close();
        }
        if ui.button("Copy field registry as JSON").clicked() {
            let rows: Vec<_> = fields.clone().map(|field| serde_json::json!({"name": field.name, "type": field.kind, "meaning": field.detail})).collect();
            match serde_json::to_string_pretty(&rows) {
                Ok(json) => ui.ctx().copy_text(json),
                Err(error) => { crate::activity::error(ui, error.to_string()); }
            }
            ui.close();
        }
    });
    if menu_changed {
        output.response.mark_changed();
    }
    output.response.response
}

/// Call immediately after this UI's filter editor, once its filter has been
/// validated by the caller's parser or external engine.
pub fn remember_valid_filter(ui: &egui::Ui, filter: &str) {
    if filter.trim().is_empty() {
        return;
    }
    let Some(id) = ui
        .ctx()
        .data(|data| data.get_temp::<egui::Id>(egui::Id::new("filter-history-target")))
    else {
        return;
    };
    ui.ctx().data_mut(|data| {
        let mut history = data.get_temp::<Vec<String>>(id).unwrap_or_default();
        if history.first().is_some_and(|entry| entry == filter) {
            return;
        }
        history.retain(|entry| entry != filter);
        history.insert(0, filter.to_owned());
        history.truncate(24);
        data.insert_temp(id, history);
    });
}
