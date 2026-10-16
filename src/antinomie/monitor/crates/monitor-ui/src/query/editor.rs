// SPDX-License-Identifier: MIT
//! The filter text editor and its token helpers.
use super::*;

pub(crate) fn filter_edit(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    scope: FilterScope,
) -> egui::Response {
    filter_edit_with(ui, text, hint, width, scope, &[])
}

pub(crate) fn filter_edit_with(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    scope: FilterScope,
    known_values: &[String],
) -> egui::Response {
    filter_edit_fields(ui, text, hint, width, &fields_for(scope), known_values)
}

pub(crate) fn filter_edit_fields(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    fields: &[FieldSpec<'_>],
    known_values: &[String],
) -> egui::Response {
    filter_edit_field_iter(ui, text, hint, width, fields.iter().copied(), known_values)
}

/// Borrow large external field registries without allocating a per-frame adapter vector.
pub(crate) fn filter_edit_field_iter<'a>(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    fields: impl Iterator<Item = FieldSpec<'a>> + Clone,
    known_values: &[String],
) -> egui::Response {
    filter_edit_iter(ui, text, hint, width, fields, known_values, false)
}

pub(crate) fn filter_edit_packet_field_iter<'a>(
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
    let mut output = egui::TextEdit::singleline(text)
        .hint_text(hint)
        .desired_width(width)
        .margin(crate::theme::TEXT_EDIT_MARGIN)
        .show(ui);
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
            .map(|range| range.primary.ccursor.index)
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
            let first = byte_index(text, range.primary.ccursor.index);
            let second = byte_index(text, range.secondary.ccursor.index);
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
        ui.memory_mut(|memory| {
            if memory.is_popup_open(popup_id) {
                memory.close_popup();
            }
        });
    } else {
        ui.memory_mut(|memory| memory.open_popup(popup_id));
        let shown = items.clone();
        let mut picked = None;
        egui::popup::popup_below_widget(
            ui,
            popup_id,
            &output.response,
            egui::PopupCloseBehavior::IgnoreClicks,
            |ui| {
                let popup_width = width
                    .min(ui.ctx().screen_rect().width() - 24.0)
                    .clamp(80.0, 560.0);
                ui.set_min_width(popup_width);
                ui.set_max_width(popup_width);
                egui::ScrollArea::vertical()
                    .max_height(240.0)
                    .show(ui, |ui| {
                        for (index, item) in shown.iter().enumerate() {
                            let label = format!("{}  {}", item.insert.trim(), item.detail);
                            let response =
                                ui.add(egui::Button::new(label).selected(index == selected).wrap());
                            if index == selected {
                                response.scroll_to_me(Some(egui::Align::Center));
                            }
                            if response.clicked() {
                                picked = Some(item.clone());
                            }
                        }
                    });
            },
        );
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
                for entry in &history {
                    if ui.button(entry).clicked() { *text = entry.clone(); menu_changed = true; ui.close_menu(); }
                }
            });
        }
        if ui.button("Clear filter").clicked() { text.clear(); menu_changed = true; ui.close_menu(); }
        if ui.button("Filter fields and examples").clicked() {
            ui.ctx().data_mut(|data| data.insert_temp(egui::Id::new("filter-guide-packet"), packet));
            let rows: Vec<_> = fields.clone().map(|field| (field.name.to_owned(), field.kind.to_owned(), field.detail.to_owned())).collect();
            ui.ctx().data_mut(|data| data.insert_temp(egui::Id::new("filter-guide-fields"), std::sync::Arc::new(rows)));
            open_guide(ui.ctx());
            ui.close_menu();
        }
        if ui.button("Copy field registry as JSON").clicked() {
            let rows: Vec<_> = fields.clone().map(|field| serde_json::json!({"name": field.name, "type": field.kind, "meaning": field.detail})).collect();
            match serde_json::to_string_pretty(&rows) {
                Ok(json) => ui.ctx().copy_text(json),
                Err(error) => { ui.colored_label(crate::theme::error(), error.to_string()); }
            }
            ui.close_menu();
        }
    });
    if menu_changed {
        output.response.mark_changed();
    }
    output.response
}

/// Call immediately after this UI's filter editor, once its filter has been
/// validated by the caller's parser or external engine.
pub(crate) fn remember_valid_filter(ui: &egui::Ui, filter: &str) {
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

pub(super) fn operator_prefix(prefix: &str) -> bool {
    prefix.starts_with(['=', '!', '<', '>', '&', '|', 'c', 'i', 'e', 'm'])
}

pub(super) fn field_before_operator(text: &str, start: usize) -> Option<String> {
    let tokens = tokenize(text[..start].trim_end()).ok()?;
    if matches!(tokens.last(), Some(Token::LBrace | Token::Comma)) {
        for pair in tokens.windows(2).rev() {
            if let [Token::Ident(field), Token::In] = pair {
                return Some(field.clone());
            }
            if matches!(pair[1], Token::And | Token::Or) {
                break;
            }
        }
    }
    let mut tail = tokens.iter().rev();
    if !matches!(
        tail.next()?,
        Token::Eq
            | Token::Ne
            | Token::Lt
            | Token::Le
            | Token::Gt
            | Token::Ge
            | Token::Contains
            | Token::Amp
    ) {
        return None;
    }
    match tail.next()? {
        Token::Ident(field) => Some(field.clone()),
        _ => None,
    }
}

pub(super) fn previous_word(text: &str, start: usize) -> Option<String> {
    let before = text[..start].trim_end();
    let (begin, end) = editor_tokens(before).last().copied()?;
    Some(before[begin..end].to_owned())
}

pub(super) fn byte_index(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map(|(index, _)| index)
        .unwrap_or(text.len())
}

pub(super) fn char_index(text: &str, byte: usize) -> usize {
    text[..byte.min(text.len())].chars().count()
}

pub(super) fn token_end(text: &str, cursor: usize) -> usize {
    active_token(text, cursor).map_or(cursor, |(_, end)| end)
}

pub(super) fn token_start(text: &str, cursor: usize) -> usize {
    active_token(text, cursor).map_or(cursor, |(start, _)| start)
}

fn active_token(text: &str, cursor: usize) -> Option<(usize, usize)> {
    let tokens = editor_tokens(text);
    tokens
        .iter()
        .copied()
        .find(|(start, end)| *start <= cursor && cursor < *end)
        .or_else(|| {
            tokens.into_iter().find(|(start, end)| {
                *start < cursor
                    && cursor == *end
                    && !matches!(
                        &text[*start..*end],
                        "(" | ")" | "{" | "}" | "," | "&&" | "||" | "!"
                    )
            })
        })
}

pub(super) fn editor_tokens(text: &str) -> Vec<(usize, usize)> {
    let mut tokens = Vec::new();
    let mut iter = text.char_indices().peekable();
    while let Some((start, ch)) = iter.next() {
        if ch.is_whitespace() {
            continue;
        }
        let mut end = start + ch.len_utf8();
        if ch == '"' || ch == '\'' {
            let mut escape = false;
            for (at, next) in iter.by_ref() {
                end = at + next.len_utf8();
                if escape {
                    escape = false;
                    continue;
                }
                if next == '\\' {
                    escape = true;
                } else if next == ch {
                    break;
                }
            }
        } else if ch.is_alphanumeric() || matches!(ch, '_' | '.' | '-' | '/') {
            while let Some(&(at, next)) = iter.peek() {
                if !next.is_alphanumeric()
                    && !matches!(next, '_' | '.' | '[' | ']' | '-' | '/' | ':')
                {
                    break;
                }
                end = at + next.len_utf8();
                iter.next();
            }
        } else if matches!(ch, '=' | '!' | '<' | '>' | '&' | '|') {
            while let Some(&(at, next)) = iter.peek() {
                if !matches!(next, '=' | '&' | '|') {
                    break;
                }
                end = at + next.len_utf8();
                iter.next();
            }
        }
        tokens.push((start, end));
    }
    tokens
}

pub(super) fn floor_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

pub(super) fn unclosed_quote(text: &str) -> bool {
    let mut quote = None;
    let mut escape = false;
    for ch in text.chars() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && quote.is_some() {
            escape = true;
            continue;
        }
        if Some(ch) == quote {
            quote = None;
        } else if quote.is_none() && matches!(ch, '"' | '\'') {
            quote = Some(ch);
        }
    }
    quote.is_some()
}
