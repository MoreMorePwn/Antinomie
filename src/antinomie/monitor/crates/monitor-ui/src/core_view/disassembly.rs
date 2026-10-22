// SPDX-License-Identifier: GPL-3.0-only
//! Disassembly of captured code and its painting.
use super::*;

impl CoreView {
    pub(super) fn disassembly(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        let view = self.listing_view();
        let mut filtered_without_selection = false;
        egui::SidePanel::left("core_function_list")
            .resizable(true)
            .default_width(220.0)
            .width_range(160.0..=420.0)
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                right: 8,
                ..Default::default()
            }))
            .show_inside(ui, |ui| {
                let filter = crate::query::table_filter(
                    ui,
                    ("core-function-filter", &record.dir),
                    "function.name == main",
                    FUNCTION_FIELDS,
                    &[],
                );
                let filter_id = ui
                    .id()
                    .with(("table-filter", ("core-function-filter", &record.dir)));
                let shown: Vec<_> = self
                    .functions
                    .iter()
                    .enumerate()
                    .filter(|(_, function)| filter.keep_table(&function_filter_row(function)))
                    .map(|(index, _)| index)
                    .collect();
                crate::code_listing::heading(ui, shown.len(), self.functions.len());
                if self
                    .code_function
                    .is_some_and(|index| !shown.contains(&index))
                {
                    self.code_function = None;
                    self.pending_function_decode = None;
                    self.status = "The selected function is hidden by this filter.".into();
                }
                filtered_without_selection =
                    shown.len() != self.functions.len() && self.code_function.is_none();
                if ui.button("Export functions").clicked() {
                    match export_saved_functions(&record.dir) {
                        Ok(path) => {
                            self.status = format!("Exported functions to {}", path.display());
                        }
                        Err(error) => self.fail(error),
                    }
                }
                if self.functions.is_empty() {
                    ui.add(egui::Label::new("No functions indexed").wrap());
                }
                let selected = self
                    .code_function
                    .and_then(|index| shown.iter().position(|&slot| slot == index));
                let chosen = crate::code_listing::function_list(
                    ui,
                    "core",
                    shown.len(),
                    |slot| {
                        let index = shown[slot];
                        let function = &self.functions[index];
                        crate::code_listing::Function {
                            name: &function.name,
                            address: function.address,
                            lines: self.function_lines(view, index),
                        }
                    },
                    selected,
                    |ui, slot| {
                        crate::query::table_row_menu(
                            ui,
                            filter_id,
                            &function_filter_row(&self.functions[shown[slot]]),
                        )
                    },
                );
                if let Some(slot) = chosen {
                    let index = shown[slot];
                    let address = self.functions[index].address;
                    self.code_function = Some(index);
                    self.code_address = format!("{address:x}");
                    self.detail = Some(self.function_detail(index));
                    if !self.show_decompiled {
                        self.pending_function_decode = Some(address);
                    }
                }
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(crate::theme::terminal())
                    .inner_margin(egui::Margin {
                        left: 10,
                        ..Default::default()
                    }),
            )
            .show_inside(ui, |ui| {
                if filtered_without_selection {
                    ui.label("Select a function matching the filter to inspect its code.");
                    return;
                }
                self.follow_function_decode(record);
                self.listing_toolbar(ui, record);
                let idle = self.code.is_empty() && !self.show_decompiled;
                if idle {
                    ui.vertical_centered(|ui| {
                        ui.add_space((ui.available_height() * 0.28).max(12.0));
                        ui.label("Disassemble or decompile this core on demand.");
                        if self.job.is_some() {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(if self.status.is_empty() {
                                    "Disassembling…"
                                } else {
                                    self.status.as_str()
                                });
                            });
                        } else if !self.status.is_empty() {
                            self.show_status(ui);
                        }
                    });
                    return;
                }
                if !self.symbol_status.is_empty() {
                    ui.label(&self.symbol_status);
                }
                if self.show_decompiled {
                    let body = self
                        .code_function
                        .and_then(|index| self.function_bodies.get(index))
                        .map(String::as_str)
                        .unwrap_or("Select a function.");
                    paint_source(ui, body);
                } else {
                    let lines = self.asm_lines();
                    if lines.is_empty() && self.code_function.is_some() {
                        ui.label(
                            RichText::new("This function is outside the decoded window.").weak(),
                        );
                    } else {
                        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
                        egui::ScrollArea::both()
                            .id_salt("core-code")
                            .auto_shrink([false, false])
                            .show_rows(ui, row_height, lines.len(), |ui, range| {
                                for index in range {
                                    crate::code_listing::text_instruction(ui, lines[index]);
                                }
                            });
                    }
                }
            });
    }

    /// What the listing shows: the decompilation after Ghidra ran and was
    /// chosen, the disassembly otherwise.
    pub(super) fn listing_view(&self) -> crate::code_listing::View {
        if self.show_decompiled {
            crate::code_listing::View::Decompilation
        } else {
            crate::code_listing::View::Disassembly
        }
    }

    /// The row above the listing: the view switch, then the on-demand actions.
    fn listing_toolbar(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        use crate::code_listing::View;
        let decompiled = !self.function_bodies.is_empty();
        let mut view = self.listing_view();
        let choices = [
            (
                View::Disassembly,
                crate::widgets::TabItem::new(View::Disassembly.label()),
            ),
            (
                View::Decompilation,
                if decompiled {
                    crate::widgets::TabItem::new(View::Decompilation.label())
                } else {
                    crate::widgets::TabItem::new(View::Decompilation.label())
                        .disabled("Decompile this core with Ghidra to read it as source.")
                },
            ),
        ];
        // A scroll area, so a narrow pane clips the switch instead of widening the pane.
        let switched = egui::ScrollArea::horizontal()
            .id_salt("core-listing-view")
            .auto_shrink([false, true])
            .show(ui, |ui| crate::widgets::segmented(ui, choices, &mut view))
            .inner;
        if switched {
            self.show_decompiled = view == View::Decompilation;
            if !self.show_decompiled {
                if let Some(address) = self
                    .code_function
                    .and_then(|index| self.functions.get(index))
                    .map(|function| function.address)
                {
                    self.pending_function_decode = Some(address);
                }
            }
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    self.job.is_none(),
                    egui::Button::new(self.disassemble_label()),
                )
                .clicked()
            {
                self.show_decompiled = false;
                self.decode_window(record);
            }
            self.ghidra_button(ui, record);
        });
    }

    /// Lines `function` has in `view`: its source lines once decompiled; its
    /// instructions once its code has been decoded, None before.
    pub(super) fn function_lines(
        &self,
        view: crate::code_listing::View,
        index: usize,
    ) -> Option<u64> {
        match view {
            crate::code_listing::View::Decompilation => self
                .function_bodies
                .get(index)
                .map(|body| body.lines().count() as u64),
            crate::code_listing::View::Disassembly => {
                let function = self.functions.get(index)?;
                self.live_asm_lines(function)
                    .or_else(|| self.asm_counts.get(&function.address).copied())
            }
        }
    }

    /// Instructions of `function` in the text decoded now, when that text
    /// reaches its first instruction.
    fn live_asm_lines(&self, function: &CoreFunction) -> Option<u64> {
        let mut index = self.asm_index.borrow_mut();
        if index.0 != self.code.len() {
            *index = (self.code.len(), asm_addresses(&self.code));
        }
        let addresses = &index.1;
        let (first, last) = (*addresses.first()?, *addresses.last()?);
        if function.address < first || function.address > last {
            return None;
        }
        let end = function.address.saturating_add(function.size.max(1));
        let from = addresses.partition_point(|&at| at < function.address);
        let to = addresses.partition_point(|&at| at < end);
        Some((to - from) as u64)
    }

    /// Keep the counts of the functions the text just decoded covers, so
    /// they stay known when another function is decoded.
    pub(super) fn remember_asm_counts(&mut self) {
        let counts: Vec<_> = self
            .functions
            .iter()
            .filter_map(|function| Some((function.address, self.live_asm_lines(function)?)))
            .collect();
        self.asm_counts.extend(counts);
    }

    fn asm_lines(&self) -> Vec<&str> {
        let range = self.code_function.and_then(|index| {
            self.functions.get(index).map(|function| {
                (
                    function.address,
                    function.address.saturating_add(function.size.max(1)),
                )
            })
        });
        let lines: Vec<&str> = self.code.lines().filter(|line| !line.is_empty()).collect();
        let Some((start, end)) = range else {
            return lines;
        };
        lines
            .into_iter()
            .filter(|line| {
                let address = line.split_whitespace().next().unwrap_or("");
                u64::from_str_radix(address, 16)
                    .is_ok_and(|address| address >= start && address < end)
            })
            .collect()
    }

    /// Start one disassembly window for a function the user just selected.
    fn follow_function_decode(&mut self, record: &CoreRecord) {
        let Some(address) = self.pending_function_decode else {
            return;
        };
        if self.function_decode_at == Some(address) {
            self.pending_function_decode = None;
            return;
        }
        if self.show_decompiled || self.job.is_some() {
            return;
        }
        let selected = self
            .code_function
            .and_then(|index| self.functions.get(index))
            .map(|function| function.address);
        if selected != Some(address) {
            return;
        }
        if !self.code.is_empty() && !self.asm_lines().is_empty() {
            self.pending_function_decode = None;
            return;
        }
        self.function_decode_at = Some(address);
        self.pending_function_decode = None;
        self.code_address = format!("{address:x}");
        self.decode_window(record);
    }

    /// Address and octet count for the next disassembly request.
    /// A selected function with a positive size starts at `function.address`
    /// for `min(function.size, 65536)` octets, even when `code_address` is stale.
    /// Otherwise the request is 65536 octets at `code_address`. `disassemble`
    /// stops at the first missing byte and caps the decode at 64 KiB.
    fn disassembly_request(&mut self, core: &CoreDump) -> Result<(u64, usize), String> {
        if let Some(function) = self
            .code_function
            .and_then(|index| self.functions.get(index))
            .filter(|function| function.size > 0)
        {
            if !captured_byte(core, function.address) {
                return Err(format!(
                    "Function {:x} has no captured bytes at its start.",
                    function.address
                ));
            }
            let octets = function.size.min(FUNCTION_DISASSEMBLY_LIMIT);
            let size = usize::try_from(octets)
                .map_err(|_| "function disassembly window does not fit".to_owned())?;
            self.code_address = format!("{:x}", function.address);
            return Ok((function.address, size));
        }
        let address = captured_code_origin(core, &self.code_address)?;
        self.code_address = format!("{address:x}");
        Ok((address, DISASSEMBLY_BYTES))
    }

    fn disassemble_label(&self) -> String {
        self.code_function
            .and_then(|index| self.functions.get(index))
            .filter(|function| function.size > 0)
            .map(|_| "Disassemble function".to_owned())
            .unwrap_or_else(|| "Disassemble captured code".to_owned())
    }

    pub(super) fn decode_window(&mut self, record: &CoreRecord) {
        match self.disassembly_request(&record.core) {
            Ok((address, size)) => {
                self.status = format!("Disassembling 0x{address:x} ({size} octets)…");
                let core = record.core.clone();
                let dir = record.dir.clone();
                self.start(move || {
                    let text = core
                        .disassemble(address, size)
                        .map_err(|error| error.to_string())?;
                    fs::write(dir.join("disassembly.txt"), &text)
                        .map_err(|error| error.to_string())?;
                    Ok(Reply::Code(text))
                });
            }
            Err(error) => self.fail(error),
        }
    }
}

/// Addresses of the decoded instructions, in order.
fn asm_addresses(code: &str) -> Vec<u64> {
    code.lines()
        .filter_map(|line| u64::from_str_radix(line.split_whitespace().next()?, 16).ok())
        .collect()
}

fn paint_source(ui: &mut egui::Ui, body: &str) {
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let lines: Vec<&str> = body.lines().collect();
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
    egui::ScrollArea::both()
        .id_salt("core-decomp")
        .auto_shrink([false, false])
        .show_rows(ui, row_height, lines.len(), |ui, range| {
            for index in range {
                ui.add(
                    egui::Label::new(crate::code_listing::highlight(lines[index], &font)).extend(),
                );
            }
        });
}
