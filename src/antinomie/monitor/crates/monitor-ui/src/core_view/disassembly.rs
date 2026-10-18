// SPDX-License-Identifier: MIT
//! Disassembly of captured code and its painting.
use super::*;

impl CoreView {
    pub(super) fn disassembly(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
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
                    "Filter functions",
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
                ui.weak(format!(
                    "{} / {} functions",
                    shown.len(),
                    self.functions.len()
                ));
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
                let row_height = ui.text_style_height(&egui::TextStyle::Body) * 4.0
                    + ui.spacing().item_spacing.y * 2.0;
                egui::ScrollArea::vertical()
                    .id_salt("core-functions")
                    .show_rows(ui, row_height, shown.len(), |ui, range| {
                        for slot in range {
                            let index = shown[slot];
                            let function = &self.functions[index];
                            let label = format!(
                                "symbol {}\naddress {:x}\nmodule not recorded\n{} octets",
                                function.name, function.address, function.size
                            );
                            let response =
                                ui.selectable_label(self.code_function == Some(index), label);
                            response.context_menu(|ui| {
                                crate::query::table_row_menu(
                                    ui,
                                    filter_id,
                                    &function_filter_row(function),
                                )
                            });
                            if response.clicked() {
                                let address = function.address;
                                self.code_function = Some(index);
                                self.code_address = format!("{address:x}");
                                if !self.show_decompiled {
                                    self.pending_function_decode = Some(address);
                                }
                            }
                        }
                    });
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
                        if ui
                            .add_enabled(
                                self.job.is_none(),
                                egui::Button::new(self.disassemble_label()),
                            )
                            .clicked()
                        {
                            self.decode_window(record);
                        }
                        self.ghidra_button(ui, record);
                    });
                    return;
                }
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            self.job.is_none(),
                            egui::Button::new(self.disassemble_label()),
                        )
                        .clicked()
                    {
                        self.decode_window(record);
                    }
                    self.ghidra_button(ui, record);
                });
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
                                    paint_asm(ui, lines[index]);
                                }
                            });
                    }
                }
            });
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
            .map(|function| {
                let octets = function.size.min(FUNCTION_DISASSEMBLY_LIMIT);
                format!("Disassemble function ({octets} octets)")
            })
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

fn paint_asm(ui: &mut egui::Ui, line: &str) {
    let (address, rest) = line.split_once("  ").unwrap_or(("", line));
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        if !address.is_empty() {
            ui.label(
                RichText::new(address)
                    .monospace()
                    .color(crate::theme::value(crate::theme::ValueKind::Pointer)),
            );
        }
        let mut parts = rest.splitn(2, char::is_whitespace);
        let mnemonic = parts.next().unwrap_or("");
        let operands = parts.next().unwrap_or("").trim_start();
        let mnemonic_color = if mnemonic.starts_with('j') || mnemonic == "call" || mnemonic == "ret"
        {
            crate::theme::warn()
        } else {
            crate::theme::value(crate::theme::ValueKind::Name)
        };
        ui.label(RichText::new(mnemonic).monospace().color(mnemonic_color));
        ui.label(
            RichText::new(operands)
                .monospace()
                .color(crate::theme::text()),
        );
    });
}

fn paint_source(ui: &mut egui::Ui, body: &str) {
    egui::ScrollArea::both()
        .id_salt("core-decomp")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for line in body.lines() {
                let mut job = egui::text::LayoutJob::default();
                for word in line.split_inclusive(|character: char| {
                    !character.is_ascii_alphanumeric() && character != '_'
                }) {
                    let color = if matches!(
                        word,
                        "if "
                            | "else "
                            | "return "
                            | "while "
                            | "for "
                            | "int "
                            | "void "
                            | "char "
                            | "long "
                    ) {
                        crate::theme::error()
                    } else if word
                        .chars()
                        .next()
                        .is_some_and(|character| character.is_ascii_digit())
                    {
                        crate::theme::warn()
                    } else {
                        crate::theme::text()
                    };
                    job.append(
                        word,
                        0.0,
                        egui::TextFormat {
                            font_id: egui::TextStyle::Monospace.resolve(ui.style()),
                            color,
                            ..Default::default()
                        },
                    );
                }
                ui.add(egui::Label::new(job).extend());
            }
        });
}
