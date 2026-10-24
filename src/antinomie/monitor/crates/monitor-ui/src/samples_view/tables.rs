// SPDX-License-Identifier: GPL-3.0-only
//! The filter bar, the result table and the stored list of the samples window.
use super::*;

impl SamplesView {
    pub(super) fn filter_bar(&mut self, ui: &mut egui::Ui) {
        let types = choices(&self.results, |s| vec![s.file_type.to_lowercase()]);
        let arches = choices(&self.results, |s| {
            vec![arch(s).unwrap_or_else(|| UNKNOWN_ARCH.into())]
        });
        let families = choices(&self.results, |s| s.signature.clone().into_iter().collect());
        let tags = choices(&self.results, |s| s.tags.clone());
        let count = shown(&self.results, &self.filters, None).len();
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            choice(
                ui,
                "samples_type",
                "File type",
                &mut self.filters.file_type,
                &types,
            );
            choice(
                ui,
                "samples_arch",
                "Architecture",
                &mut self.filters.arch,
                &arches,
            );
            choice(
                ui,
                "samples_family",
                "Family",
                &mut self.filters.family,
                &families,
            );
            let ticked = &mut self.filters.tags;
            egui::ComboBox::from_id_salt("samples_tags")
                .selected_text(match ticked.len() {
                    0 => "Tags: all".to_string(),
                    1 => format!("Tags: {}", ticked.iter().next().map_or("", String::as_str)),
                    n => format!("Tags: {n} ticked"),
                })
                .height(360.0)
                .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                .show_ui(ui, |ui| {
                    if ui
                        .add_enabled(!ticked.is_empty(), egui::Button::new("Clear"))
                        .clicked()
                    {
                        ticked.clear();
                    }
                    for (tag, count) in &tags {
                        let mut on = ticked.contains(tag);
                        if ui.checkbox(&mut on, format!("{tag}  ({count})")).changed() {
                            if on {
                                ticked.insert(tag.clone());
                            } else {
                                ticked.remove(tag);
                            }
                        }
                    }
                })
                .response
                .on_hover_text("Samples with any of the ticked tags");
            if self.filters.active() && ui.button("Clear filters").clicked() {
                self.filters = Filters::default();
            }
            if !self.results.is_empty() {
                ui.colored_label(
                    theme::muted(),
                    format!("{count} of {} · {}", self.results.len(), self.listing),
                );
            }
        });
    }

    pub(super) fn results_table(
        &mut self,
        ui: &mut egui::Ui,
        cx: &SamplesContext<'_>,
        stored: &[StoredSample],
    ) {
        if self.results.is_empty() {
            let text = if !self.key_saved {
                format!(
                    "Set the {} in Tools > API keys to list the newest samples.",
                    samples::source_api_key(self.source).label()
                )
            } else if self.searching.is_some() {
                format!("Asking {}…", self.source.label())
            } else if self.listing.is_empty() {
                "Search by family, tag, file type or hash.".to_string()
            } else {
                format!("{}: nothing found.", self.listing)
            };
            ui.add_space(8.0);
            ui.colored_label(theme::muted(), text);
            return;
        }
        let compiled = query::table_filter(
            ui,
            "sample-records",
            "sample.family == Emotet",
            SAMPLE_FIELDS,
            &[],
        );
        let order = shown(&self.results, &self.filters, self.sort)
            .into_iter()
            .filter(|index| {
                compiled.keep_table(&sample_values(
                    &self.results[*index],
                    self.results_source,
                    stored,
                ))
            })
            .collect::<Vec<_>>();
        ui.colored_label(
            theme::muted(),
            format!(
                "{} / {} retained catalog rows",
                order.len(),
                self.results.len()
            ),
        );
        if order.is_empty() {
            ui.add_space(8.0);
            ui.colored_label(theme::muted(), "No sample matches the filters.");
            return;
        }
        let filter_id = ui.id().with(("table-filter", "sample-records"));
        let mono = theme::mono(cx.font_size - 1.0);
        let row_height = theme::row_height(cx.font_size).max(ui.spacing().interact_size.y + 4.0);
        let mut download = None;
        let mut clicked = None;
        crate::widgets::table::begin(ui);
        TableBuilder::new(ui)
            .id_salt("samples_results")
            .sense(egui::Sense::click())
            .striped(true)
            .resizable(true)
            .auto_shrink([false, false])
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(190.0))
            .column(Column::initial(200.0).clip(true))
            .column(Column::initial(150.0).clip(true))
            .column(Column::initial(120.0).clip(true))
            .column(Column::initial(70.0))
            .column(Column::initial(110.0))
            .column(Column::initial(180.0))
            .column(Column::initial(200.0).clip(true))
            .column(Column::remainder().at_least(130.0))
            .header(row_height, |mut header| {
                for column in Col::ALL {
                    header.col(|ui| {
                        crate::widgets::table::head_bg(ui);
                        let mark = match self.sort {
                            Some(sort) if sort.column == column => {
                                if sort.descending {
                                    " ⏷"
                                } else {
                                    " ⏶"
                                }
                            }
                            _ => "",
                        };
                        if ui
                            .add(
                                egui::Label::new(
                                    RichText::new(format!("{}{mark}", column.label()))
                                        .strong()
                                        .color(theme::muted()),
                                )
                                .sense(egui::Sense::click()),
                            )
                            .on_hover_text("Sort; a third click restores the source's order")
                            .clicked()
                        {
                            clicked = Some(column);
                        }
                    });
                }
                header.col(|_| {});
            })
            .body(|body| {
                body.rows(row_height, order.len(), |mut row| {
                    let sample = &self.results[order[row.index()]];
                    row.col(|ui| {
                        ui.label(
                            RichText::new(sample_date(sample))
                                .font(mono.clone())
                                .color(theme::muted()),
                        );
                    });
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(RichText::new(&sample.file_name).font(mono.clone()))
                                .truncate(),
                        )
                        .on_hover_text(listed_hash(sample).unwrap_or("—"));
                    });
                    row.col(|ui| match listed_hash(sample) {
                        Some(hash) => {
                            if ui
                                .add(
                                    egui::Label::new(
                                        RichText::new(format!("{}…", &hash[..16.min(hash.len())]))
                                            .font(mono.clone())
                                            .color(theme::value(ValueKind::Number)),
                                    )
                                    .sense(egui::Sense::click()),
                                )
                                .on_hover_text(format!("{hash}\nClick to copy"))
                                .clicked()
                            {
                                ui.ctx().copy_text(hash.to_owned());
                            }
                        }
                        None => {
                            ui.label("—");
                        }
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(sample.signature.as_deref().unwrap_or("-"))
                                .color(theme::value(ValueKind::Name)),
                        );
                    });
                    row.col(|ui| {
                        // A hash alone is not a file type. SHA-1 rows stay unlabeled
                        // unless the source named a type.
                        let kind = sample.file_type.as_str();
                        ui.label(if kind.is_empty() { "—" } else { kind });
                    });
                    row.col(|ui| match arch(sample) {
                        Some(label) => {
                            let runs = sample.may_run();
                            ui.label(RichText::new(label).color(if runs {
                                theme::good()
                            } else {
                                theme::text()
                            }))
                            .on_hover_text(if sample.is_script() {
                                "A shell script: runs in the guests through /bin/sh"
                            } else if runs {
                                "Runs in Antinomie's x86-64 guests"
                            } else {
                                "Will not run in the x86-64 guests"
                            });
                        }
                        None => {
                            ui.colored_label(theme::muted(), "?").on_hover_text(
                                "Not listed by the source (MalwareBazaar's newest uploads, \
                                     MalShare): search a family, tag or file type on \
                                     MalwareBazaar, or download the sample to read it",
                            );
                        }
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(if sample.file_size == 0 {
                                "-".to_string()
                            } else {
                                crate::values::file_size(sample.file_size)
                            })
                            .color(theme::value(ValueKind::Number)),
                        );
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(sample.tags.join(", ")).truncate())
                            .on_hover_text(sample.tags.join(", "));
                    });
                    row.col(|ui| {
                        let identity = listed_hash(sample).unwrap_or("");
                        let downloaded = !sample.sha256_hash.is_empty()
                            && stored
                                .iter()
                                .any(|item| item.info.sha256_hash == sample.sha256_hash);
                        if downloaded {
                            ui.colored_label(theme::good(), "Downloaded");
                        } else if self.downloads.contains_key(identity) {
                            crate::theme::spinner(ui);
                        } else if ui
                            .button(format!(
                                "{} Download",
                                egui_phosphor::regular::DOWNLOAD_SIMPLE
                            ))
                            .clicked()
                        {
                            download = Some(sample.clone());
                        }
                    });
                    row.response().context_menu(|ui| {
                        query::table_row_menu(
                            ui,
                            filter_id,
                            &sample_values(sample, self.results_source, stored),
                        );
                    });
                });
            });
        if let Some(column) = clicked {
            self.sort = next_sort(self.sort, column);
        }
        if let Some(sample) = download {
            let (sender, receiver) = mpsc::channel();
            let (curl, key, data): (PathBuf, String, PathBuf) =
                (cx.curl.into(), self.key.clone(), cx.data_dir.into());
            let source = self.results_source;
            let hash = listed_hash(&sample).unwrap_or("").to_owned();
            std::thread::spawn(move || {
                let done = source.download(&curl, &key, &data, &sample);
                if done.is_ok() {
                    antinomie_monitor_core::api_keys::record_use(
                        &data,
                        samples::source_api_key(source),
                    );
                }
                let _ = sender.send(done);
            });
            self.downloads.insert(hash, receiver);
        }
    }

    pub(super) fn stored_list(
        &mut self,
        ui: &mut egui::Ui,
        cx: &SamplesContext<'_>,
        stored: &[StoredSample],
        height: f32,
    ) -> Option<SamplesAction> {
        let mut action = None;
        let mut delete = None;
        ui.horizontal(|ui| {
            theme::section(ui, &format!("Downloaded ({})", stored.len()));
            ui.add_space(12.0);
            ui.label(RichText::new("Run as").color(theme::muted()));
            ui.selectable_value(&mut self.as_root, false, "guest user");
            ui.selectable_value(&mut self.as_root, true, "root");
            if let Some(name) = cx.vm_name {
                ui.add_space(8.0);
                ui.colored_label(theme::muted(), format!("VM: {name}"));
            }
            if !cx.running {
                crate::activity::warning(ui, "· start the VM to send samples into it");
            }
        });
        ui.add_space(6.0);
        if stored.is_empty() {
            ui.colored_label(theme::muted(), "No samples downloaded yet.");
            return None;
        }
        let pending = self.pending.is_some() || self.awaiting.is_some();
        let mono = theme::mono(cx.font_size - 1.0);
        let row_height = theme::row_height(cx.font_size).max(ui.spacing().interact_size.y + 4.0);
        crate::widgets::table::begin(ui);
        let order =
            crate::table_sort::order(ui.ctx(), "samples_stored", stored.len(), |column, a, b| {
                let (a, b) = (&stored[a], &stored[b]);
                match column {
                    0 => a
                        .info
                        .file_name
                        .to_lowercase()
                        .cmp(&b.info.file_name.to_lowercase()),
                    1 => a
                        .info
                        .signature
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .cmp(&b.info.signature.as_deref().unwrap_or("").to_lowercase()),
                    2 => arch(&a.info)
                        .unwrap_or_default()
                        .cmp(&arch(&b.info).unwrap_or_default()),
                    3 => a.info.file_size.cmp(&b.info.file_size),
                    _ => a.pushes.len().cmp(&b.pushes.len()),
                }
            });
        TableBuilder::new(ui)
            .id_salt("samples_stored")
            .striped(true)
            .auto_shrink([false, true])
            .max_scroll_height(height)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(260.0).clip(true))
            .column(Column::initial(130.0).clip(true))
            .column(Column::initial(110.0))
            .column(Column::initial(180.0))
            .column(Column::initial(90.0))
            .column(Column::remainder().at_least(380.0))
            .header(row_height, |mut header| {
                for (column, title) in ["File", "Signature", "Architecture", "Size", "Sent"]
                    .into_iter()
                    .enumerate()
                {
                    header.col(|ui| crate::table_sort::header(ui, "samples_stored", column, title));
                }
                header.col(|ui| crate::widgets::table::head(ui, ""));
            })
            .body(|body| {
                body.rows(row_height, stored.len(), |mut row| {
                    let sample = &stored[order[row.index()]];
                    let info = &sample.info;
                    let arch = arch(info);
                    let runs_here = info.is_script() || arch.as_deref() == Some("x86-64");
                    row.col(|ui| {
                        ui.add(egui::Label::new(RichText::new(&info.file_name).font(mono.clone())).truncate())
                            .on_hover_text(format!(
                                "SHA-256 {}\nFrom {} · first seen {}",
                                info.sha256_hash, sample.source, info.first_seen
                            ));
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(info.signature.as_deref().unwrap_or("-"))
                                .color(theme::value(ValueKind::Name)),
                        );
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(arch.as_deref().unwrap_or("not an ELF")).color(if runs_here {
                                theme::good()
                            } else {
                                theme::warn()
                            }),
                        )
                        .on_hover_text(if info.is_script() {
                            "A shell script: runs in the guests through /bin/sh"
                        } else if runs_here {
                            "Runs in Antinomie's x86-64 guests"
                        } else {
                            "Built for another processor or not a Linux program: it will not run in the x86-64 guests"
                        });
                    });
                    row.col(|ui| {
                        ui.colored_label(theme::muted(), crate::values::file_size(info.file_size));
                    });
                    row.col(|ui| {
                        ui.colored_label(
                            theme::muted(),
                            match sample.pushes.len() {
                                0 => "not sent".to_string(),
                                1 => "sent once".to_string(),
                                n => format!("sent {n}×"),
                            },
                        )
                        .on_hover_text(
                            sample
                                .pushes
                                .iter()
                                .map(|push| format!("{} · {}", push.vm_name, push.path))
                                .collect::<Vec<_>>()
                                .join("\n"),
                        );
                    });
                    row.col(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .button(RichText::new("Delete").color(theme::error()))
                                .clicked()
                            {
                                delete = Some(info.sha256_hash.clone());
                            }
                            if ui
                                .button(egui_phosphor::regular::COPY)
                                .on_hover_text("Copy the SHA-256")
                                .clicked()
                            {
                                ui.ctx().copy_text(info.sha256_hash.clone());
                            }
                            let can = cx.running && !pending;
                            let destination = guest_path(info, sample.pushes.len());
                            if ui
                                .add_enabled(can && runs_here, egui::Button::new("Send and run…"))
                                .on_hover_text(format!(
                                    "Send to {destination}, then open Run program with it to choose how it runs"
                                ))
                                .on_disabled_hover_text(if runs_here {
                                    "Start the VM first"
                                } else {
                                    "Only x86-64 Linux programs and shell scripts run in the guests"
                                })
                                .clicked()
                            {
                                let uid = if self.as_root { 0 } else { 1000 };
                                action = Some(SamplesAction::Push {
                                    sha256: info.sha256_hash.clone(),
                                    destination: destination.clone(),
                                    // Scripts through /bin/sh: many have no #! line.
                                    run: Some(ExecRequest {
                                        path: if info.is_script() {
                                            "/bin/sh".into()
                                        } else {
                                            destination.clone()
                                        },
                                        args: if info.is_script() {
                                            vec![destination.clone()]
                                        } else {
                                            Vec::new()
                                        },
                                        uid,
                                        gid: uid,
                                        cwd: "/tmp".into(),
                                        ..ExecRequest::default()
                                    }),
                                });
                            }
                            if ui
                                .add_enabled(can, egui::Button::new("Send to VM"))
                                .on_hover_text(format!(
                                    "Send to {destination} without running it (executable)"
                                ))
                                .on_disabled_hover_text("Start the VM first")
                                .clicked()
                            {
                                action = Some(SamplesAction::Push {
                                    sha256: info.sha256_hash.clone(),
                                    destination,
                                    run: None,
                                });
                            }
                        });
                    });
                });
            });
        if let Some(hash) = delete {
            self.status = Some(match samples::delete(cx.data_dir, &hash) {
                Ok(()) => ("Sample deleted".into(), false),
                Err(error) => (error, true),
            });
            self.stored = None;
        }
        if let Some(SamplesAction::Push { run, .. }) = &action {
            self.awaiting = Some(run.clone());
        }
        action
    }
}
