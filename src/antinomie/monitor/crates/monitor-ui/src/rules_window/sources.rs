// SPDX-License-Identifier: GPL-3.0-only
//! The Rule manager's view of schema 2 packs: where each collection comes
//! from, what it is licensed under, which hosts it contacts, and the install,
//! update and remove buttons.
use super::{theme, Done, Model};
use antinomie_monitor_core::ruleset::{self, InstalledPack, SourcePack};
use eframe::egui::{self, RichText};
use std::{collections::BTreeSet, path::Path};

/// Rules shown with a thousands separator: `4,709`.
fn digits(value: u64) -> String {
    let text = value.to_string();
    let mut out = String::new();
    for (index, c) in text.chars().enumerate() {
        if index > 0 && (text.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A pin as people read it: a commit is shortened.
pub(super) fn short_revision(kind: &str, revision: &str) -> String {
    if kind == "commit" && revision.len() > 12 && revision.chars().all(|c| c.is_ascii_hexdigit()) {
        revision[..12].to_owned()
    } else {
        revision.to_owned()
    }
}

fn fetched_at(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0))
        .map(|time| time.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "unknown time".into())
}

fn size_text(bytes: u64) -> String {
    crate::values::file_size(bytes)
}

fn note(ui: &mut egui::Ui, text: impl Into<String>, color: egui::Color32) {
    let text = text.into();
    if color == theme::warn() {
        crate::activity::warning(ui, text);
    } else if color == theme::error() {
        crate::activity::error(ui, text);
    } else {
        ui.add(egui::Label::new(RichText::new(text).small().color(color)).wrap());
    }
}

impl Model {
    /// The consent sentence for turning downloads on: every host contacted.
    pub(super) fn hosts_line(&self) -> String {
        let hosts = ruleset::contacted_hosts(self.catalog.as_ref()).join(", ");
        if self
            .catalog
            .as_ref()
            .is_some_and(|catalog| !catalog.sources.is_empty())
        {
            format!("Rule downloads contact only: {hosts}.")
        } else {
            format!(
                "Checking for updates contacts {hosts}. Each pack then names the publisher hosts it downloads from before you install it."
            )
        }
    }

    fn chosen(&mut self, pack: &SourcePack) -> BTreeSet<String> {
        if !self.choices.contains_key(&pack.id) {
            let start = self
                .registry
                .packs
                .iter()
                .find(|installed| installed.id == pack.id)
                .and_then(|installed| installed.source.as_ref())
                .map(|source| source.options.iter().cloned().collect())
                .unwrap_or_else(|| pack.default_options());
            self.choices.insert(pack.id.clone(), start);
        }
        self.choices[&pack.id].clone()
    }

    pub(super) fn source_entry(
        &mut self,
        ui: &mut egui::Ui,
        data_dir: &Path,
        outbound: bool,
        pack: &SourcePack,
    ) {
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "{} · {} {} · about {} rules",
                    pack.name,
                    pack.revision_kind,
                    short_revision(&pack.revision_kind, &pack.revision),
                    digits(pack.rules)
                ))
                .strong()
                .color(theme::text()),
            )
            .wrap(),
        );
        note(
            ui,
            format!("Source: {}", pack.homepage.trim_start_matches("https://")),
            theme::muted(),
        );
        note(ui, format!("License: {}", pack.license), theme::muted());
        note(
            ui,
            format!(
                "Downloads {} from {}",
                size_text(pack.download_size()),
                pack.primary_hosts().join(", ")
            ),
            theme::muted(),
        );
        for notice in &pack.notices {
            note(ui, notice.clone(), theme::warn());
        }
        let mut options = self.chosen(pack);
        for option in &pack.options {
            let mut on = options.contains(&option.id);
            if ui.checkbox(&mut on, &option.label).changed() {
                if on {
                    options.insert(option.id.clone());
                } else {
                    options.remove(&option.id);
                }
                self.choices.insert(pack.id.clone(), options.clone());
            }
            if on && !option.warning.is_empty() {
                note(ui, option.warning.clone(), theme::warn());
            } else if !option.default {
                note(ui, "Off by default.", theme::muted());
            }
        }
        let version = pack.version(&options);
        let installed = self
            .registry
            .packs
            .iter()
            .find(|installed| installed.id == pack.id)
            .cloned();
        ui.horizontal_wrapped(|ui| match &installed {
            Some(current) if current.version == version => {
                ui.colored_label(theme::good(), "installed");
            }
            Some(current) if current.source.is_some() => {
                let same_pin = current
                    .source
                    .as_ref()
                    .is_some_and(|source| source.revision == pack.revision);
                let label = if same_pin {
                    "Reinstall with this choice"
                } else {
                    "Update"
                };
                if ui.button(label).clicked() {
                    self.install_source_pack(data_dir, outbound, pack.clone(), options.clone());
                }
            }
            _ => {
                if ui.button("Download and install").clicked() {
                    self.install_source_pack(data_dir, outbound, pack.clone(), options.clone());
                }
            }
        });
        egui::CollapsingHeader::new(RichText::new("About this pack").small())
            .id_salt(("rule-source-about", &pack.id))
            .default_open(false)
            .show(ui, |ui| {
                note(
                    ui,
                    format!("Contacts: {}", pack.hosts().join(", ")),
                    theme::muted(),
                );
                if !pack.license_url.is_empty() {
                    note(ui, format!("License text: {}", pack.license_url), theme::muted());
                }
                note(
                    ui,
                    format!(
                        "Pinned {} {} · {} files in {} downloads",
                        pack.revision_kind,
                        pack.revision,
                        pack.sources.iter().map(|source| source.files.len()).sum::<usize>(),
                        pack.sources.len()
                    ),
                    theme::muted(),
                );
                if pack.sources.iter().any(|source| source.rolling) {
                    note(
                        ui,
                        "The publisher updates this download in place, so a newer download is installed and recorded as different from the catalog.",
                        theme::muted(),
                    );
                }
                for limit in &pack.limits {
                    note(ui, limit.clone(), theme::muted());
                }
                note(ui, format!("Needs {} and app {}.", pack.engine_requirement, pack.app), theme::muted());
            });
    }

    /// Where an installed pack came from, and its remove and update controls.
    pub(super) fn installed_source(
        &mut self,
        ui: &mut egui::Ui,
        data_dir: &Path,
        outbound: bool,
        pack: &InstalledPack,
    ) {
        let Some(source) = &pack.source else {
            self.remove_button(ui, data_dir, &pack.id);
            return;
        };
        note(ui, source.line(), theme::muted());
        egui::CollapsingHeader::new(RichText::new("Source, license and hashes").small())
            .id_salt(("rule-installed-source", &pack.id))
            .default_open(false)
            .show(ui, |ui| {
                note(ui, format!("Project: {}", source.homepage), theme::muted());
                note(ui, format!("License: {}", source.license), theme::muted());
                if !source.license_url.is_empty() {
                    note(
                        ui,
                        format!("License text: {}", source.license_url),
                        theme::muted(),
                    );
                }
                note(
                    ui,
                    format!(
                        "Pinned {} {} · fetched {}",
                        source.revision_kind,
                        source.revision,
                        fetched_at(source.fetched_unix)
                    ),
                    theme::muted(),
                );
                for fetched in &source.sources {
                    let check = if fetched.verified {
                        "matches the catalog".to_owned()
                    } else {
                        format!("differs from the catalog ({} files)", fetched.changed_files)
                    };
                    note(
                        ui,
                        format!(
                            "{} · {} · sha256 {} · {check}",
                            fetched.url,
                            size_text(fetched.size),
                            &fetched.download_sha256[..fetched.download_sha256.len().min(16)]
                        ),
                        if fetched.verified {
                            theme::muted()
                        } else {
                            theme::warn()
                        },
                    );
                }
                for line in &source.summary {
                    note(ui, line.clone(), theme::muted());
                }
                for line in &source.notes {
                    note(ui, line.clone(), theme::warn());
                }
                if !source.options.is_empty() {
                    note(
                        ui,
                        format!("Options on: {}", source.options.join(", ")),
                        theme::warn(),
                    );
                }
            });
        if let Some(entry) = self
            .catalog
            .as_ref()
            .and_then(|catalog| ruleset::source_update(catalog, pack))
            .cloned()
        {
            let options: BTreeSet<String> = source.options.iter().cloned().collect();
            ui.horizontal_wrapped(|ui| {
                crate::activity::warning(
                    ui,
                    format!(
                        "Update available: {} {}",
                        entry.revision_kind,
                        short_revision(&entry.revision_kind, &entry.revision)
                    ),
                );
                if ui.button("Update").clicked() {
                    self.install_source_pack(data_dir, outbound, entry.clone(), options);
                }
            });
        }
        self.remove_button(ui, data_dir, &pack.id);
    }

    fn remove_button(&mut self, ui: &mut egui::Ui, data_dir: &Path, id: &str) {
        if ui
            .button("Remove")
            .on_hover_text("Deletes this pack and its retained versions from this computer.")
            .clicked()
        {
            self.remove_pack(data_dir, id);
        }
    }

    pub(super) fn install_source_pack(
        &mut self,
        data_dir: &Path,
        outbound: bool,
        pack: SourcePack,
        options: BTreeSet<String>,
    ) {
        if !outbound {
            self.status = format!(
                "Allow downloads first. {} downloads from {}.",
                pack.name,
                pack.hosts().join(", ")
            );
            return;
        }
        let dir = data_dir.to_path_buf();
        self.status = format!(
            "Downloading {} from {}…",
            pack.name,
            pack.primary_hosts().join(", ")
        );
        self.spawn_with_progress(move |cancel, progress| {
            let installed = ruleset::install_source(
                &dir,
                &pack,
                &options,
                &ruleset::Curl::default(),
                &cancel,
                &mut |line| {
                    if let Ok(mut shown) = progress.lock() {
                        *shown = line.to_owned();
                    }
                },
            )
            .map_err(|error| {
                if error == "cancelled" {
                    format!("Cancelled. {} was not changed.", pack.name)
                } else {
                    format!("{} was not installed: {error}", pack.name)
                }
            })?;
            let kept = if installed.already_installed {
                "was already installed; selected it again".to_owned()
            } else {
                format!("installed with {} rules", digits(installed.rules))
            };
            Ok(Done::Message(format!("{} {kept}.", pack.name)))
        });
    }

    fn remove_pack(&mut self, data_dir: &Path, id: &str) {
        let dir = data_dir.to_path_buf();
        let id = id.to_owned();
        self.choices.remove(&id);
        self.rows.clear();
        self.visible.clear();
        self.detail = None;
        self.spawn(move |_| {
            ruleset::remove_pack(&dir, &id)?;
            Ok(Done::Message(format!(
                "Removed {id}. Earlier scan results keep their own record."
            )))
        });
    }
}

#[cfg(test)]
mod size_tests {
    #[test]
    fn rule_pack_sizes_use_the_shared_bytes_format() {
        assert_eq!(super::size_text(2048), "2048 bytes (2.0 KB)");
        assert_eq!(super::size_text(3 * 1024 * 1024), "3145728 bytes (3.0 MB)");
    }
}
