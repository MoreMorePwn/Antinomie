// SPDX-License-Identifier: GPL-3.0-only
//! What the Getting started window needs of the Rule manager: the catalog's
//! packs, which of them are installed, and one install at a time on the
//! manager's own worker. Nothing here opens the network by itself.
use super::{sources::short_revision, Model, Ordering};
use std::{collections::BTreeSet, path::Path};

/// One pack the catalog offers, for any engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Offer {
    pub id: String,
    pub engine: String,
    pub name: String,
    /// The pin or version, as the catalog table shows it.
    pub version: String,
    pub rules: u64,
    pub size: u64,
    pub license: String,
    /// Terms to read before downloading, for example a license restriction.
    pub notices: Vec<String>,
    pub hosts: String,
    pub installed: bool,
}

/// The rule engines a complete first setup has a pack for.
pub(crate) const ENGINES: [(&str, &str); 3] =
    [("yara", "YARA"), ("ids", "IDS"), ("sigma", "Sigma")];

impl Model {
    /// The local registry is read (offers and installed state are current).
    pub(crate) fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Installed packs (enabled or not; custom groups are not packs), once
    /// the registry is read.
    pub(crate) fn pack_count(&self) -> Option<usize> {
        self.loaded.then_some(self.registry.packs.len())
    }

    pub(crate) fn is_busy(&self) -> bool {
        self.job.is_some()
    }

    /// Engines that have at least one installed pack.
    pub(crate) fn engines_with_packs(&self) -> BTreeSet<String> {
        self.registry
            .packs
            .iter()
            .map(|pack| pack.engine.clone())
            .collect()
    }

    /// The latest status line, whether it is an error, and the running job's
    /// progress line.
    pub(crate) fn status_text(&self) -> (&str, bool, Option<String>) {
        let progress = self.job.as_ref().map(|job| {
            job.progress
                .lock()
                .ok()
                .map(|text| text.clone())
                .unwrap_or_default()
        });
        (
            &self.status,
            self.status_error.as_deref() == Some(self.status.as_str()),
            progress,
        )
    }

    /// The hosts a catalog check or a download contacts, in one sentence.
    pub(crate) fn consent_line(&self) -> String {
        self.hosts_line()
    }

    pub(crate) fn offers(&self) -> Vec<Offer> {
        let Some(catalog) = &self.catalog else {
            return Vec::new();
        };
        let installed = |id: &str| self.registry.packs.iter().any(|pack| pack.id == id);
        let mut offers: Vec<Offer> = catalog
            .sources
            .iter()
            .map(|pack| Offer {
                id: pack.id.clone(),
                engine: pack.engine.clone(),
                name: pack.name.clone(),
                version: format!(
                    "{} {}",
                    pack.revision_kind,
                    short_revision(&pack.revision_kind, &pack.revision)
                ),
                rules: pack.rules,
                size: pack.download_size(),
                license: pack.license.clone(),
                notices: pack.notices.clone(),
                hosts: pack.primary_hosts().join(", "),
                installed: installed(&pack.id),
            })
            .collect();
        offers.extend(catalog.packs.iter().map(|pack| {
            Offer {
                id: pack.id.clone(),
                engine: pack.engine.clone(),
                name: pack.name.clone(),
                version: pack.version.clone(),
                rules: pack.rules,
                size: pack.size,
                license: pack.license.clone(),
                notices: Vec::new(),
                hosts: pack
                    .download_url
                    .split('/')
                    .nth(2)
                    .unwrap_or_default()
                    .to_owned(),
                installed: installed(&pack.id),
            }
        }));
        offers
    }

    /// Read the local registry again (after another window changed it).
    pub(crate) fn reload(&mut self, data_dir: &Path) {
        self.loaded = false;
        self.status_error = None;
        self.ensure(data_dir);
    }

    pub(crate) fn check_catalog(&mut self, data_dir: &Path, outbound: bool) {
        self.refresh_catalog(data_dir, outbound);
    }

    /// Install a catalog pack by id with its default options. Returns whether
    /// a job started; downloads stay off until `outbound` is allowed.
    pub(crate) fn install_offer(&mut self, data_dir: &Path, outbound: bool, id: &str) -> bool {
        if self.job.is_some() || !outbound {
            return false;
        }
        let Some(catalog) = self.catalog.clone() else {
            return false;
        };
        if let Some(pack) = catalog.sources.iter().find(|pack| pack.id == id) {
            let options = pack.default_options();
            self.install_source_pack(data_dir, outbound, pack.clone(), options);
        } else if let Some(entry) = catalog.packs.iter().find(|entry| entry.id == id) {
            self.install(data_dir, outbound, entry.clone());
        }
        self.job.is_some()
    }

    pub(crate) fn cancel_job(&mut self) {
        if let Some(job) = &self.job {
            job.cancel.store(true, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    pub(crate) fn set_catalog_for_test(
        &mut self,
        catalog: antinomie_monitor_core::ruleset::Catalog,
    ) {
        self.catalog = Some(catalog);
        self.loaded = true;
    }

    #[cfg(test)]
    pub(crate) fn set_packs_for_test(
        &mut self,
        packs: Vec<antinomie_monitor_core::ruleset::InstalledPack>,
    ) {
        self.registry.packs = packs;
        self.loaded = true;
    }
}
