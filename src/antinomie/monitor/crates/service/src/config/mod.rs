// SPDX-License-Identifier: GPL-3.0-only
//! Configuration: `service.toml` (design 2.4.2) and the presets (the five
//! built-in ones and `presets/*.toml`), their validation (`config validate`)
//! and the set of presets a running service holds. A run freezes the preset
//! it is submitted with (or its Custom options), so a reload (SIGHUP) never
//! changes a run already queued or running (5.6).

pub mod builtin;
pub mod callers;
pub mod catalog;
pub mod locate;
pub mod migrate;
pub mod preset;
pub mod service;
pub mod validate;

use crate::api::{ops::Caller, status::PresetSummary};
pub use catalog::{DiskVms, NoVms, VmCatalog, VmFacts, VmNet};
pub use preset::{LoadedPreset, Preset};
pub use service::ServiceConfig;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, RwLock},
};
pub use validate::{ConfigReport, Problem, Severity};

/// Where the service finds a preset by name.
pub trait PresetLookup: Send + Sync {
    fn get(&self, name: &str) -> Option<Arc<LoadedPreset>>;
}

/// An immutable set of presets (the built-in ones and the files), and the
/// node's lane group the presets are checked against.
#[derive(Clone, Debug)]
pub struct PresetSet {
    by_name: BTreeMap<String, Arc<LoadedPreset>>,
    lane_group: String,
}

impl Default for PresetSet {
    fn default() -> Self {
        Self::new(BTreeMap::new())
    }
}

impl PresetSet {
    /// `by_name` and the lane group of a default `service.toml`.
    pub fn new(by_name: BTreeMap<String, Arc<LoadedPreset>>) -> Self {
        Self {
            by_name,
            lane_group: preset::DEFAULT_LANE_GROUP.into(),
        }
    }

    /// The same set on a node whose lane group is `group`.
    pub fn with_lane_group(mut self, group: &str) -> Self {
        self.lane_group = group.to_owned();
        self
    }

    /// A set of one preset, for tests and for the direct-mode CLI.
    pub fn single(preset: LoadedPreset) -> Self {
        let mut by_name = BTreeMap::new();
        by_name.insert(preset.name.clone(), Arc::new(preset));
        Self::new(by_name)
    }

    /// The five built-in presets alone.
    pub fn built_in() -> Self {
        Self::new(validate::built_in_presets())
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// The node's lane group.
    pub fn lane_group(&self) -> &str {
        &self.lane_group
    }

    /// `policy.list`: every preset, with the permissions its options need,
    /// the ones `caller` lacks and what this node does not have. `offered_to`
    /// names roles; 0.9.0 callers have none, so every preset is listed.
    pub fn list_for(&self, caller: &Caller) -> Vec<PresetSummary> {
        self.by_name
            .values()
            .map(|loaded| {
                let needs: Vec<_> = crate::store::admission::permissions_used(&loaded.preset)
                    .into_iter()
                    .map(|used| used.permission)
                    .filter(|p| *p != crate::api::ops::Permission::RunsSubmit)
                    .collect();
                let missing = needs.iter().copied().filter(|p| !caller.has(*p)).collect();
                let unavailable =
                    crate::store::admission::node_refusals(&loaded.preset, &self.lane_group)
                        .into_iter()
                        .map(|refusal| refusal.message)
                        .collect();
                PresetSummary {
                    name: loaded.name.clone(),
                    title: loaded.title().to_owned(),
                    description: loaded.preset.description.clone(),
                    digest: loaded.digest.clone(),
                    built_in: loaded.built_in,
                    offered_to: loaded.preset.offered_to.clone(),
                    needs,
                    missing,
                    unavailable,
                }
            })
            .collect()
    }
}

impl PresetLookup for PresetSet {
    fn get(&self, name: &str) -> Option<Arc<LoadedPreset>> {
        self.by_name.get(name).cloned()
    }
}

/// The presets of a running service, replaced as a whole by a reload.
pub struct SharedPresets {
    current: RwLock<Arc<PresetSet>>,
}

impl SharedPresets {
    pub fn new(set: PresetSet) -> Self {
        Self {
            current: RwLock::new(Arc::new(set)),
        }
    }

    pub fn snapshot(&self) -> Arc<PresetSet> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Read `<data>/presets` again (SIGHUP). On any error the old set stays
    /// and the problems are returned; runs already stored keep the preset
    /// they froze either way.
    pub fn reload(&self, data_dir: &Path, catalog: &dyn VmCatalog) -> Result<usize, Vec<Problem>> {
        let report = validate::load(data_dir, catalog, None);
        if report.has_errors() {
            return Err(report.problems);
        }
        let count = report.presets.len();
        *self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(report.preset_set());
        Ok(count)
    }
}

impl PresetLookup for SharedPresets {
    fn get(&self, name: &str) -> Option<Arc<LoadedPreset>> {
        self.snapshot().get(name)
    }
}
