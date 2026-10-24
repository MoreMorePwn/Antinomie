// SPDX-License-Identifier: GPL-3.0-only
//! The rule manager's part of the regex matches: built-in patterns switched
//! off, and patterns the user added. Stored as one JSON file under the rules
//! folder; a missing or unreadable file means the defaults.
use super::Category;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Custom patterns kept; a longer list is refused when saved.
pub const CUSTOM_MAX_COUNT: usize = 200;
/// Longest custom pattern, in characters.
pub const PATTERN_MAX_LEN: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomPattern {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub pattern: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub schema: u32,
    /// Ids of built-in patterns that are switched off.
    pub disabled: Vec<String>,
    pub custom: Vec<CustomPattern>,
}

pub fn config_path(data_dir: &Path) -> PathBuf {
    crate::ruleset::rules_root(data_dir).join("strings-regex.json")
}

impl Config {
    /// The saved configuration, or the defaults when there is none.
    pub fn load(data_dir: &Path) -> Result<Self, String> {
        let path = config_path(data_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let config: Self = crate::storage::read_json(&path)?;
        config.validate()?;
        Ok(config)
    }

    /// Check the bounds, then replace the saved file.
    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        self.validate()?;
        let path = config_path(data_dir);
        if let Some(parent) = path.parent() {
            crate::storage::private_dir(parent).map_err(|e| e.to_string())?;
        }
        crate::storage::atomic_json(
            &path,
            &Self {
                schema: 1,
                ..self.clone()
            },
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.custom.len() > CUSTOM_MAX_COUNT || self.disabled.len() > 1024 {
            return Err("too many regex patterns".into());
        }
        for (index, pattern) in self.custom.iter().enumerate() {
            if pattern.id.is_empty()
                || pattern.id.len() > 64
                || !pattern.id.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
                })
                || self.custom[..index]
                    .iter()
                    .any(|other| other.id == pattern.id)
                || super::catalog::BUILTIN
                    .iter()
                    .any(|built| built.id == pattern.id)
            {
                return Err(format!("regex pattern id \"{}\" is not usable", pattern.id));
            }
            if pattern.name.trim().is_empty() || pattern.name.len() > 80 {
                return Err(format!(
                    "regex pattern \"{}\" needs a name of up to 80 characters",
                    pattern.id
                ));
            }
            if pattern.pattern.is_empty() || pattern.pattern.chars().count() > PATTERN_MAX_LEN {
                return Err(format!(
                    "regex pattern \"{}\" must have 1 to {PATTERN_MAX_LEN} characters",
                    pattern.id
                ));
            }
            super::compile(&pattern.pattern)
                .map_err(|error| format!("regex pattern \"{}\": {error}", pattern.id))?;
        }
        Ok(())
    }

    /// Switch a built-in pattern on or off.
    pub fn set_enabled(&mut self, id: &str, enabled: bool) {
        self.disabled.retain(|disabled| disabled != id);
        if !enabled {
            self.disabled.push(id.to_owned());
        }
    }

    pub fn is_enabled(&self, id: &str) -> bool {
        !self.disabled.iter().any(|disabled| disabled == id)
    }
}

/// The built-in patterns for the rule manager to list: id, category, type
/// and regex.
pub fn builtin_patterns() -> Vec<(&'static str, Category, &'static str, &'static str)> {
    super::catalog::BUILTIN
        .iter()
        .map(|built| (built.id, built.category, built.name, built.regex))
        .collect()
}
