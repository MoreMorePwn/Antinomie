// SPDX-License-Identifier: GPL-3.0-only
//! The presets as the desktop app's Run program form lists them: the five
//! built-in ones, then `<data>/presets/*.toml`, read by the same parser as
//! the service (`validate::parse_preset`), so a preset means the same in the
//! window, on the command line and in Auto mode. A file with an error is
//! listed with its error instead of being left out.

use super::{
    builtin,
    preset::{LoadedPreset, Preset},
    validate::{self, Severity},
};
use std::{path::Path, sync::Arc};

/// Which of the program's keys a preset text writes out. The form fills a
/// program field only from a preset that sets it, so a short preset file
/// never clears what the user typed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Written {
    pub arguments: bool,
    pub working_directory: bool,
    pub environment: bool,
    /// `user`, `uid` or `gid`.
    pub user: bool,
}

impl Written {
    /// The keys of `[program]` in `text`.
    pub fn of(text: &str) -> Self {
        let Some(program) = toml::from_str::<toml::Table>(text)
            .ok()
            .and_then(|table| table.get("program").and_then(|t| t.as_table().cloned()))
        else {
            return Self::default();
        };
        let has = |key: &str| program.contains_key(key);
        Self {
            arguments: has("arguments"),
            working_directory: has("working_directory"),
            environment: has("environment"),
            user: has("user") || has("uid") || has("gid"),
        }
    }
}

/// One entry of the form's list.
#[derive(Clone, Debug)]
pub struct FormPreset {
    /// The preset's name (`standard`, or the file's name without `.toml`).
    pub name: String,
    /// What the list shows: the title, else the name.
    pub title: String,
    pub description: String,
    pub built_in: bool,
    /// The options, or why the file cannot be used.
    pub options: Result<FormOptions, String>,
}

/// A preset that parsed.
#[derive(Clone, Debug)]
pub struct FormOptions {
    pub loaded: Arc<LoadedPreset>,
    pub written: Written,
    /// What this version cannot do for the preset: a live route is not set
    /// up, a kept VM arrives later. Empty: nothing.
    pub unavailable: Vec<String>,
}

impl FormOptions {
    pub fn preset(&self) -> &Preset {
        &self.loaded.preset
    }
}

fn unavailable(preset: &Preset) -> Vec<String> {
    crate::store::admission::node_refusals(preset, &preset.vm.lane_group)
        .into_iter()
        .map(|refusal| match refusal.field {
            "network.route" => format!(
                "Route {} is not set up in this version ({}).",
                preset.network.route, refusal.what
            ),
            _ => refusal.message,
        })
        .collect()
}

/// The five built-in presets, Standard first.
pub fn built_in() -> Vec<FormPreset> {
    let loaded = validate::built_in_presets();
    builtin::BUILT_IN
        .iter()
        .filter_map(|(name, text)| {
            let loaded = loaded.get(*name)?.clone();
            Some(FormPreset {
                name: (*name).to_owned(),
                title: loaded.title().to_owned(),
                description: loaded.preset.description.clone(),
                built_in: true,
                options: Ok(FormOptions {
                    written: Written::of(text),
                    unavailable: unavailable(&loaded.preset),
                    loaded,
                }),
            })
        })
        .collect()
}

/// The built-in presets, then the files of `<data_dir>/presets`, by name.
pub fn list(data_dir: &Path) -> Vec<FormPreset> {
    let mut out = built_in();
    let mut files: Vec<_> = std::fs::read_dir(data_dir.join("presets"))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    for path in files {
        let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let shown = format!("presets/{name}.toml");
        out.push(read_file(name, &shown, &path));
    }
    out
}

fn read_file(name: &str, shown: &str, path: &Path) -> FormPreset {
    let invalid = |reason: String| FormPreset {
        name: name.to_owned(),
        title: name.to_owned(),
        description: String::new(),
        built_in: false,
        options: Err(reason),
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => return invalid(format!("{shown}: cannot read the file: {error}")),
    };
    let (parsed, problems) = validate::parse_preset(name, shown, &text);
    if let Some(error) = problems.iter().find(|p| p.severity == Severity::Error) {
        return invalid(error.to_string());
    }
    let Some(loaded) = parsed else {
        return invalid(format!("{shown}: not a preset"));
    };
    let loaded = Arc::new(loaded);
    FormPreset {
        name: name.to_owned(),
        title: loaded.title().to_owned(),
        description: loaded.preset.description.clone(),
        built_in: false,
        options: Ok(FormOptions {
            written: Written::of(&text),
            unavailable: unavailable(&loaded.preset),
            loaded,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ant-form-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(root.join("presets")).unwrap();
        root
    }

    #[test]
    fn the_built_ins_come_first_and_are_the_services() {
        let listed = built_in();
        let names: Vec<_> = listed.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "standard",
                "quick-look",
                "deep",
                "interactive",
                "live-network"
            ]
        );
        assert!(listed.iter().all(|p| p.built_in && p.options.is_ok()));
        let live = listed[4].options.as_ref().unwrap();
        assert_eq!(live.unavailable.len(), 1);
        assert!(live.unavailable[0].contains("route.tor"), "{live:?}");
        for entry in &listed[..4] {
            assert!(entry.options.as_ref().unwrap().unavailable.is_empty());
        }
    }

    #[test]
    fn standard_writes_the_program_keys_and_the_short_ones_do_not() {
        let listed = built_in();
        let written = |index: usize| listed[index].options.as_ref().unwrap().written;
        assert_eq!(
            written(0),
            Written {
                arguments: true,
                working_directory: true,
                environment: true,
                user: true
            }
        );
        assert_eq!(written(1), Written::default());
        assert_eq!(Written::of("not = [toml"), Written::default());
    }

    #[test]
    fn files_are_listed_after_the_built_ins_and_a_broken_one_keeps_its_error() {
        let data = scratch("files");
        std::fs::write(data.join("presets/b-ok.toml"), "title = \"Fine\"\n").unwrap();
        std::fs::write(
            data.join("presets/a-bad.toml"),
            "[program]\nrun_time_s = \"x\"\n",
        )
        .unwrap();
        std::fs::write(data.join("presets/notes.txt"), "not a preset").unwrap();
        let listed = list(&data);
        let names: Vec<_> = listed.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(&names[5..], ["a-bad", "b-ok"]);
        assert!(
            listed[5]
                .options
                .as_ref()
                .unwrap_err()
                .starts_with("presets/a-bad.toml:2")
        );
        assert_eq!(listed[6].title, "Fine");
        assert!(listed[6].options.is_ok());
        assert_eq!(list(&data.join("missing")).len(), 5);
        let _ = std::fs::remove_dir_all(&data);
    }
}
