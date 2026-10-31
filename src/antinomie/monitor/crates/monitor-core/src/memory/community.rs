// SPDX-License-Identifier: GPL-3.0-only
//! Community Volatility 3 plugins from a catalog, downloaded on demand.
//!
//! Antinomie distributes none of them: the catalog (`community-plugins.json`,
//! built into the app) names each plugin's upstream repository, a pinned
//! commit and the SHA-256 of every file; installing downloads the files from
//! that commit, checks them, applies the catalog's small compatibility edits
//! (such as the plugin version a newer Volatility ships) and checks the result
//! again. Each plugin lands in its own folder of the community folder, with
//! its license file, where Volatility loads it as `<id>.<module>.<Class>`.
use super::Os;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

const CATALOG: &str = include_str!("community-plugins.json");
/// Written beside an installed plugin's files: its catalog entry.
pub const MANIFEST_FILE: &str = "antinomie-plugin.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edit {
    pub find: String,
    pub replace: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginFile {
    /// Path in the upstream repository.
    pub from: String,
    /// Path in the plugin's folder.
    pub to: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edits: Vec<Edit>,
    /// SHA-256 after the edits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityPlugin {
    /// Folder name, and the first part of its plugins' names.
    pub id: String,
    pub name: String,
    pub author: String,
    /// SPDX identifier of the upstream license.
    pub license: String,
    pub os: Os,
    pub summary: String,
    /// Python packages some of its plugins need beyond Volatility's own.
    #[serde(default)]
    pub requires: Vec<String>,
    pub repo: String,
    pub commit: String,
    pub files: Vec<PluginFile>,
    /// What was checked before it was listed.
    pub tested: String,
    /// What it was found not to do.
    #[serde(default)]
    pub caveats: Vec<String>,
}

impl CommunityPlugin {
    /// Where a file is downloaded from: the pinned commit, never a branch.
    pub fn file_url(&self, file: &PluginFile) -> Result<String, String> {
        let path = self
            .repo
            .strip_prefix("https://github.com/")
            .ok_or("only GitHub repositories are supported")?;
        Ok(format!(
            "https://raw.githubusercontent.com/{path}/{}/{}",
            self.commit, file.from
        ))
    }
    /// The source of the pinned commit, to read before installing.
    pub fn source_url(&self) -> String {
        format!("{}/tree/{}", self.repo, self.commit)
    }
    pub fn size(&self) -> u64 {
        self.files.iter().map(|file| file.size).sum()
    }
}

#[derive(Deserialize)]
struct CatalogFile {
    schema: u32,
    plugins: Vec<CommunityPlugin>,
}

/// The catalog built into this version of Antinomie.
pub fn catalog() -> Result<Vec<CommunityPlugin>, String> {
    let file: CatalogFile =
        serde_json::from_str(CATALOG).map_err(|e| format!("plugin catalog: {e}"))?;
    if file.schema != 1 {
        return Err(format!("plugin catalog schema {} is unknown", file.schema));
    }
    for plugin in &file.plugins {
        validate(plugin)?;
    }
    Ok(file.plugins)
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !name.as_bytes()[0].is_ascii_digit()
}

fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
}

fn validate(plugin: &CommunityPlugin) -> Result<(), String> {
    let hex64 = |text: &str| text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit());
    if !safe_name(&plugin.id) {
        return Err(format!("plugin catalog: bad id {:?}", plugin.id));
    }
    if plugin.commit.len() != 40 || !plugin.commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{}: the commit must be a full hash", plugin.id));
    }
    for file in &plugin.files {
        if !safe_path(&file.from) || !safe_path(&file.to) || file.to == MANIFEST_FILE {
            return Err(format!("{}: bad file path {:?}", plugin.id, file.to));
        }
        if !hex64(&file.sha256) || file.edited_sha256.as_deref().is_some_and(|h| !hex64(h)) {
            return Err(format!("{}: bad SHA-256 for {}", plugin.id, file.to));
        }
        if file.edits.is_empty() != file.edited_sha256.is_none() {
            return Err(format!(
                "{}: edits of {} lack a SHA-256",
                plugin.id, file.to
            ));
        }
    }
    plugin.file_url(&plugin.files[0]).map(|_| ())
}

/// An installed catalog plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    pub plugin: CommunityPlugin,
    pub dir: PathBuf,
}

impl Installed {
    /// The catalog lists another commit or other files: an update exists.
    pub fn outdated(&self, catalog: &[CommunityPlugin]) -> bool {
        catalog
            .iter()
            .find(|entry| entry.id == self.plugin.id)
            .is_some_and(|entry| entry != &self.plugin)
    }
}

/// Catalog plugins installed in the community folder.
pub fn installed(plugins_dir: &Path) -> Vec<Installed> {
    let mut found: Vec<Installed> = fs::read_dir(plugins_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let dir = entry.path();
            let bytes = fs::read(dir.join(MANIFEST_FILE)).ok()?;
            let plugin: CommunityPlugin = serde_json::from_slice(&bytes).ok()?;
            (dir.file_name()? == plugin.id.as_str()).then_some(Installed { plugin, dir })
        })
        .collect();
    found.sort_by(|a, b| a.plugin.id.cmp(&b.plugin.id));
    found
}

/// Symbol folders of installed plugins that bring their own symbol tables,
/// for Volatility's `-s`.
pub fn symbol_dirs(plugins_dir: &Path) -> Vec<PathBuf> {
    installed(plugins_dir)
        .into_iter()
        .map(|installed| installed.dir.join("symbols"))
        .filter(|dir| dir.is_dir())
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The file's content after the catalog's edits, checked at each step.
fn checked(plugin: &CommunityPlugin, file: &PluginFile, bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    if bytes.len() as u64 != file.size || sha256(&bytes) != file.sha256 {
        return Err(format!(
            "{} does not match the catalog's SHA-256 (the upstream file changed?); \
             nothing was installed",
            file.from
        ));
    }
    if file.edits.is_empty() {
        return Ok(bytes);
    }
    let mut text = String::from_utf8(bytes).map_err(|_| format!("{} is not text", file.from))?;
    for edit in &file.edits {
        if text.matches(&edit.find).count() != 1 {
            return Err(format!("{}: compatibility edit does not apply", file.to));
        }
        text = text.replacen(&edit.find, &edit.replace, 1);
    }
    let edited = text.into_bytes();
    if file.edited_sha256.as_deref() != Some(sha256(&edited).as_str()) {
        return Err(format!(
            "{}: {} differs after its compatibility edit",
            plugin.id, file.to
        ));
    }
    Ok(edited)
}

/// Download, check and install one catalog plugin into the community folder,
/// replacing an earlier version only once every file is in place.
/// `progress` receives `(received, total)` octets.
pub fn install(
    curl: &Path,
    plugins_dir: &Path,
    staging_root: &Path,
    plugin: &CommunityPlugin,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<(), String> {
    validate(plugin)?;
    // Staged outside the community folder: Volatility never sees half a plugin.
    let staging = staging_root.join(format!("plugin-{}", plugin.id));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    let result = (|| {
        let total = plugin.size();
        let mut done = 0;
        for (index, file) in plugin.files.iter().enumerate() {
            let download = staging.join(format!(".download-{index}"));
            let url = plugin.file_url(file)?;
            let mut child = crate::distribution::spawn_download(curl, &url, &download)?;
            loop {
                if cancel.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("plugin installation cancelled".to_owned());
                }
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
                let received = fs::metadata(&download).map_or(0, |m| m.len());
                progress((done + received).min(total), total);
                std::thread::sleep(Duration::from_millis(100));
            }
            crate::distribution::wait_download(&mut child, &url)?;
            let bytes = fs::read(&download).map_err(|e| e.to_string())?;
            let _ = fs::remove_file(&download);
            let bytes = checked(plugin, file, bytes)?;
            let target = staging.join(&file.to);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(&target, bytes).map_err(|e| format!("{}: {e}", target.display()))?;
            done += file.size;
            progress(done, total);
        }
        fs::write(
            staging.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(plugin).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        fs::create_dir_all(plugins_dir).map_err(|e| format!("{}: {e}", plugins_dir.display()))?;
        let target = plugins_dir.join(&plugin.id);
        if target.exists() {
            fs::remove_dir_all(&target).map_err(|e| format!("{}: {e}", target.display()))?;
        }
        fs::rename(&staging, &target).map_err(|e| format!("{}: {e}", target.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

/// Remove an installed catalog plugin (only a folder with its manifest).
pub fn remove(plugins_dir: &Path, id: &str) -> Result<(), String> {
    if !safe_name(id) {
        return Err(format!("bad plugin id {id:?}"));
    }
    let dir = plugins_dir.join(id);
    if !dir.join(MANIFEST_FILE).is_file() {
        return Err(format!("{id} was not installed from the catalog"));
    }
    fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "ant-community-{name}-{}",
            crate::storage::unique_id()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn built_in_catalog_is_pinned_and_valid() {
        let catalog = catalog().unwrap();
        assert!(catalog.len() >= 4);
        for plugin in &catalog {
            assert!(plugin.files.iter().any(|file| file.to.ends_with(".py")));
            assert!(
                plugin
                    .files
                    .iter()
                    .any(|file| file.to.starts_with("LICENSE")),
                "{} ships its license",
                plugin.id
            );
            let url = plugin.file_url(&plugin.files[0]).unwrap();
            assert!(url.starts_with("https://raw.githubusercontent.com/"));
            assert!(url.contains(&plugin.commit));
        }
    }

    #[test]
    fn unsafe_entries_are_rejected() {
        let mut plugin = catalog().unwrap().remove(0);
        plugin.files[0].to = "../escape.py".into();
        assert!(validate(&plugin).is_err());
        let mut plugin = catalog().unwrap().remove(0);
        plugin.commit = "master".into();
        assert!(validate(&plugin).is_err());
        let mut plugin = catalog().unwrap().remove(0);
        plugin.id = "volatility3.plugins".into();
        assert!(validate(&plugin).is_err());
    }

    #[test]
    fn files_are_checked_before_and_after_their_edits() {
        let file = PluginFile {
            from: "a.py".into(),
            to: "a.py".into(),
            size: 13,
            sha256: sha256(b"version=(2,0)"),
            edits: vec![Edit {
                find: "(2,0)".into(),
                replace: "(4,0)".into(),
            }],
            edited_sha256: Some(sha256(b"version=(4,0)")),
        };
        let plugin = CommunityPlugin {
            id: "t".into(),
            name: "t".into(),
            author: "t".into(),
            license: "MIT".into(),
            os: Os::Linux,
            summary: String::new(),
            requires: Vec::new(),
            repo: "https://github.com/a/b".into(),
            commit: "0".repeat(40),
            files: vec![file.clone()],
            tested: String::new(),
            caveats: Vec::new(),
        };
        assert_eq!(
            checked(&plugin, &file, b"version=(2,0)".to_vec()).unwrap(),
            b"version=(4,0)"
        );
        assert!(checked(&plugin, &file, b"version=(3,0)".to_vec()).is_err());
        let mut wrong = file.clone();
        wrong.edited_sha256 = Some(sha256(b"other"));
        assert!(checked(&plugin, &wrong, b"version=(2,0)".to_vec()).is_err());
    }

    #[test]
    fn installed_plugins_are_listed_and_removed() {
        let dir = temp("installed");
        let plugin = catalog().unwrap().remove(0);
        let folder = dir.join(&plugin.id);
        fs::create_dir_all(folder.join("symbols")).unwrap();
        fs::write(
            folder.join(MANIFEST_FILE),
            serde_json::to_vec(&plugin).unwrap(),
        )
        .unwrap();
        // A hand-made folder without a manifest is not the catalog's.
        fs::create_dir_all(dir.join("mine")).unwrap();
        let found = installed(&dir);
        assert_eq!(found.len(), 1);
        assert!(!found[0].outdated(&catalog().unwrap()));
        assert_eq!(symbol_dirs(&dir), vec![folder.join("symbols")]);
        assert!(remove(&dir, "mine").is_err());
        remove(&dir, &plugin.id).unwrap();
        assert!(installed(&dir).is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
