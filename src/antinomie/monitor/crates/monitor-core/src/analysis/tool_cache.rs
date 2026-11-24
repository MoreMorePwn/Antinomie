// SPDX-License-Identifier: GPL-3.0-only
//! What the analysis tools keep from one job to the next (ANT-T0618, AN-17).
//!
//! Every job started capa by unpacking its 1,368 rule files into the
//! sandbox's `/tmp` (0.3 s) and by asking each tool for its `--version` in a
//! process of its own (capa's and FLOSS's PyInstaller launchers take about
//! 2 s for it). Both are the same for every job, so:
//!
//! - the host unpacks the bundled capa rules once into
//!   `<data>/cache/capa-rules/<release>-<digest>/`, keyed by the archive's
//!   own SHA-256, and the sandbox mounts that folder read-only;
//! - a tool's `--version` first line is kept in `<data>/cache/versions/`,
//!   named by the tool's path, arguments, size, modification time and inode,
//!   so a new build of the tool is asked again. The folder is mounted
//!   writable, like capa's compiled-rule cache; a damaged or odd entry is
//!   ignored and asked again.
//!
//! Neither changes what a tool finds: the rules are the same bytes and a
//! version line is the tool's own answer.
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

/// Where the sandbox mounts the version cache.
pub(super) const VERSIONS_MOUNT: &str = "/cache/versions";
/// Where the sandbox mounts the unpacked capa rules, read-only.
pub(super) const CAPA_RULES_MOUNT: &str = "/cache/capa-rules";
/// The cache is emptied when it holds more entries than this.
const VERSION_ENTRIES_MAX: usize = 512;
/// A version line longer than this, or with a control character, is not kept.
const VERSION_MAX_LEN: usize = 200;

fn root(tools: Option<&Path>) -> Option<PathBuf> {
    Some(tools?.parent()?.join("cache"))
}

/// Mount the caches into the sandbox `cmd` builds: the version cache for every
/// job, the unpacked capa rules for one that runs capa.
pub(super) fn mount(cmd: &mut Command, tools: Option<&Path>, capa: bool) {
    let Some(root) = root(tools) else {
        return;
    };
    let versions = root.join("versions");
    if crate::storage::private_dir(&versions).is_ok() {
        if fs::read_dir(&versions).is_ok_and(|entries| entries.count() > VERSION_ENTRIES_MAX) {
            let _ = fs::remove_dir_all(&versions);
            let _ = crate::storage::private_dir(&versions);
        }
        cmd.arg("--bind").arg(&versions).arg(VERSIONS_MOUNT);
    }
    if capa && let Some(rules) = capa_rules(&root) {
        cmd.arg("--ro-bind").arg(rules).arg(CAPA_RULES_MOUNT);
    }
}

/// The unpacked bundled capa rules, unpacked now when they are not yet.
/// `None` when they cannot be (the sandbox then unpacks them itself).
fn capa_rules(root: &Path) -> Option<PathBuf> {
    static DIGEST: OnceLock<String> = OnceLock::new();
    let digest =
        DIGEST.get_or_init(|| format!("{:x}", Sha256::digest(super::capa::RULES))[..16].to_owned());
    let name = format!("{}-{digest}", super::capa::RULES_RELEASE.replace(' ', "-"));
    let base = root.join("capa-rules");
    let folder = base.join(&name);
    let rules = folder.join("capa-rules");
    if folder.join(".complete").is_file() && rules.is_dir() {
        return Some(rules);
    }
    crate::storage::private_dir(&base).ok()?;
    let staging = base.join(format!(".unpack-{}", crate::storage::unique_id()));
    let unpacked = (|| -> std::io::Result<()> {
        crate::storage::private_dir(&staging)?;
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(super::capa::RULES));
        archive.set_preserve_permissions(false);
        archive.unpack(&staging)?;
        if !staging.join("capa-rules").is_dir() {
            return Err(std::io::Error::other(
                "the rules archive has no capa-rules folder",
            ));
        }
        fs::write(staging.join(".complete"), b"ok")?;
        // Read-only for everyone: the sandbox never writes here.
        make_read_only(&staging.join("capa-rules"))
    })();
    if unpacked.is_ok() && folder.exists() && !folder.join(".complete").is_file() {
        // What an earlier unpack left unfinished is replaced.
        let _ = remove_tree(&folder);
    }
    if unpacked.is_err() || fs::rename(&staging, &folder).is_err() {
        // Another job may have unpacked at the same time: use theirs.
        let _ = remove_tree(&staging);
        if folder.join(".complete").is_file() && rules.is_dir() {
            return Some(rules);
        }
        return None;
    }
    // Rules of an older release stay as they are for jobs still using them;
    // the next release's job removes them.
    forget_other_releases(&base, &name);
    Some(rules)
}

fn make_read_only(path: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            make_read_only(&entry.path())?;
        } else {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o444))?;
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o555))
}

/// Remove a tree made read-only by [`make_read_only`].
fn remove_tree(path: &Path) -> std::io::Result<()> {
    fn open_up(path: &Path) {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        for entry in fs::read_dir(path).into_iter().flatten().flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                open_up(&entry.path());
            }
        }
    }
    open_up(path);
    fs::remove_dir_all(path)
}

fn forget_other_releases(base: &Path, keep: &str) {
    for entry in fs::read_dir(base).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name != keep && !name.starts_with(".unpack-") {
            let _ = remove_tree(&entry.path());
        }
    }
}

/// The key of a tool's version answer: the tool and what it was asked, and
/// the file it is (size, modification time, inode).
fn version_key(path: &str, args: &[&str]) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    let mut hash = Sha256::new();
    hash.update(path.as_bytes());
    for arg in args {
        hash.update([0]);
        hash.update(arg.as_bytes());
    }
    hash.update(format!(
        "\0{}:{}:{}",
        meta.len(),
        meta.mtime_nsec(),
        meta.mtime()
    ));
    hash.update(format!(":{}", meta.ino()));
    Some(format!("{:x}", hash.finalize())[..32].to_owned())
}

fn version_file(path: &str, args: &[&str]) -> Option<PathBuf> {
    let folder = Path::new(VERSIONS_MOUNT);
    folder.is_dir().then_some(())?;
    Some(folder.join(version_key(path, args)?))
}

/// The version line kept for `path`, when it is there and plain.
pub(super) fn kept_version(path: &str, args: &[&str]) -> Option<String> {
    let mut text = String::new();
    fs::File::open(version_file(path, args)?)
        .ok()?
        .take(VERSION_MAX_LEN as u64 + 1)
        .read_to_string(&mut text)
        .ok()?;
    plain(text.trim_end_matches('\n'))
}

/// Keep `line`, the version `path` printed. A failure to write costs nothing.
pub(super) fn keep_version(path: &str, args: &[&str], line: &str) {
    let (Some(file), Some(line)) = (version_file(path, args), plain(line)) else {
        return;
    };
    let temporary = file.with_extension(format!("{}", std::process::id()));
    if fs::write(&temporary, line.as_bytes()).is_ok() && fs::rename(&temporary, &file).is_err() {
        let _ = fs::remove_file(&temporary);
    }
}

fn plain(line: &str) -> Option<String> {
    (!line.is_empty() && line.len() <= VERSION_MAX_LEN && !line.chars().any(char::is_control))
        .then(|| line.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ant-tool-cache-{name}-{}",
            crate::storage::unique_id()
        ))
    }

    #[test]
    fn the_bundled_capa_rules_are_unpacked_once_and_read_only() {
        let root = temp("rules");
        let first = capa_rules(&root).expect("rules unpacked");
        assert!(first.join("LICENSE.txt").is_file());
        assert!(
            fs::metadata(first.join("LICENSE.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o222
                == 0
        );
        let stamp = fs::metadata(first.join("LICENSE.txt"))
            .unwrap()
            .modified()
            .unwrap();
        // The second job finds them and unpacks nothing.
        let second = capa_rules(&root).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            fs::metadata(second.join("LICENSE.txt"))
                .unwrap()
                .modified()
                .unwrap(),
            stamp
        );
        // The tree is the archive's: every rule file is there.
        let mut files = 0;
        let mut pending = vec![first.clone()];
        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(dir).unwrap().flatten() {
                if entry.file_type().unwrap().is_dir() {
                    pending.push(entry.path());
                } else {
                    files += 1;
                }
            }
        }
        assert_eq!(files, 1045);
        // An unpack that never finished is not trusted.
        let name = first.parent().unwrap().to_owned();
        fs::remove_file(name.join(".complete")).unwrap();
        let again = capa_rules(&root).expect("unpacked again");
        assert!(again.join("LICENSE.txt").is_file());
        assert!(name.join(".complete").is_file());
        remove_tree(&root).unwrap();
    }

    #[test]
    fn a_version_line_is_kept_only_when_plain_and_by_the_file_it_came_from() {
        assert_eq!(plain("capa 9.4.0").as_deref(), Some("capa 9.4.0"));
        assert!(plain("").is_none());
        assert!(plain("bad\u{1b}[0m").is_none());
        assert!(plain(&"x".repeat(VERSION_MAX_LEN + 1)).is_none());
        let tool = temp("tool");
        fs::write(&tool, b"one").unwrap();
        let path = tool.to_str().unwrap();
        let first = version_key(path, &["--version"]).unwrap();
        assert_eq!(first, version_key(path, &["--version"]).unwrap());
        assert_ne!(first, version_key(path, &["-v"]).unwrap());
        fs::write(&tool, b"a longer build").unwrap();
        assert_ne!(first, version_key(path, &["--version"]).unwrap());
        assert!(version_key("/nonexistent/tool", &[]).is_none());
        let _ = fs::remove_file(tool);
    }
}
