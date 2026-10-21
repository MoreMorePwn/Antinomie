// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The guest's user and group names, found without running anything in the
//! guest.
//!
//! Source: the `/etc/passwd` and `/etc/group` of the installed base a run's
//! disk came from (`disk_base_identity` in the run's manifest), read on the
//! host by the sandboxed disk reader straight out of the base's qcow2 file,
//! plus the account the app itself provisioned into a VM (`guest-account.json`,
//! uid and gid 1000). The base is immutable and verified at install, the read
//! never touches the VM's own disk while it runs, and the guest never sees it.
//! A recording's reads of `/etc/passwd` were not chosen: a run has them only
//! when the program happened to look a name up, and they show the file as the
//! program read it, which the program can arrange.
//!
//! What this cannot know: users the guest created after the base was built
//! (by an earlier run, a person at the console or the sample itself). Their
//! ids have no name here and stay numeric, as does every id when the base
//! cannot be read.
use crate::api::BackendOptions;
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Largest `/etc/passwd` or `/etc/group` read.
const FILE_MAX_SIZE: u64 = 1024 * 1024;
/// Most names kept from one file.
const ENTRIES_MAX_COUNT: usize = 65_536;
/// Longest name kept; longer ones are not names a system tool would print.
const NAME_MAX_LEN: usize = 64;
/// Names read for the bases of this process, by base image.
const CACHE_MAX_COUNT: usize = 16;
/// The uid and gid the app gives the account it provisions.
const PROVISIONED_ID: u32 = 1000;

/// User and group names by id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuestNames {
    users: BTreeMap<u32, String>,
    groups: BTreeMap<u32, String>,
}

/// One `name:x:id:...` line: the name and the id in the third field.
fn entry(line: &[u8]) -> Option<(u32, String)> {
    let mut fields = line.split(|&byte| byte == b':');
    let name = fields.next()?;
    let id = fields.nth(1)?;
    if name.is_empty()
        || name.len() > NAME_MAX_LEN
        || !name
            .iter()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
    {
        return None;
    }
    let id: u32 = std::str::from_utf8(id).ok()?.parse().ok()?;
    Some((id, String::from_utf8(name.to_vec()).ok()?))
}

/// The names of a passwd or group file. The first line for an id wins, as
/// `getpwuid` and `getgrgid` find it.
fn parse(file: &[u8]) -> BTreeMap<u32, String> {
    let mut names = BTreeMap::new();
    for line in file.split(|&byte| byte == b'\n') {
        if names.len() >= ENTRIES_MAX_COUNT {
            break;
        }
        if line.starts_with(b"#") || line.starts_with(b"+") || line.starts_with(b"-") {
            continue;
        }
        if let Some((id, name)) = entry(line) {
            names.entry(id).or_insert(name);
        }
    }
    names
}

impl GuestNames {
    /// The names of `passwd` and `group` file contents.
    pub fn from_files(passwd: &[u8], group: &[u8]) -> Self {
        Self {
            users: parse(passwd),
            groups: parse(group),
        }
    }

    /// The name of user `uid`.
    pub fn user(&self, uid: u32) -> Option<&str> {
        self.users.get(&uid).map(String::as_str)
    }

    /// The name of group `gid`.
    pub fn group(&self, gid: u32) -> Option<&str> {
        self.groups.get(&gid).map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty() && self.groups.is_empty()
    }

    /// The account the app provisioned into the VM: user and group 1000 with
    /// its name, unless the base already names that id.
    fn with_account(mut self, username: &str) -> Self {
        self.users
            .entry(PROVISIONED_ID)
            .or_insert_with(|| username.to_owned());
        self.groups
            .entry(PROVISIONED_ID)
            .or_insert_with(|| username.to_owned());
        self
    }
}

/// Read `/etc/passwd` and `/etc/group` out of the base image `image` with the
/// sandboxed reader (`executable`: the program that serves `--disk-reader`;
/// `None` for this one). A missing file reads as empty.
pub fn read_base(image: &Path, executable: Option<PathBuf>) -> Result<GuestNames, String> {
    use crate::disks::reader::{DiskAnswer, DiskRequest, ReadError, Reader};
    let scratch = std::env::temp_dir().join(format!(
        "antinomie-guest-names-{}-{}",
        std::process::id(),
        crate::storage::unique_id()
    ));
    let result = (|| {
        let mut reader = match executable {
            Some(executable) => Reader::with_executable(executable, image, &scratch)?,
            None => Reader::open(image, &scratch)?,
        };
        let mut files = Vec::new();
        for path in ["/etc/passwd", "/etc/group"] {
            let answer = reader.request(DiskRequest::Extract {
                path: path.into(),
                max_len: FILE_MAX_SIZE,
            })?;
            let bytes = match answer {
                Ok(DiskAnswer::Extracted(_)) => {
                    let out = scratch.join(reader.last_request_id().to_string());
                    let bytes = std::fs::read(&out).map_err(|error| error.to_string())?;
                    let _ = std::fs::remove_file(&out);
                    bytes
                }
                Err(ReadError::NotFound) => Vec::new(),
                Err(error) => return Err(format!("{path}: {error}")),
                Ok(other) => return Err(format!("{path}: unexpected answer {other:?}")),
            };
            files.push(bytes);
        }
        Ok(GuestNames::from_files(&files[0], &files[1]))
    })();
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

type CacheKey = (PathBuf, u64, i64, Option<String>);

fn cache() -> &'static Mutex<HashMap<CacheKey, Arc<GuestNames>>> {
    static CACHE: std::sync::OnceLock<Mutex<HashMap<CacheKey, Arc<GuestNames>>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

/// The names for a run of VM `vm_id` recorded in `run_directory`: from the
/// base its disk came from and the account the app provisioned. `None` when
/// the base is not installed any more or does not say.
pub fn for_run(
    data_dir: &Path,
    vm_id: &str,
    run_directory: &Path,
) -> Result<Option<Arc<GuestNames>>, String> {
    let options = BackendOptions {
        data_dir: data_dir.to_path_buf(),
        ..Default::default()
    };
    let manifest: serde_json::Value =
        crate::storage::read_json(&run_directory.join("manifest.json"))
            .map_err(|error| format!("run manifest: {error}"))?;
    let Some(identity) = manifest
        .get("disk_base_identity")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };
    let Some(base) = crate::locations::installed_bases(&options)?
        .into_iter()
        .find(|base| base.id == identity)
    else {
        return Ok(None);
    };
    let image = crate::storage::Bundle::load(&base.directory)?.base_disk;
    let account = crate::locations::disk_directory(&options, vm_id)
        .ok()
        .flatten()
        .and_then(|directory| crate::guest_account::GuestAccount::load(&directory).ok())
        .map(|account| account.username().to_owned());
    let metadata = std::fs::metadata(&image).map_err(|error| error.to_string())?;
    let key = (
        image.clone(),
        metadata.len(),
        std::os::unix::fs::MetadataExt::mtime(&metadata),
        account.clone(),
    );
    if let Some(names) = cache().lock().map_err(|_| "names cache")?.get(&key) {
        return Ok(Some(Arc::clone(names)));
    }
    let mut names = read_base(&image, None)?;
    if let Some(account) = &account {
        names = names.with_account(account);
    }
    let names = Arc::new(names);
    let mut cache = cache().lock().map_err(|_| "names cache")?;
    if cache.len() >= CACHE_MAX_COUNT {
        cache.clear();
    }
    cache.insert(key, Arc::clone(&names));
    Ok(Some(names))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_come_from_the_files_and_the_first_line_for_an_id_wins() {
        let names = GuestNames::from_files(
            b"root:x:0:0:root:/root:/bin/sh\n# comment\ndaemon:x:1:1::/:/bin/false\n\
              toor:x:0:0::/:/bin/sh\nbad name:x:5:5::/:\nlong:x:notanumber:1::/:\n\
              +nis:x:7:7::/:\nanalyst:x:1000:1000::/home/analyst:/bin/sh",
            b"root:x:0:\nwheel:x:10:analyst\n",
        );
        assert_eq!(names.user(0), Some("root"));
        assert_eq!(names.user(1), Some("daemon"));
        assert_eq!(names.user(1000), Some("analyst"));
        assert_eq!(names.user(5), None);
        assert_eq!(names.user(7), None);
        assert_eq!(names.user(4242), None);
        assert_eq!(names.group(10), Some("wheel"));
        assert_eq!(names.group(1000), None);
        // The provisioned account names id 1000 only where the base does not.
        let names = names.with_account("lab");
        assert_eq!(names.user(1000), Some("analyst"));
        assert_eq!(names.group(1000), Some("lab"));
        assert!(GuestNames::from_files(b"", b"").is_empty());
    }

    #[test]
    fn names_that_would_break_a_record_are_not_names() {
        let names = GuestNames::from_files(
            b"a\"b:x:3:3::/:\nc\\d:x:4:4::/:\n\xff:x:6:6::/:\nok:x:8:8::/:\n",
            b"",
        );
        assert_eq!(
            (names.user(3), names.user(4), names.user(6), names.user(8)),
            (None, None, None, Some("ok"))
        );
        let long = format!("{}:x:9:9::/:\n", "n".repeat(NAME_MAX_LEN + 1));
        assert_eq!(GuestNames::from_files(long.as_bytes(), b"").user(9), None);
    }
}
