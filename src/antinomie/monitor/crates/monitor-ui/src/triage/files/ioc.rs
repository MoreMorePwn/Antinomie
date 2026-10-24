// SPDX-License-Identifier: GPL-3.0-only
//! A changed file as the IOC window lists it: its path, what happened to it
//! and the SHA-256 the guest took of it when the last writer closed it or just
//! before it was deleted.
use super::*;

/// What the IOC window needs of one changed file.
pub(in crate::triage) struct IocFile {
    pub path: String,
    /// `created`, `written at close`, `changed`, `deleted`.
    pub roles: Vec<&'static str>,
    pub sha256: Option<String>,
    /// Why there is no hash, in the guest's words.
    pub why: Option<String>,
    pub pid: u32,
    pub image: Option<String>,
    pub stream: u64,
    pub cookie: u64,
    pub call_id: u64,
    pub time_ns: u64,
}

impl Change {
    /// The file for the IOC window, or `None` for one with no usable path.
    pub(in crate::triage) fn ioc_file(&self) -> Option<IocFile> {
        if !self.path_known || !self.path.starts_with('/') || self.standard_io {
            return None;
        }
        let mut roles = Vec::new();
        let has = |label: &str| self.categories.iter().any(|name| name.starts_with(label));
        if has("Created") {
            roles.push("created");
        }
        if self
            .hash
            .as_ref()
            .is_some_and(|hash| hash.kind == HashKind::Write)
        {
            roles.push("written at close");
        } else if has("Written") {
            roles.push("changed");
        }
        if self.deleted {
            roles.push("deleted");
        }
        if roles.is_empty() {
            roles.push("changed");
        }
        let (sha256, why) = match &self.hash {
            Some(hash) => {
                // A hash the guest could not take, or took of a script's
                // interpreter or a file that changed meanwhile, is not this file's.
                let why = hash.skipped();
                (why.is_none().then(|| hash.sha256_hex()).flatten(), why)
            }
            None => (None, None),
        };
        Some(IocFile {
            path: self.path.clone(),
            roles,
            sha256,
            why,
            pid: self.pid,
            image: self.process_image.clone(),
            stream: self.key.0,
            cookie: self.key.1,
            call_id: self.key.2,
            time_ns: self.first_ns,
        })
    }
}
