// SPDX-License-Identifier: GPL-3.0-only
//! A changed file as the IOC window lists it: its path, what happened to it
//! and the SHA-256 the guest took of it when the last writer closed it or just
//! before it was deleted.
use super::*;

/// What the IOC window needs of one changed file.
pub struct IocFile {
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
    pub fn ioc_file(&self) -> Option<IocFile> {
        if !self.path_known || !self.path.starts_with('/') || self.standard_io {
            return None;
        }
        let mut roles = Vec::new();
        let has = |label: &str| self.categories.iter().any(|name| name.starts_with(label));
        if has("Created") {
            roles.push("created");
        }
        // The guest hashes a file when its last writer closes it, written or
        // not: the role needs a write, cut, copy or shared mapping as well.
        if self.wrote()
            && self
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
            // The guest hashes a file when its last writer closes it (or just
            // before it is deleted). A written file with no record was still
            // open for writing when the run ended; an empty one has no digest.
            None if !self.deleted && self.final_size == Some(0) => (
                None,
                Some(antinomie_monitor_core::ioc::EMPTY_FILE.to_owned()),
            ),
            None if !self.deleted => (
                None,
                Some("still open at run end (the guest hashes a file when it is closed)".into()),
            ),
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

impl Change {
    /// The file as the Samples window lists the files a sample wrote, or
    /// `None` for one the run did not change or with no usable path.
    pub fn written_file(
        &self,
    ) -> Option<antinomie_monitor_core::run_digest::WrittenFile> {
        if !self.changes || !self.path_known || !self.path.starts_with('/') || self.standard_io {
            return None;
        }
        let created = self
            .categories
            .iter()
            .any(|name| name.starts_with("Created"));
        let state = if self.deleted {
            "deleted".to_owned()
        } else if let Some(name) = self.names.last().filter(|name| **name != self.path) {
            format!("renamed to {name}")
        } else if created {
            "written".to_owned()
        } else {
            "rewritten".to_owned()
        };
        let ioc = self.ioc_file()?;
        Some(antinomie_monitor_core::run_digest::WrittenFile {
            path: self.path.clone(),
            state,
            size: if self.deleted { None } else { self.final_size },
            sha256: ioc.sha256.unwrap_or_default(),
            hash_note: ioc.why.unwrap_or_default(),
        })
    }
}
