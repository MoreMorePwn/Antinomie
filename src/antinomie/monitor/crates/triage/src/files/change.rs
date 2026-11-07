// SPDX-License-Identifier: GPL-3.0-only
//! What one changed file knows about itself: its diff, steps, names and hashes.
use super::*;

impl Change {
    pub(super) fn diff_count(&self) -> usize {
        if let Some(count) = self.known_diff_count {
            return count;
        }
        bytes::merged(&self.original, &self.final_data)
            .filter(|(offset, before, after)| self.byte_diff(*offset, *before, *after))
            .count()
    }
    pub(super) fn byte_diff(&self, offset: u64, before: Option<&u8>, after: Option<&u8>) -> bool {
        match (before, after) {
            (Some(a), Some(b)) => a != b,
            (None, Some(_)) => self.original_size.is_some_and(|size| offset >= size),
            (Some(_), None) => self.final_size.is_some_and(|size| offset >= size),
            _ => false,
        }
    }
    /// Bytes of the file held, before and after.
    pub(super) fn stored(&self) -> usize {
        self.original.len() + self.final_data.len()
    }
    /// Whether anything is known to be missing from what was rebuilt.
    pub(super) fn has_gaps(&self) -> bool {
        !self.gaps.is_empty() || self.limit_hit.is_some() || self.short_capture.is_some()
    }
    /// Whether the file has a change the kernel accepted, or one with no exit.
    pub fn real(&self) -> bool {
        self.changes
    }
    /// A write, cut, copy into the file or shared mapping of it succeeded.
    pub(super) fn wrote(&self) -> bool {
        ["Written", "Truncated / resized", "Copied", "Mapped"]
            .iter()
            .any(|name| self.categories.contains(name))
    }
    /// The file was there before the run opened it with `O_CREAT`: it was not
    /// created. Drops the inferred creation, and the change if nothing else
    /// changed the file.
    pub(super) fn settle(&mut self) {
        let Some(size) = self.existed else { return };
        self.categories.remove("Created");
        for (label, _) in &mut self.lifecycle {
            if label.starts_with("created") {
                *label = format!("opened with O_CREAT; already existed ({size} bytes)");
            }
        }
        let other = self.categories.iter().any(|name| {
            !matches!(
                *name,
                "Opened" | "Read" | "Probed" | "Directory listing" | "Watched / locked"
            )
        });
        if !other && !self.deleted && !self.modified {
            self.changes = false;
        }
    }
    pub(super) fn step(&mut self, label: String) {
        if let Some((last, count)) = self.lifecycle.last_mut() {
            if *last == label {
                *count += 1;
                return;
            }
        }
        if self.lifecycle.len() < LIFECYCLE_STEPS {
            self.lifecycle.push((label, 1));
        } else {
            self.lifecycle_cut = true;
        }
    }
    /// "created → written 3× → chmod +x → executed → deleted"
    pub fn lifecycle_text(&self) -> String {
        let mut text = self
            .lifecycle
            .iter()
            .map(|(label, count)| {
                if *count > 1 {
                    format!("{label} {count}×")
                } else {
                    label.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" → ");
        if self.lifecycle_cut {
            text.push_str(" → …");
        }
        if text.is_empty() {
            text = if self.changes {
                "changed".into()
            } else {
                "no change".into()
            };
        }
        if self.failed > 0 {
            text.push_str(&format!(
                " · {} failed attempt{} not counted",
                self.failed,
                if self.failed == 1 { "" } else { "s" }
            ));
        }
        text
    }
    /// Record what the guest said about the file this change describes: its
    /// identity, how many links it has left and a new name for it.
    pub(super) fn note_identity(&mut self, id: FileId, name: Option<&str>) {
        self.identity.get_or_insert(id.key);
        if !matches!(id.kind, FileIdKind::Issue | FileIdKind::Exec) {
            self.links = Some(id.nlink);
        }
        if let (false, Some(name)) = (self.path_known, name) {
            self.path = name.to_owned();
            self.path_known = true;
            self.gaps.remove(PATH_GAP);
        }
    }
    /// The guest hashed the file: it says what the file held then, or why it
    /// has no digest.
    pub(super) fn record_hash(&mut self, hash: FileHash) {
        let wrote = self.wrote();
        if hash.kind == HashKind::Write
            && !wrote
            && self.categories.contains("Created")
            && !self.create_certain
            && hash.size > 0
        {
            self.existed = Some(hash.size);
        }
        let moment = match hash.kind {
            HashKind::Delete => "hashed before delete",
            _ if !wrote => "closed, nothing written",
            _ => "closed after write",
        };
        let what = match (hash.sha256_hex(), hash.skipped()) {
            (Some(hex), None) => format!("SHA-256 {}…", &hex[..12]),
            (_, Some(why)) => antinomie_monitor_core::ioc::no_hash_text(&why),
            (None, None) => "no hash".to_owned(),
        };
        self.step(format!("{moment} · {what}"));
        self.hash = Some(hash);
    }
    /// A transport reconnect lies between this file's last operation and the
    /// next: the recording continues in another segment.
    pub(super) fn cross_segment(&mut self, segment: usize, operation_count: &mut usize) {
        if segment <= self.segment {
            return;
        }
        self.segment = segment;
        self.step("reconnected".into());
        if self.operations.len() < TIMELINE_ROWS && *operation_count < TOTAL_OPERATIONS {
            self.operations.push(Operation {
                time: 0,
                call: 0,
                key: (0, 0, 0),
                name: format!("transport reconnected · recording segment {}", segment + 1),
                process: String::new(),
                result: String::new(),
            });
            *operation_count += 1;
        }
    }
    /// A name the file was reached by that no rename or link of the run gave it.
    pub(super) fn alias(&mut self, name: String) {
        if name != self.path && !self.names.contains(&name) && self.names.len() < 16 {
            self.step(format!("also seen as {name}"));
            self.names.push(name);
        }
    }
    /// A name the file was given by a rename or a hard link.
    pub(super) fn add_name(&mut self, name: &str) {
        if name != self.path
            && !self.names.iter().any(|known| known == name)
            && self.names.len() < 16
        {
            self.names.push(name.to_owned());
        }
    }
    /// "3 writes · 4.1 KiB": the calls that wrote and the octets that differ
    /// from the file's first known content; "partial" when the run did not see
    /// all of it.
    pub(super) fn count_label(&self) -> String {
        let writes = self
            .operations
            .iter()
            .filter(|op| op.name.starts_with("write") || op.name.starts_with("pwrite"))
            .count();
        let differing = self.diff_count();
        let mut parts = Vec::new();
        match writes {
            0 => {}
            1 => parts.push("1 write".to_owned()),
            count => parts.push(format!("{count} writes")),
        }
        if differing > 0 {
            parts.push(file_shown::size_text(differing as u64));
        }
        if parts.is_empty() {
            parts.push("no content change".to_owned());
        }
        if !(self.original_size.is_some() && self.final_size.is_some() && !self.has_gaps()) {
            parts.push("partial".to_owned());
        }
        parts.join(" \u{b7} ")
    }
    /// The octets the run captured from the start of the file, for its type.
    pub(super) fn head(&self) -> Vec<u8> {
        let from = |store: &ByteStore| {
            let mut head = Vec::new();
            for (at, byte) in store.iter() {
                if at != head.len() as u64 || head.len() == file_type::HEAD {
                    break;
                }
                head.push(*byte);
            }
            head
        };
        let head = from(&self.final_data);
        if head.is_empty() {
            from(&self.original)
        } else {
            head
        }
    }
    pub fn evidence_key(&self) -> String {
        evidence_key(&self.row(None))
    }
}
