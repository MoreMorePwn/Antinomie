// SPDX-License-Identifier: GPL-3.0-only
//! What a sample did in a run, as custody entries written by the sample: the
//! files it dropped (a copy of itself, or a file whose writer was the sample)
//! and a self-delete. Read from the run's Triage digest when the Samples page
//! indexes the run, by hash and path only, never from raw events. A run
//! whose digest does not exist yet has nothing to add; it is read again the
//! next time the page opens. An entry is written once: what the log already
//! holds for the run is skipped.
use super::{
    SeenRun,
    custody::CustodyEvent,
    library::{Library, now_ms},
};
use crate::run_digest::{LineageFile, RunDigest};
use std::{collections::BTreeSet, path::Path};

/// Most dropped-file entries one run adds to one sample's log.
const MAX_DROPPED: usize = 50;

fn has(file: &LineageFile, role: &str) -> bool {
    file.roles.iter().any(|known| known == role)
}

/// The activity lines the lineage shows for `sha256`, in a stable order.
pub(super) fn lines(sha256: &str, files: &[LineageFile]) -> Vec<String> {
    let own: BTreeSet<&str> = files
        .iter()
        .filter(|file| has(file, "sample") || file.sha256.eq_ignore_ascii_case(sha256))
        .filter(|file| !has(file, "created") && !has(file, "written at close"))
        .map(|file| file.path.as_str())
        .collect();
    let mut lines = Vec::new();
    for file in files {
        if own.contains(file.path.as_str()) && has(file, "deleted") {
            lines.push(format!("deleted itself ({})", file.path));
        }
    }
    let mut dropped = 0;
    for file in files {
        let wrote = has(file, "created") || has(file, "written at close");
        if !wrote || own.contains(file.path.as_str()) || file.sha256.is_empty() {
            continue;
        }
        let copy = file.sha256.eq_ignore_ascii_case(sha256);
        if !copy && !own.contains(file.writer.as_str()) {
            continue;
        }
        if dropped == MAX_DROPPED {
            break;
        }
        dropped += 1;
        lines.push(if copy {
            format!("dropped a copy of itself at {}", file.path)
        } else {
            format!("dropped {} (SHA-256 {})", file.path, file.sha256)
        });
    }
    lines
}

impl Library {
    /// Add what the run's digest shows the sample did. Returns how many
    /// entries were new.
    pub fn note_run_activity(&self, run: &SeenRun) -> Result<usize, String> {
        let Some(lineage) = RunDigest::read(Path::new(&run.directory)).and_then(|d| d.lineage)
        else {
            return Ok(0);
        };
        let sha256 = run.sha256.to_ascii_lowercase();
        let mut known = BTreeSet::new();
        let mut statement = self
            .connection
            .prepare("SELECT detail FROM custody_entry WHERE sha256=?1 AND kind='activity'")
            .map_err(|e| e.to_string())?;
        for detail in statement
            .query_map([&sha256], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?
        {
            known.insert(detail.map_err(|e| e.to_string())?);
        }
        let by = format!("sample (run {})", run.run_id);
        let mut added = 0;
        for line in lines(&sha256, &lineage.files) {
            let event = CustodyEvent::Activity {
                run: run.run_id.clone(),
                detail: line,
            };
            if known.contains(&event.stored()?) {
                continue;
            }
            self.record_at(&sha256, &by, now_ms(), &event)?;
            added += 1;
        }
        Ok(added)
    }
}
