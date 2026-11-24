// SPDX-License-Identifier: GPL-3.0-only
//! Rows of the Files and Process tables, made once per index.
//!
//! A frame used to copy every row of the table in view (twice for the Files
//! tabs: once to write the time, once to cut the columns and add the tags),
//! which is most of what such a frame costs with a few thousand rows. The
//! rows are a function of the index, the tab and the clock, and the index
//! never changes once the view holds it, so they are kept until the view
//! gets another one. Nothing else goes into them: the filter bar, the sort
//! and the selection act on the rows after this, as before.
use super::*;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

pub(super) type Rows = Arc<Vec<Vec<Cell>>>;

type Clock = Option<antinomie_monitor_core::HostClockAnchor>;

/// The index the kept rows were made from: the view's count of the indexes it
/// has held, and where this one lives.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Source {
    serial: u64,
    scan: usize,
}

/// The rows of one Files tab: with the time written (not for Changed, whose
/// rows are the index's own) and as the table draws them.
pub(super) struct FileRows {
    clock: Clock,
    pub raw: Option<Rows>,
    pub shown: Rows,
}

/// The Process tree's rows for the Show threads choice it was made for.
pub(super) struct ProcessRows {
    clock: Clock,
    expanded: bool,
    pub rows: Rows,
}

#[derive(Default)]
pub(super) struct ShownCache {
    source: Option<Source>,
    files: HashMap<usize, FileRows>,
    process: Option<ProcessRows>,
}

impl ShownCache {
    /// Keep the rows only while the view holds the index they came from.
    pub(super) fn bind(&mut self, serial: u64, scan: &antinomie_triage::ArchiveScan) {
        let source = Source {
            serial,
            scan: Arc::as_ptr(&scan.0) as usize,
        };
        if self.source != Some(source) {
            *self = Self::default();
            self.source = Some(source);
        }
    }

    /// What a sort can rely on to know the rows are the same ones: the index,
    /// the table and the clock, as one number.
    pub(super) fn stamp(&self, table: &str, clock: Clock) -> Option<u64> {
        let source = self.source?;
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        (source.serial, source.scan, table).hash(&mut hash);
        clock.map(|anchor| format!("{anchor:?}")).hash(&mut hash);
        Some(hash.finish())
    }

    pub(super) fn files(&self, slot: usize, clock: Clock) -> Option<&FileRows> {
        self.files.get(&slot).filter(|rows| rows.clock == clock)
    }

    pub(super) fn keep_files(&mut self, slot: usize, clock: Clock, raw: Option<Rows>, shown: Rows) {
        self.files.insert(slot, FileRows { clock, raw, shown });
    }

    pub(super) fn process(&self, clock: Clock, expanded: bool) -> Option<&Rows> {
        self.process
            .as_ref()
            .filter(|kept| kept.clock == clock && kept.expanded == expanded)
            .map(|kept| &kept.rows)
    }

    pub(super) fn keep_process(&mut self, clock: Clock, expanded: bool, rows: Rows) {
        self.process = Some(ProcessRows {
            clock,
            expanded,
            rows,
        });
    }
}
