// SPDX-License-Identifier: GPL-3.0-only
//! How much of a file's bytes the Changed files rebuild keeps, and what it
//! says when a call's bytes did not all make it in.
use super::bytes::ByteStore;
use super::Change;
use crate::trace;

const MIB: usize = 1 << 20;
/// Most bytes of a transfer held at once while they are placed: a call's
/// buffer is placed in pieces this size, not copied whole.
const STORE_STEP: usize = 65_536;

/// The caps on the bytes rebuilt, in bytes: per file, and over every file of a
/// run's view. Settings > Analysis limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::triage) struct Retention {
    pub per_file: usize,
    pub per_run: usize,
}

pub(in crate::triage) const DEFAULT_FILE_MIB: u32 = 16;
pub(in crate::triage) const DEFAULT_RUN_MIB: u32 = 256;

impl Default for Retention {
    fn default() -> Self {
        Self::from_mib(DEFAULT_FILE_MIB, DEFAULT_RUN_MIB)
    }
}

impl Retention {
    pub(in crate::triage) fn from_mib(file: u32, run: u32) -> Self {
        Self {
            per_file: file as usize * MIB,
            per_run: run as usize * MIB,
        }
    }
}

/// The bytes the run's files hold so far, against the caps, and the call that
/// is being applied.
pub(super) struct Budget<'a> {
    pub used: &'a mut usize,
    pub retention: Retention,
    pub call: trace::InvocationKey,
}

/// Which cap stopped the rebuild, and where.
#[derive(Clone, Copy, Debug)]
pub(super) struct LimitHit {
    pub run_wide: bool,
    pub call: trace::InvocationKey,
    pub kept: usize,
    pub cap: usize,
}

/// A call whose captured buffer held fewer bytes than the call moved.
#[derive(Clone, Copy, Debug)]
pub(super) struct ShortCapture {
    pub what: &'static str,
    pub first: trace::InvocationKey,
    pub moved: u64,
    pub captured: u64,
    pub calls: u32,
}

/// One thing said about a file's rebuild, with where to go from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::triage) struct GapNote {
    pub text: String,
    /// The text is about a limit that Settings raises.
    pub limit: bool,
    /// The call whose syscall evidence has the rest.
    pub evidence: Option<trace::InvocationKey>,
}

impl GapNote {
    pub(in crate::triage) fn plain(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            limit: false,
            evidence: None,
        }
    }
}

impl Change {
    /// Put the bytes of a transfer at `offset` (relative offset, value) in the
    /// rebuilt file, within the caps. With `original`, bytes not known before
    /// are also the file's first known contents.
    pub(super) fn store(
        &mut self,
        offset: u64,
        bytes: impl Iterator<Item = (u64, u8)>,
        original: bool,
        budget: &mut Budget<'_>,
    ) {
        let mut run: Vec<u8> = Vec::new();
        let mut start = 0u64;
        // One byte more than a file may keep is enough to know a cap was met.
        let most = budget.retention.per_file.saturating_add(1);
        for (relative, byte) in bytes.take(most) {
            let Some(at) = offset.checked_add(relative) else {
                break;
            };
            if !run.is_empty() && (start + run.len() as u64 != at || run.len() >= STORE_STEP) {
                if !self.store_run(start, &run, original, budget) {
                    return;
                }
                run.clear();
            }
            if run.is_empty() {
                start = at;
            }
            run.push(byte);
        }
        if !run.is_empty() {
            self.store_run(start, &run, original, budget);
        }
    }

    /// Whether all of `run` was kept; once a cap cuts it, nothing more fits.
    fn store_run(
        &mut self,
        start: u64,
        run: &[u8],
        original: bool,
        budget: &mut Budget<'_>,
    ) -> bool {
        let room_file = budget
            .retention
            .per_file
            .saturating_sub(self.final_data.len());
        let room_run = budget.retention.per_run.saturating_sub(*budget.used);
        let room = room_file.min(room_run);
        let kept = run.len().min(room);
        if kept < run.len() && self.limit_hit.is_none() {
            let run_wide = room_run <= room_file;
            self.limit_hit = Some(LimitHit {
                run_wide,
                call: budget.call,
                kept: if run_wide {
                    *budget.used
                } else {
                    self.final_data.len()
                },
                cap: if run_wide {
                    budget.retention.per_run
                } else {
                    budget.retention.per_file
                },
            });
        }
        let whole = kept == run.len();
        let run = &run[..kept];
        if run.is_empty() {
            return whole;
        }
        if original {
            for (from, to) in self.original.unknown_in(start, start + run.len() as u64) {
                let part = &run[(from - start) as usize..(to - start) as usize];
                *budget.used += self.original.put(from, part);
            }
        }
        *budget.used += self.final_data.put(start, run);
        whole
    }

    /// A call (`what`: "write", "read"...) moved `moved` bytes and the
    /// recording captured `captured` of its buffer.
    pub(super) fn note_short_capture(
        &mut self,
        what: &'static str,
        call: trace::InvocationKey,
        moved: u64,
        captured: u64,
    ) {
        match &mut self.short_capture {
            Some(known) => known.calls += 1,
            None => {
                self.short_capture = Some(ShortCapture {
                    what,
                    first: call,
                    moved,
                    captured,
                    calls: 1,
                });
            }
        }
    }

    /// Everything said about what is missing from this file's rebuild.
    pub(super) fn gap_notes(&self) -> Vec<GapNote> {
        let mut notes: Vec<GapNote> = self.gaps.iter().map(|gap| GapNote::plain(gap)).collect();
        if let Some(hit) = &self.limit_hit {
            let (which, setting) = if hit.run_wide {
                (
                    "the limit on all files together",
                    "Rebuilt file bytes per run",
                )
            } else {
                ("the limit per file", "Rebuilt file bytes per file")
            };
            notes.push(GapNote {
                text: format!(
                    "Byte reconstruction stopped at {which}: {} kept of {} allowed ({setting} in Settings > Analysis limits). \
                     The rest of this file's bytes are in the syscall evidence of the writes.",
                    crate::values::short_size(hit.kept as u64),
                    crate::values::short_size(hit.cap as u64)
                ),
                limit: true,
                evidence: Some(hit.call),
            });
        }
        if let Some(short) = &self.short_capture {
            let more = if short.calls > 1 {
                format!(" and {} more calls like it", short.calls - 1)
            } else {
                String::new()
            };
            let missing = short.moved.saturating_sub(short.captured);
            notes.push(GapNote {
                text: format!(
                    "This {} moved {} B, but the recording kept only {} B of its buffer ({} B were not recorded){more}. \
                     Those bytes are a gap in the rebuilt file; the call's own record shows what was kept.",
                    short.what,
                    crate::values::thousands(short.moved),
                    crate::values::thousands(short.captured),
                    crate::values::thousands(missing),
                ),
                limit: false,
                evidence: Some(short.first),
            });
        }
        notes
    }
}

impl ByteStore {
    /// The parts of `[from, to)` no run covers.
    pub fn unknown_in(&self, from: u64, to: u64) -> Vec<(u64, u64)> {
        let mut parts = Vec::new();
        let mut at = from;
        for (start, end) in self.spans_in(from, to) {
            if start > at {
                parts.push((at, start));
            }
            at = at.max(end);
        }
        if at < to {
            parts.push((at, to));
        }
        parts
    }
}
