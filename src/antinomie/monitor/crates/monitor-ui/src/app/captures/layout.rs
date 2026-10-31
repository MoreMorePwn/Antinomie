// SPDX-License-Identifier: GPL-3.0-only
//! Tree order of a capture's processes, built once per change of the list.
//!
//! Building walks the list a few times and costs a hash lookup per process.
//! The panel keeps the result, checks it against a fingerprint of the list
//! each frame, and draws only the rows in view, so a frame costs the rows on
//! screen, not the processes in the run.
use crate::tree_lines::{Glyph, Prefix};
use antinomie_monitor_core::capture_processes::CaptureProcess;
use std::collections::{HashMap, HashSet};

const NONE: u32 = u32::MAX;

/// One row of the tree, in display order.
///
/// | Field | Meaning |
/// | --- | --- |
/// | `process` | Index into the process list |
/// | `depth` | 0 for a root |
/// | `parent` | Row of the parent, or `NONE` for a root |
/// | `last` | No later row of the same parent follows |
#[derive(Clone, Copy, Debug)]
pub(super) struct Row {
    pub process: u32,
    pub depth: u32,
    parent: u32,
    last: bool,
}

/// The rows of a process list in tree order (parents before children).
#[derive(Debug)]
pub(super) struct Layout {
    fingerprint: u64,
    pub rows: Vec<Row>,
    /// A cycle (PID reuse, incomplete ancestry) left a process with a known
    /// parent as a root.
    pub detached: bool,
}

/// Cheap digest of the part of the list that decides the tree: process IDs
/// and parents, in order.
pub(super) fn fingerprint(processes: &[CaptureProcess]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ processes.len() as u64;
    for process in processes {
        for word in [process.pid, process.parent_pid] {
            hash = (hash ^ u64::from(word)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

impl Layout {
    /// Rows for `processes`: parents first, children in list order. A
    /// cycle ends at a process already listed; leftover processes follow as
    /// roots.
    pub(super) fn build(processes: &[CaptureProcess]) -> Self {
        let known: HashSet<u32> = processes.iter().map(|p| p.pid).collect();
        // Children of each parent as a linked list in list order.
        let mut next = vec![NONE; processes.len()];
        let mut ends: HashMap<u32, (u32, u32)> = HashMap::new();
        let mut roots = Vec::new();
        for (index, process) in processes.iter().enumerate() {
            let index = index as u32;
            if process.parent_pid != 0
                && process.parent_pid != process.pid
                && known.contains(&process.parent_pid)
            {
                match ends.get_mut(&process.parent_pid) {
                    Some((_, tail)) => {
                        next[*tail as usize] = index;
                        *tail = index;
                    }
                    None => {
                        ends.insert(process.parent_pid, (index, index));
                    }
                }
            } else {
                roots.push(index);
            }
        }
        let mut rows: Vec<Row> = Vec::with_capacity(processes.len());
        let mut visited: HashSet<u32> = HashSet::with_capacity(processes.len());
        // (process, depth, parent row); the next to pop is last.
        let mut stack: Vec<(u32, u32, u32)> = roots.iter().rev().map(|r| (*r, 0, NONE)).collect();
        let mut detached = false;
        let mut cursor = 0;
        let mut kids = Vec::new();
        loop {
            let Some((index, depth, parent)) = stack.pop() else {
                // Whatever the walk did not reach sits on a cycle.
                while cursor < processes.len() && visited.contains(&processes[cursor].pid) {
                    cursor += 1;
                }
                let Some(process) = processes.get(cursor) else {
                    break;
                };
                if process.parent_pid != 0
                    && process.parent_pid != process.pid
                    && known.contains(&process.parent_pid)
                {
                    detached = true;
                }
                stack.push((cursor as u32, 0, NONE));
                continue;
            };
            let process = &processes[index as usize];
            if !visited.insert(process.pid) {
                continue;
            }
            let row = rows.len() as u32;
            rows.push(Row {
                process: index,
                depth,
                parent,
                last: true,
            });
            if let Some((first, _)) = ends.get(&process.pid) {
                kids.clear();
                let mut kid = *first;
                while kid != NONE {
                    kids.push(kid);
                    kid = next[kid as usize];
                }
                stack.extend(kids.iter().rev().map(|kid| (*kid, depth + 1, row)));
            }
        }
        // A row is last when no row of its depth follows it before a shallower one.
        let mut more: Vec<bool> = Vec::new();
        for row in rows.iter_mut().rev() {
            let depth = row.depth as usize;
            if depth == 0 {
                more.clear();
                continue;
            }
            more.resize(depth + 1, false);
            row.last = !more[depth];
            more[depth] = true;
        }
        Self {
            fingerprint: fingerprint(processes),
            rows,
            detached,
        }
    }

    pub(super) fn matches(&self, processes: &[CaptureProcess]) -> bool {
        self.fingerprint == fingerprint(processes)
    }

    /// The branch cells in front of `row`, the same as the prefixes of the
    /// whole list would give it, built for this row alone.
    pub(super) fn prefix(&self, row: usize) -> Prefix {
        let own = self.rows[row];
        if own.depth == 0 {
            return Prefix::default();
        }
        let mut glyphs = vec![Glyph::Blank; own.depth as usize];
        glyphs[own.depth as usize - 1] = if own.last {
            Glyph::Corner
        } else {
            Glyph::Branch
        };
        let mut ancestor = own.parent;
        while ancestor != NONE {
            let above = self.rows[ancestor as usize];
            if above.depth > 0 {
                glyphs[above.depth as usize - 1] = if above.last {
                    Glyph::Blank
                } else {
                    Glyph::Pipe
                };
            }
            ancestor = above.parent;
        }
        Prefix::from_glyphs(glyphs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, parent_pid: u32) -> CaptureProcess {
        CaptureProcess {
            pid,
            parent_pid,
            ..CaptureProcess::default()
        }
    }

    #[test]
    fn row_prefixes_equal_the_prefixes_of_the_whole_list() {
        // A mix of branching, chains, orphans and a cycle.
        let mut processes = vec![
            process(1, 0),
            process(2, 1),
            process(3, 1),
            process(4, 2),
            process(5, 3),
            process(6, 3),
            process(7, 6),
            process(50, 999),
            process(51, 50),
            process(60, 61),
            process(61, 60),
            process(62, 61),
        ];
        processes
            .extend((100..140).map(|pid| process(pid, if pid % 7 == 0 { 1 } else { pid - 1 })));
        let layout = Layout::build(&processes);
        assert_eq!(layout.rows.len(), processes.len());
        let depths: Vec<_> = layout.rows.iter().map(|row| row.depth as usize).collect();
        let whole = crate::tree_lines::prefixes(&depths);
        for (index, expected) in whole.iter().enumerate() {
            assert_eq!(&layout.prefix(index), expected, "row {index}");
        }
        assert!(layout.detached, "the 60/61 cycle leaves a detached root");
    }

    #[test]
    fn a_big_run_of_roots_and_a_deep_chain_build_in_one_pass() {
        let roots: Vec<_> = (1..=200_000).map(|pid| process(pid, 4_000_000)).collect();
        let started = std::time::Instant::now();
        let layout = Layout::build(&roots);
        assert_eq!(layout.rows.len(), 200_000);
        assert!(!layout.detached);
        assert!(layout.rows.iter().all(|row| row.depth == 0));
        let chain: Vec<_> = (1..=100_000).map(|pid| process(pid, pid - 1)).collect();
        let layout = Layout::build(&chain);
        assert_eq!(layout.rows.last().unwrap().depth, 99_999);
        // The prefix of one row is its own depth, not the whole list.
        assert_eq!(layout.prefix(99_999).levels(), 99_999);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "building took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_fingerprint_follows_pids_and_parents_only() {
        let mut processes = vec![process(1, 0), process(2, 1)];
        let before = fingerprint(&processes);
        processes[1].calls = 99;
        processes[1].name = "renamed".into();
        assert_eq!(fingerprint(&processes), before);
        processes[1].parent_pid = 0;
        assert_ne!(fingerprint(&processes), before);
        assert_ne!(fingerprint(&processes[..1]), before);
    }
}
