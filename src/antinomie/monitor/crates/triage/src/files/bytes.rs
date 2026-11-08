// SPDX-License-Identifier: GPL-3.0-only
//! The bytes a file is rebuilt from, held as runs: a map from the offset a run
//! starts at to its bytes, never one entry per byte.
use std::collections::BTreeMap;

/// Runs of known bytes of one file. Runs never overlap; two runs may touch.
#[derive(Clone, Default, Debug)]
pub struct ByteStore {
    pub runs: BTreeMap<u64, Vec<u8>>,
    pub len: usize,
}

impl ByteStore {
    /// Known bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.runs.clear();
        self.len = 0;
    }

    /// The run `at` lies in, with its start.
    #[cfg(any(test, feature = "test-support"))]
    pub fn run_at(&self, at: u64) -> Option<(u64, &Vec<u8>)> {
        self.runs
            .range(..=at)
            .next_back()
            .filter(|(start, run)| at - **start < run.len() as u64)
            .map(|(start, run)| (*start, run))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn get(&self, at: &u64) -> Option<&u8> {
        self.run_at(*at)
            .map(|(start, run)| &run[(*at - start) as usize])
    }

    /// Set `data` at `start`, replacing what was known there. The number of
    /// bytes the store gained.
    pub fn put(&mut self, start: u64, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        let end = start.saturating_add(data.len() as u64);
        let data = &data[..(end - start) as usize];
        let before = self.len;
        self.remove_range(start, end);
        // Join the run that ends where this one starts, and the one that
        // starts where it ends.
        let previous = self
            .runs
            .range(..start)
            .next_back()
            .filter(|(at, run)| **at + run.len() as u64 == start)
            .map(|(at, _)| *at);
        let mut run = match previous {
            Some(at) => self.runs.remove(&at).map(|run| (at, run)),
            None => None,
        };
        let (first, bytes) = run.get_or_insert_with(|| (start, Vec::new()));
        bytes.extend_from_slice(data);
        if let Some(next) = self.runs.remove(&end) {
            bytes.extend_from_slice(&next);
        }
        self.runs.insert(*first, std::mem::take(bytes));
        self.len += data.len();
        self.len - before
    }

    /// Forget the bytes in `[from, to)`.
    pub fn remove_range(&mut self, from: u64, to: u64) {
        if from >= to {
            return;
        }
        let touching: Vec<u64> = self
            .runs
            .range(..to)
            .rev()
            .take_while(|(start, run)| **start + run.len() as u64 > from)
            .map(|(start, _)| *start)
            .collect();
        for start in touching {
            let Some(run) = self.runs.remove(&start) else {
                continue;
            };
            let end = start + run.len() as u64;
            self.len -= run.len();
            if start < from {
                let keep = run[..(from - start) as usize].to_vec();
                self.len += keep.len();
                self.runs.insert(start, keep);
            }
            if end > to {
                let keep = run[(to - start) as usize..].to_vec();
                self.len += keep.len();
                self.runs.insert(to, keep);
            }
        }
    }

    /// Forget the bytes at `size` and beyond.
    pub fn truncate(&mut self, size: u64) {
        self.remove_range(size, u64::MAX);
    }

    /// Forget `[offset, offset + len)` except the parts `newer` (ranges a later
    /// write holds) covers.
    pub fn remove_replaced(&mut self, newer: &[(u64, u64)], offset: u64, len: u64) {
        let end = offset.saturating_add(len);
        let mut held: Vec<(u64, u64)> = newer
            .iter()
            .map(|(a, b)| ((*a).max(offset), (*b).min(end)))
            .filter(|(a, b)| a < b)
            .collect();
        held.sort_unstable();
        let mut at = offset;
        for (a, b) in held {
            if a > at {
                self.remove_range(at, a);
            }
            at = at.max(b);
        }
        self.remove_range(at, end);
    }

    /// The runs that overlap `[from, to)`, clipped to it, `(start, end)`.
    pub fn spans_in(&self, from: u64, to: u64) -> Vec<(u64, u64)> {
        let first = self
            .runs
            .range(..=from)
            .next_back()
            .map_or(from, |(start, _)| *start);
        self.runs
            .range(first..to)
            .filter_map(|(start, run)| {
                let (a, b) = ((*start).max(from), (*start + run.len() as u64).min(to));
                (a < b).then_some((a, b))
            })
            .collect()
    }

    /// Every known byte in offset order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &u8)> + '_ {
        self.runs.iter().flat_map(|(start, run)| {
            run.iter()
                .enumerate()
                .map(move |(index, byte)| (start + index as u64, byte))
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn keys(&self) -> impl Iterator<Item = u64> + '_ {
        self.iter().map(|(at, _)| at)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn values(&self) -> impl Iterator<Item = u8> + '_ {
        self.runs.values().flatten().copied()
    }
}

/// Offsets known in either store with what each holds, in offset order.
pub fn merged<'a>(
    before: &'a ByteStore,
    after: &'a ByteStore,
) -> impl Iterator<Item = (u64, Option<&'a u8>, Option<&'a u8>)> + 'a {
    let mut a = before.iter().peekable();
    let mut b = after.iter().peekable();
    std::iter::from_fn(move || match (a.peek().copied(), b.peek().copied()) {
        (None, None) => None,
        (Some((x, left)), Some((y, right))) if x == y => {
            a.next();
            b.next();
            Some((x, Some(left), Some(right)))
        }
        (Some((x, left)), Some((y, _))) if x < y => {
            a.next();
            Some((x, Some(left), None))
        }
        (Some((x, left)), None) => {
            a.next();
            Some((x, Some(left), None))
        }
        (_, Some((y, right))) => {
            b.next();
            Some((y, None, Some(right)))
        }
    })
}
