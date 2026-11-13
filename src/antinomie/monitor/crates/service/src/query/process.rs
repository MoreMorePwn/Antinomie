// SPDX-License-Identifier: GPL-3.0-only
//! `recording.process.tree` (design 5.12.3 `ProcessNode`): the observed process
//! tree as flat rows with `parent_pid`, ordered by `pid`. It reads all of
//! `telemetry.raw`, so it is a heavy read and its result is cached per
//! `generation`. Core-only: it carries no Triage flags.

use super::{
    cursor::{Cursor, Generation},
    page::{Page, PageExtra, PageRequest},
    request::ProcessTreeParams,
    service::QueryService,
    types::*,
};
use crate::api::error::ApiError;
use antinomie_monitor_core::{capture_processes::CaptureProcess, recording::Recording};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
};

/// A tree as the engine read it.
pub struct Tree {
    pub nodes: Vec<ProcessNode>,
    pub issues: Vec<String>,
    pub truncated: bool,
}

/// The last few trees, by run folder and generation. A generation change
/// drops the entry: it is looked up by both.
#[derive(Default)]
pub struct TreeCache {
    entries: Vec<(PathBuf, Generation, Arc<Tree>)>,
}

/// Trees kept; each is at most 262 144 nodes.
const KEPT: usize = 4;

impl TreeCache {
    fn get(&mut self, dir: &Path, generation: Generation) -> Option<Arc<Tree>> {
        let at = self
            .entries
            .iter()
            .position(|(d, g, _)| d == dir && *g == generation)?;
        let entry = self.entries.remove(at);
        let tree = Arc::clone(&entry.2);
        self.entries.push(entry);
        Some(tree)
    }

    fn put(&mut self, dir: &Path, generation: Generation, tree: Arc<Tree>) {
        self.entries.retain(|(d, _, _)| d != dir);
        self.entries.push((dir.to_path_buf(), generation, tree));
        if self.entries.len() > KEPT {
            self.entries.remove(0);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn node(process: &CaptureProcess, scrub: &super::scrub::Scrub) -> ProcessNode {
    ProcessNode {
        pid: process.pid,
        parent_pid: process.parent_pid,
        name: process.name.clone(),
        exe: process.exe.clone(),
        at_start: process.at_start,
        first_guest_ns: process.first_ns,
        last_guest_ns: process.last_ns,
        calls: process.calls,
        packets: process.packets,
        exited: process.exited,
        exit_code: process.exit_code.and_then(|code| i32::try_from(code).ok()),
    }
    .scrubbed(scrub)
}

impl ProcessNode {
    fn scrubbed(mut self, scrub: &super::scrub::Scrub) -> Self {
        self.name = scrub.text(&self.name);
        self.exe = self.exe.map(|exe| scrub.text(&exe));
        self
    }
}

/// `root` and everything below it, by parent links, in pid order.
fn subtree(nodes: Vec<ProcessNode>, root: u32) -> Vec<ProcessNode> {
    let mut wanted = std::collections::BTreeSet::from([root]);
    // Parents have no order guarantee against pids, so grow to a fixed point.
    loop {
        let before = wanted.len();
        for node in &nodes {
            if wanted.contains(&node.parent_pid) {
                wanted.insert(node.pid);
            }
        }
        if wanted.len() == before {
            break;
        }
    }
    nodes
        .into_iter()
        .filter(|node| wanted.contains(&node.pid))
        .collect()
}

impl QueryService {
    fn read_tree(
        &self,
        opened: &super::service::Opened,
        cancel: &AtomicBool,
    ) -> Result<Arc<Tree>, ApiError> {
        let cached = self
            .trees
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&opened.dir, opened.generation);
        if let Some(tree) = cached {
            return Ok(tree);
        }
        if !opened.dir.join("telemetry.raw").is_file() {
            return Err(ApiError::not_recorded("system-call trace"));
        }
        let recording = Recording::raw(&opened.dir);
        let (list, issues) = recording
            .process_tree_cancellable(opened.run.pid, &opened.run.request.path, cancel)
            .map_err(|e| self.engine_error(&e))?;
        let truncated = list.len() >= antinomie_monitor_core::recording::PROCESS_TREE_LIMIT
            || issues
                .iter()
                .any(|issue| issue.starts_with("Process tree limited"));
        let tree = Arc::new(Tree {
            nodes: list
                .iter()
                .map(|process| node(process, &self.scrub))
                .collect(),
            issues: issues.iter().map(|issue| self.scrub.text(issue)).collect(),
            truncated,
        });
        // A tree read while the recording grew is not worth keeping.
        if !opened.phase.growing() {
            self.trees.lock().unwrap_or_else(|e| e.into_inner()).put(
                &opened.dir,
                opened.generation,
                Arc::clone(&tree),
            );
        }
        Ok(tree)
    }

    /// `recording.process.tree`.
    pub(super) fn process_tree(
        &self,
        params: &ProcessTreeParams,
        cancel: &AtomicBool,
    ) -> Result<Page<ProcessNode>, ApiError> {
        let (default, max) = self.settings.rows();
        let request = PageRequest {
            limit: params.limit,
            cursor: params.cursor.clone(),
        };
        let limit = request.effective_limit(default, max)? as usize;
        let opened = self.open_run(&params.recording_key)?;
        let binding = opened.binding(&params.root_pid, &serde_json::Value::Null);
        let start = match &request.cursor {
            Some(text) => Cursor::resume(text, binding)? as usize,
            None => 0,
        };
        let tree = self.read_tree(&opened, cancel)?;
        let nodes: Vec<ProcessNode> = match params.root_pid {
            Some(root) => subtree(tree.nodes.clone(), root),
            None => tree.nodes.clone(),
        };
        let total = nodes.len();
        let end = (start + limit).min(total);
        let items = nodes.get(start..end).unwrap_or_default().to_vec();
        let mut page = opened.counted_page(items, total as u64, true);
        page.next_cursor = (end < total).then(|| {
            Cursor {
                offset: end as u64,
                binding,
            }
            .encode()
        });
        if start == 0 {
            page.notes = Some(PageExtra::Process(ProcessTreeNotes {
                issues: tree.issues.clone(),
                truncated: tree.truncated,
            }));
        }
        if tree.truncated {
            page.partial = Some(true);
        }
        Ok(page)
    }
}
