// SPDX-License-Identifier: GPL-3.0-only
//! `recording.trace.page`, `recording.trace.get` and `recording.captured.read`
//! (design 5.12.3): the system-call trace of a run. The trace cursor is a
//! raw-file byte offset, not a row number (5.12.5); the engine's rebuildable
//! index lives outside the recording.

use super::cursor::Generation;
use super::{
    convert::{base64, find_event, group_of, invocation, parse_field_id, trace_row},
    cursor::Cursor,
    limits::fit_in_page,
    page::{Page, PageRequest, Single},
    request::{CapturedReadParams, TraceGetParams, TracePageParams},
    service::QueryService,
    types::*,
};
use crate::api::error::ApiError;
use antinomie_monitor_core::{InvocationSummary, recording::Recording};
use std::{
    cell::Cell,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

/// The engine reads at most this many calls at once.
const CHUNK: usize = 256;
/// A sized-down request is tried this many times when a page is too large.
const SHRINKS: usize = 6;
/// Filtered totals kept, by run folder, generation and filter.
const TOTALS_KEPT: usize = 16;
/// The count of a filtered total looks at the clock every this many calls.
const CLOCK_EVERY: u32 = 256;

/// The totals of filtered trace walks (BH-28): counting the calls a filter
/// keeps reads the whole trace, so it is done once per run generation and
/// filter, on a first page and within a time budget, and later pages take
/// the answer from here. A walk that did not finish leaves no entry; the
/// pages then have no `total`.
#[derive(Default)]
pub struct TotalCache {
    entries: Vec<(PathBuf, Generation, u64, u64)>,
}

impl TotalCache {
    fn get(&mut self, dir: &Path, generation: Generation, filter: u64) -> Option<u64> {
        let at = self
            .entries
            .iter()
            .position(|(d, g, f, _)| d == dir && *g == generation && *f == filter)?;
        let entry = self.entries.remove(at);
        let total = entry.3;
        self.entries.push(entry);
        Some(total)
    }

    fn put(&mut self, dir: &Path, generation: Generation, filter: u64, total: u64) {
        // A new generation of a run makes its older totals useless.
        self.entries
            .retain(|(d, g, f, _)| d != dir || (*g == generation && *f != filter));
        self.entries
            .push((dir.to_path_buf(), generation, filter, total));
        if self.entries.len() > TOTALS_KEPT {
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

/// The calls one read took from the engine, the cursor of the next one and
/// the engine's issues.
struct Rows {
    rows: Vec<TraceRow>,
    next: Option<u64>,
    issues: Vec<String>,
}

impl QueryService {
    fn trace_recording(&self, dir: &std::path::Path) -> Result<Recording, ApiError> {
        if !dir.join("telemetry.raw").is_file() {
            return Err(ApiError::not_recorded("system-call trace"));
        }
        Ok(Recording::raw(dir))
    }

    /// `recording.trace.page`.
    pub(super) fn trace_page(
        &self,
        params: &TracePageParams,
        cancel: &AtomicBool,
    ) -> Result<Page<TraceRow>, ApiError> {
        // `q` is the Triage crate's syscall filter language, the one the
        // trace tab of the window uses; a bad filter is `invalid_argument`.
        let filter = antinomie_triage::query::compile_note(params.q.as_deref().unwrap_or(""));
        if let Some(error) = &filter.error {
            return Err(super::tables::q_error(error));
        }
        let (default, max) = self.settings.rows();
        let request = PageRequest {
            limit: params.limit,
            cursor: params.cursor.clone(),
        };
        let mut limit = request.effective_limit(default, max)? as usize;
        let opened = self.open_run(&params.run_key)?;
        let recording = self.trace_recording(&opened.dir)?;
        let mut hide = params.hide_groups.clone();
        hide.sort();
        hide.dedup();
        let binding = opened.binding(&(params.pid, &hide, &params.q), &serde_json::Value::Null);
        let start = match &request.cursor {
            Some(text) => Cursor::resume(text, binding)?,
            None => 0,
        };
        let keep = |call: &InvocationSummary| {
            (hide.is_empty()
                || call
                    .entry
                    .as_ref()
                    .or(call.exit.as_ref())
                    .is_none_or(|event| !hide.contains(&group_of(&event.syscall_name))))
                && filter.keep(call)
        };
        let mut shrinks = 0;
        loop {
            let Rows { rows, next, issues } =
                self.read_rows(&recording, start, limit, params.pid, &keep, &opened, cancel)?;
            let kept = fit_in_page(
                rows.iter()
                    .map(|row| serde_json::to_vec(row).map_or(0, |b| b.len())),
            );
            if kept < rows.len() && shrinks < SHRINKS && limit > 1 {
                // A page above 1 MiB has fewer rows, never a cut row.
                limit = kept.max(1).min(limit / 2).max(1);
                shrinks += 1;
                continue;
            }
            let total = if hide.is_empty() && filter.keeps_everything() {
                Some(
                    recording
                        .invocation_count_cancellable(params.pid, cancel)
                        .map_err(|e| self.engine_error(&e))?,
                )
            } else {
                self.filtered_total(
                    &recording,
                    &opened,
                    binding.filter_hash,
                    request.cursor.is_none(),
                    params.pid,
                    &keep,
                    cancel,
                )?
            };
            let mut page = match total {
                Some(total) => opened.counted_page(rows, total, true),
                None => opened.page(rows, true),
            };
            page.next_cursor = next.map(|offset| Cursor { offset, binding }.encode());
            if !issues.is_empty() {
                page.partial = Some(true);
            }
            return Ok(page);
        }
    }

    /// The number of calls a filtered walk keeps (BH-28): from the cache;
    /// else, on a first page, counted within a quarter of the light deadline
    /// and kept; else unknown (`None`), so that a page never reads the whole
    /// trace twice and a cursor page never does.
    #[allow(clippy::too_many_arguments)]
    fn filtered_total(
        &self,
        recording: &Recording,
        opened: &super::service::Opened,
        filter: u64,
        first_page: bool,
        pid: Option<u32>,
        keep: &dyn Fn(&InvocationSummary) -> bool,
        cancel: &AtomicBool,
    ) -> Result<Option<u64>, ApiError> {
        let lock = || self.totals.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(total) = lock().get(&opened.dir, opened.generation, filter) {
            return Ok(Some(total));
        }
        if !first_page {
            return Ok(None);
        }
        let budget = self.settings.light_timeout / 4;
        let began = Instant::now();
        let over = AtomicBool::new(budget.is_zero());
        let seen = Cell::new(0u32);
        let counted = recording.matching_totals_cancellable(pid, &over, |call| {
            seen.set(seen.get().wrapping_add(1));
            if cancel.load(Ordering::Relaxed)
                || (seen.get().is_multiple_of(CLOCK_EVERY) && began.elapsed() >= budget)
            {
                over.store(true, Ordering::Relaxed);
            }
            keep(call)
        });
        match counted {
            Ok(totals) => {
                lock().put(&opened.dir, opened.generation, filter, totals.total);
                Ok(Some(totals.total))
            }
            // The request itself was cancelled: say so as before.
            Err(error) if cancel.load(Ordering::Relaxed) => Err(self.engine_error(&error)),
            // Out of budget: the page goes without a total.
            Err(_) if over.load(Ordering::Relaxed) => Ok(None),
            Err(error) => Err(self.engine_error(&error)),
        }
    }

    /// Up to `limit` kept calls from raw offset `start`, with the cursor of the
    /// next one.
    #[allow(clippy::too_many_arguments)]
    fn read_rows(
        &self,
        recording: &Recording,
        start: u64,
        limit: usize,
        pid: Option<u32>,
        keep: &dyn Fn(&InvocationSummary) -> bool,
        opened: &super::service::Opened,
        cancel: &AtomicBool,
    ) -> Result<Rows, ApiError> {
        let mut rows = Vec::new();
        let mut issues = Vec::new();
        let mut offset = start;
        let mut next = None;
        while rows.len() < limit {
            let want = (limit - rows.len()).min(CHUNK);
            let page = recording
                .matching_page_cancellable(offset, want, pid, cancel, keep)
                .map_err(|e| self.engine_error(&e))?
                .page;
            issues.extend(page.issues);
            rows.extend(
                page.invocations
                    .iter()
                    .filter_map(|call| trace_row(call, |ns| opened.ts_ms(ns))),
            );
            next = page.next_offset;
            match next {
                Some(following) => offset = following,
                None => break,
            }
        }
        issues.sort();
        issues.dedup();
        Ok(Rows { rows, next, issues })
    }

    /// The call a trace row or finding names.
    fn find_call(
        &self,
        recording: &Recording,
        identity: (u64, u64, u64),
        cancel: &AtomicBool,
    ) -> Result<InvocationSummary, ApiError> {
        recording
            .invocation_by_identity_cancellable(identity, cancel)
            .map_err(|e| self.engine_error(&e))?
            .map(|(call, _)| call)
            .ok_or_else(|| ApiError::not_found("call"))
    }

    /// `recording.trace.get`.
    pub(super) fn trace_get(
        &self,
        params: &TraceGetParams,
        cancel: &AtomicBool,
    ) -> Result<Single<Invocation>, ApiError> {
        let opened = self.open_run(&params.run_key)?;
        let recording = self.trace_recording(&opened.dir)?;
        let identity = (params.call.stream.0, params.call.task.0, params.call.call.0);
        let call = self.find_call(&recording, identity, cancel)?;
        let value = invocation(&call, |ns| opened.ts_ms(ns), &self.scrub);
        Ok(opened.single(value, true))
    }

    /// `recording.captured.read`: at most 65 536 bytes of one captured field,
    /// only where the recording captured them.
    pub(super) fn captured_read(
        &self,
        params: &CapturedReadParams,
        cancel: &AtomicBool,
    ) -> Result<Single<BytesReply>, ApiError> {
        let max = u64::from(self.settings.limits.byte_read.captured);
        if u64::from(params.len) > max {
            return Err(ApiError::payload_too_large(max));
        }
        if params.len == 0 {
            return Err(ApiError::invalid_argument("len", "at least 1 byte"));
        }
        let named = parse_field_id(&params.field)
            .ok_or_else(|| ApiError::invalid_argument("field", "not a field this service made"))?;
        let opened = self.open_run(&params.run_key)?;
        let recording = self.trace_recording(&opened.dir)?;
        let call = self.find_call(&recording, named.call, cancel)?;
        let field = find_event(&call, named.event_seq)
            .and_then(|event| {
                event
                    .fields
                    .iter()
                    .find(|field| field.object_id == named.object_id && field.key == named.key)
            })
            .ok_or_else(|| ApiError::not_found("field"))?;
        let bytes = antinomie_monitor_core::recording::read_captured_range(
            &opened.dir,
            field,
            params.offset.0,
            params.len as usize,
        )
        .map_err(|e| self.engine_error(&e))?;
        let reply = BytesReply {
            offset: params.offset,
            len: bytes.len() as u64,
            data_b64: base64(&bytes),
        };
        Ok(opened.single(reply, true))
    }
}
