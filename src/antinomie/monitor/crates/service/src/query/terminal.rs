// SPDX-License-Identifier: GPL-3.0-only
//! `recording.terminal.replay` (design 5.12.3 `TerminalRecord`): the recorded
//! terminal transcript of a finished run, not live. The cursor is a byte
//! offset of the journal; a page holds at most 256 records or 65 536 output
//! bytes. The bytes are what the sample printed: render them only in a
//! terminal widget.

use super::{
    convert::base64,
    cursor::Cursor,
    page::{Page, PageRequest},
    request::TerminalReplayParams,
    service::QueryService,
    types::TerminalRecord,
};
use crate::api::error::ApiError;
use antinomie_monitor_core::{TerminalRecord as Engine, recording::Recording};

impl QueryService {
    /// `recording.terminal.replay`.
    pub(super) fn terminal_replay(
        &self,
        params: &TerminalReplayParams,
    ) -> Result<Page<TerminalRecord>, ApiError> {
        let max = self.settings.limits.row.terminal;
        let request = PageRequest {
            limit: params.limit,
            cursor: params.cursor.clone(),
        };
        let limit = request.effective_limit(max, max)? as usize;
        let opened = self.open_run(&params.recording_key)?;
        if !opened.dir.join("terminal.journal").is_file() {
            return Err(ApiError::not_recorded("terminal"));
        }
        let binding = opened.binding(&(), &serde_json::Value::Null);
        let start = match &request.cursor {
            Some(text) => Cursor::resume(text, binding)?,
            None => 0,
        };
        let replay = Recording::raw(&opened.dir)
            .terminal_replay(start, limit)
            .map_err(|e| self.engine_error(&e))?;
        let items = replay
            .records
            .iter()
            .map(|record| match record {
                Engine::Output(bytes) => TerminalRecord::Output {
                    data_b64: base64(bytes),
                },
                Engine::Resize { rows, cols } => TerminalRecord::Resize {
                    rows: *rows,
                    cols: *cols,
                },
                Engine::Eof => TerminalRecord::Eof {},
            })
            .collect();
        let mut page = opened.page(items, true);
        page.next_cursor = replay
            .next_offset
            .map(|offset| Cursor { offset, binding }.encode());
        // A transcript still being written has no final length.
        page.total_exact = opened.phase.growing().then_some(false);
        Ok(page)
    }
}
