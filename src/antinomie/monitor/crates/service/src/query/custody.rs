// SPDX-License-Identifier: GPL-3.0-only
//! `recording.custody.list` (design 5.12.3 `CustodyEntry`): the custody chain
//! of the run's sample, or of `sha256` instead of a run. The library is opened
//! short-lived with its busy timeout (design 2.3), so the read works beside a
//! daemon or a GUI. A library that does not exist yet is not created.

use super::{
    context::ReadContext,
    cursor::{Cursor, CursorBinding, Generation, stable_hash},
    page::{Page, PageRequest},
    request::CustodyListParams,
    service::QueryService,
    types::*,
};
use crate::api::{error::ApiError, run::RecordingPhase};
use antinomie_monitor_core::samples::{self, EventRow, Library};
use serde_json::{Map, Value};

/// Members of a custody event that can be host paths (class L).
const PATH_MEMBERS: [&str; 3] = ["origin", "path", "from"];
/// The kinds whose path members are host paths.
const PATH_KINDS: [&str; 4] = ["added", "origin_added", "original_deleted", "migrated"];

/// `/a/b/c` as `c`: a remote reply carries the file name only.
fn file_name(text: &str) -> String {
    text.rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(text)
        .to_owned()
}

fn entry_of(row: &EventRow, local: bool) -> CustodyEntry {
    let mut members = match serde_json::to_value(&row.event) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    };
    let kind = members
        .remove("kind")
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    if !local && PATH_KINDS.contains(&kind.as_str()) {
        for member in PATH_MEMBERS {
            if let Some(Value::String(text)) = members.get_mut(member) {
                *text = file_name(text);
            }
        }
    }
    CustodyEntry {
        seq: row.seq,
        at_ms: row.at_ms,
        by: row.by.clone(),
        kind,
        data: members.into_iter().collect(),
        before_chain: row.before_chain,
        prev: row.prev.clone(),
        hash: row.hash.clone(),
    }
}

impl QueryService {
    /// `recording.custody.list`.
    pub(super) fn custody_list(
        &self,
        params: &CustodyListParams,
        ctx: &ReadContext,
    ) -> Result<Page<CustodyEntry>, ApiError> {
        let sha256 = match (&params.recording_key, &params.sha256) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(ApiError::invalid_argument(
                    "sha256",
                    "exactly one of recording_key or sha256 is required",
                ));
            }
            (None, Some(sha)) => sha.as_str().to_owned(),
            (Some(key), None) => {
                let opened = self.open_run(key)?;
                opened
                    .run
                    .request
                    .sample
                    .as_ref()
                    .map(|sample| sample.sha256.clone())
                    .ok_or_else(|| ApiError::not_recorded("library sample"))?
            }
        };
        let (default, max) = self.settings.rows();
        let request = PageRequest {
            limit: params.limit,
            cursor: params.cursor.clone(),
        };
        let limit = request.effective_limit(default, max)? as usize;
        // Do not create a library to read from it.
        let database = samples::samples_dir(&self.options.data_dir).join(samples::DATABASE);
        if !database.is_file() {
            return Err(ApiError::not_found("sample"));
        }
        let library = Library::open(&self.options.data_dir)
            .map_err(|e| super::errors::text_error(&e, &self.scrub))?;
        let rows = library
            .events(&sha256.to_ascii_lowercase())
            .map_err(|e| super::errors::text_error(&e, &self.scrub))?;
        if rows.is_empty() {
            return Err(ApiError::not_found("sample"));
        }
        // The chain only grows at its end, so its head and length are its
        // generation: a cursor from before an append is stale.
        let generation = Generation(stable_hash(&(rows.len(), rows.last().map(|r| &r.hash))));
        let binding = CursorBinding {
            generation,
            filter_hash: stable_hash(&sha256),
            sort_hash: stable_hash(&Value::Null),
        };
        let start = match &request.cursor {
            Some(text) => Cursor::resume(text, binding)? as usize,
            None => 0,
        };
        let local = ctx.caller.client_id.starts_with("local:");
        let total = rows.len();
        let end = (start + limit).min(total);
        let items = rows
            .get(start..end)
            .unwrap_or_default()
            .iter()
            .map(|row| entry_of(row, local))
            .collect();
        let mut page = Page::new(items, generation, RecordingPhase::Complete);
        page.total = Some(total as u64);
        page.total_exact = Some(true);
        page.untrusted = Some(true);
        page.next_cursor = (end < total).then(|| {
            Cursor {
                offset: end as u64,
                binding,
            }
            .encode()
        });
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::samples::CustodyEvent;

    fn row(event: CustodyEvent) -> EventRow {
        EventRow {
            seq: 3,
            at_ms: 9,
            by: "app".into(),
            event,
            before_chain: false,
            prev: "p".into(),
            hash: "h".into(),
        }
    }

    #[test]
    fn host_paths_of_the_events_that_carry_one_are_reduced_for_a_remote_caller() {
        let deleted = row(CustodyEvent::OriginalDeleted {
            path: "/home/analyst/Downloads/evil.bin".into(),
        });
        let remote = entry_of(&deleted, false);
        assert_eq!(remote.kind, "original_deleted");
        assert_eq!(remote.data["path"], "evil.bin");
        let local = entry_of(&deleted, true);
        assert_eq!(local.data["path"], "/home/analyst/Downloads/evil.bin");
        let migrated = entry_of(
            &row(CustodyEvent::Migrated {
                from: "/old/place/lib.db".into(),
            }),
            false,
        );
        assert_eq!(migrated.data["from"], "lib.db");
        // A guest path in `sent` is not a host path and stays.
        let sent = entry_of(
            &row(CustodyEvent::Sent {
                vm: "vm-1".into(),
                path: "/tmp/sample".into(),
            }),
            false,
        );
        assert_eq!(sent.data["path"], "/tmp/sample");
        assert_eq!(
            (remote.seq, remote.prev.as_str(), remote.hash.as_str()),
            (3, "p", "h")
        );
    }

    #[test]
    fn a_remote_reply_carries_the_file_name_only() {
        assert_eq!(file_name("/home/analyst/Downloads/evil.bin"), "evil.bin");
        assert_eq!(file_name("evil.bin"), "evil.bin");
        assert_eq!(file_name("/"), "/");
    }
}
