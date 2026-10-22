// SPDX-License-Identifier: GPL-3.0-only
//! Continuation pages for the async observations of one saved call.
//!
//! An archive page carries at most [`ASYNC_PREVIEW_LIMIT`] observations per
//! call and says how many more were saved. This reads the rest, a bounded
//! page at a time, from the same packet index and raw archive.
use super::call_reader::CallReader;
use super::matching::indexed_boundary;
use super::*;

/// Index form of an event sequence. SQLite integers are signed; flipping the
/// top bit keeps the order of the unsigned sequences.
pub(super) fn seq_index(seq: u64) -> i64 {
    (seq ^ (1 << 63)) as i64
}

fn seq_from_index(value: i64) -> u64 {
    (value as u64) ^ (1 << 63)
}

/// What a lifecycle record is, as the index stores it. Larger kinds win when
/// one event holds several lifecycle fields.
#[derive(Clone, Copy)]
pub(super) enum LifecycleKind {
    /// Exec commit and the other records the call does not carry.
    Other = 0,
    /// The task ended in this call.
    TaskExit = 1,
    /// Credentials or a file hash, read back with the call.
    KernelNote = 2,
}

/// Whether the field-begin `packet` names a lifecycle record, and which kind.
pub(super) fn lifecycle_field(header: &parser::Header, packet: &[u8]) -> Option<LifecycleKind> {
    if header.phase != 3 || header.fragment != 2 {
        return None;
    }
    let (_, body) = parser::parse_packet(packet).ok()?;
    let length = usize::from(u16::from_le_bytes(body.get(32..34)?.try_into().ok()?));
    let name = body.get(40..40usize.checked_add(length)?)?;
    if !name.starts_with(b"lifecycle.") {
        return None;
    }
    Some(if name == b"lifecycle.task_exit" {
        LifecycleKind::TaskExit
    } else if [
        crate::kernel_notes::CREDS_KEY,
        crate::kernel_notes::HASH_KEY,
        crate::kernel_notes::FILE_ID_KEY,
        crate::kernel_notes::EXEC_IMAGE_KEY,
    ]
    .iter()
    .any(|key| name == key.as_bytes())
    {
        LifecycleKind::KernelNote
    } else {
        LifecycleKind::Other
    })
}

impl Recording {
    /// Read one page of the async observations saved for a call.
    ///
    /// | Argument | Meaning |
    /// | --- | --- |
    /// | `call` | Stream, task cookie and call ID of an invocation from an archive page |
    /// | `from_event_seq` | Inclusive cursor: `0` for the first page, then a page's `next_event_seq` |
    /// | `limit` | Maximum observations, in `1..=`[`ASYNC_PREVIEW_LIMIT`] |
    /// | `cancel` | Cooperative cancellation, checked while indexing and reading packets |
    ///
    /// Lifecycle records (task end, exec commit) are not async observations;
    /// the call row carries the task end. Every other observation the index
    /// holds for the call is returned once, in event order, even when some of
    /// its packets are missing: it then reads as incomplete. Only the
    /// packets of the page are read.
    pub fn async_page_cancellable(
        &self,
        call: (u64, u64, u64),
        from_event_seq: u64,
        limit: usize,
        cancel: &AtomicBool,
    ) -> Result<AsyncPage, RecordingError> {
        if cancel.load(Ordering::Relaxed) {
            return Err(RecordingError::Limit("archive read cancelled"));
        }
        if !(1..=ASYNC_PREVIEW_LIMIT).contains(&limit) {
            return Err(RecordingError::Limit("async page size must be 1..256"));
        }
        retry_index_busy(cancel, || {
            self.async_page_once(call, from_event_seq, limit, true, cancel)
        })
    }

    /// One page of the async observations the guest attributed to a task
    /// outside its calls (contract 14.3): requests that the `iou-sqp` thread
    /// of an SQPOLL ring, or a process the ring was passed to, submitted on a
    /// ring the task created. They carry the ring creator's task cookie and
    /// call id 0, so no call owns them and archive pages never show them.
    /// Cursor, limit and order as [`Self::async_page_cancellable`]; a task
    /// with none has an empty page.
    pub fn attributed_async_page_cancellable(
        &self,
        stream_id: u64,
        task_cookie: u64,
        from_event_seq: u64,
        limit: usize,
        cancel: &AtomicBool,
    ) -> Result<AsyncPage, RecordingError> {
        if cancel.load(Ordering::Relaxed) {
            return Err(RecordingError::Limit("archive read cancelled"));
        }
        if !(1..=ASYNC_PREVIEW_LIMIT).contains(&limit) {
            return Err(RecordingError::Limit("async page size must be 1..256"));
        }
        retry_index_busy(cancel, || {
            self.async_page_once(
                (stream_id, task_cookie, 0),
                from_event_seq,
                limit,
                false,
                cancel,
            )
        })
    }

    fn async_page_once(
        &self,
        call: (u64, u64, u64),
        from_event_seq: u64,
        limit: usize,
        owned: bool,
        cancel: &AtomicBool,
    ) -> Result<AsyncPage, RecordingError> {
        let path = self.directory.join("telemetry.raw");
        let (connection, identity) = archive_index(&self.directory, cancel)?;
        let boundary = indexed_boundary(&connection)?;
        let key = key_blob(call);
        let known = connection
            .query_row("SELECT 1 FROM invocations WHERE key=?1", [&key], |_| Ok(()))
            .optional()?;
        if owned && known.is_none() {
            return Err(RecordingError::Limit("call is not in the archive index"));
        }
        let mut reader = CallReader::open(&self.directory, &connection, boundary)?;
        let mut preview = reader.preview();
        let window = reader.window(&key, seq_index(from_event_seq), limit, &mut preview, cancel)?;
        let total = reader.saved(&key)?;
        let issues = reader.take_issues();
        let (after_identity, after_size) = raw_identity(&path)?;
        if after_identity != identity || after_size < boundary {
            return Err(RecordingError::Limit(
                "raw archive was replaced or shrunk while being read; open it again",
            ));
        }
        Ok(AsyncPage {
            events: preview.latest.into_values().collect(),
            next_event_seq: window.next.map(seq_from_index),
            total,
            issues,
        })
    }
}
