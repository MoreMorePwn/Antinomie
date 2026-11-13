// SPDX-License-Identifier: GPL-3.0-only
//! `recording.network.packets` and `recording.network.packet` (design 5.12.3,
//! card Q-5): the packets of one capture of a run, through the engine's
//! `PacketFilterWorker`. TShark runs inside bubblewrap, as for the packet
//! panel. A Wireshark display filter that TShark rejects is `invalid_argument`
//! with TShark's text, host paths removed.
//!
//! Sensitivity (5.12.7): the rows carry TShark's default columns and no
//! payload bytes (`runs.see_all`). The decoded packet (its tree, which spells
//! payload text, and its bytes) needs `evidence.view`; the operation checks
//! the permission before it touches the capture.

use super::{
    convert::base64,
    cursor::Cursor,
    page::{Page, PageRequest, Single},
    pool::cancelled,
    request::{NetworkPacketParams, NetworkPacketsParams},
    service::{Opened, QueryService},
    types::*,
};
use crate::api::{
    error::{ApiError, ErrorCode},
    ids::RecordingArtifactId,
};
use antinomie_monitor_core::{
    network::{NetworkPacket, Transport},
    packet_filter::{
        CaptureIdentity, PacketFilterEvent, PacketFilterIndex, PacketFilterWorker, ParseStatus,
    },
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// The poll interval while a worker is busy.
const TICK: Duration = Duration::from_millis(2);
/// Characters kept of a TShark column.
const COLUMN_LIMIT: usize = 256;

fn cut(text: &str) -> String {
    text.chars().take(COLUMN_LIMIT).collect()
}

fn row_of(packet: &NetworkPacket, made_by: Option<MadeBy>) -> PacketRow {
    PacketRow {
        n: packet.number,
        time_us: packet.time_us,
        length: packet.length,
        captured: packet.captured,
        source: cut(&packet.source),
        destination: cut(&packet.destination),
        protocol: cut(&packet.protocol),
        info: cut(&packet.info),
        src_ip: packet.src_ip.map(|ip| ip.to_string()),
        dst_ip: packet.dst_ip.map(|ip| ip.to_string()),
        src_port: packet.src_port,
        dst_port: packet.dst_port,
        tcp_flags: packet.tcp_flags.map(u16::from),
        transport: packet.transport.map(|transport| match transport {
            Transport::Tcp => PacketTransport::Tcp,
            Transport::Udp => PacketTransport::Udp,
        }),
        made_by,
    }
}

/// A worker for the length of one read, and the capture it evaluates.
struct Session<'a> {
    service: &'a QueryService,
    worker: PacketFilterWorker,
    identity: CaptureIdentity,
    live: bool,
    cancel: &'a AtomicBool,
}

impl Session<'_> {
    fn unavailable(&self, text: &str) -> ApiError {
        ApiError::new(ErrorCode::Unavailable, self.service.scrub.text(text))
            .with_detail("reason", serde_json::json!("tshark_unavailable"))
    }

    /// Wait for the event of `generation`, or for the cancel flag.
    fn event(&self, generation: u64, detail: bool) -> Result<PacketFilterEvent, ApiError> {
        loop {
            if self.cancel.load(Ordering::Relaxed) {
                self.worker.release();
                return Err(cancelled());
            }
            let event = if detail {
                self.worker.poll_detail()
            } else {
                self.worker.poll()
            };
            if let Some(event) = event {
                let got = match &event {
                    PacketFilterEvent::Evaluated { generation, .. }
                    | PacketFilterEvent::Page { generation, .. }
                    | PacketFilterEvent::Frame { generation, .. }
                    | PacketFilterEvent::Detail { generation, .. } => *generation,
                };
                if got == generation {
                    return Ok(event);
                }
            }
            std::thread::sleep(TICK);
        }
    }

    fn evaluate_raw(
        &self,
        expression: &str,
    ) -> Result<Result<Arc<PacketFilterIndex>, String>, ApiError> {
        let generation =
            self.worker
                .request(self.identity.clone(), expression.to_owned(), self.live);
        match self.event(generation, false)? {
            PacketFilterEvent::Evaluated { result, .. } => Ok(result),
            _ => Err(ApiError::new(
                ErrorCode::Internal,
                "unexpected packet worker event",
            )),
        }
    }

    /// The index of the frames matching `filter`. A filter TShark rejects is
    /// told from a capture or tool failure by evaluating with no filter.
    fn index(&self, filter: &str) -> Result<Arc<PacketFilterIndex>, ApiError> {
        match self.evaluate_raw(filter)? {
            Ok(index) => Ok(index),
            Err(text) if filter.trim().is_empty() => Err(self.failure(&text)),
            Err(text) => match self.evaluate_raw("")? {
                Ok(_) => Err(ApiError::invalid_argument(
                    "filter",
                    self.service.scrub.text(&text),
                )),
                Err(other) => Err(self.failure(&other)),
            },
        }
    }

    fn failure(&self, text: &str) -> ApiError {
        if text.contains("unavailable") || text.contains("Install tshark") {
            self.unavailable(text)
        } else {
            super::errors::text_error(text, &self.service.scrub)
        }
    }

    /// The row store of the parse is wide enough for `needed` frames, or done.
    fn wait_rows(
        &self,
        index: &PacketFilterIndex,
        needed: Option<u64>,
    ) -> Result<ParseStatus, ApiError> {
        loop {
            if self.cancel.load(Ordering::Relaxed) {
                self.worker.release();
                return Err(cancelled());
            }
            let rows = index.rows();
            let status = rows.status();
            let enough = needed.is_some_and(|n| rows.done_count() >= n.min(index.packet_count()));
            if enough || !matches!(status, ParseStatus::Parsing) {
                return Ok(status);
            }
            std::thread::sleep(TICK);
        }
    }
}

impl QueryService {
    /// The capture file `capture_id` names, with its run.
    fn capture_of(&self, opened: &Opened, capture_id: &str) -> Result<(PathBuf, bool), ApiError> {
        let id = RecordingArtifactId::try_from(capture_id.to_owned())
            .map_err(|_| ApiError::invalid_argument("capture_id", "not a capture id"))?;
        let entry = self
            .recording_entries(opened)
            .into_iter()
            .find(|entry| entry.id == id && entry.kind == RecordingArtifactKind::NetworkCapture)
            .ok_or_else(|| ApiError::not_found("capture"))?;
        let recording = self
            .artifacts_json(opened)
            .map(|links| links.network_state)
            .unwrap_or_default();
        let live = opened.phase.growing()
            || matches!(
                recording,
                antinomie_monitor_core::RunArtifactState::Recording
                    | antinomie_monitor_core::RunArtifactState::WaitingForTreeExit
                    | antinomie_monitor_core::RunArtifactState::WaitingForRootExit
            );
        Ok((entry.root.join(&entry.relative), live))
    }

    fn session<'a>(
        &'a self,
        opened: &Opened,
        capture_id: &str,
        cancel: &'a AtomicBool,
    ) -> Result<Session<'a>, ApiError> {
        let (path, live) = self.capture_of(opened, capture_id)?;
        let identity =
            CaptureIdentity::read(&path).map_err(|e| super::errors::text_error(&e, &self.scrub))?;
        let worker = PacketFilterWorker::read_only().map_err(|e| {
            ApiError::new(ErrorCode::Unavailable, self.scrub.text(&e))
                .with_detail("reason", serde_json::json!("tshark_unavailable"))
        })?;
        Ok(Session {
            service: self,
            worker,
            identity,
            live,
            cancel,
        })
    }

    /// `recording.network.packets`: frame order, at most 500 rows a page.
    pub(super) fn network_packets(
        &self,
        params: &NetworkPacketsParams,
        cancel: &AtomicBool,
    ) -> Result<Page<PacketRow>, ApiError> {
        let max = self.settings.limits.row.packets;
        let request = PageRequest {
            limit: params.limit,
            cursor: params.cursor.clone(),
        };
        let limit = request.effective_limit(max, max)? as usize;
        let filter = params.filter.clone().unwrap_or_default();
        if filter.len() > 4096 {
            return Err(ApiError::invalid_argument("filter", "at most 4096 bytes"));
        }
        let opened = self.open_run(&params.run_key)?;
        let binding = opened.binding(&(&params.capture_id, &filter), &serde_json::Value::Null);
        let start = match &request.cursor {
            Some(text) => Cursor::resume(text, binding)?,
            None => 0,
        };
        let session = self.session(&opened, &params.capture_id, cancel)?;
        let index = session.index(&filter)?;
        // Without a filter the rows needed are the first `start + limit`; with
        // one the matching frames can be anywhere, so the parse is waited for.
        let needed = filter.trim().is_empty().then_some(start + limit as u64);
        let status = session.wait_rows(&index, needed)?;
        let generation = session.worker.request_page(Arc::clone(&index), start);
        let (rows_done, result) = match session.event(generation, false)? {
            PacketFilterEvent::Page {
                rows_done, result, ..
            } => (rows_done, result),
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "unexpected packet worker event",
                ));
            }
        };
        let packets = result.map_err(|e| super::errors::text_error(&e, &self.scrub))?;
        let _ = rows_done;
        // What made each packet needs the run's calls: one Triage index, kept.
        let attribution = self.attribution(&opened);
        let rows: Vec<PacketRow> = packets
            .iter()
            .take(limit)
            .map(|packet| {
                let made_by = attribution
                    .as_deref()
                    .map(|found| super::attribution::made_by(found, packet, &self.scrub));
                row_of(packet, made_by)
            })
            .collect();
        let total = index.matching_count;
        let next = start + rows.len() as u64;
        let mut page = opened.page(rows, true);
        page.total = Some(total);
        // The parse may have finished while the page was read.
        let after = index.rows().status();
        page.total_exact = Some(!matches!(after, ParseStatus::Parsing) && !session.live);
        if matches!(status, ParseStatus::Failed(_)) || matches!(after, ParseStatus::Failed(_)) {
            page.partial = Some(true);
        }
        page.next_cursor = (next < total && !page.items.is_empty()).then(|| {
            Cursor {
                offset: next,
                binding,
            }
            .encode()
        });
        session.worker.release();
        Ok(page)
    }

    /// `recording.network.packet`: one packet decoded, with its bytes.
    pub(super) fn network_packet(
        &self,
        params: &NetworkPacketParams,
        cancel: &AtomicBool,
    ) -> Result<Single<PacketDetail>, ApiError> {
        if params.n == 0 {
            return Err(ApiError::invalid_argument("n", "frames count from 1"));
        }
        let opened = self.open_run(&params.run_key)?;
        let session = self.session(&opened, &params.capture_id, cancel)?;
        let index = session.index("")?;
        if params.n > index.packet_count() {
            return Err(ApiError::not_found("packet"));
        }
        session.wait_rows(&index, Some(params.n))?;
        let generation = session.worker.request_frame(Arc::clone(&index), params.n);
        let offset = match session.event(generation, false)? {
            PacketFilterEvent::Frame { result, .. } => {
                result
                    .map_err(|e| super::errors::text_error(&e, &self.scrub))?
                    .0
                    .offset
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "unexpected packet worker event",
                ));
            }
        };
        let bytes = index
            .frame(offset)
            .map_err(|e| super::errors::text_error(&e, &self.scrub))?;
        let generation = session.worker.request_detail(Arc::clone(&index), params.n);
        let detail = match session.event(generation, true)? {
            PacketFilterEvent::Detail { result, .. } => {
                result.map_err(|e| super::errors::text_error(&e, &self.scrub))?
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "unexpected packet worker event",
                ));
            }
        };
        let value = PacketDetail {
            n: detail.number,
            frame_len: u32::try_from(detail.frame_len).unwrap_or(u32::MAX),
            tree: DetailTree {
                nodes: detail
                    .tree
                    .nodes
                    .iter()
                    .map(|node| DetailNode {
                        depth: u32::from(node.depth),
                        label: node.label.clone(),
                        name: node.name.clone(),
                        start: u32::try_from(node.start).unwrap_or(u32::MAX),
                        len: u32::try_from(node.len).unwrap_or(u32::MAX),
                        end: u32::try_from(node.end).unwrap_or(u32::MAX),
                    })
                    .collect(),
                cut: detail.tree.cut,
            },
            bytes: base64(&bytes),
        };
        session.worker.release();
        Ok(opened.single(value, true))
    }
}
