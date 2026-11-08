// SPDX-License-Identifier: GPL-3.0-only
//! `recording.timeline` (design 5.12.3 class T, card Q-4): the events of the
//! Triage scan merged in time order. No merged timeline exists in the engine,
//! so this one is composed from the scan's own models: process start and exit
//! (the process tree), findings, changed and executed files, and network
//! first-seen rows. Events whose guest time cannot be mapped to the host clock
//! (no clock anchor) are left out and the page says `partial`.

use super::{
    page::{Page, PageRequest},
    request::TimelineParams,
    service::QueryService,
    tables::{self, V},
    triage::{finding_id, tier_of},
    types::*,
};
use crate::api::error::{ApiError, ErrorCode};
use antinomie_triage::ScanData;

/// The longest title.
const TITLE: usize = 200;

struct Event {
    ts_ms: u64,
    sort_id: String,
    event: TimelineEvent,
}

fn title(text: impl AsRef<str>) -> String {
    text.as_ref().chars().take(TITLE).collect()
}

fn rank(kind: TimelineKind) -> u8 {
    match kind {
        TimelineKind::ProcessStart => 0,
        TimelineKind::ProcessExit => 1,
        TimelineKind::Finding => 2,
        TimelineKind::File => 3,
        TimelineKind::Network => 4,
        TimelineKind::Detection => 5,
    }
}

impl QueryService {
    fn timeline_events(
        &self,
        opened: &super::service::Opened,
        scan: &ScanData,
        captures: &[(String, String)],
        unmapped: &mut bool,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        let mut add = |ts: Option<u64>,
                       sort_id: String,
                       event: TimelineEvent,
                       unmapped: &mut bool| {
            match ts {
                Some(ts_ms) => events.push(Event {
                    ts_ms,
                    sort_id,
                    event,
                }),
                None => *unmapped = true,
            }
        };
        for node in scan.process.iter().filter(|node| !node.thread) {
            let name = node
                .argv
                .first()
                .cloned()
                .unwrap_or_else(|| node.comm.clone());
            let target = |node: &antinomie_triage::ProcessNode| {
                let (stream, task, call) = node.call_id.unwrap_or((0, node.cookie, 0));
                TimelineRef::Call(CallRef {
                    stream: U64(stream),
                    task: U64(task),
                    call: U64(call),
                })
            };
            if let Some(first) = node.first_ns {
                add(
                    opened.ts_ms(first),
                    format!("p{:020}s", node.cookie),
                    TimelineEvent {
                        ts_ms: 0,
                        guest_ns: Some(first),
                        kind: TimelineKind::ProcessStart,
                        pid: Some(node.pid),
                        tier: None,
                        title: title(format!("{name} (pid {}) started", node.pid)),
                        target: target(node),
                    },
                    unmapped,
                );
            }
            if let (Some(last), true) = (node.last_ns, node.state.starts_with("task exit")) {
                add(
                    opened.ts_ms(last),
                    format!("p{:020}x", node.cookie),
                    TimelineEvent {
                        ts_ms: 0,
                        guest_ns: Some(last),
                        kind: TimelineKind::ProcessExit,
                        pid: Some(node.pid),
                        tier: None,
                        title: title(format!("{name} (pid {}) exited: {}", node.pid, node.state)),
                        target: target(node),
                    },
                    unmapped,
                );
            }
        }
        for finding in &scan.findings {
            let v = V(&finding.values);
            let first = v.u64("finding.first_ns");
            let id = finding_id(opened, finding);
            add(
                opened.ts_ms(first),
                id.clone(),
                TimelineEvent {
                    ts_ms: 0,
                    guest_ns: Some(first),
                    kind: TimelineKind::Finding,
                    pid: Some(v.u32("process.pid")),
                    tier: Some(tier_of(&v.text("finding.tier"))),
                    title: title(format!(
                        "{}: {}",
                        v.text("finding.rule"),
                        v.text("finding.summary")
                    )),
                    target: TimelineRef::Finding { finding_id: id },
                },
                unmapped,
            );
        }
        for change in &scan.file_changes {
            let id = super::files::changed_id(opened, change);
            add(
                opened.ts_ms(change.first_ns),
                id.clone(),
                TimelineEvent {
                    ts_ms: 0,
                    guest_ns: Some(change.first_ns),
                    kind: TimelineKind::File,
                    pid: Some(change.pid),
                    tier: None,
                    title: title(format!("changed {}", change.path)),
                    target: TimelineRef::File { file_id: id },
                },
                unmapped,
            );
        }
        // Executed files: slot 12 of the operation tabs.
        for row in &scan.file_tabs[4].rows {
            let values = tables::values_of(row);
            let operation = super::files::operation_row(opened, values);
            add(
                operation.ts_ms,
                operation.file_id.clone(),
                TimelineEvent {
                    ts_ms: 0,
                    guest_ns: Some(operation.guest_ns),
                    kind: TimelineKind::File,
                    pid: Some(operation.process.pid),
                    tier: None,
                    title: title(format!("{} {}", operation.operation, operation.path)),
                    target: TimelineRef::File {
                        file_id: operation.file_id.clone(),
                    },
                },
                unmapped,
            );
        }
        let capture_of = |path: &str| {
            captures
                .iter()
                .find(|(known, _)| known == path)
                .map(|(_, id)| id.clone())
                .unwrap_or_default()
        };
        let mut network = |rows: &[Vec<antinomie_triage::Cell>],
                           time: &str,
                           text: &dyn Fn(&V<'_>) -> String,
                           events: &mut Vec<Event>| {
            for row in rows {
                let v = V(tables::values_of(row));
                let Some(us) = v.opt_u64(time) else {
                    *unmapped = true;
                    continue;
                };
                let frame = v.u64("frame.number");
                let capture_id = capture_of(&v.text("capture.path"));
                events.push(Event {
                    ts_ms: us / 1000,
                    sort_id: format!("{capture_id}:{frame:020}"),
                    event: TimelineEvent {
                        ts_ms: 0,
                        guest_ns: None,
                        kind: TimelineKind::Network,
                        pid: None,
                        tier: None,
                        title: title(text(&v)),
                        target: TimelineRef::Frame { capture_id, frame },
                    },
                });
            }
        };
        network(
            &scan.new_tabs.endpoints,
            "network.first_us",
            &|v| format!("first packet with {}", v.text("network.endpoint")),
            &mut events,
        );
        network(
            &scan.new_tabs.domains,
            "network.first_us",
            &|v| format!("name {}", v.text("network.hostname")),
            &mut events,
        );
        network(
            &scan.http,
            "frame.time_us",
            &|v| {
                format!(
                    "{} {}{}",
                    v.text("http.method"),
                    v.text("http.host"),
                    v.text("http.uri")
                )
            },
            &mut events,
        );
        events
    }

    /// `recording.timeline`.
    pub(super) fn timeline(
        &self,
        params: &TimelineParams,
    ) -> Result<Page<TimelineEvent>, ApiError> {
        let opened = self.open_run(&params.run_key)?;
        if (params.from_ms.is_some() || params.to_ms.is_some()) && opened.run.clock_anchor.is_none()
        {
            return Err(ApiError::new(
                ErrorCode::Unsupported,
                "this run has no clock anchor, so it cannot be cut by host time",
            )
            .with_field("from_ms"));
        }
        let mut kinds = params.kinds.clone();
        kinds.sort_by_key(|kind| rank(*kind));
        kinds.dedup();
        let binding = opened.binding(&(params.from_ms, params.to_ms, &kinds), &None::<()>);
        let scanned = match self.triage_scan(&opened)? {
            Err(building) => {
                return Ok(Page::building(
                    opened.generation,
                    opened.phase.phase,
                    building,
                ));
            }
            Ok(scanned) => scanned,
        };
        let captures = self.capture_paths(&opened);
        let mut unmapped = false;
        let mut events = self.timeline_events(&opened, &scanned.scan, &captures, &mut unmapped);
        events.retain(|e| {
            (kinds.is_empty() || kinds.contains(&e.event.kind))
                && params.from_ms.is_none_or(|from| e.ts_ms >= from)
                && params.to_ms.is_none_or(|to| e.ts_ms <= to)
        });
        events.sort_by(|a, b| {
            (a.ts_ms, rank(a.event.kind), &a.sort_id).cmp(&(
                b.ts_ms,
                rank(b.event.kind),
                &b.sort_id,
            ))
        });
        let order: Vec<usize> = (0..events.len()).collect();
        let cut = tables::Cut {
            request: &PageRequest {
                limit: params.limit,
                cursor: params.cursor.clone(),
            },
            max: self.settings.rows().1,
            binding,
            omitted: 0,
            untrusted: true,
        };
        let mut page = tables::page_of(&opened, &order, &cut, |at| {
            let mut event = events[at].event.clone();
            event.ts_ms = events[at].ts_ms;
            event
        })?;
        if unmapped {
            page.partial = Some(true);
        }
        Ok(page)
    }
}
