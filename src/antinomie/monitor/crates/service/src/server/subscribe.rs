// SPDX-License-Identifier: GPL-3.0-only
//! `events.subscribe` (design 5.5, 5.9): stored events after the client's
//! resume point, then live ones, with no gap and no duplicate.
//!
//! The order of work is what makes it gap-free: subscribe to the store's live
//! channel first, then read the table after the resume point, then follow the
//! channel and skip what the table already gave (by `gseq` on the all-jobs
//! stream, by `seq` on a job's). The store publishes in commit order while it
//! still holds its connection, so the channel never delivers a later event
//! before an earlier one. If the channel overflows (the client is slower than
//! the event rate, or another job is very busy), the stream subscribes again
//! and re-reads the table from the last event it sent: nothing is lost.
//! Ephemeral events (`job.progress`, `job.metrics`) are never replayed.
//!
//! | Stream | Resume point | Without one |
//! |---|---|---|
//! | one job (`job_id`) | `since_seq` | the job's whole history |
//! | all jobs and the engine | `since_gseq` | from now |
//!
//! A job stream ends with a result line once `job.finished` has passed (that
//! is the job's last event). Every stream ends on `cancel`, when the daemon
//! stops, or when the client cannot take a line within the write timeout
//! (`slow_consumer`).

use super::limits::Limits;
use crate::{
    api::{
        error::ApiError,
        event::{Event, EventBody, EventScope, Frame, Hello},
        ids::JobId,
        ops::{EventsSubscribeParams, Reply},
    },
    store::{Store, Subscription},
};
use std::{
    collections::BTreeSet,
    io,
    sync::atomic::{AtomicBool, Ordering},
    sync::mpsc::RecvTimeoutError,
    time::{Duration, Instant},
};

/// The stored event types a subscription may ask for (`types`), plus the
/// ephemeral ones.
pub const EVENT_TYPES: [&str; 14] = [
    "job.created",
    "job.state",
    "job.stage",
    "job.progress",
    "job.run",
    "job.warning",
    "job.artifact",
    "job.assessment",
    "job.requeued",
    "job.finished",
    "lane.state",
    "engine.alert",
    "job.metrics",
    // Accepted so a client may name every type of 5.5 without an error.
    "engine.ping",
];

/// How a stream ended. The caller writes the last line.
#[derive(Debug, PartialEq, Eq)]
pub enum StreamEnd {
    /// The job's `job.finished` has been sent (job streams only).
    Finished { last_seq: u64 },
    /// `{"op": "cancel"}` or the connection closing.
    Cancelled { last_seq: u64, last_gseq: u64 },
    /// The daemon is stopping.
    Stopping,
    /// A line could not be written within the write timeout.
    SlowConsumer,
    /// The connection failed.
    Closed,
}

fn type_name(body: &EventBody) -> String {
    serde_json::to_value(body)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_owned))
        .unwrap_or_default()
}

/// The checked request.
struct Wanted {
    job: Option<JobId>,
    types: Option<BTreeSet<String>>,
}

impl Wanted {
    fn wants(&self, event: &Event) -> bool {
        if let Some(job) = &self.job
            && event.job_id.as_ref() != Some(job)
        {
            return false;
        }
        self.types
            .as_ref()
            .is_none_or(|types| types.contains(&type_name(&event.body)))
    }
}

fn check(params: &EventsSubscribeParams) -> Result<Wanted, ApiError> {
    if params.job_id.is_some() && params.since_gseq.is_some() {
        return Err(ApiError::invalid_argument(
            "since_gseq",
            "a job's stream resumes by since_seq",
        ));
    }
    if params.job_id.is_none() && params.since_seq.is_some() {
        return Err(ApiError::invalid_argument(
            "since_seq",
            "the all-jobs stream resumes by since_gseq",
        ));
    }
    let types = match &params.types {
        None => None,
        Some(list) => {
            if list.is_empty() || list.len() > EVENT_TYPES.len() {
                return Err(ApiError::invalid_argument("types", "1 to 14 event types"));
            }
            let mut set = BTreeSet::new();
            for name in list {
                if !EVENT_TYPES.contains(&name.as_str()) {
                    return Err(ApiError::invalid_argument(
                        "types",
                        format!("unknown event type {name:?}"),
                    ));
                }
                set.insert(name.clone());
            }
            Some(set)
        }
    };
    Ok(Wanted {
        job: params.job_id.clone(),
        types,
    })
}

fn hello_reply(id: u64, hello: Hello) -> Reply {
    Reply {
        id,
        ok: None,
        result: None,
        error: None,
        event: None,
        frame: Some(Frame::Hello(hello)),
    }
}

fn ping_reply(id: u64) -> Reply {
    Reply {
        id,
        ok: None,
        result: None,
        error: None,
        event: None,
        frame: Some(Frame::Ping {}),
    }
}

/// The final line a slow consumer is sent, when it can still take one.
pub fn slow_consumer_line(id: u64, now_ms: u64) -> Reply {
    Reply::event(
        id,
        Event {
            seq: None,
            gseq: None,
            ts_ms: now_ms,
            scope: EventScope::Engine,
            job_id: None,
            body: EventBody::EngineAlert {
                code: "slow_consumer".into(),
                text: "the subscription fell behind and is closed; resume with since_seq or since_gseq"
                    .into(),
            },
        },
    )
}

/// Where the stream stands.
struct Cursor {
    last_seq: u64,
    last_gseq: u64,
    finished: bool,
}

struct Run<'a> {
    store: &'a Store,
    id: u64,
    wanted: Wanted,
    cursor: Cursor,
    sink: &'a mut dyn FnMut(&Reply) -> io::Result<()>,
    last_write: Instant,
}

enum Sent {
    Ok,
    End(StreamEnd),
}

fn sink_end(error: &io::Error) -> StreamEnd {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        StreamEnd::SlowConsumer
    } else {
        StreamEnd::Closed
    }
}

impl Run<'_> {
    fn write(&mut self, reply: &Reply) -> Sent {
        match (self.sink)(reply) {
            Ok(()) => {
                self.last_write = Instant::now();
                Sent::Ok
            }
            Err(error) => Sent::End(sink_end(&error)),
        }
    }

    /// Send a stored event unless the stream has passed it; track the cursor.
    fn stored(&mut self, event: Event) -> Sent {
        let (Some(seq), Some(gseq)) = (event.seq, event.gseq) else {
            return Sent::Ok;
        };
        if self.wanted.job.is_some() {
            if event.job_id != self.wanted.job || seq <= self.cursor.last_seq {
                return Sent::Ok;
            }
            self.cursor.last_seq = seq;
        } else if gseq <= self.cursor.last_gseq {
            return Sent::Ok;
        }
        self.cursor.last_gseq = self.cursor.last_gseq.max(gseq);
        let finished = matches!(event.body, EventBody::JobFinished { .. });
        if self.wanted.wants(&event)
            && let Sent::End(end) = self.write(&Reply::event(self.id, event))
        {
            return Sent::End(end);
        }
        if finished && self.wanted.job.is_some() {
            self.cursor.finished = true;
        }
        Sent::Ok
    }

    /// The table after the cursor, in pages.
    fn backlog(&mut self) -> Result<Sent, ApiError> {
        loop {
            let page = match &self.wanted.job {
                Some(job) => self.store.events_list(job, self.cursor.last_seq, 1000)?.0,
                None => self.store.events_since(self.cursor.last_gseq, 1000)?,
            };
            if page.is_empty() {
                return Ok(Sent::Ok);
            }
            for event in page {
                if let Sent::End(end) = self.stored(event) {
                    return Ok(Sent::End(end));
                }
                if self.cursor.finished {
                    return Ok(Sent::Ok);
                }
            }
        }
    }
}

/// Serve one subscription until it ends. Errors before the first line (a bad
/// request, an unknown job) are returned; after it, the end is a
/// [`StreamEnd`]. `hello` carries the daemon's version, owner and epoch; the
/// stream fills in `gseq` and `truncated`.
#[allow(clippy::too_many_arguments)]
pub fn stream(
    store: &Store,
    id: u64,
    params: &EventsSubscribeParams,
    mut hello: Hello,
    limits: &Limits,
    cancel: &AtomicBool,
    stopping: &AtomicBool,
    sink: &mut dyn FnMut(&Reply) -> io::Result<()>,
) -> Result<StreamEnd, ApiError> {
    let wanted = check(params)?;
    if let Some(job) = &wanted.job {
        store.get(job)?;
    }
    let mut subscription: Subscription = store.subscribe_bounded(limits.subscription_backlog);
    let highest = store.highest_gseq()?;
    let mut truncated = false;
    let start_gseq = match (&wanted.job, params.since_gseq) {
        (Some(_), _) => 0,
        (None, None) => highest,
        (None, Some(since)) if since > highest => {
            // A resume point this store never reached: another store, or one
            // restored from a backup. Start from now and say so.
            truncated = true;
            highest
        }
        (None, Some(since)) => {
            let oldest = store.oldest_retained_gseq()?;
            truncated = since < highest && oldest.is_some_and(|oldest| since + 1 < oldest);
            since
        }
    };
    hello.gseq = highest;
    hello.truncated = truncated;
    let mut run = Run {
        store,
        id,
        wanted,
        cursor: Cursor {
            last_seq: params.since_seq.unwrap_or(0),
            last_gseq: start_gseq,
            finished: false,
        },
        sink,
        last_write: Instant::now(),
    };
    if let Sent::End(end) = run.write(&hello_reply(id, hello)) {
        return Ok(end);
    }
    loop {
        if let Sent::End(end) = run.backlog()? {
            return Ok(end);
        }
        if run.cursor.finished {
            return Ok(StreamEnd::Finished {
                last_seq: run.cursor.last_seq,
            });
        }
        // Live, until the channel overflows (then re-read the table).
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Ok(StreamEnd::Cancelled {
                    last_seq: run.cursor.last_seq,
                    last_gseq: run.cursor.last_gseq,
                });
            }
            if stopping.load(Ordering::SeqCst) {
                // What was committed before the stop still goes out (a job's
                // `job.finished` at shutdown among it).
                while let Ok(event) = subscription.events.try_recv() {
                    let sent = if event.gseq.is_none() {
                        Sent::Ok
                    } else {
                        run.stored(event)
                    };
                    if let Sent::End(end) = sent {
                        return Ok(end);
                    }
                    if run.cursor.finished {
                        return Ok(StreamEnd::Finished {
                            last_seq: run.cursor.last_seq,
                        });
                    }
                }
                return Ok(StreamEnd::Stopping);
            }
            if subscription.overflowed.load(Ordering::SeqCst) {
                break;
            }
            match subscription
                .events
                .recv_timeout(limits.tick.min(Duration::from_millis(200)))
            {
                Ok(event) if event.gseq.is_none() => {
                    // Ephemeral: forwarded live only.
                    if run.wanted.wants(&event)
                        && let Sent::End(end) = run.write(&Reply::event(id, event))
                    {
                        return Ok(end);
                    }
                }
                Ok(event) => {
                    if let Sent::End(end) = run.stored(event) {
                        return Ok(end);
                    }
                    if run.cursor.finished {
                        return Ok(StreamEnd::Finished {
                            last_seq: run.cursor.last_seq,
                        });
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if run.last_write.elapsed() >= limits.ping_every
                        && let Sent::End(end) = run.write(&ping_reply(id))
                    {
                        return Ok(end);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        subscription = store.subscribe_bounded(limits.subscription_backlog);
    }
}
