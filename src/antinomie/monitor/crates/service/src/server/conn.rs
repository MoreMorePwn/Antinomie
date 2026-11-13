// SPDX-License-Identifier: GPL-3.0-only
//! One connection of the local socket: the hello, the request lines, the
//! requests in flight on their own threads, `cancel`, the subscriptions, and
//! the limits of [`super::limits`].

use super::{
    CallContext, Handler, Shared, Transport,
    frame::{LineReader, Next, encode, parse_request},
    limits::{Bucket, Limits},
    local_caller,
    subscribe::{self, StreamEnd},
};
use crate::api::{
    error::{ApiError, ErrorCode, ErrorReason},
    event::Frame,
    ops::{EventsSubscribeParams, Reply, Request},
};
use serde_json::json;
use std::{
    collections::HashMap,
    io::{self, Write},
    os::unix::net::UnixStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// The writing half: whole lines under a lock, each within the write timeout.
pub(super) struct Writer {
    stream: Mutex<UnixStream>,
    dead: AtomicBool,
    timeout: Duration,
}

impl Writer {
    fn new(stream: UnixStream, timeout: Duration) -> Self {
        Self {
            stream: Mutex::new(stream),
            dead: AtomicBool::new(false),
            timeout,
        }
    }

    fn write_within(&self, bytes: &[u8], limit: Duration) -> io::Result<()> {
        let mut stream = crate::store::lock(&self.stream);
        let deadline = Instant::now() + limit;
        let mut rest = bytes;
        while !rest.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "write timed out"));
            }
            stream.set_write_timeout(Some(left))?;
            match stream.write(rest) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => rest = &rest[n..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Write one reply line. Any failure marks the connection dead.
    pub(super) fn send(&self, reply: &Reply) -> io::Result<()> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let result = self.write_within(&encode(reply), self.timeout);
        if result.is_err() {
            self.dead.store(true, Ordering::SeqCst);
        }
        result
    }

    /// A last line for a connection that is closing (a slow consumer may
    /// still take it); one second at most.
    fn send_last(&self, reply: &Reply) {
        let _ = self.write_within(&encode(reply), Duration::from_secs(1));
    }

    fn close(&self) {
        self.dead.store(true, Ordering::SeqCst);
        let _ = crate::store::lock(&self.stream).shutdown(std::net::Shutdown::Both);
    }
}

fn quota(reason: ErrorReason, message: &str) -> ApiError {
    ApiError::new(ErrorCode::QuotaExceeded, message).with_reason(reason)
}

/// A 65th connection: one line saying why, then closed.
pub(super) fn refuse_full(stream: UnixStream, limits: &Limits) {
    let writer = Writer::new(stream, Duration::from_secs(1));
    writer.send_last(&Reply::failed(
        0,
        ApiError::new(
            ErrorCode::Unavailable,
            format!(
                "the daemon serves {} connections already",
                limits.connections
            ),
        )
        .with_reason(ErrorReason::TooManyConnections),
    ));
    writer.close();
}

/// Requests of this connection in flight, by id, with their cancel flags.
type InFlight = Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>>;

struct Connection<'a> {
    handler: Arc<dyn Handler>,
    limits: &'a Limits,
    shared: &'a Arc<Shared>,
    writer: Arc<Writer>,
    in_flight: InFlight,
    rate: Bucket,
    client: String,
    uid: u32,
}

/// Releases the counters of a request when its thread ends.
struct Slot {
    in_flight: InFlight,
    shared: Arc<Shared>,
    id: u64,
    subscription_of: Option<String>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        crate::store::lock(&self.in_flight).remove(&self.id);
        self.shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        if let Some(client) = &self.subscription_of {
            let mut subscriptions = crate::store::lock(&self.shared.subscriptions);
            if let Some(count) = subscriptions.get_mut(client) {
                *count = count.saturating_sub(1);
            }
        }
    }
}

pub(super) fn serve(
    stream: UnixStream,
    uid: u32,
    handler: Arc<dyn Handler>,
    limits: &Limits,
    shared: &Arc<Shared>,
) {
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    if stream.set_read_timeout(Some(limits.tick)).is_err() {
        return;
    }
    let writer = Arc::new(Writer::new(write_half, limits.write_timeout));
    // The first line is the hello frame itself, with no request id (5.9).
    let mut hello = serde_json::to_vec(&Frame::Hello(handler.hello())).unwrap_or_default();
    hello.push(b'\n');
    if writer.write_within(&hello, limits.write_timeout).is_err() {
        writer.close();
        return;
    }
    let mut connection = Connection {
        handler,
        limits,
        shared,
        writer: Arc::clone(&writer),
        in_flight: Arc::new(Mutex::new(HashMap::new())),
        rate: Bucket::new(limits.rate_per_s, limits.burst),
        client: local_caller(uid).client_id,
        uid,
    };
    connection.read_loop(stream);
    for flag in crate::store::lock(&connection.in_flight).values() {
        flag.store(true, Ordering::SeqCst);
    }
    writer.close();
}

impl Connection<'_> {
    fn read_loop(&mut self, stream: UnixStream) {
        let mut reader = LineReader::with_limit(stream, self.limits.max_line);
        let mut last_activity = Instant::now();
        let mut partial_since: Option<Instant> = None;
        loop {
            if self.shared.stopping.load(Ordering::SeqCst)
                || self.writer.dead.load(Ordering::SeqCst)
            {
                return;
            }
            match reader.next_line() {
                Err(_) | Ok(Next::Eof) => return,
                Ok(Next::TooLong) => {
                    self.writer.send_last(&Reply::failed(
                        0,
                        ApiError::payload_too_large(self.limits.max_line as u64),
                    ));
                    return;
                }
                Ok(Next::Tick { partial }) => {
                    let now = Instant::now();
                    if partial {
                        let since = *partial_since.get_or_insert(now);
                        if now.duration_since(since) > self.limits.partial_line {
                            return;
                        }
                    }
                    let busy = !crate::store::lock(&self.in_flight).is_empty();
                    if busy {
                        last_activity = now;
                    } else if now.duration_since(last_activity) > self.limits.idle {
                        return;
                    }
                }
                Ok(Next::Line(line)) => {
                    partial_since = None;
                    last_activity = Instant::now();
                    self.line(&line);
                }
            }
        }
    }

    fn reply(&self, reply: Reply) {
        let _ = self.writer.send(&reply);
    }

    fn line(&mut self, line: &[u8]) {
        let request = match parse_request(line) {
            Ok(request) => request,
            Err(bad) => return self.reply(Reply::failed(bad.id, bad.error)),
        };
        let now = Instant::now();
        let limited = self
            .rate
            .take(now)
            .and_then(|()| crate::store::lock(&self.shared.global_rate).take(now));
        if let Err(after) = limited {
            return self.reply(Reply::failed(
                request.id,
                quota(ErrorReason::RateLimited, "too many requests; slow down")
                    .with_detail("retry_after_s", json!(after)),
            ));
        }
        if request.op == "cancel" {
            return self.cancel(request.id);
        }
        {
            let in_flight = crate::store::lock(&self.in_flight);
            if in_flight.contains_key(&request.id) {
                drop(in_flight);
                return self.reply(Reply::failed(
                    request.id,
                    ApiError::new(
                        ErrorCode::Conflict,
                        "a request with this id is still in flight",
                    )
                    .with_field("id"),
                ));
            }
            if in_flight.len() >= self.limits.in_flight_per_connection {
                drop(in_flight);
                return self.reply(Reply::failed(
                    request.id,
                    quota(
                        ErrorReason::TooManyRequests,
                        "16 requests of this connection are in flight",
                    ),
                ));
            }
        }
        if self.shared.in_flight.fetch_add(1, Ordering::SeqCst) >= self.limits.in_flight_total {
            self.shared.in_flight.fetch_sub(1, Ordering::SeqCst);
            return self.reply(Reply::failed(
                request.id,
                quota(
                    ErrorReason::TooManyRequests,
                    "the daemon has too many requests in flight",
                ),
            ));
        }
        let cancel = Arc::new(AtomicBool::new(false));
        crate::store::lock(&self.in_flight).insert(request.id, Arc::clone(&cancel));
        let mut slot = Slot {
            in_flight: Arc::clone(&self.in_flight),
            shared: Arc::clone(self.shared),
            id: request.id,
            subscription_of: None,
        };
        if request.op == "events.subscribe" {
            match self.admit_subscription() {
                Ok(()) => slot.subscription_of = Some(self.client.clone()),
                Err(error) => {
                    drop(slot);
                    return self.reply(Reply::failed(request.id, error));
                }
            }
        }
        self.spawn(request, cancel, slot);
    }

    fn cancel(&self, id: u64) {
        let flag = crate::store::lock(&self.in_flight).get(&id).cloned();
        match flag {
            // The request answers for itself (a result or an error).
            Some(flag) => flag.store(true, Ordering::SeqCst),
            None => self.reply(Reply::failed(
                id,
                ApiError::not_found("request in flight").with_field("id"),
            )),
        }
    }

    fn admit_subscription(&self) -> Result<(), ApiError> {
        let mut subscriptions = crate::store::lock(&self.shared.subscriptions);
        let total: usize = subscriptions.values().sum();
        let mine = subscriptions.entry(self.client.clone()).or_insert(0);
        if *mine >= self.limits.subscriptions_per_client || total >= self.limits.subscriptions_total
        {
            return Err(quota(
                ErrorReason::TooManySubscriptions,
                "too many event subscriptions are open",
            ));
        }
        *mine += 1;
        Ok(())
    }

    fn spawn(&self, request: Request, cancel: Arc<AtomicBool>, slot: Slot) {
        let handler = Arc::clone(&self.handler);
        let writer = Arc::clone(&self.writer);
        let limits = self.limits.clone();
        let shared = Arc::clone(self.shared);
        let ctx = CallContext {
            caller: local_caller(self.uid),
            cancel,
            transport: Transport::Socket,
        };
        let id = request.id;
        let spawned = std::thread::Builder::new()
            .name("antinomie-request".into())
            .spawn(move || {
                let _slot = slot;
                if request.op == "events.subscribe" {
                    subscription(&*handler, &writer, &limits, &shared, request, &ctx);
                } else {
                    let reply = match handler.call(&request.op, request.params, &ctx) {
                        Ok(result) => Reply::ok(request.id, result),
                        Err(error) => Reply::failed(request.id, error),
                    };
                    let _ = writer.send(&reply);
                }
            });
        if spawned.is_err() {
            self.reply(Reply::failed(
                id,
                ApiError::new(ErrorCode::Unavailable, "no thread for the request"),
            ));
        }
    }
}

fn subscription(
    handler: &dyn Handler,
    writer: &Writer,
    limits: &Limits,
    shared: &Shared,
    request: Request,
    ctx: &CallContext,
) {
    let params: EventsSubscribeParams = match serde_json::from_value(request.params) {
        Ok(params) => params,
        Err(error) => {
            let _ = writer.send(&Reply::failed(
                request.id,
                ApiError::invalid_argument("params", error.to_string()),
            ));
            return;
        }
    };
    let store = handler.store();
    let mut sink = |reply: &Reply| writer.send(reply);
    let end = subscribe::stream(
        store,
        request.id,
        &params,
        &ctx.caller,
        handler.hello(),
        limits,
        &ctx.cancel,
        &shared.stopping,
        &mut sink,
    );
    let last = match end {
        Err(error) => Reply::failed(request.id, error),
        Ok(StreamEnd::Finished { last_seq }) => {
            Reply::ok(request.id, json!({"finished": true, "last_seq": last_seq}))
        }
        Ok(StreamEnd::Cancelled {
            last_seq,
            last_gseq,
        }) => Reply::ok(
            request.id,
            json!({"cancelled": true, "last_seq": last_seq, "last_gseq": last_gseq}),
        ),
        Ok(StreamEnd::Stopping) => Reply::failed(
            request.id,
            ApiError::new(ErrorCode::Unavailable, "the daemon is stopping")
                .with_reason(ErrorReason::ServiceStopping),
        ),
        Ok(StreamEnd::SlowConsumer) => {
            writer.send_last(&subscribe::slow_consumer_line(request.id, store.now_ms()));
            writer.close();
            return;
        }
        Ok(StreamEnd::Closed) => return,
    };
    let _ = writer.send(&last);
}
