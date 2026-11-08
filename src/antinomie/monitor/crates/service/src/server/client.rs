// SPDX-License-Identifier: GPL-3.0-only
//! The client end of the local socket (design 5.9): `antinomie-cli` in client
//! mode and the tests use it. One request at a time; a subscription reads its
//! lines until the stream ends.

use super::frame::{LineReader, MAX_LINE, Next};
use crate::api::{
    error::ApiError,
    event::{Event, Frame, Hello},
    ops::{Reply, Request},
};
use serde_json::Value;
use std::{
    io::{self, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// No daemon answers at the socket (no file, refused, or not a socket).
    #[error("no daemon answers at the socket: {0}")]
    NoDaemon(io::Error),
    #[error("socket: {0}")]
    Io(#[from] io::Error),
    #[error("protocol: {0}")]
    Protocol(String),
    /// The daemon answered with an error.
    #[error("{}", .0.message)]
    Api(ApiError),
    /// The caller's deadline passed.
    #[error("timed out")]
    TimedOut,
    /// The caller's interrupt check said stop.
    #[error("interrupted")]
    Interrupted,
}

/// A line of a subscription.
#[derive(Clone, Debug, PartialEq)]
pub enum Streamed {
    Hello(Hello),
    Event(Box<Event>),
    Ping,
}

pub struct Client {
    reader: LineReader<UnixStream>,
    writer: UnixStream,
    hello: Hello,
    next_id: u64,
    deadline: Option<Instant>,
    interrupted: Option<Box<dyn Fn() -> bool + Send>>,
}

const TICK: Duration = Duration::from_millis(200);

impl Client {
    /// Connect and read the hello frame (within `limit`).
    pub fn connect(path: &Path, limit: Duration) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(path).map_err(ClientError::NoDaemon)?;
        stream.set_read_timeout(Some(TICK))?;
        let writer = stream.try_clone()?;
        let mut client = Self {
            reader: LineReader::with_limit(stream, MAX_LINE),
            writer,
            hello: Hello {
                api_version: 0,
                app_version: String::new(),
                owner: crate::api::event::HelloOwner::Daemon,
                epoch: String::new(),
                gseq: 0,
                truncated: false,
            },
            next_id: 1,
            deadline: Some(Instant::now() + limit),
            interrupted: None,
        };
        let line = client.line()?;
        let value: Value = serde_json::from_slice(&line)
            .map_err(|e| ClientError::Protocol(format!("first line: {e}")))?;
        if let Some(error) = value.get("error") {
            let error: ApiError = serde_json::from_value(error.clone())
                .map_err(|e| ClientError::Protocol(e.to_string()))?;
            return Err(ClientError::Api(error));
        }
        match serde_json::from_value::<Frame>(value) {
            Ok(Frame::Hello(hello)) if hello.api_version == crate::API_VERSION => {
                client.hello = hello;
            }
            Ok(Frame::Hello(hello)) => {
                return Err(ClientError::Protocol(format!(
                    "the daemon speaks api_version {}; this client knows {}",
                    hello.api_version,
                    crate::API_VERSION
                )));
            }
            _ => return Err(ClientError::Protocol("no engine.hello frame".into())),
        }
        client.deadline = None;
        Ok(client)
    }

    pub fn hello(&self) -> &Hello {
        &self.hello
    }

    /// Every later wait ends with [`ClientError::TimedOut`] after `limit`.
    pub fn deadline_in(&mut self, limit: Option<Duration>) {
        self.deadline = limit.map(|limit| Instant::now() + limit);
    }

    /// Polled while waiting; true ends the wait with
    /// [`ClientError::Interrupted`] (a subscription is cancelled first).
    pub fn interrupt_when(&mut self, check: impl Fn() -> bool + Send + 'static) {
        self.interrupted = Some(Box::new(check));
    }

    fn interrupted(&self) -> bool {
        self.interrupted.as_ref().is_some_and(|check| check())
    }

    fn line(&mut self) -> Result<Vec<u8>, ClientError> {
        loop {
            match self.reader.next_line()? {
                Next::Line(line) => return Ok(line),
                Next::Tick { .. } => {
                    if self.deadline.is_some_and(|d| Instant::now() >= d) {
                        return Err(ClientError::TimedOut);
                    }
                    if self.interrupted() {
                        return Err(ClientError::Interrupted);
                    }
                }
                Next::TooLong => return Err(ClientError::Protocol("a line above 2 MiB".into())),
                Next::Eof => {
                    return Err(ClientError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the daemon closed the connection",
                    )));
                }
            }
        }
    }

    fn send(&mut self, id: u64, op: &str, params: Value) -> Result<(), ClientError> {
        let mut line = serde_json::to_vec(&Request {
            id,
            op: op.to_owned(),
            params,
        })
        .map_err(|e| ClientError::Protocol(e.to_string()))?;
        line.push(b'\n');
        self.writer.write_all(&line)?;
        Ok(())
    }

    fn reply(&mut self) -> Result<Reply, ClientError> {
        let line = self.line()?;
        serde_json::from_slice(&line).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    /// One operation; its `result`, or the daemon's error.
    pub fn call(&mut self, op: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(id, op, params)?;
        loop {
            let reply = self.reply()?;
            if reply.id != id {
                continue;
            }
            if let Some(error) = reply.error {
                return Err(ClientError::Api(error));
            }
            if reply.ok == Some(true) {
                return Ok(reply.result.unwrap_or(Value::Null));
            }
        }
    }

    /// `events.subscribe`: `on` sees every line until it returns false (the
    /// subscription is then cancelled) or the stream ends. Returns the final
    /// result line (`{"finished": true, ...}` for a job stream whose job
    /// ended, `{"cancelled": true, ...}` after a cancel).
    pub fn subscribe(
        &mut self,
        params: Value,
        on: &mut dyn FnMut(Streamed) -> bool,
    ) -> Result<Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(id, "events.subscribe", params)?;
        let mut cancelled = false;
        loop {
            let reply = match self.reply() {
                Err(ClientError::Interrupted) if !cancelled => {
                    self.send(id, "cancel", Value::Null)?;
                    let _ = self.drain_to_end(id);
                    return Err(ClientError::Interrupted);
                }
                other => other?,
            };
            if reply.id != id {
                continue;
            }
            if let Some(error) = reply.error {
                return Err(ClientError::Api(error));
            }
            if reply.ok == Some(true) {
                return Ok(reply.result.unwrap_or(Value::Null));
            }
            let line = match (reply.event, reply.frame) {
                (Some(event), _) => Streamed::Event(event),
                (None, Some(Frame::Hello(hello))) => Streamed::Hello(hello),
                (None, Some(Frame::Ping {})) => Streamed::Ping,
                (None, None) => continue,
            };
            if !on(line) && !cancelled {
                cancelled = true;
                self.send(id, "cancel", Value::Null)?;
            }
        }
    }

    /// After a cancel: read up to the stream's last line, for a second at most.
    fn drain_to_end(&mut self, id: u64) -> Result<(), ClientError> {
        self.interrupted = None;
        self.deadline = Some(Instant::now() + Duration::from_secs(1));
        loop {
            let reply = self.reply()?;
            if reply.id == id && (reply.ok.is_some() || reply.error.is_some()) {
                return Ok(());
            }
        }
    }

    /// Send raw bytes (tests of the server's limits).
    pub fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.writer.write_all(bytes)
    }

    /// Read one raw line (tests).
    pub fn read_line(&mut self) -> Result<Vec<u8>, ClientError> {
        self.line()
    }
}
