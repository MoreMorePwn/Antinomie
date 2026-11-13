// SPDX-License-Identifier: GPL-3.0-only
//! The framing of the local socket (design 5.9): one JSON object per line,
//! at most [`MAX_LINE`] bytes each way.
//!
//! [`LineReader`] reads lines from a socket without ever holding more than
//! one line plus one read buffer, so a client cannot make the server allocate
//! more than the limit. [`parse_request`] is the strict request parser: an
//! object with an integer `id`, a string `op` and an optional `params`, and
//! nothing else. [`encode`] writes a reply line and refuses one above the
//! limit. [`fuzz_entry`] is what the fuzz target `socket_frames` calls.

use crate::api::{
    error::{ApiError, ErrorCode},
    ops::{Reply, Request},
};
use serde_json::Value;
use std::io::{self, Read};

/// The longest line either side may send, newline included (5.9: 2 MiB).
pub const MAX_LINE: usize = 2 * 1024 * 1024;
/// The longest operation name.
pub const MAX_OP: usize = 64;
/// Request ids are JSON integers a JavaScript client can hold exactly.
pub const MAX_ID: u64 = (1 << 53) - 1;

/// What one call of [`LineReader::next_line`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    /// A complete line, without its newline.
    Line(Vec<u8>),
    /// The read timed out; `partial` is true when part of a line is buffered.
    Tick { partial: bool },
    /// The line passed [`MAX_LINE`] before its newline; the rest of the
    /// stream cannot be framed and the connection must close.
    TooLong,
    /// The peer closed the connection (a partial last line is dropped).
    Eof,
}

/// Reads newline-terminated lines with a hard size limit.
pub struct LineReader<R> {
    inner: R,
    buf: Vec<u8>,
    /// Bytes of `buf` already searched for a newline.
    scanned: usize,
    max: usize,
}

impl<R: Read> LineReader<R> {
    pub fn new(inner: R) -> Self {
        Self::with_limit(inner, MAX_LINE)
    }

    pub fn with_limit(inner: R, max: usize) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            scanned: 0,
            max: max.max(1),
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// The next line, a timeout tick, an overlong line or the end.
    pub fn next_line(&mut self) -> io::Result<Next> {
        loop {
            if let Some(at) = self.buf[self.scanned..].iter().position(|&b| b == b'\n') {
                let end = self.scanned + at;
                let mut line: Vec<u8> = self.buf.drain(..=end).collect();
                line.pop();
                self.scanned = 0;
                if line.len() + 1 > self.max {
                    return Ok(Next::TooLong);
                }
                return Ok(Next::Line(line));
            }
            self.scanned = self.buf.len();
            if self.buf.len() >= self.max {
                return Ok(Next::TooLong);
            }
            let mut chunk = [0u8; 64 * 1024];
            let room = (self.max - self.buf.len()).min(chunk.len());
            match self.inner.read(&mut chunk[..room]) {
                Ok(0) => return Ok(Next::Eof),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(Next::Tick {
                        partial: !self.buf.is_empty(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

/// A request line that could not be used: the id to answer with (0 when the
/// line carried none that could be read) and why.
#[derive(Clone, Debug, PartialEq)]
pub struct BadRequest {
    pub id: u64,
    pub error: ApiError,
}

fn bad(id: u64, field: &str, message: &str) -> BadRequest {
    BadRequest {
        id,
        error: ApiError::invalid_argument(field, message),
    }
}

/// Parse one request line strictly: a JSON object with `id` (an integer from
/// 0 to 2^53 - 1), `op` (1 to 64 printable ASCII characters) and an optional
/// `params` (an object; `null` reads as none). Any other member is refused.
pub fn parse_request(line: &[u8]) -> Result<Request, BadRequest> {
    if line.len() + 1 > MAX_LINE {
        return Err(BadRequest {
            id: 0,
            error: ApiError::payload_too_large(MAX_LINE as u64),
        });
    }
    let value: Value = serde_json::from_slice(line)
        .map_err(|e| bad(0, "request", &format!("not a JSON object: {e}")))?;
    let Value::Object(mut object) = value else {
        return Err(bad(0, "request", "a request is a JSON object"));
    };
    let id = match object.remove("id") {
        Some(Value::Number(number)) => match number.as_u64() {
            Some(id) if id <= MAX_ID => id,
            _ => return Err(bad(0, "id", "an integer from 0 to 2^53 - 1")),
        },
        Some(_) => return Err(bad(0, "id", "an integer from 0 to 2^53 - 1")),
        None => return Err(bad(0, "id", "missing")),
    };
    let op = match object.remove("op") {
        Some(Value::String(op))
            if (1..=MAX_OP).contains(&op.len()) && op.bytes().all(|b| b.is_ascii_graphic()) =>
        {
            op
        }
        Some(_) => return Err(bad(id, "op", "1 to 64 printable ASCII characters")),
        None => return Err(bad(id, "op", "missing")),
    };
    let params = match object.remove("params") {
        None | Some(Value::Null) => Value::Object(Default::default()),
        Some(params @ Value::Object(_)) => params,
        Some(_) => return Err(bad(id, "params", "an object")),
    };
    if let Some(unknown) = object.keys().next() {
        return Err(bad(id, unknown, "unknown member of a request"));
    }
    Ok(Request { id, op, params })
}

/// A reply as one line, newline included. A reply above [`MAX_LINE`] becomes
/// a `payload_too_large` error for the same id (a smaller `limit` or a range
/// fits).
pub fn encode(reply: &Reply) -> Vec<u8> {
    let mut line = serde_json::to_vec(reply).unwrap_or_else(|e| {
        serde_json::to_vec(&Reply::failed(
            reply.id,
            ApiError::new(ErrorCode::Internal, format!("reply not encodable: {e}")),
        ))
        .unwrap_or_default()
    });
    if line.len() + 1 > MAX_LINE {
        line = serde_json::to_vec(&Reply::failed(
            reply.id,
            ApiError::payload_too_large(MAX_LINE as u64)
                .with_detail("hint", "ask for fewer items (limit) or a byte range".into()),
        ))
        .unwrap_or_default();
    }
    line.push(b'\n');
    line
}

/// The fuzz entry of the socket framing: split arbitrary bytes into lines with
/// a small limit and parse each line as a request. Must never panic, and a
/// parsed request must survive a round trip.
pub fn fuzz_entry(data: &[u8]) {
    let mut reader = LineReader::with_limit(data, 4096);
    for _ in 0..1024 {
        match reader.next_line() {
            Ok(Next::Line(line)) => {
                if let Ok(request) = parse_request(&line) {
                    let text = serde_json::to_vec(&request).expect("a request encodes");
                    let again = parse_request(&text).expect("an encoded request parses");
                    assert_eq!(again.id, request.id);
                    assert_eq!(again.op, request.op);
                }
            }
            Ok(Next::Tick { .. }) | Ok(Next::TooLong) | Ok(Next::Eof) | Err(_) => break,
        }
    }
    let _ = super::b64::decode(data, 4096);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lines(input: &[u8], max: usize) -> Vec<Next> {
        let mut reader = LineReader::with_limit(input, max);
        let mut out = Vec::new();
        loop {
            let next = reader.next_line().unwrap();
            let stop = matches!(next, Next::Eof | Next::TooLong);
            out.push(next);
            if stop {
                return out;
            }
        }
    }

    #[test]
    fn lines_are_split_at_newlines_and_a_partial_last_line_is_dropped() {
        assert_eq!(
            lines(b"a\nbc\n\nd", 16),
            vec![
                Next::Line(b"a".to_vec()),
                Next::Line(b"bc".to_vec()),
                Next::Line(Vec::new()),
                Next::Eof
            ]
        );
    }

    #[test]
    fn a_line_at_the_limit_passes_and_one_byte_more_is_too_long() {
        // The limit counts the newline.
        let ok = [b'x'; 7];
        let mut input = ok.to_vec();
        input.push(b'\n');
        assert_eq!(lines(&input, 8)[0], Next::Line(ok.to_vec()));
        let mut long = [b'x'; 8].to_vec();
        long.push(b'\n');
        assert_eq!(lines(&long, 8), vec![Next::TooLong]);
        // No newline at all: the reader stops at the limit, never reads on.
        let endless = vec![b'y'; 100];
        assert_eq!(lines(&endless, 8), vec![Next::TooLong]);
    }

    #[test]
    fn the_real_limit_is_two_mebibytes() {
        assert_eq!(MAX_LINE, 2 * 1024 * 1024);
        let mut big = vec![b' '; MAX_LINE - 1];
        big.push(b'\n');
        assert!(matches!(lines(&big, MAX_LINE)[0], Next::Line(_)));
        let mut bigger = vec![b' '; MAX_LINE];
        bigger.push(b'\n');
        assert_eq!(lines(&bigger, MAX_LINE), vec![Next::TooLong]);
    }

    #[test]
    fn a_well_formed_request_parses() {
        let request =
            parse_request(br#"{"id": 7, "op": "run.get", "params": {"run_id": "x"}}"#).unwrap();
        assert_eq!(request.id, 7);
        assert_eq!(request.op, "run.get");
        assert_eq!(request.params, json!({"run_id": "x"}));
        let bare = parse_request(br#"{"id":0,"op":"health"}"#).unwrap();
        assert_eq!(bare.params, json!({}));
        let null = parse_request(br#"{"id":1,"op":"health","params":null}"#).unwrap();
        assert_eq!(null.params, json!({}));
    }

    #[test]
    fn malformed_requests_are_refused_with_the_field_and_the_id_when_known() {
        let cases: [(&[u8], u64, &str); 13] = [
            (b"", 0, "request"),
            (b"not json", 0, "request"),
            (b"[1,2]", 0, "request"),
            (br#"{"op":"health"}"#, 0, "id"),
            (br#"{"id":-1,"op":"health"}"#, 0, "id"),
            (br#"{"id":1.5,"op":"health"}"#, 0, "id"),
            (br#"{"id":"7","op":"health"}"#, 0, "id"),
            (br#"{"id":9007199254740992,"op":"health"}"#, 0, "id"),
            (br#"{"id":3}"#, 3, "op"),
            (br#"{"id":3,"op":""}"#, 3, "op"),
            (br#"{"id":3,"op":"a b"}"#, 3, "op"),
            (br#"{"id":3,"op":"health","params":[1]}"#, 3, "params"),
            (br#"{"id":3,"op":"health","extra":1}"#, 3, "extra"),
        ];
        for (line, id, field) in cases {
            let error = parse_request(line).unwrap_err();
            assert_eq!(error.id, id, "{}", String::from_utf8_lossy(line));
            assert_eq!(error.error.code, ErrorCode::InvalidArgument);
            assert_eq!(error.error.field.as_deref(), Some(field));
        }
        let long_op = format!(r#"{{"id":1,"op":"{}"}}"#, "a".repeat(65));
        assert_eq!(
            parse_request(long_op.as_bytes())
                .unwrap_err()
                .error
                .field
                .as_deref(),
            Some("op")
        );
    }

    #[test]
    fn deeply_nested_params_are_refused_not_a_stack_overflow() {
        let mut text = String::from(r#"{"id":1,"op":"health","params":{"a":"#);
        text.push_str(&"[".repeat(100_000));
        text.push_str(&"]".repeat(100_000));
        text.push_str("}}");
        assert!(parse_request(text.as_bytes()).is_err());
    }

    #[test]
    fn an_oversized_reply_becomes_a_payload_error_for_the_same_id() {
        let reply = Reply::ok(9, json!({"blob": "x".repeat(MAX_LINE)}));
        let line = encode(&reply);
        assert!(line.len() < 4096);
        let value: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(value["id"], 9);
        assert_eq!(value["error"]["code"], "payload_too_large");
        let small = encode(&Reply::ok(1, json!({"a": 1})));
        assert_eq!(small.last(), Some(&b'\n'));
    }

    /// The fuzz entry over a fixed set of hostile inputs and a deterministic
    /// stream of random ones (the libFuzzer target runs it without bounds).
    #[test]
    fn the_fuzz_entry_survives_random_and_hostile_bytes() {
        let fixed: [&[u8]; 8] = [
            b"",
            b"\n\n\n",
            br#"{"id":1,"op":"x"}"#,
            br#"{"id":1,"op":"x","params":{"a":"\u0000"}}"#,
            b"\xff\xfe\n{\"id\":1}\n",
            &[b'{'; 5000],
            b"QUJD\nQUJ=\n====\n",
            br#"{"id":1,"op":"cancel","params":{}}{"id":2}"#,
        ];
        for input in fixed {
            fuzz_entry(input);
        }
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet = br#"{}[]":,0123456789 idopparams\n-.eE"truefalsnul"#;
        for _ in 0..2000 {
            let len = (next() % 300) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    let r = next();
                    if r % 4 == 0 {
                        r as u8
                    } else {
                        alphabet[(r as usize >> 8) % alphabet.len()]
                    }
                })
                .collect();
            fuzz_entry(&bytes);
        }
    }
}
