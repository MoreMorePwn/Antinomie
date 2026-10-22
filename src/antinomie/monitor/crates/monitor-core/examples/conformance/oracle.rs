// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The lines a fixture prints about what it did (tests/monitor/conformance/
//! trace/fixture/oracle.h): `ANT_EXPECT`, `ANT_ROLE`, `ANT_GROUP`,
//! `ANT_FIXTURE_FAIL` and `ANT_DONE`.
use serde::Deserialize;
use std::collections::BTreeMap;

/// One data description of a call: bytes behind argument `arg` (or under
/// the exact recorded `key`) at entry ("in"), at exit ("out") or either.
#[derive(Clone, Debug, Deserialize)]
pub struct DataItem {
    pub p: String,
    pub arg: Option<u8>,
    pub key: Option<String>,
    /// "str" (compared without NUL terminators), "buf" (exact) or "any"
    /// (complete, content not compared).
    pub kind: String,
    #[serde(default)]
    pub hex: String,
}

impl DataItem {
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        unhex(&self.hex)
    }
}

/// A capture status the fixture triggered on purpose.
#[derive(Clone, Debug, Deserialize)]
pub struct StatusItem {
    #[serde(default = "minus_one")]
    pub arg: i32,
    pub key: Option<String>,
    pub p: String,
    pub status: String,
}

fn minus_one() -> i32 {
    -1
}

/// A field the case expects captured after the Entry (contract section 22):
/// `mark` is "at exit" or "kernel copy".
#[derive(Clone, Debug, Deserialize)]
pub struct RecaptureItem {
    pub key: String,
    pub mark: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Allow {
    pub status: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FileItem {
    pub kind: String,
    pub major: u32,
    pub minor: u32,
    pub ino: u64,
    pub nlink: u64,
}

impl FileItem {
    /// The device number as the kernel encodes it (`new_encode_dev`).
    pub fn dev(&self) -> u64 {
        u64::from(self.minor & 0xff)
            | (u64::from(self.major) << 8)
            | (u64::from(self.minor & !0xff) << 12)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AsyncItem {
    pub user_data: String,
    pub op: Option<i64>,
    pub res: Option<i64>,
    pub key: Option<String>,
    pub hex: Option<String>,
}

impl AsyncItem {
    pub fn user_data(&self) -> Result<u64, String> {
        parse_hex_u64(&self.user_data)
    }
}

/// One `ANT_EXPECT` line.
#[derive(Clone, Debug, Deserialize)]
pub struct Expect {
    pub seq: u64,
    pub label: String,
    pub nr: u64,
    pub name: String,
    pub pid: u32,
    pub tid: u32,
    pub t0: u64,
    pub t1: u64,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub unchecked: u32,
    /// The raw result: a value, or the negative errno.
    pub ret: Option<i64>,
    pub ok: bool,
    #[serde(default, rename = "volatile")]
    pub is_volatile: bool,
    #[serde(default)]
    pub data: Vec<DataItem>,
    #[serde(default)]
    pub status: Vec<StatusItem>,
    #[serde(default)]
    pub recapture: Vec<RecaptureItem>,
    #[serde(default, rename = "async")]
    pub requests: Vec<AsyncItem>,
    pub file: Option<FileItem>,
    pub allow: Option<Allow>,
    pub why: Option<String>,
    #[serde(default)]
    pub implicit: bool,
    #[serde(default)]
    pub noreturn: bool,
    pub wait_status: Option<i32>,
}

impl Expect {
    pub fn args(&self) -> Result<[u64; 6], String> {
        let mut args = [0; 6];
        if self.args.len() != 6 {
            return Err(format!("{}: {} arguments", self.label, self.args.len()));
        }
        for (slot, text) in args.iter_mut().zip(&self.args) {
            *slot = parse_hex_u64(text)?;
        }
        Ok(args)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Transcript {
    pub expects: Vec<Expect>,
    /// Role name by pid or tid.
    pub roles: BTreeMap<u32, String>,
    pub areas: Vec<String>,
    /// The fixture's private directory, for golden files.
    pub work_dir: Option<String>,
    pub fixture_failures: Vec<String>,
    pub done: Option<serde_json::Value>,
    /// Lines that start with ANT_ but did not parse.
    pub malformed: Vec<String>,
    /// Every other line, for stress scorecards.
    pub other: Vec<String>,
}

pub fn parse(text: &str) -> Transcript {
    let mut transcript = Transcript::default();
    for raw in text.split('\n') {
        let line = raw.trim_end_matches('\r');
        let Some((tag, body)) = line.split_once(' ') else {
            if !line.is_empty() {
                transcript.other.push(line.to_owned());
            }
            continue;
        };
        let parsed: Result<(), String> = match tag {
            "ANT_EXPECT" => serde_json::from_str::<Expect>(body)
                .map(|expect| transcript.expects.push(expect))
                .map_err(|e| e.to_string()),
            "ANT_ROLE" => serde_json::from_str::<serde_json::Value>(body)
                .map_err(|e| e.to_string())
                .and_then(|value| {
                    let id = value["id"].as_u64().ok_or("role id")?;
                    let role = value["role"].as_str().ok_or("role name")?;
                    transcript.roles.insert(id as u32, role.to_owned());
                    Ok(())
                }),
            "ANT_GROUP" => serde_json::from_str::<serde_json::Value>(body)
                .map_err(|e| e.to_string())
                .map(|value| {
                    if let Some(area) = value["area"].as_str() {
                        transcript.areas.push(area.to_owned());
                    }
                    if let Some(dir) = value["workdir"].as_str() {
                        transcript.work_dir = Some(dir.to_owned());
                    }
                }),
            "ANT_FIXTURE_FAIL" => {
                transcript.fixture_failures.push(body.to_owned());
                Ok(())
            }
            "ANT_DONE" => serde_json::from_str::<serde_json::Value>(body)
                .map(|value| transcript.done = Some(value))
                .map_err(|e| e.to_string()),
            _ => {
                transcript.other.push(line.to_owned());
                Ok(())
            }
        };
        if let Err(error) = parsed {
            transcript
                .malformed
                .push(format!("{error}: {}", &line[..line.len().min(200)]));
        }
    }
    transcript
}

pub fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub fn parse_hex_u64(text: &str) -> Result<u64, String> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(digits, 16).map_err(|e| format!("{text}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_parse_with_carriage_returns_and_report_malformed_ones() {
        let text = "ANT_GROUP {\"area\":\"file_io\",\"pid\":5}\r\n\
            ANT_EXPECT {\"seq\":1,\"label\":\"close.badf\",\"nr\":3,\"name\":\"close\",\"pid\":5,\
            \"tid\":5,\"t0\":10,\"t1\":20,\"argc\":1,\"args\":[\"0x3e7\",\"0\",\"0\",\"0\",\"0\",\"0\"],\
            \"unchecked\":0,\"ret\":-9,\"want\":9,\"ok\":true,\"volatile\":false,\"data\":[],\
            \"status\":[],\"async\":[]}\r\n\
            ANT_EXPECT {broken\r\nplain output\r\n";
        let transcript = parse(text);
        assert_eq!(transcript.areas, ["file_io"]);
        assert_eq!(transcript.expects.len(), 1);
        assert_eq!(transcript.expects[0].args().unwrap()[0], 999);
        assert_eq!(transcript.expects[0].ret, Some(-9));
        assert_eq!(transcript.malformed.len(), 1);
        assert_eq!(transcript.other, ["plain output"]);
    }

    #[test]
    fn device_numbers_follow_the_kernel_encoding() {
        let file = FileItem {
            kind: "OPEN".into(),
            major: 8,
            minor: 0x123,
            ino: 1,
            nlink: 1,
        };
        assert_eq!(file.dev(), 0x23 | (8 << 8) | (0x100 << 12));
        assert_eq!(unhex("00ff").unwrap(), [0, 255]);
        assert!(unhex("0").is_err());
    }
}
