// SPDX-License-Identifier: GPL-3.0-only
//! What the built-in services saw during a run: the telnet and FTP sessions
//! (who connected where, the logins tried, every line), the files sent and
//! received over HTTP, FTP and TFTP, and the stand-ins served. The gateway
//! writes it into the run's folder as `inetsim.json` when the run lets go of
//! its route, with the uploaded files under `inetsim-uploads/`; Triage reads
//! it for findings, indicators and the Network view's InetSim tab.
use serde::{Deserialize, Serialize};

/// The report's file name in a run's folder.
pub const REPORT: &str = "inetsim.json";
/// The folder of the files the guest uploaded, in a run's folder.
pub const UPLOADS: &str = "inetsim-uploads";
/// Lines kept of one session; more are counted.
pub(crate) const MAX_LINES: usize = 2_000;
/// Characters kept of one line.
pub(crate) const MAX_LINE_CHARS: usize = 1_024;
/// Sessions and transfers kept of one run; more are counted.
pub(crate) const MAX_ENTRIES: usize = 4_096;

/// One login tried on a fake device or the FTP server.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Login {
    pub user: String,
    pub password: String,
    pub accepted: bool,
}

/// One line the guest typed, with when (host Unix ms).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Line {
    pub ms: u64,
    pub text: String,
}

/// A download a telnet session asked for (`wget`, `curl`, `tftp`, `ftpget`).
/// Nothing is fetched: the fake shell says it worked.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Download {
    pub ms: u64,
    pub tool: String,
    /// `http://host/path`, `ftp://host/path` or `tftp://host/file`.
    pub url: String,
    pub host: String,
    pub port: u16,
    /// The remote path or file name.
    pub name: String,
    /// The local name the guest asked to save it as.
    pub saved_as: String,
    /// What the fake shell pretends it got: a stand-in or the fake file.
    pub served: String,
}

/// A file the session wrote with `echo` (a dropper typed in piece by piece).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Written {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    /// Its bytes under the run's folder, `inetsim-uploads/<file>`; empty when
    /// over the size limits.
    pub artifact: String,
}

/// One telnet or FTP session.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Session {
    pub id: u32,
    /// `telnet` or `ftp`.
    pub service: String,
    /// The address and port the guest connected to.
    pub endpoint: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub logins: Vec<Login>,
    /// Every line after the login (the login lines are in `logins`).
    pub lines: Vec<Line>,
    pub lines_omitted: u64,
    /// Bytes the guest sent.
    pub bytes: u64,
    /// How it ended: `closed by the guest`, `idle`, `byte limit`, `time limit`.
    pub ended: String,
    pub downloads: Vec<Download>,
    pub written: Vec<Written>,
    /// Programs the session ran (`./x`), with what they were.
    pub executed: Vec<String>,
}

/// One file sent to or received from the guest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Transfer {
    pub ms: u64,
    /// `http`, `ftp` or `tftp`.
    pub protocol: String,
    /// `download` (to the guest) or `upload` (from it).
    pub direction: String,
    pub endpoint: String,
    /// The HTTP Host, or the address.
    pub host: String,
    /// The path or file name asked for.
    pub name: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
    /// Downloads: what was served (a stand-in, the fake file, the page).
    pub served: String,
    /// Uploads: the file under the run's folder; empty when over the limits.
    pub artifact: String,
    /// Uploads: more bytes came than were kept.
    pub truncated: bool,
    /// The FTP session it belongs to (0 for none).
    pub session: u32,
}

/// Everything a run's report holds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    pub version: u32,
    pub run: String,
    /// The guest architecture the stand-in programs were built for.
    pub arch: String,
    pub stand_ins: bool,
    /// `any` or `defaults`.
    pub telnet_logins: String,
    pub sessions: Vec<Session>,
    pub transfers: Vec<Transfer>,
    /// Sessions hung up at once because the run had opened its limit.
    pub sessions_refused: u64,
    /// Sessions and transfers not kept past [`MAX_ENTRIES`].
    pub omitted: u64,
}

impl Report {
    /// Whether there is anything to write.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty() && self.transfers.is_empty() && self.sessions_refused == 0
    }
}

/// The report of a run, if its folder holds a readable one.
pub fn read_report(directory: &std::path::Path) -> Option<Report> {
    let path = directory.join(REPORT);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() || meta.len() > 32 * 1024 * 1024 {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// `text` as one line for the log: control characters shown as `\xNN`, cut at
/// [`MAX_LINE_CHARS`].
pub(crate) fn printable(text: &[u8]) -> String {
    let mut out = String::new();
    for c in String::from_utf8_lossy(text).chars() {
        if out.len() >= MAX_LINE_CHARS {
            out.push('…');
            break;
        }
        if c.is_control() {
            out.push_str(&format!("\\x{:02x}", u32::from(c) & 0xff));
        } else {
            out.push(c);
        }
    }
    out
}
