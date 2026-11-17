// SPDX-License-Identifier: GPL-3.0-only
//! The built-in services of one gateway: the current run's options and log,
//! the files the guest uploads (spooled to the gateway's folder until the run
//! ends), and the FTP data ports waiting for their connection.
use super::log::{MAX_ENTRIES, Report, Session, Transfer, UPLOADS, Written};
use crate::{api::GuestArch, route::config::BuiltinServices};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    net::Ipv4Addr,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Mutex, MutexGuard,
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// Bytes kept of one uploaded file, and of all of a run's (the recorder's
/// defaults for written content).
pub(crate) const UPLOAD_FILE: u64 = crate::file_writes::DEFAULT_PER_FILE;
pub(crate) const UPLOAD_RUN: u64 = crate::file_writes::DEFAULT_PER_RUN;
/// The FTP data ports handed out by PASV.
const PASV_FIRST: u16 = 40_000;
const PASV_COUNT: u16 = 20_000;

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// Which run's log an entry belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionId {
    generation: u64,
    index: usize,
}

struct State {
    generation: u64,
    options: BuiltinServices,
    report: Report,
    /// Sessions opened in the run, kept or not.
    opened: u32,
    uploaded: u64,
    next_upload: u32,
    next_pasv: u16,
    /// Data ports waiting for the guest's connection.
    pasv: HashMap<(Ipv4Addr, u16), SyncSender<UnixStream>>,
}

pub struct Services {
    arch: Mutex<GuestArch>,
    spool: PathBuf,
    state: Mutex<State>,
}

/// What a session needs to know of the run.
#[derive(Clone, Debug)]
pub(crate) struct RunView {
    pub generation: u64,
    pub options: BuiltinServices,
    pub arch: GuestArch,
}

impl Services {
    /// The services of a gateway whose folder is `dir`.
    pub fn new(dir: &Path) -> Self {
        Self {
            arch: Mutex::new(GuestArch::X86_64),
            spool: dir.join("inetsim-spool"),
            state: Mutex::new(State {
                generation: 0,
                options: BuiltinServices::default(),
                report: Report::default(),
                opened: 0,
                uploaded: 0,
                next_upload: 0,
                next_pasv: 0,
                pasv: HashMap::new(),
            }),
        }
    }

    /// The guest's architecture, for the stand-in programs.
    pub fn set_arch(&self, arch: GuestArch) {
        *self.arch.lock().unwrap_or_else(|p| p.into_inner()) = arch;
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn arch(&self) -> GuestArch {
        *self.arch.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A new run on the built-in services: its options, an empty log.
    pub fn begin_run(&self, run: &str, options: &BuiltinServices) {
        let arch = self.arch();
        let mut state = self.lock();
        state.generation += 1;
        state.options = options.clone();
        state.report = Report {
            version: 1,
            run: run.into(),
            arch: super::stand_in::program(arch).map_or_else(
                || format!("ELF machine {}", arch.machine),
                |(_, l)| l.into(),
            ),
            stand_ins: options.stand_ins,
            telnet_logins: match options.telnet_logins {
                crate::route::config::TelnetLogins::Any => "any",
                crate::route::config::TelnetLogins::Defaults => "defaults",
            }
            .into(),
            ..Report::default()
        };
        state.opened = 0;
        state.uploaded = 0;
        state.next_upload = 0;
        state.pasv.clear();
        let _ = std::fs::remove_dir_all(&self.spool);
    }

    pub(crate) fn view(&self) -> RunView {
        let arch = self.arch();
        let state = self.lock();
        RunView {
            generation: state.generation,
            options: state.options.clone(),
            arch,
        }
    }

    /// A new session of `service` to `endpoint`, or `None` when the run has
    /// opened as many as it may (the session is hung up, and counted).
    pub(crate) fn open_session(&self, service: &str, endpoint: String) -> Option<SessionId> {
        let mut state = self.lock();
        if state.opened >= state.options.run_sessions {
            state.report.sessions_refused += 1;
            return None;
        }
        state.opened += 1;
        let id = state.opened;
        let index = state.report.sessions.len();
        if index >= MAX_ENTRIES {
            state.report.omitted += 1;
            return Some(SessionId {
                generation: state.generation,
                index: usize::MAX,
            });
        }
        state.report.sessions.push(Session {
            id,
            service: service.into(),
            endpoint,
            start_ms: now_ms(),
            ..Session::default()
        });
        Some(SessionId {
            generation: state.generation,
            index,
        })
    }

    /// Changes session `id` of the log, unless a newer run has begun.
    pub(crate) fn update(&self, id: SessionId, change: impl FnOnce(&mut Session)) {
        let mut state = self.lock();
        if state.generation != id.generation {
            return;
        }
        if let Some(session) = state.report.sessions.get_mut(id.index) {
            change(session);
        }
    }

    /// The session's number in the log (0 when it is not kept).
    pub(crate) fn session_number(&self, id: SessionId) -> u32 {
        let state = self.lock();
        state
            .report
            .sessions
            .get(id.index)
            .filter(|_| state.generation == id.generation)
            .map_or(0, |session| session.id)
    }

    /// Logs a transfer of run `generation`.
    pub(crate) fn transfer(&self, generation: u64, transfer: Transfer) {
        let mut state = self.lock();
        if state.generation != generation {
            return;
        }
        if state.report.transfers.len() >= MAX_ENTRIES {
            state.report.omitted += 1;
        } else {
            state.report.transfers.push(transfer);
        }
    }

    /// A spool file for an upload named `name`, within the run's limits.
    pub(crate) fn upload(&self, generation: u64, name: &str) -> Upload {
        let mut state = self.lock();
        let current = state.generation == generation;
        // The room is reserved now, so uploads at once stay within the run's
        // limit; `uploaded` gives back what was not kept.
        let room = if current {
            UPLOAD_RUN.saturating_sub(state.uploaded).min(UPLOAD_FILE)
        } else {
            0
        };
        state.uploaded += room;
        state.next_upload += 1;
        let file_name = format!(
            "{:04}-{}",
            state.next_upload,
            safe_name(name).chars().take(80).collect::<String>()
        );
        drop(state);
        let file = (room > 0)
            .then(|| {
                crate::storage::private_dir(&self.spool).ok()?;
                File::create(self.spool.join(&file_name)).ok()
            })
            .flatten();
        Upload {
            file,
            name: file_name,
            room,
            size: 0,
            kept: 0,
            hash: Sha256::new(),
        }
    }

    /// Counts what an upload kept against the run's limit, giving back the
    /// rest of its reserved room.
    pub(crate) fn uploaded(&self, generation: u64, done: &Uploaded) {
        let mut state = self.lock();
        if state.generation == generation {
            state.uploaded = state
                .uploaded
                .saturating_sub(done.reserved.saturating_sub(done.kept));
        }
    }

    /// Keeps bytes a telnet session wrote with `echo` as an upload.
    pub(crate) fn keep_written(&self, generation: u64, name: &str, bytes: &[u8]) -> Written {
        let mut upload = self.upload(generation, name);
        upload.write(bytes);
        let done = upload.finish();
        self.uploaded(generation, &done);
        Written {
            name: name.into(),
            size: bytes.len() as u64,
            sha256: crate::storage::sha256_hex(bytes),
            artifact: done.artifact,
        }
    }

    /// A data port for an FTP session to `ip`; the guest's connection to it
    /// arrives on the receiver.
    pub(crate) fn passive(&self, ip: Ipv4Addr) -> (u16, Receiver<UnixStream>) {
        let mut state = self.lock();
        let (tx, rx) = sync_channel(1);
        let mut port = PASV_FIRST;
        for _ in 0..PASV_COUNT {
            state.next_pasv = (state.next_pasv + 1) % PASV_COUNT;
            port = PASV_FIRST + state.next_pasv;
            if !state.pasv.contains_key(&(ip, port)) {
                break;
            }
        }
        state.pasv.insert((ip, port), tx);
        (port, rx)
    }

    /// Forgets a data port nobody connected to.
    pub(crate) fn forget_passive(&self, ip: Ipv4Addr, port: u16) {
        self.lock().pasv.remove(&(ip, port));
    }

    /// Hands a connection to `ip:port` to the FTP session waiting for it;
    /// gives the stream back when no session waits there.
    pub(crate) fn claim_passive(
        &self,
        ip: Ipv4Addr,
        port: u16,
        stream: UnixStream,
    ) -> Result<(), UnixStream> {
        let waiting = self.lock().pasv.remove(&(ip, port));
        match waiting {
            Some(tx) => tx.send(stream).map_err(|error| error.0),
            None => Err(stream),
        }
    }

    /// The run's log as it is now.
    pub fn report(&self) -> Report {
        self.lock().report.clone()
    }

    /// Writes the log into `directory`, with the uploaded files, when the run
    /// used the services; false when there was nothing.
    pub fn write_report(&self, directory: &Path) -> Result<bool, String> {
        let report = self.report();
        if report.is_empty() {
            return Ok(false);
        }
        if let Ok(entries) = std::fs::read_dir(&self.spool) {
            let target = directory.join(UPLOADS);
            crate::storage::private_dir(&target).map_err(|e| format!("{UPLOADS}: {e}"))?;
            for entry in entries.flatten() {
                let to = target.join(entry.file_name());
                if std::fs::rename(entry.path(), &to).is_err() {
                    std::fs::copy(entry.path(), &to).map_err(|e| format!("{UPLOADS}: {e}"))?;
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        crate::storage::atomic_json(&directory.join(super::log::REPORT), &report)?;
        Ok(true)
    }
}

impl Drop for Services {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.spool);
    }
}

/// A file name the run's folder can hold: letters, digits, `.`, `-`, `_`.
fn safe_name(name: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim_start_matches('.').to_owned();
    if cleaned.is_empty() {
        "file".into()
    } else {
        cleaned
    }
}

/// One file the guest is uploading.
pub(crate) struct Upload {
    file: Option<File>,
    name: String,
    room: u64,
    size: u64,
    kept: u64,
    hash: Sha256,
}

/// What an upload came to.
pub(crate) struct Uploaded {
    pub size: u64,
    pub kept: u64,
    pub sha256: String,
    /// `inetsim-uploads/<file>`, or empty when nothing was kept.
    pub artifact: String,
    pub truncated: bool,
    /// The run's room it had reserved.
    reserved: u64,
}

impl Upload {
    pub fn write(&mut self, bytes: &[u8]) {
        self.size += bytes.len() as u64;
        self.hash.update(bytes);
        let take = (self.room.saturating_sub(self.kept)).min(bytes.len() as u64) as usize;
        if take > 0
            && let Some(file) = &mut self.file
        {
            if file.write_all(&bytes[..take]).is_ok() {
                self.kept += take as u64;
            } else {
                self.file = None;
            }
        }
    }

    pub fn finish(self) -> Uploaded {
        Uploaded {
            size: self.size,
            kept: self.kept,
            sha256: format!("{:x}", self.hash.finalize()),
            artifact: if self.kept > 0 || (self.size == 0 && self.file.is_some()) {
                format!("{UPLOADS}/{}", self.name)
            } else {
                String::new()
            },
            truncated: self.kept < self.size,
            reserved: self.room,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uploads_at_once_reserve_their_room_and_give_back_the_rest() {
        let dir = crate::route::tests::scratch("inetsim-upload-room");
        let services = Services::new(&dir);
        services.begin_run("run-1", &BuiltinServices::default());
        let generation = services.view().generation;
        let mut first = services.upload(generation, "a.bin");
        let second = services.upload(generation, "b.bin");
        // Both hold a file's room until they end.
        assert_eq!(services.lock().uploaded, 2 * UPLOAD_FILE);
        first.write(b"0123456789");
        let done = first.finish();
        services.uploaded(generation, &done);
        assert_eq!(services.lock().uploaded, UPLOAD_FILE + 10);
        let done = second.finish();
        services.uploaded(generation, &done);
        assert_eq!(services.lock().uploaded, 10);
        // An upload of an older run reserves nothing and keeps nothing.
        services.begin_run("run-2", &BuiltinServices::default());
        let mut stale = services.upload(generation, "c.bin");
        stale.write(b"late");
        let done = stale.finish();
        assert!(done.artifact.is_empty() && done.truncated);
        services.uploaded(generation, &done);
        assert_eq!(services.lock().uploaded, 0);
        drop(services);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
