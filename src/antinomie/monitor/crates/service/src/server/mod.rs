// SPDX-License-Identifier: GPL-3.0-only
//! The local socket of the daemon (design 5.9; card P3-6a): `JobApi` and
//! `QueryApi` as NDJSON over a Unix socket, for the owner of the data
//! directory only.
//!
//! Security model, in the order a connection meets it:
//!
//! 1. **Where the socket lives.** `<data>/run/antinomie.sock` by default. The
//!    folder must be a real directory (not a symlink) owned by the daemon's
//!    user with no group or other access (0700); the server refuses to start
//!    otherwise. An old socket file is removed only when it is a socket (the
//!    daemon holds the data-directory lock, so no one else serves it); any
//!    other file there is left alone and the start fails. The socket is
//!    chmod 0600 right after `bind`, and the folder already keeps everyone else
//!    out while it is not.
//! 2. **Who connects.** The peer's credentials (`SO_PEERCRED`) are read on
//!    accept; a peer with another UID gets nothing, not even the hello, and is
//!    closed. The caller is `local:<uid>` with every scope (5.8: the local
//!    socket is a single-user view, A15). Nothing the client sends can change
//!    its identity.
//! 3. **What it may send.** [`frame`]: lines of at most 2 MiB, strictly
//!    parsed. [`limits`]: requests in flight, rate, connections,
//!    subscriptions, idle and slow clients. Host paths from a client are not
//!    accepted (`sample.path` is refused on the socket: files arrive through
//!    `upload.*`); paths in replies are checked to lie inside the data
//!    directory before they are shown.
//!
//! [`Handler`] is what the daemon implements; [`client::Client`] is the other
//! end, used by `antinomie-cli` and the tests.

pub mod b64;
pub mod client;
mod conn;
pub mod frame;
pub mod limits;
pub mod subscribe;
#[cfg(test)]
mod tests;

use crate::{
    api::{
        error::ApiError,
        event::Hello,
        ops::{Caller, Scope},
    },
    store::Store,
};
use limits::{Bucket, Limits};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs, io,
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

/// Where a call comes from. A local path in a request is only honoured for a
/// caller in the same process (direct mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Socket,
    InProcess,
}

/// What one call carries besides its parameters.
#[derive(Clone, Debug)]
pub struct CallContext {
    pub caller: Caller,
    /// Set by `{"op": "cancel"}` or when the connection closes.
    pub cancel: Arc<AtomicBool>,
    pub transport: Transport,
}

impl CallContext {
    pub fn in_process(caller: Caller) -> Self {
        Self {
            caller,
            cancel: Arc::new(AtomicBool::new(false)),
            transport: Transport::InProcess,
        }
    }
}

/// The service behind the socket.
pub trait Handler: Send + Sync + 'static {
    /// The `engine.hello` of a new connection (`truncated` false).
    fn hello(&self) -> Hello;
    /// One operation (every op of 5.3 and `recording.*`, but not
    /// `events.subscribe`, which the connection serves from [`Handler::store`]).
    fn call(&self, op: &str, params: Value, ctx: &CallContext) -> Result<Value, ApiError>;
    fn store(&self) -> &Store;
}

/// The caller of a peer with `uid`: the owner of the data directory.
pub fn local_caller(uid: u32) -> Caller {
    Caller {
        client_id: format!("local:{uid}"),
        scopes: vec![
            Scope::Read,
            Scope::Submit,
            Scope::ArtifactsSensitive,
            Scope::Manage,
        ],
        policies: Vec::new(),
    }
}

/// This process's effective UID: the only peer the socket admits.
pub fn own_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The UID of the peer of a connected socket (`SO_PEERCRED`).
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    rustix::net::sockopt::socket_peercred(stream)
        .map(|cred| cred.uid.as_raw())
        .map_err(io::Error::from)
}

/// Whether a peer may talk to the daemon: its credentials were read and its
/// UID is the daemon's own (design 5.9).
pub(crate) fn admits(peer: io::Result<u32>, euid: u32) -> bool {
    matches!(peer, Ok(uid) if uid == euid)
}

/// The counters every connection shares.
pub(crate) struct Shared {
    pub stopping: AtomicBool,
    pub connections: AtomicUsize,
    pub in_flight: AtomicUsize,
    pub subscriptions: Mutex<HashMap<String, usize>>,
    pub global_rate: Mutex<Bucket>,
    pub euid: u32,
}

/// Refuse a folder for the socket that someone else could reach into.
fn check_private_dir(dir: &Path, euid: u32) -> io::Result<()> {
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let meta = fs::symlink_metadata(dir)?;
    let refuse = |why: &str| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("socket folder {}: {why}", dir.display()),
        ))
    };
    if !meta.is_dir() {
        return refuse("not a directory (a symlink is not accepted)");
    }
    if meta.uid() != euid {
        return refuse("owned by another user");
    }
    if meta.mode() & 0o077 != 0 {
        return refuse("group or others have access; it must be 0700");
    }
    Ok(())
}

/// A bound, listening socket.
pub struct Server {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
    handler: Arc<dyn Handler>,
    limits: Limits,
    shared: Arc<Shared>,
}

/// Stops a serving [`Server`] from another thread.
#[derive(Clone)]
pub struct StopHandle(Arc<Shared>);

impl StopHandle {
    pub fn stop(&self) {
        self.0.stopping.store(true, Ordering::SeqCst);
    }

    pub fn connections(&self) -> usize {
        self.0.connections.load(Ordering::SeqCst)
    }
}

impl Server {
    /// Bind `path` for `handler` (see the module notes for the checks).
    pub fn bind(path: &Path, handler: Arc<dyn Handler>, limits: Limits) -> io::Result<Self> {
        let euid = own_uid();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "socket path has no folder")
            })?;
        check_private_dir(parent, euid)?;
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket; not removed", path.display()),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(path).map_err(|e| {
            io::Error::new(e.kind(), format!("cannot bind {}: {e}", path.display()))
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let meta = fs::symlink_metadata(path)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            identity: (meta.dev(), meta.ino()),
            handler,
            shared: Arc::new(Shared {
                stopping: AtomicBool::new(false),
                connections: AtomicUsize::new(0),
                in_flight: AtomicUsize::new(0),
                subscriptions: Mutex::new(HashMap::new()),
                global_rate: Mutex::new(Bucket::new(limits.rate_per_s * 10.0, limits.burst * 10.0)),
                euid,
            }),
            limits,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn stop_handle(&self) -> StopHandle {
        StopHandle(Arc::clone(&self.shared))
    }

    /// Accept connections until [`StopHandle::stop`]. Each connection runs on
    /// its own thread; they see the stop flag within one tick and close.
    pub fn serve(&self) {
        while !self.shared.stopping.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, _)) => self.admit(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        // Wait a little for the connections to see the flag.
        for _ in 0..40 {
            if self.shared.connections.load(Ordering::SeqCst) == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn admit(&self, stream: UnixStream) {
        // The listener is non-blocking; the connection is not.
        if stream.set_nonblocking(false).is_err() {
            return;
        }
        if !admits(peer_uid(&stream), self.shared.euid) {
            // Another user, or credentials that cannot be read: nothing is
            // sent, not even the hello.
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
        let open = self.shared.connections.fetch_add(1, Ordering::SeqCst);
        if open >= self.limits.connections {
            self.shared.connections.fetch_sub(1, Ordering::SeqCst);
            conn::refuse_full(stream, &self.limits);
            return;
        }
        let handler = Arc::clone(&self.handler);
        let limits = self.limits.clone();
        let shared = Arc::clone(&self.shared);
        let uid = shared.euid;
        let spawned = std::thread::Builder::new()
            .name("antinomie-socket".into())
            .spawn(move || {
                conn::serve(stream, uid, handler, &limits, &shared);
                shared.connections.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            self.shared.connections.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for Server {
    /// Remove the socket file, but only the one this server bound: a newer
    /// daemon may have replaced it.
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        if let Ok(meta) = fs::symlink_metadata(&self.path)
            && (meta.dev(), meta.ino()) == self.identity
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
