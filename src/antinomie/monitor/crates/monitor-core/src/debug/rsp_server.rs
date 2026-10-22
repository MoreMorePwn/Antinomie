// SPDX-License-Identifier: GPL-3.0-only
//! The RSP server: a loopback Unix socket and an ephemeral 127.0.0.1 TCP port,
//! one client at a time, driving the project's own RSP implementation
//! (`rsp_client`) against a `DebugBackend`. It never binds a non-loopback
//! address. A client that goes away (or detaches) leaves the process running:
//! breakpoints are removed and the group resumed, and the server keeps
//! listening until it is shut down.
use super::{
    debugger::{AdoptedChild, Debugger},
    inferior::RunState,
    rsp_client::{self, Outcome, Wire},
    target::{DebugBackend, DebugError, DetachMode, ResumeAction, TargetState},
    ui_control::{PanelControl, PanelHandle, Pump},
};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    os::unix::fs::DirBuilderExt,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const INTERRUPT_DEADLINE: Duration = Duration::from_secs(5);
const RUNNING_POLL: Duration = Duration::from_millis(2);
/// How often the in-app panel's controller runs while no client is connected.
const PANEL_TICK: Duration = Duration::from_millis(10);

/// Where a debugger connects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugEndpoints {
    pub unix_socket: PathBuf,
    pub tcp_port: u16,
}
impl DebugEndpoints {
    /// The command to paste into a terminal: gdb over the loopback TCP port.
    pub fn gdb_command(&self) -> String {
        format!("gdb -ex 'target remote 127.0.0.1:{}'", self.tcp_port)
    }
    /// The same through the Unix socket, for clients that can reach one.
    pub fn gdb_unix_command(&self) -> String {
        format!(
            "gdb -ex 'target remote | socat - UNIX-CONNECT:{}'",
            self.unix_socket.display()
        )
    }
}

/// What the app shows about a running server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerStatus {
    pub client_connected: bool,
    pub clients_served: u32,
    /// "running", "stopped at 0x...", "exited", ...
    pub target: String,
    pub ended: Option<String>,
}

struct Resync {
    reason: String,
    leave: bool,
}

struct Shared {
    stop: AtomicBool,
    status: Mutex<ServerStatus>,
    /// The guest's state may have moved under us (a restored snapshot, a
    /// reconnect): what we believe is read again. `leave`: the guest went back in
    /// time, so a connected client's picture of it is wrong.
    resync: Mutex<Option<Resync>>,
}
impl Shared {
    fn update(&self, change: impl FnOnce(&mut ServerStatus)) {
        if let Ok(mut status) = self.status.lock() {
            change(&mut status);
        }
    }
}

pub struct DebugServer {
    endpoints: DebugEndpoints,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
    detach_mode: Arc<Mutex<DetachMode>>,
    panel: PanelHandle,
}

impl DebugServer {
    /// Start serving `backend`. `directory` must be private to the user (the
    /// run's runtime directory); the socket inside gets mode 0600.
    pub fn start(backend: Box<dyn DebugBackend>, directory: &Path) -> Result<Self, String> {
        Self::start_with(backend, None, directory)
    }

    /// Like `start`; with `adopted` the session is one the guest already had and the
    /// list is the other processes it held.
    pub(crate) fn start_with(
        backend: Box<dyn DebugBackend>,
        adopted: Option<Vec<AdoptedChild>>,
        directory: &Path,
    ) -> Result<Self, String> {
        let (unix_socket, temporary) = socket_path(directory)?;
        let _ = std::fs::remove_file(&unix_socket);
        let unix = UnixListener::bind(&unix_socket).map_err(|e| format!("debug socket: {e}"))?;
        std::fs::set_permissions(&unix_socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("debug socket permissions: {e}"))?;
        let tcp = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .map_err(|e| format!("debug port: {e}"))?;
        let tcp_port = tcp.local_addr().map_err(|e| e.to_string())?.port();
        unix.set_nonblocking(true).map_err(|e| e.to_string())?;
        tcp.set_nonblocking(true).map_err(|e| e.to_string())?;
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            status: Mutex::new(ServerStatus {
                target: "attached".into(),
                ..ServerStatus::default()
            }),
            resync: Mutex::new(None),
        });
        let detach_mode = Arc::new(Mutex::new(DetachMode::Resume));
        let (mut panel_control, panel) = PanelControl::new(backend.caps());
        let thread = {
            let shared = shared.clone();
            let detach_mode = detach_mode.clone();
            let socket = unix_socket.clone();
            let temporary = temporary.clone();
            thread::Builder::new()
                .name("antinomie-debug".into())
                .spawn(move || {
                    let mut debugger = Debugger::new(backend);
                    if let Some(children) = adopted {
                        debugger.adopt_existing(children);
                        let _ = debugger.leave_nonstop();
                    }
                    serve(&mut debugger, &mut panel_control, &unix, &tcp, &shared);
                    // A stopped process the client left behind is released.
                    release(&mut debugger);
                    let mode = detach_mode
                        .lock()
                        .map(|mode| *mode)
                        .unwrap_or(DetachMode::Resume);
                    for pid in debugger.pids() {
                        if let Err(error) = debugger.detach(pid, mode, true) {
                            shared.update(|status| {
                                status.ended.get_or_insert(format!("detach: {error}"));
                            });
                        }
                    }
                    let _ = std::fs::remove_file(&socket);
                    if let Some(directory) = temporary {
                        let _ = std::fs::remove_dir(directory);
                    }
                    shared.update(|status| {
                        status.client_connected = false;
                        status.ended.get_or_insert("detached".into());
                    });
                })
                .map_err(|e| e.to_string())?
        };
        Ok(Self {
            endpoints: DebugEndpoints {
                unix_socket,
                tcp_port,
            },
            shared,
            thread: Some(thread),
            detach_mode,
            panel,
        })
    }

    pub fn endpoints(&self) -> &DebugEndpoints {
        &self.endpoints
    }
    /// The in-app panel's side of the server: its requests and its view.
    pub fn panel(&self) -> &PanelHandle {
        &self.panel
    }
    /// The guest was restored from a snapshot (`time_travel`) or reconnected: read
    /// its state again and make its breakpoints what we registered. After a restore
    /// a connected client's session ends (its picture of the target is from another
    /// time); a reconnect changed nothing a client can see.
    pub fn request_resync(&self, reason: &str, time_travel: bool) {
        if let Ok(mut slot) = self.shared.resync.lock() {
            *slot = Some(Resync {
                reason: reason.to_string(),
                leave: time_travel || slot.as_ref().is_some_and(|earlier| earlier.leave),
            });
        }
    }
    pub fn status(&self) -> ServerStatus {
        self.shared
            .status
            .lock()
            .map(|status| status.clone())
            .unwrap_or_default()
    }
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
    /// Ask the server to end: breakpoints out, process resumed (or killed),
    /// sockets closed. It finishes on its own thread; poll `is_finished`. The
    /// thread needs the guest link while it ends, so whoever serves that link
    /// must keep serving until then.
    pub fn request_stop(&mut self, mode: DetachMode) {
        if let Ok(mut slot) = self.detach_mode.lock() {
            *slot = mode;
        }
        self.shared.stop.store(true, Ordering::Release);
    }
    /// `request_stop`, then wait for the thread (for callers that do not own the
    /// link's other end).
    pub fn shutdown(&mut self, mode: DetachMode, deadline: Duration) -> Result<(), String> {
        self.request_stop(mode);
        let until = Instant::now() + deadline;
        while !self.is_finished() {
            if Instant::now() >= until {
                return Err("the debug server did not stop in time".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        self.join()
    }
    /// Join a finished server thread.
    pub fn join(&mut self) -> Result<(), String> {
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| "the debug server thread panicked".to_string()),
            None => Ok(()),
        }
    }
}
/// A Unix socket path must fit `sun_path`: when the run's folder is too deep,
/// use a short private folder under the temporary directory instead (the same
/// rule the QMP socket follows).
fn socket_path(directory: &Path) -> Result<(PathBuf, Option<PathBuf>), String> {
    let name = format!("debug-{}.sock", std::process::id());
    let direct = directory.join(&name);
    if direct.as_os_str().len() <= 100 {
        return Ok((direct, None));
    }
    let short = std::env::temp_dir().join(format!("ant-dbg-{}", crate::storage::unique_id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&short)
        .map_err(|e| format!("debug socket folder: {e}"))?;
    Ok((short.join(&name), Some(short)))
}

impl Drop for DebugServer {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ = self.shutdown(DetachMode::Resume, Duration::from_secs(10));
        }
    }
}

// ---- connection -----------------------------------------------------------

enum Stream {
    Unix(UnixStream),
    Tcp(TcpStream),
}
struct Conn {
    stream: Stream,
    incoming: VecDeque<u8>,
}
impl Conn {
    fn new(stream: Stream) -> io::Result<Self> {
        match &stream {
            Stream::Unix(socket) => socket.set_nonblocking(false)?,
            Stream::Tcp(socket) => {
                socket.set_nonblocking(false)?;
                socket.set_nodelay(true)?;
            }
        }
        Ok(Self {
            stream,
            incoming: VecDeque::new(),
        })
    }
    /// The next byte from the client, waiting up to `timeout`. `Err` is a closed
    /// or broken connection.
    fn read_byte(&mut self, timeout: Duration) -> io::Result<Option<u8>> {
        if let Some(byte) = self.incoming.pop_front() {
            return Ok(Some(byte));
        }
        let timeout = Some(timeout.max(Duration::from_millis(1)));
        let mut buffer = [0u8; 4096];
        let read = match &mut self.stream {
            Stream::Unix(socket) => {
                socket.set_read_timeout(timeout)?;
                socket.read(&mut buffer)
            }
            Stream::Tcp(socket) => {
                socket.set_read_timeout(timeout)?;
                socket.read(&mut buffer)
            }
        };
        match read {
            Ok(0) => Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => {
                self.incoming.extend(&buffer[..count]);
                Ok(self.incoming.pop_front())
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}
impl Wire for Conn {
    fn read_byte(&mut self, timeout: Duration) -> io::Result<Option<u8>> {
        Conn::read_byte(self, timeout)
    }
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let socket: &mut dyn Write = match &mut self.stream {
            Stream::Unix(socket) => socket,
            Stream::Tcp(socket) => socket,
        };
        socket.write_all(data)?;
        socket.flush()
    }
}

// ---- serving ------------------------------------------------------------

fn accept(unix: &UnixListener, tcp: &TcpListener) -> Option<Stream> {
    if let Ok((socket, _)) = unix.accept() {
        // The socket file is 0600 in a private folder; the kernel also tells us
        // who connected.
        let own = rustix::process::getuid().as_raw();
        if rustix::net::sockopt::socket_peercred(&socket).is_ok_and(|peer| peer.uid.as_raw() == own)
        {
            return Some(Stream::Unix(socket));
        }
        return None;
    }
    if let Ok((socket, peer)) = tcp.accept() {
        // A TCP port on loopback is open to every local user: serve only
        // connections made by this user's processes.
        let local = socket.local_addr().ok()?;
        if peer.ip().is_loopback() && tcp_peer_is_this_user(&peer, &local) {
            return Some(Stream::Tcp(socket));
        }
    }
    None
}

/// Whether the process that opened the connection from `peer` to `local` runs
/// as this user, from the kernel's TCP table (`uid` of the client's socket).
pub(super) fn tcp_peer_is_this_user(peer: &SocketAddr, local: &SocketAddr) -> bool {
    let (SocketAddr::V4(peer), SocketAddr::V4(local)) = (peer, local) else {
        return false;
    };
    let Ok(table) = std::fs::read_to_string("/proc/net/tcp") else {
        return false;
    };
    let own = rustix::process::getuid().as_raw();
    let endpoint = |address: &SocketAddrV4| {
        format!(
            "{:08X}:{:04X}",
            u32::from_le_bytes(address.ip().octets()),
            address.port()
        )
    };
    let (client, server) = (endpoint(peer), endpoint(local));
    table.lines().skip(1).any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.get(1) == Some(&client.as_str())
            && fields.get(2) == Some(&server.as_str())
            && fields.get(7).and_then(|uid| uid.parse::<u32>().ok()) == Some(own)
    })
}

fn serve(
    debugger: &mut Debugger,
    panel: &mut PanelControl,
    unix: &UnixListener,
    tcp: &TcpListener,
    shared: &Shared,
) {
    while !shared.stop.load(Ordering::Acquire) {
        if let Some(Resync { reason, .. }) =
            shared.resync.lock().ok().and_then(|mut slot| slot.take())
        {
            let notes = resync(debugger);
            panel.invalidate(debugger);
            shared.update(|status| {
                status.target = format!(
                    "{reason}{}",
                    if notes.is_empty() {
                        String::new()
                    } else {
                        format!(" ({notes})")
                    }
                );
            });
        }
        if let Pump::Ended(why) = panel.pump(debugger) {
            shared.update(|status| {
                status.target = "ended".into();
                status.ended = Some(why);
            });
            return;
        }
        let Some(stream) = accept(unix, tcp) else {
            thread::sleep(PANEL_TICK);
            continue;
        };
        // One controller at a time: the client takes the process, the panel
        // goes read-only until it leaves.
        panel.client_arrived();
        shared.update(|status| {
            status.client_connected = true;
            status.clients_served += 1;
            status.target = "connecting".into();
        });
        let outcome = match Conn::new(stream) {
            Ok(mut conn) => {
                let mut on_state = |state: &str| {
                    shared.update(|status| status.target = state.to_string());
                };
                let mut on_idle = |debugger: &mut Debugger| panel.observe(debugger);
                let leave = || {
                    let mut slot = shared.resync.lock().ok()?;
                    let leaving = slot.as_ref().is_some_and(|resync| resync.leave);
                    leaving.then(|| slot.take().map(|resync| resync.reason))?
                };
                rsp_client::serve(
                    debugger,
                    &mut conn,
                    &shared.stop,
                    rsp_client::Hooks {
                        on_state: &mut on_state,
                        on_idle: &mut on_idle,
                        leave: &leave,
                    },
                )
            }
            Err(error) => Outcome::ClientGone(format!("connection setup: {error}")),
        };
        shared.update(|status| status.client_connected = false);
        match outcome {
            Outcome::Shutdown => return,
            Outcome::ClientGone(why) => {
                resync(debugger);
                release(debugger);
                panel.client_left(debugger);
                shared.update(|status| status.target = format!("running ({why})"));
            }
            Outcome::TargetGone(why) => {
                shared.update(|status| {
                    status.target = "ended".into();
                    status.ended = Some(why);
                });
                return;
            }
        }
    }
}

/// Read every process's state again and make the guest's breakpoints what the
/// session registered. Returns what had to be fixed.
fn resync(debugger: &mut Debugger) -> String {
    let mut notes = Vec::new();
    for pid in debugger.pids() {
        let Some(inferior) = debugger.get(pid) else {
            continue;
        };
        match inferior.backend.state() {
            Ok(TargetState::Stopped(event)) => {
                inferior.run = RunState::Stopped(event);
                inferior.current_tid = event.tid;
                inferior.invalidate();
                inferior.auxv = None;
                inferior.refresh_auxv();
            }
            Ok(TargetState::Running | TargetState::Transition) => inferior.run = RunState::Running,
            Ok(TargetState::Exited { wait_status }) => inferior.run = RunState::Exited(wait_status),
            Ok(TargetState::Replaced) | Err(DebugError::Gone) => {
                inferior.run = RunState::Exited(0);
                notes.push(format!("process {pid} is gone"));
                continue;
            }
            Err(error) => {
                notes.push(format!("process {pid}: {error}"));
                continue;
            }
        }
        if inferior.is_stopped() || inferior.nonstop {
            match inferior.with_registry(|registry, backend| registry.reconcile(backend)) {
                Ok(fixed) if !fixed.is_empty() => notes.push(format!("process {pid}: {fixed}")),
                Ok(_) => {}
                Err(error) => notes.push(format!("process {pid}: breakpoints: {error}")),
            }
        }
    }
    notes.join("; ")
}

/// Take breakpoints out and let every process run, whatever state it is in.
fn release(debugger: &mut Debugger) {
    let _ = debugger.leave_nonstop();
    for pid in debugger.pids() {
        if let Some(inferior) = debugger.get(pid)
            && inferior.is_running()
        {
            let _ = inferior.backend.interrupt();
        }
    }
    let until = Instant::now() + INTERRUPT_DEADLINE;
    while debugger.any_running() && Instant::now() < until {
        if debugger.poll().is_err() {
            break;
        }
        thread::sleep(RUNNING_POLL);
    }
    for pid in debugger.pids() {
        let Some(inferior) = debugger.get(pid) else {
            continue;
        };
        if inferior.is_stopped() {
            inferior.with_registry(|registry, backend| registry.clear_client(backend));
            let _ = debugger.resume(pid, ResumeAction::Continue);
        }
    }
}
