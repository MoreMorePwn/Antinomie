// SPDX-License-Identifier: MIT
//! The RSP server: a loopback Unix socket and an ephemeral 127.0.0.1 TCP port,
//! one client at a time, driving the `gdbstub` state machine against a
//! `DebugBackend`. It never binds a non-loopback address. A client that goes
//! away (or detaches) leaves the process running: breakpoints are removed and
//! the group resumed, and the server keeps listening until it is shut down.
use super::{
    rsp_target::{PACKET_BUFFER, RspTarget},
    target::{DebugBackend, DebugError, DetachMode, TargetState},
};
use gdbstub::{
    conn::Connection,
    stub::{DisconnectReason, GdbStub, MultiThreadStopReason, state_machine::GdbStubStateMachine},
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

const GONE: &str = "the guest ended the debug session";
const INTERRUPT_DEADLINE: Duration = Duration::from_secs(5);
const IDLE_POLL: Duration = Duration::from_millis(50);
const RUNNING_POLL: Duration = Duration::from_millis(2);

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

struct Shared {
    stop: AtomicBool,
    status: Mutex<ServerStatus>,
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
}

impl DebugServer {
    /// Start serving `backend`. `directory` must be private to the user (the
    /// run's runtime directory); the socket inside gets mode 0600.
    pub fn start(backend: Box<dyn DebugBackend>, directory: &Path) -> Result<Self, String> {
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
        });
        let detach_mode = Arc::new(Mutex::new(DetachMode::Resume));
        let thread = {
            let shared = shared.clone();
            let detach_mode = detach_mode.clone();
            let socket = unix_socket.clone();
            let temporary = temporary.clone();
            thread::Builder::new()
                .name("antinomie-debug".into())
                .spawn(move || {
                    let mut target = RspTarget::new(backend);
                    serve(&mut target, &unix, &tcp, &shared);
                    // A stopped process the client left behind is released.
                    release(&mut target);
                    let mode = detach_mode
                        .lock()
                        .map(|mode| *mode)
                        .unwrap_or(DetachMode::Resume);
                    if let Err(error) = target.backend().detach(mode) {
                        shared.update(|status| {
                            status.ended.get_or_insert(format!("detach: {error}"));
                        });
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
        })
    }

    pub fn endpoints(&self) -> &DebugEndpoints {
        &self.endpoints
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
    outgoing: Vec<u8>,
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
            outgoing: Vec::new(),
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
impl Connection for Conn {
    type Error = io::Error;
    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        self.outgoing.push(byte);
        Ok(())
    }
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.outgoing.extend_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        let data = std::mem::take(&mut self.outgoing);
        let socket: &mut dyn Write = match &mut self.stream {
            Stream::Unix(socket) => socket,
            Stream::Tcp(socket) => socket,
        };
        socket.write_all(&data)?;
        socket.flush()
    }
}

// ---- serving ------------------------------------------------------------

enum Outcome {
    /// The client left; the process lives on.
    ClientGone(String),
    /// The target ended or the client killed it: nothing more to debug.
    TargetGone(String),
    Shutdown,
}

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

fn serve(target: &mut RspTarget, unix: &UnixListener, tcp: &TcpListener, shared: &Shared) {
    while !shared.stop.load(Ordering::Acquire) {
        let Some(stream) = accept(unix, tcp) else {
            thread::sleep(Duration::from_millis(20));
            continue;
        };
        shared.update(|status| {
            status.client_connected = true;
            status.clients_served += 1;
            status.target = "connecting".into();
        });
        let outcome = match Conn::new(stream) {
            Ok(conn) => session(target, conn, shared),
            Err(error) => Outcome::ClientGone(format!("connection setup: {error}")),
        };
        shared.update(|status| status.client_connected = false);
        match outcome {
            Outcome::Shutdown => return,
            Outcome::ClientGone(why) => {
                release(target);
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

/// Take breakpoints out and let the process run, whatever state it is in.
fn release(target: &mut RspTarget) {
    if target.is_running() && target.interrupt().is_ok() {
        let until = Instant::now() + INTERRUPT_DEADLINE;
        while Instant::now() < until {
            match target.poll() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => thread::sleep(RUNNING_POLL),
            }
        }
    }
    if !target.is_running() {
        target.clear_all_breakpoints();
        let _ = target.resume_plain();
    }
}

fn wait_for_stop(
    target: &mut RspTarget,
    stop: &AtomicBool,
) -> Result<MultiThreadStopReason<u64>, DebugError> {
    let until = Instant::now() + INTERRUPT_DEADLINE;
    loop {
        if let Some(reason) = target.poll()? {
            return Ok(reason);
        }
        if stop.load(Ordering::Acquire) || Instant::now() >= until {
            let why = target
                .backend()
                .take_failure()
                .unwrap_or_else(|| "the process did not stop in time".into());
            return Err(DebugError::Transport(why));
        }
        thread::sleep(RUNNING_POLL);
    }
}

fn describe(reason: &MultiThreadStopReason<u64>) -> String {
    match reason {
        MultiThreadStopReason::Exited(code) => format!("exited with status {code}"),
        MultiThreadStopReason::Terminated(signal) => format!("killed by signal {}", signal.0),
        _ => "stopped".into(),
    }
}

fn session(target: &mut RspTarget, conn: Conn, shared: &Shared) -> Outcome {
    // A debugger expects a stopped target at connect.
    match target.adopt() {
        Ok(TargetState::Stopped(_)) => {}
        Ok(TargetState::Exited { .. } | TargetState::Replaced) => {
            return Outcome::TargetGone("the process has already ended".into());
        }
        Ok(TargetState::Running | TargetState::Transition) => {
            if let Err(error) = target.interrupt() {
                return Outcome::ClientGone(format!("cannot stop the process: {error}"));
            }
            if let Err(error) = wait_for_stop(target, &shared.stop) {
                return Outcome::ClientGone(error.to_string());
            }
        }
        Err(DebugError::Gone) => return Outcome::TargetGone(GONE.into()),
        Err(error) => return Outcome::ClientGone(error.to_string()),
    }
    let stub = match GdbStub::builder(conn)
        .packet_buffer_size(PACKET_BUFFER)
        .build()
    {
        Ok(stub) => stub,
        Err(error) => return Outcome::ClientGone(format!("{error:?}")),
    };
    let mut machine = match stub.run_state_machine(target) {
        Ok(machine) => machine,
        Err(error) => return Outcome::ClientGone(error.to_string()),
    };
    shared.update(|status| status.target = "stopped".into());
    loop {
        if shared.stop.load(Ordering::Acquire) {
            return Outcome::Shutdown;
        }
        let next = match machine {
            GdbStubStateMachine::Idle(mut inner) => {
                match inner.borrow_conn().read_byte(IDLE_POLL) {
                    Ok(Some(byte)) => inner.incoming_data(target, byte),
                    Ok(None) => Ok(inner.into()),
                    Err(error) => return Outcome::ClientGone(error.to_string()),
                }
            }
            GdbStubStateMachine::Running(mut inner) => {
                match inner.borrow_conn().read_byte(RUNNING_POLL) {
                    Ok(Some(byte)) => inner.incoming_data(target, byte),
                    Ok(None) => match target.poll() {
                        Ok(Some(reason)) => {
                            shared.update(|status| status.target = describe(&reason));
                            inner.report_stop(target, reason)
                        }
                        Ok(None) => Ok(inner.into()),
                        Err(DebugError::Gone) => return Outcome::TargetGone(GONE.into()),
                        Err(error) => return Outcome::ClientGone(error.to_string()),
                    },
                    Err(error) => return Outcome::ClientGone(error.to_string()),
                }
            }
            GdbStubStateMachine::CtrlCInterrupt(inner) => {
                let was_running = target.is_running();
                if was_running && let Err(error) = target.interrupt() {
                    return Outcome::ClientGone(format!("interrupt: {error}"));
                }
                let reason = if was_running {
                    match wait_for_stop(target, &shared.stop) {
                        Ok(reason) => Some(reason),
                        Err(error) => return Outcome::ClientGone(error.to_string()),
                    }
                } else {
                    None
                };
                inner.interrupt_handled(target, reason)
            }
            GdbStubStateMachine::Disconnected(inner) => {
                return match inner.get_reason() {
                    DisconnectReason::Disconnect => Outcome::ClientGone("detached".into()),
                    DisconnectReason::Kill => {
                        target.clear_all_breakpoints();
                        let _ = target.backend().detach(DetachMode::Kill);
                        Outcome::TargetGone("killed by the debugger".into())
                    }
                    DisconnectReason::TargetExited(code) => {
                        Outcome::TargetGone(format!("exited with status {code}"))
                    }
                    DisconnectReason::TargetTerminated(signal) => {
                        Outcome::TargetGone(format!("killed by signal {}", signal.0))
                    }
                };
            }
        };
        machine = match next {
            Ok(machine) => machine,
            Err(error) => return Outcome::ClientGone(error.to_string()),
        };
    }
}
