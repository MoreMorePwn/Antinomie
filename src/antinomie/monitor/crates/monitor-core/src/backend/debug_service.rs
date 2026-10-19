// SPDX-License-Identifier: MIT
//! The app side of the debugger: attach to a guest process, run the loopback
//! RSP server, and serve the server thread's guest requests on the transport
//! thread (which alone owns the transport). The server thread never touches the
//! transport; it sends `LinkRequest`s here, restricted to the debug opcodes.
use super::*;
use crate::debug::{DebugServer, DetachMode, GuestLink, KernelDebugBackend, LinkError, wire};
use sha2::{Digest, Sha256};

/// Guest debug opcodes the server thread may send; everything else is refused.
fn allowed(opcode: u32) -> bool {
    (wire::CAPS..=wire::BP_CLEAR).contains(&opcode)
}

/// Longest the transport thread spends on one debug request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the server thread may wait for an answer before giving up.
const LINK_DEADLINE: Duration = Duration::from_secs(15);

pub(super) struct LinkRequest {
    opcode: u32,
    args: Vec<u8>,
    reply: SyncSender<Result<Vec<u8>, LinkError>>,
}

/// A handle to the transport thread for the debug server thread.
#[derive(Clone)]
pub struct DebugLink {
    requests: SyncSender<LinkRequest>,
}
impl GuestLink for DebugLink {
    fn request(&mut self, opcode: u32, args: &[u8]) -> Result<Vec<u8>, LinkError> {
        let (reply, answer) = mpsc::sync_channel(1);
        self.requests
            .send(LinkRequest {
                opcode,
                args: args.to_vec(),
                reply,
            })
            .map_err(|_| LinkError::transport("the app is closing"))?;
        answer.recv_timeout(LINK_DEADLINE).map_err(|_| LinkError {
            errno: None,
            message: "the app did not answer the debug request".into(),
            outcome_unknown: true,
        })?
    }
}

/// The transport thread's own path to the guest, used while it executes the
/// attach command (it cannot wait for itself).
struct WorkerLink<'a> {
    session: &'a mut Session,
    snapshot: &'a mut Snapshot,
    sender: &'a SyncSender<Notification>,
}
impl GuestLink for WorkerLink<'_> {
    fn request(&mut self, opcode: u32, args: &[u8]) -> Result<Vec<u8>, LinkError> {
        guest_request(self.session, opcode, args, self.snapshot, self.sender)
    }
}

fn guest_request(
    session: &mut Session,
    opcode: u32,
    args: &[u8],
    snapshot: &mut Snapshot,
    sender: &SyncSender<Notification>,
) -> Result<Vec<u8>, LinkError> {
    if !allowed(opcode) {
        return Err(LinkError::transport("not a debug command"));
    }
    session
        .request_typed(opcode, args, snapshot, sender, REQUEST_TIMEOUT)
        .map_err(|error| match error {
            RequestError::Rejected { status, message } => LinkError {
                errno: Some(-status),
                message,
                outcome_unknown: false,
            },
            RequestError::TimedOut(message) => LinkError {
                errno: None,
                message,
                outcome_unknown: true,
            },
            RequestError::Failed(message) => LinkError::transport(message),
        })
}

pub(super) struct ActiveDebug {
    server: DebugServer,
    target: crate::observation::GuestProcessIdentity,
    architecture: &'static str,
}

pub(super) struct DebugService {
    requests: Receiver<LinkRequest>,
    link: DebugLink,
    active: Option<ActiveDebug>,
    last_shown: Option<DebugSessionInfo>,
}
impl DebugService {
    pub(super) fn new() -> (Self, DebugLink) {
        let (sender, requests) = mpsc::sync_channel(64);
        let link = DebugLink { requests: sender };
        (
            Self {
                requests,
                link: link.clone(),
                active: None,
                last_shown: None,
            },
            link,
        )
    }
    pub(super) fn is_active(&self) -> bool {
        self.active.is_some()
    }
}

fn nonce(target: &crate::observation::GuestProcessIdentity) -> [u64; 2] {
    let digest = Sha256::digest(
        format!(
            "{}:{}:{}:{}",
            storage::unique_id(),
            target.task_cookie,
            target.start_boot_ns,
            target.tgid
        )
        .as_bytes(),
    );
    [
        u64::from_le_bytes(digest[..8].try_into().expect("digest extent")) | 1,
        u64::from_le_bytes(digest[8..16].try_into().expect("digest extent")),
    ]
}

impl Worker {
    /// Answer the debug server's pending guest requests.
    pub(super) fn serve_debug_requests(&mut self) {
        for _ in 0..64 {
            let Ok(request) = self.debug.requests.try_recv() else {
                return;
            };
            let result = match self.session.as_mut() {
                Some(session) => guest_request(
                    session,
                    request.opcode,
                    &request.args,
                    &mut self.snapshot,
                    &self.sender,
                ),
                None => Err(LinkError::transport("the VM is stopped")),
            };
            let _ = request.reply.send(result);
        }
    }

    pub(super) fn debug_attach(
        &mut self,
        identity: crate::observation::GuestProcessIdentity,
    ) -> Result<String, String> {
        if self.debug.active.is_some() {
            return Err("a debugger is already attached; detach it first".into());
        }
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        if !self
            .snapshot
            .guest_kernel
            .as_ref()
            .and_then(|kernel| kernel.revision)
            .is_some_and(|revision| revision >= 17)
        {
            return Err("the debugger needs a revision-17 guest".into());
        }
        let mut link = WorkerLink {
            session,
            snapshot: &mut self.snapshot,
            sender: &self.sender,
        };
        let attached =
            KernelDebugBackend::attach_session(&mut link, &identity, nonce(&identity), false)
                .map_err(|error| error.to_string())?;
        let architecture = attached.caps.arch.name();
        let session_id = attached.session;
        let backend = KernelDebugBackend::new(Box::new(self.debug.link.clone()), attached);
        let directory = session.process.runtime_dir.clone();
        let server = match DebugServer::start(Box::new(backend), &directory) {
            Ok(server) => server,
            Err(error) => {
                // The guest session is open: close it again.
                let mut link = WorkerLink {
                    session,
                    snapshot: &mut self.snapshot,
                    sender: &self.sender,
                };
                let _ = link.request(wire::DETACH, &wire::detach_request(session_id, false));
                return Err(error);
            }
        };
        let message = format!(
            "debugger attached to PID {}: {}",
            identity.tgid,
            server.endpoints().gdb_command()
        );
        self.debug.active = Some(ActiveDebug {
            server,
            target: identity,
            architecture,
        });
        self.refresh_debug_info();
        self.publish();
        Ok(message)
    }

    pub(super) fn debug_detach(&mut self, kill: bool) -> Result<String, String> {
        let Some(mut active) = self.debug.active.take() else {
            return Err("no debugger is attached".into());
        };
        active.server.request_stop(if kill {
            DetachMode::Kill
        } else {
            DetachMode::Resume
        });
        let until = Instant::now() + Duration::from_secs(20);
        while !active.server.is_finished() {
            self.serve_debug_requests();
            if Instant::now() >= until {
                self.debug.active = Some(active);
                return Err("the debugger did not detach in time".into());
            }
            thread::sleep(Duration::from_millis(1));
        }
        let joined = active.server.join();
        let status = active.server.status();
        self.snapshot.debug = None;
        self.debug.last_shown = None;
        self.publish();
        joined?;
        Ok(match status.ended {
            Some(why) if why != "detached" => format!("debugger detached ({why})"),
            _ => "debugger detached; the process continues".into(),
        })
    }

    /// Keep `Snapshot::debug` current.
    pub(super) fn refresh_debug_info(&mut self) {
        let shown = self.debug.active.as_ref().map(|active| {
            let status = active.server.status();
            let endpoints = active.server.endpoints();
            DebugSessionInfo {
                target: active.target.clone(),
                architecture: active.architecture.to_string(),
                unix_socket: endpoints.unix_socket.clone(),
                tcp_port: endpoints.tcp_port,
                gdb_command: endpoints.gdb_command(),
                gdb_unix_command: endpoints.gdb_unix_command(),
                client_connected: status.client_connected,
                clients_served: status.clients_served,
                target_state: status.target,
                ended: status.ended,
            }
        });
        if shown != self.debug.last_shown {
            self.snapshot.debug = shown.clone();
            self.debug.last_shown = shown;
            self.publish();
        }
    }

    /// The VM went away under the debugger, or the app is closing.
    pub(super) fn end_debug(&mut self) {
        if self.debug.active.is_some() {
            let _ = self.debug_detach(false);
            if self.debug.active.is_some() {
                self.debug.active = None;
            }
        }
        if self.snapshot.debug.is_some() {
            self.snapshot.debug = None;
            self.debug.last_shown = None;
        }
    }

    /// A VM snapshot would capture a stopped, instrumented process.
    pub(super) fn debug_snapshot_guard(&self) -> Result<(), String> {
        if self.debug.active.is_some() {
            return Err("detach the debugger before taking or restoring a VM snapshot".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
