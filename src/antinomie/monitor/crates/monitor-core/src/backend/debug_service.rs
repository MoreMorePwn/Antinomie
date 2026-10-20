// SPDX-License-Identifier: MIT
//! The app side of the debugger: attach to a guest process, run the loopback
//! RSP server, and serve the server thread's guest requests on the transport
//! thread (which alone owns the transport). The server thread never touches the
//! transport; it sends `LinkRequest`s here, restricted to the debug opcodes.
use super::*;
use crate::debug::{
    AdoptedChild, DebugBackend, DebugServer, DetachMode, GuestLink, KernelDebugBackend, LinkError,
    SessionInfo, wire,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicBool;

/// Guest debug opcodes the server thread may send; everything else is refused.
fn allowed(opcode: u32) -> bool {
    (wire::CAPS..=wire::BP_LIST).contains(&opcode)
}

/// Longest the transport thread spends on one debug request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the server thread may wait for an answer before giving up.
const LINK_DEADLINE: Duration = Duration::from_secs(15);
/// How often a waiting request looks at whether the guest is paused.
const LINK_SLICE: Duration = Duration::from_millis(100);

pub(super) struct LinkRequest {
    opcode: u32,
    args: Vec<u8>,
    reply: SyncSender<Result<Vec<u8>, LinkError>>,
}

/// A handle to the transport thread for the debug server thread.
#[derive(Clone)]
pub struct DebugLink {
    requests: SyncSender<LinkRequest>,
    /// The guest is being snapshotted, restored or reconnected: a request waits
    /// for it (the wait does not count against its deadline).
    paused: Arc<AtomicBool>,
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
        let mut waited = Duration::ZERO;
        loop {
            match answer.recv_timeout(LINK_SLICE) {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(LinkError::transport("the app is closing"));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if !self.paused.load(Ordering::Acquire) {
                        waited += LINK_SLICE;
                    }
                    if waited >= LINK_DEADLINE {
                        return Err(LinkError {
                            errno: None,
                            message: "the app did not answer the debug request".into(),
                            outcome_unknown: true,
                        });
                    }
                }
            }
        }
    }
    fn duplicate(&self) -> Option<Box<dyn GuestLink + Send>> {
        Some(Box::new(self.clone()))
    }
}

/// While alive, debug requests wait instead of timing out: the guest is being
/// snapshotted, restored or reconnected.
pub(super) struct DebugPause(Arc<AtomicBool>);
impl Drop for DebugPause {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The transport thread's own path to the guest, used while it executes the
/// attach command (it cannot wait for itself).
pub(super) struct WorkerLink<'a> {
    pub(super) session: &'a mut Session,
    pub(super) snapshot: &'a mut Snapshot,
    pub(super) sender: &'a SyncSender<Notification>,
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
    /// The panel view last published, by epoch.
    last_view: Option<u64>,
    /// Debug requests wait while the guest moves (snapshot, restore, reconnect).
    paused: Arc<AtomicBool>,
    /// When a debug client last had a request served. A client of the debug link
    /// that is not the loopback server (the in-app debugger, a test) keeps the
    /// worker loop on its short wait for a while after each request.
    last_served: Option<Instant>,
}
impl DebugService {
    pub(super) fn new() -> (Self, DebugLink) {
        let (sender, requests) = mpsc::sync_channel(64);
        let paused = Arc::new(AtomicBool::new(false));
        let link = DebugLink {
            requests: sender,
            paused: paused.clone(),
        };
        (
            Self {
                requests,
                link: link.clone(),
                active: None,
                last_shown: None,
                last_view: None,
                paused,
                last_served: None,
            },
            link,
        )
    }
    pub(super) fn is_active(&self) -> bool {
        self.active.is_some()
    }
    /// Hold debug requests until the returned guard is dropped.
    pub(super) fn pause(&self) -> DebugPause {
        self.paused.store(true, Ordering::Release);
        DebugPause(self.paused.clone())
    }
    /// The worker loop should wait briefly between passes: a debugger's round
    /// trips each wait for it.
    pub(super) fn is_busy(&self) -> bool {
        self.active.is_some()
            || self
                .last_served
                .is_some_and(|served| served.elapsed() < Duration::from_secs(2))
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
            self.debug.last_served = Some(Instant::now());
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
        self.debug_reap_ended();
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

    /// A request from the in-app panel: queued for the controller on the
    /// server thread, which answers through `Snapshot::debug_view`. Refused
    /// while an external debugger controls the process.
    pub(super) fn debug_panel_request(
        &mut self,
        request: crate::debug::view::DebugRequest,
    ) -> Result<String, String> {
        let active = self
            .debug
            .active
            .as_ref()
            .ok_or("no debugger is attached")?;
        active.server.panel().submit(request)?;
        Ok(String::new())
    }

    /// A debugger whose target ended (the process exited or was killed) is not
    /// holding the slot: finish it so another program can be debugged.
    pub(super) fn debug_reap_ended(&mut self) {
        let ended = self.debug.active.as_ref().is_some_and(|active| {
            active.server.status().ended.is_some() || active.server.is_finished()
        });
        if ended {
            let _ = self.debug_detach(false);
        }
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
        self.snapshot.debug_view = None;
        self.debug.last_shown = None;
        self.debug.last_view = None;
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
        let view = self
            .debug
            .active
            .as_ref()
            .map(|active| active.server.panel().clone());
        let view_epoch = view.as_ref().map(|panel| panel.epoch());
        let mut changed = false;
        if view_epoch != self.debug.last_view {
            self.snapshot.debug_view = view.map(|panel| panel.view());
            self.debug.last_view = view_epoch;
            changed = true;
        }
        if shown != self.debug.last_shown {
            self.snapshot.debug = shown.clone();
            self.debug.last_shown = shown;
            changed = true;
        }
        if changed {
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
            self.snapshot.debug_view = None;
            self.debug.last_shown = None;
            self.debug.last_view = None;
        }
    }

    /// The guest moved under the debugger: a snapshot was restored or the
    /// transport reconnected. A session of ours is read again (its breakpoints made
    /// what we registered, a connected client told to go: its picture of the target
    /// is from another time); without one, sessions the guest holds are adopted.
    pub(super) fn debug_guest_moved(&mut self, reason: &str, time_travel: bool) {
        self.debug_reap_ended();
        if let Some(active) = self.debug.active.as_ref() {
            active.server.request_resync(reason, time_travel);
            return;
        }
        if let Some(message) = self.debug_adopt_existing() {
            self.emit(Notification::CommandResult {
                id: 0,
                success: true,
                message,
            });
        }
    }

    /// Find the sessions the guest holds and make a debugger of them: the
    /// breakpoints and the stopped threads are still there.
    fn debug_adopt_existing(&mut self) -> Option<String> {
        if self.debug.active.is_some() {
            return None;
        }
        let session = self.session.as_mut()?;
        // The restored guest's description is not read yet; the probe itself
        // tells whether it speaks the contract (an older one refuses).
        let boot_id = self.snapshot.boot_id.clone().unwrap_or_default();
        let mut link = WorkerLink {
            session,
            snapshot: &mut self.snapshot,
            sender: &self.sender,
        };
        let caps = KernelDebugBackend::probe(&mut link).ok()?;
        if !caps.adopt {
            return None;
        }
        let live: Vec<SessionInfo> = KernelDebugBackend::list_sessions(&mut link)
            .ok()?
            .into_iter()
            .filter(|info| info.state != wire::STATE_EXITED && info.state != wire::STATE_EXEC)
            .collect();
        let root = live.iter().find(|info| info.parent_session == 0)?.clone();
        let identity_of = |info: &SessionInfo| crate::observation::GuestProcessIdentity {
            boot_id: boot_id.clone(),
            task_cookie: info.task_cookie,
            tgid: info.tgid,
            start_boot_ns: info.start_boot_ns,
        };
        let mut adopt = |info: &SessionInfo| -> Option<KernelDebugBackend> {
            let identity = identity_of(info);
            let attached = KernelDebugBackend::adopt_session(
                &mut link,
                caps.clone(),
                &identity,
                nonce(&identity),
            )
            .ok()?;
            Some(KernelDebugBackend::adopted(
                Box::new(self.debug.link.clone()),
                attached,
                info,
            ))
        };
        let root_backend = adopt(&root)?;
        let architecture = caps.arch.name();
        let mut children = Vec::new();
        for info in live.iter().filter(|info| info.session != root.session) {
            if let Some(backend) = adopt(info) {
                children.push(AdoptedChild {
                    backend: Box::new(backend),
                    parent_session: info.parent_session,
                    shared_memory: info.shared_memory,
                    nonstop: info.nonstop,
                });
            }
        }
        let directory = self.session.as_ref()?.process.runtime_dir.clone();
        let count = children.len() + 1;
        let server = DebugServer::start_with(
            Box::new(root_backend) as Box<dyn DebugBackend>,
            Some(children),
            &directory,
        )
        .ok()?;
        let message = format!(
            "debugger re-attached to {count} process(es) the guest still had under debug: {}",
            server.endpoints().gdb_command()
        );
        self.debug.active = Some(ActiveDebug {
            server,
            target: identity_of(&root),
            architecture,
        });
        self.refresh_debug_info();
        self.publish();
        Some(message)
    }
}

#[cfg(test)]
mod tests;
