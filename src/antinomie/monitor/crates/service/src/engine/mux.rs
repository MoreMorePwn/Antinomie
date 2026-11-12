// SPDX-License-Identifier: GPL-3.0-only
//! One engine, several waiters (addendum P5-1 card A): the lane's waiter and
//! one per host worker share the daemon's single `Backend`.
//!
//! [`Mux`] holds the engine; every [`Handle`] is an [`Engine`] of its own, so
//! a [`Waiter`](crate::waiter::Waiter) works on it unchanged. What the engine
//! sends is routed:
//!
//! | Notification | Goes to |
//! |---|---|
//! | `CommandResult { id }` | the handle that sent command `id` (by id); an id no handle sent goes to the first handle (the lane) |
//! | `Snapshot` | every handle; a handle keeps only the latest one it has not taken |
//! | `AnalysisUpdated` | every handle (a host worker waits on its static analysis) |
//! | `Terminal`, `TerminalScreen`, `RunStarted` | the first handle (the lane runs the program) |
//!
//! Whoever receives pulls from the engine for a short slice while holding the
//! lock, routes what came, and takes its own next notification; nobody needs a
//! thread of its own. A handle that is dropped stops receiving: results still
//! owed to it are discarded. The engine itself is shut down once, through
//! [`Mux::into_engine`] after every handle is gone.
use super::Engine;
use antinomie_monitor_core::{Command, Notification};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

/// How long one receive holds the engine.
const SLICE: Duration = Duration::from_millis(20);
/// Notifications a handle may have waiting besides its snapshot; beyond it the
/// oldest terminal output is dropped (the engine drops it too when a lane is
/// full, and the waiter keeps only a tail).
const QUEUE_CAP: usize = 4096;

pub(super) struct State<E> {
    pub(super) engine: E,
    routes: HashMap<u64, usize>,
    queues: Vec<Option<VecDeque<Notification>>>,
    gone: Option<String>,
}

pub struct Mux<E: Engine> {
    pub(super) state: Mutex<State<E>>,
}

/// One connection to the shared engine.
pub struct Handle<E: Engine> {
    mux: Option<Arc<Mux<E>>>,
    slot: usize,
}

fn lock<E>(mux: &Mutex<State<E>>) -> MutexGuard<'_, State<E>> {
    mux.lock().unwrap_or_else(|p| p.into_inner())
}

impl<E: Engine> Mux<E> {
    pub fn new(engine: E) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                engine,
                routes: HashMap::new(),
                queues: Vec::new(),
                gone: None,
            }),
        })
    }

    /// A new handle. The first one made is the lane's: it gets what belongs to
    /// no command (terminal output, run starts, results of unknown ids).
    pub fn handle(self: &Arc<Self>) -> Handle<E> {
        let mut state = lock(&self.state);
        state.queues.push(Some(VecDeque::new()));
        Handle {
            mux: Some(Arc::clone(self)),
            slot: state.queues.len() - 1,
        }
    }

    /// The engine back, once no handle is left.
    pub fn into_engine(this: Arc<Self>) -> Result<E, String> {
        match Arc::try_unwrap(this) {
            Ok(mux) => Ok(mux
                .state
                .into_inner()
                .unwrap_or_else(|p| p.into_inner())
                .engine),
            Err(_) => Err("a connection to the engine is still open".into()),
        }
    }
}

impl<E> State<E> {
    fn push(&mut self, slot: usize, notification: Notification) {
        if let Some(Some(queue)) = self.queues.get_mut(slot) {
            if queue.len() >= QUEUE_CAP
                && let Some(at) = queue
                    .iter()
                    .position(|n| matches!(n, Notification::Terminal { .. }))
            {
                queue.remove(at);
            }
            queue.push_back(notification);
        }
    }

    fn first_live(&self) -> Option<usize> {
        self.queues.iter().position(Option::is_some)
    }

    pub(super) fn route(&mut self, notification: Notification) {
        match notification {
            Notification::Snapshot(_) | Notification::AnalysisUpdated { .. } => {
                let snapshot = matches!(notification, Notification::Snapshot(_));
                for queue in self.queues.iter_mut().flatten() {
                    if snapshot {
                        queue.retain(|n| !matches!(n, Notification::Snapshot(_)));
                    }
                    queue.push_back(notification.clone());
                }
            }
            Notification::CommandResult { id, .. } => {
                let to = self
                    .routes
                    .remove(&id)
                    .filter(|slot| matches!(self.queues.get(*slot), Some(Some(_))))
                    .or_else(|| self.first_live());
                if let Some(slot) = to {
                    self.push(slot, notification);
                }
            }
            other => {
                if let Some(slot) = self.first_live() {
                    self.push(slot, other);
                }
            }
        }
    }
}

impl<E: Engine> Handle<E> {
    fn mux(&self) -> &Arc<Mux<E>> {
        self.mux.as_ref().expect("a live handle")
    }

    /// This handle's place: 0 is the lane's.
    pub fn slot(&self) -> usize {
        self.slot
    }

    /// Close this handle and hand back the engine when it was the last one.
    pub fn into_engine(mut self) -> Result<E, String> {
        let mux = self.mux.take().expect("a live handle");
        {
            let mut state = lock(&mux.state);
            close(&mut state, self.slot);
        }
        Mux::into_engine(mux)
    }
}

fn close<E>(state: &mut State<E>, slot: usize) {
    if let Some(queue) = state.queues.get_mut(slot) {
        *queue = None;
    }
    state.routes.retain(|_, to| *to != slot);
}

impl<E: Engine> Drop for Handle<E> {
    fn drop(&mut self) {
        if let Some(mux) = self.mux.take() {
            let mut state = lock(&mux.state);
            close(&mut state, self.slot);
        }
    }
}

impl<E: Engine> Engine for Handle<E> {
    fn send(&mut self, command: Command) -> Result<u64, String> {
        let mut state = lock(&self.mux().state);
        if let Some(gone) = &state.gone {
            return Err(gone.clone());
        }
        // The route is in place before anyone can receive the result: both
        // happen under the lock.
        let id = state.engine.send(command)?;
        state.routes.insert(id, self.slot);
        Ok(id)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Notification>, String> {
        let mut state = lock(&self.mux().state);
        if let Some(Some(queue)) = state.queues.get_mut(self.slot)
            && let Some(next) = queue.pop_front()
        {
            return Ok(Some(next));
        }
        if let Some(gone) = &state.gone {
            return Err(gone.clone());
        }
        match state.engine.recv(timeout.min(SLICE)) {
            Ok(Some(notification)) => state.route(notification),
            Ok(None) => return Ok(None),
            Err(error) => {
                state.gone = Some(error.clone());
                return Err(error);
            }
        }
        // Drain what else is ready, so a result is not held up by a snapshot.
        for _ in 0..64 {
            match state.engine.recv(Duration::ZERO) {
                Ok(Some(notification)) => state.route(notification),
                Ok(None) => break,
                Err(error) => {
                    state.gone = Some(error);
                    break;
                }
            }
        }
        Ok(state
            .queues
            .get_mut(self.slot)
            .and_then(|q| q.as_mut())
            .and_then(VecDeque::pop_front))
    }

    /// Only the engine's owner stops it ([`Mux::into_engine`]); a handle has
    /// nothing of its own to release.
    fn shutdown(&mut self) -> Result<(), String> {
        Ok(())
    }

    /// The actor is the shared engine's: only the lane's handle sets it.
    fn set_custody_actor(&mut self, actor: Option<&str>) -> Result<(), String> {
        lock(&self.mux().state).engine.set_custody_actor(actor)
    }
}
