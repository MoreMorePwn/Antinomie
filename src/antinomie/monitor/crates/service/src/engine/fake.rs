// SPDX-License-Identifier: GPL-3.0-only
//! [`FakeEngine`]: an [`Engine`] that plays a script (design 7.1).
//!
//! A script is a list of steps per command name. When the pipeline sends
//! `Start`, the next `Start` step says what the real engine would do: reply
//! with a result after some delay, change the [`Snapshot`] at later times, say
//! nothing at all, or die. Time is a [`ManualClock`]: a receive with nothing
//! due moves the clock by the timeout, and one with a later item inside the
//! timeout moves it to that item, so a thirty-minute layer wait costs
//! nothing and every deadline can be crossed.
//!
//! Every command is recorded in order ([`FakeEngine::sent`]).
use super::Engine;
use crate::clock::{Clock, ManualClock};
use antinomie_monitor_core::{Command, Notification, Snapshot};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

/// What the engine answers to a command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// `CommandResult { success: true }` with this message.
    Ok(String),
    /// `CommandResult { success: false }` with this message.
    Fail(String),
    /// No result ever: the guest or the engine is silent.
    Silent,
    /// `send` itself fails (the command queue is closed).
    SendError(String),
    /// The engine dies when the command arrives: no result, and every later
    /// `send` and `recv` fails.
    Die,
}

type Mutation = Arc<dyn Fn(&mut Snapshot) + Send + Sync>;

/// A change that happens some time after the command.
#[derive(Clone)]
pub enum Change {
    /// Edit the engine's snapshot; a `Snapshot` notification follows.
    Snapshot(Mutation),
    /// Any other notification, as it is.
    Notify(Box<Notification>),
}

impl Change {
    pub fn snapshot(edit: impl Fn(&mut Snapshot) + Send + Sync + 'static) -> Self {
        Self::Snapshot(Arc::new(edit))
    }
}

/// One scripted answer.
#[derive(Clone)]
pub struct Step {
    pub reply: Reply,
    /// Delay of the reply after the command.
    pub after: Duration,
    /// Later happenings, each with its delay after the command.
    pub changes: Vec<(Duration, Change)>,
    /// Keep using this step after it ran, instead of passing to the next.
    pub forever: bool,
}

impl Step {
    pub fn new(reply: Reply) -> Self {
        Self {
            reply,
            after: Duration::ZERO,
            changes: Vec::new(),
            forever: false,
        }
    }
}

/// A command the fake received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub id: u64,
    pub name: String,
    /// The `Debug` text of the command, for tests that check a field.
    pub detail: String,
    pub at_ms: u64,
}

enum Item {
    Result { id: u64, reply: Reply },
    Change(Box<Change>),
}

/// What the fake does with a command no step covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unscripted {
    /// Answer with a failure naming the command: a test that forgot a step
    /// fails loudly instead of passing by luck.
    Fail,
    /// Answer success with an empty message.
    Ok,
}

pub struct FakeEngine {
    clock: Arc<ManualClock>,
    snapshot: Snapshot,
    steps: BTreeMap<String, VecDeque<Step>>,
    due: Vec<(u64, u64, Item)>,
    order: u64,
    next_id: u64,
    sent: Arc<Mutex<Vec<Sent>>>,
    dead: Option<String>,
    unscripted: Unscripted,
    shutdowns: usize,
}

impl FakeEngine {
    pub fn new(clock: Arc<ManualClock>) -> Self {
        Self {
            clock,
            snapshot: Snapshot::default(),
            steps: BTreeMap::new(),
            due: Vec::new(),
            order: 0,
            next_id: 0,
            sent: Arc::default(),
            dead: None,
            unscripted: Unscripted::Fail,
            shutdowns: 0,
        }
    }

    pub fn clock(&self) -> &Arc<ManualClock> {
        &self.clock
    }

    /// The snapshot the engine would send now.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// Set the state the engine starts in; its first snapshot is sent at once.
    pub fn start_with(&mut self, edit: impl FnOnce(&mut Snapshot)) -> &mut Self {
        edit(&mut self.snapshot);
        let notification = Notification::Snapshot(self.snapshot.clone());
        self.schedule(
            0,
            Item::Change(Box::new(Change::Notify(Box::new(notification)))),
        );
        self
    }

    /// The snapshot changes `delay` from now, with no command behind it (the
    /// engine finishing a disk layer on its own).
    pub fn after(
        &mut self,
        delay: Duration,
        edit: impl Fn(&mut Snapshot) + Send + Sync + 'static,
    ) -> &mut Self {
        self.schedule(ms(delay), Item::Change(Box::new(Change::snapshot(edit))));
        self
    }

    pub fn unscripted(&mut self, behaviour: Unscripted) -> &mut Self {
        self.unscripted = behaviour;
        self
    }

    /// Script the next answer to the command named `name` (its variant name,
    /// for example `"Start"`).
    pub fn on(&mut self, name: &str) -> StepBuilder<'_> {
        StepBuilder {
            fake: self,
            name: name.to_owned(),
            step: Step::new(Reply::Ok(String::new())),
        }
    }

    pub fn push_step(&mut self, name: &str, step: Step) {
        self.steps
            .entry(name.to_owned())
            .or_default()
            .push_back(step);
    }

    /// The commands received so far, in order.
    pub fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }

    /// A handle on the list of commands that outlives the engine (a waiter
    /// takes the engine by value).
    pub fn sent_log(&self) -> Arc<Mutex<Vec<Sent>>> {
        self.sent.clone()
    }

    /// Names of the commands received, in order.
    pub fn sent_names(&self) -> Vec<String> {
        self.sent().into_iter().map(|s| s.name).collect()
    }

    /// The engine process dies now: later calls fail with `message`.
    pub fn die(&mut self, message: &str) {
        self.dead = Some(message.to_owned());
    }

    pub fn is_dead(&self) -> bool {
        self.dead.is_some()
    }

    pub fn shutdowns(&self) -> usize {
        self.shutdowns
    }

    /// Steps of `name` that have not run yet.
    pub fn steps_left(&self, name: &str) -> usize {
        self.steps.get(name).map_or(0, VecDeque::len)
    }

    fn schedule(&mut self, delay_ms: u64, item: Item) {
        self.order += 1;
        self.due
            .push((self.clock.now_ms() + delay_ms, self.order, item));
    }

    fn take_step(&mut self, name: &str) -> Option<Step> {
        let queue = self.steps.get_mut(name)?;
        let front = queue.front()?;
        if front.forever {
            return Some(front.clone());
        }
        queue.pop_front()
    }

    fn emit(&mut self, item: Item) -> Option<Notification> {
        match item {
            Item::Result { id, reply } => match reply {
                Reply::Ok(message) => Some(Notification::CommandResult {
                    id,
                    success: true,
                    message,
                }),
                Reply::Fail(message) => Some(Notification::CommandResult {
                    id,
                    success: false,
                    message,
                }),
                Reply::Silent | Reply::SendError(_) | Reply::Die => None,
            },
            Item::Change(change) => match *change {
                Change::Notify(notification) => {
                    if let Notification::Snapshot(snapshot) = &*notification {
                        self.snapshot = snapshot.clone();
                    }
                    Some(*notification)
                }
                Change::Snapshot(edit) => {
                    edit(&mut self.snapshot);
                    Some(Notification::Snapshot(self.snapshot.clone()))
                }
            },
        }
    }
}

/// `fake.on("Start").after(..).then(..).ok("running")`: the last call adds the
/// step.
pub struct StepBuilder<'a> {
    fake: &'a mut FakeEngine,
    name: String,
    step: Step,
}

impl<'a> StepBuilder<'a> {
    /// The reply comes this long after the command.
    pub fn after(mut self, delay: Duration) -> Self {
        self.step.after = delay;
        self
    }

    /// The snapshot changes `delay` after the command.
    pub fn then(
        mut self,
        delay: Duration,
        edit: impl Fn(&mut Snapshot) + Send + Sync + 'static,
    ) -> Self {
        self.step.changes.push((delay, Change::snapshot(edit)));
        self
    }

    /// Another notification arrives `delay` after the command.
    pub fn notify(mut self, delay: Duration, notification: Notification) -> Self {
        self.step
            .changes
            .push((delay, Change::Notify(Box::new(notification))));
        self
    }

    /// Use this step for every later command of the name too.
    pub fn forever(mut self) -> Self {
        self.step.forever = true;
        self
    }

    pub fn ok(self, message: &str) -> &'a mut FakeEngine {
        self.finish(Reply::Ok(message.to_owned()))
    }

    pub fn fail(self, message: &str) -> &'a mut FakeEngine {
        self.finish(Reply::Fail(message.to_owned()))
    }

    pub fn silent(self) -> &'a mut FakeEngine {
        self.finish(Reply::Silent)
    }

    pub fn send_error(self, message: &str) -> &'a mut FakeEngine {
        self.finish(Reply::SendError(message.to_owned()))
    }

    /// The engine dies on this command.
    pub fn die(self) -> &'a mut FakeEngine {
        self.finish(Reply::Die)
    }

    fn finish(mut self, reply: Reply) -> &'a mut FakeEngine {
        self.step.reply = reply;
        self.fake.push_step(&self.name, self.step);
        self.fake
    }
}

fn ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl Engine for FakeEngine {
    fn send(&mut self, command: Command) -> Result<u64, String> {
        if let Some(message) = &self.dead {
            return Err(message.clone());
        }
        let name = crate::waiter::command_name(&command);
        self.next_id += 1;
        let id = self.next_id;
        self.sent.lock().unwrap().push(Sent {
            id,
            name: name.clone(),
            detail: format!("{command:?}"),
            at_ms: self.clock.now_ms(),
        });
        let step = self.take_step(&name).unwrap_or_else(|| {
            Step::new(match self.unscripted {
                Unscripted::Ok => Reply::Ok(String::new()),
                Unscripted::Fail => Reply::Fail(format!("FakeEngine: no step scripted for {name}")),
            })
        });
        match &step.reply {
            Reply::SendError(message) => return Err(message.clone()),
            Reply::Die => {
                self.dead = Some("the engine process died".into());
                return Ok(id);
            }
            _ => {}
        }
        for (delay, change) in step.changes {
            self.schedule(ms(delay), Item::Change(Box::new(change)));
        }
        self.schedule(
            ms(step.after),
            Item::Result {
                id,
                reply: step.reply,
            },
        );
        Ok(id)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Notification>, String> {
        if let Some(message) = &self.dead {
            return Err(message.clone());
        }
        let now = self.clock.now_ms();
        let limit = now + ms(timeout);
        loop {
            self.due.sort_by_key(|(at, order, _)| (*at, *order));
            match self.due.first() {
                Some((at, _, _)) if *at <= limit => {
                    let (at, _, item) = self.due.remove(0);
                    self.clock.set(at.max(self.clock.now_ms()));
                    // A silent reply is consumed without a notification.
                    if let Some(notification) = self.emit(item) {
                        return Ok(Some(notification));
                    }
                }
                _ => {
                    self.clock.set(limit.max(self.clock.now_ms()));
                    return Ok(None);
                }
            }
        }
    }

    fn shutdown(&mut self) -> Result<(), String> {
        self.shutdowns += 1;
        self.dead = Some("the engine was shut down".into());
        Ok(())
    }
}
