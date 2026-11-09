// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::clock::ManualClock;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

type Reactor = Box<dyn FnMut(&Command, u64, &mut VecDeque<Notification>)>;

/// An engine that plays notifications back. A receive with nothing queued
/// moves the clock by the timeout, as a real wait would, or to the next
/// notification scheduled for a later time.
pub(super) struct Fake {
    pub clock: Arc<ManualClock>,
    pub queue: VecDeque<Notification>,
    pub sent: Arc<Mutex<Vec<String>>>,
    next_id: u64,
    /// Notifications released by the n-th command sent.
    pub on_send: Vec<VecDeque<Notification>>,
    /// Called for every command sent, with its id; what it pushes is queued.
    pub react: Option<Reactor>,
    /// Notifications that arrive when the clock reaches the time (ms).
    pub timed: Vec<(u64, Notification)>,
}

impl Fake {
    pub fn new(clock: Arc<ManualClock>) -> Self {
        Self {
            clock,
            queue: VecDeque::new(),
            sent: Arc::default(),
            next_id: 0,
            on_send: Vec::new(),
            react: None,
            timed: Vec::new(),
        }
    }
}

impl Engine for Fake {
    fn send(&mut self, command: Command) -> Result<u64, String> {
        self.next_id += 1;
        self.sent.lock().unwrap().push(command_name(&command));
        if !self.on_send.is_empty() {
            let released = self.on_send.remove(0);
            self.queue.extend(released);
        }
        if let Some(react) = self.react.as_mut() {
            react(&command, self.next_id, &mut self.queue);
        }
        Ok(self.next_id)
    }
    fn recv(&mut self, timeout: Duration) -> Result<Option<Notification>, String> {
        if let Some(notification) = self.queue.pop_front() {
            return Ok(Some(notification));
        }
        let now = self.clock.now_ms();
        let limit = now + timeout.as_millis() as u64;
        self.timed.sort_by_key(|(at, _)| *at);
        if let Some((at, _)) = self.timed.first()
            && *at <= limit
        {
            let (at, notification) = self.timed.remove(0);
            self.clock.set(at.max(now));
            return Ok(Some(notification));
        }
        self.clock.advance(timeout.as_millis() as u64);
        Ok(None)
    }
}

pub(super) fn result(id: u64, success: bool, message: &str) -> Notification {
    Notification::CommandResult {
        id,
        success,
        message: message.into(),
    }
}

pub(super) fn make(fake: Fake) -> (Waiter<Fake>, Arc<ManualClock>) {
    let clock = fake.clock.clone();
    (Waiter::new(fake, clock.clone()), clock)
}

#[test]
fn a_command_returns_its_own_result_and_keeps_another_for_later() {
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = Fake::new(clock);
    fake.on_send = vec![VecDeque::from([
        result(2, true, "second"),
        result(1, true, "first"),
    ])];
    let (mut waiter, _) = make(fake);
    assert_eq!(waiter.command(Command::Stop, None), Ok("first".to_owned()));
    assert_eq!(waiter.take_result(2), Some(Ok("second".to_owned())));
    assert_eq!(waiter.take_result(2), None);
}

#[test]
fn a_refused_command_carries_the_engines_words() {
    let mut fake = Fake::new(Arc::new(ManualClock::new(0)));
    fake.on_send = vec![VecDeque::from([result(1, false, "unknown VM")])];
    let (mut waiter, _) = make(fake);
    assert_eq!(
        waiter.command(Command::Stop, None),
        Err(WaitError::Failed("unknown VM".into()))
    );
}

#[test]
fn the_limit_ends_a_wait_on_the_clock_without_sleeping() {
    let (mut waiter, clock) = make(Fake::new(Arc::new(ManualClock::new(0))));
    let error = waiter
        .command(Command::Stop, Some(Duration::from_secs(5)))
        .unwrap_err();
    assert_eq!(
        error,
        WaitError::TimedOut {
            what: "Stop".into()
        }
    );
    assert!((5_000..6_000).contains(&clock.now_ms()));
}

#[test]
fn a_guest_command_without_a_result_is_silence_after_sixty_seconds() {
    let (mut waiter, clock) = make(Fake::new(Arc::new(ManualClock::new(0))));
    let error = waiter.lane_command(Command::Stop).unwrap_err();
    assert_eq!(
        error,
        WaitError::Silent {
            what: "Stop".into(),
            seconds: 60
        }
    );
    assert!((60_000..61_000).contains(&clock.now_ms()));
    assert!(error.to_string().contains("60 seconds"));
}

fn on_tcg(factor: f64) -> Snapshot {
    Snapshot {
        accelerator: Some(antinomie_monitor_core::AcceleratorUsed {
            record: "tcg".into(),
            fallback_warning: None,
            guest_wait_factor: factor,
        }),
        ..Snapshot::default()
    }
}

#[test]
fn the_silence_is_stretched_by_the_engines_own_factor_under_tcg() {
    let mut fake = Fake::new(Arc::new(ManualClock::new(0)));
    fake.queue.push_back(Notification::Snapshot(on_tcg(12.5)));
    let (mut waiter, clock) = make(fake);
    waiter.drain().unwrap();
    assert_eq!(waiter.guest_wait_factor(), 12.5);
    assert_eq!(waiter.lane_silence(), Duration::from_secs(750));
    let error = waiter.lane_command(Command::Stop).unwrap_err();
    assert!((750_000..751_000).contains(&clock.now_ms()));
    assert!(error.to_string().contains("750 seconds"), "{error}");
    // KVM (factor 1) and no VM keep the minute; a factor below 1 never shortens it.
    for snapshot in [on_tcg(1.0), Snapshot::default(), on_tcg(0.0)] {
        let mut fake = Fake::new(Arc::new(ManualClock::new(0)));
        fake.queue.push_back(Notification::Snapshot(snapshot));
        let (mut waiter, _) = make(fake);
        waiter.drain().unwrap();
        assert_eq!(waiter.lane_silence(), LANE_SILENCE);
    }
}

#[test]
fn the_engines_boot_wait_is_work_not_silence() {
    use antinomie_monitor_core::boot_wait::{LaunchWait, WAIT_TEXT};
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = Fake::new(clock.clone());
    let booting = Snapshot {
        launch_wait: Some(LaunchWait {
            program: "/tmp/job.sh".into(),
            started_ms: 0,
            text: WAIT_TEXT.into(),
        }),
        ..Snapshot::default()
    };
    // The engine waits 100 s for the guest to boot, then needs 50 s more.
    fake.on_send = vec![VecDeque::from([Notification::Snapshot(booting)])];
    fake.timed = vec![
        (100_000, Notification::Snapshot(Snapshot::default())),
        (150_000, result(1, true, "launched pid 9")),
    ];
    let (mut waiter, _) = make(fake);
    assert_eq!(
        waiter.lane_command(Command::Stop),
        Ok("launched pid 9".to_owned())
    );
    assert_eq!(clock.now_ms(), 150_000);
    // Silence after the boot wait still counts: 60 s from its end.
    let mut fake = Fake::new(Arc::new(ManualClock::new(0)));
    fake.on_send = vec![VecDeque::from([Notification::Snapshot(Snapshot {
        launch_wait: Some(LaunchWait {
            program: "/tmp/job.sh".into(),
            started_ms: 0,
            text: WAIT_TEXT.into(),
        }),
        ..Snapshot::default()
    })])];
    fake.timed = vec![(100_000, Notification::Snapshot(Snapshot::default()))];
    let (mut waiter, clock) = make(fake);
    assert!(matches!(
        waiter.lane_command(Command::Stop),
        Err(WaitError::Silent { seconds: 60, .. })
    ));
    // (The last look that saw the wait was one pump before its end.)
    assert!(
        (159_000..161_000).contains(&clock.now_ms()),
        "{}",
        clock.now_ms()
    );
}

#[test]
fn wait_until_follows_the_latest_snapshot() {
    use antinomie_monitor_core::VmState;
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = Fake::new(clock);
    let running = Snapshot {
        state: VmState::Running,
        ..Snapshot::default()
    };
    fake.queue
        .push_back(Notification::Snapshot(Snapshot::default()));
    fake.queue.push_back(Notification::Snapshot(running));
    let (mut waiter, _) = make(fake);
    let seen = Arc::new(Mutex::new(0));
    let counter = seen.clone();
    waiter.observe(move |_| *counter.lock().unwrap() += 1);
    waiter
        .wait_until("the VM to run", Some(Duration::from_secs(10)), |snapshot| {
            snapshot.state == VmState::Running
        })
        .unwrap();
    assert_eq!(*seen.lock().unwrap(), 2);
    let error = waiter
        .wait_until("a stopped VM", Some(Duration::from_secs(1)), |snapshot| {
            snapshot.state == VmState::Stopped
        })
        .unwrap_err();
    assert_eq!(
        error,
        WaitError::TimedOut {
            what: "a stopped VM".into()
        }
    );
}

#[test]
fn a_signal_ends_a_wait() {
    let (mut waiter, _) = make(Fake::new(Arc::new(ManualClock::new(0))));
    let flag = Arc::new(AtomicBool::new(false));
    let seen = flag.clone();
    waiter.interrupt_when(move || seen.load(Ordering::SeqCst));
    flag.store(true, Ordering::SeqCst);
    assert_eq!(
        waiter.command(Command::Stop, None),
        Err(WaitError::Interrupted)
    );
}

#[test]
fn terminal_output_is_kept_as_a_bounded_tail() {
    let mut fake = Fake::new(Arc::new(ManualClock::new(0)));
    let piece = |data: Vec<u8>, eof| Notification::Terminal {
        run_id: "r1".into(),
        sequence: 0,
        data,
        eof,
    };
    fake.queue
        .push_back(piece(vec![b'a'; TERMINAL_TAIL], false));
    fake.queue.push_back(piece(b"tail".to_vec(), true));
    let (mut waiter, _) = make(fake);
    waiter.drain().unwrap();
    let tail = waiter.terminal("r1").unwrap();
    assert_eq!(tail.bytes.len(), TERMINAL_TAIL);
    assert!(tail.bytes.ends_with(b"tail"));
    assert_eq!(tail.dropped, 4);
    assert!(tail.eof);
    assert!(waiter.terminal("other").is_none());
}

#[test]
fn a_command_name_never_includes_its_fields() {
    let command = Command::CreateWithCredentials {
        vm: Default::default(),
        credentials: antinomie_monitor_core::GuestCredentials::new(
            "analyst".into(),
            "a-private-password".into(),
        )
        .unwrap(),
    };
    assert_eq!(command_name(&command), "CreateWithCredentials");
}

#[test]
fn a_stop_waits_for_the_flush_and_the_disk_layer() {
    use antinomie_monitor_core::{
        VmState,
        disk_layers::{DiskLayer, LayerPhase},
    };
    let layer = DiskLayer {
        vm_id: "vm1".into(),
        boot_id: "b".into(),
        phase: LayerPhase::Saving,
        started_ms: 0,
        phase_ms: 0,
    };
    let stopped_with_layer = Snapshot {
        state: VmState::Stopped,
        disk_layers: vec![layer.clone()],
        ..Snapshot::default()
    };
    let settled = Snapshot {
        state: VmState::Stopped,
        ..Snapshot::default()
    };
    assert!(!settled_after_stop(&stopped_with_layer, "vm1"));
    assert!(settled_after_stop(&stopped_with_layer, "other"));
    assert!(settled_after_stop(&settled, "vm1"));
    let mut fake = Fake::new(Arc::new(ManualClock::new(0)));
    fake.on_send = vec![VecDeque::from([
        Notification::Snapshot(stopped_with_layer),
        result(1, true, "VM stopped"),
        Notification::Snapshot(settled),
    ])];
    let (mut waiter, _) = make(fake);
    assert_eq!(waiter.stop_vm("vm1", None), Ok("VM stopped".to_owned()));
    assert!(waiter.snapshot().disk_layers.is_empty());
}

#[test]
fn a_stop_whose_layer_never_settles_times_out_on_the_clock() {
    use antinomie_monitor_core::{
        VmState,
        disk_layers::{DiskLayer, LayerPhase},
    };
    let stuck = Snapshot {
        state: VmState::Stopped,
        disk_layers: vec![DiskLayer {
            vm_id: "vm1".into(),
            boot_id: "b".into(),
            phase: LayerPhase::Finalizing,
            started_ms: 0,
            phase_ms: 0,
        }],
        ..Snapshot::default()
    };
    let mut fake = Fake::new(Arc::new(ManualClock::new(0)));
    fake.on_send = vec![VecDeque::from([
        result(1, true, "VM stopped"),
        Notification::Snapshot(stuck),
    ])];
    let (mut waiter, _) = make(fake);
    let error = waiter
        .stop_vm("vm1", Some(Duration::from_secs(30)))
        .unwrap_err();
    assert!(matches!(error, WaitError::TimedOut { .. }));
}

#[test]
fn the_deadline_of_the_command_ends_every_wait_the_same_way() {
    let (mut waiter, clock) = make(Fake::new(Arc::new(ManualClock::new(0))));
    waiter.deadline_in(Duration::from_secs(30));
    let error = waiter.command(Command::Stop, None).unwrap_err();
    assert_eq!(error, WaitError::DeadlineExceeded);
    assert!((30_000..31_000).contains(&clock.now_ms()));
    let again = waiter.wait_until("anything", None, |_| false).unwrap_err();
    assert_eq!(again, WaitError::DeadlineExceeded);
}
