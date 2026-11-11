// SPDX-License-Identifier: GPL-3.0-only
//! The multiplexed engine connection: results by id, snapshots to everyone,
//! terminal output to the lane.
use super::{Engine, FakeEngine, Mux};
use crate::{
    clock::ManualClock,
    waiter::{WaitError, Waiter},
};
use antinomie_monitor_core::{Command, Notification, VmState};
use std::{sync::Arc, time::Duration};

const SECOND: Duration = Duration::from_secs(1);

fn fake() -> (FakeEngine, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(1_000_000));
    (FakeEngine::new(clock.clone()), clock)
}

#[test]
fn each_waiter_gets_its_own_results_and_every_snapshot() {
    let (mut fake, clock) = fake();
    fake.on("Stop")
        .after(2 * SECOND)
        .then(SECOND, |s| s.state = VmState::Stopped)
        .ok("stopped");
    fake.on("AnalyzeSample").after(SECOND).ok("report-1");
    let mux = Mux::new(fake);
    let mut lane = Waiter::new(mux.handle(), clock.clone());
    let mut host = Waiter::new(mux.handle(), clock.clone());
    let lane_id = lane.send(Command::Stop).unwrap();
    let host_id = host
        .send(Command::AnalyzeSample {
            sha256: "ab".repeat(32),
            selection: Default::default(),
        })
        .unwrap();
    // The host's result comes first; the lane's waiter must not take it.
    for _ in 0..400 {
        let _ = lane.pump(Duration::from_millis(50));
        let _ = host.pump(Duration::from_millis(50));
    }
    assert_eq!(lane.take_result(host_id), None);
    assert_eq!(host.take_result(lane_id), None);
    assert_eq!(lane.take_result(lane_id), Some(Ok("stopped".into())));
    assert_eq!(host.take_result(host_id), Some(Ok("report-1".into())));
    assert_eq!(lane.snapshot().state, VmState::Stopped);
    assert_eq!(host.snapshot().state, VmState::Stopped);
}

#[test]
fn a_command_waits_on_its_own_handle_while_the_other_sends() {
    let (mut fake, clock) = fake();
    fake.on("AnalyzeSample").after(3 * SECOND).ok("report-2");
    fake.on("Stop").after(SECOND).ok("stopped");
    let mux = Mux::new(fake);
    let mut lane = Waiter::new(mux.handle(), clock.clone());
    let mut host = Waiter::new(mux.handle(), clock.clone());
    let id = host
        .send(Command::AnalyzeSample {
            sha256: "cd".repeat(32),
            selection: Default::default(),
        })
        .unwrap();
    assert_eq!(
        lane.command(Command::Stop, Some(10 * SECOND)),
        Ok("stopped".into())
    );
    let mut answer = None;
    for _ in 0..200 {
        let _ = host.pump(Duration::from_millis(50));
        if let Some(result) = host.take_result(id) {
            answer = Some(result);
            break;
        }
    }
    assert_eq!(answer, Some(Ok("report-2".into())));
}

#[test]
fn terminal_output_goes_to_the_lane_and_a_dead_engine_reaches_everyone() {
    let (fake, clock) = fake();
    let mux = Mux::new(fake);
    let mut lane = mux.handle();
    let mut host = mux.handle();
    {
        // A terminal notification with no command behind it.
        let mut state = mux.state.lock().unwrap();
        state.route(Notification::Terminal {
            run_id: "r".into(),
            sequence: 1,
            data: b"hi".to_vec(),
            eof: false,
        });
    }
    assert!(host.recv(Duration::ZERO).unwrap().is_none());
    assert!(matches!(
        lane.recv(Duration::ZERO).unwrap(),
        Some(Notification::Terminal { .. })
    ));
    mux.state.lock().unwrap().engine.die("engine stopped");
    let mut waiter = Waiter::new(host, clock);
    assert!(matches!(
        waiter.pump(Duration::from_millis(10)),
        Err(WaitError::Disconnected(_))
    ));
    assert!(lane.recv(Duration::ZERO).is_err());
}

#[test]
fn the_engine_comes_back_only_when_every_handle_is_closed() {
    let (fake, _clock) = fake();
    let mux = Mux::new(fake);
    let lane = mux.handle();
    let host = mux.handle();
    drop(mux);
    assert!(lane.into_engine().is_err(), "the host handle is still open");
    assert!(host.into_engine().is_ok(), "the last handle hands it back");
}
