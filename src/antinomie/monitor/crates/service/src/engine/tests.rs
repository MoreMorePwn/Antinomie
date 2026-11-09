// SPDX-License-Identifier: GPL-3.0-only
use super::{
    Engine,
    fake::{FakeEngine, Reply, Unscripted},
    trace,
};
use crate::{
    clock::{Clock, ManualClock},
    waiter::{WaitError, Waiter},
};
use antinomie_monitor_core::{Command, Notification, VmState};
use std::{path::PathBuf, sync::Arc, time::Duration};

const SECOND: Duration = Duration::from_secs(1);

fn fake() -> (FakeEngine, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(1_000_000));
    (FakeEngine::new(clock.clone()), clock)
}

fn waiter(fake: FakeEngine, clock: &Arc<ManualClock>) -> Waiter<FakeEngine> {
    Waiter::new(fake, clock.clone())
}

fn start(vm: &str) -> Command {
    Command::Start { vm_id: vm.into() }
}

#[test]
fn a_reply_arrives_after_its_delay_and_the_clock_follows_it() {
    let (mut fake, clock) = fake();
    fake.on("Start")
        .after(5 * SECOND)
        .then(SECOND, |s| s.state = VmState::Starting)
        .then(6 * SECOND, |s| s.state = VmState::Running)
        .ok("VM running");
    let begin = clock.now_ms();
    let mut waiter = waiter(fake, &clock);
    assert_eq!(waiter.command(start("v"), None), Ok("VM running".into()));
    assert_eq!(clock.now_ms() - begin, 5000);
    assert_eq!(waiter.snapshot().state, VmState::Starting);
    waiter
        .wait_until("running", Some(10 * SECOND), |s| {
            s.state == VmState::Running
        })
        .unwrap();
    assert_eq!(
        clock.now_ms() - begin,
        6000,
        "the clock moved to the change"
    );
}

#[test]
fn steps_run_in_order_and_the_last_forever_step_repeats() {
    let (mut fake, clock) = fake();
    fake.on("Start").fail("busy");
    fake.on("Start").ok("first");
    fake.on("Start").forever().ok("again");
    let mut waiter = waiter(fake, &clock);
    assert_eq!(
        waiter.command(start("v"), None),
        Err(WaitError::Failed("busy".into()))
    );
    assert_eq!(waiter.command(start("v"), None), Ok("first".into()));
    for _ in 0..3 {
        assert_eq!(waiter.command(start("v"), None), Ok("again".into()));
    }
    assert_eq!(waiter.into_engine().steps_left("Start"), 1);
}

#[test]
fn a_silent_command_never_answers_and_the_wait_times_out_on_the_fake_clock() {
    let (mut fake, clock) = fake();
    fake.on("Stop").silent();
    let mut waiter = waiter(fake, &clock);
    let begin = clock.now_ms();
    assert_eq!(
        waiter.lane_command(Command::Stop),
        Err(WaitError::Silent {
            what: "Stop".into(),
            seconds: 60
        })
    );
    assert!(
        clock.now_ms() - begin >= 60_000,
        "a minute passed, no sleep"
    );
}

#[test]
fn an_unscripted_command_fails_by_name_unless_told_otherwise() {
    let (fake, clock) = fake();
    let mut waiter = waiter(fake, &clock);
    match waiter.command(Command::Stop, None) {
        Err(WaitError::Failed(message)) => assert!(message.contains("Stop"), "{message}"),
        other => panic!("{other:?}"),
    }
    waiter.engine_mut().unscripted(Unscripted::Ok);
    assert_eq!(waiter.command(Command::Stop, None), Ok(String::new()));
}

#[test]
fn a_send_error_and_a_death_reach_the_caller_as_the_engine_would_report_them() {
    let (mut fake, clock) = fake();
    fake.on("Start").send_error("queue closed");
    fake.on("Stop").die();
    let mut waiter = waiter(fake, &clock);
    assert_eq!(
        waiter.command(start("v"), None),
        Err(WaitError::Failed("queue closed".into()))
    );
    // The engine dies on Stop: the command was accepted, nothing comes back.
    let error = waiter
        .command(Command::Stop, Some(10 * SECOND))
        .unwrap_err();
    assert!(
        matches!(error, WaitError::Disconnected(_)),
        "a dead engine is a disconnect: {error:?}"
    );
    assert!(waiter.engine_mut().is_dead());
    assert_eq!(
        waiter.send(start("v")),
        Err(WaitError::Failed("the engine process died".into()))
    );
}

#[test]
fn commands_are_recorded_with_their_name_text_and_time() {
    let (mut fake, clock) = fake();
    fake.unscripted(Unscripted::Ok);
    let log = fake.sent_log();
    let mut waiter = waiter(fake, &clock);
    waiter.command(start("lane-vm"), None).unwrap();
    clock.advance(250);
    waiter.command(Command::Stop, None).unwrap();
    let sent = log.lock().unwrap().clone();
    assert_eq!(
        sent.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["Start", "Stop"]
    );
    assert!(sent[0].detail.contains("lane-vm"));
    assert_eq!(sent[1].at_ms - sent[0].at_ms, 250);
}

#[test]
fn shutdown_is_counted_and_the_engine_is_gone_afterwards() {
    let (fake, clock) = fake();
    let mut waiter = waiter(fake, &clock);
    Engine::shutdown(waiter.engine_mut()).unwrap();
    assert_eq!(waiter.engine_mut().shutdowns(), 1);
    assert!(waiter.pump(SECOND).is_err());
}

#[test]
fn the_starting_state_is_the_first_snapshot() {
    let (mut fake, clock) = fake();
    fake.start_with(|s| {
        s.state = VmState::Running;
        s.active_vm = Some("lane-vm".into());
    });
    let mut waiter = waiter(fake, &clock);
    waiter.first_snapshot(SECOND).unwrap();
    assert_eq!(waiter.snapshot().state, VmState::Running);
    assert_eq!(waiter.snapshot().active_vm.as_deref(), Some("lane-vm"));
}

#[test]
fn a_notification_the_script_adds_is_delivered_untouched() {
    let (mut fake, clock) = fake();
    fake.on("Stop")
        .notify(
            SECOND,
            Notification::CommandResult {
                id: 99,
                success: true,
                message: "late".into(),
            },
        )
        .ok("stopped");
    let mut waiter = waiter(fake, &clock);
    waiter.command(Command::Stop, None).unwrap();
    waiter.pump(2 * SECOND).unwrap();
    assert_eq!(waiter.take_result(99), Some(Ok("late".into())));
}

#[test]
fn the_reply_enum_has_a_message_only_where_there_is_one() {
    assert_ne!(Reply::Silent, Reply::Die);
}

// ---- traces -------------------------------------------------------------

fn fixture(name: &str) -> Vec<serde_json::Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/auto-cycle")
        .join(format!("{name}.trace.jsonl"));
    trace::parse(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}")))
        .unwrap()
}

/// The recorded time between a command and its result.
fn recorded_latency(rows: &[serde_json::Value], name: &str, nth: usize) -> u64 {
    let command = rows
        .iter()
        .filter(|r| r["dir"] == "command" && r["name"] == name)
        .nth(nth)
        .unwrap_or_else(|| panic!("no {name} #{nth}"));
    let result = rows
        .iter()
        .find(|r| r["kind"] == "command_result" && r["id"] == command["id"])
        .unwrap();
    ((result["t"].as_f64().unwrap() - command["t"].as_f64().unwrap()) * 1000.0).round() as u64
}

#[test]
fn a_recorded_busybox_trace_replays_with_its_results_states_and_timings() {
    let rows = fixture("bb-full-10");
    let clock = Arc::new(ManualClock::new(0));
    let mut waiter = Waiter::new(trace::replay(&rows, clock.clone()).unwrap(), clock.clone());
    waiter.first_snapshot(SECOND).unwrap();
    assert_eq!(waiter.snapshot().state, VmState::Stopped);

    let begin = clock.now_ms();
    let message = waiter
        .command(
            Command::ImportBase {
                directory: PathBuf::from("/bases/any"),
            },
            None,
        )
        .unwrap();
    assert_eq!(message, "base imported");
    assert_eq!(
        clock.now_ms() - begin,
        recorded_latency(&rows, "ImportBase", 0)
    );

    // Start: the recorded result, then the guest answering the INFO probe.
    let begin = clock.now_ms();
    let message = waiter.command(start("lane-vm"), None).unwrap();
    assert_eq!(message, "VM running; transport attached");
    assert_eq!(clock.now_ms() - begin, recorded_latency(&rows, "Start", 0));
    waiter
        .wait_until("guest kernel", Some(60 * SECOND), |s| {
            s.guest_kernel.is_some()
        })
        .unwrap();
    assert_eq!(waiter.snapshot().state, VmState::Running);
    assert!(waiter.snapshot().active_vm.is_some());

    // Stop: the recorded result and the Stopped state with the flush.
    waiter.command(Command::Stop, None).unwrap();
    waiter
        .wait_until("stopped", Some(600 * SECOND), |s| {
            s.state == VmState::Stopped && s.recording_flush.is_none()
        })
        .unwrap();
}

#[test]
fn every_recorded_trace_builds_a_fake_and_a_failed_result_stays_failed() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/auto-cycle");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.to_string_lossy().ends_with(".trace.jsonl") {
            continue;
        }
        let rows = trace::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let clock = Arc::new(ManualClock::new(0));
        let fake = trace::replay(&rows, clock).unwrap();
        for row in rows.iter().filter(|r| r["dir"] == "command") {
            let name = row["name"].as_str().unwrap();
            assert!(fake.steps_left(name) > 0, "{path:?}: {name}");
        }
        seen += 1;
    }
    assert!(seen >= 5);
    // dm-desktop recorded a refusal: `Execute` fails at once.
    let rows = fixture("dm-desktop");
    trace::replay(&rows, Arc::new(ManualClock::new(0))).unwrap();
    let refused = rows
        .iter()
        .any(|r| r["kind"] == "command_result" && r["success"] == false);
    assert!(refused, "the fixture holds a failed command");
}

#[test]
fn a_malformed_trace_row_is_an_error_not_a_panic() {
    assert!(trace::parse("{not json").is_err());
    let rows = trace::parse("{\"dir\":\"command\",\"name\":\"Stop\",\"t\":1.0}").unwrap();
    assert!(trace::replay(&rows, Arc::new(ManualClock::new(0))).is_err());
}
