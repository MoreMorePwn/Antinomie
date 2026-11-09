// SPDX-License-Identifier: GPL-3.0-only
//! The suspicious-activity rules, run on a live recording one call at a time,
//! for the dump trigger of a run (`antinomie_monitor_core::dump_trigger`).
//!
//! This is the engine the saved-recording index uses, fed the way
//! `findings::suspicious_output` feeds it, so there is one set of rules. It
//! sees only what a single call, or one task across calls, can show; rules
//! that read the whole run or the network capture do not fire here.
use super::rules::{Engine, Options, Tier};
use super::*;
use antinomie_monitor_core::dump_trigger::{LiveFinding, LiveJudge, TriggerTier};

pub struct Judge {
    pub engine: Engine,
    pub files: FdState,
    pub sets: std::collections::BTreeMap<u32, std::collections::BTreeSet<u64>>,
}

impl LiveJudge for Judge {
    fn judge(&mut self, call: &InvocationSummary) -> Vec<LiveFinding> {
        observe_processes(&mut self.files.process_images, std::slice::from_ref(call));
        let Some(event) = trace::representative(call) else {
            return Vec::new();
        };
        note_cookie_sets(&mut self.sets, std::slice::from_ref(call));
        self.engine.observe(call, &self.files, None, false);
        remember_cwd(&mut self.files, call, event);
        remember_open(&mut self.files, call, event);
        apply_dup(&mut self.files, call, event);
        forget_closed(&mut self.files, call, event);
        let cookies = resolve_cookies(&self.sets);
        inherit_open_fds(&mut self.files, call, event, &cookies);
        sigma_events::track(&mut self.files, call, event);
        self.engine
            .live_changes()
            .into_iter()
            .filter_map(|row| {
                let tier = match row.tier {
                    Tier::High => TriggerTier::High,
                    Tier::Medium => TriggerTier::Medium,
                    Tier::Low => TriggerTier::Low,
                    Tier::Info => return None,
                };
                Some(LiveFinding {
                    rule: row.rule.to_owned(),
                    summary: row.summary,
                    tier,
                    pid: row.pid,
                    tid: row.tid,
                    task_cookie: row.cookie,
                    stream_id: row.stream,
                    call_id: row.call_id,
                    guest_ns: row.ns,
                    syscall: row.syscall,
                })
            })
            .collect()
    }
}

pub fn make() -> Box<dyn LiveJudge> {
    Box::new(Judge {
        engine: Engine::new(Options::default()),
        files: FdState::default(),
        sets: Default::default(),
    })
}

/// Hand the rule engine to the recorder.
pub fn register() {
    antinomie_monitor_core::dump_trigger::set_judge(make);
}

#[cfg(test)]
mod tests {
    //! The rule engine fed through the recorder's live watch, with the
    //! recorder's list of calls, on every architecture (ANT-T0426: an arm64
    //! run's calls never reached the judge).
    use super::*;
    use antinomie_monitor_core::dump_trigger::{replay, DumpTrigger};
    use antinomie_monitor_core::syscalls::{self as calls, Abi};
    use antinomie_monitor_core::EventSummary;

    const AT_FDCWD: u64 = -100i64 as u64;
    /// O_WRONLY | O_CREAT | O_TRUNC, the same on x86-64, aarch64 and arm.
    const CREATE: u64 = 0o1101;

    fn id(abi: Abi, name: &str) -> u64 {
        calls::id(abi, calls::table(abi).number(name).unwrap())
    }

    /// `sh` starts and writes a systemd unit, as the recorder delivers it.
    fn writes_a_unit(abi: Abi) -> Vec<EventSummary> {
        let exec = crate::tests::path_call(7, id(abi, "execve"), "execve", 0, "/bin/sh");
        let mut open = crate::tests::path_call(
            7,
            id(abi, "openat"),
            "openat",
            3,
            "/etc/systemd/system/antinomie-test.service",
        );
        open.entry.as_mut().unwrap().args = Some([AT_FDCWD, 0, CREATE, 0o644, 0, 0]);
        [exec, open]
            .into_iter()
            .enumerate()
            .flat_map(|(at, mut call)| {
                let call_id = at as u64 + 1;
                [call.entry.take(), call.exit.take()]
                    .into_iter()
                    .flatten()
                    .map(move |mut event| {
                        event.call_id = call_id;
                        event.timestamp_ns = call_id * 1_000_000 + u64::from(event.phase);
                        event
                    })
            })
            .collect()
    }

    fn fired(abi: Abi) -> Vec<LiveFinding> {
        replay(
            make(),
            &DumpTrigger::default(),
            &crate::rules::watched_calls(),
            writes_a_unit(abi),
        )
    }

    #[test]
    fn a_systemd_unit_written_on_x86_64_fires_the_high_trigger() {
        let found = fired(Abi::X86_64);
        assert!(
            found
                .iter()
                .any(|row| row.rule == "persistence.systemd" && row.tier == TriggerTier::High),
            "{found:?}"
        );
    }

    #[test]
    fn a_systemd_unit_written_on_aarch64_fires_the_high_trigger() {
        let found = fired(Abi::Aarch64);
        assert!(
            found
                .iter()
                .any(|row| row.rule == "persistence.systemd" && row.tier == TriggerTier::High),
            "{found:?}"
        );
    }

    #[test]
    fn a_systemd_unit_written_by_an_aarch32_program_fires_the_high_trigger() {
        let found = fired(Abi::Arm);
        assert!(
            found
                .iter()
                .any(|row| row.rule == "persistence.systemd" && row.tier == TriggerTier::High),
            "{found:?}"
        );
    }
}
