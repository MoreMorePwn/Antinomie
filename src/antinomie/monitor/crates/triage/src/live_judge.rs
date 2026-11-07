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
