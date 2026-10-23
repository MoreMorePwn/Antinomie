// SPDX-License-Identifier: GPL-3.0-only
//! Runs the rules over a run's calls and settles their hits into rows.
use super::super::*;
use super::ctx::Ctx;
use super::frames::{self, FrameKind};
use super::noise::{self, flag, Agg, Gaps, SAMPLES};
use super::state::State;
use super::{collect_hits, probes, rows, spec, Hit, Tier};
use std::collections::HashMap;

/// What the scan asks of the engine.
#[derive(Clone, Copy, Default)]
pub(in crate::triage) struct Options {
    /// Build INFO rows; their counts are kept either way.
    pub show_info: bool,
    /// A capture of the whole VM: only processes started during it are in scope.
    pub capture_all: bool,
}

/// The rows of a scan and what to count about them.
pub(in crate::triage) struct Output {
    /// Every row to list, hidden ones included; the view and the filter narrow them.
    pub rows: Vec<Finding>,
    /// Rows by tier (HIGH, MEDIUM, LOW) that are not hidden; INFO is the number of matches.
    pub tiers: [u64; 4],
    /// Rows hidden as housekeeping or outside the run.
    pub hidden: u64,
    /// Rows the caps did not keep.
    pub capped: u64,
    /// Frames of VM housekeeping the suppression list skipped.
    pub suppressed: u64,
    /// Rules that could not be evaluated, and why.
    pub notes: Vec<String>,
    /// The badge: rows of LOW and above that are not hidden, and the capped ones.
    pub badge: u64,
    /// Rows counted for each task's chip in the process tree.
    pub tasks: Suspicious,
}

/// Where the host uploads the resource collector of a base from before 0.7.0; the
/// rest of the name is random for each launch.
const COLLECTOR: &str = "/tmp/.antinomie-resource-";

/// Rows held before the caps are applied; past it matches are only counted.
const ROWS_HELD: usize = 200_000;

pub(in crate::triage) struct Engine {
    options: Options,
    aggs: Vec<Agg>,
    index: HashMap<(&'static str, u64, String), usize>,
    state: State,
    /// INFO matches that were counted without building a row.
    info_matches: u64,
    /// Matches past the bound on rows held; they are counted, not kept.
    dropped: u64,
    notes: Vec<String>,
}

impl Engine {
    pub(in crate::triage) fn new(options: Options) -> Self {
        Self {
            options,
            aggs: Vec::new(),
            index: HashMap::new(),
            state: State::default(),
            info_matches: 0,
            dropped: 0,
            notes: Vec::new(),
        }
    }

    /// Judge one call. `files` holds the state before the call; `via_async` marks
    /// a file request standing for an io_uring or AIO submission.
    pub(in crate::triage) fn observe(
        &mut self,
        call: &InvocationSummary,
        files: &FdState,
        directory: Option<&Path>,
        via_async: bool,
    ) {
        let Some(event) = trace::representative(call) else {
            return;
        };
        let cx = Ctx::new(call, event, files, directory, via_async);
        // Antinomie's own resource collector (bases from before 0.7.0) is not the sample's.
        let ours = |path: &str| path.starts_with(COLLECTOR);
        if cx.image.is_some_and(ours) || cx.exec_path().is_some_and(|path| ours(&path)) {
            self.state.app_tasks.insert(call.task_cookie);
        }
        if self.state.app_tasks.contains(&call.task_cookie) {
            self.state.track(&cx);
            return;
        }
        let mut hits = collect_hits(&cx, &mut self.state);
        // One call is one occurrence of a rule on an object, however many ways it touched it.
        let mut seen = std::collections::BTreeSet::new();
        hits.retain(|hit| seen.insert((hit.rule, hit.object.clone())));
        for hit in hits {
            self.record(&cx, hit);
        }
        self.state.track(&cx);
    }

    fn record(&mut self, cx: &Ctx, hit: Hit) {
        let Some(spec) = spec(hit.rule) else {
            debug_assert!(false, "unclassified rule {}", hit.rule);
            return;
        };
        let task = cx.call.task_cookie;
        // At an exec the trace already names the new program, not the one that asked for it.
        let allowed = !cx.is_exec() && spec.allow.contains(&cx.image_name());
        let failed = cx.failed;
        let time = cx.time();
        let key = (spec.id, task, hit.object.clone());
        if let Some(&at) = self.index.get(&key) {
            let agg = &mut self.aggs[at];
            agg.count += 1;
            agg.failed += u64::from(failed);
            agg.allowed += u64::from(allowed);
            agg.first_ns = agg.first_ns.min(time);
            agg.last_ns = agg.last_ns.max(time);
            agg.gaps.add(time);
            if agg.samples.len() < SAMPLES {
                agg.samples.push((cx.call.stream_id, cx.call.call_id));
            }
            for line in hit.detail {
                if agg.detail.len() < 32 && !agg.detail.contains(&line) {
                    agg.detail.push(line);
                }
            }
            return;
        }
        if self.aggs.len() >= ROWS_HELD {
            self.dropped += 1;
            return;
        }
        let mut gaps = Gaps::default();
        gaps.add(time);
        let image = cx.image.map(str::to_owned);
        let agg = Agg {
            rule: spec.id,
            cookie: task,
            pid: cx.event.pid,
            tid: cx.event.tid,
            process: process_identity(cx.event.pid, cx.event.tid, cx.image),
            image,
            object: hit.object,
            summary: hit.summary,
            attack: hit.attack.unwrap_or(spec.attack),
            base: hit.tier.unwrap_or(spec.tier),
            count: 1,
            failed: u64::from(failed),
            allowed: u64::from(allowed),
            first_ns: time,
            last_ns: time,
            stream: cx.call.stream_id,
            call_id: cx.call.call_id,
            ret: cx.ret,
            high_confidence: cx.call.entry.as_ref().is_some_and(|entry| entry.complete)
                && cx.call.exit.as_ref().is_some_and(|exit| exit.complete),
            outcome: outcome(cx.call),
            evidence: format!("syscall {} call {}", cx.name, cx.call.call_id),
            gaps,
            flags: if cx.via_async { flag::ASYNC } else { 0 },
            detail: hit.detail,
            siblings: 0,
            samples: Vec::new(),
            packet: None,
            tier: spec.tier,
            why: Vec::new(),
        };
        self.index.insert(key, self.aggs.len());
        self.aggs.push(agg);
    }

    /// Judge one row of the capture. `clock` places the packet time on the guest's clock.
    pub(in crate::triage) fn frame(
        &mut self,
        kind: FrameKind,
        values: &[(&'static str, RowValue)],
        destination: &str,
        port: &str,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        let frame = frames::Frame {
            kind,
            values,
            destination,
            port,
        };
        let hits = frames::rules(&mut self.state, &frame);
        if hits.is_empty() {
            return;
        }
        let contact = frames::contact(&self.state, &frame).cloned();
        let number = frame.number("frame.number").unwrap_or(0);
        let capture = frame.text("capture.path").to_owned();
        let guest_ns = clock
            .zip(frame.number("frame.time_us"))
            .and_then(|(clock, us)| {
                let delta = (i128::from(us) - i128::from(clock.host_us)) * 1000;
                u64::try_from(i128::from(clock.guest_ns) + delta).ok()
            });
        for hit in hits {
            self.record_frame(
                hit,
                number,
                &capture,
                guest_ns.unwrap_or(0),
                contact.as_ref(),
            );
        }
    }

    fn record_frame(
        &mut self,
        hit: Hit,
        number: u64,
        capture: &str,
        time: u64,
        contact: Option<&super::state::Contact>,
    ) {
        let Some(spec) = spec(hit.rule) else {
            debug_assert!(false, "unclassified rule {}", hit.rule);
            return;
        };
        let (cookie, pid, tid, image) = contact.map_or((0, 0, 0, None), |contact| {
            (
                contact.cookie,
                contact.pid,
                contact.tid,
                contact.image.clone(),
            )
        });
        let key = (spec.id, cookie, hit.object.clone());
        if let Some(&at) = self.index.get(&key) {
            let agg = &mut self.aggs[at];
            agg.count += 1;
            agg.last_ns = agg.last_ns.max(time);
            agg.gaps.add(time);
            return;
        }
        if self.aggs.len() >= ROWS_HELD {
            self.dropped += 1;
            return;
        }
        let mut gaps = Gaps::default();
        gaps.add(time);
        let process = match &image {
            Some(_) => format!(
                "{} · from this task's call to the same address",
                process_identity(pid, tid, image.as_deref())
            ),
            None => "VM-wide (capture)".to_owned(),
        };
        let agg = Agg {
            rule: spec.id,
            cookie,
            pid,
            tid,
            process,
            flags: if contact.is_some() {
                flag::INFERRED
            } else {
                flag::VM_WIDE
            },
            image,
            object: hit.object,
            summary: hit.summary,
            attack: hit.attack.unwrap_or(spec.attack),
            base: hit.tier.unwrap_or(spec.tier),
            count: 1,
            failed: 0,
            allowed: 0,
            first_ns: time,
            last_ns: time,
            stream: 0,
            call_id: number,
            ret: None,
            high_confidence: contact.is_some(),
            outcome: "observed in the capture".into(),
            evidence: format!("packet #{number}"),
            gaps,
            detail: hit.detail,
            siblings: 0,
            samples: Vec::new(),
            packet: Some((capture.to_owned(), number)),
            tier: spec.tier,
            why: Vec::new(),
        };
        self.index.insert(key, self.aggs.len());
        self.aggs.push(agg);
    }

    /// Settle every row: scope, siblings, tiers, caps.
    pub(in crate::triage) fn finish(mut self, files: &FdState) -> Output {
        let traced = self.state.probes.traced_exec.clone();
        if let Some((hit, number, capture, time)) = self.state.frames.nxdomain_hit.take() {
            if self.state.frames.resolver_answers {
                let resolver = self.state.dns_task.clone();
                self.record_frame(hit, number, &capture, time, resolver.as_ref());
            } else {
                self.notes.push(
                    "network.dga_nxdomain was not evaluated: no resolver answered any name in this run, so every lookup failing says nothing."
                        .into(),
                );
            }
        }
        let mut aggs: Vec<Agg> = self
            .aggs
            .into_iter()
            .filter(|agg| {
                !(agg.rule == "evasion.traceme"
                    && agg.object == "PTRACE_TRACEME"
                    && traced.contains(&agg.cookie))
            })
            .collect();
        aggs.extend(probes::rows(&self.state, files));
        if self.options.capture_all {
            scope(&mut aggs, &self.state, files);
        }
        noise::fold_siblings(&mut aggs, files);
        for agg in &mut aggs {
            noise::settle(agg);
        }
        aggs.sort_by_key(|agg| agg.first_ns);
        let mut info_matches = self.info_matches;
        let mut shown = Vec::new();
        for agg in aggs {
            if agg.tier == Tier::Info {
                info_matches += agg.count;
                if !self.options.show_info {
                    continue;
                }
            }
            shown.push(agg);
        }
        let (kept, overflow) = noise::cap(shown);
        let held_back = self.dropped;
        let mut output = Output {
            rows: Vec::new(),
            tiers: [0; 4],
            hidden: 0,
            capped: 0,
            suppressed: self.state.frames.suppressed,
            notes: std::mem::take(&mut self.notes),
            badge: 0,
            tasks: Suspicious::new(),
        };
        output.tiers[Tier::Info.index()] = info_matches;
        output.capped += held_back;
        output.badge += held_back;
        for agg in &kept {
            if agg.hidden() {
                output.hidden += 1;
            } else if agg.tier != Tier::Info {
                output.tiers[agg.tier.index()] += 1;
                output.badge += 1;
            }
            let row = rows::finding(agg);
            if !agg.hidden() && agg.tier != Tier::Info && agg.cookie != 0 {
                tally(&mut output.tasks, &row.values);
            }
            output.rows.push(row);
        }
        for (rule, overflow) in &overflow {
            output.capped += overflow.count;
            output.badge += overflow.count;
            if let Some(row) = rows::overflow_row(rule, overflow) {
                output.rows.push(row);
            }
        }
        output
    }
}

/// A capture of the whole VM: processes that were running before it began are out of scope.
fn scope(aggs: &mut [Agg], state: &State, files: &FdState) {
    for agg in aggs {
        let task = TaskKey {
            pid: agg.pid,
            cookie: agg.cookie,
        };
        let seen_created = files
            .process_images
            .get(&task)
            .is_some_and(|node| node.parent.is_some());
        let started_by_exec = state
            .tasks()
            .get(&agg.cookie)
            .is_some_and(|task| matches!(task.first_nr, Some(59 | 322)));
        let caused = agg
            .image
            .as_deref()
            .is_some_and(|image| state.written.contains(image));
        if !(seen_created || started_by_exec || caused) {
            agg.flags |= flag::OUTSIDE;
        }
    }
}

/// How a call ended, as the `Outcome` cell words it.
fn outcome(call: &InvocationSummary) -> String {
    findings::outcome(call)
}
