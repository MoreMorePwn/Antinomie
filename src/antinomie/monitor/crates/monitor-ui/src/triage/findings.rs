// SPDX-License-Identifier: GPL-3.0-only
//! Suspicious-behaviour findings: the rules run over a list of calls, and the
//! helpers the rows and the filter share.
use super::rules::{view_keeps, Engine, Options, Output, View};
use super::*;

pub(super) fn call_args(invocation: &InvocationSummary) -> Option<[u64; 6]> {
    invocation
        .entry
        .as_ref()
        .and_then(|event| event.args)
        .or_else(|| invocation.exit.as_ref().and_then(|event| event.args))
}

pub(super) fn outcome(invocation: &InvocationSummary) -> String {
    invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .map_or("exit not recorded".to_string(), |result| {
            if result < 0 {
                format!("failed ({result})")
            } else {
                format!("returned {result}")
            }
        })
}

/// `setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER)`. Another level with optname 26 is not a match.
pub(super) fn classic_socket_filter(event: &EventSummary, args: [u64; 6]) -> bool {
    (event.syscall_name == "setsockopt" || event.syscall_nr == 54) && args[1] == 1 && args[2] == 26
}

pub(super) fn filter_findings(rows: Vec<Finding>, filter: &str) -> Vec<Finding> {
    let compiled = query::compile_table(filter, FINDING_FIELDS);
    rows.into_iter()
        .filter(|row| compiled.keep_table(&row.values))
        .collect()
}

/// The rows for calls held in memory, as the live view shows them: every tier
/// the default view keeps, in time order.
pub(super) fn suspicious_rows(invocations: &[InvocationSummary]) -> Vec<Finding> {
    suspicious_output(invocations, Options::default())
        .rows
        .into_iter()
        .filter(|row| view_keeps(&View::default(), &row.values))
        .collect()
}

/// Run the rules over calls in order, following the descriptor state the way
/// the saved-recording scan does.
pub(super) fn suspicious_output(invocations: &[InvocationSummary], options: Options) -> Output {
    let mut files = FdState::default();
    let mut engine = Engine::new(options);
    let mut sets = std::collections::BTreeMap::new();
    note_cookie_sets(&mut sets, invocations);
    let cookies = resolve_cookies(&sets);
    for invocation in invocations {
        observe_processes(&mut files.process_images, std::slice::from_ref(invocation));
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        engine.observe(invocation, &files, None, false);
        remember_cwd(&mut files, invocation, event);
        remember_open(&mut files, invocation, event);
        apply_dup(&mut files, invocation, event);
        forget_closed(&mut files, invocation, event);
        inherit_open_fds(&mut files, invocation, event, &cookies);
        sigma_events::track(&mut files, invocation, event);
    }
    engine.finish(&files)
}
