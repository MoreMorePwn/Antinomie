// SPDX-License-Identifier: GPL-3.0-only
//! Rules for evasion that is not a file or a program name: long sleeps, names
//! taken from kernel threads and daemons, and the anti-analysis checks of
//! [`probes`](super::probes).
use super::ctx::{base, nr, Ctx};
use super::state::State;
use super::{probes, process, Hit, Tier};

const MINUTE: u64 = 60 * 1_000_000_000;

pub(super) fn rules(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    probes::call(cx, st, out);
    if cx.is_exec() {
        exec_name(cx, st, out);
    } else {
        sleep(cx, st, out);
    }
    probes::behaviour(cx, st);
}

/// The new program's `argv[0]` is a kernel thread's or a daemon's name.
fn exec_name(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    let cookie = cx.call.task_cookie;
    if st.probes.traceme.remove(&cookie) && cx.ok {
        st.probes.traced_exec.insert(cookie);
    }
    let (Some(argv0), Some(path)) = (cx.argv().first(), cx.exec_path()) else {
        return;
    };
    process::masquerade(argv0, base(&path), "exec argv[0]", out);
}

/// A wait of a minute or more, before the program has done anything else.
fn sleep(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    let length = match cx.nr {
        nr::NANOSLEEP | nr::CLOCK_NANOSLEEP => probes::sleep_ns(cx),
        // select(0, NULL, NULL, NULL, timeval)
        23 if cx.args[0] == 0 => cx
            .word(4, "", 0)
            .map(|seconds| seconds.saturating_mul(1_000_000_000)),
        // poll(NULL, 0, timeout in milliseconds)
        7 if cx.args[1] == 0 => Some((cx.args[2] as i32).max(0) as u64 * 1_000_000),
        nr::ALARM => Some(cx.args[0].saturating_mul(1_000_000_000)),
        // timerfd_settime: it_value is the second timespec of the structure
        nr::TIMERFD_SETTIME => cx
            .word(2, "", 16)
            .map(|seconds| seconds.saturating_mul(1_000_000_000)),
        _ => None,
    };
    let Some(length) = length.filter(|length| *length >= MINUTE) else {
        return;
    };
    let first = !st.task(cx).active;
    let mut hit = Hit::new(
        "evasion.long_sleep",
        cx.name,
        format!(
            "{} for {} s{}",
            cx.name,
            length / 1_000_000_000,
            if first {
                ", before any network or file write"
            } else {
                ""
            }
        ),
    );
    if !first {
        hit = hit
            .tier(Tier::Low)
            .detail("The task had already used the network or written a file: LOW.");
    }
    out.push(hit);
}
