// SPDX-License-Identifier: GPL-3.0-only
//! Rules for evasion that is not a file or a program name: long sleeps, names
//! taken from kernel threads and daemons, and the anti-analysis checks of
//! [`probes`](super::probes).
use super::ctx::{base, Ctx};
use super::state::State;
use super::{probes, process, Hit, Tier};
use crate::{file_location, process_cells};

pub const MINUTE: u64 = 60 * 1_000_000_000;

pub fn rules(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    probes::call(cx, st, out);
    if cx.is_exec() {
        packed_image(cx, st, out);
        exec_name(cx, st, out);
    } else {
        sleep(cx, st, out);
    }
    probes::behaviour(cx, st);
}

/// The run's own program is the file Static analysis found packed. It is judged
/// at the first exec of the run's root task: the packer is a fact about the
/// file, so this is not a claim about what the program did.
pub fn packed_image(cx: &Ctx, st: &State, out: &mut Vec<Hit>) {
    let Some(packed) = st.packed.as_ref() else {
        return;
    };
    let (root, task) = (cx.event.root_task_cookie, cx.call.task_cookie);
    let Some(path) = cx.exec_path().filter(|_| root != 0 && root == task) else {
        return;
    };
    // The run was asked for a path as typed; the exec names the resolved one.
    let same =
        path == packed.path || (!packed.path.starts_with('/') && base(&path) == base(&packed.path));
    if !same {
        return;
    }
    let layers = packed.layers;
    let mut hit = Hit::new(
        "evasion.packed_image",
        &path,
        format!("{path} is packed with {}", packed.packer),
    )
    .detail(format!(
        "Static analysis (Unpacking) found the file packed with {}; its SHA-256 as it came is {}.",
        packed.packer, packed.sha256
    ))
    .detail(if layers == 0 {
        "No layer could be recovered from it.".to_owned()
    } else {
        format!(
            "{layers} unpacked {} recovered, each analysed on its own.",
            if layers == 1 {
                "layer was"
            } else {
                "layers were"
            }
        )
    });
    hit = if packed.modified {
        hit.detail("The packer's own headers had been changed so that its unpacker refuses the file: MEDIUM.")
    } else {
        hit.tier(Tier::Low)
            .detail("The packer's headers are as it writes them: LOW. A packer is common in legitimate software too.")
    };
    out.push(hit);
}

/// The new program's `argv[0]` is a kernel thread's or a daemon's name.
pub fn exec_name(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    let cookie = cx.call.task_cookie;
    if st.probes.traceme.remove(&cookie) && cx.ok {
        st.probes.traced_exec.insert(cookie);
    }
    let (Some(argv0), Some(path)) = (cx.argv().first(), cx.exec_path()) else {
        return;
    };
    let before = out.len();
    process::masquerade(argv0, base(&path), "exec argv[0]", out);
    // A kernel-thread or daemon name has its own rule above.
    if out.len() == before && cx.ok {
        argv_masquerade(&path, cx.argv(), out);
    }
}

/// Programs a reader trusts by name: what a disguise would copy.
pub const KNOWN_TOOLS: &[&str] = &[
    "bash",
    "sudo",
    "login",
    "python",
    "python3",
    "perl",
    "apt",
    "dpkg",
    "systemctl",
    "journalctl",
    "cron",
    "init",
    "sshd",
    "systemd",
    "udevd",
    "dbus-daemon",
    "NetworkManager",
];

/// The new program's `argv[0]` names a different program than the image the
/// kernel loaded. Some tools rename themselves on purpose, so this is LOW; it
/// is MEDIUM when the name is a well-known system tool and the image sits in a
/// writable place (temp, hidden or home).
pub fn argv_masquerade(path: &str, argv: &[String], out: &mut Vec<Hit>) {
    let Some(claimed) = process_cells::argv0_mismatch(path, argv) else {
        return;
    };
    let name = process_cells::file_name(claimed.trim_start_matches('-'));
    let classes = file_location::classify(path, &[]);
    let writable = [
        file_location::Location::Temp,
        file_location::Location::Hidden,
        file_location::Location::Home,
    ]
    .iter()
    .any(|place| classes.contains(place));
    let known = KNOWN_TOOLS.contains(&name) || process_cells::is_applet(name);
    let mut hit = Hit::new(
        "evasion.argv_masquerade",
        path,
        format!("{path} runs with argv[0] {claimed:?}"),
    )
    .detail(process_cells::mismatch_text(claimed, path));
    hit = if known && writable {
        hit.tier(Tier::Medium).detail(format!(
            "{name} is a well-known system tool and the image is in a writable location: MEDIUM."
        ))
    } else {
        hit.tier(Tier::Low).detail(
            "Some tools rename argv[0] on purpose, and the name is not a well-known tool in a writable place: LOW.",
        )
    };
    out.push(hit);
}

/// A wait of a minute or more, before the program has done anything else.
pub fn sleep(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    let length = match cx.name {
        "nanosleep" | "clock_nanosleep" => probes::sleep_ns(cx),
        // select(0, NULL, NULL, NULL, timeval)
        "select" if cx.args[0] == 0 => cx
            .member(4, "tv_sec", 0, 0)
            .map(|seconds| seconds.saturating_mul(1_000_000_000)),
        // poll(NULL, 0, timeout in milliseconds)
        "poll" if cx.args[1] == 0 => Some((cx.args[2] as i32).max(0) as u64 * 1_000_000),
        "alarm" => Some(cx.args[0].saturating_mul(1_000_000_000)),
        // timerfd_settime: it_value is the second timespec of the structure
        "timerfd_settime" => cx
            .member(2, "it_value.tv_sec", 16, 8)
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
