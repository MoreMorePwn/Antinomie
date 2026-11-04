// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Golden files of how the Syscall Trace view shows each described call,
//! normalised so a rerun reproduces them: process and thread IDs become
//! `<pid>`, addresses `<addr>`, and content the program could not predict
//! (`volatile` cases, exit-time buffers) is left out. The files live in
//! tests/monitor/conformance/trace/golden/GROUP.txt; `--bless` rewrites them.
//! A Debian base has its own (`golden/debian-minimal/GROUP.txt`, on arm64
//! `golden/aarch64/debian-minimal/GROUP.txt`): its
//! kernel has Debian's configuration, so calls whose result depends on it
//! (kexec_file_load, userfaultfd, transparent huge pages, the shadow stack, the
//! persistent keyring, the log buffer size, the built-in file systems) answer
//! as Debian's kernel does, not as the BusyBox kernel's.
//! A result written as a set (`= 0|ESRCH`) accepts any one of those results:
//! a race the fixture calls with WANT_ANY and whose outcomes its `why` names
//! (process_mrelease on a target that may already have exited). `--bless`
//! keeps such a set while the run's result is in it.
use crate::{Context, judge::CaseResult, oracle, recording, render::Views, trace::GroupReport};
use std::collections::{BTreeMap, BTreeSet};

/// Groups whose calls happen in a fixed order with fixed values.
const GOLDEN_GROUPS: [&str; 2] = ["user", "root"];

pub struct Checked {
    pub passed: bool,
    pub summary: Vec<String>,
}

fn looks_like_address(text: &str) -> bool {
    text.strip_prefix("0x")
        .is_some_and(|digits| digits.len() >= 5 && digits.chars().all(|c| c.is_ascii_hexdigit()))
}

/// What a golden line must not depend on: process and thread IDs, the
/// fixture's private directory, and the base's root disk (a whole disk on
/// BusyBox, a partition on Debian) and its device number.
pub struct Volatile {
    pub ids: BTreeSet<String>,
    pub work_dir: Option<String>,
    pub root_device: Option<String>,
    pub work_device: Option<String>,
}

/// One value as the golden file keeps it. Only values that name a process
/// (`pidish`) are compared with the run's IDs.
fn normal(text: &str, volatile: &Volatile, pidish: bool) -> String {
    if looks_like_address(text) {
        return "<addr>".into();
    }
    // A process or thread number other than 0 and -1, whoever it names.
    if pidish && text.parse::<i64>().is_ok_and(|id| id > 0) {
        return "<pid>".into();
    }
    // Kernel-chosen handles printed in decimal (an AIO context).
    if text
        .parse::<u64>()
        .is_ok_and(|value| value > u64::from(u32::MAX))
    {
        return "<handle>".into();
    }
    // A CPU clock names its process or thread: "… of process 120".
    for owner in [" of process ", " of thread "] {
        if let Some((head, id)) = text.rsplit_once(owner)
            && id.chars().all(|c| c.is_ascii_digit())
        {
            return format!("{head}{owner}<pid>");
        }
    }
    if let Some(device) = &volatile.root_device
        && (text == device || text == format!("\"{device}\""))
    {
        return text.replace(device.as_str(), "<root-dev>");
    }
    let mut text = text.to_owned();
    if let Some(dir) = &volatile.work_dir {
        text = text.replace(dir.as_str(), "<work>");
    }
    // IDs inside text (/proc/1234/...): whole numbers only.
    let mut out = String::with_capacity(text.len());
    let mut digits = String::new();
    for c in text.chars().chain(std::iter::once('\0')) {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        if !digits.is_empty() {
            let embedded = out.ends_with('/') || out.ends_with(':') || out.ends_with('-');
            if embedded && volatile.ids.contains(&digits) {
                out.push_str("<pid>");
            } else {
                out.push_str(&digits);
            }
            digits.clear();
        }
        if c != '\0' {
            out.push(c);
        }
    }
    out
}

/// The work directory's device number, where a device field holds it (an
/// argument or a decoded member named `dev` or `…_dev`); the same digits in
/// any other value (a size, a count) are kept.
fn work_device(name: &str, text: &str, volatile: &Volatile) -> Option<String> {
    let device = name == "dev" || name.ends_with("_dev");
    (device && volatile.work_device.as_deref() == Some(text)).then(|| "<work-dev>".to_owned())
}

/// A captured object as the golden file keeps it: text, socket addresses and
/// exec vectors are stable; raw bytes (structs holding times, addresses,
/// inode numbers) are not, so only their presence is kept.
fn data(preview: &str, volatile: &Volatile) -> String {
    let readable = preview.starts_with('"')
        || preview.starts_with('[')
        || preview.starts_with("unix:")
        || preview.ends_with(" captured objects")
        || preview
            .rsplit_once(':')
            .is_some_and(|(_, port)| port.chars().all(|c| c.is_ascii_digit()));
    if readable {
        normal(preview, volatile, false)
    } else if preview == "uncaptured" {
        preview.into()
    } else {
        "<bytes>".into()
    }
}

/// Decoded members whose value changes on every run: inode numbers and file
/// times, clock readings, the machine's uptime, load and free memory, a
/// process's CPU time, the kernel's release and the host name. They are kept
/// by name and lose their value (`st_mtime=<value>`).
fn is_volatile_member(name: &str) -> bool {
    const NAMES: &[&str] = &[
        "st_ino",
        "stx_ino",
        "stx_mnt_id",
        "stx_dev_major",
        "stx_dev_minor",
        "tms_utime",
        "tms_stime",
        "tms_cutime",
        "tms_cstime",
        "uptime",
        "loads",
        "freeram",
        "sharedram",
        "bufferram",
        "freeswap",
        "freehigh",
        "procs",
        "nodename",
        "release",
        "version",
        "domainname",
        "f_bfree",
        "f_bavail",
        "f_blocks",
        "f_files",
        "f_ffree",
        "f_fsid",
        "maxerror",
        "esterror",
    ];
    NAMES.contains(&name)
        || name.starts_with("ru_")
        || ["st_atime", "st_mtime", "st_ctime"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        || (name.starts_with("stx_") && name.contains("time"))
}

/// `text` with the value of every volatile member (see
/// [`is_volatile_member`]) replaced by `<value>`. A value runs to the next
/// `,` or `}` outside brackets and quotes.
fn hide_volatile_members(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        let starts_name = c.is_ascii_alphabetic() || c == '_';
        let after_boundary =
            at == 0 || !(chars[at - 1].is_ascii_alphanumeric() || chars[at - 1] == '_');
        if starts_name && after_boundary {
            let end = (at..chars.len())
                .find(|&i| !(chars[i].is_ascii_alphanumeric() || chars[i] == '_'))
                .unwrap_or(chars.len());
            let name: String = chars[at..end].iter().collect();
            if chars.get(end) == Some(&'=') && is_volatile_member(&name) {
                out.push_str(&name);
                out.push_str("=<value>");
                let (mut depth, mut quoted, mut escaped) = (0i32, false, false);
                let mut i = end + 1;
                while i < chars.len() {
                    let c = chars[i];
                    if quoted {
                        if escaped {
                            escaped = false;
                        } else if c == '\\' {
                            escaped = true;
                        } else if c == '"' {
                            quoted = false;
                        }
                    } else {
                        match c {
                            '"' => quoted = true,
                            '{' | '[' | '(' => depth += 1,
                            '}' | ']' | ')' if depth == 0 => break,
                            '}' | ']' | ')' => depth -= 1,
                            ',' if depth == 0 => break,
                            _ => {}
                        }
                    }
                    i += 1;
                }
                at = i;
                continue;
            }
            out.push_str(&name);
            at = end;
            continue;
        }
        out.push(c);
        at += 1;
    }
    out
}

/// Outputs of a call that read a clock or a timer: their value differs on
/// every run, whatever its layout (`clock_gettime`'s `tp`).
fn reads_clock(call: &str, argument: &str) -> bool {
    matches!(
        (call, argument),
        ("clock_gettime", "tp")
            | ("gettimeofday", "tv")
            | ("getitimer", "value")
            | ("timer_gettime", "setting")
            | ("timerfd_gettime", "otmr")
            | ("time", "tloc")
    )
}

/// Calls whose result is a time or a tick count.
fn returns_clock(call: &str) -> bool {
    matches!(call, "time" | "times")
}

/// A field the view decoded by its layout (`{si_signo=SIGCHLD, si_pid=120}`,
/// `[SIGINT SIGTERM]`, a version name) is kept, with the values in it that a
/// rerun changes normalised one at a time: addresses, kernel handles, and the
/// process and thread IDs of members named for one (`si_pid`, `pid`,
/// `sigev_notify_thread_id`) or of a whole value that is one (`pidish`).
/// Quoted text inside (a name) is kept, the work directory replaced.
fn decoded(text: &str, volatile: &Volatile, pidish: bool) -> String {
    let hidden = hide_volatile_members(text);
    let text = hidden.as_str();
    let names_process =
        |name: &str| name.ends_with("pid") || name.ends_with("tid") || name.ends_with("thread_id");
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    let mut member = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in text.chars().chain(std::iter::once('\0')) {
        if quoted {
            token.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
                out.push_str(&normal(&token, volatile, false));
                token.clear();
            }
            continue;
        }
        if c == '"' && token.is_empty() {
            quoted = true;
            token.push(c);
            continue;
        }
        if c.is_ascii_alphanumeric() || c == '_' || (c == '-' && token.is_empty()) {
            token.push(c);
            continue;
        }
        if !token.is_empty() {
            if c == '=' {
                out.push_str(&token);
                member = std::mem::take(&mut token);
            } else {
                let whole = out.is_empty() && c == '\0';
                let pid = names_process(&member) || (whole && pidish);
                match work_device(&member, &token, volatile) {
                    Some(device) => out.push_str(&device),
                    None => out.push_str(&normal(&token, volatile, pid)),
                }
                token.clear();
            }
        }
        if c != '\0' {
            out.push(c);
        }
    }
    out
}

/// Syscalls whose result is a process or thread ID.
const RETURNS_ID: [&str; 12] = [
    "getpid",
    "getppid",
    "gettid",
    "fork",
    "vfork",
    "clone",
    "clone3",
    "getpgid",
    "getpgrp",
    "getsid",
    "setsid",
    "set_tid_address",
];

fn line(
    case: &CaseResult,
    volatile: bool,
    view: &crate::render::CallView,
    ids: &Volatile,
) -> String {
    let arguments: Vec<String> = view
        .arguments
        .iter()
        .map(|argument| {
            let shown = match &argument.data {
                Some(_) if volatile => "<data>".to_owned(),
                Some(_) if reads_clock(&view.name, &argument.name) => "<time>".to_owned(),
                Some(preview) if argument.decoded => decoded(preview, ids, false),
                Some(preview) => data(preview, ids),
                // In a case the fixture marks volatile, large numbers are
                // kernel-chosen (key serials, timer ids).
                None if volatile
                    && argument
                        .text
                        .parse::<i64>()
                        .is_ok_and(|value| value.unsigned_abs() > 0xffff) =>
                {
                    "<value>".to_owned()
                }
                None if work_device(&argument.name, &argument.text, ids).is_some() => {
                    "<work-dev>".to_owned()
                }
                None => normal(
                    &argument.text,
                    ids,
                    ["pid", "tid", "tgid", "pgid", "pgrp", "sid"]
                        .iter()
                        .any(|name| argument.name.contains(name)),
                ),
            };
            format!("{}={shown}", argument.name)
        })
        .collect();
    let result = view.result.as_deref().map_or("-".to_owned(), |text| {
        if (volatile || returns_clock(&view.name)) && !text.starts_with('E') {
            "<value>".into()
        } else {
            normal(
                text,
                ids,
                RETURNS_ID.contains(&view.name.as_str()) || view.name.starts_with("wait"),
            )
        }
    });
    let fields: Vec<String> = view
        .fields
        .iter()
        .map(|field| {
            let key = field["key"].as_str().unwrap_or("?");
            let mut status = field["status"].as_str().unwrap_or("?").to_owned();
            // A field captured after the Entry (contract 22) says how.
            if let Some(mark) = field["recapture"].as_str() {
                status = format!("{status}@{mark}");
            }
            if field["phase"].as_u64() == Some(1) && !volatile {
                let typed = field["decoded"].as_bool() == Some(true);
                format!(
                    "{key}:{status}:{}",
                    field["preview"].as_str().map_or("?".into(), |p| if typed {
                        decoded(p, ids, key.ends_with("pid"))
                    } else {
                        data(p, ids)
                    })
                )
            } else {
                format!("{key}:{status}")
            }
        })
        .collect();
    let warnings = if view.warnings.is_empty() {
        String::new()
    } else {
        format!(" !{}", view.warnings.len())
    };
    format!(
        "{} | {}({}) = {result} | {}{warnings}",
        case.label,
        view.name,
        arguments.join(", "),
        fields.join(" ")
    )
    .trim_end()
    .to_owned()
}

/// Where a golden line's result is: after the call's `) = `, up to the
/// separator before the fields (` |`, its trailing blank trimmed when no field
/// follows) or the end. A set's own `|` has no blank before it.
fn result_span(line: &str) -> Option<(usize, usize)> {
    let call = line.find(" | ")? + 3;
    let start = call + line[call..].find(") = ")? + 4;
    let end = line[start..].find(" |").map_or(line.len(), |at| start + at);
    Some((start, end))
}

/// Whether a run's line matches a golden line. A golden result may name the
/// set of results the fixture allows (`= 0|ESRCH`, a race the fixture calls
/// with WANT_ANY and explains both outcomes of): the run's result must be
/// one of them, and the rest of the line identical. Any other line must be
/// identical.
fn line_matches(golden: &str, run: &str) -> bool {
    if golden == run {
        return true;
    }
    let (Some((start, end)), Some((run_start, run_end))) = (result_span(golden), result_span(run))
    else {
        return false;
    };
    let allowed = &golden[start..end];
    allowed.contains('|')
        && golden[..start] == run[..run_start]
        && golden[end..] == run[run_end..]
        && allowed
            .split('|')
            .any(|result| result == &run[run_start..run_end])
}

/// Whether a run's golden text matches the golden file line for line.
fn golden_matches(golden: &str, run: &str) -> bool {
    golden.lines().count() == run.lines().count()
        && golden
            .lines()
            .zip(run.lines())
            .all(|(golden, run)| line_matches(golden, run))
}

/// The run's text as `--bless` writes it: a golden line whose allowed set the
/// run's line matches is kept, so blessing never narrows a set to one result.
fn blessed(golden: &str, run: &str) -> String {
    let mut sets: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for line in golden
        .lines()
        .filter(|line| result_span(line).is_some_and(|(start, end)| line[start..end].contains('|')))
    {
        sets.entry(line.split(" | ").next().unwrap_or(line))
            .or_default()
            .push(line);
    }
    let mut out = String::with_capacity(run.len());
    for line in run.lines() {
        let label = line.split(" | ").next().unwrap_or(line);
        let kept = sets
            .get(label)
            .and_then(|lines| lines.iter().find(|golden| line_matches(golden, line)));
        out.push_str(kept.copied().unwrap_or(line));
        out.push('\n');
    }
    out
}

/// Line-based diff: lines only in the golden file (-) and only in the run (+).
fn diff(old: &str, new: &str) -> Vec<String> {
    let old: Vec<&str> = old.lines().collect();
    let new: Vec<&str> = new.lines().collect();
    let (n, m) = (old.len(), new.len());
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if line_matches(old[i], new[j]) {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < n || j < m {
        if i < n && j < m && line_matches(old[i], new[j]) {
            i += 1;
            j += 1;
        } else if j < m && (i == n || lcs[i][j + 1] >= lcs[i + 1][j]) {
            out.push(format!("+{}", new[j]));
            j += 1;
        } else {
            out.push(format!("-{}", old[i]));
            i += 1;
        }
    }
    out
}

pub fn check(context: &Context, reports: &[GroupReport], views: &Views) -> Result<Checked, String> {
    let directory = context.golden_dir();
    let mut passed = true;
    let mut summary = Vec::new();
    for report in reports
        .iter()
        .filter(|report| GOLDEN_GROUPS.contains(&report.group.as_str()))
    {
        let Some(group_views) = views.get(&report.group) else {
            continue;
        };
        let transcript = oracle::parse(&recording::transcript(std::path::Path::new(
            &report.run_dir,
        ))?);
        let mut ids = Volatile {
            ids: BTreeSet::new(),
            work_dir: transcript.work_dir.clone(),
            root_device: transcript.root_device.clone(),
            work_device: transcript.work_device.clone(),
        };
        let mut volatile: BTreeMap<u64, bool> = BTreeMap::new();
        for expect in &transcript.expects {
            ids.ids.insert(expect.pid.to_string());
            ids.ids.insert(expect.tid.to_string());
            volatile.insert(expect.seq, expect.is_volatile);
        }
        ids.ids.extend(transcript.roles.keys().map(u32::to_string));
        let mut text = String::new();
        let mut cases: Vec<&CaseResult> = report.cases.iter().collect();
        cases.sort_by(|a, b| a.label.cmp(&b.label).then(a.seq.cmp(&b.seq)));
        for case in cases {
            let Some(view) = case.matched.and_then(|key| group_views.calls.get(&key)) else {
                text.push_str(&format!("{} | not recorded\n", case.label));
                continue;
            };
            let volatile = volatile.get(&case.seq).copied().unwrap_or(false);
            text.push_str(&line(case, volatile, view, &ids));
            text.push('\n');
        }
        let path = directory.join(format!("{}.txt", report.group));
        if context.bless {
            std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
            let old = std::fs::read_to_string(&path).unwrap_or_default();
            std::fs::write(&path, blessed(&old, &text)).map_err(|e| e.to_string())?;
            summary.push(format!("BLESSED golden {}", path.display()));
            continue;
        }
        let old = std::fs::read_to_string(&path).unwrap_or_default();
        if golden_matches(&old, &text) {
            summary.push(format!("PASS golden {}", report.group));
            continue;
        }
        passed = false;
        let changes = diff(&old, &text);
        let out = context.out.join(format!("golden-{}.txt", report.group));
        std::fs::write(&out, &text).map_err(|e| e.to_string())?;
        summary.push(format!(
            "FAIL golden {}: {} changed lines (run written to {})",
            report.group,
            changes.len(),
            out.display()
        ));
        for change in changes.iter().take(60) {
            summary.push(format!("    {change}"));
        }
    }
    Ok(Checked { passed, summary })
}

#[cfg(test)]
mod tests {
    #[test]
    fn diff_shows_removed_and_added_lines() {
        assert_eq!(super::diff("a\nb\nc\n", "a\nc\nd\n"), ["-b", "+d"]);
        assert!(super::diff("a\n", "a\n").is_empty());
    }

    #[test]
    fn a_golden_result_may_name_the_set_the_fixture_allows() {
        let golden =
            "process_mrelease.killed_target | process_mrelease(pidfd=<pid>, flags=0x0) = 0|ESRCH |";
        let run = |result: &str| {
            format!(
                "process_mrelease.killed_target | process_mrelease(pidfd=<pid>, flags=0x0) = {result} |"
            )
        };
        assert_eq!(
            super::result_span(golden).map(|(start, end)| &golden[start..end]),
            Some("0|ESRCH")
        );
        assert!(super::line_matches(golden, &run("0")));
        assert!(super::line_matches(golden, &run("ESRCH")));
        // Any other result, or another argument, still fails.
        for other in ["EINVAL", "EPERM", "ENOSYS", "0|ESRCH|EINVAL", "ESRC"] {
            assert!(!super::line_matches(golden, &run(other)), "{other}");
        }
        assert!(!super::line_matches(
            golden,
            "process_mrelease.killed_target | process_mrelease(pidfd=<pid>, flags=0x1) = 0 |"
        ));
        // A result without a set, and fields after the result, are compared exactly.
        let plain = "a.b | read(fd=3, buf=<addr>, count=4) = 4 | arg1.data:complete:\"ab|c\"";
        assert!(super::line_matches(plain, plain));
        assert!(!super::line_matches(plain, &plain.replace("= 4", "= 5")));
        assert_eq!(
            super::result_span(plain).map(|(start, end)| &plain[start..end]),
            Some("4")
        );
        let file = format!("x | y() = 1\n{golden}\n");
        assert!(super::golden_matches(
            &file,
            &format!("x | y() = 1\n{}\n", run("ESRCH"))
        ));
        assert!(!super::golden_matches(
            &file,
            &format!("x | y() = 2\n{}\n", run("ESRCH"))
        ));
        assert!(super::diff(&file, &format!("x | y() = 1\n{}\n", run("0"))).is_empty());
        // Blessing keeps the set where the run's result is in it.
        assert_eq!(
            super::blessed(&file, &format!("x | y() = 3\n{}\n", run("0"))),
            format!("x | y() = 3\n{golden}\n")
        );
        assert_eq!(
            super::blessed(&file, &format!("x | y() = 3\n{}\n", run("EINVAL"))),
            format!("x | y() = 3\n{}\n", run("EINVAL"))
        );
    }

    #[test]
    fn raw_bytes_are_kept_only_as_present() {
        let ids = super::Volatile {
            ids: Default::default(),
            work_dir: None,
            root_device: None,
            work_device: None,
        };
        assert_eq!(super::data("06 00 00 00 b6 c8", &ids), "<bytes>");
        assert_eq!(super::data("\"io-at\"", &ids), "\"io-at\"");
        assert_eq!(super::data("127.0.0.1:80", &ids), "127.0.0.1:80");
        assert_eq!(super::data("[\"sh\", \"-c\"]", &ids), "[\"sh\", \"-c\"]");
        assert_eq!(super::data("uncaptured", &ids), "uncaptured");
        // The view shows a time or a pointer-holding struct in hex whatever
        // its bytes (futex_waitv's timeout, seccomp's empty sock_fprog), so
        // the golden keeps only its presence; a data buffer stays text.
        assert_eq!(
            super::data("0a 00 00 00 00 00 00 00 28 5b 7d 0d 00 00 00 00", &ids),
            "<bytes>"
        );
        assert_eq!(
            super::data("00 00 00 00 00 00 00 00 40 2e 4b 00 00 00 00 00", &ids),
            "<bytes>"
        );
        assert_eq!(super::data("\"\\x06\\0A\"", &ids), "\"\\x06\\0A\"");
    }

    #[test]
    fn decoded_fields_keep_their_members_and_lose_what_a_rerun_changes() {
        let ids = super::Volatile {
            ids: ["1234".to_owned()].into_iter().collect(),
            work_dir: Some("/tmp/ant-conformance-AbC123".into()),
            root_device: None,
            work_device: None,
        };
        assert_eq!(
            super::decoded(
                "{si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=1234, si_uid=0, si_status=-1}",
                &ids,
                false
            ),
            "{si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=<pid>, si_uid=0, si_status=-1}"
        );
        assert_eq!(
            super::decoded(
                "{ss_sp=0x7ffe00001000, ss_flags=SS_ONSTACK, ss_size=8192}",
                &ids,
                false
            ),
            "{ss_sp=<addr>, ss_flags=SS_ONSTACK, ss_size=8192}"
        );
        assert_eq!(
            super::decoded("[SIGINT SIGUSR1]", &ids, false),
            "[SIGINT SIGUSR1]"
        );
        assert_eq!(super::decoded("1234", &ids, true), "<pid>");
        assert_eq!(super::decoded("1234", &ids, false), "1234");
        assert_eq!(
            super::decoded(
                "[{d_ino=12, d_name=\"/tmp/ant-conformance-AbC123/x 1234=\\\"\"}]",
                &ids,
                false
            ),
            "[{d_ino=12, d_name=\"<work>/x 1234=\\\"\"}]"
        );
    }

    #[test]
    fn addresses_ids_and_the_work_directory_are_normalised() {
        let ids = super::Volatile {
            ids: ["1234".to_owned()].into_iter().collect(),
            work_dir: Some("/tmp/ant-conformance-AbC123".into()),
            root_device: Some("/dev/vda1".into()),
            work_device: Some("64769".into()),
        };
        // The root disk and its device number by role, whichever the base.
        assert_eq!(
            super::normal("\"/dev/vda1\"", &ids, false),
            "\"<root-dev>\""
        );
        // The work directory's device number only in a device field.
        assert_eq!(super::normal("64769", &ids, false), "64769");
        assert_eq!(
            super::work_device("dev", "64769", &ids).as_deref(),
            Some("<work-dev>")
        );
        assert_eq!(super::work_device("size", "64769", &ids), None);
        assert_eq!(
            super::decoded("{st_dev=64769, st_size=64769}", &ids, false),
            "{st_dev=<work-dev>, st_size=64769}"
        );
        assert_eq!(super::normal("\"/dev/vda\"", &ids, false), "\"/dev/vda\"");
        assert_eq!(super::normal("0x7ffe00001000", &ids, false), "<addr>");
        assert_eq!(super::normal("1234", &ids, true), "<pid>");
        assert_eq!(super::normal("-1", &ids, true), "-1");
        assert_eq!(
            super::normal("CPU clock (scheduler) of process 120", &ids, false),
            "CPU clock (scheduler) of process <pid>"
        );
        assert_eq!(super::normal("140291445530624", &ids, false), "<handle>");
        assert_eq!(super::normal("1234", &ids, false), "1234");
        assert_eq!(super::normal("O_RDONLY", &ids, true), "O_RDONLY");
        assert_eq!(super::normal("0x10", &ids, false), "0x10");
        assert_eq!(
            super::normal("\"/tmp/ant-conformance-AbC123/io-at\"", &ids, false),
            "\"<work>/io-at\""
        );
        assert_eq!(
            super::normal("\"/proc/1234/ns\"", &ids, false),
            "\"/proc/<pid>/ns\""
        );
        assert_eq!(super::normal("\"a1234\"", &ids, false), "\"a1234\"");
    }

    #[test]
    fn run_dependent_decoded_members_and_clock_readings_are_hidden() {
        let ids = super::Volatile {
            ids: Default::default(),
            work_dir: None,
            root_device: None,
            work_device: None,
        };
        assert_eq!(
            super::decoded(
                "{st_dev=7, st_ino=131234, st_mode=S_IFREG|0644, st_size=12, \
                 st_atime=1700000000, st_atime_nsec=5, st_mtime=1700000001}",
                &ids,
                false
            ),
            "{st_dev=7, st_ino=<value>, st_mode=S_IFREG|0644, st_size=12, \
             st_atime=<value>, st_atime_nsec=<value>, st_mtime=<value>}"
        );
        // A nested time group (statx) and a list (sysinfo's loads) go whole.
        assert_eq!(
            super::decoded(
                "{stx_mode=S_IFDIR|0755, stx_mtime=1700000000 s (19675 d 22 h), stx_ino=9, \
                 stx_size=4096}",
                &ids,
                false
            ),
            "{stx_mode=S_IFDIR|0755, stx_mtime=<value>, stx_ino=<value>, stx_size=4096}"
        );
        assert_eq!(
            super::decoded(
                "{uptime=812, loads=[1, 2, 3], totalram=1000, procs=40}",
                &ids,
                false
            ),
            "{uptime=<value>, loads=<value>, totalram=1000, procs=<value>}"
        );
        assert_eq!(
            super::decoded(
                "{sysname=\"Linux\", nodename=\"a, b\", release=\"6.12.94\", machine=\"x86_64\"}",
                &ids,
                false
            ),
            "{sysname=\"Linux\", nodename=<value>, release=<value>, machine=\"x86_64\"}"
        );
        assert_eq!(
            super::decoded("{ru_utime=1 s, ru_maxrss=2048}", &ids, false),
            "{ru_utime=<value>, ru_maxrss=<value>}"
        );
        // Names that merely contain a volatile one are kept.
        assert_eq!(
            super::decoded("{my_release=3, tick_rate=4}", &ids, false),
            "{my_release=3, tick_rate=4}"
        );
        // Clock readings by call and argument; results of time() and times().
        assert!(super::reads_clock("clock_gettime", "tp"));
        assert!(super::reads_clock("gettimeofday", "tv"));
        assert!(!super::reads_clock("clock_gettime", "which_clock"));
        assert!(!super::reads_clock("nanosleep", "rqtp"));
        assert!(super::returns_clock("times") && !super::returns_clock("getpid"));
    }
}
