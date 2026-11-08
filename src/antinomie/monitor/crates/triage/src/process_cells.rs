// SPDX-License-Identifier: GPL-3.0-only
//! The words of the Process tree's cells: file names, the argv[0] check, times
//! relative to the start of the run, lifetimes, the outcome and the exec chain.
use super::process_record::CredStep;

/// The last component of a path.
pub fn file_name(path: &str) -> &str {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(path)
}

/// A task in a Files table: "name (412 \u{b7} 412)", the process and thread
/// as bare numbers, as the Process tree shows them.
pub fn task_label(pid: u32, tid: u32, image: Option<&str>) -> String {
    let name = match image {
        Some("?" | "") | None => "unknown",
        Some(image) => file_name(image),
    };
    format!("{name} ({pid} \u{b7} {tid})")
}

/// Applets BusyBox runs by the name it was called with.
pub const APPLETS: &[&str] = &[
    "ash",
    "awk",
    "base64",
    "basename",
    "cat",
    "chmod",
    "chown",
    "cp",
    "cut",
    "date",
    "dd",
    "df",
    "dirname",
    "dmesg",
    "du",
    "echo",
    "env",
    "expr",
    "false",
    "find",
    "free",
    "grep",
    "gunzip",
    "gzip",
    "head",
    "hostname",
    "id",
    "ifconfig",
    "ip",
    "kill",
    "less",
    "ln",
    "ls",
    "md5sum",
    "mkdir",
    "mktemp",
    "more",
    "mount",
    "mv",
    "nc",
    "netstat",
    "nslookup",
    "ping",
    "ps",
    "pwd",
    "readlink",
    "rm",
    "rmdir",
    "route",
    "sed",
    "seq",
    "sh",
    "sha256sum",
    "sleep",
    "sort",
    "stat",
    "su",
    "sync",
    "tail",
    "tar",
    "tee",
    "test",
    "top",
    "touch",
    "tr",
    "true",
    "umount",
    "uname",
    "uniq",
    "unzip",
    "vi",
    "wc",
    "wget",
    "which",
    "whoami",
    "xargs",
    "yes",
    "zcat",
];

/// Names of one program under its aliases and versions: `python3.13` and
/// `python3` are `python`; every shell is `sh`; `gawk` and `mawk` are `awk`.
pub fn family(name: &str) -> String {
    let name = name.to_ascii_lowercase();
    let mut base = name.as_str();
    // A version suffix: digits and dots after a letter, with an optional dash.
    let trimmed = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    let trimmed = trimmed.strip_suffix('-').unwrap_or(trimmed);
    if trimmed.ends_with(|c: char| c.is_ascii_alphabetic()) {
        base = trimmed;
    }
    match base {
        "sh" | "dash" | "bash" | "ash" | "ksh" | "zsh" | "csh" | "tcsh" | "fish" | "rbash" => "sh",
        "awk" | "gawk" | "mawk" | "nawk" => "awk",
        "vi" | "vim" | "view" | "ex" | "nvim" | "vim.basic" | "vim.tiny" => "vi",
        "nc" | "ncat" | "netcat" => "nc",
        "node" | "nodejs" => "node",
        other => other,
    }
    .to_owned()
}

/// The name a process gave itself in argv[0]: no path, no login-shell dash,
/// and only its first word (daemons rewrite it to a title such as
/// "nginx: master process").
pub fn called(argv0: &str) -> &str {
    let word = argv0.split_whitespace().next().unwrap_or("");
    let word = word.trim_end_matches(':');
    file_name(word.trim_start_matches('-'))
}

/// What argv[0] says against the image the kernel loaded: `Some(argv0)` when
/// the file names do not match and no known pairing explains it.
pub fn argv0_mismatch<'a>(exe: &str, argv: &'a [String]) -> Option<&'a str> {
    let argv0 = argv.first()?.as_str();
    if exe.is_empty() || exe == "?" || called(argv0).is_empty() {
        return None;
    }
    let (name, image) = (called(argv0), file_name(exe));
    if name == image || family(name) == family(image) {
        return None;
    }
    // BusyBox picks the applet by argv[0]: the binary itself, or a link to it
    // (the kernel names the path it was given, not the link's target).
    let busybox = family(image) == "busybox";
    if (busybox || APPLETS.contains(&image)) && APPLETS.contains(&name) {
        return None;
    }
    if busybox && name == "busybox" {
        return None;
    }
    Some(argv0)
}

/// Whether a name is one BusyBox applets or common system tools answer to.
pub fn is_applet(name: &str) -> bool {
    APPLETS.contains(&name)
}

/// The sentence for a mismatch.
pub fn mismatch_text(argv0: &str, exe: &str) -> String {
    format!("This process calls itself \"{argv0}\", but the kernel loaded {exe}.")
}

/// "sh → busybox → demo-all": the file name of each image the task ran.
/// The gap that stands for an argument that was not captured whole.
pub const GAP: &str = "\u{2026}";

/// One argument as a shell would need it written: bare when it has only
/// plain characters, else in single quotes; the gap stays as it is.
pub fn shell_quote(argument: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    if argument == GAP || (!argument.is_empty() && argument.chars().all(plain)) {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

/// The Argv cell: every argument shell-quoted, so one with a space stays one.
pub fn argv_line(argv: &[String]) -> String {
    argv.iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The Argv hover: `argv[i] = value` per argument, then the count and how
/// many were cut short. Past `LISTED` arguments the rest is counted.
pub fn argv_hover(argv: &[String]) -> Option<String> {
    const LISTED: usize = 40;
    if argv.is_empty() {
        return None;
    }
    let mut text = argv
        .iter()
        .enumerate()
        .take(LISTED)
        .map(|(at, argument)| format!("argv[{at}] = {argument}"))
        .collect::<Vec<_>>()
        .join("\n");
    if argv.len() > LISTED {
        text.push_str(&format!("\n\u{2026} and {} more", argv.len() - LISTED));
    }
    let cut = argv.iter().filter(|argument| *argument == GAP).count();
    text.push_str(&format!(
        "\n{} argument{}",
        argv.len(),
        if argv.len() == 1 { "" } else { "s" }
    ));
    if cut > 0 {
        text.push_str(&format!(", {cut} cut short (\u{2026}: not captured whole)"));
    }
    Some(text)
}

pub fn exec_chain(images: &[String]) -> String {
    let mut names: Vec<&str> = Vec::new();
    for image in images {
        let name = file_name(image);
        if image != "further exec history omitted" && names.last() != Some(&name) {
            names.push(name);
        }
    }
    names.join(" \u{2192} ")
}

/// "+1.204 s": where the task started, from the start of the run.
pub fn relative(ns: Option<u64>, start: Option<u64>) -> String {
    match (ns, start) {
        (Some(ns), Some(start)) => format!("+{:.3} s", ns.saturating_sub(start) as f64 / 1e9),
        _ => "\u{2014}".into(),
    }
}

/// How long the task lived, or "running" when no exit was recorded.
pub fn lifetime(first: Option<u64>, last: Option<u64>, ended: bool) -> String {
    if !ended {
        return "running".into();
    }
    let (Some(first), Some(last)) = (first, last) else {
        return "\u{2014}".into();
    };
    duration(last.saturating_sub(first))
}

pub fn duration(ns: u64) -> String {
    let ms = ns / 1_000_000;
    match ns {
        0..=999_999 => format!("{} \u{b5}s", ns / 1000),
        1_000_000..=999_999_999 => format!("{ms} ms"),
        1_000_000_000..=59_999_999_999 => format!("{:.3} s", ns as f64 / 1e9),
        60_000_000_000..=3_599_999_999_999 => {
            format!("{} min {} s", ns / 60_000_000_000, ns / 1_000_000_000 % 60)
        }
        _ => format!(
            "{} h {} min",
            ns / 3_600_000_000_000,
            ns / 60_000_000_000 % 60
        ),
    }
}

/// The task's state as a reader says it: "exit 0", "killed by SIGKILL (from
/// pid 9)", "in read() at end".
pub fn outcome(state: &str, in_call: Option<&str>, killed_by: Option<u32>) -> String {
    if let Some(call) = in_call {
        return format!("in {call}() at end");
    }
    let text = state
        .strip_prefix("task exit, ")
        .or_else(|| state.strip_prefix("task exit "))
        .map(|rest| {
            if rest.starts_with(|c: char| c.is_ascii_digit()) {
                format!("exit {rest}")
            } else {
                rest.to_owned()
            }
        });
    match (text, killed_by) {
        (Some(text), Some(pid)) if text.starts_with("killed by") => {
            format!("{text} (from pid {pid})")
        }
        (Some(text), _) => text,
        (None, _) if state == "task exit" => "exited".into(),
        (None, _) => "no exit recorded".into(),
    }
}

/// The user id of a task: "1000", or "1000 \u{2192} 0" when the effective id differs.
pub fn user(step: Option<&CredStep>) -> String {
    match step {
        None => "\u{2014}".into(),
        Some(step) if step.uid == step.euid => step.uid.to_string(),
        Some(step) => format!("{} \u{2192} {}", step.uid, step.euid),
    }
}

/// The name of a user id, when it is one every Linux system has.
pub fn known_user(id: u32) -> Option<&'static str> {
    match id {
        0 => Some("root"),
        65534 => Some("nobody"),
        _ => None,
    }
}

/// The hover of the User ID cell: the ids in words, and the name of each that
/// is known.
pub fn user_hover(step: &CredStep) -> String {
    let named = |id: u32| match known_user(id) {
        Some(name) => format!("{id} ({name})"),
        None => id.to_string(),
    };
    if step.uid == step.euid {
        format!("User id {}", named(step.uid))
    } else {
        format!(
            "User id {}, effective user id {} (the rights it acts with)",
            named(step.uid),
            named(step.euid)
        )
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn warns(exe: &str, argv: &[&str]) -> bool {
        let argv: Vec<String> = argv.iter().map(|arg| (*arg).to_owned()).collect();
        argv0_mismatch(exe, &argv).is_some()
    }

    #[test]
    fn the_user_is_an_id_and_the_name_is_on_hover() {
        use crate::process_record::CredStep;
        let step = |uid, euid| CredStep {
            ns: 0,
            uid,
            euid,
            gid: 0,
            egid: 0,
            change: antinomie_monitor_core::kernel_notes::CredentialChange::SetUid,
        };
        assert_eq!(user(None), "\u{2014}");
        assert_eq!(user(Some(&step(1000, 1000))), "1000");
        assert_eq!(user(Some(&step(1000, 0))), "1000 \u{2192} 0");
        assert_eq!(user_hover(&step(0, 0)), "User id 0 (root)");
        assert_eq!(user_hover(&step(1000, 1000)), "User id 1000");
        assert!(user_hover(&step(1000, 0)).contains("effective user id 0 (root)"));
    }

    #[test]
    fn a_stand_in_calling_itself_something_else_warns() {
        assert!(warns("/tmp/demo-all", &["ps", "aux"]));
        assert!(warns("/tmp/.x", &["/usr/sbin/sshd", "-D"]));
        let argv = ["ps".to_owned(), "aux".to_owned()];
        assert_eq!(argv0_mismatch("/tmp/demo-all", &argv), Some("ps"));
        assert_eq!(
            mismatch_text("ps", "/tmp/demo-all"),
            "This process calls itself \"ps\", but the kernel loaded /tmp/demo-all."
        );
    }

    #[test]
    fn matching_names_never_warn_whatever_the_path() {
        assert!(!warns("/usr/bin/ls", &["ls", "-l"]));
        assert!(!warns("/usr/bin/ls", &["/bin/ls"]));
        assert!(!warns("ls", &["./ls"]));
        assert!(!warns("/bin/x", &[]));
        assert!(!warns("?", &["x"]));
    }

    #[test]
    fn busybox_applets_are_not_a_mismatch() {
        assert!(!warns("/bin/busybox", &["ls", "-l"]));
        assert!(!warns("/usr/bin/busybox", &["busybox", "ps"]));
        // A link to busybox is named by the link; the applet name is argv[0].
        assert!(!warns("/bin/sh", &["ash"]));
        assert!(!warns("/bin/ls", &["cat"]));
        // An applet name is not an excuse for any program.
        assert!(warns("/tmp/demo-all", &["ls"]));
        assert!(warns("/bin/busybox", &["evil-tool"]));
    }

    #[test]
    fn interpreters_reached_through_symlinks_are_not_a_mismatch() {
        assert!(!warns("/usr/bin/python3.13", &["python3"]));
        assert!(!warns("/usr/bin/python3", &["python"]));
        assert!(!warns("/usr/bin/python", &["python3.12", "x.py"]));
        assert!(!warns("/usr/bin/dash", &["sh", "-c", "id"]));
        assert!(!warns("/bin/sh", &["bash"]));
        assert!(!warns("/usr/bin/perl5.38.2", &["perl"]));
        assert!(!warns("/usr/bin/mawk", &["awk"]));
        // Different programs of the same letters are still different.
        assert!(warns("/usr/bin/python3", &["perl"]));
    }

    #[test]
    fn a_login_shell_dash_and_a_daemon_title_are_not_a_mismatch() {
        assert!(!warns("/bin/bash", &["-bash"]));
        assert!(!warns("/usr/bin/zsh", &["-zsh"]));
        assert!(!warns(
            "/usr/sbin/nginx",
            &["nginx: master process /usr/sbin/nginx"]
        ));
        assert!(warns("/tmp/x", &["-bash"]));
    }

    #[test]
    fn the_exec_chain_is_file_names_without_repeats() {
        let chain = |images: &[&str]| {
            exec_chain(&images.iter().map(|i| (*i).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(
            chain(&["/bin/sh", "/bin/busybox", "/tmp/demo-all"]),
            "sh \u{2192} busybox \u{2192} demo-all"
        );
        assert_eq!(chain(&["/bin/sh", "/usr/bin/sh"]), "sh");
        assert_eq!(chain(&["/bin/sh", "further exec history omitted"]), "sh");
        assert_eq!(chain(&[]), "");
    }

    #[test]
    fn times_are_relative_to_the_start_of_the_run() {
        assert_eq!(
            relative(Some(2_204_000_000), Some(1_000_000_000)),
            "+1.204 s"
        );
        assert_eq!(
            relative(Some(1_000_000_000), Some(1_000_000_000)),
            "+0.000 s"
        );
        assert_eq!(relative(None, Some(1)), "\u{2014}");
        assert_eq!(relative(Some(5), None), "\u{2014}");
    }

    #[test]
    fn a_lifetime_is_last_minus_first_or_running() {
        assert_eq!(lifetime(Some(0), Some(500_000), true), "500 \u{b5}s");
        assert_eq!(lifetime(Some(0), Some(120_000_000), true), "120 ms");
        assert_eq!(
            lifetime(Some(1_000_000_000), Some(2_204_000_000), true),
            "1.204 s"
        );
        assert_eq!(lifetime(Some(0), Some(125_000_000_000), true), "2 min 5 s");
        assert_eq!(
            lifetime(Some(0), Some(3_720_000_000_000), true),
            "1 h 2 min"
        );
        assert_eq!(lifetime(Some(0), Some(9), false), "running");
        assert_eq!(lifetime(None, None, true), "\u{2014}");
    }

    #[test]
    fn the_outcome_is_cleaned_and_names_a_recorded_sender() {
        assert_eq!(outcome("task exit 0", None, None), "exit 0");
        assert_eq!(outcome("task exit 137", None, None), "exit 137");
        assert_eq!(
            outcome("task exit, killed by SIGKILL", None, None),
            "killed by SIGKILL"
        );
        assert_eq!(
            outcome("task exit, killed by SIGKILL", None, Some(77)),
            "killed by SIGKILL (from pid 77)"
        );
        assert_eq!(
            outcome("task exit, killed by SIGSEGV (core dumped)", None, None),
            "killed by SIGSEGV (core dumped)"
        );
        assert_eq!(
            outcome("exit not recorded", Some("read"), None),
            "in read() at end"
        );
        assert_eq!(outcome("exit not recorded", None, None), "no exit recorded");
        assert_eq!(outcome("task exit 0", None, Some(5)), "exit 0");
    }
}
