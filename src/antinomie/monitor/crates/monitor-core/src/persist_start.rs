// SPDX-License-Identifier: GPL-3.0-only
//! Start what a run persisted when its tree ends early (ANT-T0608).
//!
//! Malware that installs persistence (an init script, a systemd unit, a cron
//! line, a shell profile) and then exits waits for a boot, a login or a
//! service start that never comes in a sandbox, so its second stage is never
//! seen. With the option on, when the run's tree ends well before its run
//! time and the run wrote such entries, the host starts them, the way a boot
//! or a login would, inside the same run:
//!
//! * The entries come from the live Triage rules (`persistence.*` with the
//!   path they name, [`Written`]); only paths the run wrote or changed, and
//!   only writes that did not all fail.
//! * [`select`] turns them into at most [`MAX_ENTRIES`] [`Entry`]s, in boot
//!   order: systemd units, init scripts and `rc.local`, cron, a login shell
//!   per user for the profiles, XDG autostart.
//! * Each entry is started by one EXEC of `/bin/sh -c` [`script`] as the
//!   entry's user, with the guest's shell-job shape (parent init: outside the
//!   original tree). Nothing new is asked of the guest. The starter's
//!   telemetry is folded into the run's own recording, so the second stage is
//!   recorded, judged and dumped like the first.
//! * The run is held open ([`PersistenceStart::holding`]) until every
//!   started tree ended, Stop (sent by Auto and `run exec` at the run time),
//!   the VM stops, or, for a run without a run time, [`HOLD_MAX`].
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Entries started per run at most; more are counted.
pub const MAX_ENTRIES: usize = 8;
/// A tree that ends closer than this to the run time is not followed by a
/// start: the run would end before anything could be seen.
pub const MARGIN: Duration = Duration::from_secs(30);
/// How long the next entry waits for the previous starter to return.
pub const ENTRY_WAIT: Duration = Duration::from_secs(20);
/// The hold of a run that has no run time (the desktop).
pub const HOLD_MAX: Duration = Duration::from_secs(600);
/// How long after the tree's end the entries are chosen: the last calls of
/// the tree are judged first.
pub const DECIDE_AFTER: Duration = Duration::from_secs(2);
/// How often a live starter's status is read.
pub const POLL: Duration = Duration::from_secs(1);
/// Cron lines one crontab starts at most.
const CRON_LINES_MAX: usize = 8;

/// Starter exit codes for what the script found (above any shell's own).
pub const EXIT_GONE: i32 = 120;
pub const EXIT_NO_COMMAND: i32 = 121;
pub const EXIT_LAUNCHED: i32 = 122;

/// The option, as a launch carries it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StartPersistence {
    /// The run time a front end stops the run at, seconds; `None` (the
    /// desktop) has none, and the hold then lasts at most [`HOLD_MAX`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_limit_s: Option<u32>,
}

/// A `persistence.*` row of the live rules with the path it names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Written {
    pub rule: String,
    pub path: String,
    /// Every call of the row failed (a write that was refused).
    pub failed: bool,
    pub pid: u32,
}

/// What kind of entry was started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A systemd `.service` unit: its `ExecStart=` command.
    #[default]
    Systemd,
    /// An init.d or rc.d script: `<script> start`.
    InitScript,
    /// `rc.local`: `<script> start`.
    RcLocal,
    /// A crontab: its job lines.
    Cron,
    /// A script in `/etc/cron.{hourly,daily,weekly,monthly}`.
    CronScript,
    /// Shell profiles: a login shell of their user.
    Login,
    /// An XDG autostart `.desktop` file: its `Exec=` command.
    Autostart,
}

impl EntryKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Systemd => "systemd unit",
            Self::InitScript => "init script",
            Self::RcLocal => "rc.local",
            Self::Cron => "crontab",
            Self::CronScript => "cron script",
            Self::Login => "shell profile",
            Self::Autostart => "autostart entry",
        }
    }
}

/// One entry to start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    /// The file the entry is (for a login, the first profile).
    pub path: String,
    /// A login's profile files, in the order the run wrote them.
    pub files: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    /// A crontab with a user field (`/etc/crontab`, `/etc/cron.d`).
    pub system_crontab: bool,
    /// A login through zsh (a zsh file was written).
    pub zsh: bool,
}

impl Entry {
    /// What is started, in words: `/etc/init.d/x start`.
    pub fn command(&self) -> String {
        match self.kind {
            EntryKind::Systemd => format!("ExecStart of {}", self.path),
            EntryKind::InitScript | EntryKind::RcLocal => format!("{} start", self.path),
            EntryKind::Cron => format!("the job lines of {}", self.path),
            EntryKind::CronScript => self.path.clone(),
            EntryKind::Login => format!(
                "a login shell ({}) reading {}",
                if self.zsh { "zsh" } else { "bash, or sh" },
                self.files.join(", ")
            ),
            EntryKind::Autostart => format!("Exec of {}", self.path),
        }
    }

    /// The account in words: `root`, `uid 1000`.
    pub fn who(&self) -> String {
        if self.uid == 0 {
            "root".into()
        } else {
            format!("uid {}", self.uid)
        }
    }
}

/// What `run.json` keeps (`persistence_start`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistenceStart {
    /// From the launch to the end of the run's tree, milliseconds.
    pub tree_ended_after_ms: u64,
    pub entries: Vec<StartedEntry>,
    /// Entries over [`MAX_ENTRIES`], not started.
    pub more: u32,
    /// The run is held open while what was started runs.
    pub holding: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_started_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_ended: Option<String>,
    /// Why nothing was started, when nothing was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_started: Option<String>,
}

/// One entry started by Antinomie, as `run.json` keeps it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StartedEntry {
    pub kind: EntryKind,
    pub path: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    pub command: String,
    pub uid: u32,
    /// Always "started by Antinomie (persistence)": the processes of this
    /// entry are the app's start, not the program's.
    pub started_by: String,
    /// The starter's process id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// The starter's root task cookie (its processes in the recording).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_cookie: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_ms: Option<u64>,
    /// How the starter's own process ended, in words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned: Option<String>,
    /// Every process the entry started has ended.
    pub ended: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The mark every started entry carries.
pub const STARTED_BY: &str = "started by Antinomie (persistence)";

impl StartedEntry {
    pub fn of(entry: &Entry) -> Self {
        Self {
            kind: entry.kind,
            path: entry.path.clone(),
            files: if entry.kind == EntryKind::Login {
                entry.files.clone()
            } else {
                Vec::new()
            },
            command: entry.command(),
            uid: entry.uid,
            started_by: STARTED_BY.into(),
            ..Self::default()
        }
    }
}

/// What the starter's root exit code says, for the codes the script uses.
pub fn returned_words(code: i32) -> String {
    match code {
        EXIT_GONE => "the file was no longer there".into(),
        EXIT_NO_COMMAND => "the file named no command to start".into(),
        EXIT_LAUNCHED => {
            "its command runs the launched program itself, which is not started again".into()
        }
        code => format!("returned {code}"),
    }
}

fn under(path: &str, dirs: &[&str]) -> bool {
    dirs.iter().any(|dir| {
        path.strip_prefix(dir)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|rest| !rest.is_empty())
    })
}

fn base(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A name an editor or a tool leaves for a moment (`crontab`'s temporary
/// table, a backup), not an entry.
fn temporary(name: &str) -> bool {
    name.is_empty()
        || name.starts_with("tmp.")
        || name.starts_with('#')
        || name.starts_with(".#")
        || name.ends_with('~')
        || name.ends_with(".swp")
        || name.contains(".dpkg-")
        || name.ends_with(".bak")
        // BusyBox crond's note that a table changed, not a table.
        || name == "cron.update"
}

const SYSTEM_UNITS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
];
const USER_UNITS: &[&str] = &["/etc/systemd/user", "/usr/lib/systemd/user"];
const CRON_SCRIPTS: &[&str] = &[
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];
const PROFILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zlogin",
];

/// The startable kind of a written path, and whether it is a user's (run as
/// a user rather than root).
pub fn classify(path: &str) -> Option<(EntryKind, bool)> {
    if !path.starts_with('/') || path.contains("/../") || path.contains("/./") {
        return None;
    }
    let name = base(path);
    if temporary(name) {
        return None;
    }
    let user_unit = under(path, USER_UNITS)
        || path.contains("/.config/systemd/user/")
        || path.contains("/.local/share/systemd/user/");
    if (under(path, SYSTEM_UNITS) || user_unit) && name.ends_with(".service") && !name.contains('@')
    {
        return Some((EntryKind::Systemd, user_unit));
    }
    if path == "/etc/rc.local" || path == "/etc/rc.d/rc.local" {
        return Some((EntryKind::RcLocal, false));
    }
    if under(path, &["/etc/init.d", "/etc/rc.d/init.d"]) && !name.ends_with(".conf") {
        return Some((EntryKind::InitScript, false));
    }
    // rcN.d start links (S20name); the K links stop a service.
    if let Some(dir) = path
        .strip_prefix("/etc/rc.d/")
        .or_else(|| path.strip_prefix("/etc/"))
        .and_then(|rest| rest.split('/').next())
        && dir.starts_with("rc")
        && dir.ends_with(".d")
        && dir.len() == 5
        && path.matches('/').count() == if path.starts_with("/etc/rc.d/") { 4 } else { 3 }
    {
        return name
            .strip_prefix('S')
            .is_some_and(|rest| rest.len() > 2 && rest[..2].bytes().all(|b| b.is_ascii_digit()))
            .then_some((EntryKind::InitScript, false));
    }
    if path == "/etc/crontab" || under(path, &["/etc/cron.d"]) {
        return Some((EntryKind::Cron, false));
    }
    // A user's table: /var/spool/cron/crontabs/<user> (Debian, BusyBox),
    // /var/spool/cron/tabs/<user> (SUSE), /var/spool/cron/<user> (cronie).
    let spool_user = path.strip_prefix("/var/spool/cron/").and_then(|rest| {
        let rest = rest
            .strip_prefix("crontabs/")
            .or_else(|| rest.strip_prefix("tabs/"))
            .unwrap_or(rest);
        (!rest.contains('/')
            && !matches!(rest, "crontabs" | "tabs" | "atjobs" | "atspool" | "lastrun"))
        .then_some(rest)
    });
    if let Some(user) = spool_user {
        return Some((EntryKind::Cron, user != "root"));
    }
    if under(path, CRON_SCRIPTS) && path.matches('/').count() == 3 {
        return Some((EntryKind::CronScript, false));
    }
    if PROFILES.contains(&name)
        || matches!(
            path,
            "/etc/profile" | "/etc/bash.bashrc" | "/etc/zsh/zshrc" | "/etc/zsh/zprofile"
        )
        || (under(path, &["/etc/profile.d"]) && path.matches('/').count() == 3)
    {
        return Some((EntryKind::Login, true));
    }
    if (under(path, &["/etc/xdg/autostart"]) || path.contains("/.config/autostart/"))
        && name.ends_with(".desktop")
    {
        return Some((EntryKind::Autostart, true));
    }
    None
}

/// The account a user's entry at `path` runs as: its home's owner as far as
/// the path says, else the run's.
fn account(path: &str, run: (u32, u32, &str)) -> (u32, u32, String) {
    let (uid, gid, home) = run;
    if path.starts_with("/root/") {
        return (0, 0, "/root".into());
    }
    if let Some(rest) = path.strip_prefix("/home/")
        && let Some(user) = rest.split('/').next()
        && !user.is_empty()
        && rest.len() > user.len()
    {
        let home = format!("/home/{user}");
        // A run as root that wrote into a user's home: the guest's normal
        // user (1000) is the one who logs in there.
        return if uid == 0 {
            (1000, 1000, home)
        } else {
            (uid, gid, home)
        };
    }
    (uid, gid, home.to_owned())
}

/// The run's own home: its `HOME`, else root's or the normal user's.
pub fn run_home(uid: u32, env: &[String]) -> String {
    env.iter()
        .find_map(|item| item.strip_prefix("HOME="))
        .filter(|home| home.starts_with('/'))
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if uid == 0 {
                "/root".into()
            } else {
                "/home/user".into()
            }
        })
}

/// Choose the entries to start from what the live rules saw, in boot order,
/// each once. `run` is the run's uid, gid and home. Returns the entries and
/// how many more there were.
pub fn select(written: &[Written], run: (u32, u32, &str)) -> (Vec<Entry>, u32) {
    // A path counts when one of its rows did not all fail.
    let mut paths: Vec<&str> = Vec::new();
    for row in written {
        if !row.rule.starts_with("persistence.") || row.failed {
            continue;
        }
        if !paths.contains(&row.path.as_str()) {
            paths.push(&row.path);
        }
    }
    let mut entries: Vec<Entry> = Vec::new();
    for path in &paths {
        let Some((kind, users)) = classify(path) else {
            continue;
        };
        let (uid, gid, home) = if users {
            match kind {
                // A user crontab of root, or any other user's.
                EntryKind::Cron if base(path) != "root" && run.0 == 0 => {
                    (1000, 1000, "/home/user".to_owned())
                }
                EntryKind::Cron => (run.0, run.1, run.2.to_owned()),
                _ => account(path, run),
            }
        } else {
            (0, 0, "/root".to_owned())
        };
        let entry = Entry {
            kind,
            path: (*path).to_owned(),
            files: vec![(*path).to_owned()],
            uid,
            gid,
            home,
            system_crontab: kind == EntryKind::Cron && !path.starts_with("/var/spool/"),
            zsh: base(path).starts_with(".z") || path.starts_with("/etc/zsh/"),
        };
        match kind {
            // One unit per name: a `*.wants/` link and its unit are one.
            EntryKind::Systemd => {
                if let Some(other) = entries.iter_mut().find(|other| {
                    other.kind == EntryKind::Systemd && base(&other.path) == base(path)
                }) {
                    if other.path.contains(".wants/") && !path.contains(".wants/") {
                        *other = entry;
                    }
                    continue;
                }
            }
            // An rcN.d link and its init.d script are one script.
            EntryKind::InitScript => {
                let script = init_name(path);
                if let Some(other) = entries.iter_mut().find(|other| {
                    other.kind == EntryKind::InitScript && init_name(&other.path) == script
                }) {
                    if is_rc_link(&other.path) && !is_rc_link(path) {
                        *other = entry;
                    }
                    continue;
                }
            }
            // One login per account reads every profile written for it.
            EntryKind::Login => {
                if let Some(other) = entries.iter_mut().find(|other| {
                    other.kind == EntryKind::Login && other.uid == uid && other.home == entry.home
                }) {
                    other.files.push(entry.path);
                    other.zsh |= entry.zsh;
                    continue;
                }
            }
            _ => {}
        }
        entries.push(entry);
    }
    entries.sort_by_key(|entry| match entry.kind {
        EntryKind::Systemd => 0,
        EntryKind::InitScript | EntryKind::RcLocal => 1,
        EntryKind::Cron | EntryKind::CronScript => 2,
        EntryKind::Login => 3,
        EntryKind::Autostart => 4,
    });
    let more = entries.len().saturating_sub(MAX_ENTRIES) as u32;
    entries.truncate(MAX_ENTRIES);
    (entries, more)
}

fn is_rc_link(path: &str) -> bool {
    !path.contains("/init.d/")
}

/// The script name of an init entry: `S20foo` is `foo`.
fn init_name(path: &str) -> &str {
    let name = base(path);
    if is_rc_link(path)
        && let Some(rest) = name.strip_prefix('S')
        && rest.len() > 2
        && rest[..2].bytes().all(|b| b.is_ascii_digit())
    {
        return &rest[2..];
    }
    name
}

/// `text` as one shell word.
pub fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Leave a command whose program is the launched one.
fn launched_check(launched: &str) -> String {
    format!(
        "set -f; set -- $cmd; set +f; [ \"$1\" = {} ] && exit {EXIT_LAUNCHED}\n",
        quote(launched)
    )
}

/// The starter's script for `entry` (run by `/bin/sh -c`). `launched` is the
/// path of the run's own program, which is never started again by itself.
/// POSIX sh and BusyBox tools only; nothing in it names the app.
pub fn script(entry: &Entry, launched: &str) -> String {
    let file = quote(&entry.path);
    let mut text = String::from("exec </dev/null >/dev/null 2>&1\n");
    match entry.kind {
        EntryKind::Systemd => {
            text.push_str(&format!("f={file}\n[ -r \"$f\" ] || exit {EXIT_GONE}\n"));
            text.push_str(
                "cmd=$(sed -n 's/^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*//p' \"$f\" | sed '/^$/d' | head -n 1 | sed 's/^[-@:+!]*//')\n",
            );
            text.push_str(&format!("[ -n \"$cmd\" ] || exit {EXIT_NO_COMMAND}\n"));
            text.push_str(&launched_check(launched));
            text.push_str(
                "dir=$(sed -n 's/^[[:space:]]*WorkingDirectory[[:space:]]*=[[:space:]]*-*//p' \"$f\" | head -n 1)\n",
            );
            text.push_str(
                "case \"$dir\" in /*) cd \"$dir\" 2>/dev/null || cd / ;; *) cd / ;; esac\n",
            );
            text.push_str("exec /bin/sh -c \"$cmd\"\n");
        }
        EntryKind::InitScript | EntryKind::RcLocal | EntryKind::CronScript => {
            let start = if entry.kind == EntryKind::CronScript {
                ""
            } else {
                " start"
            };
            text.push_str(&format!(
                "f={file}\n[ -e \"$f\" ] || exit {EXIT_GONE}\ncd /\n"
            ));
            text.push_str(&format!("[ -x \"$f\" ] && exec \"$f\"{start}\n"));
            text.push_str(&format!("exec /bin/sh \"$f\"{start}\n"));
        }
        EntryKind::Cron => {
            text.push_str(&format!("f={file}\n[ -r \"$f\" ] || exit {EXIT_GONE}\n"));
            text.push_str("cd \"$HOME\" 2>/dev/null || cd /\nn=0\nset -f\n");
            text.push_str("while IFS= read -r line || [ -n \"$line\" ]; do\n");
            text.push_str("  set -- $line\n  [ $# -gt 0 ] || continue\n");
            text.push_str("  case \"$1\" in\n    '#'*) continue ;;\n    @*) shift ;;\n    *=*) continue ;;\n    *) [ $# -gt 5 ] || continue; shift 5 ;;\n  esac\n");
            if entry.system_crontab {
                text.push_str("  [ $# -gt 1 ] || continue\n  shift\n");
            }
            text.push_str("  [ $# -gt 0 ] || continue\n");
            text.push_str("  case \" $* \" in *' run-parts '*) continue ;; esac\n");
            text.push_str(&format!("  [ \"$1\" = {} ] && continue\n", quote(launched)));
            text.push_str("  /bin/sh -c \"$*\" &\n  n=$((n+1))\n");
            text.push_str(&format!("  [ $n -lt {CRON_LINES_MAX} ] || break\n"));
            text.push_str("done < \"$f\"\n");
            text.push_str(&format!("[ $n -gt 0 ] || exit {EXIT_NO_COMMAND}\nexit 0\n"));
        }
        EntryKind::Login => {
            text.push_str("cd \"$HOME\" 2>/dev/null || cd /\n");
            if entry.zsh {
                text.push_str("command -v zsh >/dev/null 2>&1 && exec zsh -l -i -c 'exit 0'\n");
            }
            text.push_str("command -v bash >/dev/null 2>&1 && exec bash -l -i -c 'exit 0'\n");
            text.push_str("exec /bin/sh -l -c 'exit 0'\n");
        }
        EntryKind::Autostart => {
            text.push_str(&format!("f={file}\n[ -r \"$f\" ] || exit {EXIT_GONE}\n"));
            text.push_str(
                "cmd=$(sed -n 's/^Exec[[:space:]]*=[[:space:]]*//p' \"$f\" | head -n 1 | sed 's/%[fFuUdDnNickvm]//g')\n",
            );
            text.push_str(&format!("[ -n \"$cmd\" ] || exit {EXIT_NO_COMMAND}\n"));
            text.push_str(&launched_check(launched));
            text.push_str("cd \"$HOME\" 2>/dev/null || cd /\nexec /bin/sh -c \"$cmd\"\n");
        }
    }
    text
}

/// The environment of a starter: what a boot or a login gives.
pub fn environment(entry: &Entry) -> Vec<String> {
    let user = if entry.uid == 0 {
        "root".to_owned()
    } else {
        base(&entry.home).to_owned()
    };
    let mut env = vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
        format!("HOME={}", entry.home),
        format!("USER={user}"),
        format!("LOGNAME={user}"),
        "SHELL=/bin/sh".to_owned(),
        "LANG=C.UTF-8".to_owned(),
    ];
    if entry.kind == EntryKind::Login {
        env.push("TERM=xterm".to_owned());
    } else {
        // Debian's LSB functions would hand `<script> start` to systemd,
        // which starts the service outside anything the guest traces.
        env.push("_SYSTEMCTL_SKIP_REDIRECT=1".to_owned());
        env.push("SYSTEMCTL_SKIP_REDIRECT=1".to_owned());
    }
    env
}

/// Whether the entries may be started now: `None` when they may, else why
/// not, in the words of the run's notes. `elapsed` is from the launch to the
/// tree's end.
pub fn refusal(
    option: Option<&StartPersistence>,
    elapsed: Duration,
    stopped: bool,
    judged: bool,
) -> Option<String> {
    let after = elapsed_words(elapsed);
    if stopped {
        return Some(format!("the run was stopped after {after}"));
    }
    let Some(option) = option else {
        return Some(format!(
            "the tree ended after {after}; persistence installed but not started (option off)"
        ));
    };
    if !judged {
        return Some(format!(
            "the tree ended after {after}; persistence may have been installed, but this build has no live Triage rules to find it"
        ));
    }
    if let Some(limit) = option.run_limit_s
        && elapsed + MARGIN > Duration::from_secs(u64::from(limit))
    {
        return Some(format!(
            "the tree ended after {after}, less than {} s before the run time ({limit} s); persistence installed but not started",
            MARGIN.as_secs()
        ));
    }
    None
}

/// `12 s`, `3 min 4 s`.
pub fn elapsed_words(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{secs} s")
    } else if secs.is_multiple_of(60) {
        format!("{} min", secs / 60)
    } else {
        format!("{} min {} s", secs / 60, secs % 60)
    }
}

/// The note said when the entries are started.
pub fn started_note(record: &PersistenceStart) -> String {
    let list: Vec<String> = record
        .entries
        .iter()
        .map(|entry| {
            let who = if entry.uid == 0 {
                "root".to_owned()
            } else {
                format!("uid {}", entry.uid)
            };
            format!("{} as {who}", entry.command)
        })
        .collect();
    let more = if record.more > 0 {
        format!(" ({} more not started)", record.more)
    } else {
        String::new()
    };
    format!(
        "The run's tree ended after {} having installed persistence; {}, as a boot or login would, and the run is held open until they end or the run is stopped: {}{more}.",
        elapsed_words(Duration::from_millis(record.tree_ended_after_ms)),
        capitalized_started_by(),
        list.join("; ")
    )
}

fn capitalized_started_by() -> &'static str {
    "these were started by Antinomie (persistence)"
}

/// The report's note: what was started, each entry marked, or why nothing
/// was. `None` for a run whose record says neither.
pub fn report_note(record: &PersistenceStart) -> Option<String> {
    if record.entries.is_empty() {
        return record.not_started.as_deref().map(not_started_note);
    }
    let list: Vec<String> = record
        .entries
        .iter()
        .map(|entry| {
            let who = if entry.uid == 0 {
                "root".to_owned()
            } else {
                format!("uid {}", entry.uid)
            };
            let how = match (&entry.pid, &entry.error) {
                (_, Some(error)) => error.clone(),
                (Some(pid), None) => format!(
                    "pid {pid}{}",
                    entry
                        .returned
                        .as_deref()
                        .map(|words| format!(", {words}"))
                        .unwrap_or_default()
                ),
                (None, None) => "not reached before the run ended".into(),
            };
            format!("{} as {who} ({how})", entry.command)
        })
        .collect();
    Some(format!(
        "The program's tree ended after {} having installed persistence. Each entry below was {STARTED_BY}, as a boot or login would, and what it ran is part of this recording: {}.",
        elapsed_words(Duration::from_millis(record.tree_ended_after_ms)),
        list.join("; ")
    ))
}

/// The note of a run that installed persistence but had nothing started.
pub fn not_started_note(reason: &str) -> String {
    let mut chars = reason.chars();
    let first = chars.next().map(|c| c.to_uppercase().collect::<String>());
    format!("{}{}.", first.unwrap_or_default(), chars.as_str())
}

/// The live part of a run's start of its persistence; nothing of it is saved.
#[derive(Default)]
pub(crate) struct Live {
    /// When the guest said the run's tree ended.
    pub(crate) tree_ended: Option<std::time::Instant>,
    /// The entries were chosen (or the run was stopped first).
    pub(crate) decided: bool,
    /// Entries still to start, with their place in the record.
    pub(crate) plan: std::collections::VecDeque<(usize, Entry)>,
    pub(crate) starters: Vec<Starter>,
    /// When the hold for the started entries began.
    pub(crate) hold_since: Option<std::time::Instant>,
}

/// One started entry's EXEC, followed by its root task cookie.
pub(crate) struct Starter {
    pub(crate) cookie: u64,
    /// Its place in [`PersistenceStart::entries`].
    pub(crate) index: usize,
    pub(crate) launched: std::time::Instant,
    pub(crate) generation: u64,
    pub(crate) last_poll: Option<std::time::Instant>,
    /// The starter's own process returned.
    pub(crate) returned: bool,
    /// Every process of the starter's tree ended.
    pub(crate) ended: bool,
    pub(crate) stop_sent: bool,
}

impl Live {
    /// A started tree still runs, as far as the host knows.
    pub(crate) fn any_live(&self) -> bool {
        self.starters.iter().any(|starter| !starter.ended)
    }

    /// The next entry may be started: none is waiting for its starter.
    pub(crate) fn next_due(&self) -> bool {
        !self.plan.is_empty()
            && self.starters.last().is_none_or(|last| {
                last.returned || last.ended || last.launched.elapsed() >= ENTRY_WAIT
            })
    }
}

/// How a starter's root process ended, in words.
pub fn wait_words(status: crate::api::WaitStatus) -> String {
    match status {
        crate::api::WaitStatus::Exited { code } => returned_words(i32::from(code)),
        crate::api::WaitStatus::Signaled { signal, .. } => format!("ended by signal {signal}"),
    }
}

#[cfg(test)]
mod tests;
