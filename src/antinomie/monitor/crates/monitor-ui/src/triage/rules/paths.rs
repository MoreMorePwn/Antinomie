// SPDX-License-Identifier: GPL-3.0-only
//! Rules that read what a call did to a file: the path, and whether it was
//! changed, read, removed or only looked at.
use super::super::file_category::Category as Op;
use super::super::*;
use super::ctx::{base, home_relative, nr, proc_self, under, Ctx, Touch};
use super::state::State;
use super::Hit;

type Matcher = fn(&str) -> bool;

/// Rules for a file that was created, written, cut, or given a name.
const CHANGES: &[(&str, Matcher)] = &[
    ("persistence.at_job", |p| {
        under(
            p,
            &[
                "/var/spool/cron/atjobs",
                "/var/spool/at",
                "/var/spool/atjobs",
            ],
        )
    }),
    ("persistence.cron", |p| {
        p == "/etc/crontab"
            || p == "/etc/anacrontab"
            || under(
                p,
                &[
                    "/etc/cron.d",
                    "/etc/cron.hourly",
                    "/etc/cron.daily",
                    "/etc/cron.weekly",
                    "/etc/cron.monthly",
                    "/etc/cron.yearly",
                    "/var/spool/cron",
                ],
            )
    }),
    ("persistence.systemd", |p| {
        under(
            p,
            &[
                "/etc/systemd/system",
                "/run/systemd/system",
                "/lib/systemd/system",
                "/usr/lib/systemd/system",
                "/etc/systemd/user",
                "/usr/lib/systemd/user",
                "/etc/systemd/system-generators",
                "/usr/lib/systemd/system-generators",
                "/run/systemd/generator",
            ],
        ) || p.contains("/.config/systemd/user")
            || p.contains("/.local/share/systemd/user")
    }),
    ("persistence.rc_init", |p| {
        p == "/etc/rc.local"
            || p == "/etc/inittab"
            || under(p, &["/etc/init.d"])
            || (p.starts_with("/etc/rc") && p.contains(".d/"))
            || (p.starts_with("/etc/init/") && p.ends_with(".conf"))
    }),
    ("persistence.event_script", |p| {
        under(
            p,
            &["/etc/update-motd.d", "/etc/NetworkManager/dispatcher.d"],
        )
    }),
    ("persistence.shell_profile", |p| {
        matches!(
            p,
            "/etc/profile"
                | "/etc/bash.bashrc"
                | "/etc/environment"
                | "/etc/zsh/zshrc"
                | "/etc/zsh/zshenv"
        ) || under(p, &["/etc/profile.d"])
            || matches!(
                base(p),
                ".bashrc"
                    | ".bash_profile"
                    | ".bash_login"
                    | ".bash_logout"
                    | ".profile"
                    | ".zshrc"
                    | ".zshenv"
                    | ".zprofile"
                    | ".zlogin"
            )
    }),
    ("persistence.ssh_authorized_keys", |p| {
        matches!(base(p), "authorized_keys" | "authorized_keys2")
            || p.ends_with("/.ssh/rc")
            || p == "/etc/ssh/sshd_config"
            || under(p, &["/etc/ssh/sshd_config.d"])
    }),
    ("persistence.xdg_autostart", |p| {
        p.contains("/.config/autostart/")
            || under(p, &["/etc/xdg/autostart"])
            || p.contains("/.kde/Autostart/")
            || p.contains("/.kde4/Autostart/")
            || p.contains("/.config/autostart-scripts/")
            || p.contains("/.config/plasma-workspace/env/")
    }),
    ("persistence.udev", |p| {
        under(
            p,
            &[
                "/etc/udev/rules.d",
                "/lib/udev/rules.d",
                "/usr/lib/udev/rules.d",
                "/run/udev/rules.d",
            ],
        )
    }),
    ("persistence.pam", |p| {
        under(p, &["/etc/pam.d", "/etc/security"])
            || (base(p).starts_with("pam_") && base(p).ends_with(".so") && p.contains("/security/"))
    }),
    ("persistence.module_autoload", |p| {
        p == "/etc/modules"
            || under(
                p,
                &[
                    "/etc/modules-load.d",
                    "/etc/modprobe.d",
                    "/usr/lib/modprobe.d",
                    "/lib/modprobe.d",
                    "/usr/lib/modules-load.d",
                    "/run/modules-load.d",
                ],
            )
            || (under(p, &["/lib/modules", "/usr/lib/modules"])
                && (p.ends_with(".ko") || p.contains(".ko.")))
    }),
    ("persistence.apt_hook", |p| {
        under(
            p,
            &[
                "/etc/apt/apt.conf.d",
                "/etc/dpkg/dpkg.cfg.d",
                "/etc/yum/pluginconf.d",
                "/etc/dnf/plugins",
            ],
        ) || p == "/etc/apt/apt.conf"
    }),
    ("persistence.web_shell", |p| {
        under(
            p,
            &[
                "/var/www",
                "/srv/www",
                "/srv/http",
                "/usr/share/nginx",
                "/usr/lib/cgi-bin",
                "/var/lib/tomcat",
                "/opt/tomcat",
            ],
        ) && p.rsplit_once('.').is_some_and(|(_, ext)| {
            matches!(
                ext,
                "php"
                    | "phtml"
                    | "php5"
                    | "php7"
                    | "jsp"
                    | "jspx"
                    | "asp"
                    | "aspx"
                    | "cgi"
                    | "pl"
                    | "py"
            )
        })
    }),
    ("persistence.account", |p| {
        matches!(
            p,
            "/etc/passwd" | "/etc/shadow" | "/etc/group" | "/etc/gshadow"
        )
    }),
    ("injection.ld_so_preload", |p| p == "/etc/ld.so.preload"),
    ("injection.ld_so_conf", |p| {
        p == "/etc/ld.so.conf" || p == "/etc/ld.so.cache" || under(p, &["/etc/ld.so.conf.d"])
    }),
    ("privilege.sudoers", |p| {
        p == "/etc/sudoers" || under(p, &["/etc/sudoers.d"])
    }),
    ("privilege.kernel_helper_hijack", |p| {
        matches!(
            p,
            "/proc/sys/kernel/core_pattern"
                | "/proc/sys/kernel/modprobe"
                | "/proc/sys/kernel/hotplug"
                | "/sys/kernel/uevent_helper"
        ) || (under(p, &["/proc/sys/fs/binfmt_misc"]) && matches!(base(p), "register"))
    }),
    ("evasion.sysctl_security", |p| {
        matches!(
            p,
            "/proc/sys/kernel/randomize_va_space"
                | "/proc/sys/kernel/kptr_restrict"
                | "/proc/sys/kernel/dmesg_restrict"
                | "/proc/sys/kernel/yama/ptrace_scope"
                | "/proc/sys/kernel/unprivileged_bpf_disabled"
        )
    }),
    ("evasion.security_disable", |p| {
        matches!(
            p,
            "/sys/fs/selinux/enforce"
                | "/etc/selinux/config"
                | "/sys/module/apparmor/parameters/enabled"
        )
    }),
    ("evasion.audit_disable", |p| {
        under(p, &["/etc/audit", "/etc/audisp"])
    }),
    ("impact.miner_tuning", |p| {
        p == "/proc/sys/vm/nr_hugepages"
            || under(p, &["/sys/kernel/mm/hugepages"])
            || (p.starts_with("/dev/cpu/") && p.ends_with("/msr"))
    }),
    ("impact.block_device_write", |p| is_block_device(p)),
    ("rootkit.dev_mem", |p| {
        matches!(p, "/dev/mem" | "/dev/kmem" | "/dev/port" | "/proc/kcore")
    }),
];

/// Rules for a file that was opened or read.
const READS: &[(&str, Matcher)] = &[
    ("credential.shadow_read", |p| {
        matches!(
            p,
            "/etc/shadow"
                | "/etc/gshadow"
                | "/etc/security/opasswd"
                | "/etc/shadow-"
                | "/etc/gshadow-"
                | "/etc/master.passwd"
        )
    }),
    ("credential.ssh_keys", |p| {
        home_relative(p).is_some_and(|rest| {
            (rest.starts_with(".ssh/id_") || rest == ".ssh/identity") && !rest.ends_with(".pub")
        }) || (p.starts_with("/etc/ssh/ssh_host_") && p.ends_with("_key"))
    }),
    ("credential.cloud_tokens", |p| {
        home_relative(p).is_some_and(|rest| {
            matches!(
                rest,
                ".aws/credentials"
                    | ".aws/config"
                    | ".kube/config"
                    | ".docker/config.json"
                    | ".git-credentials"
                    | ".netrc"
            ) || rest.starts_with(".config/gcloud/")
                || rest.starts_with(".azure/")
        }) || p.ends_with("/secrets/kubernetes.io/serviceaccount/token")
    }),
    ("credential.browser_store", |p| {
        home_relative(p).is_some_and(|rest| {
            (rest.starts_with(".mozilla/firefox/")
                && matches!(base(rest), "logins.json" | "key4.db" | "signons.sqlite"))
                || ([
                    ".config/google-chrome/",
                    ".config/chromium/",
                    ".config/BraveSoftware/",
                    ".config/microsoft-edge/",
                ]
                .iter()
                .any(|root| rest.starts_with(root))
                    && matches!(base(rest), "Login Data" | "Cookies" | "Local State"))
        })
    }),
    ("credential.wallet", |p| {
        base(p) == "wallet.dat"
            || home_relative(p).is_some_and(|rest| {
                [
                    ".bitcoin/",
                    ".electrum/wallets/",
                    ".ethereum/keystore/",
                    ".config/Exodus/",
                    ".monero/",
                    ".litecoin/",
                    ".zcash/",
                    ".dogecoin/",
                ]
                .iter()
                .any(|root| rest.starts_with(root))
            })
    }),
    ("credential.history_read", |p| {
        matches!(
            base(p),
            ".bash_history"
                | ".zsh_history"
                | ".mysql_history"
                | ".psql_history"
                | ".python_history"
                | ".sh_history"
        )
    }),
    ("credential.kerberos_ccache", |p| {
        p.starts_with("/tmp/krb5cc_")
            || p.starts_with("/var/lib/sss/db/ccache_")
            || base(p).ends_with(".keytab")
    }),
    ("collection.keylog", |p| {
        p.starts_with("/dev/input/event")
            || p == "/dev/uinput"
            || (p.starts_with("/dev/input/by-id/") && p.contains("kbd"))
    }),
    ("collection.screen_capture", |p| p == "/dev/fb0"),
    ("collection.av_capture", |p| {
        p.starts_with("/dev/video") || (p.starts_with("/dev/snd/pcmC") && p.ends_with('c'))
    }),
    ("rootkit.dev_mem", |p| {
        matches!(p, "/dev/mem" | "/dev/kmem" | "/dev/port" | "/proc/kcore")
    }),
];

/// Paths of security agents and policies, probed even when they are absent.
const SECURITY_PATHS: &[&str] = &[
    "/etc/aliyun",
    "/usr/local/aegis",
    "/usr/local/qcloud",
    "/usr/local/cloudmonitor",
    "/opt/CrowdStrike",
    "/opt/sentinelone",
    "/opt/carbonblack",
    "/var/ossec",
    "/etc/wazuh",
    "/etc/falco",
    "/usr/bin/falco",
    "/usr/bin/sysdig",
    "/usr/bin/osqueryd",
    "/usr/bin/clamd",
    "/usr/sbin/clamd",
    "/opt/microsoft/mdatp",
    "/opt/Tanium",
];
/// Operating-system hardening that ordinary tools also look at.
const HARDENING_PATHS: &[&str] = &[
    "/sys/fs/selinux",
    "/etc/selinux",
    "/etc/apparmor.d",
    "/sys/kernel/security/apparmor",
    "/etc/audit",
];

fn is_block_device(path: &str) -> bool {
    let Some(name) = path.strip_prefix("/dev/") else {
        return false;
    };
    [
        "sd", "vd", "hd", "xvd", "nvme", "mmcblk", "mtd", "loop", "dm-",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix) && name.len() > prefix.len() && !name.contains('/'))
}

pub(super) fn rules(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    if cx.touches().is_empty() {
        other_calls(cx, st, out);
        return;
    }
    let mut changed_matched = false;
    for touch in cx.changes() {
        changed_matched |= changed(cx, st, touch, out);
    }
    if cx.ok || cx.failed || cx.ret.is_none() {
        for touch in cx.removes() {
            removed(cx, st, touch, out);
        }
    }
    for touch in cx.reads() {
        read(cx, st, touch, out);
    }
    for touch in cx.looks() {
        super::probes::path(cx, st, touch, out);
        look(cx, st, touch, out);
    }
    for touch in cx.touches() {
        match touch.op {
            Op::Permissions => permissions(cx, touch, out),
            Op::Timestamps => timestamps(cx, st, touch, out),
            Op::Xattrs => xattr(cx, touch, out),
            Op::Mapped => mapped(cx, st, touch, out),
            Op::DirListing => st.listing(cx, &touch.path, out),
            _ => {}
        }
    }
    if !changed_matched {
        fallback(cx, out);
    }
    other_calls(cx, st, out);
}

/// Calls that name no file but still act on one through a descriptor.
fn other_calls(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    match cx.nr {
        // sendfile(out, in), copy_file_range(in, _, out, ...), splice(in, _, out, ...)
        40 | 326 | 275 => {
            let (from, to) = if cx.nr == 40 {
                (cx.args[1], cx.args[0])
            } else {
                (cx.args[0], cx.args[2])
            };
            if let (Some(file), Some(socket)) = (cx.fd_path(from), cx.socket(to)) {
                if file.starts_with('/') && !file.starts_with("/proc/") {
                    let secret = !file_location::classify(file, &[]).is_empty()
                        && file_location::classify(file, &[])
                            .iter()
                            .any(|class| class.flagged());
                    let _ = socket;
                    let mut hit = Hit::new(
                        "exfil.file_to_socket",
                        file,
                        format!("{} sends {file} straight to a socket", cx.name),
                    );
                    if secret {
                        hit = hit
                            .detail("The file is in a persistence, credential or hidden location.");
                    }
                    out.push(hit);
                }
            }
        }
        nr::IOCTL => {
            match cx.args[1] {
                // TIOCSTI
                0x5412 => out.push(Hit::new(
                    "collection.tty_inject",
                    format!("fd {}", cx.args[0]),
                    "ioctl TIOCSTI pushes keystrokes into a terminal".into(),
                )),
                // FS_IOC_SETFLAGS, FS_IOC32_SETFLAGS
                0x4008_6602 | 0x4004_6602 => attributes(cx, out),
                // BLKDISCARD, BLKSECDISCARD, BLKZEROOUT, MEMERASE
                0x1277 | 0x127d | 0x127f | 0x4008_4d02 => {
                    let target = cx
                        .fd_path(cx.args[0])
                        .unwrap_or("a block device")
                        .to_owned();
                    out.push(Hit::new(
                        "impact.block_device_write",
                        &target,
                        format!("ioctl {:#x} wipes or erases {target}", cx.args[1]),
                    ));
                }
                _ => {}
            }
        }
        nr::MOUNT => mount(cx, out),
        _ => {}
    }
    let _ = st;
}

fn mount(cx: &Ctx, out: &mut Vec<Hit>) {
    let target = cx.text(1).unwrap_or_default();
    let bind = cx.args[3] & 4096 != 0;
    let hides = bind
        && (target.starts_with("/proc/")
            && target[6..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit()));
    let hidepid = cx
        .bytes(4, "")
        .is_some_and(|data| String::from_utf8_lossy(data).contains("hidepid"));
    if hides || (hidepid && target == "/proc") {
        out.push(Hit::new(
            "evasion.proc_hide_mount",
            &target,
            format!("mount hides {target} from the process list"),
        ));
    }
}

/// `ioctl(FS_IOC_SETFLAGS)`: the flags word is the pointee of the third argument.
fn attributes(cx: &Ctx, out: &mut Vec<Hit>) {
    let path = cx.fd_path(cx.args[0]).map(str::to_owned);
    let flags = cx
        .bytes(2, "")
        .and_then(|bytes| bytes.get(..4))
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap_or_default()));
    // FS_IMMUTABLE_FL 0x10, FS_APPEND_FL 0x20.
    if flags.is_some_and(|flags| flags & 0x30 == 0) {
        return;
    }
    let guarded = path.as_deref().is_some_and(|path| {
        file_location::classify(path, &[]).iter().any(|class| {
            matches!(
                class,
                file_location::Location::Persistence | file_location::Location::Credentials
            )
        })
    });
    let shown = path.clone().unwrap_or_else(|| format!("fd {}", cx.args[0]));
    let mut hit = Hit::new(
        "evasion.immutable_attr",
        &shown,
        format!("ioctl SETFLAGS on {shown}"),
    );
    if !guarded {
        hit = hit
            .tier(super::Tier::Medium)
            .detail("Not a persistence or credential path: MEDIUM.");
    }
    out.push(hit);
}

/// One file the call changed; true when a specific rule took it.
fn changed(cx: &Ctx, st: &mut State, touch: &Touch, out: &mut Vec<Hit>) -> bool {
    let path = touch.path.as_str();
    let mut matched = false;
    for (rule, matches) in CHANGES {
        if !matches(path) {
            continue;
        }
        // Reading a device or the kernel's memory is the rule; so is opening it.
        if *rule == "impact.block_device_write"
            && !(cx.opens_for_write() || touch.op == Op::Written)
        {
            continue;
        }
        if *rule == "persistence.web_shell" && touch.op != Op::Created && touch.op != Op::Opened {
            continue;
        }
        let verb = match touch.op {
            Op::Created => "creates",
            Op::Written => "writes",
            Op::Truncated => "cuts",
            Op::Renamed => "moves a file onto",
            Op::Linked => "links a file as",
            _ => "opens for writing",
        };
        let mut hit = Hit::new(rule, path, format!("{} {verb} {path}", cx.name));
        if *rule == "persistence.apt_hook" || *rule == "persistence.shell_profile" {
            hit = hit.detail("The command written decides whether this is a backdoor; read the written bytes in Files.");
        }
        out.push(hit);
        matched = true;
    }
    if let Some(hit) = system_file(cx, touch) {
        out.push(hit);
        matched = true;
    }
    if touch.op == Op::Created {
        st.created(cx, path, out);
    }
    if let Some(hit) = hidden_file(cx, touch) {
        out.push(hit);
    }
    if let Some(hit) = proc_mem(cx, touch, true) {
        out.push(hit);
        matched = true;
    }
    if matches!(
        touch.op,
        Op::Created | Op::Written | Op::Truncated | Op::Renamed | Op::Linked
    ) || (touch.op == Op::Opened && cx.opens_for_write())
    {
        super::probes::note_write(cx, st);
    }
    if cx.ok && !via_pseudo(path) {
        st.wrote(cx, path, touch);
    }
    if cx.ok && touch.op == Op::Written {
        elf_into_memfd(cx, st, out);
    }
    matched || history_or_log(cx, touch, out)
}

fn via_pseudo(path: &str) -> bool {
    path.starts_with("/proc/")
        || path.starts_with("/sys/")
        || path.starts_with("/dev/") && !path.starts_with("/dev/shm/")
}

/// A system program or library written over: a trojaned `sshd`, `ps` or library.
fn system_file(cx: &Ctx, touch: &Touch) -> Option<Hit> {
    let path = touch.path.as_str();
    let system = file_location::classify(path, &[]).contains(&file_location::Location::System);
    let noise =
        path.ends_with(".pyc") || path.contains("/__pycache__/") || path.contains("/.cache/");
    if !system
        || noise
        || !matches!(
            touch.op,
            Op::Created | Op::Written | Op::Truncated | Op::Renamed | Op::Linked
        )
    {
        return None;
    }
    Some(Hit::new(
        "persistence.binary_replace",
        path,
        format!("{} changes the system file {path}", cx.name),
    ))
}

/// A hidden file made where nothing hidden belongs.
fn hidden_file(cx: &Ctx, touch: &Touch) -> Option<Hit> {
    if touch.op != Op::Created {
        return None;
    }
    let path = touch.path.as_str();
    let name = base(path);
    let odd = (name.starts_with('.') && name != "." && name != "..")
        && under(
            path,
            &[
                "/tmp",
                "/var/tmp",
                "/dev/shm",
                "/usr/share",
                "/lib",
                "/usr/lib",
                "/lib64",
                "/usr/lib64",
                "/bin",
                "/sbin",
                "/usr/bin",
                "/usr/sbin",
                "/etc",
            ],
        );
    let strange = name.chars().all(|c| c == '.' || c == ' ') && name.len() > 1 || name == " ";
    (odd || strange).then(|| {
        Hit::new(
            "evasion.hidden_artifact",
            path,
            format!("{} creates the hidden entry {path}", cx.name),
        )
    })
}

/// `/proc/PID/mem`: opened for writing (injection) or reading (credential scraping).
fn proc_mem(cx: &Ctx, touch: &Touch, writing: bool) -> Option<Hit> {
    if touch.op != Op::Opened {
        return None;
    }
    let path = proc_self(&touch.path, cx.event.pid);
    let rest = path.strip_prefix("/proc/")?;
    let (who, tail) = rest.split_once('/')?;
    if tail != "mem" {
        return None;
    }
    let own = who == "self";
    if writing && cx.opens_for_write() {
        let mut hit = Hit::new(
            "injection.proc_mem_write",
            &path,
            format!("{} opens {path} for writing", cx.name),
        );
        if own {
            hit = hit
                .tier(super::Tier::Medium)
                .detail("The process's own memory: MEDIUM.");
        }
        return Some(hit);
    }
    (!writing && !own && cx.opens_for_read() && !cx.opens_for_write()).then(|| {
        Hit::new(
            "credential.proc_mem_read",
            &path,
            format!("{} opens {path} for reading", cx.name),
        )
    })
}

/// Deleting or cutting logs and history, and the files a run removes.
fn history_or_log(cx: &Ctx, touch: &Touch, out: &mut Vec<Hit>) -> bool {
    let path = touch.path.as_str();
    let cutting = touch.op == Op::Truncated
        || (touch.op == Op::Opened && cx.open_flags().is_some_and(|flags| flags & 0o1000 != 0));
    let history = matches!(
        base(path),
        ".bash_history"
            | ".zsh_history"
            | ".sh_history"
            | ".mysql_history"
            | ".psql_history"
            | ".python_history"
    );
    if history && cutting {
        out.push(Hit::new(
            "evasion.history_clear",
            path,
            format!("{} empties {path}", cx.name),
        ));
        return true;
    }
    if log_file(path) && cutting {
        out.push(Hit::new(
            "evasion.log_clear",
            path,
            format!("{} empties {path}", cx.name),
        ));
        return true;
    }
    false
}

fn log_file(path: &str) -> bool {
    under(path, &["/var/log", "/run/log/journal"])
        || matches!(
            path,
            "/var/run/utmp" | "/run/utmp" | "/var/run/wtmp" | "/run/wtmp"
        )
}

/// A file deleted or moved away.
fn removed(cx: &Ctx, st: &mut State, touch: &Touch, out: &mut Vec<Hit>) {
    let path = touch.path.as_str();
    let history = matches!(
        base(path),
        ".bash_history"
            | ".zsh_history"
            | ".sh_history"
            | ".mysql_history"
            | ".psql_history"
            | ".python_history"
    );
    if history {
        out.push(Hit::new(
            "evasion.history_clear",
            path,
            format!("{} removes {path}", cx.name),
        ));
    } else if log_file(path) && !path.ends_with('/') {
        out.push(Hit::new(
            "evasion.log_clear",
            path,
            format!("{} removes {path}", cx.name),
        ));
    }
    if under(path, &["/var/backups"]) || path.starts_with("/backup") || path.ends_with(".bak") {
        out.push(Hit::new(
            "impact.inhibit_recovery",
            path,
            format!("{} removes {path}", cx.name),
        ));
    }
    st.removed(cx, path, touch, out);
}

/// A file opened for reading, or read through a descriptor.
fn read(cx: &Ctx, st: &mut State, touch: &Touch, out: &mut Vec<Hit>) {
    let path = touch.path.as_str();
    if touch.op == Op::Opened {
        if let Some(hit) = proc_mem(cx, touch, false) {
            out.push(hit);
        }
    }
    for (rule, matches) in READS {
        if !matches(path) || touch.op == Op::Read && !cx.ok {
            continue;
        }
        if touch.op == Op::Read && *rule != "credential.ssh_keys" {
            continue;
        }
        out.push(Hit::new(rule, path, format!("{} reads {path}", cx.name)));
    }
    if touch.op == Op::Read && cx.ok {
        let bytes = cx.payload(true);
        if bytes.starts_with(b"-----BEGIN")
            && String::from_utf8_lossy(&bytes[..bytes.len().min(80)]).contains("PRIVATE KEY")
        {
            out.push(Hit::new(
                "credential.ssh_keys",
                path,
                format!("read of a private key from {path}"),
            ));
        }
    }
    st.read(cx, path, touch, out);
}

/// Probes for security software, and the classes of discovery reads.
fn look(cx: &Ctx, st: &mut State, touch: &Touch, out: &mut Vec<Hit>) {
    let path = touch.path.as_str();
    if touch.op == Op::Executed {
        return;
    }
    if SECURITY_PATHS.iter().any(|root| under(path, &[root])) {
        out.push(Hit::new(
            "discovery.security_software",
            path,
            format!("{} looks for {path}", cx.name),
        ));
    } else if HARDENING_PATHS.iter().any(|root| under(path, &[root])) && touch.op == Op::Probed {
        out.push(
            Hit::new(
                "discovery.security_software",
                path,
                format!("{} looks for {path}", cx.name),
            )
            .tier(super::Tier::Low)
            .detail("An operating-system hardening path that ordinary programs also look at: LOW."),
        );
    }
    st.discovery(cx, path, touch, out);
}

/// `chmod` and friends: an execute bit in a staging directory, a setuid bit anywhere.
fn permissions(cx: &Ctx, touch: &Touch, out: &mut Vec<Hit>) {
    let Some(mode) = file_category::mode_argument(cx.call, cx.event) else {
        return;
    };
    let path = touch.path.as_str();
    if mode & 0o6000 != 0 {
        let what = if mode & 0o4000 != 0 {
            "setuid"
        } else {
            "setgid"
        };
        out.push(Hit::new(
            "privilege.setid_bit",
            path,
            format!("{} sets the {what} bit on {path}", cx.name),
        ));
    }
    if mode & 0o111 != 0 {
        let classes = file_location::classify(path, &[]);
        if classes.contains(&file_location::Location::Temp)
            || classes.contains(&file_location::Location::Hidden)
            || path.starts_with("/run/user/")
        {
            out.push(Hit::new(
                "execution.chmod_exec_temp",
                path,
                format!("{} makes {path} executable ({mode:o})", cx.name),
            ));
        }
    }
}

/// Times set on purpose, not to "now".
fn timestamps(cx: &Ctx, st: &mut State, touch: &Touch, out: &mut Vec<Hit>) {
    let explicit = match cx.nr {
        // utime(path, times), utimes(path, times)
        132 | 235 => cx.args[1] != 0,
        // utimensat(dirfd, path, times, flags), futimesat(dirfd, path, times)
        280 | 261 => cx.args[2] != 0,
        _ => false,
    };
    // UTIME_NOW and UTIME_OMIT in both nanosecond fields are not a chosen time.
    let now = cx.bytes(2, "").is_some_and(|bytes| {
        bytes.len() >= 32
            && [8usize, 24].iter().all(|at| {
                let nanos = u64::from_le_bytes(bytes[*at..*at + 8].try_into().unwrap_or_default());
                nanos == 0x3fff_ffff || nanos == 0x3fff_fffe
            })
    });
    if explicit && !now {
        let path = touch.path.as_str();
        out.push(Hit::new(
            "evasion.timestomp",
            path,
            format!("{} sets chosen times on {path}", cx.name),
        ));
    }
    let _ = st;
}

/// `setxattr` of a file capability.
fn xattr(cx: &Ctx, touch: &Touch, out: &mut Vec<Hit>) {
    let name = cx.text(1).unwrap_or_default();
    if name == "security.capability" {
        out.push(Hit::new(
            "privilege.setid_bit",
            &touch.path,
            format!("{} sets a file capability on {}", cx.name, touch.path),
        ));
    }
}

/// An executable mapping of a file the run wrote.
fn mapped(cx: &Ctx, st: &State, touch: &Touch, out: &mut Vec<Hit>) {
    if cx.args[2] & 4 != 0 && cx.nr == nr::MMAP && st.written.contains(&touch.path) {
        out.push(Hit::new(
            "execution.dropped_library",
            &touch.path,
            format!(
                "{} maps {} executable; the run wrote it",
                cx.name, touch.path
            ),
        ));
    }
}

/// A write of ELF bytes into a memfd.
fn elf_into_memfd(cx: &Ctx, _st: &State, out: &mut Vec<Hit>) {
    let Some(fd) = cx
        .fd_path(cx.args[0])
        .filter(|path| path.starts_with("memfd:"))
    else {
        return;
    };
    if cx.payload(false).starts_with(b"\x7fELF") {
        out.push(Hit::new(
            "execution.memfd_elf",
            fd,
            format!("{} writes an ELF image into {fd}", cx.name),
        ));
    }
}

/// Persistence-class writes that no specific rule took.
fn fallback(cx: &Ctx, out: &mut Vec<Hit>) {
    for touch in cx.changes() {
        let path = touch.path.as_str();
        if via_pseudo(path) {
            continue;
        }
        let place = file_location::classify(path, &[]);
        let configuration = place.contains(&file_location::Location::Persistence)
            || path.starts_with("/etc/")
            || path.starts_with("/root/.ssh/")
            || path.contains("/.ssh/")
            || path.contains("/.config/");
        let already = out
            .iter()
            .any(|hit| hit.rule.starts_with("persistence.") && hit.object == path);
        if configuration && !already {
            out.push(Hit::new(
                "persistence.config_write",
                path,
                format!("{} changes {path}", cx.name),
            ));
        }
    }
}
