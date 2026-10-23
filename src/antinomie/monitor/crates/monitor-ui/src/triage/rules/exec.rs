// SPDX-License-Identifier: GPL-3.0-only
//! Rules that read an exec: the program, its arguments and its environment.
//!
//! A shell started with `-c` is read command by command, so `sh -c 'iptables
//! -F; crontab -'` is judged as the two programs it runs.
use super::super::*;
use super::ctx::{base, nr, Ctx};
use super::state::State;
use super::tools::{self, Command};
use super::Hit;

pub(super) fn rules(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    if !cx.is_exec() {
        return;
    }
    // An execveat on a descriptor names no path.
    let Some(path) = cx
        .exec_path()
        .or_else(|| (cx.nr == nr::EXECVEAT).then(|| format!("descriptor {}", cx.args[0])))
    else {
        return;
    };
    let argv = cx.argv();
    let name = base(&path).to_owned();
    let line = if argv.len() > 1 {
        format!("{path} {}", argv[1..].join(" "))
    } else {
        path.clone()
    };
    out.push(Hit::new("process.exec", &line, short(&line)));
    interpreter(cx, &path, &name, &line, out);
    in_memory(cx, &path, out);
    dropped(cx, st, &path, out);
    staging(st, &path, out);
    environment(cx, out);
    if name == "pkexec"
        && (empty_argv(cx) || cx.envp().iter().any(|var| var.starts_with("GCONV_PATH=")))
    {
        out.push(
            Hit::new(
                "privilege.pwnkit",
                &path,
                "pkexec started with no arguments".into(),
            )
            .detail("CVE-2021-4034: pkexec reads past the end of an empty argument vector."),
        );
    }
    let first = Command::new(argv.iter().map(String::as_str).collect());
    commands(cx, st, &first, false, out);
    if tools::is_shell(&name) || name == "busybox" {
        if let Some(script) = tools::shell_script(&first) {
            cradle(&script, out);
            for segment in tools::segments(&script) {
                commands(cx, st, &Command::from_words(&segment), true, out);
            }
        }
    }
}

fn short(text: &str) -> String {
    let mut shown: String = text.chars().take(200).collect();
    if text.chars().count() > 200 {
        shown.push('…');
    }
    shown
}

/// `argc == 0`: the first pointer of the vector is NULL.
fn empty_argv(cx: &Ctx) -> bool {
    let argument = if cx.nr == nr::EXECVE { 1 } else { 2 };
    let key = format!("arg{argument}.ptr[0]");
    cx.call
        .entry
        .iter()
        .chain(cx.call.exit.iter())
        .flat_map(|event| &event.fields)
        .find(|field| field.key == key)
        .is_some_and(|field| trace::covered_preview(field).iter().all(|byte| *byte == 0))
}

fn interpreter(cx: &Ctx, path: &str, name: &str, line: &str, out: &mut Vec<Hit>) {
    let scripted = kernel_records::exec_image(cx.call)
        .and_then(|image| image.interpreter)
        .map(|text| {
            let mut words = text.split_whitespace();
            let first = words.next().unwrap_or_default().to_owned();
            if base(&first) == "env" {
                words.next().map(str::to_owned).unwrap_or(first)
            } else {
                first
            }
        });
    let applet = (name == "busybox")
        .then(|| cx.argv().get(1).map(|applet| base(applet).to_owned()))
        .flatten();
    let chosen = [
        Some(name.to_owned()),
        scripted.as_deref().map(|text| base(text).to_owned()),
        applet,
    ]
    .into_iter()
    .flatten()
    .find_map(|candidate| tools::interpreter(&candidate).map(|attack| (candidate, attack)));
    if let Some((which, attack)) = chosen {
        let via = if which == name {
            String::new()
        } else {
            format!(" (named by {path})")
        };
        out.push(
            Hit::new(
                "process.interpreter",
                path,
                format!("{which}{via}: {}", short(line)),
            )
            .attack(attack),
        );
    }
}

/// The descriptor an exec path names, and the pid when it is not the caller's.
fn descriptor_path(path: &str, own: u32) -> Option<(u64, Option<u32>)> {
    if let Some(rest) = path.strip_prefix("/dev/fd/") {
        return rest.parse().ok().map(|fd| (fd, None));
    }
    let rest = path.strip_prefix("/proc/")?;
    let (who, rest) = rest.split_once("/fd/")?;
    let fd = rest.parse().ok()?;
    match who {
        "self" | "thread-self" => Some((fd, None)),
        pid => {
            let pid: u32 = pid.parse().ok()?;
            Some((fd, (pid != own).then_some(pid)))
        }
    }
}

/// Exec of a file that has no name on disk: a memfd, a deleted or unnamed file.
fn in_memory(cx: &Ctx, path: &str, out: &mut Vec<Hit>) {
    let owner = table_owner(cx.files, cx.call.task_cookie, cx.event.tid);
    let named = descriptor_path(path, cx.event.pid);
    let by_fd = if cx.nr == nr::EXECVEAT && cx.args[4] & 0x1000 != 0 {
        cx.files
            .opened
            .get(&(owner.0, owner.1, cx.args[0]))
            .cloned()
    } else {
        named.and_then(|(fd, other)| match other {
            None => cx.files.opened.get(&(owner.0, owner.1, fd)).cloned(),
            Some(pid) => cx
                .files
                .opened
                .iter()
                .find(|((_, owner_pid, descriptor), _)| *owner_pid == pid && *descriptor == fd)
                .map(|(_, opened)| opened.clone()),
        })
    };
    if let Some(target) = by_fd.filter(|target| target.starts_with("memfd:")) {
        out.push(
            Hit::new(
                "process.memfd_exec",
                &target,
                format!("exec of {target} through {path}"),
            )
            .detail("The image never existed as a named file."),
        );
        return;
    }
    if named.is_some() {
        out.push(Hit::new(
            "execution.fileless_exec",
            path,
            format!("exec of the file behind {path}, not a memfd"),
        ));
        return;
    }
    if kernel_records::file_id(cx.call).is_some_and(|id| id.regular && id.nlink == 0) {
        out.push(
            Hit::new(
                "execution.fileless_exec",
                path,
                format!("exec of {path}, a file with no name left"),
            )
            .detail("The exec's file identity record shows no hard link."),
        );
    }
}

/// Exec of a file the run wrote, or a compiler's output.
fn dropped(cx: &Ctx, st: &State, path: &str, out: &mut Vec<Hit>) {
    if st.sample.as_deref() == Some(path) {
        return;
    }
    let by_identity = kernel_records::file_id(cx.call)
        .filter(|id| id.regular)
        .is_some_and(|id| st.written_keys.contains(&id.key));
    if !(by_identity || st.written.contains(path)) {
        return;
    }
    if st.compiled.contains(path) {
        out.push(
            Hit::new(
                "execution.compile_then_run",
                path,
                format!("{path} was compiled in the guest and is now run"),
            )
            .detail("A compiler started by the run wrote this file."),
        );
        return;
    }
    out.push(
        Hit::new(
            "execution.dropped_exec",
            path,
            format!("{path} was written during the run and is now executed"),
        )
        .detail(if by_identity {
            "Matched by file identity: the inode the run wrote is the inode executed."
        } else {
            "Matched by path: the guest recorded no file identity for this exec."
        }),
    );
}

/// Exec from a staging or hidden directory, other than the sample itself.
fn staging(st: &State, path: &str, out: &mut Vec<Hit>) {
    if st.sample.as_deref() == Some(path) || descriptor_path(path, 0).is_some() {
        return;
    }
    let classes = file_location::classify(path, &[]);
    let shared = path.starts_with("/dev/shm/");
    let hidden = classes.contains(&file_location::Location::Hidden);
    let temp = classes.contains(&file_location::Location::Temp);
    if !(temp || hidden) {
        return;
    }
    let attack: &'static [&'static str] = if shared {
        &["T1027.011", "DET0344"]
    } else {
        &["T1564.001", "DET0032"]
    };
    let place = if shared {
        "shared-memory"
    } else if temp {
        "staging"
    } else {
        "hidden"
    };
    out.push(
        Hit::new(
            "execution.temp_exec",
            path,
            format!("exec of {path} from a {place} directory"),
        )
        .attack(attack),
    );
}

/// `LD_PRELOAD` and its relatives, and history switches, in the new program's environment.
fn environment(cx: &Ctx, out: &mut Vec<Hit>) {
    for var in cx.envp() {
        let Some((name, value)) = var.split_once('=') else {
            continue;
        };
        let risky = match name {
            "LD_PRELOAD" | "LD_AUDIT" => true,
            "LD_LIBRARY_PATH" => value.split(':').any(|part| {
                let classes = file_location::classify(part, &[]);
                classes.contains(&file_location::Location::Temp)
                    || classes.contains(&file_location::Location::Hidden)
            }),
            _ => false,
        };
        if risky {
            out.push(Hit::new(
                "injection.ld_preload_env",
                var,
                format!("program started with {name}={value}"),
            ));
        }
        if matches!(
            (name, value),
            ("HISTFILE", "/dev/null") | ("HISTSIZE", "0") | ("HISTFILESIZE", "0")
        ) {
            out.push(Hit::new(
                "evasion.history_clear",
                var,
                format!("program started with {name}={value}: no command history is kept"),
            ));
        }
    }
}

/// A download that is run: a fetcher whose output goes to an interpreter, or
/// is made executable and started.
fn cradle(script: &str, out: &mut Vec<Hit>) {
    let lower = script.to_ascii_lowercase();
    let fetches = [
        "curl ",
        "wget ",
        "fetch ",
        "tftp ",
        "/dev/tcp/",
        "lwp-download",
        "ftpget",
    ]
    .iter()
    .any(|word| lower.contains(word));
    let python_fetch = (lower.contains("urlopen")
        || lower.contains("urllib")
        || lower.contains("requests.get"))
        && (lower.contains("exec(") || lower.contains("os.system") || lower.contains("subprocess"));
    let piped = tools::pipes_into_interpreter(&lower);
    let substituted = ["$(curl", "$(wget", "`curl", "`wget", "<(curl", "<(wget"]
        .iter()
        .any(|word| lower.contains(word));
    let made_executable =
        (lower.contains("chmod +x") || lower.contains("chmod 7") || lower.contains("chmod u+x"))
            && fetches
            && (lower.contains("&&") || lower.contains(';'));
    if (fetches && (piped || substituted || made_executable)) || python_fetch {
        out.push(Hit::new(
            "execution.download_cradle",
            short(script),
            format!("download run as code: {}", short(script)),
        ));
    }
}

/// Rules that name a program and its arguments, whether exec'd or run by a shell.
fn commands(cx: &Ctx, st: &mut State, cmd: &Command, via_shell: bool, out: &mut Vec<Hit>) {
    let name = cmd.name();
    if name.is_empty() {
        return;
    }
    let text = short(&cmd.text());
    let note = if via_shell {
        " (in a shell command)"
    } else {
        ""
    };
    let summary = format!("{text}{note}");
    let mut found: Vec<&'static str> = Vec::new();
    match name {
        "iptables" | "ip6tables" | "iptables-nft" | "iptables-legacy" | "nft" | "ufw"
        | "firewall-cmd" => {
            let changes = cmd.has_any(&["-F", "--flush", "-X", "flush", "disable", "--delete-all"])
                || (cmd.has("-P") && cmd.has("ACCEPT"))
                || cmd.has_any(&["REDIRECT", "DNAT"]);
            if changes {
                found.push("evasion.firewall_modify");
            }
        }
        "systemctl" | "service" | "chkconfig" | "rc-service" | "update-rc.d" => {
            if cmd.has_any(&["stop", "disable", "mask", "kill", "off", "remove"]) {
                if cmd.services(&["auditd", "audit"]) {
                    found.push("evasion.audit_disable");
                } else if cmd.services(&[
                    "apparmor",
                    "selinux",
                    "falcon-sensor",
                    "osqueryd",
                    "wazuh",
                    "sysmon",
                    "sentinelone",
                    "ossec",
                    "clamav-daemon",
                    "clamd",
                    "falco",
                    "sysdig",
                    "aliyun",
                    "aegis",
                    "cloudmonitor",
                    "qcloud",
                    "yunjing",
                    "bcm-agent",
                ]) {
                    found.push("evasion.security_disable");
                } else if cmd.services(&["firewalld", "ufw", "iptables", "nftables", "ip6tables"]) {
                    found.push("evasion.firewall_modify");
                } else {
                    found.push("impact.service_stop");
                }
            }
            if name == "systemctl" && cmd.has_any(&["reboot", "poweroff", "halt", "kexec"]) {
                found.push("impact.reboot");
            }
            if cmd.has_any(&["enable", "link", "add", "defaults"])
                && cmd
                    .operands()
                    .iter()
                    .any(|unit| st.written_names.contains(base(unit)))
            {
                found.push(if name == "systemctl" {
                    "persistence.systemd"
                } else {
                    "persistence.rc_init"
                });
            }
        }
        "setenforce" if cmd.has_any(&["0", "Permissive", "permissive"]) => {
            found.push("evasion.security_disable");
        }
        "aa-teardown" | "aa-disable" => found.push("evasion.security_disable"),
        "auditctl" if cmd.has("-D") || cmd.pair("-e", "0") || cmd.has("-e0") => {
            found.push("evasion.audit_disable");
        }
        "journalctl" if cmd.starts_with_any(&["--vacuum", "--rotate", "--flush"]) => {
            found.push("evasion.log_clear");
        }
        "history" if cmd.has("-c") => found.push("evasion.history_clear"),
        "unset" if cmd.has("HISTFILE") => found.push("evasion.history_clear"),
        "export"
            if cmd.starts_with_any(&["HISTFILE=/dev/null", "HISTSIZE=0", "HISTFILESIZE=0"]) =>
        {
            found.push("evasion.history_clear");
        }
        "chattr" if changes_flags(cmd) => found.push("evasion.immutable_attr"),
        "crontab" => {
            if !cmd.has_any(&["-l", "-r", "-i"]) && !cmd.operands().is_empty() {
                found.push("persistence.cron");
            }
        }
        "at" | "batch" => found.push("persistence.at_job"),
        "useradd" | "adduser" | "usermod" | "groupadd" | "gpasswd" | "passwd" => {
            if !cmd.operands().is_empty() {
                found.push("persistence.account");
            }
        }
        "chpasswd" | "newusers" => found.push("persistence.account"),
        "nsenter" if cmd.pair("-t", "1") || cmd.pair("--target", "1") || cmd.has("--target=1") => {
            found.push("privilege.container_escape");
        }
        "reboot" | "shutdown" | "halt" | "poweroff" | "kexec" => found.push("impact.reboot"),
        "init" | "telinit" if cmd.has_any(&["0", "6"]) => found.push("impact.reboot"),
        "lvremove" => found.push("impact.inhibit_recovery"),
        "btrfs" if cmd.has("subvolume") && cmd.has("delete") => {
            found.push("impact.inhibit_recovery")
        }
        "zfs" if cmd.has("destroy") => found.push("impact.inhibit_recovery"),
        "vim-cmd" => {
            if cmd
                .operands()
                .iter()
                .any(|arg| arg.contains("snapshot.removeall"))
            {
                found.push("impact.inhibit_recovery");
            } else if cmd.operands().iter().any(|arg| arg.contains("power.off")) {
                found.push("impact.service_stop");
            }
        }
        "esxcli" if cmd.has("vm") && cmd.has("kill") => found.push("impact.service_stop"),
        "modprobe" if cmd.has("msr") => found.push("impact.miner_tuning"),
        "pkill" | "killall" | "killall5" if cmd.operands().len() >= 3 => {
            found.push("evasion.kill_list");
        }
        "ps" | "pgrep" | "pidof" | "top" | "htop" | "pstree" => {
            found.push("discovery.process_enum")
        }
        "dmidecode" | "systemd-detect-virt" | "virt-what" | "lscpu" => {
            super::probes::tool(cx, st, name, &text);
            found.push("discovery.system_info");
        }
        "uname" | "hostnamectl" | "lsb_release" | "arch" | "lshw" => {
            found.push("discovery.system_info")
        }
        "id" | "whoami" | "who" | "w" | "last" | "lastlog" | "users" | "logname" | "finger" => {
            found.push("discovery.user_enum");
        }
        "getent" if cmd.has_any(&["passwd", "group"]) => found.push("discovery.user_enum"),
        "ip" | "ifconfig" | "netstat" | "ss" | "arp" | "route" | "iwconfig" | "nmcli" => {
            found.push("discovery.network_config");
        }
        "find" | "locate" | "mlocate" | "plocate" if tools::searches_secrets(&cmd.text()) => {
            found.push("discovery.file_search");
        }
        "nmap" | "masscan" | "zmap" | "unicornscan" | "rustscan" | "zgrab" | "zgrab2" => {
            found.push("discovery.network_scan");
        }
        "hydra" | "medusa" | "ncrack" | "patator" | "crowbar" => found.push("lateral.bruteforce"),
        "xclip" | "xsel" | "wl-paste" if tools::reads_clipboard(name, cmd) => {
            found.push("collection.clipboard");
        }
        "import" | "xwd" | "scrot" | "gnome-screenshot" | "grim" | "maim" | "spectacle"
        | "flameshot" | "fbgrab" => found.push("collection.screen_capture"),
        "arecord" | "parecord" | "parec" | "fswebcam" | "streamer" => {
            found.push("collection.av_capture");
        }
        "ffmpeg" | "avconv" => {
            if cmd.has_any(&["x11grab", "kmsgrab", "fbdev"]) {
                found.push("collection.screen_capture");
            }
            if cmd.has_any(&["v4l2", "alsa", "pulse"]) {
                found.push("collection.av_capture");
            }
        }
        "tor" | "tor-browser" | "torsocks" | "torify" => found.push("network.tor"),
        "ssh"
            if cmd.has_any(&["-R", "-L", "-D", "-w"])
                || cmd.starts_with_any(&["-R", "-L", "-D"]) =>
        {
            found.push("network.proxy_tunnel");
        }
        "socat" | "chisel" | "frpc" | "frps" | "ngrok" | "gost" | "iodine" | "iodined"
        | "dnscat" | "dnscat2" | "ptunnel" | "cloudflared" | "rathole" => {
            found.push("network.proxy_tunnel")
        }
        "xmrig" | "minerd" | "cpuminer" | "ccminer" | "ethminer" | "nbminer" | "t-rex"
        | "lolminer" | "cgminer" | "bfgminer" | "kdevtmpfsi" => found.push("impact.miner"),
        _ => {}
    }
    if name != "xmrig" && tools::mining_arguments(cmd) {
        found.push("impact.miner");
    }
    if remote_push(cmd) {
        found.push("lateral.tool_transfer");
    }
    if matches!(name, "ssh" | "scp" | "sftp") && st.task(cx).ssh_hosts_read {
        found.push("lateral.ssh_spread");
    }
    if stages_archive(cmd) {
        found.push("collection.archive_staging");
    }
    found.dedup();
    for rule in found {
        out.push(Hit::new(rule, &text, summary.clone()));
    }
}

/// `chattr +i`, `-a` and the like.
fn changes_flags(cmd: &Command) -> bool {
    cmd.args().iter().any(|arg| {
        arg.len() > 1
            && (arg.starts_with('+') || arg.starts_with('-'))
            && arg[1..].chars().all(|c| c.is_ascii_alphabetic())
            && (arg.contains('i') || arg.contains('a'))
    })
}

/// scp, rsync, sftp, `curl -T` and `ssh host 'cat > file'` toward another host.
fn remote_push(cmd: &Command) -> bool {
    let remote = |arg: &&str| {
        !arg.starts_with('-')
            && arg.split_once(':').is_some_and(|(host, path)| {
                !host.is_empty() && !host.contains('/') && !path.starts_with("//")
            })
    };
    match cmd.name() {
        "scp" | "rsync" | "sftp" => cmd.operands().iter().any(remote),
        "curl" => {
            cmd.has_any(&["-T", "--upload-file"])
                && cmd.operands().iter().any(|arg| arg.contains("://"))
        }
        "ssh" => cmd
            .operands()
            .iter()
            .any(|arg| arg.contains("cat >") || arg.contains("cat>")),
        _ => false,
    }
}

/// An archiver reading home or credential paths and writing into a staging directory.
fn stages_archive(cmd: &Command) -> bool {
    let name = cmd.name();
    let tool = matches!(
        name,
        "tar" | "zip" | "7z" | "7za" | "7zr" | "gzip" | "bzip2" | "xz" | "rar" | "gpg" | "gpg2"
    ) || (name == "openssl" && cmd.has("enc"));
    if !tool {
        return false;
    }
    let sources = cmd.args().iter().any(|word| {
        super::ctx::home_relative(word).is_some()
            || word.starts_with("~/")
            || word.contains("/.ssh")
            || word.contains("/.aws")
            || word.starts_with("/etc/shadow")
    });
    let staged = cmd.args().iter().any(|word| {
        let classes = file_location::classify(word, &[]);
        classes.contains(&file_location::Location::Temp)
            || classes.contains(&file_location::Location::Hidden)
    });
    sources && staged
}
