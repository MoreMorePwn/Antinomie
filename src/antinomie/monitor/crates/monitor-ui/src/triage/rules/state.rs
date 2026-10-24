// SPDX-License-Identifier: GPL-3.0-only
//! What the engine remembers between calls: the files the run wrote, the
//! programs it is running, and per task the windows the correlated rules count in.
use super::super::file_category::Category as Op;
use super::super::sigma_events::Role;
use super::super::*;
use super::ctx::{base, home_relative, parent, Ctx, Touch};
use super::probes::Probes;
use super::Hit;
use antinomie_monitor_core::kernel_notes::FileKey;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Bound on every table that grows with the run.
const LIMIT: usize = 65_536;
const WINDOW_ITEMS: usize = 8_192;

const NS: u64 = 1_000_000_000;
const MASS_DELETE: (u64, usize) = (30 * NS, 100);
const RANSOM: (u64, usize) = (30 * NS, 20);
const FILE_SEARCH: (u64, usize) = (60 * NS, 200);
const PROCESSES: usize = 10;
const DOCUMENTS: usize = 50;
const NOTE_DIRECTORIES: usize = 3;

/// Items seen within a span of time.
pub(super) struct Window<T> {
    items: VecDeque<(u64, T)>,
}

impl<T> Default for Window<T> {
    fn default() -> Self {
        Self {
            items: VecDeque::new(),
        }
    }
}

impl<T: Ord + Clone> Window<T> {
    pub(super) fn push(&mut self, now: u64, span: u64, item: T) {
        while self
            .items
            .front()
            .is_some_and(|(time, _)| now.saturating_sub(*time) > span)
        {
            self.items.pop_front();
        }
        if self.items.len() >= WINDOW_ITEMS {
            self.items.pop_front();
        }
        self.items.push_back((now, item));
    }

    pub(super) fn len(&self) -> usize {
        self.items.len()
    }

    /// Items newer than `span` before `now`.
    pub(super) fn items_since(&self, now: u64, span: u64) -> impl Iterator<Item = &T> {
        self.items
            .iter()
            .filter(move |(time, _)| now.saturating_sub(*time) <= span)
            .map(|(_, item)| item)
    }

    pub(super) fn distinct(&self) -> usize {
        self.items
            .iter()
            .map(|(_, item)| item)
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub(super) fn items(&self) -> impl Iterator<Item = &T> {
        self.items.iter().map(|(_, item)| item)
    }
}

/// One task's counters. A flag that ends in `_done` means the rule already fired.
#[derive(Default)]
pub(super) struct Task {
    pub first_nr: Option<u64>,
    pub first_ns: u64,
    pub last_ns: u64,
    pub ssh_hosts_read: bool,
    /// Under `/proc`: pids whose process files were opened.
    pub proc_pids: BTreeSet<u32>,
    proc_done: bool,
    pub dirs: Window<String>,
    search_done: bool,
    documents: BTreeSet<String>,
    sweep_done: bool,
    pub deleted: Window<String>,
    delete_done: bool,
    pub renamed: Window<(String, String)>,
    ransom_done: bool,
    notes: BTreeMap<String, BTreeSet<String>>,
    note_done: BTreeSet<String>,
    passwd: bool,
    group: bool,
    user_done: bool,
    /// The task made a network call or wrote a file.
    pub active: bool,
    pub kills: Window<u32>,
    pub connects: Window<(std::net::IpAddr, u16)>,
    pub scan_done: bool,
    pub login_done: bool,
    pub exploit_done: bool,
    pub forks: Window<u64>,
    pub fork_done: bool,
    pub fork_failures: u32,
    pub sent: u64,
    pub received: u64,
    pub upload_done: bool,
    pub flood: Window<std::net::IpAddr>,
    pub flood_done: bool,
    /// Writable anonymous ranges, to tell a write-then-execute from a plain exec map.
    pub writable: Vec<(u64, u64)>,
    pub ended: bool,
    pub kill_done: bool,
    /// Pipe descriptor → the file just spliced into it.
    pub spliced: BTreeMap<u64, String>,
    /// An ELF image came in over a socket.
    pub net_elf: bool,
}

/// A task that reached an address with its own calls.
#[derive(Clone)]
pub(super) struct Contact {
    pub cookie: u64,
    pub pid: u32,
    pub tid: u32,
    pub image: Option<String>,
}

impl Contact {
    pub(super) fn of(cx: &Ctx) -> Self {
        Self {
            cookie: cx.call.task_cookie,
            pid: cx.event.pid,
            tid: cx.event.tid,
            image: cx.image.map(str::to_owned),
        }
    }
}

#[derive(Default)]
pub(super) struct State {
    /// Connections and executed programs for the IOC window.
    pub ioc: super::ioc::Log,
    /// Addresses the run's calls connected or sent to, with the first task to do so.
    pub contacted: BTreeMap<std::net::IpAddr, Contact>,
    /// The first task to talk to a name server.
    pub dns_task: Option<Contact>,
    pub frames: super::frames::Frames,
    /// The launched program's own image.
    pub sample: Option<String>,
    pub written: BTreeSet<String>,
    pub written_names: BTreeSet<String>,
    pub written_keys: BTreeSet<FileKey>,
    /// Files a compiler started by the run wrote.
    pub compiled: BTreeSet<String>,
    /// Programs the run is running, by path, and who runs them.
    pub images: BTreeMap<String, BTreeSet<u64>>,
    pub image_keys: BTreeMap<FileKey, BTreeSet<u64>>,
    tasks: BTreeMap<u64, Task>,
    overflow: Task,
    /// Tasks of Antinomie itself, which the rules leave alone.
    pub app_tasks: BTreeSet<u64>,
    /// Tasks that entered a user namespace of their own.
    pub userns: BTreeSet<u64>,
    /// The credentials each task had at its last record.
    pub creds: BTreeMap<u64, antinomie_monitor_core::kernel_notes::Credentials>,
    pub probes: Probes,
}

impl State {
    pub(super) fn task(&mut self, cx: &Ctx) -> &mut Task {
        if self.tasks.len() >= LIMIT && !self.tasks.contains_key(&cx.call.task_cookie) {
            return &mut self.overflow;
        }
        self.tasks.entry(cx.call.task_cookie).or_default()
    }

    pub(super) fn tasks(&self) -> &BTreeMap<u64, Task> {
        &self.tasks
    }

    /// Bookkeeping after a call has been judged.
    pub(super) fn track(&mut self, cx: &Ctx) {
        let time = cx.time();
        let (nr, root) = (cx.nr, cx.event.root_task_cookie);
        let cookie = cx.call.task_cookie;
        if self.sample.is_none() && root != 0 && root == cookie {
            self.sample = cx
                .files
                .process_images
                .get(&TaskKey {
                    pid: cx.event.pid,
                    cookie,
                })
                .and_then(|node| node.exec_history.first().cloned());
            if let Some(sample) = self.sample.clone() {
                self.images.entry(sample).or_default().insert(cookie);
            }
        }
        let task = self.task(cx);
        if matches!(nr, 41 | 42 | 44 | 46) {
            task.active = true;
        }
        task.first_nr.get_or_insert(nr);
        if task.first_ns == 0 {
            task.first_ns = time;
        }
        task.last_ns = task.last_ns.max(time);
        if cx.call.task_exit.is_some() || matches!(nr, 60 | 231) {
            task.ended = true;
        }
        if cx.is_exec() && cx.ok && !cx.via_async {
            if let Some(path) = cx.exec_path() {
                if self.images.len() < LIMIT {
                    self.images.entry(path).or_default().insert(cookie);
                }
            }
            if let Some(id) = kernel_records::file_id(cx.call) {
                if self.image_keys.len() < LIMIT {
                    self.image_keys.entry(id.key).or_default().insert(cookie);
                }
            }
        }
        if task_ended(cx) {
            for runners in self.images.values_mut().chain(self.image_keys.values_mut()) {
                runners.remove(&cookie);
            }
        }
    }

    /// The call changed `path`: remember that the run wrote it.
    pub(super) fn wrote(&mut self, cx: &Ctx, path: &str, touch: &Touch) {
        let task = self.task(cx);
        task.active = true;
        let new_file = matches!(
            touch.op,
            Op::Created | Op::Written | Op::Truncated | Op::Renamed | Op::Linked
        ) || (touch.op == Op::Opened && cx.opens_for_write());
        if !new_file || self.written.len() >= LIMIT {
            return;
        }
        self.written.insert(path.to_owned());
        self.written_names.insert(base(path).to_owned());
        if let Some(id) = kernel_records::file_id(cx.call).filter(|id| id.regular) {
            self.written_keys.insert(id.key);
        }
        if is_compiler(cx.image_name()) && !path.starts_with("/proc/") {
            self.compiled.insert(path.to_owned());
        }
    }

    /// A file was deleted or moved away.
    pub(super) fn removed(&mut self, cx: &Ctx, path: &str, touch: &Touch, out: &mut Vec<Hit>) {
        let time = cx.time();
        let own = self
            .images
            .get(path)
            .is_some_and(|runners| !runners.is_empty())
            || kernel_records::file_id(cx.call).is_some_and(|id| {
                self.image_keys
                    .get(&id.key)
                    .is_some_and(|runners| !runners.is_empty())
            });
        if own && cx.ok {
            out.push(
                Hit::new(
                    "evasion.self_delete",
                    path,
                    format!(
                        "{} removes {path}, a program that is still running",
                        cx.name
                    ),
                )
                .detail("A process is running the file this call removes or moves away."),
            );
        }
        let made = self.written.contains(path);
        let moved_to = cx
            .touches()
            .iter()
            .find(|other| other.op == Op::Renamed && other.role == Role::New)
            .map(|other| other.path.clone());
        let task = self.task(cx);
        if touch.op == Op::Deleted && cx.ok && !made && !task.delete_done {
            task.deleted.push(time, MASS_DELETE.0, path.to_owned());
            // Counting distinct names is not free: look every few deletions once there are enough.
            if task.deleted.len() >= MASS_DELETE.1 && task.deleted.len().is_multiple_of(16) {
                let folders: BTreeSet<_> = task
                    .deleted
                    .items()
                    .map(|path| parent(path).to_owned())
                    .collect();
                if task.deleted.distinct() >= MASS_DELETE.1 && folders.len() >= 3 {
                    task.delete_done = true;
                    out.push(
                        Hit::new(
                            "impact.mass_delete",
                            "bulk",
                            format!(
                                "{} files the run did not create were deleted within 30 s, in {} directories",
                                task.deleted.distinct(),
                                folders.len()
                            ),
                        )
                        .detail(format!("Last deleted: {path}")),
                    );
                }
            }
        }
        if let (Op::Renamed, Some(target), true, false) =
            (touch.op, moved_to, cx.ok, task.ransom_done)
        {
            let (old, new) = (extension(path), extension(&target));
            if old != new && !new.is_empty() {
                task.renamed
                    .push(time, RANSOM.0, (path.to_owned(), new.clone()));
                let same = if task.renamed.len() >= RANSOM.1 && task.renamed.len().is_multiple_of(4)
                {
                    task.renamed.items().filter(|(_, ext)| *ext == new).count()
                } else {
                    0
                };
                if same >= RANSOM.1 {
                    task.ransom_done = true;
                    out.push(
                        Hit::new(
                            "impact.ransom_rewrite",
                            &new,
                            format!("{same} files renamed to the extension .{new} within 30 s"),
                        )
                        .detail("Rename pattern only: the written bytes' entropy is not judged."),
                    );
                }
            }
        }
    }

    /// A file was opened for reading, or read.
    pub(super) fn read(&mut self, cx: &Ctx, path: &str, touch: &Touch, out: &mut Vec<Hit>) {
        let task = self.task(cx);
        if touch.op != Op::Opened {
            return;
        }
        if matches!(base(path), "known_hosts" | "config" if path.contains("/.ssh/"))
            || base(path) == ".bash_history"
        {
            task.ssh_hosts_read = true;
        }
        match path {
            "/etc/passwd" => task.passwd = true,
            "/etc/group" => task.group = true,
            _ => {}
        }
        if task.passwd && task.group && !task.user_done {
            task.user_done = true;
            out.push(Hit::new(
                "discovery.user_enum",
                "passwd and group",
                "reads /etc/passwd and /etc/group".into(),
            ));
        }
        if home_relative(path).is_some() && document(path) && !task.sweep_done {
            if task.documents.len() < LIMIT {
                task.documents.insert(path.to_owned());
            }
            if task.documents.len() >= DOCUMENTS {
                task.sweep_done = true;
                out.push(Hit::new(
                    "collection.local_sweep",
                    "documents",
                    format!(
                        "{} documents, databases or keys under home directories read",
                        task.documents.len()
                    ),
                ));
            }
        }
    }

    /// A directory was listed.
    pub(super) fn listing(&mut self, cx: &Ctx, path: &str, out: &mut Vec<Hit>) {
        let time = cx.time();
        let task = self.task(cx);
        if !task.search_done {
            task.dirs.push(time, FILE_SEARCH.0, path.to_owned());
        }
        let look = task.dirs.len() >= FILE_SEARCH.1 && task.dirs.len().is_multiple_of(32);
        if !task.search_done && look && task.dirs.distinct() >= FILE_SEARCH.1 {
            task.search_done = true;
            out.push(Hit::new(
                "discovery.file_search",
                "sweep",
                format!(
                    "{} directories listed within a minute",
                    task.dirs.distinct()
                ),
            ));
        }
        if path == "/proc" {
            task.proc_pids.insert(0);
        }
    }

    /// Reads that tell a program about the machine.
    pub(super) fn discovery(&mut self, cx: &Ctx, path: &str, touch: &Touch, out: &mut Vec<Hit>) {
        if !matches!(touch.op, Op::Opened | Op::Read)
            || !cx.opens_for_read() && touch.op == Op::Opened
        {
            return;
        }
        let class = match path {
            "/etc/os-release"
            | "/usr/lib/os-release"
            | "/proc/version"
            | "/proc/meminfo"
            | "/etc/hostname"
            | "/etc/issue"
            | "/proc/cpuinfo" => Some(("discovery.system_info", "system details")),
            "/etc/resolv.conf" | "/proc/net/route" | "/proc/net/arp" | "/proc/net/dev"
            | "/proc/net/if_inet6" | "/proc/net/fib_trie" => {
                Some(("discovery.network_config", "network configuration"))
            }
            p if p.starts_with("/proc/net/tcp") || p.starts_with("/proc/net/udp") => {
                Some(("discovery.network_config", "open connections"))
            }
            p if p.starts_with("/sys/class/net/") && p.ends_with("/address") => {
                Some(("discovery.network_config", "network configuration"))
            }
            _ => None,
        };
        if let Some((rule, what)) = class {
            if cx.ok || cx.failed {
                out.push(Hit::new(rule, what, format!("{} reads {path}", cx.name)));
            }
        }
        if let Some(rest) = path.strip_prefix("/proc/") {
            if let Some((pid, tail)) = rest.split_once('/') {
                if let (Ok(pid), true) = (
                    pid.parse::<u32>(),
                    matches!(
                        tail,
                        "cmdline" | "comm" | "status" | "exe" | "stat" | "environ" | "cwd"
                    ),
                ) {
                    let task = self.task(cx);
                    task.proc_pids.insert(pid);
                    let seen = task.proc_pids.iter().filter(|pid| **pid != 0).count();
                    if !task.proc_done && seen >= PROCESSES {
                        task.proc_done = true;
                        out.push(Hit::new(
                            "discovery.process_enum",
                            "/proc",
                            format!(
                                "{seen} processes' command lines, names or states read under /proc"
                            ),
                        ));
                    }
                }
            }
        }
    }

    /// A file of this name was created: the same note in many directories is a ransom note.
    pub(super) fn created(&mut self, cx: &Ctx, path: &str, out: &mut Vec<Hit>) {
        let name = base(path);
        if matches!(
            name,
            "__init__.py"
                | "Makefile"
                | "CMakeLists.txt"
                | ".gitignore"
                | "index.html"
                | "package.json"
                | "Cargo.toml"
                | "README"
                | ".DS_Store"
        ) || path.starts_with("/proc/")
        {
            return;
        }
        let task = self.task(cx);
        if task.notes.len() >= LIMIT {
            return;
        }
        let folders = task.notes.entry(name.to_owned()).or_default();
        folders.insert(parent(path).to_owned());
        if folders.len() >= NOTE_DIRECTORIES && task.note_done.insert(name.to_owned()) {
            let count = task.notes[name].len();
            out.push(Hit::new(
                "impact.ransom_note",
                name,
                format!("{name} created in {count} directories"),
            ));
        }
    }
}

fn task_ended(cx: &Ctx) -> bool {
    cx.call.task_exit.is_some() || matches!(cx.nr, 60 | 231)
}

fn is_compiler(name: &str) -> bool {
    matches!(
        name,
        "gcc"
            | "cc"
            | "c++"
            | "g++"
            | "clang"
            | "clang++"
            | "tcc"
            | "as"
            | "ld"
            | "cc1"
            | "cc1plus"
            | "collect2"
            | "x86_64-linux-gnu-gcc"
            | "x86_64-linux-gnu-ld"
            | "rustc"
            | "go"
    ) || name.starts_with("x86_64-linux-gnu-g")
}

/// The last extension of a file name, without the dot.
fn extension(path: &str) -> String {
    base(path)
        .rsplit_once('.')
        .filter(|(stem, _)| !stem.is_empty())
        .map(|(_, ext)| ext.to_owned())
        .unwrap_or_default()
}

fn document(path: &str) -> bool {
    matches!(
        extension(path).to_ascii_lowercase().as_str(),
        "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "pdf"
            | "odt"
            | "ods"
            | "csv"
            | "db"
            | "sqlite"
            | "sqlite3"
            | "kdbx"
            | "key"
            | "pem"
            | "rtf"
            | "txt"
            | "p12"
            | "pfx"
            | "ovpn"
            | "wallet"
    )
}
