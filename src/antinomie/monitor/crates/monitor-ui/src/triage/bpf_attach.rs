// SPDX-License-Identifier: GPL-3.0-only
//! Programs attached by `bpf(BPF_LINK_CREATE)`, `bpf(BPF_RAW_TRACEPOINT_OPEN)` and
//! `ioctl(PERF_EVENT_IOC_SET_BPF)` on a perf event, read from the recorded
//! attribute block and tied back to the load or the `perf_event_open` that made
//! the fds. Nothing here is guessed: a target the recording did not capture says so.
use super::rules::Tier;
use super::*;

/// `_IOW('$', 8, __u32)`.
pub(super) const PERF_EVENT_IOC_SET_BPF: u64 = 0x4004_2408;
const BPF: u64 = 321;
const PERF_EVENT_OPEN: u64 = 298;
const CLOSE: u64 = 3;
const HELD: usize = 4096;
const NAMES_SHOWN: usize = 4;

pub(super) const LINK_CREATE: &str = "BPF_LINK_CREATE";
pub(super) const RAW_TRACEPOINT_OPEN: &str = "BPF_RAW_TRACEPOINT_OPEN";
pub(super) const SET_BPF: &str = "PERF_EVENT_IOC_SET_BPF";
pub(super) const PERF_OPEN: &str = "PERF_EVENT_OPEN";

/// What a `perf_event_open` asked for, as far as the recording captured it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct PerfEvent {
    pub call_id: u64,
    pub kind: Option<u32>,
    pub config: Option<u64>,
}

impl PerfEvent {
    pub(super) fn describe(&self) -> String {
        match (self.kind, self.config) {
            (Some(2), Some(id)) => format!("tracepoint id {id} (name not resolved)"),
            (Some(0), config) => format!("hardware event config {}", hex(config)),
            (Some(1), config) => format!("software event config {}", hex(config)),
            (Some(3), config) => format!("hardware cache event config {}", hex(config)),
            (Some(4), config) => format!("raw event config {}", hex(config)),
            (Some(5), _) => "hardware breakpoint".into(),
            (Some(kind), config) => format!(
                "dynamic PMU type {kind} config {} (kprobe or uprobe; probe target not captured)",
                hex(config)
            ),
            (None, _) => "event type not captured".into(),
        }
    }

    /// A kernel tracepoint or a dynamic PMU (the kprobe and uprobe ones) hooks
    /// the whole kernel or every user of a binary.
    fn tier(&self) -> Tier {
        match self.kind {
            Some(2) => Tier::High,
            Some(kind) if kind >= 6 => Tier::High,
            _ => Tier::Medium,
        }
    }
}

fn hex(value: Option<u64>) -> String {
    value.map_or("not captured".into(), |value| format!("{value:#x}"))
}

/// Descriptors the trace has shown, per task: loaded programs and perf events.
#[derive(Default)]
pub(super) struct BpfFds {
    programs: Vec<(u64, i64, u64)>,
    perf: Vec<(u64, i64, PerfEvent)>,
}

impl BpfFds {
    /// Fold one finished call in. Call it after judging the call, so a call
    /// sees the descriptors that existed before it.
    pub(super) fn observe(&mut self, invocation: &InvocationSummary) {
        let Some(event) = trace::representative(invocation) else {
            return;
        };
        let cookie = invocation.task_cookie;
        let args = event.args.or_else(|| call_args(invocation));
        let fd = invocation
            .exit
            .as_ref()
            .and_then(|exit| exit.result)
            .filter(|fd| *fd >= 0);
        match (event.syscall_nr, args) {
            (CLOSE, Some(args)) if succeeded(invocation) => {
                if let Ok(fd) = i64::try_from(args[0]) {
                    self.programs.retain(|key| (key.0, key.1) != (cookie, fd));
                    self.perf.retain(|key| (key.0, key.1) != (cookie, fd));
                }
            }
            (BPF, Some(args)) if args[0] == 5 => {
                if let Some(fd) = fd {
                    self.programs.retain(|key| (key.0, key.1) != (cookie, fd));
                    if self.programs.len() < HELD {
                        self.programs.push((cookie, fd, invocation.call_id));
                    }
                }
            }
            (PERF_EVENT_OPEN, _) => {
                if let Some(fd) = fd {
                    let attr = attr_bytes(invocation, "arg0.perf_event_attr");
                    let attr = attr.as_deref();
                    self.perf.retain(|key| (key.0, key.1) != (cookie, fd));
                    if self.perf.len() < HELD {
                        self.perf.push((
                            cookie,
                            fd,
                            PerfEvent {
                                call_id: invocation.call_id,
                                kind: attr.and_then(|attr| word(attr, 0)),
                                config: attr.and_then(|attr| wide(attr, 8)),
                            },
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    /// The call that loaded program fd `fd` in this task.
    pub(super) fn program(&self, cookie: u64, fd: i64) -> Option<u64> {
        self.programs
            .iter()
            .find(|key| (key.0, key.1) == (cookie, fd))
            .map(|key| key.2)
    }

    pub(super) fn perf(&self, cookie: u64, fd: i64) -> Option<&PerfEvent> {
        self.perf
            .iter()
            .find(|key| (key.0, key.1) == (cookie, fd))
            .map(|key| &key.2)
    }
}

/// One attachment of a program, with what the recording says about it.
pub(super) struct Attach {
    /// `kprobe_multi`, `raw tracepoint`, `perf event`, an attach type.
    pub kind: String,
    pub prog_fd: Option<i64>,
    /// The call that loaded `prog_fd`, when this slice saw it.
    pub loaded_by: Option<u64>,
    pub target: String,
    /// Tier of a successful attach.
    pub tier: Tier,
}

impl Attach {
    /// The step as a sentence, for the lifecycle line and the Observation column.
    pub(super) fn lifecycle(&self, result: Option<i64>) -> String {
        let verb = match result {
            Some(ret) if ret >= 0 => format!("attached {}", self.kind),
            Some(ret) => format!("attach of {} failed ({ret})", self.kind),
            None => format!("attach of {} attempted; exit not recorded", self.kind),
        };
        format!("{verb} {}: {}", self.program(), self.target)
    }

    pub(super) fn program(&self) -> String {
        match (self.prog_fd, self.loaded_by) {
            (Some(fd), Some(call)) => format!("of program fd {fd} (loaded in call {call})"),
            (Some(fd), None) => format!("of program fd {fd} (its load was not seen)"),
            (None, _) => "of a program (fd not captured)".into(),
        }
    }
}

/// Which attach command a call is, if any.
pub(super) fn command_of(event: &EventSummary, args: [u64; 6]) -> Option<&'static str> {
    match event.syscall_nr {
        BPF => match args[0] {
            17 => Some(RAW_TRACEPOINT_OPEN),
            28 => Some(LINK_CREATE),
            _ => None,
        },
        16 if args[1] == PERF_EVENT_IOC_SET_BPF => Some(SET_BPF),
        _ => None,
    }
}

pub(super) fn attach(
    invocation: &InvocationSummary,
    command: &'static str,
    args: [u64; 6],
    fds: &BpfFds,
) -> Attach {
    let cookie = invocation.task_cookie;
    let tied = |prog_fd: Option<i64>| prog_fd.and_then(|fd| fds.program(cookie, fd));
    match command {
        LINK_CREATE => {
            let attr = attr_bytes(invocation, "arg1.attr");
            let attr = attr.as_deref();
            let prog_fd = attr.and_then(|attr| word(attr, 0)).map(i64::from);
            let target_fd = attr.and_then(|attr| word(attr, 4));
            let kind = attr.and_then(|attr| word(attr, 8));
            let (name, tier, target) = match kind {
                Some(kind) => link_target(invocation, attr, kind, target_fd, fds),
                None => (
                    "link".to_owned(),
                    Tier::Medium,
                    "attach type not captured (target not captured)".to_owned(),
                ),
            };
            Attach {
                kind: name,
                prog_fd,
                loaded_by: tied(prog_fd),
                target,
                tier,
            }
        }
        RAW_TRACEPOINT_OPEN => {
            let attr = attr_bytes(invocation, "arg1.attr");
            let attr = attr.as_deref();
            let prog_fd = attr.and_then(|attr| word(attr, 8)).map(i64::from);
            let pointer = attr.and_then(|attr| wide(attr, 0));
            let name = string_field(invocation, "arg1.attr.name");
            let target = match (name, pointer) {
                (Some(name), _) => format!("tracepoint {name}"),
                (None, Some(0)) => {
                    "no tracepoint name: a tracing program (fentry, fexit or LSM) whose kernel function was chosen at load, not captured".into()
                }
                _ => "tracepoint name not captured (target not captured)".into(),
            };
            Attach {
                kind: "raw tracepoint".into(),
                prog_fd,
                loaded_by: tied(prog_fd),
                target,
                tier: Tier::High,
            }
        }
        _ => {
            let prog_fd = i64::try_from(args[2]).ok();
            let perf_fd = i64::try_from(args[0]).ok();
            let event = perf_fd.and_then(|fd| fds.perf(cookie, fd));
            let target = match (perf_fd, event) {
                (Some(fd), Some(event)) => {
                    format!(
                        "perf event fd {fd} opened in call {}: {}",
                        event.call_id,
                        event.describe()
                    )
                }
                (Some(fd), None) => {
                    format!("perf event fd {fd} (its perf_event_open was not seen; target not captured)")
                }
                _ => "perf event fd not captured (target not captured)".into(),
            };
            Attach {
                kind: "perf event".into(),
                prog_fd,
                loaded_by: tied(prog_fd),
                target,
                tier: event.map_or(Tier::Medium, PerfEvent::tier),
            }
        }
    }
}

/// Name, tier and target text of a `BPF_LINK_CREATE` by its attach type.
fn link_target(
    invocation: &InvocationSummary,
    attr: Option<&[u8]>,
    kind: u32,
    target_fd: Option<u32>,
    fds: &BpfFds,
) -> (String, Tier, String) {
    let name = attach_type(kind).map_or_else(|| format!("attach type {kind}"), str::to_owned);
    let fd = target_fd.map_or("not captured".into(), |fd| fd.to_string());
    let count = |at: usize| attr.and_then(|attr| word(attr, at));
    match kind {
        42 | 56 => {
            let cnt = count(20);
            let mut names = Vec::new();
            for index in 0..cnt.unwrap_or(0).min(256) {
                if let Some(name) = string_field(invocation, &format!("arg1.attr.syms[{index}]")) {
                    names.push(name);
                }
            }
            let target = match (cnt, names.is_empty()) {
                (Some(cnt), false) => format!(
                    "{cnt} kernel symbols: {}{}",
                    names
                        .iter()
                        .take(NAMES_SHOWN)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                    if names.len() > NAMES_SHOWN {
                        ", ..."
                    } else {
                        ""
                    }
                ),
                (Some(cnt), true) => format!("{cnt} kernel symbols (names not captured)"),
                _ => "kernel symbols not captured (target not captured)".into(),
            };
            (name, Tier::High, target)
        }
        48 => {
            let path = string_field(invocation, "arg1.attr.path");
            let cnt = count(48);
            let target = match path {
                Some(path) => format!(
                    "{path}, {} offsets",
                    cnt.map_or("? ".into(), |c| c.to_string())
                ),
                None => "binary path not captured (target not captured)".into(),
            };
            (name, Tier::Medium, target)
        }
        23..=27 | 43 => (
            name,
            Tier::High,
            format!(
                "kernel function chosen at load (attach_btf_id), name not captured; target fd {fd}"
            ),
        ),
        44 => (
            name,
            Tier::High,
            "kernel struct_ops replaced (target not captured)".into(),
        ),
        41 => {
            let event = target_fd.and_then(|fd| fds.perf(invocation.task_cookie, i64::from(fd)));
            match event {
                Some(event) => (
                    name,
                    event.tier(),
                    format!(
                        "perf event fd {fd} opened in call {}: {}",
                        event.call_id,
                        event.describe()
                    ),
                ),
                None => (
                    name,
                    Tier::Medium,
                    format!("perf event fd {fd} (its perf_event_open was not seen; target not captured)"),
                ),
            }
        }
        37 | 33 | 35 | 46 | 47 | 54 | 55 => (name, Tier::Medium, format!("interface index {fd}")),
        45 => {
            let target = match (count(16), count(20)) {
                (Some(pf), Some(hook)) => format!("netfilter family {pf} hook {hook}"),
                _ => "netfilter hook not captured (target not captured)".into(),
            };
            (name, Tier::Medium, target)
        }
        28 => (name, Tier::Medium, "kernel iterator".into()),
        _ if cgroup_type(kind) => (name, Tier::Medium, format!("cgroup fd {fd}")),
        _ => (name, Tier::Medium, format!("target fd {fd}")),
    }
}

fn cgroup_type(kind: u32) -> bool {
    matches!(kind, 0..=3 | 6 | 8..=15 | 18..=22 | 29..=32 | 34 | 49..=53)
}

fn attach_type(kind: u32) -> Option<&'static str> {
    const NAMES: [&str; 57] = [
        "cgroup_inet_ingress",
        "cgroup_inet_egress",
        "cgroup_inet_sock_create",
        "cgroup_sock_ops",
        "sk_skb_stream_parser",
        "sk_skb_stream_verdict",
        "cgroup_device",
        "sk_msg_verdict",
        "cgroup_inet4_bind",
        "cgroup_inet6_bind",
        "cgroup_inet4_connect",
        "cgroup_inet6_connect",
        "cgroup_inet4_post_bind",
        "cgroup_inet6_post_bind",
        "cgroup_udp4_sendmsg",
        "cgroup_udp6_sendmsg",
        "lirc_mode2",
        "flow_dissector",
        "cgroup_sysctl",
        "cgroup_udp4_recvmsg",
        "cgroup_udp6_recvmsg",
        "cgroup_getsockopt",
        "cgroup_setsockopt",
        "trace_raw_tp",
        "fentry",
        "fexit",
        "modify_return",
        "lsm",
        "trace_iter",
        "cgroup_inet4_getpeername",
        "cgroup_inet6_getpeername",
        "cgroup_inet4_getsockname",
        "cgroup_inet6_getsockname",
        "xdp_devmap",
        "cgroup_inet_sock_release",
        "xdp_cpumap",
        "sk_lookup",
        "xdp",
        "sk_skb_verdict",
        "sk_reuseport_select",
        "sk_reuseport_select_or_migrate",
        "perf_event",
        "kprobe_multi",
        "lsm_cgroup",
        "struct_ops",
        "netfilter",
        "tcx_ingress",
        "tcx_egress",
        "uprobe_multi",
        "cgroup_unix_connect",
        "cgroup_unix_sendmsg",
        "cgroup_unix_recvmsg",
        "cgroup_unix_getpeername",
        "cgroup_unix_getsockname",
        "netkit_primary",
        "netkit_peer",
        "kprobe_session",
    ];
    NAMES.get(usize::try_from(kind).ok()?).copied()
}

/// `perf_event_open` as a table row: the type and config it asked for.
pub(super) fn perf_open_text(invocation: &InvocationSummary, result: Option<i64>) -> String {
    let attr = attr_bytes(invocation, "arg0.perf_event_attr");
    let event = PerfEvent {
        call_id: invocation.call_id,
        kind: attr.as_deref().and_then(|attr| word(attr, 0)),
        config: attr.as_deref().and_then(|attr| wide(attr, 8)),
    };
    match result {
        Some(fd) if fd >= 0 => format!("perf event fd {fd} opened: {}", event.describe()),
        Some(ret) => format!("perf event open failed ({ret}): {}", event.describe()),
        None => format!(
            "perf event open attempted: {}; exit not recorded",
            event.describe()
        ),
    }
}

/// The entry's captured bytes for `key`, when the field is a plain prefix.
fn attr_bytes(invocation: &InvocationSummary, key: &str) -> Option<Vec<u8>> {
    let field = invocation
        .entry
        .iter()
        .flat_map(|event| &event.fields)
        .find(|field| field.key == key)?;
    Some(trace::covered_preview(field).to_vec())
}

fn string_field(invocation: &InvocationSummary, key: &str) -> Option<String> {
    let field = invocation
        .entry
        .iter()
        .flat_map(|event| &event.fields)
        .find(|field| field.key == key)?;
    let bytes = trace::covered_preview(field);
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    (end > 0).then(|| String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn wide(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}
