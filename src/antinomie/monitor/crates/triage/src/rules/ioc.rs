// SPDX-License-Identifier: GPL-3.0-only
//! What the rules pass leaves for the IOC window: the connections the run's
//! calls made, who made them, and the programs it executed (with the hash the
//! guest took when the exec committed). The IOC window joins a process to a
//! capture row only when exactly one of them made a matching call.
use super::Tier;
use super::{
    ctx::Ctx,
    engine::Engine,
    noise::{flag, Agg, Gaps},
    spec, Hit,
};
use crate::net_attr::Role;
use crate::*;
use antinomie_monitor_core::kernel_notes::HashKind;
use std::net::IpAddr;

/// Most entries kept of each list.
pub const LIMIT: usize = 50_000;
/// `connect` on a non-blocking socket starts the connection.
pub const EINPROGRESS: i64 = -115;

/// One call that reached an address.
#[derive(Clone, Debug)]
pub struct Connection {
    pub ip: IpAddr,
    pub port: u16,
    pub udp: bool,
    pub ok: bool,
    pub who: Who,
    pub name: &'static str,
}

/// The task that made a call, and which call.
#[derive(Clone, Debug, Default)]
pub struct Who {
    pub cookie: u64,
    pub pid: u32,
    pub tid: u32,
    pub image: Option<String>,
    pub time_ns: u64,
    pub stream: u64,
    pub call_id: u64,
}

/// A program the run started.
#[derive(Clone, Debug)]
pub struct Executed {
    pub path: String,
    /// SHA-256 as the guest recorded it; `None` with the reason in `why`.
    pub sha256: Option<String>,
    pub why: Option<String>,
    pub who: Who,
}

/// A network call for flow attribution: the address it named, in which role,
/// and when (a burst of calls to one peer by one task is one record).
#[derive(Clone, Debug)]
pub struct NetCall {
    pub ip: IpAddr,
    pub port: u16,
    pub udp: bool,
    pub role: Role,
    pub name: &'static str,
    pub who: Who,
    /// Guest time of the last call of the burst.
    pub last_ns: u64,
}

#[derive(Default)]
pub struct Log {
    /// Every network call that names an address, for [`crate::net_attr`].
    pub net: Vec<NetCall>,
    /// Where each task's latest record to a peer is in `net`.
    pub(crate) net_at: std::collections::HashMap<(u64, IpAddr, u16, bool, Role), usize>,
    pub connections: Vec<Connection>,
    pub executed: Vec<Executed>,
    /// Entries dropped past the limit.
    pub omitted: u64,
}

pub fn who(cx: &Ctx) -> Who {
    Who {
        cookie: cx.call.task_cookie,
        pid: cx.event.pid,
        tid: cx.event.tid,
        image: cx.image.map(str::to_owned),
        time_ns: cx.time(),
        stream: cx.call.stream_id,
        call_id: cx.call.call_id,
    }
}

pub fn address(cx: &Ctx, argument: usize) -> Option<(IpAddr, u16)> {
    let found = cx.address(argument)?;
    Some((found.ip.parse().ok()?, found.port))
}

/// Record the network call `cx` is, if it names an address.
pub fn observe_net(cx: &Ctx, log: &mut Log) {
    let (role, name, argument, fd) = match cx.name {
        "connect" => (Role::Remote, "connect", 1, cx.args[0]),
        "sendto" => (Role::Remote, "sendto", 4, cx.args[0]),
        "sendmsg" | "sendmmsg" => (Role::Remote, "sendmsg", 0, cx.args[0]),
        "accept" | "accept4" => (Role::Accepted, "accept", 1, cx.args[0]),
        "recvfrom" => (Role::Received, "recvfrom", 4, cx.args[0]),
        "bind" => (Role::Bound, "bind", 1, cx.args[0]),
        _ => return,
    };
    // `accept` and `recvfrom` only name a peer when they returned one.
    if matches!(role, Role::Accepted | Role::Received) && !cx.ok {
        return;
    }
    let socket = cx.socket(fd);
    let peer = if argument == 0 {
        // `sendmsg` carries its address in a message header the trace does
        // not decode: a connected datagram socket's peer is all it gives.
        socket.and_then(|socket| socket.peer)
    } else {
        address(cx, argument).or_else(|| {
            socket
                .filter(|_| role == Role::Remote)
                .and_then(|socket| socket.peer)
        })
    };
    let Some((ip, port)) = peer else {
        return;
    };
    let udp = match (role, socket) {
        (_, Some(socket)) => socket.is_datagram(),
        (Role::Received, None) => true,
        _ => false,
    };
    let time = cx.time();
    let key = (cx.call.task_cookie, ip, port, udp, role);
    if let Some(&at) = log.net_at.get(&key)
        && let Some(held) = log.net.get_mut(at)
        && time.saturating_sub(held.last_ns) <= crate::net_attr::BURST_NS
    {
        held.last_ns = held.last_ns.max(time);
        return;
    }
    if log.net.len() >= LIMIT {
        log.omitted += 1;
        return;
    }
    log.net_at.insert(key, log.net.len());
    log.net.push(NetCall {
        ip,
        port,
        udp,
        role,
        name,
        who: who(cx),
        last_ns: time,
    });
}

pub fn observe(cx: &Ctx, log: &mut Log) {
    observe_net(cx, log);
    match cx.name {
        "connect" => {
            let Some((ip, port)) = address(cx, 1) else {
                return;
            };
            let datagram = cx
                .socket(cx.args[0])
                .is_some_and(|socket| socket.is_datagram());
            push(
                log,
                Connection {
                    ip,
                    port,
                    udp: datagram,
                    ok: cx.ret.is_some_and(|ret| ret >= 0 || ret == EINPROGRESS),
                    who: who(cx),
                    name: "connect",
                },
            );
        }
        "sendto" | "sendmsg" | "sendmmsg" => {
            let Some(socket) = cx.socket(cx.args[0]) else {
                return;
            };
            // A stream socket was connected; its connect call is the record.
            if !socket.is_datagram() {
                return;
            }
            let Some((ip, port)) = socket.peer.or_else(|| address(cx, 4)) else {
                return;
            };
            push(
                log,
                Connection {
                    ip,
                    port,
                    udp: true,
                    ok: cx.ok,
                    who: who(cx),
                    name: if cx.name == "sendto" {
                        "sendto"
                    } else {
                        "sendmsg"
                    },
                },
            );
        }
        "execve" | "execveat" if cx.ok => {
            let Some(path) = cx.exec_path().filter(|path| path.starts_with('/')) else {
                return;
            };
            let hash = kernel_records::file_hash(cx.call, HashKind::Exec);
            let (sha256, why) = match &hash {
                Some(hash) => {
                    // A hash the guest could not take, or took of a script's
                    // interpreter or a file that changed meanwhile, is not this file's.
                    let why = hash.skipped();
                    (why.is_none().then(|| hash.sha256_hex()).flatten(), why)
                }
                None => (
                    None,
                    Some("the guest sent no hash record for this program".to_owned()),
                ),
            };
            if log.executed.len() >= LIMIT {
                log.omitted += 1;
                return;
            }
            log.executed.push(Executed {
                path,
                sha256,
                why,
                who: who(cx),
            });
        }
        _ => {}
    }
}

pub fn push(log: &mut Log, connection: Connection) {
    if log.connections.len() >= LIMIT {
        log.omitted += 1;
    } else {
        log.connections.push(connection);
    }
}

/// How an IOC match is recorded as a finding.
pub enum Evidence {
    Packet { capture: String, frame: u64 },
    Call { stream: u64, call_id: u64 },
}

/// One dataset match to list among the findings.
pub struct IocHit {
    pub object: String,
    pub summary: String,
    pub detail: Vec<String>,
    pub tier: Tier,
    pub evidence: Evidence,
    pub time_ns: u64,
    /// The one process that made a matching call.
    pub who: Option<Who>,
}

impl Engine {
    /// The network calls seen so far, for flow attribution.
    pub fn net_calls(&self) -> &[NetCall] {
        &self.state.ioc.net
    }

    /// What the run's calls left for the IOC window.
    pub fn take_ioc(&mut self) -> Log {
        std::mem::take(&mut self.state.ioc)
    }

    /// The findings of a cloud profile's fake metadata service, from the report
    /// the gateway wrote into the run's folder: the requests (one row, with
    /// the request lines as facts), the credentials handed out, and every use
    /// of the run's canary values the gateway saw in what the guest sent
    /// out. The host saw them, not a task, so the rows are VM-wide. A use
    /// also lists the address it went to as an endpoint indicator.
    pub fn cloud_report(
        &mut self,
        report: &antinomie_monitor_core::route::MetadataReport,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        let time_of = |ms: u64| {
            clock
                .and_then(|clock| {
                    let delta = (i128::from(ms) * 1000 - i128::from(clock.host_us)) * 1000;
                    u64::try_from(i128::from(clock.guest_ns) + delta).ok()
                })
                .unwrap_or(0)
        };
        let requests: Vec<_> = report
            .events
            .iter()
            .filter(|event| event.kind == "request")
            .collect();
        if let Some(first) = requests.first() {
            let detail = requests
                .iter()
                .take(32)
                .map(|event| event.detail.clone())
                .collect();
            self.host_row(
                "credential.cloud_metadata",
                first.endpoint.clone(),
                format!(
                    "{} requests to the instance metadata service {}",
                    requests.len(),
                    first.endpoint
                ),
                time_of(first.ms),
                (
                    requests.len() as u64,
                    time_of(requests[requests.len() - 1].ms),
                ),
                detail,
            );
        }
        for event in &report.events {
            let (rule, summary) = match event.kind.as_str() {
                "credentials" => (
                    "credential.cloud_credentials",
                    format!(
                        "the instance role's credentials were read from the metadata service ({})",
                        event.detail
                    ),
                ),
                "canary-use" => (
                    "credential.canary_used",
                    format!(
                        "the run's canary cloud credential was sent to {}",
                        event.endpoint
                    ),
                ),
                _ => continue,
            };
            let ms = time_of(event.ms);
            self.host_row(
                rule,
                event.endpoint.clone(),
                summary,
                ms,
                (1, ms),
                vec![event.detail.clone()],
            );
            if event.kind == "canary-use"
                && let Some((ip, port)) = event.endpoint.rsplit_once(':')
                && let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), port.parse::<u16>())
            {
                self.state.ioc.connections.push(Connection {
                    ip,
                    port,
                    udp: false,
                    ok: true,
                    who: Who {
                        time_ns: ms,
                        ..Who::default()
                    },
                    name: "cloud canary",
                });
            }
        }
    }

    /// One HIGH row per copy of the program the host found running outside
    /// the recorded tree (`run.json` `persisted`).
    pub fn persisted_copies(
        &mut self,
        copies: &antinomie_monitor_core::persisted_copy::PersistedCopies,
    ) {
        use antinomie_monitor_core::persisted_copy::CopyOf;
        for copy in &copies.copies {
            let of = copy.copy_of.unwrap_or(CopyOf::Sample);
            let mut detail = vec![
                format!(
                    "Its program has SHA-256 {} ({} bytes), {}.",
                    copy.sha256,
                    copy.size,
                    match of {
                        CopyOf::Sample => "the same as the program the run launched",
                        CopyOf::Written => "the same as a file the run wrote, as the guest hashed it when its last writer closed it",
                    }
                ),
                format!(
                    "The host read it from the guest (/proc/{}/exe) because the process was not running before the launch and is not in the recorded tree; it was {} with uid {}.",
                    copy.pid,
                    copy.started_by(),
                    copy.uid
                ),
                if copy.ended {
                    "It had exited before the run ended.".into()
                } else {
                    "It was still running when the run ended, and may still run in the guest.".into()
                },
                "Its own system calls are not in this recording: the guest traces only the launched tree.".into(),
            ];
            if copy.children > 0 {
                detail.push(format!(
                    "It forked {} more process{} under the same name.",
                    copy.children,
                    if copy.children == 1 { "" } else { "es" }
                ));
            }
            if let Some(why) = &copies.hold_ended {
                detail.push(format!(
                    "The run was kept open after its tree ended while a copy ran, until {why}."
                ));
            }
            self.host_row_from(
                "persistence.copy_running",
                (
                    copy.who(),
                    format!(
                        "{} runs {} outside the recorded tree, {}",
                        copy.who(),
                        of.label(),
                        copy.started_by()
                    ),
                ),
                (copy.start_boot_ns, 1 + u64::from(copy.children), copy.start_boot_ns),
                detail,
                &format!("outside the recorded tree ({})", copy.who()),
                "the host's process list and its hash of the process's program (run.json persisted)",
            );
        }
        if copies.more > 0 {
            self.notes.push(format!(
                "{} more processes outside the recorded tree ran a copy of the program; only the first {} are listed.",
                copies.more,
                copies.copies.len()
            ));
        }
    }

    /// One row for something the host saw, not a task: VM-wide, from the
    /// gateway's report.
    /// The run's program died of a signal before its first recorded system call.
    pub fn root_crash(
        &mut self,
        signal: &str,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        let at = clock.map_or(0, |clock| clock.guest_ns);
        self.host_row_as(
            "process.crashed_at_start",
            "the sample's program".to_owned(),
            format!("the sample crashed before its first system call: {signal}"),
            at,
            (1, at),
            vec![
                "No system call of the program was recorded, so there is nothing to judge: the \
                 program died while loading or in its first instructions."
                    .into(),
                "Common causes: a binary built for another kernel or CPU, an ELF the guest's \
                 loader cannot map, or legacy static code that needs vsyscall."
                    .into(),
            ],
            "the run's program (no task was recorded)",
        );
    }

    pub fn host_row(
        &mut self,
        rule: &'static str,
        object: String,
        summary: String,
        first_ns: u64,
        (count, last_ns): (u64, u64),
        detail: Vec<String>,
    ) {
        self.host_row_as(
            rule,
            object,
            summary,
            first_ns,
            (count, last_ns),
            detail,
            "VM-wide (seen by the host's cloud metadata service)",
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn host_row_as(
        &mut self,
        rule: &'static str,
        object: String,
        summary: String,
        first_ns: u64,
        (count, last_ns): (u64, u64),
        detail: Vec<String>,
        process: &str,
    ) {
        self.host_row_from(
            rule,
            (object, summary),
            (first_ns, count, last_ns),
            detail,
            process,
            "cloud-metadata.json in the run's folder",
        );
    }

    /// [`host_row_as`](Self::host_row_as) with the evidence it rests on.
    pub fn host_row_from(
        &mut self,
        rule: &'static str,
        (object, summary): (String, String),
        (first_ns, count, last_ns): (u64, u64, u64),
        detail: Vec<String>,
        process: &str,
        evidence: &str,
    ) {
        let Some(spec) = spec(rule) else {
            debug_assert!(false, "unclassified rule {rule}");
            return;
        };
        if let Some(known) = self
            .host_aggs
            .iter_mut()
            .find(|agg| agg.rule == spec.id && agg.object == object)
        {
            known.count += count;
            known.first_ns = known.first_ns.min(first_ns);
            known.last_ns = known.last_ns.max(last_ns);
            for line in detail {
                if known.detail.len() < 32 && !known.detail.contains(&line) {
                    known.detail.push(line);
                }
            }
            return;
        }
        let mut gaps = Gaps::default();
        gaps.add(first_ns);
        let agg = Agg {
            rule: spec.id,
            cookie: 0,
            pid: 0,
            tid: 0,
            process: process.to_owned(),
            flags: 0,
            image: None,
            object,
            summary,
            attack: spec.attack,
            base: spec.tier,
            count,
            failed: 0,
            allowed: 0,
            first_ns,
            last_ns,
            stream: 0,
            call_id: 0,
            ret: None,
            high_confidence: true,
            outcome: "seen by the host".into(),
            evidence: evidence.into(),
            gaps,
            detail,
            siblings: 0,
            samples: Vec::new(),
            packet: None,
            tier: spec.tier,
            why: Vec::new(),
        };
        self.host_aggs.push(agg);
    }

    /// List a dataset match as a `c2.ioc_match` finding, so it appears with the
    /// run's other detections.
    pub fn ioc_match(&mut self, found: IocHit) {
        let Some(spec) = spec("c2.ioc_match") else {
            debug_assert!(false, "unclassified rule c2.ioc_match");
            return;
        };
        let mut hit = Hit::new("c2.ioc_match", found.object, found.summary).tier(found.tier);
        hit.detail = found.detail;
        let who = found.who.unwrap_or_default();
        let named = who.cookie != 0 || who.image.is_some();
        let key = (spec.id, who.cookie, hit.object.clone());
        if self.index.contains_key(&key) {
            return;
        }
        let mut gaps = Gaps::default();
        gaps.add(found.time_ns);
        let (stream, call_id, packet, evidence) = match &found.evidence {
            Evidence::Packet { capture, frame } => (
                0,
                *frame,
                Some((capture.clone(), *frame)),
                format!("packet #{frame}"),
            ),
            Evidence::Call { stream, call_id } => {
                (*stream, *call_id, None, format!("syscall call {call_id}"))
            }
        };
        let agg = Agg {
            rule: spec.id,
            cookie: who.cookie,
            pid: who.pid,
            tid: who.pid,
            process: if named {
                format!(
                    "{} · the one task whose call reached it",
                    process_identity(who.pid, who.pid, who.image.as_deref())
                )
            } else {
                "VM-wide (capture)".to_owned()
            },
            flags: if named { flag::INFERRED } else { flag::VM_WIDE },
            image: who.image.clone(),
            object: hit.object,
            summary: hit.summary,
            attack: spec.attack,
            base: hit.tier.unwrap_or(spec.tier),
            count: 1,
            failed: 0,
            allowed: 0,
            first_ns: found.time_ns,
            last_ns: found.time_ns,
            stream,
            call_id,
            ret: None,
            high_confidence: named,
            outcome: "matched an abuse.ch dataset".into(),
            evidence,
            gaps,
            detail: hit.detail,
            siblings: 0,
            samples: Vec::new(),
            packet,
            tier: spec.tier,
            why: Vec::new(),
        };
        self.index.insert(key, self.aggs.len());
        self.aggs.push(agg);
    }
}

#[cfg(test)]
pub mod tests {
    use super::super::tests::support::*;
    use super::super::Options;
    use super::*;

    /// Run the engine over calls the way the scan does and hand back the engine.
    fn engine_over(calls: Calls) -> (Engine, FdState) {
        let mut files = FdState::default();
        let mut engine = Engine::new(Options {
            show_info: true,
            capture_all: false,
            packed: None,
            cloud_profile: false,
        });
        let mut sets = std::collections::BTreeMap::new();
        note_cookie_sets(&mut sets, &calls);
        let cookies = resolve_cookies(&sets);
        for (at, call) in calls.iter().enumerate() {
            let mut call = call.clone();
            call.call_id = at as u64 + 1;
            observe_processes(&mut files.process_images, std::slice::from_ref(&call));
            let Some(event) = trace::representative(&call) else {
                continue;
            };
            engine.observe(&call, &files, None, false);
            remember_open(&mut files, &call, event);
            apply_dup(&mut files, &call, event);
            forget_closed(&mut files, &call, event);
            inherit_open_fds(&mut files, &call, event, &cookies);
            sigma_events::track(&mut files, &call, event);
        }
        (engine, files)
    }

    #[test]
    fn connections_and_started_programs_are_logged_with_their_task() {
        let mut failing = connect(2, 4, [198, 51, 100, 7], 8080);
        failing.exit.as_mut().unwrap().result = Some(-101);
        let (mut engine, _) = engine_over(vec![
            socket(1, 2, 1, 3),
            connect(1, 3, [203, 0, 113, 45], 443),
            socket(2, 2, 2, 4),
            failing,
            exec(1, "/tmp/.kd", &[".kd"]),
        ]);
        let log = engine.take_ioc();
        assert_eq!(log.connections.len(), 2, "{:?}", log.connections);
        let first = &log.connections[0];
        assert_eq!(
            (first.ip.to_string(), first.port),
            ("203.0.113.45".into(), 443)
        );
        assert!(first.ok && !first.udp);
        assert_eq!((first.who.pid, first.who.call_id), (1, 2));
        let second = &log.connections[1];
        assert!(!second.ok, "a refused connect is logged as failed");
        assert!(second.udp, "a datagram socket's connect is UDP");
        assert_eq!(log.executed.len(), 1);
        assert_eq!(log.executed[0].path, "/tmp/.kd");
        assert!(log.executed[0].sha256.is_none(), "no hash record, no hash");
        // Taken once.
        assert!(engine.take_ioc().connections.is_empty());
    }

    fn sendto(pid: u32, fd: u64, ip: [u8; 4], port: u16) -> InvocationSummary {
        let row = sys(pid, 44, "sendto", [fd, 0, 32, 0, 0, 16], 32);
        with_entry(
            row,
            "arg4.address",
            &super::super::tests::support::address(2, ip, port),
        )
    }

    fn bind(pid: u32, fd: u64, ip: [u8; 4], port: u16) -> InvocationSummary {
        let row = sys(pid, 49, "bind", [fd, 0, 16, 0, 0, 0], 0);
        with_entry(
            row,
            "arg1.address",
            &super::super::tests::support::address(2, ip, port),
        )
    }

    fn accept(pid: u32, fd: u64, ip: [u8; 4], port: u16, new_fd: i64) -> InvocationSummary {
        let row = sys(pid, 43, "accept", [fd, 0, 0, 0, 0, 0], new_fd);
        with_exit(
            row,
            "arg1.address",
            &super::super::tests::support::address(2, ip, port),
        )
    }

    #[test]
    fn network_calls_are_kept_with_their_role_protocol_and_task() {
        let (mut engine, _) = engine_over(vec![
            // A TCP connect.
            socket(10, 2, 1, 3),
            connect(10, 3, [192, 0, 2, 9], 80),
            // A UDP DNS lookup through sendto, twice in one burst.
            socket(11, 2, 2, 4),
            sendto(11, 4, [10, 0, 2, 3], 53),
            sendto(11, 4, [10, 0, 2, 3], 53),
            // A listener that accepts one client.
            socket(12, 2, 1, 5),
            bind(12, 5, [0, 0, 0, 0], 8080),
            accept(12, 5, [10, 0, 2, 2], 51000, 6),
        ]);
        let calls = engine.net_calls().to_vec();
        let find = |name: &str| calls.iter().find(|call| call.name == name).unwrap();
        let connect = find("connect");
        assert_eq!((connect.who.pid, connect.who.tid), (10, 10));
        assert_eq!(
            (connect.ip.to_string(), connect.port, connect.udp),
            ("192.0.2.9".into(), 80, false)
        );
        assert_eq!(connect.role, Role::Remote);
        let send = find("sendto");
        assert_eq!((send.port, send.udp, send.role), (53, true, Role::Remote));
        assert_eq!(
            calls.iter().filter(|call| call.name == "sendto").count(),
            1,
            "a burst to one peer is one record"
        );
        let bound = find("bind");
        assert_eq!(
            (bound.port, bound.udp, bound.role),
            (8080, false, Role::Bound)
        );
        let accepted = find("accept");
        assert_eq!(
            (accepted.ip.to_string(), accepted.port, accepted.role),
            ("10.0.2.2".into(), 51000, Role::Accepted)
        );
        // The IOC list's connections are unchanged by the new record: the
        // connect and each of the two sends.
        assert_eq!(engine.take_ioc().connections.len(), 3);
    }

    #[test]
    fn a_dataset_match_becomes_one_finding_with_its_packet_evidence() {
        let (mut engine, files) = engine_over(vec![socket(1, 2, 1, 3)]);
        let hit = |tier| IocHit {
            object: "endpoint 203.0.113.45:443".into(),
            summary: "endpoint 203.0.113.45:443 is listed by ThreatFox: Mirai (75% confidence)"
                .into(),
            detail: vec!["Dataset: ThreatFox · record 1831204".into()],
            tier,
            evidence: Evidence::Packet {
                capture: "/run/capture.pcap".into(),
                frame: 211,
            },
            time_ns: 3_000_000_000,
            who: Some(Who {
                cookie: 1,
                pid: 1,
                tid: 1,
                image: Some("kworkerd".into()),
                ..Who::default()
            }),
        };
        engine.ioc_match(hit(Tier::High));
        // The same object by the same task is one row.
        engine.ioc_match(hit(Tier::High));
        let out = engine.finish(&files);
        let found = rows(&out, "c2.ioc_match");
        assert_eq!(found.len(), 1);
        assert_eq!(text(found[0], "finding.tier"), "high");
        assert_eq!(text(found[0], "finding.category"), "c2");
        assert!(text(found[0], "finding.summary").contains("ThreatFox: Mirai"));
        assert_eq!(text(found[0], "capture.path"), "/run/capture.pcap");
        assert_eq!(files::number(&found[0].values, "frame.number"), Some(211));
        assert_eq!(list(found[0], "finding.technique"), ["T1071", "DET0444"]);
    }
}
