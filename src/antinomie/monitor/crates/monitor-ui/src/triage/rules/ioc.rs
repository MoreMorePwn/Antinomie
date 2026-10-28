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
use crate::triage::*;
use antinomie_monitor_core::kernel_notes::HashKind;
use std::net::IpAddr;

/// Most entries kept of each list.
const LIMIT: usize = 50_000;
/// `connect` on a non-blocking socket starts the connection.
const EINPROGRESS: i64 = -115;

/// One call that reached an address.
#[derive(Clone, Debug)]
pub(in crate::triage) struct Connection {
    pub ip: IpAddr,
    pub port: u16,
    pub udp: bool,
    pub ok: bool,
    pub who: Who,
    pub name: &'static str,
}

/// The task that made a call, and which call.
#[derive(Clone, Debug, Default)]
pub(in crate::triage) struct Who {
    pub cookie: u64,
    pub pid: u32,
    pub image: Option<String>,
    pub time_ns: u64,
    pub stream: u64,
    pub call_id: u64,
}

/// A program the run started.
#[derive(Clone, Debug)]
pub(in crate::triage) struct Executed {
    pub path: String,
    /// SHA-256 as the guest recorded it; `None` with the reason in `why`.
    pub sha256: Option<String>,
    pub why: Option<String>,
    pub who: Who,
}

#[derive(Default)]
pub(in crate::triage) struct Log {
    pub connections: Vec<Connection>,
    pub executed: Vec<Executed>,
    /// Entries dropped past the limit.
    pub omitted: u64,
}

fn who(cx: &Ctx) -> Who {
    Who {
        cookie: cx.call.task_cookie,
        pid: cx.event.pid,
        image: cx.image.map(str::to_owned),
        time_ns: cx.time(),
        stream: cx.call.stream_id,
        call_id: cx.call.call_id,
    }
}

fn address(cx: &Ctx, argument: usize) -> Option<(IpAddr, u16)> {
    let found = cx.address(argument)?;
    Some((found.ip.parse().ok()?, found.port))
}

pub(super) fn observe(cx: &Ctx, log: &mut Log) {
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
                None => (None, None),
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

fn push(log: &mut Log, connection: Connection) {
    if log.connections.len() >= LIMIT {
        log.omitted += 1;
    } else {
        log.connections.push(connection);
    }
}

/// How an IOC match is recorded as a finding.
pub(in crate::triage) enum Evidence {
    Packet { capture: String, frame: u64 },
    Call { stream: u64, call_id: u64 },
}

/// One dataset match to list among the findings.
pub(in crate::triage) struct IocHit {
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
    /// What the run's calls left for the IOC window.
    pub(in crate::triage) fn take_ioc(&mut self) -> Log {
        std::mem::take(&mut self.state.ioc)
    }

    /// List a dataset match as a `c2.ioc_match` finding, so it appears with the
    /// run's other detections.
    pub(in crate::triage) fn ioc_match(&mut self, found: IocHit) {
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
mod tests {
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
