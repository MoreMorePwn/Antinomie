// SPDX-License-Identifier: GPL-3.0-only
//! The Relationships graph as data: the processes of the run, the files they
//! wrote or ran, the endpoints they contacted and the processes they injected
//! into or signalled, joined by what happened between them. Built from plain
//! facts so it is tested without a recording; `facts` reads them from the scan.
use super::super::super::rules::Tier;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A task's identity: its pid and the recording's stable cookie.
pub(in crate::triage) type Key = (u32, u64);

/// A process of the run.
#[derive(Clone, Debug, Default)]
pub(in crate::triage) struct Proc {
    pub pid: u32,
    pub cookie: u64,
    pub parent: Option<Key>,
    pub name: String,
    /// argv[0] names a program other than the image the kernel loaded.
    pub mismatch: bool,
    /// The images the task ran, each with when.
    pub execs: Vec<(String, u64)>,
    /// `(target pid, signal)` of each kill it made.
    pub sent: Vec<(i64, u8)>,
    /// A fork that has not run an exec of its own.
    pub forked: bool,
}

/// A finding, with what the graph needs of it.
#[derive(Clone, Debug)]
pub(in crate::triage) struct Fact {
    pub tier: Tier,
    pub rule: String,
    pub object: String,
    pub pid: u32,
    pub cookie: u64,
}

/// A file a process wrote or ran.
#[derive(Clone, Debug)]
pub(in crate::triage) struct FileFact {
    pub path: String,
    pub roles: Vec<String>,
    pub process: Option<Key>,
}

/// An endpoint a process contacted.
#[derive(Clone, Debug)]
pub(in crate::triage) struct EndpointFact {
    pub endpoint: String,
    pub process: Option<Key>,
}

#[derive(Clone, Debug, Default)]
pub(in crate::triage) struct Facts {
    pub procs: Vec<Proc>,
    pub findings: Vec<Fact>,
    pub files: Vec<FileFact>,
    pub endpoints: Vec<EndpointFact>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::triage) enum NodeKind {
    Process(Key),
    File(String),
    Endpoint(String),
    /// A process that was injected into or signalled but is not in the run.
    Victim(u32),
    /// Several processes or files shown as one (see `group`).
    Group(GroupInfo),
}

/// What a group node stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::triage) enum GroupWhat {
    /// Children of one parent that ran the same image.
    Processes,
    /// Files one process wrote into one folder.
    Files,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::triage) struct GroupInfo {
    /// Stable: made from the parent's identity and the image or folder.
    pub id: String,
    pub what: GroupWhat,
    pub members: u32,
    /// Its members are drawn beside it.
    pub open: bool,
    /// The labels of the first few members, for the tooltip.
    pub sample: Vec<String>,
}

/// What a node is, for the Compact view's "best of each kind".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::triage) enum Family {
    Process,
    Victim,
    File,
    Endpoint,
}

impl NodeKind {
    /// Stable between builds: the same run gives the same text.
    pub(in crate::triage) fn id(&self) -> String {
        match self {
            Self::Process((pid, cookie)) => format!("p:{pid}:{cookie}"),
            Self::File(path) => format!("f:{path}"),
            Self::Endpoint(endpoint) => format!("e:{endpoint}"),
            Self::Victim(pid) => format!("v:{pid}"),
            Self::Group(info) => info.id.clone(),
        }
    }

    pub(in crate::triage) fn family(&self) -> Family {
        match self {
            Self::Process(_)
            | Self::Group(GroupInfo {
                what: GroupWhat::Processes,
                ..
            }) => Family::Process,
            Self::Victim(_) => Family::Victim,
            Self::File(_)
            | Self::Group(GroupInfo {
                what: GroupWhat::Files,
                ..
            }) => Family::File,
            Self::Endpoint(_) => Family::Endpoint,
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::triage) struct Node {
    pub kind: NodeKind,
    pub label: String,
    /// The highest tier of a finding that involves it.
    pub tier: Option<Tier>,
    /// argv does not match the image.
    pub warn: bool,
    /// Findings that involve it.
    pub findings: u32,
    /// For a process: the image it ran, by which siblings are grouped.
    pub image: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::triage) enum EdgeKind {
    Forked,
    Execed,
    Wrote,
    Ran,
    Connected,
    Injected,
    Signalled,
    /// From a group to what it holds, when it is open.
    Member,
}

impl EdgeKind {
    pub(in crate::triage) fn label(self) -> &'static str {
        match self {
            Self::Forked => "fork",
            Self::Execed => "exec",
            Self::Wrote => "write",
            Self::Ran => "run",
            Self::Connected => "connect",
            Self::Injected => "inject",
            Self::Signalled => "signal",
            Self::Member => "member",
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::triage) struct Edge {
    pub from: usize,
    pub to: usize,
    pub kind: EdgeKind,
    pub count: u32,
}

#[derive(Clone, Debug, Default)]
pub(in crate::triage) struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// Per node, the indices of the edges that leave and enter it.
    pub out: Vec<Vec<u32>>,
    pub inc: Vec<Vec<u32>>,
}

/// Rules whose object names a process the run acted on.
const INJECTION_RULES: &[&str] = &[
    "injection.ptrace_attach",
    "injection.ptrace_poke",
    "process.ptrace",
    "injection.vm_write",
    "injection.proc_mem_write",
    "credential.proc_mem_read",
];

/// Roles of a file that put it in the graph.
const FILE_ROLES: &[&str] = &["created", "written at close", "executed"];

/// The pid an injection finding's object names: `pid 418 poke`, `pid 7` or
/// `/proc/418/mem`.
pub(in crate::triage) fn target_pid(object: &str) -> Option<u32> {
    let digits = |text: &str| -> Option<u32> {
        let run: String = text.chars().take_while(char::is_ascii_digit).collect();
        run.parse().ok()
    };
    if let Some(rest) = object.strip_prefix("pid ") {
        return digits(rest);
    }
    object.strip_prefix("/proc/").and_then(digits)
}

fn tier_max(into: &mut Option<Tier>, tier: Tier) {
    if into.is_none_or(|have| tier > have) {
        *into = Some(tier);
    }
}

fn process_label(proc: &Proc) -> String {
    let name = if proc.name.is_empty() {
        "unknown"
    } else {
        &proc.name
    };
    format!("{name} ({})", proc.pid)
}

/// The image a process ran, by which siblings are told apart.
fn image_of(proc: &Proc) -> String {
    proc.execs
        .last()
        .map(|(image, _)| image.clone())
        .unwrap_or_else(|| proc.name.clone())
}

impl Graph {
    /// Fill `out` and `inc` from `edges`.
    pub(in crate::triage) fn index(&mut self) {
        self.out = vec![Vec::new(); self.nodes.len()];
        self.inc = vec![Vec::new(); self.nodes.len()];
        for (at, edge) in self.edges.iter().enumerate() {
            self.out[edge.from].push(at as u32);
            self.inc[edge.to].push(at as u32);
        }
    }

    /// The edges that enter `node`.
    pub(in crate::triage) fn edges_in(&self, node: usize) -> impl Iterator<Item = &Edge> {
        self.inc[node].iter().map(|&at| &self.edges[at as usize])
    }

    /// The edges that leave `node`.
    pub(in crate::triage) fn edges_out(&self, node: usize) -> impl Iterator<Item = &Edge> {
        self.out[node].iter().map(|&at| &self.edges[at as usize])
    }

    pub(in crate::triage) fn build(facts: &Facts) -> Self {
        let mut graph = Graph::default();
        let mut index: BTreeMap<String, usize> = BTreeMap::new();
        let mut by_key: BTreeMap<Key, usize> = BTreeMap::new();
        let mut by_pid: BTreeMap<u32, usize> = BTreeMap::new();
        for proc in &facts.procs {
            let at = graph.nodes.len();
            graph.nodes.push(Node {
                kind: NodeKind::Process((proc.pid, proc.cookie)),
                label: process_label(proc),
                tier: None,
                warn: proc.mismatch,
                findings: 0,
                image: image_of(proc),
            });
            by_key.insert((proc.pid, proc.cookie), at);
            by_pid.entry(proc.pid).or_insert(at);
        }
        let root = facts
            .procs
            .iter()
            .find(|proc| {
                proc.parent
                    .is_none_or(|parent| !by_key.contains_key(&parent))
            })
            .map(|proc| (proc.pid, proc.cookie));
        let find = |key: Option<Key>| key.and_then(|key| by_key.get(&key).copied());
        let actor = |key: Option<Key>| find(key).or_else(|| find(root));

        let mut edges: BTreeMap<(usize, usize, EdgeKind), u32> = BTreeMap::new();
        let mut edge = |from: usize, to: usize, kind: EdgeKind| {
            if from != to {
                *edges.entry((from, to, kind)).or_default() += 1;
            }
        };
        for proc in &facts.procs {
            let Some(&child) = by_key.get(&(proc.pid, proc.cookie)) else {
                continue;
            };
            if let Some(&parent) = proc.parent.and_then(|parent| by_key.get(&parent)) {
                let kind = if proc.forked {
                    EdgeKind::Forked
                } else {
                    EdgeKind::Execed
                };
                edge(parent, child, kind);
            }
        }
        // The processes that ran each image, for "ran" edges.
        let mut ran_by: HashMap<&str, Vec<usize>> = HashMap::new();
        for proc in &facts.procs {
            let Some(&at) = by_key.get(&(proc.pid, proc.cookie)) else {
                continue;
            };
            let mut seen: Vec<&str> = Vec::new();
            for (image, _) in &proc.execs {
                if !seen.contains(&image.as_str()) {
                    seen.push(image);
                    ran_by.entry(image).or_default().push(at);
                }
            }
        }
        // Files: the ones written or run, by path.
        let mut node_of = |graph: &mut Graph, kind: NodeKind, label: String| -> usize {
            let id = match &kind {
                NodeKind::File(path) => format!("f:{path}"),
                NodeKind::Endpoint(endpoint) => format!("e:{endpoint}"),
                NodeKind::Victim(pid) => format!("v:{pid}"),
                NodeKind::Process(key) => format!("p:{}:{}", key.0, key.1),
                NodeKind::Group(info) => info.id.clone(),
            };
            *index.entry(id).or_insert_with(|| {
                graph.nodes.push(Node {
                    kind,
                    label,
                    tier: None,
                    warn: false,
                    findings: 0,
                    image: String::new(),
                });
                graph.nodes.len() - 1
            })
        };
        for file in &facts.files {
            if !file
                .roles
                .iter()
                .any(|role| FILE_ROLES.contains(&role.as_str()))
            {
                continue;
            }
            let at = node_of(
                &mut graph,
                NodeKind::File(file.path.clone()),
                crate::triage::process_cells::file_name(&file.path).to_owned(),
            );
            let wrote = file
                .roles
                .iter()
                .any(|role| role == "created" || role == "written at close");
            if wrote {
                if let Some(from) = actor(file.process) {
                    edge(from, at, EdgeKind::Wrote);
                }
            }
            // A process whose image this file is ran it.
            for &from in ran_by.get(file.path.as_str()).into_iter().flatten() {
                edge(from, at, EdgeKind::Ran);
            }
        }
        for endpoint in &facts.endpoints {
            let at = node_of(
                &mut graph,
                NodeKind::Endpoint(endpoint.endpoint.clone()),
                endpoint.endpoint.clone(),
            );
            if let Some(from) = actor(endpoint.process) {
                edge(from, at, EdgeKind::Connected);
            }
        }
        // Injection and signals.
        let mut victim = |graph: &mut Graph, pid: u32| -> usize {
            by_pid
                .get(&pid)
                .copied()
                .unwrap_or_else(|| node_of(graph, NodeKind::Victim(pid), format!("pid {pid}")))
        };
        for finding in &facts.findings {
            if !INJECTION_RULES.contains(&finding.rule.as_str()) {
                continue;
            }
            let (Some(pid), Some(from)) = (
                target_pid(&finding.object),
                actor(Some((finding.pid, finding.cookie))),
            ) else {
                continue;
            };
            let to = victim(&mut graph, pid);
            edge(from, to, EdgeKind::Injected);
        }
        for proc in &facts.procs {
            let Some(&from) = by_key.get(&(proc.pid, proc.cookie)) else {
                continue;
            };
            for &(target, _) in &proc.sent {
                if target > 0 && target as u32 != proc.pid {
                    let to = victim(&mut graph, target as u32);
                    edge(from, to, EdgeKind::Signalled);
                }
            }
        }
        graph.edges = edges
            .into_iter()
            .map(|((from, to, kind), count)| Edge {
                from,
                to,
                kind,
                count,
            })
            .collect();
        graph.index();
        graph.tiers(facts, &by_key);
        graph
    }

    /// Mark the nodes the findings involve with their highest tier.
    fn tiers(&mut self, facts: &Facts, by_key: &BTreeMap<Key, usize>) {
        let mut marks: Vec<(usize, Tier)> = Vec::new();
        // What a finding's object can name: a file path, an address, a pid.
        let mut files: HashMap<&str, usize> = HashMap::new();
        let mut hosts: HashMap<&str, Vec<usize>> = HashMap::new();
        let mut pids: HashMap<u32, Vec<usize>> = HashMap::new();
        for (at, node) in self.nodes.iter().enumerate() {
            match &node.kind {
                NodeKind::File(path) => {
                    files.insert(path, at);
                }
                NodeKind::Endpoint(endpoint) => {
                    let ip = endpoint.rsplit_once(':').map_or(endpoint.as_str(), |p| p.0);
                    hosts.entry(ip).or_default().push(at);
                }
                NodeKind::Victim(pid) | NodeKind::Process((pid, _)) => {
                    pids.entry(*pid).or_default().push(at);
                }
                NodeKind::Group(_) => {}
            }
        }
        for finding in &facts.findings {
            if finding.tier == Tier::Info {
                continue;
            }
            let actor = by_key.get(&(finding.pid, finding.cookie)).copied();
            if let Some(at) = actor {
                marks.push((at, finding.tier));
            }
            let mut hit: Vec<usize> = Vec::new();
            if !finding.object.is_empty() {
                hit.extend(files.get(finding.object.as_str()));
                if !hosts.is_empty() {
                    let mut seen: Vec<&str> = Vec::new();
                    for token in finding
                        .object
                        .split(|c: char| !(c.is_ascii_alphanumeric() || ".:-".contains(c)))
                    {
                        let bare = token.rsplit_once(':').map_or(token, |p| p.0);
                        for key in [token, bare] {
                            if !seen.contains(&key) {
                                seen.push(key);
                                hit.extend(hosts.get(key).into_iter().flatten());
                            }
                        }
                    }
                }
            }
            if let Some(target) = target_pid(&finding.object)
                .filter(|_| INJECTION_RULES.contains(&finding.rule.as_str()))
            {
                for &at in pids.get(&target).into_iter().flatten() {
                    if actor != Some(at) {
                        hit.push(at);
                    }
                }
            }
            hit.sort_unstable();
            hit.dedup();
            for at in hit {
                marks.push((at, finding.tier));
            }
        }
        drop((files, hosts, pids));
        for (at, tier) in marks {
            tier_max(&mut self.nodes[at].tier, tier);
            self.nodes[at].findings += 1;
        }
    }

    /// The node that connects `node` to the rest: the process that started,
    /// wrote, contacted or acted on it. A parent comes before an injector.
    pub(in crate::triage) fn anchor(&self, node: usize) -> Option<usize> {
        self.edges_in(node)
            .min_by_key(|edge| {
                (
                    matches!(edge.kind, EdgeKind::Injected | EdgeKind::Signalled),
                    edge.from,
                )
            })
            .map(|edge| edge.from)
    }

    /// The first process nothing started: the run's root. (A process another
    /// injected into has an anchor, but it was not started by it.)
    pub(in crate::triage) fn root(&self) -> usize {
        (0..self.nodes.len())
            .find(|&at| {
                matches!(self.nodes[at].kind, NodeKind::Process(_))
                    && !self
                        .edges_in(at)
                        .any(|edge| matches!(edge.kind, EdgeKind::Forked | EdgeKind::Execed))
            })
            .unwrap_or(0)
    }

    /// How much a node is worth showing: its tier first, then what it does.
    fn score(&self, node: usize) -> i64 {
        let item = &self.nodes[node];
        let tier = match item.tier {
            Some(Tier::High) => 4000,
            Some(Tier::Medium) => 3000,
            Some(Tier::Low) => 2000,
            Some(Tier::Info) | None => 0,
        };
        let kind = match item.kind.family() {
            Family::Process => 300,
            Family::Victim => 250,
            Family::Endpoint => 200,
            Family::File => 150,
        };
        let degree = (self.out[node].len() + self.inc[node].len()) as i64;
        tier + kind
            + i64::from(item.findings.min(50)) * 4
            + degree * 10
            + i64::from(item.warn) * 100
    }

    /// `node` and the chain of anchors that joins it to the root.
    pub(in crate::triage) fn add_chain(&self, node: usize, chosen: &mut BTreeSet<usize>) {
        let mut next = Some(node);
        let mut guard = 0;
        while let Some(at) = next {
            if !chosen.insert(at) || guard > 4096 {
                break;
            }
            next = self.anchor(at);
            guard += 1;
        }
    }

    /// The nodes of the Compact view: the root, the `per_kind` best
    /// processes, files and endpoints (by `score`; a group counts as one
    /// node), and the processes the run injected into or signalled, each with
    /// the chain that joins it to the root. Processes the chains pull in come
    /// on top of the `per_kind`. What an open group holds is shown with it.
    pub(in crate::triage) fn compact(&self, per_kind: usize) -> Vec<usize> {
        if self.nodes.is_empty() {
            return Vec::new();
        }
        let mut chosen: BTreeSet<usize> = BTreeSet::new();
        chosen.insert(self.root());
        let best = |wanted: &dyn Fn(usize) -> bool| -> Vec<usize> {
            let mut all: Vec<usize> = (0..self.nodes.len()).filter(|&at| wanted(at)).collect();
            all.sort_by_key(|&at| (std::cmp::Reverse(self.score(at)), at));
            all.truncate(per_kind);
            all
        };
        let family = |at: usize| self.nodes[at].kind.family();
        let victim = |at: usize| {
            family(at) == Family::Victim
                || (family(at) == Family::Process
                    && self
                        .edges_in(at)
                        .any(|edge| edge.kind == EdgeKind::Injected))
        };
        let picks = [
            best(&|at| family(at) == Family::Process),
            best(&victim),
            best(&|at| family(at) == Family::File),
            best(&|at| family(at) == Family::Endpoint),
        ];
        for node in picks.into_iter().flatten() {
            self.add_chain(node, &mut chosen);
        }
        let opened: Vec<usize> = chosen
            .iter()
            .copied()
            .filter(|&at| matches!(&self.nodes[at].kind, NodeKind::Group(info) if info.open))
            .collect();
        for group in opened {
            for edge in self.edges_out(group) {
                if edge.kind == EdgeKind::Member {
                    chosen.insert(edge.to);
                }
            }
        }
        chosen.into_iter().collect()
    }

    /// At most `cap` nodes, joined to the root: what is nearest the root (the
    /// nodes come in breadth-first order from a view), after the nodes with a
    /// finding and the chains that join them.
    pub(in crate::triage) fn capped(&self, cap: usize) -> Vec<usize> {
        if self.nodes.len() <= cap {
            return (0..self.nodes.len()).collect();
        }
        let mut chosen: BTreeSet<usize> = BTreeSet::new();
        let mut tiered: Vec<usize> = (0..self.nodes.len())
            .filter(|&at| self.nodes[at].tier.is_some())
            .collect();
        tiered.sort_by_key(|&at| (std::cmp::Reverse(self.score(at)), at));
        for at in tiered {
            if chosen.len() >= cap / 4 {
                break;
            }
            self.add_chain(at, &mut chosen);
        }
        let mut at = 0;
        while chosen.len() < cap && at < self.nodes.len() {
            chosen.insert(at);
            at += 1;
        }
        chosen.into_iter().collect()
    }
}

/// A process the Summary names for its findings or its argv.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::triage) struct Interest {
    pub key: Key,
    pub label: String,
    pub tier: Option<Tier>,
    pub findings: u32,
    pub warn: bool,
}

/// The processes with the most findings (by tier, then count), and those whose
/// argv does not match the image, at most `limit`.
pub(in crate::triage) fn interest(facts: &Facts, limit: usize) -> Vec<Interest> {
    let mut tiers: HashMap<Key, Vec<Tier>> = HashMap::new();
    for finding in facts.findings.iter().filter(|f| f.tier != Tier::Info) {
        tiers
            .entry((finding.pid, finding.cookie))
            .or_default()
            .push(finding.tier);
    }
    let mut out: Vec<Interest> = facts
        .procs
        .iter()
        .filter_map(|proc| {
            let mine: &[Tier] = tiers
                .get(&(proc.pid, proc.cookie))
                .map_or(&[], Vec::as_slice);
            (!mine.is_empty() || proc.mismatch).then(|| Interest {
                key: (proc.pid, proc.cookie),
                label: process_label(proc),
                tier: mine.iter().copied().max(),
                findings: mine.len() as u32,
                warn: proc.mismatch,
            })
        })
        .collect();
    out.sort_by_key(|item| {
        (
            std::cmp::Reverse(item.tier),
            std::cmp::Reverse(item.findings),
            std::cmp::Reverse(item.warn),
            item.key,
        )
    });
    out.truncate(limit);
    out
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn proc(pid: u32, cookie: u64, parent: Option<Key>, name: &str) -> Proc {
        Proc {
            pid,
            cookie,
            parent,
            name: name.into(),
            ..Proc::default()
        }
    }

    pub(in crate::triage) fn fixture() -> Facts {
        let mut sh = proc(420, 4, Some((401, 1)), "sh");
        sh.forked = true;
        sh.sent = vec![(555, 9)];
        let mut demo = proc(401, 1, None, "demo-all");
        demo.mismatch = true;
        let mut dropped = proc(421, 5, Some((401, 1)), "kdevtmpfsi");
        dropped.execs = vec![("/tmp/.x/kdevtmpfsi".into(), 500_000_000)];
        Facts {
            procs: vec![demo, sh, dropped, proc(430, 6, Some((420, 4)), "curl")],
            findings: vec![
                Fact {
                    tier: Tier::High,
                    rule: "injection.ptrace_poke".into(),
                    object: "pid 418 poke".into(),
                    pid: 401,
                    cookie: 1,
                },
                Fact {
                    tier: Tier::Medium,
                    rule: "execution.dropped_exec".into(),
                    object: "/tmp/.x/kdevtmpfsi".into(),
                    pid: 420,
                    cookie: 4,
                },
                Fact {
                    tier: Tier::Info,
                    rule: "discovery.system_info".into(),
                    object: "x".into(),
                    pid: 430,
                    cookie: 6,
                },
            ],
            files: vec![
                FileFact {
                    path: "/tmp/.x/kdevtmpfsi".into(),
                    roles: vec!["created".into(), "executed".into()],
                    process: Some((420, 4)),
                },
                FileFact {
                    path: "/etc/passwd".into(),
                    roles: vec!["changed".into()],
                    process: None,
                },
            ],
            endpoints: vec![EndpointFact {
                endpoint: "45.9.148.9:80".into(),
                process: Some((430, 6)),
            }],
        }
    }

    /// A big run: one root, `processes` below it in a tree whose images
    /// repeat, and `files` written into forty folders; every 97th process has
    /// a finding.
    pub(in crate::triage) fn synthetic(processes: usize, files: usize) -> Facts {
        let mut facts = Facts::default();
        facts.procs.push(proc(1, 1, None, "demo-all"));
        for i in 0..processes {
            let parent = if i < 30 { 0 } else { (i - 30) / 8 };
            let parent = &facts.procs[parent];
            let parent = (parent.pid, parent.cookie);
            let mut child = proc(
                100 + i as u32,
                100 + i as u64,
                Some(parent),
                &format!("tool{}", i % 2),
            );
            child.execs = vec![(format!("/usr/bin/tool{}", i % 2), 1)];
            facts.procs.push(child);
            if i % 97 == 0 {
                facts.findings.push(Fact {
                    tier: Tier::Medium,
                    rule: "execution.temp_exec".into(),
                    object: format!("/tmp/x{i}"),
                    pid: 100 + i as u32,
                    cookie: 100 + i as u64,
                });
            }
        }
        for j in 0..files {
            let writer = &facts.procs[1 + (j / 4) % processes.max(1)];
            facts.files.push(FileFact {
                path: format!("/tmp/d{}/f{j}", (j / 4) % 40),
                roles: vec!["created".into()],
                process: Some((writer.pid, writer.cookie)),
            });
        }
        facts
    }

    fn at(graph: &Graph, kind: NodeKind) -> usize {
        graph
            .nodes
            .iter()
            .position(|node| node.kind == kind)
            .unwrap()
    }

    fn has(graph: &Graph, from: &NodeKind, to: &NodeKind, kind: EdgeKind) -> bool {
        let (from, to) = (at(graph, from.clone()), at(graph, to.clone()));
        graph
            .edges
            .iter()
            .any(|edge| edge.from == from && edge.to == to && edge.kind == kind)
    }

    #[test]
    fn nodes_and_edges_cover_processes_files_endpoints_and_victims() {
        let graph = Graph::build(&fixture());
        let (demo, sh, dropped, curl) = (
            NodeKind::Process((401, 1)),
            NodeKind::Process((420, 4)),
            NodeKind::Process((421, 5)),
            NodeKind::Process((430, 6)),
        );
        let file = NodeKind::File("/tmp/.x/kdevtmpfsi".into());
        assert!(has(&graph, &demo, &sh, EdgeKind::Forked));
        assert!(has(&graph, &demo, &dropped, EdgeKind::Execed));
        assert!(has(&graph, &sh, &file, EdgeKind::Wrote));
        assert!(has(&graph, &dropped, &file, EdgeKind::Ran));
        assert!(has(
            &graph,
            &curl,
            &NodeKind::Endpoint("45.9.148.9:80".into()),
            EdgeKind::Connected
        ));
        // Injection into a process that is not in the run, and a kill of another.
        assert!(has(
            &graph,
            &demo,
            &NodeKind::Victim(418),
            EdgeKind::Injected
        ));
        assert!(has(
            &graph,
            &sh,
            &NodeKind::Victim(555),
            EdgeKind::Signalled
        ));
        // A changed file is no node.
        assert!(!graph
            .nodes
            .iter()
            .any(|node| node.kind == NodeKind::File("/etc/passwd".into())));
        assert!(graph.nodes[at(&graph, demo)].warn);
        assert_eq!(graph.nodes[at(&graph, sh.clone())].label, "sh (420)");
    }

    #[test]
    fn an_injection_into_a_process_of_the_run_is_an_edge_to_that_process() {
        let mut facts = fixture();
        facts.findings[0].object = "/proc/430/mem".into();
        facts.findings[0].rule = "injection.proc_mem_write".into();
        let graph = Graph::build(&facts);
        assert!(has(
            &graph,
            &NodeKind::Process((401, 1)),
            &NodeKind::Process((430, 6)),
            EdgeKind::Injected
        ));
        assert!(!graph
            .nodes
            .iter()
            .any(|n| matches!(n.kind, NodeKind::Victim(_)) && n.label == "pid 430"));
    }

    #[test]
    fn tiers_mark_the_nodes_the_findings_involve() {
        let graph = Graph::build(&fixture());
        let tier = |kind: NodeKind| graph.nodes[at(&graph, kind)].tier;
        assert_eq!(tier(NodeKind::Process((401, 1))), Some(Tier::High));
        assert_eq!(tier(NodeKind::Victim(418)), Some(Tier::High));
        assert_eq!(
            tier(NodeKind::File("/tmp/.x/kdevtmpfsi".into())),
            Some(Tier::Medium)
        );
        // INFO is not a finding of the graph.
        assert_eq!(tier(NodeKind::Process((430, 6))), None);
    }

    #[test]
    fn edge_labels_are_the_plain_verb() {
        let all = [
            EdgeKind::Forked,
            EdgeKind::Execed,
            EdgeKind::Wrote,
            EdgeKind::Ran,
            EdgeKind::Connected,
            EdgeKind::Injected,
            EdgeKind::Signalled,
            EdgeKind::Member,
        ];
        let labels: Vec<_> = all.iter().map(|kind| kind.label()).collect();
        assert_eq!(
            labels,
            ["fork", "exec", "write", "run", "connect", "inject", "signal", "member"]
        );
    }

    #[test]
    fn target_pids_come_from_the_object() {
        assert_eq!(target_pid("pid 418 poke"), Some(418));
        assert_eq!(target_pid("pid 7"), Some(7));
        assert_eq!(target_pid("/proc/99/mem"), Some(99));
        assert_eq!(target_pid("/proc/self/mem"), None);
        assert_eq!(target_pid("kill"), None);
    }

    #[test]
    fn the_compact_view_takes_the_top_fifteen_of_each_kind_and_their_chains() {
        let mut facts = fixture();
        // Thirty quiet children of the sh, and one deep one with a HIGH finding.
        for n in 0..30u32 {
            facts
                .procs
                .push(proc(1000 + n, 100 + u64::from(n), Some((420, 4)), "ls"));
        }
        facts.procs.push(proc(2000, 200, Some((1029, 129)), "deep"));
        facts.findings.push(Fact {
            tier: Tier::High,
            rule: "persistence.cron".into(),
            object: "/etc/cron.d/x".into(),
            pid: 2000,
            cookie: 200,
        });
        // Twenty files and twenty endpoints the demo-all wrote and contacted.
        for n in 0..20 {
            facts.files.push(FileFact {
                path: format!("/tmp/f{n}"),
                roles: vec!["created".into()],
                process: Some((401, 1)),
            });
            facts.endpoints.push(EndpointFact {
                endpoint: format!("10.0.0.{n}:80"),
                process: Some((401, 1)),
            });
        }
        let graph = Graph::build(&facts);
        let picked = graph.compact(15);
        let count = |wanted: fn(&NodeKind) -> bool| {
            picked
                .iter()
                .filter(|&&at| wanted(&graph.nodes[at].kind))
                .count()
        };
        let name = |at: usize| graph.nodes[at].label.clone();
        let names: Vec<String> = picked.iter().map(|&at| name(at)).collect();
        // Files and endpoints: fifteen each (the kdevtmpfsi file is among the
        // files, the one endpoint of the fixture among the endpoints).
        assert_eq!(count(|k| matches!(k, NodeKind::File(_))), 15, "{names:?}");
        assert_eq!(
            count(|k| matches!(k, NodeKind::Endpoint(_))),
            15,
            "{names:?}"
        );
        assert!(names.contains(&"demo-all (401)".to_string()), "root");
        assert!(names.contains(&"deep (2000)".to_string()), "a HIGH process");
        // Its chain to the root is shown with it.
        assert!(names.contains(&"ls (1029)".to_string()), "{names:?}");
        assert!(names.contains(&"sh (420)".to_string()), "{names:?}");
        // The injected-into process is shown with the processes.
        assert!(names.contains(&"pid 418".to_string()), "{names:?}");
        // Processes: fifteen best, plus the chains that join them.
        let processes = count(|k| matches!(k, NodeKind::Process(_)));
        assert!((15..=15 + 4).contains(&processes), "{processes}");
        // Every picked node but the root has its anchor picked.
        for &at in &picked {
            if let Some(anchor) = graph.anchor(at) {
                assert!(picked.contains(&anchor), "{} lost its anchor", name(at));
            }
        }
        // A small graph is shown whole.
        let small = Graph::build(&fixture());
        assert_eq!(small.compact(15).len(), small.nodes.len());
    }

    #[test]
    fn processes_of_interest_lead_with_the_highest_tier_then_the_count() {
        let list = interest(&fixture(), 5);
        let labels: Vec<_> = list.iter().map(|i| i.label.as_str()).collect();
        assert_eq!(
            labels,
            ["demo-all (401)", "sh (420)"],
            "curl has an INFO row only"
        );
        assert_eq!(list[0].tier, Some(Tier::High));
        assert!(list[0].warn);
        assert_eq!(list[1].findings, 1);
        assert_eq!(interest(&fixture(), 1).len(), 1);
    }
}
