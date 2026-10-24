// SPDX-License-Identifier: GPL-3.0-only
//! The swimlanes: the process tree's depth-first order, one lane per process,
//! with leaf siblings of the same program folded into one lane.
use super::*;
use std::collections::HashMap;

/// Leaf siblings with the same image and arguments fold once there are this many.
pub(in crate::triage) const FOLD_MIN: usize = 8;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::triage) struct Lane {
    pub cookie: u64,
    pub pid: u32,
    /// The program's name, or `pid N` when it has none.
    pub name: String,
    pub depth: u16,
    pub first_ns: u64,
    pub last_ns: u64,
    /// The task's exit was recorded.
    pub exited: bool,
    /// Processes folded into this lane.
    pub members: u32,
    /// The lane after the last descendant: lanes `index..subtree_end` are this lane's subtree.
    pub subtree_end: u32,
    pub parent: Option<u32>,
}

/// What leaf siblings must share to fold: parent, program and arguments.
type Siblings<'a> = (Option<usize>, &'a str, &'a [String]);

/// Lane 0 stands for findings with no process of the run: the capture's own.
#[derive(Default)]
pub(in crate::triage) struct Lanes {
    pub list: Vec<Lane>,
    lookup: HashMap<(u64, u32), u32>,
    by_pid: HashMap<u32, Vec<u32>>,
}

impl Lanes {
    pub(in crate::triage) fn from_processes(nodes: &[ProcessNode]) -> Self {
        let mut lanes = Lanes::default();
        lanes.list.push(Lane {
            name: "VM-wide / not tied to a process".into(),
            members: 0,
            subtree_end: 1,
            ..Lane::default()
        });
        // The node each node hangs from, by depth.
        let mut stack: Vec<usize> = Vec::new();
        let mut parent = vec![None; nodes.len()];
        for (index, node) in nodes.iter().enumerate() {
            stack.truncate(node.depth);
            parent[index] = stack.last().copied();
            stack.push(index);
        }
        let leaf = |index: usize| {
            nodes
                .get(index + 1)
                .is_none_or(|next| next.depth <= nodes[index].depth)
        };
        // Leaf siblings of one program fold into the first of them.
        let mut groups: HashMap<Siblings, Vec<usize>> = HashMap::new();
        for (index, node) in nodes.iter().enumerate() {
            if leaf(index) && node.comm != "?" {
                groups
                    .entry((parent[index], node.comm.as_str(), node.argv.as_slice()))
                    .or_default()
                    .push(index);
            }
        }
        let mut folded_into: HashMap<usize, usize> = HashMap::new();
        for members in groups.values().filter(|members| members.len() >= FOLD_MIN) {
            for member in &members[1..] {
                folded_into.insert(*member, members[0]);
            }
        }
        let mut lane_of_node: Vec<Option<u32>> = vec![None; nodes.len()];
        for (index, node) in nodes.iter().enumerate() {
            if folded_into.contains_key(&index) {
                continue;
            }
            let lane = lanes.list.len() as u32;
            lane_of_node[index] = Some(lane);
            lanes.list.push(Lane {
                cookie: node.cookie,
                pid: node.pid,
                name: name(node),
                depth: (node.depth + 1).min(u16::MAX as usize) as u16,
                first_ns: node.first_ns.unwrap_or(0),
                last_ns: node.last_ns.unwrap_or(0),
                exited: node.state.starts_with("task exit"),
                members: 1,
                subtree_end: 0,
                parent: parent[index].and_then(|parent| lane_of_node[parent]),
            });
        }
        for (member, rep) in &folded_into {
            let Some(rep_lane) = lane_of_node[*rep] else {
                continue;
            };
            lane_of_node[*member] = Some(rep_lane);
            let node = &nodes[*member];
            let lane = &mut lanes.list[rep_lane as usize];
            lane.members += 1;
            lane.first_ns = match (lane.first_ns, node.first_ns) {
                (0, Some(time)) => time,
                (mine, Some(time)) => mine.min(time),
                (mine, None) => mine,
            };
            lane.last_ns = lane.last_ns.max(node.last_ns.unwrap_or(0));
            lane.exited &= node.state.starts_with("task exit");
        }
        // Subtree ends from the depths, which are in depth-first order.
        let count = lanes.list.len();
        for index in 1..count {
            let depth = lanes.list[index].depth;
            let end = (index + 1..count)
                .find(|next| lanes.list[*next].depth <= depth)
                .unwrap_or(count);
            lanes.list[index].subtree_end = end as u32;
        }
        for (index, node) in nodes.iter().enumerate() {
            if let Some(lane) = lane_of_node[index] {
                lanes.lookup.insert((node.cookie, node.pid), lane);
                lanes.by_pid.entry(node.pid).or_default().push(lane);
            }
        }
        lanes
    }

    /// The lane of a process; lane 0 when the run has no such process.
    pub(in crate::triage) fn lane_of(&self, cookie: u64, pid: u32) -> u32 {
        self.lookup.get(&(cookie, pid)).copied().unwrap_or(0)
    }

    /// The lane of `pid` that was alive at `ns`, else the latest one with that pid.
    pub(in crate::triage) fn lane_for_pid(&self, pid: u32, ns: u64) -> Option<u32> {
        let lanes = self.by_pid.get(&pid)?;
        lanes
            .iter()
            .copied()
            .find(|lane| {
                let lane = &self.list[*lane as usize];
                lane.first_ns <= ns && ns <= lane.last_ns
            })
            .or_else(|| lanes.last().copied())
    }

    /// The time the lanes span, when any of them has one.
    pub(in crate::triage) fn extent(&self) -> Option<(u64, u64)> {
        self.list
            .iter()
            .filter(|lane| lane.last_ns > 0)
            .map(|lane| (lane.first_ns, lane.last_ns))
            .reduce(|(lo, hi), (first, last)| (lo.min(first), hi.max(last)))
    }

    /// The cookies of a lane and everything under it.
    pub(in crate::triage) fn subtree_cookies(&self, lane: u32) -> Vec<u64> {
        let Some(root) = self.list.get(lane as usize) else {
            return Vec::new();
        };
        let mut cookies: Vec<u64> = self.list[lane as usize..root.subtree_end as usize]
            .iter()
            .map(|lane| lane.cookie)
            .filter(|cookie| *cookie != 0)
            .collect();
        cookies.sort_unstable();
        cookies.dedup();
        cookies
    }
}

fn basename(name: &str) -> &str {
    name.rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(name)
}

fn name(node: &ProcessNode) -> String {
    if node.comm == "?" {
        format!("pid {}", node.pid)
    } else {
        basename(&node.comm).to_owned()
    }
}

impl Lane {
    /// The name on the lane: `sh 1202`, or `miner ×64` for folded siblings.
    pub(in crate::triage) fn label(&self) -> String {
        match self.members {
            0 | 1 if self.name.starts_with("pid ") || self.pid == 0 => self.name.clone(),
            0 | 1 => format!("{} {}", self.name, self.pid),
            members => format!("{} ×{members}", self.name),
        }
    }
}

/// The rows of the lane list for the current collapse state.
pub(in crate::triage) struct Rows {
    /// The lane drawn on each row, top to bottom.
    pub lanes: Vec<u32>,
    /// For every lane, the row it is drawn on or the row of the collapsed lane
    /// that holds it; `u32::MAX` for a lane with no row (lane 0 when unused).
    pub row_of: Vec<u32>,
}

impl Rows {
    pub(in crate::triage) fn build(
        lanes: &Lanes,
        collapsed: &std::collections::BTreeSet<(u64, u32)>,
        lane0: bool,
    ) -> Self {
        let mut shown = Vec::new();
        let mut row_of = vec![u32::MAX; lanes.list.len()];
        let mut index = 0;
        while index < lanes.list.len() {
            let lane = &lanes.list[index];
            if index == 0 && !lane0 {
                index = 1;
                continue;
            }
            let row = shown.len() as u32;
            shown.push(index as u32);
            let end = lane.subtree_end.max(index as u32 + 1) as usize;
            if index > 0 && collapsed.contains(&(lane.cookie, lane.pid)) && end > index + 1 {
                for hidden in index..end.min(row_of.len()) {
                    row_of[hidden] = row;
                }
                index = end;
            } else {
                row_of[index] = row;
                index += 1;
            }
        }
        Self {
            lanes: shown,
            row_of,
        }
    }

    pub(in crate::triage) fn is_collapsed(&self, lanes: &Lanes, row: usize) -> bool {
        self.lanes.get(row).is_some_and(|lane| {
            let lane = *lane as usize;
            lanes.list[lane].subtree_end as usize > lane + 1
                && self
                    .row_of
                    .get(lane + 1)
                    .is_some_and(|other| *other == row as u32)
        })
    }
}
