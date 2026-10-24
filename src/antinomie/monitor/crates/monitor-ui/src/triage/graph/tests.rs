// SPDX-License-Identifier: GPL-3.0-only
//! The graph: the index and its pyramid, phases, lanes, filter text, hit
//! testing, the keyboard and mouse through a real egui pass, the filter sync
//! with the Suspicious table, the contrast of every theme and the live toast.
use super::filter::Parts;
use super::index::{Builder, GraphIndex, Record, HOLLOW, NO_PHASE};
use super::input::{self, Action, Hit, Layout};
use super::lanes::{Lanes, Rows, FOLD_MIN};
use super::paint::{contrast, Colors};
use super::phases::{self, Phase};
use super::view::{self, Drag, State};
use super::widget::{self, Config};
use super::*;
use crate::theme::Theme;
use crate::triage::rules::{Category, Tier};
use eframe::egui::{Event, Key, Modifiers, PointerButton, Pos2, Rect};

const S: u64 = 1_000_000_000;
const SF: f64 = 1e9;

pub(super) fn node(
    depth: usize,
    pid: u32,
    cookie: u64,
    comm: &str,
    first: u64,
    last: u64,
) -> ProcessNode {
    ProcessNode {
        parent: None,
        call_id: None,
        depth,
        pid,
        cookie,
        comm: comm.into(),
        parent_missing: false,
        tid: pid,
        argv: Vec::new(),
        first_ns: Some(first),
        last_ns: Some(last),
        state: "exit not recorded".into(),
        exec_history: Vec::new(),
    }
}

pub(super) fn record(ns: u64, lane: u32, tier: Tier, category: Category) -> Record {
    Record {
        first_ns: ns,
        last_ns: ns,
        count: 1,
        lane,
        tier: tier.index() as u8,
        category: category.index() as u8,
        phase: phases::phase_of("", category).map_or(NO_PHASE, |phase| phase.index() as u8),
        flags: 0,
    }
}

/// A dropper that starts `sh`, which starts `curl`; a hidden `.x` reached later.
pub(super) fn scene_nodes() -> Vec<ProcessNode> {
    let mut curl = node(2, 1203, 13, "/usr/bin/curl", 3 * S, 10 * S);
    curl.state = "task exit 0".into();
    vec![
        node(0, 1201, 11, "/tmp/dropper", S, 40 * S),
        node(1, 1202, 12, "/bin/sh", 2 * S, 30 * S),
        curl,
        node(1, 1204, 14, "/tmp/.x", 20 * S, 40 * S),
    ]
}

/// Lanes: 0 unattributed, 1 dropper, 2 sh, 3 curl, 4 .x.
pub(super) fn scene() -> GraphIndex {
    let mut builder = Builder::new(Lanes::from_processes(&scene_nodes())).without_rows();
    builder.push_record(record(2 * S, 1, Tier::Low, Category::Execution));
    builder.push_record(record(5 * S, 3, Tier::High, Category::Execution));
    builder.push_record(record(6 * S, 2, Tier::Medium, Category::Persistence));
    builder.push_record(record(25 * S, 4, Tier::High, Category::Command));
    builder.push_record(record(26 * S, 4, Tier::Low, Category::Evasion));
    builder.push_record(record(27 * S, 4, Tier::High, Category::Injection));
    builder.inject_into(1202);
    builder.finish()
}

#[test]
fn a_record_is_32_bytes_and_a_cell_32_so_the_index_stays_under_48_bytes_a_finding() {
    assert_eq!(std::mem::size_of::<Record>(), 32);
    assert_eq!(std::mem::size_of::<index::Cell>(), 32);
}

#[test]
fn every_level_of_the_pyramid_holds_every_finding_once() {
    let index = scene();
    let geometry = index.geometry();
    assert!(geometry.buckets() as u64 <= index::L0_BUCKETS);
    assert_eq!(index.cells.len(), index.stored.len());
    assert_eq!(index.stored[0], 0, "the base level is always kept");
    assert!(index.stored.windows(2).all(|pair| pair[0] < pair[1]));
    for (level, cells) in index.cells.iter().enumerate() {
        let total: u32 = cells.iter().map(index::Cell::total).sum();
        assert_eq!(total as usize, index.records.len(), "level {level}");
        assert!(
            cells
                .windows(2)
                .all(|pair| (pair[0].lane, pair[0].bucket) < (pair[1].lane, pair[1].bucket)),
            "level {level} is sorted by lane and bucket with no cell twice"
        );
    }
    for bins in &index.bins {
        let binned: u32 = bins.iter().map(|bin| bin.tiers.iter().sum::<u32>()).sum();
        assert_eq!(binned as usize, index.records.len());
    }
    assert_eq!(index.bins.len(), geometry.levels());
    // One bucket for the whole run at the top.
    assert_eq!(index.bins.last().map(Vec::len), Some(1));
    assert_eq!(index.tiers, [3, 1, 2, 0]);
}

#[test]
fn the_level_drawn_from_is_the_coarsest_kept_one_not_coarser_than_asked() {
    let index = synthetic_spread();
    // Many findings in few lanes: every level halves, so every level is kept.
    assert!(index.stored.len() > 3, "{:?}", index.stored);
    for asked in 0..index.geometry().levels() {
        let (slot, level) = index.kept_level(asked);
        assert_eq!(index.stored[slot], level);
        assert!(level <= asked);
        assert!(index.stored.get(slot + 1).is_none_or(|next| *next > asked));
    }
}

fn synthetic_spread() -> GraphIndex {
    let mut builder = Builder::new(Lanes::from_processes(&scene_nodes())).without_rows();
    for n in 0..20_000u64 {
        builder.push_record(record(
            S + n * 1_000_000,
            1 + (n % 4) as u32,
            Tier::Low,
            Category::Discovery,
        ));
    }
    builder.finish()
}

#[test]
fn a_cell_keeps_the_worst_tier_the_category_of_it_and_the_first_finding() {
    let mut builder = Builder::new(Lanes::default()).without_rows();
    builder.push_record(record(10, 0, Tier::Low, Category::Discovery));
    builder.push_record(record(11, 0, Tier::High, Category::Command));
    builder.push_record(record(12, 0, Tier::High, Category::Impact));
    builder.push_record(record(5000, 0, Tier::Info, Category::Execution));
    let index = builder.finish();
    let top = index.cells.last().unwrap();
    assert_eq!(top.len(), 1);
    let cell = top[0];
    assert_eq!(cell.counts, [2, 0, 1, 1]);
    assert_eq!(cell.top, Tier::High.index() as u8);
    assert_eq!(
        cell.lead,
        Category::Command.index() as u8,
        "the first of the worst tier"
    );
    assert_eq!(cell.first, 0);
    assert_eq!(cell.cats.count_ones(), 4);
}

#[test]
fn records_given_out_of_order_are_sorted_with_their_injection_edges() {
    let mut builder = Builder::new(Lanes::from_processes(&scene_nodes())).without_rows();
    builder.push_record(record(30 * S, 3, Tier::Low, Category::Discovery));
    builder.push_record(record(7 * S, 4, Tier::High, Category::Injection));
    builder.inject_into(1202);
    builder.push_record(record(2 * S, 1, Tier::Low, Category::Execution));
    let index = builder.finish();
    let times: Vec<u64> = index.records.iter().map(|record| record.first_ns).collect();
    assert_eq!(times, [2 * S, 7 * S, 30 * S]);
    // The injector moved to index 1; the edge follows it to .x's target, sh.
    assert_eq!(index.injections.len(), 1);
    assert_eq!(index.injections[0].record, 1);
    assert_eq!(index.injections[0].target, 2);
}

#[test]
fn injection_edges_reach_the_lane_of_the_pid_acted_on() {
    let index = scene();
    assert_eq!(index.injections.len(), 1);
    let edge = index.injections[0];
    assert_eq!(index.records[edge.record as usize].lane, 4);
    assert_eq!(index.lanes.list[edge.target as usize].pid, 1202);
}

#[test]
fn level_for_picks_the_level_where_a_bucket_is_wide_enough() {
    let index = scene();
    let geometry = index.geometry();
    let ns_per_px = (geometry.end - geometry.origin) as f64 / 1000.0;
    let level = index.level_for(ns_per_px, 3.0);
    assert!(geometry.width(level) / ns_per_px >= 3.0 || level == geometry.levels() - 1);
    if level > 0 {
        assert!(geometry.width(level - 1) / ns_per_px < 3.0);
    }
    // Zoomed far in, level 0 is already wider than 3 px.
    assert_eq!(index.level_for(0.001, 3.0), 0);
}

#[test]
fn an_overview_keeps_the_sums_over_time_and_nothing_else() {
    let mut builder = Builder::overview();
    builder.push_record(record(S, 0, Tier::High, Category::Command));
    builder.push_record(record(2 * S, 0, Tier::Low, Category::Discovery));
    let overview = builder.finish();
    assert!(overview.records.is_empty() && overview.cells.is_empty() && overview.rows.is_empty());
    assert_eq!(overview.tiers, [1, 0, 1, 0]);
    assert!(!overview.bins.is_empty());
}

// ----- phases -----

fn run_with(items: &[(u64, Tier, Category, &str)], span_ns: u64) -> GraphIndex {
    let mut builder = Builder::overview();
    for (ns, tier, category, rule) in items {
        let mut item = record(*ns, 0, *tier, *category);
        item.phase =
            phases::phase_of(rule, *category).map_or(NO_PHASE, |phase| phase.index() as u8);
        builder.push_record(item);
    }
    // Pin the run's extent with two quiet INFO rows that belong to no phase.
    builder.push_record(record(1, 0, Tier::Info, Category::Execution));
    builder.push_record(record(span_ns, 0, Tier::Info, Category::Execution));
    builder.finish()
}

fn labels(index: &GraphIndex) -> Vec<&'static str> {
    index.phases.iter().map(|span| span.phase.label()).collect()
}

#[test]
fn a_lone_medium_cannot_label_a_phase_but_a_high_can() {
    let medium = run_with(&[(500, Tier::Medium, Category::Persistence, "")], 1000);
    assert!(
        medium.phases.is_empty(),
        "weight 4 is below the threshold of 5"
    );
    let high = run_with(&[(500, Tier::High, Category::Persistence, "")], 1000);
    assert_eq!(labels(&high), ["persistence"]);
}

#[test]
fn a_phase_needs_corroboration_the_way_the_design_says() {
    let m = |ns| (ns, Tier::Medium, Category::Persistence, "");
    let l = |ns| (ns, Tier::Low, Category::Persistence, "");
    // A MEDIUM with one LOW is 5.
    assert_eq!(labels(&run_with(&[m(500), l(501)], 1000)), ["persistence"]);
    // Two MEDIUMs are 8.
    assert_eq!(labels(&run_with(&[m(500), m(501)], 1000)), ["persistence"]);
    // Five LOWs are 5; four are not.
    let five: Vec<_> = (0..5).map(|n| l(500 + n)).collect();
    assert_eq!(labels(&run_with(&five, 1000)), ["persistence"]);
    assert!(run_with(&five[..4], 1000).phases.is_empty());
}

#[test]
fn categories_map_to_the_phases_of_the_design() {
    let cases = [
        ("", Category::Discovery, Some(Phase::Recon)),
        (
            "evasion.sandbox_probe",
            Category::Evasion,
            Some(Phase::Recon),
        ),
        ("evasion.self_delete", Category::Evasion, None),
        (
            "execution.download_cradle",
            Category::Execution,
            Some(Phase::Download),
        ),
        ("c2.elf_download", Category::Command, Some(Phase::Download)),
        ("execution.temp_exec", Category::Execution, None),
        ("", Category::Persistence, Some(Phase::Persistence)),
        ("", Category::Privilege, Some(Phase::Escalation)),
        ("", Category::Injection, Some(Phase::Hide)),
        ("", Category::Rootkit, Some(Phase::Hide)),
        ("", Category::Command, Some(Phase::C2)),
        ("", Category::Exfiltration, Some(Phase::C2)),
        ("", Category::Lateral, Some(Phase::Spread)),
        ("", Category::Impact, Some(Phase::Impact)),
        ("", Category::Credential, None),
    ];
    for (rule, category, phase) in cases {
        assert_eq!(
            phases::phase_of(rule, category),
            phase,
            "{rule} {category:?}"
        );
    }
}

#[test]
fn a_run_reads_as_phases_in_order_and_a_short_blip_is_absorbed() {
    let mut items = Vec::new();
    for n in 0..40 {
        items.push((5_000 + 500 * n, Tier::High, Category::Discovery, ""));
        items.push((30_000 + 500 * n, Tier::High, Category::Persistence, ""));
        items.push((55_000 + 500 * n, Tier::High, Category::Command, ""));
    }
    // A single HIGH impact amid the C2 stretch lasts 400 ns of 100,000: under
    // 2 % of the run, so it is absorbed.
    items.push((62_100, Tier::High, Category::Impact, ""));
    let index = run_with(&items, 100_000);
    assert_eq!(labels(&index), ["recon", "persistence", "C2"]);
    assert!(index.phases.len() <= phases::MAX_SPANS);
}

#[test]
fn at_most_eight_phases_are_labelled() {
    let mut items = Vec::new();
    let categories = [
        Category::Discovery,
        Category::Persistence,
        Category::Privilege,
        Category::Injection,
        Category::Command,
        Category::Lateral,
        Category::Impact,
    ];
    for round in 0..4u64 {
        for (at, category) in categories.iter().enumerate() {
            let base = (round * 7 + at as u64) * 2_000;
            for n in 0..10 {
                items.push((base + n, Tier::High, *category, ""));
            }
        }
    }
    let index = run_with(&items, 60_000);
    assert!(
        index.phases.len() <= phases::MAX_SPANS,
        "{:?}",
        labels(&index)
    );
    assert!(index.phases.len() >= 2);
}

#[test]
fn a_recon_span_of_info_matches_needs_twenty_of_them() {
    let mut builder = Builder::overview();
    builder.count_info(500, 19, "discovery.process_enum", Category::Discovery);
    builder.push_record(record(1, 0, Tier::Info, Category::Execution));
    builder.push_record(record(1000, 0, Tier::Info, Category::Execution));
    assert!(
        builder.finish().phases.is_empty(),
        "19 INFO matches are not a phase"
    );
    let mut builder = Builder::overview();
    builder.count_info(500, 20, "discovery.process_enum", Category::Discovery);
    builder.push_record(record(1, 0, Tier::Info, Category::Execution));
    builder.push_record(record(1000, 0, Tier::Info, Category::Execution));
    assert_eq!(labels(&builder.finish()), ["recon"]);
}

// ----- lanes -----

#[test]
fn lanes_follow_the_process_tree_and_know_their_subtrees() {
    let lanes = Lanes::from_processes(&scene_nodes());
    let names: Vec<String> = lanes.list.iter().map(|lane| lane.label()).collect();
    assert_eq!(
        names,
        [
            "VM-wide / not tied to a process",
            "dropper 1201",
            "sh 1202",
            "curl 1203",
            ".x 1204"
        ]
    );
    assert_eq!(lanes.list[1].subtree_end, 5);
    assert_eq!(lanes.list[2].subtree_end, 4);
    assert_eq!(lanes.list[3].parent, Some(2));
    assert_eq!(lanes.list[4].parent, Some(1));
    assert!(lanes.list[3].exited && !lanes.list[2].exited);
    assert_eq!(lanes.lane_of(13, 1203), 3);
    assert_eq!(
        lanes.lane_of(99, 5),
        0,
        "an unknown process is not tied to a lane"
    );
    assert_eq!(lanes.subtree_cookies(2), [12, 13]);
}

#[test]
fn leaf_siblings_of_one_program_fold_into_one_lane() {
    let mut nodes = vec![node(0, 100, 1, "/usr/bin/miner", S, 9 * S)];
    for n in 0..FOLD_MIN as u32 + 4 {
        let mut kid = node(
            1,
            200 + n,
            2 + u64::from(n),
            "/tmp/kworkerds",
            S + u64::from(n),
            5 * S + u64::from(n),
        );
        kid.argv = vec!["kworkerds".into(), "-o".into()];
        nodes.push(kid);
    }
    nodes.push(node(1, 300, 99, "/bin/sh", 2 * S, 3 * S));
    let lanes = Lanes::from_processes(&nodes);
    assert_eq!(
        lanes.list.len(),
        1 + 3,
        "unattributed, the miner, one folded lane and sh"
    );
    let folded = lanes.list.iter().find(|lane| lane.members > 1).unwrap();
    assert_eq!(folded.label(), format!("kworkerds ×{}", FOLD_MIN + 4));
    // Every member finds its way to the folded lane.
    assert_eq!(
        lanes.lane_of(2, 200),
        lanes.lane_of(2 + FOLD_MIN as u64 + 3, 200 + FOLD_MIN as u32 + 3)
    );
    // Fewer than the minimum stay apart.
    let few = Lanes::from_processes(&nodes[..FOLD_MIN]);
    assert!(few.list.iter().all(|lane| lane.members <= 1));
}

#[test]
fn collapsing_a_lane_puts_its_descendants_on_its_row() {
    let index = scene();
    let none = std::collections::BTreeSet::new();
    let open = Rows::build(&index.lanes, &none, true);
    assert_eq!(open.lanes, [0, 1, 2, 3, 4]);
    let collapsed: std::collections::BTreeSet<_> = [(12, 1202)].into();
    let rows = Rows::build(&index.lanes, &collapsed, true);
    assert_eq!(rows.lanes, [0, 1, 2, 4]);
    assert_eq!(rows.row_of[3], rows.row_of[2], "curl is drawn on sh's row");
    assert!(rows.is_collapsed(&index.lanes, 2));
    assert!(!rows.is_collapsed(&index.lanes, 3));
    // Lane 0 has no row when no finding is outside the process tree.
    assert_eq!(Rows::build(&index.lanes, &none, false).lanes, [1, 2, 3, 4]);
}

// ----- filter text -----

#[test]
fn a_brush_and_a_lane_are_written_after_what_the_user_typed_and_read_back() {
    let typed = "finding.tier == high";
    let parts = Parts {
        base: typed.into(),
        cookies: vec![12, 13],
        brush: Some((5, 90)),
    };
    let text = parts.render();
    assert_eq!(
        text,
        "finding.tier == high && (process.cookie == 12 || process.cookie == 13) && event.time_ns >= 5 && event.time_ns <= 90"
    );
    assert_eq!(Parts::parse(&text), parts);
    // Clearing the brush leaves the rest.
    let mut cleared = Parts::parse(&text);
    cleared.brush = None;
    assert_eq!(
        cleared.render(),
        "finding.tier == high && (process.cookie == 12 || process.cookie == 13)"
    );
    // A second brush replaces the first instead of stacking.
    let mut again = Parts::parse(&text);
    again.brush = Some((7, 8));
    assert_eq!(again.render().matches("event.time_ns >=").count(), 1);
}

#[test]
fn an_or_in_the_users_filter_is_grouped_before_the_graph_adds_to_it() {
    let parts = Parts {
        base: "finding.rule == \"a\" || finding.rule == \"b\"".into(),
        cookies: vec![],
        brush: Some((1, 2)),
    };
    let text = parts.render();
    assert!(
        text.starts_with("(finding.rule == \"a\" || finding.rule == \"b\") && "),
        "{text}"
    );
    assert_eq!(Parts::parse(&text), parts, "the group is taken off again");
    // A filter that only looks like ours is left alone.
    let odd = Parts::parse("event.time_ns >= x && event.time_ns <= 9");
    assert_eq!(odd.brush, None);
    assert_eq!(Parts::parse("").render(), "");
    assert_eq!(Parts::parse("  ").render(), "");
    for text in [
        Parts {
            base: String::new(),
            cookies: vec![4],
            brush: None,
        },
        Parts {
            base: String::new(),
            cookies: vec![],
            brush: Some((3, 4)),
        },
    ] {
        assert_eq!(Parts::parse(&text.render()), text);
    }
}

#[test]
fn the_rendered_filter_compiles_in_the_tables_language() {
    let text = Parts {
        base: "finding.tier == high".into(),
        cookies: vec![12, 13],
        brush: Some((5, 90)),
    }
    .render();
    let compiled = query::compile_table(&text, FINDING_FIELDS);
    assert!(compiled.error.is_none(), "{:?}", compiled.error);
    let row = |cookie: i128, ns: i128| {
        vec![
            ("finding.tier", RowValue::Text("high".into())),
            ("process.cookie", RowValue::Number(cookie)),
            ("event.time_ns", RowValue::Number(ns)),
        ]
    };
    assert!(compiled.keep_table(&row(12, 5)));
    assert!(compiled.keep_table(&row(13, 90)));
    assert!(!compiled.keep_table(&row(14, 50)), "another lane");
    assert!(!compiled.keep_table(&row(12, 91)), "after the brush");
}

// ----- hit testing -----

const SIZE: egui::Vec2 = egui::vec2(1100.0, 640.0);
const WIDGET_HEIGHT: f32 = 520.0;

fn layout_of(index: &GraphIndex, state: &State) -> Layout {
    Layout::new(
        Rect::from_min_size(Pos2::new(8.0, 8.0), egui::vec2(1084.0, WIDGET_HEIGHT)),
        state,
        index,
    )
}

/// Where a record's marker is drawn.
fn marker_pos(layout: &Layout, index: &GraphIndex, at: usize) -> Pos2 {
    let record = &index.records[at];
    Pos2::new(
        layout.frame.x(record.first_ns as f64),
        layout.row_center(layout.row_of(record.lane).unwrap()),
    )
}

#[test]
fn a_point_on_a_marker_hits_it_and_one_far_from_any_hits_nothing() {
    let index = scene();
    let state = State::default();
    let layout = layout_of(&index, &state);
    for at in 0..index.records.len() {
        let pos = marker_pos(&layout, &index, at);
        assert_eq!(
            input::hit_test(&layout, &index, 10.0, pos),
            Some(Hit::Marker {
                record: at,
                near: 1
            }),
            "record {at}"
        );
    }
    let pos = marker_pos(&layout, &index, 1);
    assert_eq!(
        input::hit_test(&layout, &index, 10.0, pos + egui::vec2(30.0, 0.0)),
        None
    );
    assert!(
        !input::hit_test(&layout, &index, 10.0, pos + egui::vec2(0.0, 20.0))
            .is_some_and(|hit| matches!(hit, Hit::Marker { .. })),
        "the row below holds another lane"
    );
}

#[test]
fn where_two_findings_overlap_the_worst_is_hit_and_the_rest_are_counted() {
    let mut builder = Builder::new(Lanes::from_processes(&scene_nodes())).without_rows();
    builder.push_record(record(10 * S, 2, Tier::Low, Category::Discovery));
    builder.push_record(record(10 * S + 1, 2, Tier::High, Category::Command));
    builder.push_record(record(10 * S + 2, 2, Tier::Medium, Category::Impact));
    builder.push_record(record(40 * S, 4, Tier::Low, Category::Execution));
    let index = builder.finish();
    let layout = layout_of(&index, &State::default());
    let pos = marker_pos(&layout, &index, 0);
    assert_eq!(
        input::hit_test(&layout, &index, 10.0, pos),
        Some(Hit::Marker { record: 1, near: 3 })
    );
    let lines = input::tooltip(&index, 1, 3, None);
    assert!(
        lines
            .iter()
            .any(|line| line.contains("HIGH") && line.contains("Command & control")),
        "{lines:?}"
    );
    assert!(lines.iter().any(|line| line.contains("3 findings")));
}

#[test]
fn a_collapsed_lane_answers_for_its_descendants() {
    let index = scene();
    let mut state = State::default();
    state.collapsed.insert((12, 1202));
    let layout = layout_of(&index, &state);
    // Record 1 is curl's; curl is drawn on sh's row now.
    let pos = marker_pos(&layout, &index, 1);
    assert_eq!(layout.row_of(3), layout.row_of(2));
    assert_eq!(
        input::hit_test(&layout, &index, 10.0, pos),
        Some(Hit::Marker { record: 1, near: 1 })
    );
}

#[test]
fn names_chevrons_the_axis_the_phase_band_and_fit_are_told_apart() {
    let mut builder = Builder::new(Lanes::from_processes(&scene_nodes())).without_rows();
    for n in 0..30 {
        builder.push_record(Record {
            phase: Phase::C2.index() as u8,
            ..record(20 * S + n * 100_000_000, 4, Tier::High, Category::Command)
        });
    }
    let index = builder.finish();
    assert_eq!(labels(&index), ["C2"]);
    let layout = layout_of(&index, &State::default());
    let frame = &layout.frame;
    let name_at = |row: usize, dx: f32| Pos2::new(frame.labels.left() + dx, layout.row_center(row));
    // Row 0 is dropper (lane 0 is unused here), which has children.
    assert_eq!(layout.rows.lanes[0], 1);
    assert_eq!(
        input::hit_test(&layout, &index, 10.0, name_at(0, 8.0)),
        Some(Hit::Chevron { row: 0 })
    );
    assert_eq!(
        input::hit_test(&layout, &index, 10.0, name_at(0, 60.0)),
        Some(Hit::LaneName { row: 0 })
    );
    // A leaf has no chevron to hit.
    assert_eq!(
        input::hit_test(&layout, &index, 10.0, name_at(2, 18.0)),
        Some(Hit::LaneName { row: 2 })
    );
    assert_eq!(
        input::hit_test(
            &layout,
            &index,
            10.0,
            Pos2::new(frame.plot.center().x, frame.axis.center().y)
        ),
        Some(Hit::Axis)
    );
    assert_eq!(
        input::hit_test(&layout, &index, 10.0, layout.fit.center()),
        Some(Hit::Fit)
    );
    let span = index.phases[0];
    let mid = (index.geometry().start(0, span.first as usize)
        + index.geometry().start(0, span.last as usize))
        / 2.0;
    assert_eq!(
        input::hit_test(
            &layout,
            &index,
            10.0,
            Pos2::new(frame.x(mid), frame.phases.center().y)
        ),
        Some(Hit::Phase { span: 0 })
    );
}

#[test]
fn zoom_pan_and_the_window_stay_inside_the_run() {
    let bounds = view::bounds((0, 10 * S));
    let fit = view::fitted((0, 10 * S));
    let zoomed = view::zoomed(fit, 5.0 * SF, 4.0, bounds);
    assert!(((zoomed.1 - zoomed.0) * 4.0 - (fit.1 - fit.0)).abs() < 1e-6);
    // The anchor stays where it was on the screen.
    let share = |window: (f64, f64)| (5.0 * SF - window.0) / (window.1 - window.0);
    assert!((share(zoomed) - share(fit)).abs() < 1e-9);
    // Zooming out past the run stops at the run.
    let out = view::zoomed(zoomed, 5.0 * SF, 0.0001, bounds);
    assert_eq!(out, bounds);
    // Panning cannot leave the run.
    let panned = view::panned(zoomed, -1e12, bounds);
    assert_eq!(panned.0, bounds.0);
    // The shortest window is a microsecond.
    let tiny = view::zoomed(zoomed, 5.0 * SF, 1e12, bounds);
    assert!((tiny.1 - tiny.0 - view::MIN_SPAN_NS).abs() < 1e-6);
    assert_eq!(view::tick_step(1_000_000.0, 100.0), 100_000_000.0);
}

// ----- the widget through egui -----

struct Harness {
    ctx: egui::Context,
    state: State,
    time: f64,
    rect: Rect,
    /// Held down while the next frames run.
    modifiers: Modifiers,
}

impl Harness {
    fn new() -> Self {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        Self {
            ctx,
            state: State::default(),
            time: 0.0,
            rect: Rect::NOTHING,
            modifiers: Modifiers::NONE,
        }
    }

    fn frame(&mut self, index: &GraphIndex, events: Vec<Event>) -> Vec<Action> {
        self.time += 0.03;
        let mut actions = Vec::new();
        let (state, rect) = (&mut self.state, &mut self.rect);
        let _ = self.ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
                events,
                modifiers: self.modifiers,
                time: Some(self.time),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    *rect = Rect::from_min_size(
                        ui.available_rect_before_wrap().min,
                        egui::vec2(ui.available_width(), WIDGET_HEIGHT),
                    );
                    let config = Config {
                        index,
                        colors: Colors::of(Theme::Dark.palette()),
                        clock: None,
                        height: WIDGET_HEIGHT,
                    };
                    actions = widget::show(ui, state, &config);
                });
            },
        );
        actions
    }

    fn layout(&self, index: &GraphIndex) -> Layout {
        Layout::new(self.rect, &self.state, index)
    }

    fn press(&mut self, index: &GraphIndex, pos: Pos2, pressed: bool) -> Vec<Action> {
        self.frame(
            index,
            vec![
                Event::PointerMoved(pos),
                Event::PointerButton {
                    pos,
                    button: PointerButton::Primary,
                    pressed,
                    modifiers: Modifiers::NONE,
                },
            ],
        )
    }

    fn click(&mut self, index: &GraphIndex, pos: Pos2) -> Vec<Action> {
        self.press(index, pos, true);
        let actions = self.press(index, pos, false);
        self.time += 1.0;
        actions
    }

    fn key(&mut self, index: &GraphIndex, key: Key) -> Vec<Action> {
        self.key_with(index, key, Modifiers::NONE)
    }

    fn key_with(&mut self, index: &GraphIndex, key: Key, modifiers: Modifiers) -> Vec<Action> {
        let event = |pressed| Event::Key {
            key,
            physical_key: Some(key),
            pressed,
            repeat: false,
            modifiers,
        };
        let actions = self.frame(index, vec![event(true)]);
        self.frame(index, vec![event(false)]);
        actions
    }

    /// Draw once so the area is known, then click the marker of `at` to focus the graph.
    fn focus_on(&mut self, index: &GraphIndex, at: usize) {
        self.frame(index, vec![]);
        let pos = marker_pos(&self.layout(index), index, at);
        self.click(index, pos);
        self.frame(index, vec![]);
    }
}

#[test]
fn clicking_a_marker_selects_it_and_double_clicking_opens_it() {
    let index = scene();
    let mut harness = Harness::new();
    harness.frame(&index, vec![]);
    let pos = marker_pos(&harness.layout(&index), &index, 3);
    let actions = harness.click(&index, pos);
    assert_eq!(
        actions,
        [Action::Select {
            record: 3,
            focus: true
        }]
    );
    assert_eq!(harness.state.selected, Some(3));
    // Two clicks in quick succession are a double click.
    let target = marker_pos(&harness.layout(&index), &index, 5);
    let mut actions = Vec::new();
    for pressed in [true, false, true, false] {
        actions = harness.press(&index, target, pressed);
    }
    assert!(actions.contains(&Action::Open(5)), "{actions:?}");
}

#[test]
fn clicking_a_lane_name_filters_to_the_lane_and_shift_adds_its_descendants() {
    let index = scene();
    let mut harness = Harness::new();
    harness.frame(&index, vec![]);
    let layout = harness.layout(&index);
    let name = Pos2::new(layout.frame.labels.left() + 70.0, layout.row_center(1));
    assert_eq!(
        harness.click(&index, name),
        [Action::Lane { cookies: vec![12] }]
    );
    // Shift-click takes sh and everything under it.
    harness.modifiers = Modifiers::SHIFT;
    assert_eq!(
        harness.click(&index, name),
        [Action::Lane {
            cookies: vec![12, 13]
        }]
    );
}

#[test]
fn clicking_a_chevron_folds_the_lane_and_the_row_count_drops() {
    let index = scene();
    let mut harness = Harness::new();
    harness.frame(&index, vec![]);
    let layout = harness.layout(&index);
    // Row 1 is sh, one level down: its chevron sits one indent in.
    let chevron = Pos2::new(
        layout.frame.labels.left() + 4.0 + 5.0 + 10.0,
        layout.row_center(1),
    );
    assert!(harness.click(&index, chevron).is_empty());
    assert!(harness.state.collapsed.contains(&(12, 1202)));
    assert_eq!(
        harness.layout(&index).rows.lanes.len(),
        layout.rows.lanes.len() - 1
    );
    harness.click(&index, chevron);
    assert!(harness.state.collapsed.is_empty());
}

#[test]
fn dragging_on_the_axis_brushes_a_range_and_escape_clears_it() {
    let index = scene();
    let mut harness = Harness::new();
    harness.frame(&index, vec![]);
    let frame = harness.layout(&index).frame;
    let y = frame.axis.center().y;
    let (from, to) = (
        Pos2::new(frame.x(10.0 * SF), y),
        Pos2::new(frame.x(20.0 * SF), y),
    );
    harness.press(&index, from, true);
    harness.frame(
        &index,
        vec![Event::PointerMoved(Pos2::new(from.x + 30.0, y))],
    );
    harness.frame(&index, vec![Event::PointerMoved(to)]);
    assert!(matches!(harness.state.drag, Some(Drag::Brush { .. })));
    let actions = harness.press(&index, to, false);
    let Some(Action::Brush(a, b)) = actions.first().cloned() else {
        panic!("a brush was expected: {actions:?}");
    };
    assert!(
        a < b && (a as f64 - 10.0 * SF).abs() < 0.1 * SF && (b as f64 - 20.0 * SF).abs() < 0.1 * SF
    );
    assert_eq!(harness.state.brush, Some((a, b)));
    assert!(harness.state.drag.is_none());
    // Escape clears it (the graph has focus after the click on its axis).
    harness.frame(&index, vec![]);
    assert_eq!(harness.key(&index, Key::Escape), [Action::ClearBrush]);
    assert_eq!(harness.state.brush, None);
}

#[test]
fn a_tiny_drag_on_the_axis_is_not_a_brush() {
    let index = scene();
    let mut harness = Harness::new();
    harness.frame(&index, vec![]);
    let frame = harness.layout(&index).frame;
    let at = Pos2::new(frame.plot.center().x, frame.axis.center().y);
    harness.press(&index, at, true);
    harness.frame(&index, vec![Event::PointerMoved(at + egui::vec2(2.0, 0.0))]);
    let actions = harness.press(&index, at + egui::vec2(2.0, 0.0), false);
    assert!(actions
        .iter()
        .all(|action| !matches!(action, Action::Brush(..))));
}

#[test]
fn double_clicking_the_axis_zooms_two_times_at_the_pointer() {
    let index = scene();
    let mut harness = Harness::new();
    harness.frame(&index, vec![]);
    let frame = harness.layout(&index).frame;
    let at = Pos2::new(frame.x(25.0 * SF), frame.axis.center().y);
    for pressed in [true, false, true, false] {
        harness.press(&index, at, pressed);
    }
    let window = harness.state.window.expect("zoomed");
    assert!(((frame.t1 - frame.t0) / (window.1 - window.0) - 2.0).abs() < 1e-6);
    assert!(window.0 < 25.0 * SF && 25.0 * SF < window.1);
}

#[test]
fn ctrl_wheel_zooms_shift_wheel_pans_and_the_wheel_scrolls_lanes() {
    let index = scene();
    let mut harness = Harness::new();
    harness.frame(&index, vec![]);
    let frame = harness.layout(&index).frame;
    let over = Pos2::new(frame.plot.center().x, frame.lanes.center().y);
    let wheel = |delta: egui::Vec2, modifiers| Event::MouseWheel {
        unit: egui::MouseWheelUnit::Line,
        delta,
        modifiers,
    };
    harness.frame(&index, vec![Event::PointerMoved(over)]);
    harness.modifiers = Modifiers::CTRL;
    harness.frame(&index, vec![wheel(egui::vec2(0.0, 3.0), Modifiers::CTRL)]);
    harness.modifiers = Modifiers::NONE;
    // The wheel's step is spread over a few frames; let it finish.
    for _ in 0..30 {
        harness.frame(&index, vec![]);
    }
    let zoomed = harness.state.window.expect("Ctrl+wheel zoomed");
    assert!(zoomed.1 - zoomed.0 < frame.t1 - frame.t0, "zoomed in");
    // Shift+wheel moves the window without resizing it.
    let before = harness.state.window.unwrap();
    harness.modifiers = Modifiers::SHIFT;
    for _ in 0..8 {
        harness.frame(&index, vec![wheel(egui::vec2(0.0, -2.0), Modifiers::SHIFT)]);
    }
    harness.modifiers = Modifiers::NONE;
    let after = harness.state.window.unwrap();
    assert!(((after.1 - after.0) - (before.1 - before.0)).abs() < 1.0);
    assert!(after.0 != before.0, "panned");
    // A plain wheel scrolls the lane list: with enough lanes to scroll.
    let mut nodes = vec![node(0, 1, 1, "/bin/a", S, 2 * S)];
    for n in 0..60 {
        nodes.push(node(
            1,
            10 + n,
            10 + u64::from(n),
            &format!("/bin/b{n}"),
            S,
            2 * S,
        ));
    }
    let mut builder = Builder::new(Lanes::from_processes(&nodes)).without_rows();
    builder.push_record(record(S, 1, Tier::High, Category::Execution));
    let many = builder.finish();
    let mut harness = Harness::new();
    harness.frame(&many, vec![Event::PointerMoved(over)]);
    for _ in 0..8 {
        harness.frame(&many, vec![wheel(egui::vec2(0.0, -2.0), Modifiers::NONE)]);
    }
    assert!(
        harness.state.scroll > 0.0,
        "scrolled to {}",
        harness.state.scroll
    );
}

#[test]
fn the_keyboard_moves_through_findings_lanes_and_chips() {
    let index = scene();
    let mut harness = Harness::new();
    harness.focus_on(&index, 0);
    assert_eq!(harness.state.selected, Some(0));
    // → and ← step through time.
    assert_eq!(
        harness.key(&index, Key::ArrowRight),
        [Action::Select {
            record: 1,
            focus: false
        }]
    );
    assert_eq!(
        harness.key(&index, Key::ArrowRight),
        [Action::Select {
            record: 2,
            focus: false
        }]
    );
    assert_eq!(
        harness.key(&index, Key::ArrowLeft),
        [Action::Select {
            record: 1,
            focus: false
        }]
    );
    // Record 1 is curl's (row 3 of lanes 0..4 with lane 0 unused: row 2). ↑ goes to sh's record.
    assert_eq!(
        harness.key(&index, Key::ArrowUp),
        [Action::Select {
            record: 2,
            focus: false
        }]
    );
    // ↓ from sh goes to curl's.
    assert_eq!(
        harness.key(&index, Key::ArrowDown),
        [Action::Select {
            record: 1,
            focus: false
        }]
    );
    // Enter is a double click.
    assert_eq!(harness.key(&index, Key::Enter), [Action::Open(1)]);
    // H M L I and 1…9, 0 are chips.
    assert_eq!(harness.key(&index, Key::H), [Action::Tier(Tier::High)]);
    assert_eq!(harness.key(&index, Key::M), [Action::Tier(Tier::Medium)]);
    assert_eq!(harness.key(&index, Key::L), [Action::Tier(Tier::Low)]);
    assert_eq!(harness.key(&index, Key::I), [Action::Tier(Tier::Info)]);
    assert_eq!(
        harness.key(&index, Key::Num1),
        [Action::Category(Category::Execution)]
    );
    assert_eq!(
        harness.key(&index, Key::Num4),
        [Action::Category(Category::Evasion)]
    );
    assert_eq!(
        harness.key(&index, Key::Num0),
        [Action::Category(Category::ALL[9])]
    );
    // Ctrl chords are not ours.
    harness.modifiers = Modifiers::CTRL;
    assert!(harness.key_with(&index, Key::H, Modifiers::CTRL).is_empty());
}

#[test]
fn plus_and_minus_zoom_at_the_selection_f_fits_and_space_folds() {
    let index = scene();
    let mut harness = Harness::new();
    harness.focus_on(&index, 3);
    harness.key(&index, Key::Plus);
    let window = harness.state.window.expect("zoomed in");
    let at = index.records[3].first_ns as f64;
    assert!(
        window.0 < at && at < window.1,
        "the selection stays in view"
    );
    let width = window.1 - window.0;
    harness.key(&index, Key::Minus);
    let wider = harness.state.window.unwrap();
    assert!(wider.1 - wider.0 > width);
    harness.key(&index, Key::F);
    assert_eq!(harness.state.window, None, "F fits the whole run");
    // Space folds the selected record's lane when it has children: sh (record 2).
    harness.key(&index, Key::Home);
    harness.key(&index, Key::ArrowRight);
    harness.key(&index, Key::ArrowRight);
    assert_eq!(harness.state.selected, Some(2));
    harness.key(&index, Key::Space);
    assert!(harness.state.collapsed.contains(&(12, 1202)));
    harness.key(&index, Key::Space);
    assert!(harness.state.collapsed.is_empty());
}

#[test]
fn keys_do_nothing_until_the_graph_has_focus() {
    let index = scene();
    let mut harness = Harness::new();
    harness.frame(&index, vec![]);
    assert!(harness.key(&index, Key::ArrowRight).is_empty());
    assert!(harness.key(&index, Key::H).is_empty());
    assert_eq!(harness.state.selected, None);
}

#[test]
fn stepping_into_the_dark_brings_the_finding_into_view() {
    let index = scene();
    let mut harness = Harness::new();
    harness.focus_on(&index, 0);
    // Zoom to the start, then walk to the last finding, which is far to the right.
    let bounds = view::bounds(index.extent());
    harness.state.window = Some((bounds.0, bounds.0 + 3.0 * SF));
    harness.key(&index, Key::End);
    let window = harness.state.window.unwrap();
    let last = index.records.last().unwrap().first_ns as f64;
    assert!(window.0 <= last && last <= window.1);
    assert_eq!(harness.state.selected, Some(index.records.len() - 1));
}

// ----- themes -----

#[test]
fn markers_keep_three_to_one_contrast_against_the_lane_in_every_theme() {
    for theme in Theme::ALL {
        let colors = Colors::of(theme.palette());
        for row in [0, 1] {
            let lane = colors.lane(row);
            for (tier, color) in colors.tier.iter().enumerate() {
                let ratio = contrast(*color, lane);
                assert!(
                    ratio >= 3.0,
                    "{} {} tier {tier} on lane {row}: {ratio:.2}:1",
                    theme.label(),
                    Tier::ALL[tier].tag()
                );
            }
        }
    }
}

#[test]
fn the_widget_paints_in_each_theme_with_that_themes_colors() {
    let index = scene();
    for theme in Theme::ALL {
        let ctx = egui::Context::default();
        theme::apply_theme(&ctx, theme);
        let mut state = State::default();
        let colors = Colors::of(theme.palette());
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let config = Config {
                        index: &index,
                        colors,
                        clock: None,
                        height: WIDGET_HEIGHT,
                    };
                    widget::show(ui, &mut state, &config);
                });
            },
        );
        let painted: Vec<egui::Color32> = {
            fn walk(shape: &egui::Shape, out: &mut Vec<egui::Color32>) {
                match shape {
                    egui::Shape::Circle(circle) => out.push(circle.fill),
                    egui::Shape::Path(path) => out.push(path.fill),
                    egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, out)),
                    egui::Shape::Mesh(mesh) => {
                        out.extend(mesh.vertices.iter().map(|vertex| vertex.color))
                    }
                    _ => {}
                }
            }
            let mut out = Vec::new();
            output
                .shapes
                .iter()
                .for_each(|clipped| walk(&clipped.shape, &mut out));
            out
        };
        assert!(
            painted.contains(&colors.tier[0]),
            "{}: a HIGH marker in the error color",
            theme.label()
        );
        assert!(
            painted.contains(&colors.tier[2]),
            "{}: a LOW marker in the info color",
            theme.label()
        );
        let _ = HOLLOW;
    }
}
