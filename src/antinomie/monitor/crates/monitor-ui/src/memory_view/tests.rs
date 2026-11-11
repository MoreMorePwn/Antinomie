// SPDX-License-Identifier: GPL-3.0-only
use super::*;

#[test]
fn every_result_column_gets_a_distinct_parseable_filter_keyword() {
    let columns: Vec<_> = ["X", "X", "X_1_0", "Depth", "and", "lower", "1st", ""]
        .into_iter()
        .map(|name| ResultColumn {
            name: name.into(),
            kind: ColumnKind::Int,
        })
        .collect();
    let names = column_fields(&columns);
    assert_eq!(
        names
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        columns.len()
    );
    let fields = result_fields(&names, &columns);
    let row = memory::ResultRow {
        depth: 0,
        values: (0..columns.len())
            .map(|index| serde_json::json!(index))
            .collect(),
    };
    let values = result_row(&names, &columns, &row);
    for (index, name) in names.iter().enumerate() {
        let query = crate::query::compile_table(&format!("{name} == {index}"), &fields);
        assert!(query.error.is_none(), "{name}: {:?}", query.error);
        assert!(query.keep_table(&values), "{name}");
    }
}

#[test]
fn plugins_are_grouped_by_system_and_module() {
    assert_eq!(plugin_area("linux.pslist.PsList"), "linux");
    assert_eq!(
        plugin_area("linux.malware.malfind.Malfind"),
        "linux · malware"
    );
    assert_eq!(
        plugin_area("windows.registry.hivelist.HiveList"),
        "windows · registry"
    );
    assert_eq!(plugin_area("yarascan.YaraScan"), "generic");
}

#[test]
fn saved_runs_set_their_options_up_again() {
    let plugin: PluginInfo = serde_json::from_str(
        r#"{"name":"linux.pslist.PsList","options":[
            {"name":"pid","kind":"list","element":"int"},
            {"name":"threads","kind":"bool"}]}"#,
    )
    .unwrap();
    let run = PluginRun {
        plugin: plugin.name.clone(),
        args: vec!["--pid".into(), "1".into(), "42".into(), "--threads".into()],
        ..PluginRun::default()
    };
    let values = args_values(&run, std::slice::from_ref(&plugin));
    assert_eq!(
        values,
        [
            ("pid".to_owned(), "1, 42".to_owned()),
            ("threads".into(), "true".into())
        ]
    );
    assert_eq!(memory::plugin_args(&plugin, &values).unwrap(), run.args);
    assert!(args_values(&run, &[]).is_empty());
}

#[test]
fn results_copy_as_tab_separated_text_with_tree_indent() {
    let table = ResultTable {
        columns: vec![
            ResultColumn {
                name: "PID".into(),
                kind: ColumnKind::Int,
            },
            ResultColumn {
                name: "COMM".into(),
                kind: ColumnKind::Str,
            },
        ],
        rows: vec![
            memory::ResultRow {
                depth: 0,
                values: vec![1.into(), "init".into()],
            },
            memory::ResultRow {
                depth: 1,
                values: vec![42.into(), "sh".into()],
            },
        ],
        truncated: false,
    };
    assert_eq!(
        result_tsv(&table.columns, &table, &[0, 1]),
        "PID\tCOMM\n1\tinit\n  42\tsh"
    );
}

#[test]
fn result_rows_get_tree_branches_from_their_depth_after_filtering() {
    let row = |depth| memory::ResultRow {
        depth,
        values: vec![1.into()],
    };
    let table = ResultTable {
        columns: vec![ResultColumn {
            name: "PID".into(),
            kind: ColumnKind::Int,
        }],
        rows: [0, 1, 2, 2, 1, 0, 1].map(row).to_vec(),
        truncated: false,
    };
    let text = |shown: &[usize]| {
        result_branches(&table, shown)
            .iter()
            .map(|branch| branch.text())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        text(&[0, 1, 2, 3, 4, 5, 6]),
        ["", "├── ", "│   ├── ", "│   └── ", "└── ", "", "└── "]
    );
    // Rows without their parents are siblings of each other.
    assert_eq!(text(&[1, 6]), ["├── ", "└── "]);
}

#[test]
fn column_clicks_sort_up_then_down_then_back() {
    let up = next_sort(None, 2);
    assert_eq!(
        up,
        Some(Sort {
            column: 2,
            descending: false
        })
    );
    let down = next_sort(up, 2);
    assert!(down.is_some_and(|sort| sort.descending));
    assert_eq!(next_sort(down, 2), None);
    assert_eq!(next_sort(down, 0).map(|sort| sort.column), Some(0));
}

#[test]
fn result_worker_filters_beyond_old_prefix_and_sorts_entire_retained_source() {
    use std::io::Write;
    let root = std::env::temp_dir().join(format!(
        "antinomie-paged-memory-{}-{}",
        std::process::id(),
        crate::time_format::now_ms()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("result.jsonl");
    let mut output = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
    writeln!(output, "{{\"columns\":[{{\"name\":\"PID\",\"type\":\"int\"}},{{\"name\":\"COMM\",\"type\":\"str\"}}]}}").unwrap();
    for index in 0..200_005 {
        writeln!(
            output,
            "{{\"d\":0,\"v\":[{index},\"{}\"]}}",
            if index == 200_004 {
                "beyond-prefix"
            } else {
                "row"
            }
        )
        .unwrap();
    }
    output.flush().unwrap();
    let run = PluginRun {
        id: "run-one".into(),
        dir: root.clone(),
        ..Default::default()
    };
    antinomie_monitor_core::annotations::save(
        &root,
        &antinomie_monitor_core::annotations::Annotation {
            name: "Renamed plugin result".into(),
            tags: vec!["needs review".into()],
        },
    )
    .unwrap();
    let cancel = AtomicBool::new(false);
    let mut request = ResultRequest {
        vm_id: None,
        boot_id: None,
        run_id: run.id.clone(),
        source: path.clone(),
        query: "comm == \"beyond-prefix\" && tag == \"needs review\" && entry.name == \"Renamed plugin result\"".into(),
        sort: None,
        start: 0,
    };
    let loaded = load_result(run.clone(), &request, &cancel);
    assert!(loaded.filter_error.is_none());
    assert_eq!(
        (loaded.total, loaded.source_rows, loaded.start),
        (1, 200_005, 0)
    );
    assert_eq!(
        loaded.table.as_ref().unwrap().rows[0].values[0],
        serde_json::json!(200_004)
    );
    request.query.clear();
    request.sort = Some(Sort {
        column: 0,
        descending: true,
    });
    request.start = 1024;
    let loaded = load_result(run, &request, &cancel);
    assert_eq!(loaded.table.as_ref().unwrap().rows.len(), 1024);
    assert_eq!(
        loaded.table.as_ref().unwrap().rows[0].values[0],
        serde_json::json!(200_004 - 1024)
    );
    assert_eq!(
        (loaded.total, loaded.source_rows, loaded.start),
        (200_005, 200_005, 1024)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn text_view_expands_tabs_like_a_terminal() {
    assert_eq!(expand_tabs("PID\tCOMM"), "PID     COMM");
    assert_eq!(expand_tabs("12345678\tx"), "12345678        x");
}

#[test]
fn memnixfs_runs_are_marked_and_partial_results_say_so() {
    let run = PluginRun {
        id: "r1".into(),
        dump_id: "d1".into(),
        plugin: "memnixfs.processes".into(),
        analyzer: Analyzer::MemNixFs,
        state: RunState::Finished,
        rows: 92,
        partial: vec!["The kernel's page-table root was not validated.".into()],
        ..PluginRun::default()
    };
    assert_eq!(run.short_name(), "processes");
    assert!(run_detail(&run, None).ends_with(" · partial"));
    let row = plugin_run_row(&run, None);
    let field = |name: &str| {
        row.iter()
            .find(|(key, _)| *key == name)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(
        field("entry.kind"),
        Some(crate::query::RowValue::Text("memnixfs".into()))
    );
    assert_eq!(
        field("analyzer"),
        Some(crate::query::RowValue::Text("memnixfs".into()))
    );
    assert_eq!(field("partial"), Some(crate::query::RowValue::Bool(true)));
    // A complete result and a Volatility run are not partial.
    let whole = PluginRun {
        partial: Vec::new(),
        ..run.clone()
    };
    assert!(!run_detail(&whole, None).contains("partial"));
    let volatility = PluginRun {
        analyzer: Analyzer::Volatility,
        plugin: "linux.pslist.PsList".into(),
        ..whole
    };
    let row = plugin_run_row(&volatility, None);
    assert!(row.contains(&(
        "entry.kind",
        crate::query::RowValue::Text("volatility".into())
    )));
    assert!(row.contains(&("partial", crate::query::RowValue::Bool(false))));
}

#[test]
fn a_note_chip_selects_its_dump_and_the_row_names_the_vm_and_the_dump() {
    use antinomie_monitor_core::samples::{vm_item_target, RefKind};
    let dump = |id: &str| MemoryDump {
        id: id.into(),
        vm_id: "vm1".into(),
        started_ms: 1_700_000_000_000,
        ..MemoryDump::default()
    };
    let mut view = MemoryView::default();
    view.dumps = vec![dump("first"), dump("second")];
    view.dumps_for = Some(Vec::new());
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let data_dir = std::env::temp_dir();
    let frame = |view: &mut MemoryView| {
        let _ = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(600.0, 600.0),
                )),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    let cx = MemoryContext {
                        vm: None,
                        recordings: None,
                        recording_roots: &[],
                        running: false,
                        dumping: None,
                        pending: false,
                        data_dir: &data_dir,
                        volatility_installed: false,
                        volatility_installing: false,
                        memnixfs_installed: false,
                        memnixfs_installing: false,
                        bases: &[],
                        font_size: 16.0,
                        online_symbols: false,
                        curl: Path::new("curl"),
                    };
                    view.dump_list(ui, &cx);
                });
            },
        );
    };
    view.hide_list = true;
    view.ask_note_target("second".into());
    assert!(
        !view.hide_list,
        "the list shows so the dump can be selected"
    );
    frame(&mut view);
    assert_eq!(view.selected.as_deref(), Some("second"));
    assert!(view.note_target.is_none());
    view.ask_note_target("gone".into());
    frame(&mut view);
    assert_eq!(view.selected.as_deref(), Some("second"));
    assert!(view
        .status
        .as_ref()
        .is_some_and(|(text, failed)| *failed && text.contains("deleted")));
    let reference = MemoryView::note_reference(&view.dumps[1]);
    assert_eq!(reference.kind, RefKind::MemoryDump);
    assert_eq!(reference.target, vm_item_target("vm1", "second"));
}

#[test]
fn an_arm64_vm_says_its_memory_cannot_be_analysed() {
    let mut base = BaseSummary {
        id: "arm".into(),
        label: "BusyBox arm64".into(),
        directory: PathBuf::from("/bases/arm"),
        guest: None,
        min_ram_mib: 256,
        min_disk_gib: 1,
        fixed_display: true,
        arch: Default::default(),
        size_bytes: 0,
        revision: None,
        min_app_version: None,
        built_with: None,
        stealth_support: Vec::new(),
    };
    let vm = VmConfig {
        base_identity: Some("arm".into()),
        ..Default::default()
    };
    let context = |bases: &[BaseSummary]| {
        foreign_guest(&MemoryContext {
            vm: Some(&vm),
            recordings: None,
            recording_roots: &[],
            running: false,
            dumping: None,
            pending: false,
            data_dir: Path::new("/nonexistent"),
            volatility_installed: true,
            volatility_installing: false,
            memnixfs_installed: true,
            memnixfs_installing: false,
            bases,
            font_size: 14.0,
            online_symbols: false,
            curl: Path::new("curl"),
        })
    };
    assert_eq!(context(std::slice::from_ref(&base)), None);
    base.arch = antinomie_monitor_core::GuestArch::AARCH64;
    let note = context(std::slice::from_ref(&base)).unwrap();
    assert!(
        note.starts_with("Memory analysis does not work on arm64 VMs"),
        "{note}"
    );
}

#[test]
fn a_dump_links_to_its_run_by_provenance_then_by_the_runs_own_record() {
    use antinomie_monitor_core::provenance::{Certainty, Provenance};
    let mut view = MemoryView::default();
    let mut dump = MemoryDump {
        id: "d".into(),
        dir: PathBuf::from("/rec/memory/d"),
        ..Default::default()
    };
    // Saved before the field: not in a run.
    let link = view.link_of(&dump);
    assert!(link.run.is_none() && link.certainty == Certainty::Unknown);
    assert_eq!(view.cell_of(&link).line().text, "Run: Not in a run");
    // The run's own record names the folder.
    view.legacy_links.insert(
        dump.dir.clone(),
        Provenance::run_exit("vm", "boot", "r1", 0),
    );
    assert_eq!(view.link_of(&dump).run.as_deref(), Some("r1"));
    // A by-hand dump taken while two runs were live: by time.
    dump.provenance = Some(Provenance::by_hand(
        "vm",
        "boot",
        None,
        vec!["r1".into(), "r2".into()],
        0,
    ));
    let link = view.link_of(&dump);
    assert_eq!(link.certainty, Certainty::ByTime);
    assert!(view
        .cell_of(&link)
        .line()
        .text
        .starts_with("Run: by time: r1"));
    view.this_run_only = true;
    view.triage_run = Some("r2".into());
    assert!(view.of_this_run(&link));
    view.triage_run = Some("r3".into());
    assert!(!view.of_this_run(&link));
    // Taken while no run was live: VM-wide.
    dump.provenance = Some(Provenance::by_hand("vm", "boot", None, Vec::new(), 0));
    let wide = view.link_of(&dump);
    assert_eq!(view.cell_of(&wide).line().text, "Run: VM-wide");
}

#[test]
fn a_plugin_run_ends_without_the_memory_tab_being_drawn() {
    let run = PluginRun {
        id: "r1".into(),
        plugin: "linux.pslist.PsList".into(),
        dump_id: "d".into(),
        state: RunState::Finished,
        rows: 3,
        ..PluginRun::default()
    };
    let mut view = MemoryView::default();
    view.jobs.push(RunHandle::ended(run));
    assert_eq!(view.running_jobs().len(), 1);
    // The app's every-frame hook, with no `show` call at all.
    view.background(&egui::Context::default());
    assert!(view.jobs.is_empty(), "the run left the running list");
    assert!(view.running_jobs().is_empty());
    assert_eq!(
        view.status,
        Some(("PsList finished: 3 rows".to_owned(), false))
    );
}
