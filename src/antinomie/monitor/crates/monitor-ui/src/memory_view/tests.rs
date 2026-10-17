// SPDX-License-Identifier: MIT
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
        now_ms()
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
