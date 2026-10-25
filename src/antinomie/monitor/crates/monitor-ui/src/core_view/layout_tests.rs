// SPDX-License-Identifier: GPL-3.0-only
//! The Cores view in the mockup's arrangement: the list, the tabs, the
//! shared function sidebar with the lines of each function, and Details.
use super::tests::{click, settle, texts, Fixture};
use super::*;

fn painted(
    view: &mut CoreView,
    ctx: &egui::Context,
    size: egui::Vec2,
) -> Vec<(String, egui::Rect)> {
    texts(&settle(ctx, view, size))
}

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    ctx
}

fn has(shown: &[(String, egui::Rect)], text: &str) -> bool {
    shown.iter().any(|(shown, _)| shown == text)
}

fn function(name: &str, address: u64, size: u64) -> CoreFunction {
    CoreFunction {
        address,
        size,
        name: name.into(),
    }
}

/// Three functions; the decoded text covers the first two.
fn with_functions(fixture: &mut Fixture) {
    let view = &mut fixture.view;
    view.tab = Tab::Code;
    view.functions = vec![
        function("_start", 0x400000, 0x10),
        function("main", 0x400010, 0x10),
        function("unread", 0x401000, 0x10),
    ];
    view.code_function = Some(0);
    let mut code = String::from("x86-64 process memory at 0x400000\n");
    for address in [0x400000u64, 0x400004, 0x400008, 0x400010, 0x400018] {
        code.push_str(&format!("{address:016x}  nop\n"));
    }
    view.code = code;
}

#[test]
fn the_core_tabs_follow_the_mockup_with_counts_and_the_new_strings_tab() {
    let ctx = context();
    let mut fixture = Fixture::new();
    let shown = painted(&mut fixture.view, &ctx, egui::vec2(1280.0, 820.0));
    let tabs: Vec<_> = [
        "Context",
        "Memory mappings",
        "Disassembly",
        "Strings",
        "Recovered notes",
    ]
    .into_iter()
    .map(|label| {
        shown
            .iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("tab {label} missing"))
            .1
    })
    .collect();
    assert!(
        tabs.windows(2).all(|pair| pair[0].max.x < pair[1].min.x),
        "tabs in order on one row: {tabs:?}"
    );
    // One mapping; the notes table lists one AUXV entry, one note and one file.
    assert!(has(&shown, "1") && has(&shown, "3"), "{shown:?}");
}

#[test]
fn registers_are_grouped_in_cards_with_a_thread_row_and_a_banner() {
    let ctx = context();
    let mut fixture = Fixture::new();
    let shown = painted(&mut fixture.view, &ctx, egui::vec2(1280.0, 820.0));
    for text in [
        "Instruction pointer & stack",
        "General",
        "Copy all",
        "Thread",
    ] {
        assert!(has(&shown, text), "{text}: {shown:?}");
    }
    assert!(shown
        .iter()
        .any(|(text, _)| text.starts_with("Saved core: registers only")));
    let rip = shown.iter().find(|(text, _)| text == "rip").unwrap().1;
    let rax = shown.iter().find(|(text, _)| text == "rax").unwrap().1;
    assert!(
        rip.min.x < rax.min.x,
        "pointers on the left, general registers on the right"
    );
}

#[test]
fn a_function_shows_its_instructions_in_the_disassembly_view() {
    let ctx = context();
    let mut fixture = Fixture::new();
    with_functions(&mut fixture);
    let shown = painted(&mut fixture.view, &ctx, egui::vec2(1280.0, 820.0));
    assert!(has(&shown, "0x400000 · 3 lines"), "_start: {shown:?}");
    assert!(has(&shown, "0x400010 · 2 lines"), "main: {shown:?}");
    assert!(has(&shown, "0x401000 · – lines"), "not decoded: {shown:?}");
    assert!(
        !shown.iter().any(|(text, _)| text.starts_with("0x4")
            && (text.contains("octets") || text.contains("bytes"))),
        "a function's detail counts lines, not bytes: {shown:?}"
    );
}

#[test]
fn the_decompilation_view_counts_source_lines_instead() {
    let ctx = context();
    let mut fixture = Fixture::new();
    with_functions(&mut fixture);
    fixture.view.function_bodies = vec![
        "void _start(void) {\n  main();\n  return;\n}\n".into(),
        "int main(void) {\n  return 0;\n}\n".into(),
    ];
    fixture.view.show_decompiled = true;
    let shown = painted(&mut fixture.view, &ctx, egui::vec2(1280.0, 820.0));
    assert!(has(&shown, "0x400000 · 4 lines"), "_start: {shown:?}");
    assert!(has(&shown, "0x400010 · 3 lines"), "main: {shown:?}");
    assert!(
        has(&shown, "0x401000 · – lines"),
        "not decompiled: {shown:?}"
    );
    // Back to the disassembly: the same functions, their instructions.
    fixture.view.show_decompiled = false;
    let shown = painted(&mut fixture.view, &ctx, egui::vec2(1280.0, 820.0));
    assert!(has(&shown, "0x400000 · 3 lines") && has(&shown, "0x400010 · 2 lines"));
}

#[test]
fn counts_stay_known_when_another_function_replaces_the_decoded_text() {
    let ctx = context();
    let mut fixture = Fixture::new();
    with_functions(&mut fixture);
    fixture.view.remember_asm_counts();
    fixture.view.code = "0000000000401000  nop\n0000000000401002  nop\n".into();
    let shown = painted(&mut fixture.view, &ctx, egui::vec2(1280.0, 820.0));
    assert!(has(&shown, "0x400000 · 3 lines"), "remembered: {shown:?}");
    assert!(has(&shown, "0x401000 · 2 lines"), "decoded now: {shown:?}");
}

#[test]
fn the_view_switch_disables_decompilation_until_ghidra_has_run() {
    let ctx = context();
    let mut fixture = Fixture::new();
    with_functions(&mut fixture);
    let size = egui::vec2(1280.0, 820.0);
    let shown = painted(&mut fixture.view, &ctx, size);
    let position = shown
        .iter()
        .find(|(text, _)| text == "Decompilation")
        .expect("the view switch")
        .1
        .center();
    click(&ctx, &mut fixture.view, size, position);
    assert!(
        !fixture.view.show_decompiled,
        "disabled until there is source"
    );
    fixture.view.function_bodies = vec!["a\nb\n".into()];
    let shown = painted(&mut fixture.view, &ctx, size);
    let position = shown
        .iter()
        .find(|(text, _)| text == "Decompilation")
        .unwrap()
        .1
        .center();
    click(&ctx, &mut fixture.view, size, position);
    assert!(fixture.view.show_decompiled);
}

#[test]
fn choosing_a_function_or_a_mapping_fills_the_details_panel() {
    let ctx = context();
    let mut fixture = Fixture::new();
    with_functions(&mut fixture);
    let size = egui::vec2(1280.0, 820.0);
    let shown = painted(&mut fixture.view, &ctx, size);
    let main = shown
        .iter()
        .find(|(text, _)| text == "main")
        .unwrap()
        .1
        .center();
    click(&ctx, &mut fixture.view, size, main);
    let detail = fixture
        .view
        .detail
        .clone()
        .expect("a function row fills Details");
    assert_eq!((detail.what, detail.title.as_str()), ("Function", "main"));
    assert!(detail.fields.contains(&("Address", "0x400010".into())));
    assert!(detail.fields.contains(&("Disassembly", "2 lines".into())));
    fixture.view.tab = Tab::Mappings;
    let shown = painted(&mut fixture.view, &ctx, size);
    let row = shown
        .iter()
        .find(|(text, _)| text.starts_with("0x400000-0x"))
        .expect("the mappings table")
        .1
        .center();
    fixture.view.mapping_index = usize::MAX;
    click(&ctx, &mut fixture.view, size, row);
    let detail = fixture.view.detail.clone().unwrap();
    assert_eq!(detail.what, "Mapping");
    assert!(detail.fields.contains(&("Permissions", "r-x".into())));
    assert!(detail
        .fields
        .contains(&("File", "/synthetic/sample".into())));
}

#[test]
fn the_mappings_table_lists_each_mapping_and_sorts_by_its_headers() {
    let ctx = context();
    let mut fixture = Fixture::new();
    fixture.view.tab = Tab::Mappings;
    let record = fixture.view.selected.as_mut().unwrap();
    record.core.mappings.push(CoreMapping {
        start: 0x100000,
        memory_size: 0x2000,
        file_offset: 0,
        captured_size: 16,
        available_size: 16,
        flags: 6,
    });
    fixture.view.selected = Some(record.clone());
    let size = egui::vec2(1280.0, 820.0);
    let shown = painted(&mut fixture.view, &ctx, size);
    for header in ["Range", "Perms", "Size", "Captured", "File"] {
        assert!(has(&shown, header), "{header}: {shown:?}");
    }
    let rows = |shown: &[(String, egui::Rect)]| {
        let mut ranges: Vec<_> = shown
            .iter()
            .filter(|(text, _)| text.starts_with("0x") && text.contains("-0x"))
            .cloned()
            .collect();
        ranges.sort_by(|a, b| a.1.top().total_cmp(&b.1.top()));
        ranges.into_iter().map(|(text, _)| text).collect::<Vec<_>>()
    };
    let before = rows(&shown);
    assert_eq!(before.len(), 2, "{before:?}");
    let header = shown
        .iter()
        .find(|(text, _)| text.starts_with("Range"))
        .unwrap()
        .1
        .center();
    click(&ctx, &mut fixture.view, size, header);
    let ascending = rows(&painted(&mut fixture.view, &ctx, size));
    assert!(ascending[0].starts_with("0x100000-"), "{ascending:?}");
    let header = texts(&settle(&ctx, &mut fixture.view, size))
        .into_iter()
        .find(|(text, _)| text.starts_with("Range"))
        .unwrap()
        .1
        .center();
    click(&ctx, &mut fixture.view, size, header);
    let descending = rows(&painted(&mut fixture.view, &ctx, size));
    assert!(descending[0].starts_with("0x400000-"), "{descending:?}");
}

#[test]
fn the_details_panel_names_what_is_selected_or_asks_for_a_selection() {
    let ctx = context();
    let mut view = CoreView::default();
    let shown = |view: &CoreView| {
        let output = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| view.details(ui));
        });
        texts(&output)
    };
    assert!(shown(&view)
        .iter()
        .any(|(text, _)| text.starts_with("Nothing selected.")));
    view.detail = Some(details::note(
        "Note",
        "NT_PRSTATUS",
        "core note",
        "signal 11",
    ));
    let shown = shown(&view);
    assert!(has(&shown, "Note NT_PRSTATUS"), "{shown:?}");
    assert!(has(&shown, "from Cores · Recovered notes"));
    assert!(has(&shown, "signal 11"));
}
