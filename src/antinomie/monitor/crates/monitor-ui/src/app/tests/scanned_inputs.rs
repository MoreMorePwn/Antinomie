// SPDX-License-Identifier: GPL-3.0-only
//! Detection > Scanned inputs rows open the panel that shows each input.
use super::*;
use crate::triage::OpenInput;

#[test]
fn scanned_input_rows_open_their_panel() {
    let mut app = app();
    app.selected_analysis = Some("older".into());
    app.open_scanned_input(OpenInput::StaticAnalysis);
    assert_eq!(app.focus_panel, Some(Panel::StaticAnalysis));
    assert!(app.selected_analysis.is_none());

    app.open_scanned_input(OpenInput::Capture("/runs/r/network-0001.pcap".into()));
    assert_eq!(app.focus_panel, Some(Panel::Network));

    app.open_scanned_input(OpenInput::Core("/runs/r/core/core.elf".into()));
    assert_eq!(app.focus_panel, Some(Panel::CoreDump));

    app.open_scanned_input(OpenInput::Memory("/runs/r/memory".into()));
    assert_eq!(app.focus_panel, Some(Panel::Memory));
}
