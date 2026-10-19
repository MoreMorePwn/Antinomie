// SPDX-License-Identifier: MIT
//! Network panel and the shared Details pane.
use super::*;

#[test]
fn network_panel_lists_captures_toggles_capture_and_filters_by_clicked_values() {
    use antinomie_monitor_core::network::NetworkCapture;
    let root = std::env::temp_dir().join(format!("ant-ui-network-{}", std::process::id()));
    let dir = root.join("boots").join("b1").join("network");
    std::fs::create_dir_all(&dir).unwrap();
    let save = |capture: &NetworkCapture| {
        std::fs::write(&capture.file, test_pcap()).unwrap();
        let mut saved = capture.clone();
        saved.file = capture.file.file_name().unwrap().into();
        std::fs::write(
            capture.file.with_extension("json"),
            serde_json::to_vec(&saved).unwrap(),
        )
        .unwrap();
    };
    let earlier = NetworkCapture {
        stopped_ms: Some(1_800_000_006_000),
        packets: Some(2),
        bytes: Some(200),
        ..NetworkCapture::new(&root.join("boots/b1"), "b1", "earlier", 1_800_000_000_000)
    };
    save(&earlier);
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.vms[0].nat = true;
    app.snapshot
        .vm_locations
        .push(antinomie_monitor_core::VmLocations {
            vm_id: "vm".into(),
            disk_directory: root.clone(),
            recording_directory: root.clone(),
            recording_directories: vec![root.clone()],
        });
    app.focus_panel = Some(Panel::Network);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1400.0, 900.0);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let shown: Vec<_> = texts(&render(&mut app, &ctx, size))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    let local_start = crate::time_format::local_seconds(1_800_000_000);
    for expected in [
        "Captures",
        &local_start,
        "2 packets · 6 s · 200 B",
        "DNS",
        "TCP",
        "10.0.2.15",
        ":5353",
        "query A example.com",
    ] {
        assert!(
            shown.iter().any(|text| text == expected),
            "missing {expected:?} in {shown:?}"
        );
    }
    // The capture list's button starts a capture of the running NAT VM.
    let start = format!("{} Start capture", egui_phosphor::regular::RECORD);
    click_label(&mut app, &ctx, size, &start);
    assert!(matches!(
        app.submitted.last(),
        Some(Command::StartNetworkCapture)
    ));
    app.pending_network = None;
    // Clicking a value filters by it.
    click_label(&mut app, &ctx, size, "DNS");
    click_label(&mut app, &ctx, size, ":5353");
    let shown: Vec<_> = texts(&render(&mut app, &ctx, size))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    assert!(
        shown
            .iter()
            .any(|text| text == "Quick search port 5353: 1 of 2 loaded packets"),
        "{shown:?}"
    );
    assert!(!shown.iter().any(|text| text == "TCP"));
    click_label(&mut app, &ctx, size, "Clear filter");
    // The quick filters list values with their packet counts.
    click_label(&mut app, &ctx, size, "Addresses");
    click_label(&mut app, &ctx, size, "10.0.2.3 (2)");
    let shown: Vec<_> = texts(&render(&mut app, &ctx, size))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    assert!(
        shown
            .iter()
            .any(|text| text == "Quick search ip 10.0.2.3: 2 of 2 loaded packets"),
        "{shown:?}"
    );
    click_label(&mut app, &ctx, size, "Clear filter");
    // A running capture is listed first, opened, and stopped from the list.
    let live = NetworkCapture::new(&root.join("boots/b1"), "b1", "live", 1_800_000_100_000);
    save(&live);
    app.snapshot.network_capture = Some(live.clone());
    let stop = format!("{} Stop capture", egui_phosphor::regular::STOP);
    click_label(&mut app, &ctx, size, &stop);
    assert!(matches!(
        app.submitted.last(),
        Some(Command::StopNetworkCapture)
    ));
    let shown: Vec<_> = texts(&render(&mut app, &ctx, size))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    assert!(
        shown
            .iter()
            .any(|text| text
                .starts_with(&format!("{} Live capture", egui_phosphor::regular::RECORD))),
        "{shown:?}"
    );
    assert!(shown.iter().any(|text| *text
        == format!(
            "Live capture of {}",
            crate::time_format::local_seconds(1_800_000_100)
        )));
    // Without NAT the toggle stays off.
    app.pending_network = None;
    app.snapshot.network_capture = None;
    app.snapshot.vms[0].nat = false;
    assert!(!app.network_toggle_enabled());
    app.snapshot.vms[0].nat = true;
    assert!(app.network_toggle_enabled());
    app.toggle_network_capture();
    assert!(matches!(
        app.submitted.last(),
        Some(Command::StartNetworkCapture)
    ));
    // A stopped VM's capture panel must never start a capture of a
    // different VM that happens to be running.
    app.pending_network = None;
    app.selected = Some("other-vm".into());
    app.snapshot.vms.push(VmConfig {
        id: "other-vm".into(),
        nat: true,
        ..VmConfig::default()
    });
    app.snapshot
        .vm_locations
        .push(antinomie_monitor_core::VmLocations {
            vm_id: "other-vm".into(),
            disk_directory: root.clone(),
            recording_directory: root.clone(),
            recording_directories: vec![root.clone()],
        });
    app.submitted.clear();
    click_label(&mut app, &ctx, size, &start);
    assert!(app.submitted.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn details_follow_the_triage_tab_and_return_to_the_trace() {
    let mut app = app();
    observer_fixture(&mut app);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1700.0, 1000.0);
    app.focus_panel = Some(Panel::Triage);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    assert!(texts(&output)
        .iter()
        .any(|(text, _)| text == "Select an entry in Triage to inspect it here."));
    assert!(!texts(&output)
        .iter()
        .any(|(text, _)| text == "Select a syscall in the trace to decode it here"));
    app.focus_panel = Some(Panel::Trace);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    assert!(texts(&output)
        .iter()
        .any(|(text, _)| text == "Select a syscall in the trace to decode it here"));
}

#[test]
fn details_follow_the_network_tab_with_the_selected_packet_layers_and_bytes() {
    use antinomie_monitor_core::network::NetworkCapture;
    let root = std::env::temp_dir().join(format!("ant-ui-packet-{}", std::process::id()));
    let capture = NetworkCapture {
        stopped_ms: Some(1_800_000_006_000),
        packets: Some(2),
        bytes: Some(200),
        ..NetworkCapture::new(&root.join("boots/b1"), "b1", "one", 1_800_000_000_000)
    };
    std::fs::create_dir_all(capture.file.parent().unwrap()).unwrap();
    std::fs::write(&capture.file, test_pcap()).unwrap();
    let mut saved = capture.clone();
    saved.file = capture.file.file_name().unwrap().into();
    std::fs::write(capture.summary_path(), serde_json::to_vec(&saved).unwrap()).unwrap();
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.vms[0].nat = true;
    app.snapshot
        .vm_locations
        .push(antinomie_monitor_core::VmLocations {
            vm_id: "vm".into(),
            disk_directory: root.clone(),
            recording_directory: root.clone(),
            recording_directories: vec![root.clone()],
        });
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1700.0, 1000.0);
    let shown = |app: &mut MonitorApp| -> Vec<String> {
        texts(&render(app, &ctx, size))
            .into_iter()
            .map(|(text, _)| text)
            .collect()
    };
    // The trace is the open tab: Details show the (empty) syscall.
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    assert!(shown(&mut app)
        .iter()
        .any(|text| text == "Select a syscall in the trace to decode it here"));
    // On the Network tab, Details follow it; selecting a packet shows its
    // layers and bytes.
    app.focus_panel = Some(Panel::Network);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let texts_now = shown(&mut app);
    assert!(
        texts_now
            .iter()
            .any(|text| text.starts_with("No packet selected")),
        "{texts_now:?}"
    );
    assert!(!texts_now
        .iter()
        .any(|text| text == "Select a syscall in the trace to decode it here"));
    click_label(&mut app, &ctx, size, "query A example.com");
    let texts_now = shown(&mut app);
    for expected in [
        "Ethernet II  Src 52:54:00:12:34:56, Dst 52:55:0a:00:02:02",
        "Internet Protocol Version 4  Src 10.0.2.15, Dst 10.0.2.3",
        "Source: 52:54:00:12:34:56",
    ] {
        assert!(
            texts_now.iter().any(|text| text == expected),
            "missing {expected:?} in {texts_now:?}"
        );
    }
    assert!(
        texts_now
            .iter()
            .any(|text| text.starts_with("0000  52 55 0a 00 02 02 52 54  00 12 34 56 08 00")),
        "{texts_now:?}"
    );
    // Choosing a field marks its bytes.
    click_label(&mut app, &ctx, size, "Source: 52:54:00:12:34:56");
    assert!(shown(&mut app)
        .iter()
        .any(|text| text == "Source: 6 bytes at 0x0006"));
    // Back on the trace tab, Details show the syscall again.
    app.focus_panel = Some(Panel::Trace);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let texts_now = shown(&mut app);
    assert!(texts_now
        .iter()
        .any(|text| text == "Select a syscall in the trace to decode it here"));
    assert!(!texts_now.iter().any(|text| text.starts_with("Ethernet II")));
    std::fs::remove_dir_all(root).unwrap();
}
