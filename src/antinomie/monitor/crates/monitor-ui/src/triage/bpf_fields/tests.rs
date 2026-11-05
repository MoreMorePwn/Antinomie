// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::app::tests::texts;

fn identity() -> BpfIdentity {
    BpfIdentity {
        stream_id: 7,
        vm_id: Some("vm-1".into()),
        boot_id: Some("boot-1".into()),
        run_id: Some("run-1".into()),
        cookie: Some(40),
        pid: Some(185),
        tid: Some(185),
        timestamp_ns: Some(168_911_414_442),
        action: "SECCOMP_SET_MODE_FILTER".into(),
        source_syscall: "seccomp".into(),
        event_id: Some(4),
        result: Some(0),
        attachment_kind: "classic seccomp filter".into(),
        declared_instruction_count: None,
        fd: None,
        program_id: None,
        capture_issues: Vec::new(),
    }
}

fn note(identity: BpfIdentity, bytes: Vec<u8>) -> BpfNote {
    BpfNote {
        heading: "seccomp".into(),
        summary: String::new(),
        outcome: String::new(),
        lifecycle: None,
        translation: None,
        dump: None,
        export: Some(crate::bpf::export_capture(&bytes, &identity)),
        bytes: Some(bytes),
        identity,
        loaded_by: None,
        attributes: Vec::new(),
    }
}

fn labels(fields: &[Field]) -> Vec<(&'static str, &str)> {
    fields
        .iter()
        .map(|field| (field.label, field.value.as_str()))
        .collect()
}

#[test]
fn the_identity_is_labelled_fields_and_null_ones_are_left_out() {
    let cx = Context {
        image: Some("/usr/bin/demo".into()),
        start: Some(168_000_000_000),
        clock: None,
    };
    let shown = fields(&identity(), Some(&[0; 8]), &cx);
    assert_eq!(
        labels(&shown),
        [
            ("Action", "SECCOMP_SET_MODE_FILTER"),
            ("Attachment", "classic seccomp filter"),
            ("Source syscall", "seccomp"),
            ("Process", "demo (185 \u{b7} 185)"),
            ("Time", "+0.911 s"),
            ("Result", "0"),
            ("Instructions", "1"),
            ("Captured bytes", "8"),
            ("Partial", "no"),
            ("Padded", "no"),
        ]
    );
    // Declared and captured instructions, a program id and a descriptor.
    let mut partial = identity();
    partial.declared_instruction_count = Some(4);
    partial.program_id = Some(12);
    partial.fd = Some(3);
    partial.capture_issues = vec!["tail cut".into()];
    let shown = fields(&partial, Some(&[0; 12]), &cx);
    let map = labels(&shown);
    assert!(map.contains(&("Instructions", "1 captured of 4 declared")));
    assert!(map.contains(&("Partial", "yes")));
    assert!(map.contains(&("Program id", "12")));
    assert!(map.contains(&("fd", "3")));
    // The recording's ids are kept apart.
    let ids = recording_ids(&identity());
    assert_eq!(
        labels(&ids),
        [
            ("VM", "vm-1"),
            ("Boot", "boot-1"),
            ("Run", "run-1"),
            ("Task cookie", "40"),
            ("Stream", "7"),
            ("Event", "4"),
        ]
    );
}

fn drawn(note: &BpfNote) -> egui::FullOutput {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let cx = Context {
        image: None,
        start: Some(168_000_000_000),
        clock: None,
    };
    let mut out = egui::FullOutput::default();
    for step in 0..3 {
        out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(700.0, 600.0),
                )),
                time: Some(f64::from(step) * 0.02),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| show(ui, note, &cx));
            },
        );
    }
    out
}

#[test]
fn the_details_show_fields_not_the_raw_json() {
    let mut identity = identity();
    identity.capture_issues = vec!["tail cut".into()];
    let note = note(identity, vec![0; 8]);
    let out = drawn(&note);
    let all = texts(&out);
    let has = |text: &str| all.iter().any(|(shown, _)| shown == text);
    for label in [
        "Action",
        "Attachment",
        "Source syscall",
        "Process",
        "Time",
        "Result",
        "SHA-256",
    ] {
        assert!(has(label), "{label}: {all:?}");
    }
    assert!(has("seccomp") && has("classic seccomp filter"));
    assert!(has("unknown (185 \u{b7} 185)"), "{all:?}");
    assert!(has("Capture issues") && has("\u{2022} tail cut"));
    assert!(has("Recording ids"));
    // No raw JSON, and the internal ids are folded away.
    assert!(
        all.iter().all(|(shown, _)| !shown.contains("\"sha256\"")
            && !shown.contains("captured_octets")
            && !shown.starts_with('{')),
        "{all:?}"
    );
    assert!(!has("vm-1") && !has("boot-1") && !has("run-1"), "{all:?}");
    // The digest is short, with the whole one a click away.
    let (short, full) = digest(&[0; 8]);
    assert!(has(&short) && short.chars().count() == 13 && full.len() == 64);
}
