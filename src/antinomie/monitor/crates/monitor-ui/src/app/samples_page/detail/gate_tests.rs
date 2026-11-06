// SPDX-License-Identifier: GPL-3.0-only
//! The Samples page's run gate follows the selected VM's architecture.
use super::*;
use antinomie_monitor_core::GuestArch;

fn record(kind: &str, arch: &str) -> SampleRecord {
    SampleRecord {
        file_type: kind.into(),
        arch: arch.into(),
        ..SampleRecord::default()
    }
}

#[test]
fn the_gate_follows_the_selected_vms_architecture() {
    let (x86, arm64) = (Some(GuestArch::X86_64), Some(GuestArch::AARCH64));
    assert!(run_error(&record("elf", "AArch64"), x86).is_some());
    assert!(run_error(&record("elf", "AArch64"), arm64).is_none());
    assert!(run_error(&record("elf", "ARM"), arm64).is_none());
    assert!(run_error(&record("elf", "ARM"), x86).is_some());
    assert!(run_error(&record("elf", "x86-64"), x86).is_none());
    assert!(run_error(&record("elf", "x86"), x86).is_none());
    assert!(run_error(&record("elf", "x86-64"), arm64).is_some());
    for guest in [x86, arm64, None] {
        assert!(run_error(&record("sh", ""), guest).is_none());
        assert!(run_error(&record("elf", ""), guest).is_none());
        assert!(run_error(&record("exe", ""), guest).is_some());
    }
    assert!(run_error(&record("elf", "AArch64"), None).is_none());
    assert!(run_error(&record("elf", "MIPS"), None).is_some());
    let mut removed = record("sh", "");
    removed.removed_ms = Some(1);
    assert_eq!(
        run_error(&removed, arm64).as_deref(),
        Some("The archive was removed")
    );
}

#[test]
fn the_refusal_text_is_shown_with_both_architectures() {
    let why = run_error(&record("elf", "AArch64"), Some(GuestArch::X86_64));
    let ctx = egui::Context::default();
    let output = ctx.run_ui(egui::RawInput::default(), |root| {
        egui::CentralPanel::default().show(root, |ui| show_refusal(ui, why.as_deref()));
    });
    let text = crate::app::tests::texts(&output)
        .into_iter()
        .map(|(text, _)| text)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("This is an AArch64 program; the selected VM is x86-64. Choose an arm64 VM."),
        "{text}"
    );
}
