// SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn paste(app: &mut MonitorApp, ctx: &egui::Context, text: &str) {
    let _ = ctx.run(
        egui::RawInput {
            events: vec![egui::Event::Paste(text.into())],
            ..Default::default()
        },
        |ctx| {
            app.receive_clipboard(ctx);
            assert!(!ctx.input(|input| input
                .events
                .iter()
                .any(|e| matches!(e, egui::Event::Paste(_)))));
        },
    );
}

#[test]
fn clipboard_uses_native_request_and_does_not_feed_run_terminal() {
    let mut app = upload_app();
    let ctx = egui::Context::default();
    let out = ctx.run(Default::default(), |ctx| app.request_clipboard(ctx));
    assert!(out.viewport_output[&egui::ViewportId::ROOT]
        .commands
        .iter()
        .any(|c| matches!(c, egui::ViewportCommand::RequestPaste)));
    paste(&mut app, &ctx, "hello");
    assert!(
        matches!(&app.submitted[..], [Command::TypeClipboard { vm_id, boot_id, text }]
        if vm_id == "vm" && boot_id == "boot" && text == "hello")
    );
}

#[test]
fn multiline_confirms_and_changed_boot_cannot_receive_old_clipboard() {
    let mut app = upload_app();
    let ctx = egui::Context::default();
    app.request_clipboard(&ctx);
    paste(&mut app, &ctx, "hello\n");
    assert!(app.submitted.is_empty());
    let Some(Confirm::Clipboard { intent, text }) = app.confirm.take() else {
        panic!("confirmation required");
    };
    app.snapshot.boot_id = Some("next-boot".into());
    app.submit_clipboard(intent, text);
    assert!(app.submitted.is_empty());
    assert!(app.status.contains("target changed"));
    app.request_clipboard(&ctx);
    app.snapshot.state = VmState::Stopped;
    paste(&mut app, &ctx, "stale");
    assert!(app.submitted.is_empty());
    assert!(!app.clipboard_enabled());
}
