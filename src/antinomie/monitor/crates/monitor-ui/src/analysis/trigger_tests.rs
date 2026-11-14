// SPDX-License-Identifier: GPL-3.0-only
//! The dump trigger's tier choice.
use super::*;
use antinomie_monitor_core::dump_trigger::{DumpTrigger, TriggerTier};

fn render(
    ctx: &egui::Context,
    request: &mut ExecRequest,
    events: Vec<egui::Event>,
) -> egui::FullOutput {
    ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(700.0, 600.0),
            )),
            events,
            ..Default::default()
        },
        |root| {
            egui::CentralPanel::default().show(root, |ui| {
                trigger_selection(
                    ui,
                    request,
                    LaunchCapabilities {
                        graphical: false,
                        screen: false,
                        core_on_exit: true,
                        debug_on_start: false,
                        core_limits: None,
                        core_default_mib: 256,
                        route: crate::route_ui::RouteChoice::fixed(
                            antinomie_monitor_core::VmNetwork::Disconnected,
                        ),
                        guest_arch: antinomie_monitor_core::GuestArch::default(),
                    },
                )
            });
        },
    )
}

fn labels(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
    crate::app::tests::texts(output)
}

fn click(ctx: &egui::Context, request: &mut ExecRequest, point: egui::Pos2) {
    for pressed in [true, false] {
        let _ = render(
            ctx,
            request,
            vec![
                egui::Event::PointerMoved(point),
                egui::Event::PointerButton {
                    pos: point,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
    }
}

#[test]
fn the_tier_is_a_minimum_tier_combo_of_low_medium_and_high() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut request = ExecRequest {
        dump_trigger: Some(DumpTrigger::default()),
        ..Default::default()
    };
    let mut output = render(&ctx, &mut request, vec![]);
    for _ in 0..3 {
        output = render(&ctx, &mut request, vec![]);
    }
    let shown = labels(&output);
    assert!(
        shown.iter().any(|(text, _)| text == "Minimum tier"),
        "{shown:?}"
    );
    assert!(
        !shown.iter().any(|(text, _)| text.contains("At tier")),
        "{shown:?}"
    );
    // The combo shows the tier alone, not "High or higher".
    let current = shown
        .iter()
        .find(|(text, _)| text == "High")
        .expect("High")
        .1;
    click(&ctx, &mut request, current.center());
    for _ in 0..3 {
        output = render(&ctx, &mut request, vec![]);
    }
    let shown = labels(&output);
    let low = shown.iter().find(|(text, _)| text == "Low").expect("Low").1;
    assert!(shown.iter().any(|(text, _)| text == "Medium"), "{shown:?}");
    click(&ctx, &mut request, low.center());
    assert_eq!(
        request.dump_trigger.as_ref().unwrap().min_tier,
        TriggerTier::Low
    );
}

/// Item 29: the core and the memory dump each have a box with their own
/// settings under it: the core its count and Read non-resident pages, the
/// memory dump its count and RAM cap.
#[test]
fn the_core_and_the_memory_dump_each_have_their_own_count() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut request = ExecRequest {
        dump_trigger: Some(DumpTrigger {
            memory: true,
            core: true,
            max_cores: 2,
            max_memory_dumps: 3,
            ..DumpTrigger::default()
        }),
        ..Default::default()
    };
    let mut output = render(&ctx, &mut request, vec![]);
    for _ in 0..3 {
        output = render(&ctx, &mut request, vec![]);
    }
    let shown = labels(&output);
    let find = |text: &str| {
        shown
            .iter()
            .find(|(t, _)| t == text)
            .unwrap_or_else(|| panic!("{text}: {shown:?}"))
            .1
    };
    let core = find("Core of the process that triggered it");
    let nonresident = find("Read non-resident pages");
    let memory = find("Memory dump");
    let cores = find("core(s) per run");
    let dumps = find("memory dump(s) per run");
    let cap = find("Only if the VM has at most");
    // Each setting sits under its own box.
    assert!(core.top() < cores.top() && cores.top() < memory.top());
    assert!(core.top() < nonresident.top() && nonresident.top() < memory.top());
    assert!(memory.top() < dumps.top() && dumps.top() < cap.top());
    assert!(shown.iter().any(|(t, _)| t == "2"), "{shown:?}");
    assert!(shown.iter().any(|(t, _)| t == "3"), "{shown:?}");
    // The memory dump off: its settings go, the core's stay.
    request.dump_trigger.as_mut().unwrap().memory = false;
    for _ in 0..3 {
        output = render(&ctx, &mut request, vec![]);
    }
    let shown = labels(&output);
    assert!(!shown.iter().any(|(t, _)| t == "memory dump(s) per run"));
    assert!(shown.iter().any(|(t, _)| t == "core(s) per run"));
    let plan = request.dump_trigger.unwrap();
    assert_eq!((plan.max_cores, plan.max_memory_dumps), (2, 3));
}
