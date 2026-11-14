// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's notes as bullets, the Screenshots (N) box with its redirect
//! button, and the colours of the four one-line rows.
use super::*;
use antinomie_monitor_core::timed_shots::RunShot;

const REDIRECT: &str = egui_phosphor::regular::ARROW_SQUARE_OUT;

fn shots(count: u64) -> Vec<RunShot> {
    (0..count)
        .map(|step| RunShot {
            t_ms: step * 10_000,
            path: std::path::PathBuf::from(format!("/nonexistent/t+{step}.png")),
            bytes: 10,
        })
        .collect()
}

#[test]
fn notes_are_one_bullet_each_and_the_last_screenshot_is_gone() {
    let (_files, mut view) = fixture();
    view.set_notes(vec!["First note".to_owned(), "Second note".to_owned()]);
    view.set_run_facts(None, shots(2), Vec::new());
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(has(&out, "\u{2022} First note"), "{:?}", texts(&out));
    assert!(has(&out, "\u{2022} Second note"));
    assert!(!texts(&out)
        .iter()
        .any(|(t, _)| t.contains("Last screenshot")));
}

#[test]
fn the_screenshots_box_is_titled_with_its_count_and_has_a_redirect_button() {
    let (_files, mut view) = fixture();
    view.set_run_facts(None, shots(3), Vec::new());
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(has(&out, "Screenshots (3)"), "{:?}", texts(&out));
    assert!(!texts(&out)
        .iter()
        .any(|(t, _)| t.contains("Timed screenshots")));
    // The button sits beside the title, on its line.
    let button = find(&out, REDIRECT);
    let title = find(&out, "Screenshots (3)");
    assert!((button.center().y - title.center().y).abs() < 6.0);
    assert!(button.left() >= title.right());
    assert!(!view.take_open_screenshots_page());
    click(&ctx, &mut view, WIDE, button.center());
    assert!(view.take_open_screenshots_page());
    // The button asks for the page only: no picture is opened.
    assert!(view.take_open_screenshot().is_none());
    assert!(!view.take_open_screenshots_page(), "taken once");
}

#[test]
fn a_run_without_screenshots_has_no_screenshots_box() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(!texts(&out).iter().any(|(t, _)| t.contains("Screenshots (")));
}

#[test]
fn the_four_rows_wear_their_own_theme_colours_in_every_theme() {
    for choice in crate::theme::Theme::ALL {
        let (_files, mut view) = fixture();
        view.scan.as_mut().unwrap().network_counts = Some((641, 2, 3));
        let ctx = context(16.0);
        theme::apply_theme(&ctx, choice);
        let out = settle(&ctx, &mut view, WIDE, None);
        let own = [
            ("Processes of interest", theme::triage_processes()),
            ("Files", theme::triage_files()),
            ("Network", theme::triage_network()),
        ];
        for (title, color) in own {
            assert_eq!(colour(&out, title), color, "{title} in {choice:?}");
        }
        let mitre = texts(&out)
            .into_iter()
            .map(|(text, _)| text)
            .find(|text| text.starts_with("MITRE ATT&CK ("));
        if let Some(mitre) = mitre {
            assert_eq!(colour(&out, &mitre), theme::triage_mitre(), "{choice:?}");
        }
        // Four different colours, each readable on the panel.
        let all = [
            theme::triage_mitre(),
            theme::triage_processes(),
            theme::triage_files(),
            theme::triage_network(),
        ];
        for (at, a) in all.iter().enumerate() {
            assert!(all[at + 1..].iter().all(|b| a != b), "{choice:?}: {all:?}");
            assert!(contrast(*a, theme::panel()) >= 3.0, "{choice:?}: {a:?}");
        }
    }
}

/// WCAG contrast ratio of two colours.
fn contrast(a: egui::Color32, b: egui::Color32) -> f32 {
    fn luminance(c: egui::Color32) -> f32 {
        let channel = |v: u8| {
            let v = f32::from(v) / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(c.r()) + 0.7152 * channel(c.g()) + 0.0722 * channel(c.b())
    }
    let (x, y) = (luminance(a), luminance(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

#[test]
fn the_summarys_solid_scroll_bars_use_the_text_coloured_handle_of_the_others() {
    let style = theme::solid_scroll();
    assert!(!style.floating, "it still takes its room");
    assert!(
        style.foreground_color,
        "the handle is not the dark widget fill"
    );
}
