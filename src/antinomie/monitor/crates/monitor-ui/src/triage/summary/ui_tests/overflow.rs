// SPDX-License-Identifier: GPL-3.0-only
//! ANT-T0589: a long unbroken indicator (a URL, a path) and thousands of
//! indicators never make the Summary wider than its window.
use super::*;
use antinomie_monitor_core::ioc::indicator::Type;

/// A recording like a botnet's: endpoints, DNS names, URLs with a query of
/// 300 characters and no space, and a file under a path as long.
fn crowded_indicators(view: &mut TriageView) {
    let mut all = indicators::tests::sample();
    for n in 0..2_000 {
        all.push(indicators::tests::indicator(
            Type::Endpoint,
            &format!("10.{}.{}.{}:5555", n / 65_536, (n / 256) % 256, n % 256),
        ));
    }
    for n in 0..40 {
        all.push(indicators::tests::indicator(
            Type::Url,
            &format!("GET 10.0.0.{n}/setup.cgi?x={}", "a/b;c+d=".repeat(37)),
        ));
    }
    let mut file = indicators::tests::indicator(Type::File, "long");
    file.path = format!("/tmp/{}", "deep".repeat(75));
    file.roles = vec!["created".into()];
    all.push(file);
    view.scan.as_mut().unwrap().ioc = Some(std::sync::Arc::new(
        crate::triage::ioc_scan::IocScan::for_tests(all),
    ));
}

/// How far the long rows' text reaches past the edge it is clipped at
/// (`texts` leaves a clipped text out, so it is read from the shapes), and
/// how many of them were drawn.
fn long_rows(out: &egui::FullOutput) -> (f32, usize) {
    fn walk(shape: &egui::Shape, clip: egui::Rect, found: &mut (f32, usize)) {
        match shape {
            egui::Shape::Text(text) => {
                let galley = text.galley.text();
                if galley.contains("setup.cgi") || galley.starts_with("/tmp/deepdeep") {
                    let rect = text.visual_bounding_rect();
                    found.0 = found.0.max(rect.right() - clip.right());
                    found.1 += 1;
                }
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|one| walk(one, clip, found)),
            _ => {}
        }
    }
    let mut found = (f32::MIN, 0);
    for shape in &out.shapes {
        walk(&shape.shape, shape.clip_rect, &mut found);
    }
    found
}

fn widest(out: &egui::FullOutput) -> f32 {
    texts(out)
        .iter()
        .map(|(_, rect)| rect.right())
        .fold(0.0, f32::max)
}

#[test]
fn a_long_url_or_path_and_thousands_of_indicators_stay_inside_the_window() {
    for (width, font) in [(1280.0, 16.0), (800.0, 16.0), (1000.0, 24.0)] {
        let (_files, mut view) = fixture();
        crowded_indicators(&mut view);
        let size = egui::vec2(width, 2600.0);
        let ctx = context(font);
        let mut out = settle(&ctx, &mut view, size, None);
        assert!(has(&out, "URLs (42)"), "{:?}", texts(&out));
        assert!(
            widest(&out) <= width,
            "{width} wide at {font}: the content reaches {}",
            widest(&out)
        );
        // The long rows are drawn, and cut inside their clip.
        let (past, drawn) = long_rows(&out);
        assert!(drawn >= 3, "{drawn} long rows drawn");
        assert!(
            past <= 1.0,
            "{width} wide at {font}: a long row runs {past} past its clip"
        );
        // Opened, the lists scroll inside the same width.
        for more in ["Show 2005 more", "Show 37 more"] {
            if has(&out, more) {
                click(&ctx, &mut view, size, find(&out, more).center());
                out = settle(&ctx, &mut view, size, None);
            }
        }
        assert!(
            long_rows(&out).0 <= 1.0,
            "{width} wide at {font}, lists open: a long row runs past its clip"
        );
        assert!(
            widest(&out) <= width,
            "{width} wide at {font}, lists open: the content reaches {}",
            widest(&out)
        );
    }
}
