// SPDX-License-Identifier: GPL-3.0-only
//! The UI-free crates must not link the GUI stack (design 2.1): none of
//! `antinomie-cli`, `antinomie-service` (and later `antinomie-triage`) may
//! depend on egui, eframe, winit or `antinomie-monitor-ui`.
use std::process::Command;

const FORBIDDEN: [&str; 6] = [
    "egui",
    "eframe",
    "winit",
    "egui_extras",
    "egui_dock",
    "antinomie-monitor-ui",
];

fn tree(package: &str) -> Vec<String> {
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--offline",
            "--prefix",
            "none",
            "--edges",
            "normal,build",
        ])
        .args(["--manifest-path", manifest, "-p", package])
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree -p {package}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn headless_crates_do_not_depend_on_the_gui_stack() {
    for package in ["antinomie-cli", "antinomie-service", "antinomie-triage"] {
        let crates = tree(package);
        assert!(
            crates.iter().any(|name| name == "antinomie-monitor-core"),
            "{package} should depend on the engine"
        );
        for forbidden in FORBIDDEN {
            assert!(
                !crates.iter().any(|name| name == forbidden),
                "{package} depends on {forbidden}"
            );
        }
    }
}
