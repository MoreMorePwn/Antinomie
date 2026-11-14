#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Tests of scripts/check-control-hover.py (item 9 of the 0.9.0 UI round):
the real tree passes; a long or computed hover text on a control fails in
the usual spellings; a name, the `Tip` helpers, the marker, labels, test
code, comments and strings pass."""
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-control-hover.py"
CRATE = "src/antinomie/monitor/crates/monitor-ui/src"


def tree(files):
    d = pathlib.Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return d


def run(body, name="x.rs"):
    d = tree({f"{CRATE}/{name}": body})
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--root", str(d)], capture_output=True, text=True
    )


class Gate(unittest.TestCase):
    def test_the_repository_passes(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_long_text_on_a_control_fails(self):
        for body in [
            'fn f(ui: &mut Ui) { if ui.button("Go").on_hover_text("Open this run in Triage now").clicked() {} }',
            'fn f(ui: &mut Ui) { ui.checkbox(&mut on, "Live").on_hover_text(TIP); }',
            'fn f(ui: &mut Ui) { ui.add_enabled(ok, egui::Button::new("Run")).on_disabled_hover_text(format!("Wait for {x}")); }',
            'fn f(ui: &mut Ui) { egui::ComboBox::from_id_salt("a").show_ui(ui, |ui| {}).response.on_hover_text("Which of the many tiers counts"); }',
            'fn f(ui: &mut Ui) { let response = ui.add(egui::DragValue::new(&mut v));\n response.on_hover_text("From one to ten seconds, at most"); }',
            'fn f(ui: &mut Ui) { ui.button("Go").on_hover_ui(|ui| { ui.label("x"); }); }',
            'fn f(ui: &mut Ui) { ui.button(ICON).name_tip("Open this category in a separate pane"); }',
        ]:
            with self.subTest(body=body):
                r = run(body)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("x.rs:", r.stderr)

    def test_names_helpers_markers_and_non_controls_pass(self):
        for body in [
            'fn f(ui: &mut Ui) { ui.button(egui_phosphor::regular::COPY).on_hover_text("Copy"); }',
            'fn f(ui: &mut Ui) { ui.button(ICON).name_tip(name); }',
            'fn f(ui: &mut Ui) { ui.selectable_label(on, short).value_tip(full_path); }',
            'fn f(ui: &mut Ui) { ui.add_enabled(ok, egui::Button::new("Run")).reason_tip(why); }',
            'fn f(ui: &mut Ui) {\n // hover: the whole command line\n ui.button(cmd).on_hover_text(full); }',
            'fn f(ui: &mut Ui) { ui.label("PID").on_hover_text("The process id the kernel gave it, at start"); }',
            'fn f(ui: &mut Ui) { crate::widgets::with_help(ui, "A long explanation here, as long as it likes", |ui| ui.button("Go")); }',
            '// ui.button("Go").on_hover_text("Open this run in Triage now")\nfn f() {}',
            'fn f() { let s = "ui.button(\\"Go\\").on_hover_text(\\"Open this run in Triage now\\")"; }',
            '#[cfg(test)]\nmod tests { fn f(ui: &mut Ui) { ui.button("Go").on_hover_text("Open this run in Triage now"); } }',
        ]:
            with self.subTest(body=body):
                r = run(body)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_test_files_are_skipped(self):
        body = 'fn f(ui: &mut Ui) { ui.button("Go").on_hover_text("Open this run in Triage now"); }'
        for name in ["tests/a.rs", "a_tests.rs", "test_a.rs"]:
            with self.subTest(name=name):
                self.assertEqual(run(body, name).returncode, 0)


if __name__ == "__main__":
    unittest.main()
