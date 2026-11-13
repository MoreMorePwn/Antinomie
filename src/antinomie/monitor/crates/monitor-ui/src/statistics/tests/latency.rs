// SPDX-License-Identifier: GPL-3.0-only
//! Card E, Latency: the banners, the warning, the estimates, the links.
use super::*;
use crate::statistics::latency::{self, banner, rows, slowest_percent_click, Part};
use crate::statistics::properties::Tone;
use antinomie_triage::statistics::blocking::BlockClass;
use serde_json::json;

const MS: u64 = 1_000_000;

/// Ten close of 1 to 10 us, five reads of 1 to 5 ms and one of 90 ms, three
/// nanosleeps of 50 to 70 ms, and a read whose exit never arrived.
fn timed_calls() -> Vec<Call> {
    let mut calls = Vec::new();
    let mut t = 1_000 * MS;
    let mut add = |call: Call, duration: u64| {
        t += 10 * MS;
        calls.push(call.at(t, duration));
    };
    for i in 1..=10_u64 {
        add(Call::new(nr::CLOSE, 2).pid(2).returns(3), i * 1_000);
    }
    for i in 1..=5_u64 {
        add(Call::new(nr::READ, 3).pid(2).returns(10), i * MS);
    }
    add(Call::new(nr::READ, 3).pid(2).returns(10), 90 * MS);
    for i in 5..=7_u64 {
        add(Call::new(nr::NANOSLEEP, 3).pid(2).returns(0), i * 10 * MS);
    }
    add(Call::new(nr::READ, 3).pid(2).unfinished(), 0);
    calls
}

/// A rig tall enough that the whole tab is on screen.
fn tall_rig(fixture: &Fixture) -> Rig {
    let mut rig = Rig::new(Some(target(fixture, "run-a")));
    rig.screen = egui::vec2(1400.0, 2200.0);
    rig.window.size = [1300.0, 2100.0];
    rig.window.request_open(Some(Tab::Latency));
    rig
}

fn manifest(accelerator: Option<&str>, waits: u64) -> serde_json::Value {
    let mut value = json!({
        "format": "ANTT run raw LE32",
        "health": {"transport_waits": waits, "transport_wait_ns": 2_100_000_000_u64},
        "run": {"environment": {"accelerator": accelerator.unwrap_or("")}}
    });
    if accelerator.is_none() {
        value["run"] = json!({});
    }
    value
}

#[test]
fn e1_the_banner_names_kvm_tcg_or_a_missing_accelerator() {
    let kvm = banner(Some("kvm"));
    assert_eq!(kvm.tone, Tone::Plain);
    assert!(kvm.text.starts_with("Measured under KVM"), "{}", kvm.text);
    let tcg = banner(Some("tcg (KVM unavailable)"));
    assert_eq!(tcg.tone, Tone::Warn);
    assert!(
        tcg.text.contains("TCG (software emulation)")
            && tcg.text.contains("only with other TCG runs")
    );
    for missing in [None, Some(""), Some("  ")] {
        let none = banner(missing);
        assert_eq!(none.tone, Tone::Warn);
        assert_eq!(none.text, "Accelerator not recorded: compare with care.");
    }
    // On screen, from the manifest.
    for (accelerator, words) in [
        (Some("tcg"), "Measured under TCG"),
        (Some("kvm"), "Measured under KVM"),
        (None, "Accelerator not recorded"),
    ] {
        let fixture = Fixture::with_manifest(&timed_calls(), manifest(accelerator, 0));
        let mut rig = tall_rig(&fixture);
        rig.settle();
        let shown = rig.texts();
        assert!(
            shown.iter().any(|(t, _)| t.contains(words)),
            "{words}: {shown:?}"
        );
        assert!(
            shown.iter().any(|(t, _)| t.contains("recorder's own work")),
            "what it includes is said"
        );
    }
}

#[test]
fn e2_the_send_wait_warning_appears_only_when_the_boot_counted_waits() {
    let with = Fixture::with_manifest(&timed_calls(), manifest(Some("kvm"), 4113));
    let warning = latency::send_wait_warning(&stats_of(&with, "")).expect("a warning");
    assert!(
        warning.contains("4,113 times") && warning.contains("2.10 s"),
        "{warning}"
    );
    let without = Fixture::with_manifest(&timed_calls(), manifest(Some("kvm"), 0));
    assert_eq!(latency::send_wait_warning(&stats_of(&without, "")), None);
    let unknown = Fixture::new(&timed_calls());
    assert_eq!(latency::send_wait_warning(&stats_of(&unknown, "")), None);
    let mut rig = tall_rig(&with);
    rig.settle();
    let shown = rig.texts();
    assert!(
        shown.iter().any(|(t, _)| t.contains("4,113 times")),
        "{shown:?}"
    );
}

#[test]
fn e3_median_and_percentiles_carry_the_approximately_sign_and_min_max_are_exact() {
    let fixture = Fixture::new(&timed_calls());
    let stats = stats_of(&fixture, "");
    let all = rows(&stats, false, None);
    let close = all.iter().find(|r| r.name == "close").unwrap();
    assert_eq!(
        (close.timed, close.min_ns, close.max_ns),
        (10, 1_000, 10_000)
    );
    assert_eq!(close.total_ns, 55_000);
    assert_eq!(close.mean_ns, 5_500);
    let mut rig = tall_rig(&fixture);
    rig.settle();
    let shown = rig.texts();
    for title in ["Median ≈", "p95 ≈", "p99 ≈"] {
        assert!(shown.iter().any(|(t, _)| t == title), "{title}: {shown:?}");
    }
    for exact in ["Min", "Max", "Total", "Mean"] {
        assert!(shown.iter().any(|(t, _)| t == exact), "{exact}");
    }
    // The number of the unfinished call is said.
    assert_eq!(stats.not_timed, 1);
    assert!(
        shown
            .iter()
            .any(|(t, _)| t.contains("1 calls have no entry or no exit")),
        "{shown:?}"
    );
}

#[test]
fn e4_a_slowest_row_opens_that_exact_call() {
    let fixture = Fixture::new(&timed_calls());
    let stats = stats_of(&fixture, "");
    let slowest = &stats.slowest[0];
    assert_eq!(
        (slowest.name.as_str(), slowest.duration_ns),
        ("read", 90 * MS)
    );
    let mut rig = tall_rig(&fixture);
    rig.settle();
    // "read may block" is in the calls table and again in the slowest list.
    let found = all_at(&mut rig, "read may block");
    assert!(found.len() >= 2, "{found:?}");
    rig.press_at(found[1].center());
    assert_eq!(rig.navigated, [Navigate::Call(slowest.key)]);
    // The key is the Trace's own: it finds exactly one call.
    let (stream, cookie, call) = slowest.key;
    let filter =
        format!("stream.id == {stream} && process.cookie == {cookie} && call.id == {call}");
    assert_eq!(super::hierarchy::trace_count(&fixture, &filter), 1);
    // The calls table's own link opens the call name's calls.
    rig.navigated.clear();
    rig.press_at(found[0].center());
    assert_eq!(
        rig.navigated,
        [Navigate::Filter("syscall.name == read".into())]
    );
}

#[test]
fn e5_slowest_one_percent_sends_the_duration_clause() {
    let fixture = Fixture::new(&timed_calls());
    let stats = stats_of(&fixture, "");
    let close = stats.latency.iter().find(|r| r.name == "close").unwrap();
    let click = slowest_percent_click(close);
    assert_eq!(
        click.clause,
        format!(
            "syscall.name == close && syscall.duration_ns >= {}",
            close.p99_ns
        )
    );
    assert_eq!(click.group, SyscallGroup::of("close"));
    let behind = stats_of(&fixture, &click.clause);
    assert!(behind.calls >= 1 && behind.calls <= 2, "{}", behind.calls);
    assert_eq!(
        super::hierarchy::trace_count(&fixture, &click.clause),
        behind.calls + behind.out_of_scope
    );
}

#[test]
fn e6_may_block_calls_are_marked_and_waits_by_design_have_their_own_table() {
    let fixture = Fixture::new(&timed_calls());
    let stats = stats_of(&fixture, "");
    let ordinary = rows(&stats, false, None);
    assert!(ordinary
        .iter()
        .any(|r| r.name == "close" && r.class == BlockClass::Ordinary));
    assert!(ordinary
        .iter()
        .any(|r| r.name == "read" && r.class == BlockClass::MayBlock));
    assert!(ordinary.iter().all(|r| r.class != BlockClass::Waits));
    let waits = rows(&stats, true, None);
    assert_eq!(waits.len(), 1);
    assert_eq!(waits[0].name, "nanosleep");
    // Sorted by total time, longest first, unless a column is chosen.
    assert_eq!(ordinary[0].name, "read");
    let by_name = rows(&stats, false, Some((0, false)));
    assert_eq!(
        by_name.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        ["close", "read"]
    );
    // The longest waits list has the sleeps, the slowest list none.
    assert!(stats.slowest.iter().all(|c| c.name != "nanosleep"));
    assert_eq!(stats.longest_waits.len(), 3);
    let mut rig = tall_rig(&fixture);
    rig.settle();
    let shown = rig.texts();
    let has = |needle: &str| shown.iter().any(|(t, _)| t.contains(needle));
    assert!(has("Calls that wait by design"), "{shown:?}");
    assert!(has("nanosleep"), "{shown:?}");
    assert!(has("Longest waits"), "{shown:?}");
    assert!(has("Slowest ordinary calls"), "{shown:?}");
    // Copy and Export take the part chosen.
    rig.window.latency.part = Part::Waits;
    let stats = stats_of(&fixture, "");
    let table = latency::table(&stats, Part::Waits);
    assert_eq!(table.name, "slowest");
    assert_eq!(table.rows.len(), 3);
    assert_eq!(latency::table(&stats, Part::Blocking).rows.len(), 1);
    assert_eq!(latency::table(&stats, Part::Calls).rows.len(), 2);
}

#[test]
fn e_the_histogram_has_bars_in_log_order_and_a_table_toggle() {
    let fixture = Fixture::new(&timed_calls());
    let stats = stats_of(&fixture, "");
    let read = stats.latency.iter().find(|r| r.name == "read").unwrap();
    let bars = latency::bars(&read.histogram, read.min_ns, read.max_ns);
    assert_eq!(bars.len(), read.histogram.len());
    assert!(
        bars.windows(2).all(|pair| pair[0].0 <= pair[1].0),
        "{bars:?}"
    );
    assert!(bars
        .iter()
        .all(|(x, h)| (0.0..=1.0).contains(x) && (0.0..=1.0).contains(h)));
    assert_eq!(
        read.histogram.iter().map(|(_, n)| n).sum::<u64>(),
        read.timed
    );
    let mut rig = tall_rig(&fixture);
    rig.settle();
    let shown = rig.texts();
    assert!(
        shown
            .iter()
            .any(|(t, _)| t.contains("how long the") && t.contains("timed calls took")),
        "{shown:?}"
    );
    assert!(shown.iter().any(|(t, _)| t == "log scale"), "{shown:?}");
    rig.window.latency.table = true;
    let shown = rig.texts();
    assert!(shown.iter().any(|(t, _)| t == "Up to"), "{shown:?}");
}
