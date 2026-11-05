// SPDX-License-Identifier: GPL-3.0-only
//! The words of the Suspicious activity table's cells: result, count, time
//! span, process, technique and the notes a tier chip carries.
use super::noise::{flag, pace, Agg};
use super::Tier;
use crate::triage::process_cells;

/// "succeeded", "3 of 5 failed" or "all failed". A row with no call result
/// (a packet, a host report) has none to say.
pub(in crate::triage) fn result_text(count: u64, failed: u64, known: bool) -> String {
    if !known {
        "\u{2014}".into()
    } else if failed == 0 {
        "succeeded".into()
    } else if failed >= count {
        "all failed".into()
    } else {
        format!("{failed} of {count} failed")
    }
}

/// "×12", or "×40 every ~5.0 s" for a row that repeats at a steady pace.
pub(in crate::triage) fn count_text(count: u64, period: Option<u64>) -> String {
    match period.filter(|_| count > 1) {
        Some(period) => format!("\u{d7}{count} every ~{}", pace(period)),
        None => format!("\u{d7}{count}"),
    }
}

/// A moment as an offset from the start of the run: "+1.2 s", "+340 ms".
pub(in crate::triage) fn offset(ns: u64, start: u64) -> String {
    let ns = ns.saturating_sub(start);
    if ns < 1_000_000_000 {
        format!("+{} ms", ns / 1_000_000)
    } else {
        format!("+{:.1} s", ns as f64 / 1e9)
    }
}

/// "+1.2 s \u{2192} +9.8 s"; one moment when the row happened once or all
/// at the same time. A row with no known time says so.
pub(in crate::triage) fn when_text(first: u64, last: u64, start: Option<u64>) -> String {
    let Some(start) = start.filter(|_| first != 0) else {
        return "\u{2014}".into();
    };
    let (from, to) = (offset(first, start), offset(last.max(first), start));
    if from == to {
        from
    } else {
        format!("{from} \u{2192} {to}")
    }
}

/// "sshd (418 \u{b7} 418)": the process and thread as the Process tree writes them.
pub(in crate::triage) fn process_text(agg: &Agg, mismatch: bool) -> String {
    if agg.pid == 0 {
        return agg.process.clone();
    }
    let name = agg
        .image
        .as_deref()
        .map(process_cells::file_name)
        .filter(|name| !matches!(*name, "?" | ""))
        .unwrap_or("unknown");
    let ids = match agg.tid {
        0 => format!("({} \u{b7} ?)", agg.pid),
        tid => format!("({} \u{b7} {tid})", agg.pid),
    };
    let warn = if mismatch { "\u{26a0} " } else { "" };
    format!("{warn}{name} {ids}")
}

/// The technique chip of a row: "T1053.003 Cron", with the names of all its
/// techniques for the hover. The ids that name a detection strategy are left out.
pub(in crate::triage) fn technique(ids: &[&str]) -> (String, String) {
    let techniques: Vec<&&str> = ids
        .iter()
        .filter(|id| id.starts_with('T') && !id.starts_with("TA"))
        .collect();
    let Some(first) = techniques.first() else {
        return ("\u{2014}".into(), "No ATT&CK technique".into());
    };
    let name = antinomie_monitor_core::mitre::technique_name(first);
    let short = name
        .as_deref()
        .map(|name| name.rsplit(": ").next().unwrap_or(name));
    let mut chip = match short {
        Some(short) => format!("{first} {short}"),
        None => (**first).to_owned(),
    };
    if techniques.len() > 1 {
        chip.push_str(&format!(" +{}", techniques.len() - 1));
    }
    let hover = techniques
        .iter()
        .map(|id| antinomie_monitor_core::mitre::technique_label(id))
        .collect::<Vec<_>>()
        .join("\n");
    (chip, hover)
}

/// Why a tier is what it is, in one line: the rule's tier and what lowered it.
pub(in crate::triage) fn why_short(agg: &Agg) -> String {
    let mut reasons = Vec::new();
    if agg.flags & flag::ALLOW != 0 {
        reasons.push("the program is on the rule's allow-list");
    }
    if agg.flags & flag::FAILED != 0 && agg.flags & flag::RESTORED == 0 && !agg.spec().signal {
        reasons.push("every call failed");
    }
    if agg.flags & flag::OUTSIDE != 0 {
        reasons.push("the process is outside the run's tree");
    }
    if agg.flags & flag::VM_WIDE != 0 {
        reasons.push("seen only on the network");
    }
    if agg.tier == agg.base || reasons.is_empty() {
        format!("The rule's own tier ({}).", agg.base.label())
    } else {
        format!(
            "The rule's tier is {}; lowered to {} because {}.",
            agg.base.label(),
            agg.tier.label(),
            reasons.join(" and ")
        )
    }
}

/// Why the evidence of a row is limited, when it is.
pub(in crate::triage) fn limited_reason(agg: &Agg) -> Option<&'static str> {
    if agg.high_confidence {
        None
    } else if agg.packet.is_some() {
        Some("Seen in the capture; no process of the run is tied to it.")
    } else {
        Some("The call's entry or exit record is incomplete, so an argument or the result may be missing.")
    }
}

/// The hover of a tier chip: what the tier means and why this row has it.
pub(in crate::triage) fn tier_hover(tier: Tier, why: &str, limited: Option<&str>) -> String {
    let mut text = format!("{}: {}\n\n{why}", tier.label(), tier.meaning());
    if let Some(limited) = limited {
        text.push_str(&format!("\n\n\u{2691} Limited confidence: {limited}"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_result_says_how_many_calls_failed() {
        assert_eq!(result_text(1, 0, true), "succeeded");
        assert_eq!(result_text(12, 0, true), "succeeded");
        assert_eq!(result_text(5, 3, true), "3 of 5 failed");
        assert_eq!(result_text(5, 5, true), "all failed");
        assert_eq!(result_text(1, 1, true), "all failed");
        assert_eq!(result_text(1, 0, false), "\u{2014}");
    }

    #[test]
    fn the_count_names_the_pace_of_a_loop() {
        assert_eq!(count_text(12, None), "\u{d7}12");
        assert_eq!(count_text(40, Some(5_000_000_000)), "\u{d7}40 every ~5.0 s");
        assert_eq!(count_text(1, Some(5_000_000_000)), "\u{d7}1");
    }

    #[test]
    fn the_time_span_reads_from_the_run_start() {
        let start = Some(10_000_000_000);
        assert_eq!(
            when_text(11_200_000_000, 19_800_000_000, start),
            "+1.2 s \u{2192} +9.8 s"
        );
        assert_eq!(when_text(11_200_000_000, 11_200_000_000, start), "+1.2 s");
        assert_eq!(when_text(10_340_000_000, 10_340_000_000, start), "+340 ms");
        assert_eq!(when_text(0, 0, start), "\u{2014}");
        assert_eq!(when_text(5, 5, None), "\u{2014}");
        // A time before the recorded start does not go negative.
        assert_eq!(when_text(9_000_000_000, 9_000_000_000, start), "+0 ms");
    }

    #[test]
    fn a_technique_chip_carries_the_id_and_the_short_name() {
        let (chip, hover) = technique(&["T1053.003", "DET0290"]);
        assert_eq!(chip, "T1053.003 Cron");
        assert!(hover.starts_with("T1053.003 "));
        let (chip, _) = technique(&["T1105", "DET0060", "T1059.004"]);
        assert!(
            chip.starts_with("T1105 ") && chip.ends_with(" +1"),
            "{chip}"
        );
        assert_eq!(technique(&[]).0, "\u{2014}");
        assert_eq!(technique(&["DET0001"]).0, "\u{2014}");
    }
}
