// SPDX-License-Identifier: GPL-3.0-only
//! The phases band of the graph as Mermaid text: the run's phases in time
//! order, each pointing at the next, with the weight each one carries.
use super::phases::Span;

/// `spans` as a left-to-right Mermaid flowchart.
pub fn phases(spans: &[Span]) -> String {
    let mut chart = crate::mermaid::Flowchart::new("LR");
    let key = |at: usize, span: &Span| format!("{at}:{}", span.phase.label());
    for (at, span) in spans.iter().enumerate() {
        let detail = if span.weight > 0 {
            format!("weight {}", span.weight)
        } else {
            format!("{} info matches", span.info)
        };
        chart.node(&key(at, span), &format!("{}\n{detail}", span.phase.label()));
    }
    for (at, pair) in spans.windows(2).enumerate() {
        chart.edge(&key(at, &pair[0]), &key(at + 1, &pair[1]), None);
    }
    chart.render()
}

#[cfg(test)]
mod tests {
    use super::super::phases::Phase;
    use super::*;

    #[test]
    fn phases_follow_each_other_in_order() {
        let span = |phase, weight, info| Span {
            phase,
            first: 0,
            last: 1,
            weight,
            info,
        };
        let text = phases(&[
            span(Phase::Recon, 0, 24),
            span(Phase::Download, 14, 0),
            span(Phase::C2, 10, 0),
        ]);
        assert!(text.starts_with("flowchart LR\n"));
        assert!(text.contains("recon<br/>24 info matches"), "{text}");
        assert!(text.contains("download<br/>weight 14"), "{text}");
        assert_eq!(text.matches(" --> ").count(), 2, "{text}");
        assert_eq!(phases(&[]), "flowchart LR\n");
    }
}
