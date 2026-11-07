// SPDX-License-Identifier: GPL-3.0-only
//! A process's environment against the one its parent had at its own exec.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Change {
    Same,
    Added,
    /// Changed; holds the parent's value.
    Changed(String),
    Removed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Line {
    pub(super) name: String,
    pub(super) value: String,
    pub(super) change: Change,
}

impl Line {
    /// The variable as the exec carried it.
    pub(super) fn text(&self) -> String {
        format!("{}={}", self.name, self.value)
    }

    /// The marker shown before the variable.
    pub(super) fn mark(&self) -> &'static str {
        match self.change {
            Change::Same => " ",
            Change::Added => "+",
            Change::Changed(_) => "~",
            Change::Removed => "\u{2212}",
        }
    }
}

fn split(variable: &str) -> (&str, &str) {
    variable.split_once('=').unwrap_or((variable, ""))
}

/// The variables of `own` in their order, each marked against `parent`
/// (`None`: nothing to compare with, all unchanged), then those only the
/// parent had.
pub(super) fn diff(parent: Option<&[String]>, own: &[String]) -> Vec<Line> {
    let Some(parent) = parent else {
        return own
            .iter()
            .map(|variable| {
                let (name, value) = split(variable);
                Line {
                    name: name.into(),
                    value: value.into(),
                    change: Change::Same,
                }
            })
            .collect();
    };
    let before: std::collections::BTreeMap<&str, &str> =
        parent.iter().map(|variable| split(variable)).collect();
    let mut lines: Vec<Line> = own
        .iter()
        .map(|variable| {
            let (name, value) = split(variable);
            let change = match before.get(name) {
                None => Change::Added,
                Some(old) if *old == value => Change::Same,
                Some(old) => Change::Changed((*old).into()),
            };
            Line {
                name: name.into(),
                value: value.into(),
                change,
            }
        })
        .collect();
    let kept: std::collections::BTreeSet<&str> =
        own.iter().map(|variable| split(variable).0).collect();
    for variable in parent {
        let (name, value) = split(variable);
        if !kept.contains(name) {
            lines.push(Line {
                name: name.into(),
                value: value.into(),
                change: Change::Removed,
            });
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn variables_added_changed_and_removed_are_marked_against_the_parent() {
        let parent = env(&["PATH=/bin", "HOME=/root", "OLD=1"]);
        let own = env(&["PATH=/tmp:/bin", "HOME=/root", "LD_PRELOAD=/tmp/x.so"]);
        let lines = diff(Some(&parent), &own);
        let marks: Vec<_> = lines
            .iter()
            .map(|line| (line.name.as_str(), line.mark()))
            .collect();
        assert_eq!(
            marks,
            [
                ("PATH", "~"),
                ("HOME", " "),
                ("LD_PRELOAD", "+"),
                ("OLD", "\u{2212}")
            ]
        );
        assert_eq!(lines[0].change, Change::Changed("/bin".into()));
        assert_eq!(lines[2].text(), "LD_PRELOAD=/tmp/x.so");
        assert_eq!(lines[3].value, "1");
    }

    #[test]
    fn without_a_parent_environment_nothing_is_marked() {
        let lines = diff(None, &env(&["A=1", "B", "C=x=y"]));
        assert!(lines.iter().all(|line| line.change == Change::Same));
        assert_eq!(lines[1].value, "");
        assert_eq!(lines[2].value, "x=y");
    }
}
