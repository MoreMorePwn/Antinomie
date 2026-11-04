// SPDX-License-Identifier: GPL-3.0-only
//! The counts line of the Detection rules page, in the style of the IOC
//! tab's "x of y loaded · size": what is installed and switched on.
use super::Model;

/// "1 pack", "2 packs".
fn counted(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// The line itself: installed packs, how many are enabled, custom groups
/// and the string patterns in use.
pub(super) fn line(packs: usize, enabled: usize, groups: usize, patterns: usize) -> String {
    format!(
        "{} · {enabled} enabled · {} · {}",
        counted(packs, "pack", "packs"),
        counted(groups, "custom group", "custom groups"),
        counted(patterns, "string pattern", "string patterns"),
    )
}

impl Model {
    /// The counts line for the current registry and string patterns.
    pub(super) fn counts_line(&self) -> String {
        let packs = &self.registry.packs;
        let groups = self.registry.groups.iter().filter(|g| !g.deleted).count();
        line(
            packs.len(),
            packs.iter().filter(|pack| pack.enabled).count(),
            groups,
            self.regex.active_count(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::line;

    #[test]
    fn the_line_counts_in_the_right_number() {
        assert_eq!(
            line(1, 1, 1, 1),
            "1 pack · 1 enabled · 1 custom group · 1 string pattern"
        );
        assert_eq!(
            line(3, 2, 0, 40),
            "3 packs · 2 enabled · 0 custom groups · 40 string patterns"
        );
    }
}
