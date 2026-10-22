// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::collections::BTreeSet;

/// Values go into the new system's configuration, so none may carry anything
/// but plain characters.
fn plain(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '+' | '@'))
}

#[test]
fn locales_are_unique_utf8_codes_with_a_label() {
    let mut seen = BTreeSet::new();
    for (code, label) in LOCALES {
        assert!(plain(code) && code.ends_with(".UTF-8"), "{code}");
        assert!(!label.trim().is_empty(), "{code} has no label");
        assert!(seen.insert(*code), "{code} twice");
    }
    assert!(seen.contains("en_US.UTF-8"));
}

#[test]
fn keyboard_layouts_are_unique_and_plain() {
    let mut seen = BTreeSet::new();
    for (code, label) in KEYBOARD_LAYOUTS {
        assert!(plain(code), "{code}");
        assert!(!label.trim().is_empty(), "{code} has no label");
        assert!(seen.insert(*code), "{code} twice");
    }
    assert!(seen.contains("us"));
}

#[test]
fn every_keyboard_variant_belongs_to_a_listed_layout_and_is_unique() {
    let layouts: BTreeSet<_> = KEYBOARD_LAYOUTS.iter().map(|(code, _)| *code).collect();
    let mut seen = BTreeSet::new();
    for (layout, code, label) in KEYBOARD_VARIANTS {
        assert!(
            layouts.contains(layout),
            "variant {code} of unlisted layout {layout}"
        );
        assert!(plain(code), "{layout}/{code}");
        assert!(!label.trim().is_empty(), "{layout}/{code} has no label");
        assert!(seen.insert((*layout, *code)), "{layout}/{code} twice");
    }
}

#[test]
fn time_zones_are_unique_relative_zone_names_in_order() {
    let mut seen = BTreeSet::new();
    for zone in TIMEZONES {
        assert!(plain(zone), "{zone}");
        assert!(!zone.starts_with('/') && !zone.contains(".."), "{zone}");
        assert!(zone.contains('/'), "{zone} has no area");
        assert!(seen.insert(*zone), "{zone} twice");
    }
    assert!(
        TIMEZONES.windows(2).all(|pair| pair[0] <= pair[1]),
        "sorted"
    );
    assert!(seen.contains("Europe/London"));
}
