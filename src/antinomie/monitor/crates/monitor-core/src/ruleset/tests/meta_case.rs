// SPDX-License-Identifier: GPL-3.0-only
//! Well-known YARA meta keys are read in any case.
use super::*;

fn only(text: &str) -> IndexedRule {
    parse_yara(text).into_iter().next().unwrap()
}

#[test]
fn a_capital_description_is_the_description() {
    for key in ["Description", "DESCRIPTION", "description"] {
        let rule = only(&format!(
            "rule R {{ meta:\n  {key} = \"finds a thing\"\n  Author = \"Ann\"\n condition: true }}"
        ));
        assert_eq!(rule.condition, "finds a thing", "{key}");
        assert_eq!(rule.author, "Ann");
    }
}

#[test]
fn the_lowercase_key_wins_when_both_are_set() {
    let rule = only(
        "rule R {\n meta:\n  Description = \"upper\"\n  description = \"lower\"\n  AUTHOR = \"U\"\n  author = \"l\"\n  License = \"MIT\"\n  Reference = \"https://a\"\n condition:\n  true\n}",
    );
    assert_eq!(rule.condition, "lower");
    assert_eq!(rule.author, "l");
    assert_eq!(rule.license, "MIT");
    assert_eq!(rule.references, vec!["https://a".to_owned()]);
}

#[test]
fn meta_get_prefers_the_exact_key() {
    let pairs = [("Author", "a"), ("author", "b"), ("DESCRIPTION", "d")];
    assert_eq!(meta_get(pairs, "author"), Some("b"));
    assert_eq!(meta_get(pairs, "description"), Some("d"));
    assert_eq!(meta_get(pairs, "license"), None);
}

#[test]
fn the_license_filter_reads_any_case_and_prefers_exact() {
    let body = "rule R {\n meta:\n  License = \"GPL\"\n  license = \"MIT\"\n condition: true\n}";
    assert_eq!(
        license_by_keys(body, &["license", "yarahub_license"]).as_deref(),
        Some("MIT")
    );
    let upper = "rule R {\n meta:\n  YARAHUB_LICENSE = \"CC0\"\n condition: true\n}";
    assert_eq!(
        license_by_keys(upper, &["license", "yarahub_license"]).as_deref(),
        Some("CC0")
    );
}
