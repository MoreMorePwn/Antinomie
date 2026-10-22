// SPDX-License-Identifier: GPL-3.0-only
use super::*;

#[test]
fn a_kernel_is_named_by_the_app_version_that_shipped_it() {
    let (revision, version) = crate::api::revision_history()
        .into_iter()
        .next()
        .expect("at least one known revision");
    let source = "0123456789abcdef0123";
    assert_eq!(
        describe_source((Some(revision), Some(source))),
        format!("for Antinomie {version} (build 0123456789ab…)")
    );
    assert_eq!(
        describe_source((Some(revision), Some("abc"))),
        format!("for Antinomie {version} (build abc…)"),
        "a short source id is not cut"
    );
    assert_eq!(
        describe_source((Some(revision), None)),
        format!("for Antinomie {version}, unversioned build")
    );
}

#[test]
fn a_kernel_without_a_known_revision_is_named_as_older_or_newer() {
    assert_eq!(describe_source((None, None)), "from before Antinomie 0.1.0");
    assert_eq!(
        describe_source((None, Some("abc"))),
        "from before Antinomie 0.1.0"
    );
    assert_eq!(
        describe_source((Some(u32::MAX), Some("abc"))),
        "for a newer Antinomie"
    );
}
