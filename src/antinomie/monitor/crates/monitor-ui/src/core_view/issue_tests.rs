// SPDX-License-Identifier: GPL-3.0-only
use super::*;

#[test]
fn a_standing_issue_is_reported_once_until_the_list_is_reloaded_or_it_changes() {
    let ctx = egui::Context::default();
    let mut view = CoreView::default();
    view.catalog_issues = vec!["Run a: broken".into()];
    assert_eq!(view.report_new_issues(&ctx), 1);
    for _ in 0..5 {
        assert_eq!(view.report_new_issues(&ctx), 0, "no repeat per frame");
    }
    view.catalog_issues.push("Run b: other".into());
    assert_eq!(view.report_new_issues(&ctx), 1, "a new issue is reported");
    view.set_catalog_scope(&[], Some("vm"));
    view.set_catalog_scope(&[], Some("other"));
    view.catalog_issues = vec!["Run a: broken".into()];
    assert_eq!(view.report_new_issues(&ctx), 1, "a reload reports again");
}

#[test]
fn the_legacy_arm_reply_record_reads_in_plain_words() {
    let stored = "process-core arm: invalid acquisition reply length or padding";
    let text = catalog::plain_issue(stored);
    assert_eq!(
        text,
        "This run's core dump record is from an older guest and can't be listed"
    );
    assert_eq!(catalog::plain_issue("something else"), "something else");
}
