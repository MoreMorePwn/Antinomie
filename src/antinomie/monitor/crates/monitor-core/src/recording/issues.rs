//! Bounded, distinct diagnostics for archive queries.

pub(super) fn push_issue(issues: &mut Vec<String>, message: String) {
    if issues.len() < 32 && !issues.contains(&message) {
        issues.push(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_errors_leave_room_for_distinct_archive_failures() {
        let mut issues = Vec::new();
        for _ in 0..100 {
            push_issue(&mut issues, "first failure".into());
        }
        push_issue(&mut issues, "different failure".into());
        assert_eq!(issues, ["first failure", "different failure"]);
        for number in 0..100 {
            push_issue(&mut issues, format!("failure {number}"));
        }
        assert_eq!(issues.len(), 32);
    }
}
