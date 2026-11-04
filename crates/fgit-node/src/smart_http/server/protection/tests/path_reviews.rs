use super::*;

fn selector(path: &[u8], scope: &str, count: u16) -> String {
    format!(
        "{}:{scope}:{}:{count}:{},{}",
        hex(b"refs/heads/main"),
        hex(path),
        person(3),
        person(2)
    )
}

#[test]
fn native_path_policy_is_order_independent_complete_and_can_protect_without_branch_reviewers() {
    let prefix = format!(
        "expected_version=1&expected_epoch=2&administrator={}",
        person(1)
    );
    let a = format!(
        "required_path_review={}",
        selector(b"src/\xff", "subtree", 1)
    );
    let b = format!("required_path_review={}", selector(b"src/\xff", "exact", 2));
    let selected = parse_command(format!("{prefix}&{a}&{b}").as_bytes()).unwrap();
    assert_eq!(
        parse_command(format!("{b}&{prefix}&{a}").as_bytes()).unwrap(),
        selected
    );
    let branch = &selected.protection.branches[0];
    assert!(branch.reviewers.is_empty());
    assert_eq!(branch.required_approvals, 0);
    assert_eq!(branch.path_reviews[0].scope, PathReviewScope::Exact);
    assert_eq!(branch.path_reviews[1].path, b"src/\xff");
    let shown = policy_json(&selected.protection).unwrap();
    assert!(shown.contains("\"path_hex\":\"7372632fff\""));
    assert!(shown.contains("\"scope\":\"subtree\""));
    assert!(parse_command(format!("{prefix}&{a}&{a}").as_bytes()).is_err());
    assert!(parse_command(format!("{prefix}&{a}&clear=true").as_bytes()).is_err());
    let combined = parse_command(format!("{}&{a}", form()).as_bytes()).unwrap();
    assert!(!combined.protection.branches[0].reviewers.is_empty());
}

#[test]
fn hostile_path_fields_counts_and_branch_bounds_fail_closed() {
    for value in [
        selector(b"src", "glob", 1),
        selector(b"/src", "exact", 1),
        selector(b"src/..", "exact", 1),
        selector(b"src/\0", "exact", 1),
        selector(b"src", "exact", 0),
        selector(b"src", "exact", 3),
        selector(b"src", "exact", 1).replace(&person(3).to_string(), &person(2).to_string()),
        selector(b"src", "exact", 1) + ":extra",
    ] {
        assert!(
            parse_command(format!("{}&required_path_review={value}", form()).as_bytes()).is_err()
        );
    }
    let mut body = form();
    for i in 0..MAX_BRANCH_PATH_REVIEWS {
        write!(
            body,
            "&required_path_review={}",
            selector(format!("src/{i}").as_bytes(), "subtree", 1)
        )
        .unwrap();
    }
    assert!(parse_command(body.as_bytes()).is_ok());
    write!(
        body,
        "&required_path_review={}",
        selector(b"overflow", "exact", 1)
    )
    .unwrap();
    assert!(parse_command(body.as_bytes()).is_err());
}
