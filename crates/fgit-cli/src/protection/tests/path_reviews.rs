use super::*;

fn command(args: &[String]) -> ProtectionCommand {
    let Operation::Set { command, .. } = parse(args).unwrap().operation else {
        panic!("set")
    };
    command
}
fn selector(path: &[u8], scope: &str, count: u16) -> String {
    format!(
        "refs/heads/main:{scope}:{}:{count}:{},{}",
        bytes_hex(path),
        "44".repeat(16),
        "33".repeat(16)
    )
}

#[test]
fn path_only_and_combined_policies_retain_native_bytes_and_canonical_identity() {
    let mut args = input();
    let historical = command(&args);
    assert!(historical.protection.branches[0].path_reviews.is_empty());
    args.extend([
        "--require-path-review".into(),
        selector(b"src/\xff", "subtree", 1),
    ]);
    let mixed = command(&args);
    assert_eq!(
        mixed.protection.branches[0].reviewers,
        historical.protection.branches[0].reviewers
    );
    let rule = &mixed.protection.branches[0].path_reviews[0];
    assert_eq!(rule.path, b"src/\xff");
    assert_eq!(rule.scope, PathReviewScope::Subtree);
    assert_eq!(rule.required_approvals, 1);
    assert!(rule.reviewers[0] < rule.reviewers[1]);
    let shown = policy_json(&mixed.protection).unwrap();
    assert!(shown.contains("\"path_hex\":\"7372632fff\""));
    assert!(shown.contains("\"scope\":\"subtree\""));
    args.drain(15..17);
    let paths_only = command(&args);
    assert_eq!(paths_only.protection.branches[0].required_approvals, 0);
    assert!(paths_only.protection.branches[0].reviewers.is_empty());
    args.extend([
        "--require-path-review".into(),
        selector(b"src/\xff", "exact", 2),
    ]);
    let ordered = command(&args);
    args.swap(16, 18);
    assert_eq!(command(&args), ordered);
    assert_eq!(
        ordered.protection.branches[0].path_reviews[0].scope,
        PathReviewScope::Exact
    );
}

#[test]
fn malformed_paths_counts_principals_and_duplicate_selectors_refuse() {
    for path in [
        &b""[..],
        b"/src",
        b"src/",
        b"src//lib",
        b"src/../lib",
        b"./lib",
        b"src/\0",
    ] {
        let mut args = input();
        args.extend(["--require-path-review".into(), selector(path, "subtree", 1)]);
        assert!(parse(&args).is_err(), "{path:?}");
    }
    for value in [
        selector(b"src", "glob", 1),
        selector(b"src", "exact", 0),
        selector(b"src", "exact", 3),
        selector(b"src", "exact", 1).replace("737263", "73726A"),
        selector(b"src", "exact", 1).replace(&"44".repeat(16), &"33".repeat(16)),
    ] {
        let mut args = input();
        args.extend(["--require-path-review".into(), value]);
        assert!(parse(&args).is_err());
    }
    let mut args = input();
    for count in [1, 2] {
        args.extend([
            "--require-path-review".into(),
            selector(b"src", "exact", count),
        ]);
    }
    assert!(parse(&args).is_err());
}

#[test]
fn path_byte_and_branch_rule_limits_are_inclusive() {
    let mut args = input();
    args.extend([
        "--require-path-review".into(),
        selector(&vec![b'x'; MAX_PATH_REVIEW_PATH_BYTES], "exact", 1),
    ]);
    assert!(parse(&args).is_ok());
    *args.last_mut().unwrap() = selector(&vec![b'x'; MAX_PATH_REVIEW_PATH_BYTES + 1], "exact", 1);
    assert!(parse(&args).is_err());
    let mut args = input();
    for i in 0..MAX_BRANCH_PATH_REVIEWS {
        args.extend([
            "--require-path-review".into(),
            selector(format!("src/{i:02}").as_bytes(), "exact", 1),
        ]);
    }
    assert!(parse(&args).is_ok());
    args.extend([
        "--require-path-review".into(),
        selector(b"overflow", "exact", 1),
    ]);
    assert!(parse(&args).is_err());
}
