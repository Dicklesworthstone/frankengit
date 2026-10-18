use super::*;
fn input() -> Vec<String> {
    vec![
        "set".into(),
        "unused-storage".into(),
        "11".repeat(16),
        "22".repeat(16),
        "--trusted-local".into(),
        "--principal".into(),
        "33".repeat(16),
        "--idempotency-key".into(),
        "do-not-echo".into(),
        "--expected-version".into(),
        "0".into(),
        "--expected-epoch".into(),
        "1".into(),
        "--admin".into(),
        "33".repeat(16),
        "--require-reviewer".into(),
        format!("refs/heads/main:{}", "44".repeat(16)),
    ]
}
#[test]
fn complete_policy_is_canonical_and_does_not_infer_versions_or_ownership() {
    let mut a = input();
    a.extend([
        "--require-reviewer".into(),
        format!("refs/heads/main:{}", "55".repeat(16)),
    ]);
    let mut b = a.clone();
    b.swap(16, 18);
    let Operation::Set { command: ca, .. } = parse(&a).unwrap().operation else {
        panic!()
    };
    let Operation::Set { command: cb, .. } = parse(&b).unwrap().operation else {
        panic!()
    };
    assert_eq!(ca, cb);
    for flag in [
        "--principal",
        "--idempotency-key",
        "--expected-version",
        "--expected-epoch",
        "--admin",
    ] {
        let mut a = input();
        let i = a.iter().position(|s| s == flag).unwrap();
        a.drain(i..i + 2);
        assert!(parse(&a).is_err(), "{flag}");
    }
    let mut a = input();
    a.retain(|s| s != "--trusted-local");
    assert!(parse(&a).is_err());
}
#[test]
fn clear_is_explicit_and_does_not_erase_administrators() {
    let mut a = input();
    a.truncate(a.len() - 2);
    assert!(parse(&a).is_err());
    a.push("--clear".into());
    let Operation::Set { command, .. } = parse(&a).unwrap().operation else {
        panic!()
    };
    assert!(command.protection.branches.is_empty());
    assert_eq!(command.protection.administrators.len(), 1);
    let mut a = input();
    a.push("--clear".into());
    assert!(parse(&a).is_err());
}
#[test]
fn duplicates_nonbranches_overflow_unknown_flags_and_read_mutations_refuse() {
    for pair in [
        ["--admin".into(), "33".repeat(16)],
        [
            "--require-reviewer".into(),
            format!("refs/heads/main:{}", "44".repeat(16)),
        ],
        ["--force".into(), "true".into()],
        ["--object-format".into(), "wrong".into()],
    ] {
        let mut a = input();
        a.extend(pair);
        assert!(parse(&a).is_err());
    }
    for text in [
        "refs/tags/main:abcd",
        "refs/heads/main",
        "refs/heads/main:zz",
        ":00",
    ] {
        let mut a = input();
        *a.last_mut().unwrap() = text.into();
        assert!(parse(&a).is_err());
    }
    for text in [
        "0",
        "01",
        "-1",
        "18446744073709551615",
        "18446744073709551616",
    ] {
        let mut a = input();
        a[12] = text.into();
        assert!(parse(&a).is_err(), "epoch {text}");
    }
    let mut a = input();
    a[0] = "show".into();
    assert!(parse(&a).is_err());
}

#[test]
fn required_check_cli_binds_full_job_names_and_explicit_publisher_graph_and_source() {
    let mut args = input();
    args.truncate(args.len() - 2);
    let check = format!("refs/heads/main:refs/heads/ci-candidate:{}:{}:build:linux λ",
        "77".repeat(16), "55".repeat(32));
    args.extend(["--require-check".into(), check.clone()]);
    let Operation::Set { command, .. } = parse(&args).unwrap().operation else { panic!() };
    let rule = &command.protection.branches[0];
    assert!(rule.reviewers.is_empty());
    assert_eq!(rule.required_checks.len(), 1);
    assert_eq!(rule.required_checks[0].job, "build:linux λ");
    assert_eq!(rule.required_checks[0].publisher, PrincipalId::from_bytes([0x77; 16]));
    assert_eq!(rule.required_checks[0].graph_root, [0x55; 32]);
    assert_eq!(rule.required_checks[0].source_ref.as_bytes(), b"refs/heads/ci-candidate");
    assert!(policy_json(&command.protection).contains("\"required_checks\":["));
    args.extend(["--require-check".into(), check]);
    assert!(parse(&args).is_err(), "duplicate checks cannot collapse silently");
}
#[test]
fn required_check_cli_refuses_malformed_or_ambiguous_selectors() {
    for value in [
        format!("refs/heads/main:refs/tags/ci:{}:{}:job", "77".repeat(16), "55".repeat(32)),
        format!("refs/heads/main:refs/heads/ci:{}:{}:job", "77".repeat(16), "FF".repeat(32)),
        format!("refs/heads/main:refs/heads/ci:{}:{}:", "77".repeat(16), "55".repeat(32)),
        format!("refs/heads/main:refs/heads/ci:{}:{}:bad\njob", "77".repeat(16), "55".repeat(32)),
        format!("refs/heads/main:refs/heads/ci:{}:55:job", "77".repeat(16)),
    ] {
        let mut args = input();
        args.extend(["--require-check".into(), value]);
        assert!(parse(&args).is_err());
    }
}
