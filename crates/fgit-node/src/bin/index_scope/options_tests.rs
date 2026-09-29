use super::*;
fn args(op: &str, flags: &[&str]) -> Vec<OsString> {
    let mut values = vec![
        op.into(),
        "node".into(),
        "11".repeat(16).into(),
        "22".repeat(16).into(),
        "sha1".into(),
        "refs/heads/main".into(),
        "--trusted-local".into(),
        "--prefix".into(),
        "src".into(),
    ];
    values.extend(flags.iter().map(|value| OsString::from(*value)));
    values
}
#[test]
fn scope_input_is_copied_and_canonicalized_but_remains_separate_from_query_filters() {
    let mut input = args(
        "search",
        &[
            "--term",
            "NEEDLE",
            "--prefix",
            "src/a",
            "--prefix-hex",
            "726177ff",
            "--filter-prefix",
            "src/a",
        ],
    );
    let options = parse(&input).unwrap();
    input.clear();
    assert_eq!(
        options.scope.prefixes(),
        &[b"raw\xff".to_vec(), b"src".to_vec()]
    );
    let Command::Search { query, .. } = options.command else {
        panic!("expected search");
    };
    assert_eq!(query.terms(), &[b"needle".to_vec()]);
    assert_eq!(query.prefixes(), &[b"src/a".to_vec()]);
}
#[test]
fn explicit_authority_scope_and_candidate_record_are_required_before_node_open() {
    let input = args("build", &["--candidate-file", "private/new.json"]);
    assert!(parse(&input).is_ok());
    let mut no_trust = input.clone();
    no_trust.remove(6);
    assert!(parse(&no_trust).is_err());
    let mut no_scope = input;
    no_scope.drain(7..9);
    assert!(parse(&no_scope).is_err());
    assert!(parse(&args("build", &[])).is_err());
    for flags in [
        &["--candidate-file", "x", "--term", "needle"][..],
        &["--candidate-file", "x", "--force", "true"],
        &["--candidate-file", "x", "--candidate-file", "y"],
        &["--candidate-file", "x", "--max-file-bytes", "8388609"],
    ] {
        assert!(parse(&args("build", flags)).is_err());
    }
}
#[test]
fn search_refuses_unknown_and_inapplicable_fields_and_empty_terms() {
    assert!(parse(&args("search", &[])).is_err());
    for flags in [
        &["--term", "a b"][..],
        &["--term", "needle", "--channel", "symbols"],
        &["--term", "needle", "--limit", "0"],
        &["--term", "needle", "--limit", "4097"],
        &["--term", "needle", "--max-file-bytes", "10"],
        &["--term", "needle", "--source-mode", "revalidated"],
        &["--term", "needle", "--trusted-local"],
        &["--term", "needle", "--index-number", "1"],
        &["--term", "needle", "--minimum-index-number", "1"],
    ] {
        assert!(parse(&args("search", flags)).is_err(), "{flags:?}");
    }
    assert!(
        parse(&args(
            "search",
            &[
                "--term-hex",
                "6e6565646c65",
                "--channel",
                "path",
                "--limit",
                "4096"
            ]
        ))
        .is_ok()
    );
}
#[test]
fn exact_u64_floors_and_continuations_are_lossless_and_fully_pinned() {
    let token = format!("alg:2:{}", "a".repeat(64));
    let commit = "b".repeat(40);
    let flags = [
        "--term",
        "needle",
        "--after",
        "18446744073709551615",
        "--index-token",
        &token,
        "--index-number",
        "18446744073709551615",
        "--expected-head",
        &token,
        "--expected-commit",
        &commit,
    ];
    let options = parse(&args("search", &flags)).unwrap();
    let Command::Search {
        generation, after, ..
    } = options.command
    else {
        panic!("expected search");
    };
    assert_eq!(after, Some(u64::MAX));
    assert_eq!(generation.unwrap().authority_generation.get(), u64::MAX);
    for missing in [
        "--index-token",
        "--index-number",
        "--expected-head",
        "--expected-commit",
    ] {
        let mut input = args("search", &flags);
        let at = input.iter().position(|a| a == missing).unwrap();
        input.drain(at..at + 2);
        assert!(parse(&input).is_err(), "{missing}");
    }
    for bad in ["", "-1", "01", "+1", "1.0", "1e2", "18446744073709551616"] {
        assert!(decimal(bad).is_err());
    }
}
#[test]
fn native_hash_domain_and_token_shape_are_validated() {
    let mut input = args(
        "search",
        &["--term", "needle", "--expected-commit", &"a".repeat(64)],
    );
    assert!(parse(&input).is_err());
    input[4] = "sha256".into();
    assert!(parse(&input).is_ok());
    for bad in [
        "alg:1:".to_owned() + &"a".repeat(64),
        format!("alg:2:{}", "0".repeat(64)),
        format!("alg:2:{}", "A".repeat(64)),
        format!("alg:2:{}", "a".repeat(63)),
    ] {
        assert!(generation(&bad).is_err());
    }
}
#[test]
fn recovery_requires_original_candidate_and_never_accepts_source_reselection() {
    let token = format!("alg:2:{}", "c".repeat(64));
    assert!(parse(&args("recover", &["--candidate", &token])).is_ok());
    assert!(
        parse(&args(
            "recover",
            &[
                "--candidate",
                &token,
                "--minimum-index-token",
                &token,
                "--minimum-index-number",
                "9"
            ]
        ))
        .is_ok()
    );
    for flags in [
        vec![],
        vec!["--candidate", &token, "--term", "needle"],
        vec!["--candidate", &token, "--expected-head", &token],
        vec!["--candidate", &token, "--minimum-index-number", "9"],
    ] {
        assert!(parse(&args("recover", &flags)).is_err());
    }
}
#[test]
fn oversized_arguments_and_invalid_paths_refuse_before_copying_native_scope() {
    let mut input = args("search", &["--term", "needle"]);
    input.push("x".repeat(8193).into());
    assert!(parse(&input).is_err());
    for path in ["", "../src", "src//a", ".Git/a", "/src"] {
        let mut input = args("search", &["--term", "needle"]);
        input[8] = path.into();
        assert!(parse(&input).is_err());
    }
    let mut input = args("search", &["--term", "needle"]);
    input[5] = "main".into();
    assert!(parse(&input).is_err());
}
