use super::*;

fn arguments(extra: &[&str]) -> Vec<String> {
    [
        "node",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "33333333333333333333333333333333",
        "literal-retry-key",
        "source",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(str::to_owned)
    .collect()
}

#[test]
fn original_import_shape_preserves_scope_and_retry_identity() {
    let options = parse(&arguments(&[])).unwrap();
    assert_eq!(options.storage, PathBuf::from("node"));
    assert_eq!(options.source, PathBuf::from("source"));
    assert_eq!(options.key, b"literal-retry-key");
    assert_eq!(options.principal, PrincipalId::from_bytes([0x33; 16]));
    assert!(options.incarnation.is_none());
    assert!(options.timeout.is_none());
}

#[test]
fn timeout_and_incarnation_work_in_either_order() {
    let incarnation = "44444444444444444444444444444444";
    for extras in [
        vec![
            "--timeout-secs",
            "600",
            "--expected-incarnation",
            incarnation,
        ],
        vec![
            "--expected-incarnation",
            incarnation,
            "--timeout-secs",
            "600",
        ],
    ] {
        let options = parse(&arguments(&extras)).unwrap();
        assert_eq!(
            options.timeout.unwrap().duration(),
            Duration::from_secs(600)
        );
        assert_eq!(
            options.incarnation,
            Some(RepositoryIncarnationId::from_bytes([0x44; 16]))
        );
    }
}

#[test]
fn invalid_and_duplicate_budgets_never_reach_node_open() {
    for token in [
        "",
        "0",
        "-1",
        "+1",
        "1.0",
        " 1",
        "1 ",
        "18446744073709551616",
    ] {
        assert!(
            parse(&arguments(&["--timeout-secs", token])).is_err(),
            "{token:?}"
        );
    }
    for extras in [
        vec!["--timeout-secs"],
        vec!["--timeout-secs", "1", "--timeout-secs", "2"],
        vec!["--unknown", "1"],
        vec!["--expected-incarnation", "bad"],
        vec![
            "--expected-incarnation",
            "44444444444444444444444444444444",
            "--expected-incarnation",
            "55555555555555555555555555555555",
        ],
    ] {
        assert!(parse(&arguments(&extras)).is_err(), "{extras:?}");
    }
    assert!(parse(&arguments(&["--timeout-secs", "1"])).is_ok());
}

#[test]
fn malformed_principal_key_and_path_are_rejected_before_effects() {
    for (index, bad) in [
        (0, ""),
        (1, "bad"),
        (2, "bad"),
        (3, "bad"),
        (4, ""),
        (5, ""),
    ] {
        let mut args = arguments(&[]);
        args[index] = bad.into();
        assert!(parse(&args).is_err());
    }
    let mut args = arguments(&[]);
    args[5] = "x".repeat(4097);
    assert!(parse(&args).is_err());
    assert!(parse(&arguments(&[])).is_ok());
}

#[test]
fn json_is_an_independent_flag_in_every_option_position() {
    let incarnation = "44444444444444444444444444444444";
    for extras in [
        vec!["--json"],
        vec![
            "--json",
            "--timeout-secs",
            "600",
            "--expected-incarnation",
            incarnation,
        ],
        vec![
            "--timeout-secs",
            "600",
            "--json",
            "--expected-incarnation",
            incarnation,
        ],
        vec![
            "--timeout-secs",
            "600",
            "--expected-incarnation",
            incarnation,
            "--json",
        ],
    ] {
        let options = parse(&arguments(&extras)).unwrap();
        assert!(options.json);
        assert_eq!(options.key, b"literal-retry-key");
    }
    assert!(!parse(&arguments(&[])).unwrap().json);
    for extras in [
        vec!["--json", "--json"],
        vec!["--json", "false"],
        vec!["--timeout-secs", "--json"],
        vec!["--json", "--timeout-secs"],
        vec!["--expected-incarnation", "--json"],
    ] {
        assert!(parse(&arguments(&extras)).is_err(), "{extras:?}");
    }
}
