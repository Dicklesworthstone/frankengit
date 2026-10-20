use super::*;
fn args() -> Vec<String> {
    [
        "publish-run",
        "/not-opened",
        &"11".repeat(16),
        &"22".repeat(16),
        "refs/heads/main",
        "--trusted-local",
        "--run-directory",
        "/private/run",
        "--journal-id",
        &"33".repeat(32),
        "--at-pin",
        &format!("72:{}", "44".repeat(32)),
        "--principal-id",
        &"55".repeat(16),
        "--expected-incarnation",
        &"66".repeat(16),
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
#[test]
fn exact_scope_defaults_and_lowered_limits_parse_without_io() {
    let mut input = args();
    let p = parse(&input).unwrap();
    assert_eq!(p.limits, (128, 16 * 1024 * 1024));
    assert!(!p.plan_only);
    assert_eq!(p.snapshot.0, 72);
    input.extend([
        "--plan-only".into(),
        "--max-checks".into(),
        "3".into(),
        "--max-evidence-mib".into(),
        "1".into(),
        "--expected-set".into(),
        "aa".repeat(32),
    ]);
    let p = parse(&input).unwrap();
    assert!(p.plan_only);
    assert_eq!(p.limits, (3, 1024 * 1024));
    assert_eq!(p.expected_set, Some([0xaa; 32]));
}
#[test]
fn every_required_pin_publisher_and_trust_flag_is_mandatory() {
    for flag in [
        "--run-directory",
        "--journal-id",
        "--at-pin",
        "--principal-id",
        "--expected-incarnation",
    ] {
        let mut input = args();
        let at = input.iter().position(|a| a == flag).unwrap();
        input.drain(at..at + 2);
        assert!(parse(&input).is_err(), "{flag}");
    }
    let mut input = args();
    input.retain(|a| a != "--trusted-local");
    assert!(parse(&input).is_err());
    assert!(parse(&args()).is_ok());
}
#[test]
fn replacement_keys_unknown_flags_duplicates_and_out_of_bounds_refuse() {
    for extra in [
        vec!["--idempotency-key", "new"],
        vec!["--force"],
        vec!["--fact-index", "0"],
        vec!["--batch", "aa"],
        vec!["--trusted-local"],
        vec!["--max-checks", "0"],
        vec!["--max-checks", "129"],
        vec!["--max-evidence-mib", "17"],
        vec!["--max-evidence-mib", "01"],
        vec!["--object-format", "sha512"],
        vec!["--expected-set", "short"],
        vec!["--plan-only", "--plan-only"],
    ] {
        let mut input = args();
        input.extend(extra.into_iter().map(str::to_owned));
        assert!(parse(&input).is_err(), "{input:?}");
    }
    for (flag, value) in [
        ("--run-directory", "relative"),
        ("--at-pin", "71:bad"),
        ("--principal-id", "BAD"),
        ("--journal-id", "../../host"),
    ] {
        let mut input = args();
        let at = input.iter().position(|a| a == flag).unwrap();
        input[at + 1] = value.into();
        assert!(parse(&input).is_err());
    }
}
#[test]
fn raw_ref_bytes_and_hash_domain_are_preserved() {
    let mut input = args();
    input[4] = "726566732f68656164732fff".into();
    input.extend([
        "--ref-hex".into(),
        "--object-format".into(),
        "sha256".into(),
    ]);
    let p = parse(&input).unwrap();
    assert_eq!(p.reference.as_bytes(), b"refs/heads/\xff");
    assert_eq!(p.format, GitHashAlgorithm::Sha256);
    input[4] = "726566732f746167732f7631".into();
    assert!(parse(&input).is_err());
}
#[test]
fn summary_preserves_refusals_errors_cleanup_and_broken_output() {
    let mut output = Vec::new();
    assert_eq!(
        finish(&mut output, Some("{}"), false, 3, None, None).unwrap(),
        3
    );
    assert!(
        String::from_utf8(output.clone())
            .unwrap()
            .contains("\"node_closed\":true")
    );
    output.clear();
    assert_eq!(
        finish(
            &mut output,
            Some("{}"),
            false,
            0,
            None,
            Some("cleanup\nfailed")
        )
        .unwrap(),
        2
    );
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("\"publication\":{}")
    );
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("broken"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(
        finish(&mut Broken, Some("{}"), false, 0, None, None)
            .unwrap_err()
            .contains("may already be canonical")
    );
}
