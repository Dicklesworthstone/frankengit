use super::*;

fn args(extra: &[&str]) -> Vec<String> {
    [
        "/unused",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "--trusted-local",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(str::to_owned)
    .collect()
}
fn token() -> String {
    format!("alg:1:{}", "ab".repeat(32))
}

#[test]
fn defaults_shrink_with_smaller_explicit_pages_but_conflicting_explicit_limits_refuse() {
    let options = parse(&args(&[])).unwrap();
    assert_eq!(options.query.max_page_objects, 1000);
    assert_eq!(options.query.max_findings, 100);
    assert_eq!(options.query.max_payload_bytes, 64 * MIB);
    let one = parse(&args(&["--max-page-objects", "1"])).unwrap();
    assert_eq!(one.query.max_findings, 1);
    let small = parse(&args(&["--max-selected-objects", "3"])).unwrap();
    assert_eq!(
        (small.query.max_page_objects, small.query.max_findings),
        (3, 3)
    );
    assert!(parse(&args(&["--max-page-objects", "1", "--max-findings", "2"])).is_err());
    assert!(
        parse(&args(&[
            "--max-selected-objects",
            "1",
            "--max-page-objects",
            "2"
        ]))
        .is_err()
    );
}

#[test]
fn all_options_fit_the_argument_envelope_and_exact_cursor_fences_round_trip() {
    let token = token();
    let after = "12".repeat(32);
    let all = args(&[
        "--object-format",
        "sha256",
        "--expected-generation",
        "7",
        "--expected-head",
        &token,
        "--resume-after",
        &after,
        "--max-selected-objects",
        "100",
        "--max-page-objects",
        "10",
        "--max-findings",
        "3",
        "--max-bytes",
        "999",
        "--max-object-bytes",
        "1024",
        "--timeout-secs",
        "9",
    ]);
    assert_eq!(all.len(), 24);
    let options = parse(&all).unwrap();
    assert_eq!(options.format, GitHashAlgorithm::Sha256);
    assert_eq!(options.query.expected_generation.unwrap().get(), 7);
    let cursor = options.query.cursor.unwrap();
    assert_eq!(head_token(cursor.head()), token);
    assert_eq!(cursor.after().to_string(), after);
    assert_eq!(options.query.max_payload_bytes, 999);
    assert_eq!(options.object_bytes, 1024);
    assert_eq!(options.query.timeout, Duration::from_secs(9));
}

#[test]
fn resume_requires_an_exact_head_nonzero_canonical_oid_and_matching_git_domain() {
    let token = token();
    let oid = "ab".repeat(20);
    assert!(parse(&args(&["--resume-after", &oid])).is_err());
    assert!(parse(&args(&["--resume-after", &oid, "--expected-head", &token])).is_ok());
    for bad in [
        "AB".repeat(20),
        "0".repeat(40),
        "12".repeat(32),
        "not-an-oid".into(),
    ] {
        assert!(parse(&args(&["--resume-after", &bad, "--expected-head", &token])).is_err());
    }
    assert!(
        parse(&args(&[
            "--expected-head",
            "deadbeef",
            "--resume-after",
            &oid
        ]))
        .is_err()
    );
}

#[test]
fn no_implicit_authorization_duplicates_unknown_flags_or_unbounded_input() {
    let mut untrusted = args(&[]);
    untrusted.pop();
    assert!(parse(&untrusted).is_err());
    assert!(parse(&args(&["--trusted-local"])).is_err());
    assert!(parse(&args(&["--repair", "yes"])).is_err());
    assert!(
        parse(&args(&[
            "--max-page-objects",
            "2",
            "--max-page-objects",
            "2"
        ]))
        .is_err()
    );
    assert!(parse(&args(&["--max-page-objects"])).is_err());
    let mut oversized = args(&[]);
    oversized[0] = "x".repeat(8193);
    assert!(parse(&oversized).is_err());
    assert!(parse(&vec!["x".into(); 25]).is_err());
    assert!(parse(&[]).is_err());
}

#[test]
fn numeric_bounds_and_overflow_refuse_without_silent_clamping() {
    for (flag, maximum) in [
        ("--max-selected-objects", 1_000_000_u64),
        ("--max-page-objects", 100_000),
        ("--max-findings", 1_000),
        ("--max-bytes", 16 * 1024 * MIB),
        ("--max-object-bytes", 16 * 1024 * MIB),
        ("--timeout-secs", 3_600),
    ] {
        assert!(parse(&args(&[flag, &maximum.to_string()])).is_ok());
        assert!(parse(&args(&[flag, &(maximum + 1).to_string()])).is_err());
        for bad in ["0", "-1", "+1", "1.0", " 1", "1 ", "18446744073709551616"] {
            assert!(parse(&args(&[flag, bad])).is_err(), "{flag}: {bad}");
        }
    }
}

#[test]
fn streaming_object_opt_in_keeps_page_and_sweep_budgets_independent() {
    let defaults = parse(&args(&[])).unwrap();
    assert_eq!(defaults.object_bytes, 32 * MIB);

    // Exercise a value above u32::MAX without allocating a large fixture.
    let large = 4 * 1024 * MIB;
    let large_text = large.to_string();
    let object_only = parse(&args(&["--max-object-bytes", &large_text])).unwrap();
    assert_eq!(object_only.object_bytes, large);
    assert_eq!(object_only.query.max_payload_bytes, 64 * MIB);
    assert!(object_only.sweep.is_none());

    // A wider storage ceiling cannot silently widen a deliberately small
    // page or whole-sweep allowance. The native scan enforces both at read time.
    let page_text = (2 * MIB).to_string();
    let sweep_text = (3 * MIB).to_string();
    let narrow = parse(&args(&[
        "--all",
        "--max-object-bytes",
        &large_text,
        "--max-bytes",
        &page_text,
        "--max-sweep-bytes",
        &sweep_text,
    ]))
    .unwrap();
    assert_eq!(narrow.object_bytes, large);
    assert_eq!(narrow.query.max_payload_bytes, 2 * MIB);
    assert_eq!(narrow.sweep.unwrap().payload_bytes, 3 * MIB);

    // The explicitly widened twin retains all three independent allowances.
    let permitted = parse(&args(&[
        "--all",
        "--max-object-bytes",
        &large_text,
        "--max-bytes",
        &large_text,
        "--max-sweep-bytes",
        &large_text,
    ]))
    .unwrap();
    assert_eq!(permitted.object_bytes, large);
    assert_eq!(permitted.query.max_payload_bytes, large);
    assert_eq!(permitted.sweep.unwrap().payload_bytes, large);
}

#[test]
fn diagnostic_output_preserves_utf8_prefix_and_hard_byte_bound() {
    let mut out = Diagnostic {
        text: String::new(),
        truncated: false,
    };
    fmt::Write::write_str(&mut out, &"a".repeat(1023)).unwrap();
    fmt::Write::write_str(&mut out, "\u{1f600}").unwrap();
    fmt::Write::write_str(&mut out, "must-not-follow-a-truncated-codepoint").unwrap();
    assert_eq!(out.text, "a".repeat(1023));
    assert!(out.truncated);
    let mut exact = Diagnostic {
        text: String::new(),
        truncated: false,
    };
    fmt::Write::write_str(&mut exact, &"b".repeat(1024)).unwrap();
    assert!(!exact.truncated);
    fmt::Write::write_str(&mut exact, "more").unwrap();
    assert_eq!(exact.text.len(), 1024);
    assert!(exact.truncated);
}

#[test]
fn shutdown_or_audit_failure_never_emits_a_success_receipt() {
    let options = parse(&args(&[])).unwrap();
    for cleanup in [None, Some("injected shutdown refusal".into())] {
        let mut output = Vec::new();
        assert!(
            finish(
                &mut output,
                &options,
                Err("injected authority refusal".into()),
                cleanup
            )
            .is_err()
        );
        assert!(output.is_empty());
    }
}
