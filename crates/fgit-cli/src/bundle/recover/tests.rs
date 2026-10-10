use super::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
fn base() -> Vec<String> {
    args(&[
        "input.bundle",
        "new.git",
        "--trusted-local",
        "--head-ref",
        "refs/heads/main",
    ])
}

#[test]
fn explicit_head_and_local_write_consent_are_required_before_input_reads() {
    let parsed = parse(&base()).unwrap();
    assert_eq!(parsed.verification.path, PathBuf::from("input.bundle"));
    assert_eq!(parsed.destination, PathBuf::from("new.git"));
    assert!(!parsed.resume);
    assert_eq!(
        parsed.verification.recovery_head.unwrap().as_bytes(),
        b"refs/heads/main"
    );
    for values in [
        args(&["input", "output", "--head-ref", "refs/heads/main"]),
        args(&["input", "output", "--trusted-local"]),
        args(&["input", "output", "--trusted-local", "--head-ref", "HEAD"]),
        args(&[
            "input",
            "output",
            "--trusted-local",
            "--head-ref",
            "refs/tags/v1",
        ]),
        args(&[
            "input",
            "output",
            "--trusted-local",
            "--head-ref-hex",
            "ff00",
        ]),
    ] {
        assert!(parse(&values).is_err(), "{values:?}");
    }
}

#[test]
fn raw_head_names_resume_and_literal_paths_keep_the_original_bytes() {
    let values = args(&[
        "--trusted-local",
        "--resume",
        "--head-ref-hex",
        "726566732f68656164732f726177ff",
        "--",
        "--literal.bundle",
        "--literal.git",
    ]);
    let parsed = parse(&values).unwrap();
    assert!(parsed.resume);
    assert_eq!(parsed.verification.path, PathBuf::from("--literal.bundle"));
    assert_eq!(parsed.destination, PathBuf::from("--literal.git"));
    assert_eq!(
        parsed.verification.recovery_head.unwrap().as_bytes(),
        b"refs/heads/raw\xff"
    );
}

#[test]
fn existing_verifier_pins_limits_and_duplicate_rules_remain_authoritative() {
    let mut values = base();
    values.extend(args(&[
        "--expect-sha256",
        &"a".repeat(64),
        "--max-input-mib",
        "3",
        "--max-expanded-mib",
        "2",
        "--max-objects",
        "10",
        "--max-refs",
        "3",
        "--timeout-secs",
        "11",
    ]));
    let parsed = parse(&values).unwrap();
    assert_eq!(
        parsed.verification.limits.envelope.max_bundle_bytes,
        3 * 1024 * 1024
    );
    assert_eq!(
        parsed.verification.limits.graph.max_payload_bytes,
        2 * 1024 * 1024
    );
    assert_eq!(parsed.verification.limits.graph.max_objects, 10);
    assert_eq!(parsed.verification.timeout.as_secs(), 11);
    assert!(parsed.verification.expectations.is_some());
    for tail in [
        args(&["--trusted-local"]),
        args(&["--resume", "--resume"]),
        args(&["--head-ref-hex", "726566732f68656164732f6d61696e"]),
        args(&["--force"]),
        args(&["--principal", "11111111111111111111111111111111"]),
        args(&["--max-input-mib", "129"]),
        args(&["--timeout-secs", "0"]),
        args(&[
            "--expect-ref",
            "refs/heads/main=1111111111111111111111111111111111111111",
        ]),
        args(&["--max-refs", "1", "--max-refs", "2"]),
        args(&["unexpected-path"]),
    ] {
        let mut values = base();
        values.extend(tail);
        assert!(parse(&values).is_err(), "{values:?}");
    }
}
