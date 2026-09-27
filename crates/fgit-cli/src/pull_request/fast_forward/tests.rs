use super::*;
use fgit_types::GitHashAlgorithm;

fn args(format: GitHashAlgorithm) -> Vec<String> {
    vec![
        "/not-opened-by-the-parser".into(), "e1".repeat(16), "e2".repeat(16), "7".into(),
        "--trusted-local".into(), "--principal".into(), "02".repeat(16),
        "--idempotency-key".into(), "ff-key".into(),
        "--expected-version".into(), "2".into(),
        "--source-ref".into(), "refs/heads/topic".into(),
        "--expected-source".into(), "aa".repeat(format.digest_len()),
        "--target-ref".into(), "refs/heads/main".into(),
        "--expected-target".into(), "bb".repeat(format.digest_len()),
    ]
}
fn set(args: &mut [String], name: &str, value: &str) {
    let position = args.iter().position(|arg| arg == name).unwrap();
    args[position + 1] = value.into();
}

#[test]
fn exact_native_coordinates_are_parsed_without_repo_or_metadata_lookup() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = args(format);
        let parsed = options::parse(&input).unwrap();
        assert_eq!(parsed.format, format);
        assert_eq!(parsed.number.get(), 7);
        assert_eq!(parsed.version.get(), 2);
        assert_eq!(parsed.source.to_string(), "aa".repeat(format.digest_len()));
        assert_eq!(parsed.target.to_string(), "bb".repeat(format.digest_len()));
        assert_eq!(parsed.source_ref.as_bytes(), b"refs/heads/topic");
        assert_eq!(parsed.target_ref.as_bytes(), b"refs/heads/main");
        let mut declared = input;
        declared.extend(["--object-format".into(), format.as_str().into()]);
        assert_eq!(options::parse(&declared).unwrap().source, parsed.source);
    }
}

#[test]
fn the_operator_grant_and_every_semantic_coordinate_are_mandatory() {
    let good = args(GitHashAlgorithm::Sha1);
    for name in ["--principal", "--idempotency-key", "--expected-version", "--source-ref",
        "--target-ref", "--expected-source", "--expected-target"]
    {
        let mut missing = good.clone();
        let at = missing.iter().position(|arg| arg == name).unwrap();
        missing.drain(at..at + 2);
        assert!(options::parse(&missing).is_err(), "{name}");
    }
    let mut untrusted = good.clone();
    untrusted.retain(|arg| arg != "--trusted-local");
    assert!(options::parse(&untrusted).is_err());
    for flag in ["--force", "--method", "--body", "--title", "--bundle", "--expected-head", "--policy-epoch"] {
        let mut injected = good.clone();
        injected.extend([flag.into(), "ignored-is-not-allowed".into()]);
        assert!(options::parse(&injected).is_err(), "{flag}");
    }
}

#[test]
fn positive_and_exhausted_u64_versions_are_not_lossily_coerced() {
    let mut input = args(GitHashAlgorithm::Sha256);
    input[3] = u64::MAX.to_string();
    set(&mut input, "--expected-version", &(u64::MAX - 1).to_string());
    let edge = options::parse(&input).unwrap();
    assert_eq!(edge.number.get(), u64::MAX);
    assert_eq!(edge.version.get(), u64::MAX - 1);
    for bad in ["0", "00", "01", "-1", "+1", "1.0", "1e2", "18446744073709551615", "18446744073709551616"] {
        set(&mut input, "--expected-version", bad);
        assert!(options::parse(&input).is_err(), "{bad}");
    }
    set(&mut input, "--expected-version", "1");
    for bad in ["0", "01", "-1", "18446744073709551616"] {
        input[3] = bad.into();
        assert!(options::parse(&input).is_err(), "{bad}");
    }
}

#[test]
fn object_formats_zero_equal_tips_and_nonbranch_coordinates_refuse_before_io() {
    let good = args(GitHashAlgorithm::Sha1);
    for (name, value) in [
        ("--expected-source", "0".repeat(40)),
        ("--expected-source", "b".repeat(40)),
        ("--expected-target", "b".repeat(64)),
        ("--source-ref", "refs/heads/main".into()),
        ("--source-ref", "refs/tags/v1".into()),
        ("--target-ref", "refs/heads/../main".into()),
    ] {
        let mut bad = good.clone();
        set(&mut bad, name, &value);
        assert!(options::parse(&bad).is_err(), "{name} {value}");
    }
    for declared in ["sha256", "sha3", "SHA1"] {
        let mut bad = good.clone();
        bad.extend(["--object-format".into(), declared.into()]);
        assert!(options::parse(&bad).is_err());
    }
}

#[test]
fn aliases_and_duplicate_flags_cannot_hide_conflicting_expectations() {
    let good = args(GitHashAlgorithm::Sha1);
    for name in ["--expected-source", "--source-tip", "--target-tip", "--expected-version", "--principal"] {
        let mut repeated = good.clone();
        repeated.extend([name.into(), "aa".repeat(20)]);
        assert!(options::parse(&repeated).is_err(), "{name}");
    }
    let mut repeated = good.clone();
    repeated.push("--trusted-local".into());
    assert!(options::parse(&repeated).is_err());
    let aliases: Vec<_> = good.iter().map(|arg| match arg.as_str() {
        "--expected-source" => "--source-tip".to_owned(),
        "--expected-target" => "--target-tip".to_owned(),
        _ => arg.clone(),
    }).collect();
    let normal = options::parse(&good).unwrap();
    let alternate = options::parse(&aliases).unwrap();
    assert_eq!(alternate.source, normal.source);
    assert_eq!(alternate.target, normal.target);
    assert_eq!(alternate.key, normal.key);
}

#[test]
fn byte_references_stay_exact_and_competing_spellings_are_not_merged() {
    let good = args(GitHashAlgorithm::Sha1);
    let mut encoded = good.clone();
    let at = encoded.iter().position(|arg| arg == "--source-ref").unwrap();
    encoded[at] = "--source-ref-hex".into();
    encoded[at + 1] = hex(b"refs/heads/topic\xff");
    assert_eq!(options::parse(&encoded).unwrap().source_ref.as_bytes(), b"refs/heads/topic\xff");
    for malformed in ["", "a", "AA", "zz", "00"] {
        let mut bad = encoded.clone();
        bad[at + 1] = malformed.into();
        assert!(options::parse(&bad).is_err());
    }
    let mut competing = good;
    competing.extend(["--source-ref-hex".into(), hex(b"refs/heads/topic")]);
    assert!(options::parse(&competing).is_err());
}

#[test]
fn argument_budgets_and_nul_are_checked_before_node_open() {
    for size in [4096, 4097] {
        let mut input = args(GitHashAlgorithm::Sha1);
        input[0] = "x".repeat(size);
        assert_eq!(options::parse(&input).is_ok(), size == 4096);
    }
    let mut input = args(GitHashAlgorithm::Sha1);
    input[0] = "bad\0path".into();
    assert!(options::parse(&input).is_err());
    let mut input = args(GitHashAlgorithm::Sha1);
    set(&mut input, "--source-ref", &"x".repeat(8193));
    assert!(options::parse(&input).is_err());
    let mut input = args(GitHashAlgorithm::Sha1);
    input.resize(33, "extra".into());
    assert!(options::parse(&input).is_err());
}

#[test]
fn pre_admission_errors_and_ambiguous_admission_errors_remain_distinct() {
    let before = operation_error("missing authority", false, None);
    assert!(before.contains("before merge admission"));
    assert!(before.contains("does not determine any earlier invocation"));
    let after = operation_error("timeout", true, Some("shutdown failed"));
    assert!(after.contains("not evidence of non-commit"));
    assert!(after.contains("ORIGINAL"));
    assert!(after.contains("shutdown also failed"));
    assert!(!after.contains("canonical refusal"));
}

#[test]
fn help_and_invalid_input_do_not_open_storage_or_suppress_output_failure() {
    let mut output = Vec::new();
    assert_eq!(run(&["--help".into()], &mut output).unwrap(), 0);
    let help = String::from_utf8(output).unwrap();
    assert!(help.contains("--expected-version"));
    assert!(help.contains("not proof of rollback"));
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    assert!(run(&["--help".into()], &mut Broken).unwrap_err().contains("help output failed"));
    let mut bad = args(GitHashAlgorithm::Sha1);
    set(&mut bad, "--expected-version", "0");
    let error = run(&bad, &mut Vec::new()).unwrap_err();
    assert!(error.contains("positive exact PR version"));
    assert!(!error.contains("cannot open"));
}
