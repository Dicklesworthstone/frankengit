use super::*;

const REF_POLICY: &str = r#"policy retained_tags {
    rule keep { when ref.name matches "refs/tags/release-*" and ref.update == delete then deny "retained tag" }
    default allow
}"#;

struct PolicyFile(PathBuf);
impl PolicyFile {
    fn new(bytes: &[u8]) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-policy-input-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::File::create_new(&path).unwrap();
        file.write_all(bytes).unwrap();
        Self(path)
    }
    fn argument(&self) -> String {
        self.0.to_str().unwrap().to_owned()
    }
}
impl Drop for PolicyFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

#[test]
fn cli_activates_source_and_exact_frame_as_the_same_complete_policy() {
    let source = PolicyFile::new(REF_POLICY.as_bytes());
    let mut args = input();
    args.truncate(args.len() - 2);
    args.extend(["--policy-source".into(), source.argument()]);
    let Operation::Set { command, .. } = parse(&args).unwrap().operation else {
        panic!()
    };
    assert!(command.protection.branches.is_empty());
    let snapshot = command.protection.ref_policy.as_ref().unwrap();
    let encoded = snapshot.encode().unwrap();
    let frame = PolicyFile::new(&encoded);
    args.truncate(args.len() - 2);
    args.extend(["--policy-frame".into(), frame.argument()]);
    let Operation::Set {
        command: restored, ..
    } = parse(&args).unwrap().operation
    else {
        panic!()
    };
    assert_eq!(restored, command);
    let report = policy_json(&command.protection).unwrap();
    assert!(report.contains(&snapshot.id().to_string()));
    assert!(report.contains(&bytes_hex(&encoded)));
    args.push("--clear".into());
    assert!(parse(&args).is_err());
}

#[test]
fn cli_policy_files_refuse_invalid_unsupported_oversized_and_ambiguous_inputs() {
    for bytes in [
        b"not a policy".to_vec(),
        vec![0xff],
        vec![b' '; MAX_REF_POLICY_SOURCE_BYTES + 1],
        b"policy unavailable { rule r { when principal.kind == agent then allow } default deny \"no\" }".to_vec(),
        b"policy unavailable { rule r { when ref.update == fast_forward then allow } default deny \"no\" }".to_vec(),
    ] {
        let file = PolicyFile::new(&bytes);
        let mut args = input();
        args.extend(["--policy-source".into(), file.argument()]);
        assert!(parse(&args).is_err());
    }
    let source = PolicyFile::new(REF_POLICY.as_bytes());
    let mut args = input();
    args.extend(["--policy-source".into(), source.argument()]);
    assert!(parse(&args).is_ok());
    args.extend(["--policy-frame".into(), source.argument()]);
    assert!(parse(&args).is_err());
    args.truncate(args.len() - 4);
    args.extend(["--policy-frame".into(), source.argument()]);
    assert!(parse(&args).is_err());
    args.truncate(args.len() - 2);
    args.extend([
        "--policy-source".into(),
        std::env::temp_dir().to_str().unwrap().into(),
    ]);
    assert!(parse(&args).is_err());
}
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
    let check = format!(
        "refs/heads/main:refs/heads/ci-candidate:{}:{}:build:linux λ",
        "77".repeat(16),
        "55".repeat(32)
    );
    args.extend(["--require-check".into(), check.clone()]);
    let Operation::Set { command, .. } = parse(&args).unwrap().operation else {
        panic!()
    };
    let rule = &command.protection.branches[0];
    assert!(rule.reviewers.is_empty());
    assert_eq!(rule.required_checks.len(), 1);
    assert_eq!(rule.required_checks[0].job, "build:linux λ");
    assert_eq!(
        rule.required_checks[0].publisher,
        PrincipalId::from_bytes([0x77; 16])
    );
    assert_eq!(rule.required_checks[0].graph_root, [0x55; 32]);
    assert_eq!(
        rule.required_checks[0].source_ref.as_bytes(),
        b"refs/heads/ci-candidate"
    );
    assert!(
        policy_json(&command.protection)
            .unwrap()
            .contains("\"required_checks\":[")
    );
    args.extend(["--require-check".into(), check]);
    assert!(
        parse(&args).is_err(),
        "duplicate checks cannot collapse silently"
    );
}
#[test]
fn required_check_cli_refuses_malformed_or_ambiguous_selectors() {
    for value in [
        format!(
            "refs/heads/main:refs/tags/ci:{}:{}:job",
            "77".repeat(16),
            "55".repeat(32)
        ),
        format!(
            "refs/heads/main:refs/heads/ci:{}:{}:job",
            "77".repeat(16),
            "FF".repeat(32)
        ),
        format!(
            "refs/heads/main:refs/heads/ci:{}:{}:",
            "77".repeat(16),
            "55".repeat(32)
        ),
        format!(
            "refs/heads/main:refs/heads/ci:{}:{}:bad\njob",
            "77".repeat(16),
            "55".repeat(32)
        ),
        format!("refs/heads/main:refs/heads/ci:{}:55:job", "77".repeat(16)),
    ] {
        let mut args = input();
        args.extend(["--require-check".into(), value]);
        assert!(parse(&args).is_err());
    }
}

#[test]
fn quorum_cli_supports_n_of_m_and_preserves_legacy_unanimity() {
    let mut args = input();
    for person in ["55", "66"] {
        args.extend([
            "--require-reviewer".into(),
            format!("refs/heads/main:{}", person.repeat(16)),
        ]);
    }
    let Operation::Set {
        command: legacy, ..
    } = parse(&args).unwrap().operation
    else {
        panic!()
    };
    assert_eq!(legacy.protection.branches[0].required_approvals, 3);
    let mut unanimous = args.clone();
    unanimous.extend(["--require-approvals".into(), "refs/heads/main:3".into()]);
    let Operation::Set {
        command: explicit, ..
    } = parse(&unanimous).unwrap().operation
    else {
        panic!()
    };
    assert_eq!(
        explicit, legacy,
        "explicit default must preserve the exact sealed command"
    );
    args.extend(["--require-approvals".into(), "refs/heads/main:2".into()]);
    let Operation::Set { command, .. } = parse(&args).unwrap().operation else {
        panic!()
    };
    assert_eq!(command.protection.branches[0].required_approvals, 2);
    assert_eq!(
        command.protection.branches[0].reviewers,
        legacy.protection.branches[0].reviewers
    );
    assert!(
        policy_json(&command.protection)
            .unwrap()
            .contains("\"required_approvals\":2")
    );
    let mut reordered = input();
    reordered.splice(
        4..4,
        ["--require-approvals".into(), "refs/heads/main:1".into()],
    );
    let Operation::Set { command, .. } = parse(&reordered).unwrap().operation else {
        panic!()
    };
    assert_eq!(command.protection.branches[0].required_approvals, 1);
}

#[test]
fn quorum_cli_rejects_invalid_counts_duplicate_settings_and_unknown_branches() {
    for count in ["0", "2", "33", "65536", "01", "-1", "+1", "1.0", "1e0", ""] {
        let mut args = input();
        args.extend([
            "--require-approvals".into(),
            format!("refs/heads/main:{count}"),
        ]);
        assert!(parse(&args).is_err(), "{count}");
    }
    for branch in ["refs/heads/other", "refs/tags/main"] {
        let mut args = input();
        args.extend(["--require-approvals".into(), format!("{branch}:1")]);
        assert!(parse(&args).is_err(), "{branch}");
    }
    let mut args = input();
    args.extend([
        "--require-approvals".into(),
        "refs/heads/main:1".into(),
        "--require-approvals".into(),
        "refs/heads/main:1".into(),
    ]);
    assert!(parse(&args).is_err());
}

#[test]
fn check_only_cli_quorum_is_zero_and_cannot_grant_missing_reviewers() {
    let mut args = input();
    args.truncate(args.len() - 2);
    args.extend([
        "--require-check".into(),
        format!(
            "refs/heads/main:refs/heads/ci:{}:{}:test",
            "77".repeat(16),
            "55".repeat(32)
        ),
    ]);
    let Operation::Set {
        command: legacy, ..
    } = parse(&args).unwrap().operation
    else {
        panic!()
    };
    assert_eq!(legacy.protection.branches[0].required_approvals, 0);
    args.extend(["--require-approvals".into(), "refs/heads/main:0".into()]);
    let Operation::Set { command, .. } = parse(&args).unwrap().operation else {
        panic!()
    };
    assert_eq!(command, legacy);
    *args.last_mut().unwrap() = "refs/heads/main:1".into();
    assert!(parse(&args).is_err());
}
